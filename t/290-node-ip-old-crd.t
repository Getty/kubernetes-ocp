#!/usr/bin/env perl
use strict;
use warnings;

# OCP::Node paces its reconcile loop with sleep, `ocp node add` waits 5s before
# it polls robocop's CR. Nothing here waits for anything that takes time --
# set before the modules below are compiled, or they would keep the real one.
BEGIN { *CORE::GLOBAL::sleep = sub { 0 } }

use Test::More;
use File::Temp qw(tempdir);
use JSON::PP ();
use Path::Tiny qw(path);
use Storable qw(dclone);
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::AMDGPU;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Deploy;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Node::Add;
use OCP::Config;
use OCP::Drift;
use OCP::Node;
use OCP::Secrets;

no warnings 'once';

#
# k290: `ocp node add --node_ip` on a cluster whose OCPNode CRD an older OCP
# installed. Live on amdlab, 2026-10-31: the CRD had no spec.nodeIP, and the
# API server prunes a field its structural schema does not declare -- without
# an error. The OCPNode was stored without spec.nodeIP, OCP::Node (which reads
# the stored CR) handed the install no node-ip, the node registered
# 192.168.0.165 instead of 10.230.30.50, and nothing was said: status.nodeIP
# was never set, so the mismatch check had nothing to compare.
#
# The claims here:
#   1. the fake API below prunes the way that API server did (premise);
#   2. with --node_ip, node add reads the OCPNode CRD and refuses BEFORE
#      anything is written or any machine is contacted when the CRD cannot
#      store spec.nodeIP -- an old CRD, no CRD -- with a diagnosis on STDERR
#      that names `ocp apply`; a CRD that cannot be read refuses too, with
#      its cause, and is never taken as fine (only a 404 is "absent", k269);
#      the CRD is read, never re-applied;
#   3. without --node_ip the CRD is not read at all;
#   4. an OCPNode stored without the spec.nodeIP node add asked for -- an API
#      server that still prunes by the old schema for a moment after the CRD
#      was updated -- is said on STDERR once the node is Ready, on either path,
#      and the InternalIP check is no longer left to an OCP::Node that had no
#      node-ip to hold it against;
#   5. `ocp apply` writes spec.nodeIP only after it ensured the CRDs, on the
#      deploy path and the reconcile path, and a CRD apply that fails writes
#      no OCPNode after it.
#

my $ASKED    = '10.230.30.50';
my $WRONG    = '192.168.0.165';
my $CRD_PATH = '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/ocpnodes.ocp.internal';

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die $!;
    open my $efh, '>', \$err or die $!;
    my ($rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, out => $out, err => $err, died => $died };
}

sub v1_schema {
    my ($crd) = @_;
    my ($v1) = grep { $_->{name} eq 'v1' } @{ $crd->{spec}{versions} };
    return $v1->{schema}{openAPIV3Schema};
}

# The CRD this OCP ships, and the one an OCP from before k254 installed: the
# same, without nodeIP in spec and status.
my ($NEW_CRD) = grep { ref $_ eq 'HASH' && ($_->{kind} // '') eq 'CustomResourceDefinition' }
    YAML::XS::LoadFile('share/robocop/crds/ocpnode.yaml');
my $OLD_CRD = dclone($NEW_CRD);
delete v1_schema($OLD_CRD)->{properties}{$_}{properties}{nodeIP} for qw(spec status);

sub node_with {
    my ($name, @internal) = @_;
    return {
        metadata => { name => $name },
        status   => {
            conditions => [ { type => 'Ready', status => 'True' } ],
            addresses  => [
                (map { { type => 'InternalIP', address => $_ } } @internal),
                { type => 'Hostname', address => $name },
            ],
        },
    };
}

my $DIAG = OCP::Node->node_ip_mismatch(node_with('x', $WRONG), $ASKED);

package FakeIO       { sub new { bless {}, shift } sub object_to_struct { $_[1] } }
package FakeList     { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeResponse {
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}

# A cluster with one ssh provider, OCPNodes, Nodes and an OCPNode CRD.
#
# GET of the CRD (_request, as OCP::Cmd::Apply::K8s::crd_get makes it)
# answers `crd` -- undef for a cluster without one -- or `crd_answer`: an
# [ HTTP status, body ], or a string to die with (no response at all).
#
# Writes prune what the CRD's v1 schema does not declare, at the top level of
# spec and status, without an error -- what the API server does with a
# structural schema. They prune by `store_crd` when given: an API server that
# serves the updated CRD but still stores by the schema it had before.
#
# ensure() replaces spec and keeps status (the status subresource) and returns
# what was stored; patch_status() merges, undef deleting.
package CrdApi {
    my $io = FakeIO->new;
    sub new {
        my ($c, %a) = @_;
        return bless { crd => $NEW_CRD, ocpnodes => {}, nodes => {}, calls => [], %a }, $c;
    }
    sub k8s { $io }
    sub provider {
        return { metadata => { name => 'ssh-default', annotations => {} },
                 spec     => { type => 'ssh' } };
    }
    sub list {
        my ($self, $kind) = @_;
        push @{ $self->{calls} }, [ 'list', $kind ];
        return FakeList->new([ $self->provider ]) if $kind eq 'OCPNodeProvider';
        return FakeList->new([]);
    }
    sub _request {
        my ($self, $method, $path) = @_;
        push @{ $self->{calls} }, [ 'request', $method, $path ];
        return FakeResponse->new(404, '{}') unless $path eq $CRD_PATH;
        my $answer = $self->{crd_answer};
        die $answer if defined $answer && !ref $answer;
        return FakeResponse->new(@$answer) if $answer;
        return FakeResponse->new(404, '{"kind":"Status","reason":"NotFound","code":404}')
            unless $self->{crd};
        return FakeResponse->new(200, JSON::PP->new->canonical->encode($self->{crd}));
    }
    sub _pruned {
        my ($self, $part, $h) = @_;
        my $props = main::v1_schema($self->{store_crd} // $self->{crd} // $OLD_CRD)
            ->{properties}{$part}{properties};
        return { map { $_ => $h->{$_} } grep { exists $props->{$_} } keys %{ $h // {} } };
    }
    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : undef;
        my %o = @rest;
        $name //= $o{name};
        push @{ $self->{calls} }, [ 'get', $kind, $name ];
        return $self->provider if $kind eq 'OCPNodeProvider';
        if ($kind eq 'Deployment') {
            return $self->{robocop} ? { status => { readyReplicas => 1 } } : undef;
        }
        if ($kind eq 'OCPNode') {
            my $cr = $self->{ocpnodes}{$name} or die "404 OCPNode $name not found\n";
            return { %$cr, spec => { %{ $cr->{spec} // {} } },
                     status => { %{ $cr->{status} // {} } } };
        }
        if ($kind eq 'Node') {
            return $self->{nodes}{$name} // die "404 Node $name not found\n";
        }
        return undef;
    }
    sub ensure {
        my ($self, $obj) = @_;
        push @{ $self->{calls} }, [ 'ensure', $obj ];
        my $name = $obj->{metadata}{name};
        my $old  = $self->{ocpnodes}{$name} // {};
        my $stored = { %$obj, spec => $self->_pruned(spec => $obj->{spec}),
                       ($old->{status} ? (status => $old->{status}) : ()) };
        $self->{ocpnodes}{$name} = $stored;
        return Storable::dclone($stored);
    }
    sub patch_status {
        my ($self, $kind, %a) = @_;
        push @{ $self->{calls} }, [ 'patch_status', $kind, $a{name} ];
        my $status = $self->{ocpnodes}{ $a{name} }{status} //= {};
        my $patch  = $a{patch}{status};
        my $keep   = $self->_pruned(status => { map { $_ => 1 } keys %$patch });
        for my $k (keys %$patch) {
            next unless $keep->{$k};
            defined $patch->{$k} ? ($status->{$k} = $patch->{$k}) : delete $status->{$k};
        }
        return 1;
    }
    sub patch { push @{ $_[0]{calls} }, [ 'patch', $_[1] ]; return {} }
}

# The project as `ocp node add` reads it: no control-plane address recorded,
# so the CLI path opens no SSH and reads no join token.
package AddConfig {
    my $dir = Path::Tiny->tempdir;
    sub new            { bless {}, shift }
    sub cluster_status { +{} }
    sub control_planes { [] }
    sub distribution   { 'rke2' }
    sub pod_cidr       { '10.42.0.0/16' }
    sub project_dir    { $dir }
    sub gpu_enabled    { 0 }
}

package main;

sub calls_of {
    my ($api, $what) = @_;
    return grep { $_->[0] eq $what } @{ $api->{calls} };
}
sub crd_reads { my ($api) = @_; return grep { $_->[2] eq $CRD_PATH } calls_of($api, 'request') }

sub warn_lines { my ($err) = @_; return grep { /^\[WARN\] / } split /\n/, $err }

# node add, with the machine-facing steps recorded rather than taken: the SSH
# preflight (which may ask for PIN2) and the CLI join itself, unless `join`
# asks for the real OCP::Node.
sub run_add {
    my ($api, %opt) = @_;
    my $real_join = delete $opt{join};
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $api,
        name     => 'synapse',
        provider => 'ssh-default',
        host     => $ASKED,
        %opt,
    );
    my @steps;
    no warnings 'redefine';
    local *OCP::Cmd::Node::Add::_config = sub { AddConfig->new };
    local *OCP::Cmd::Node::Add::_host_probe_ssh = sub { push @steps, 'ssh probe'; 1 };
    local *OCP::Cmd::Node::Add::_cli_reconcile  = sub { push @steps, 'join'; 1 }
        unless $real_join;
    local $OCP::Node::READY_TIMEOUT = 2;
    my $r = capture { $add->execute([], []) };
    $r->{steps} = \@steps;
    return $r;
}

# =============================================================================
# 1. premise: an old CRD prunes spec.nodeIP, and says nothing
# =============================================================================

subtest 'premise: the shipped CRD declares spec.nodeIP, the old one does not' => sub {
    ok exists v1_schema($NEW_CRD)->{properties}{spec}{properties}{nodeIP}, 'shipped: spec.nodeIP';
    ok !exists v1_schema($OLD_CRD)->{properties}{spec}{properties}{nodeIP}, 'old: none';
    ok exists v1_schema($OLD_CRD)->{properties}{spec}{properties}{host}, 'old: the rest is there';
};

subtest 'premise: the fake stores an OCPNode on an old CRD as that API server did' => sub {
    my $api = CrdApi->new(crd => $OLD_CRD);
    my $stored = $api->ensure({ metadata => { name => 'synapse' },
        spec => { role => 'worker', providerRef => 'ssh-default', host => $ASKED,
                  gpu => JSON::PP::true, nodeIP => $ASKED } });
    is_deeply [ sort keys %{ $stored->{spec} } ], [ qw(gpu host providerRef role) ],
        'spec.nodeIP gone, the rest kept -- the amdlab OCPNode, field for field';
};

# =============================================================================
# 2. --node_ip on a cluster that cannot store it: refused before anything
# =============================================================================

sub refused_before_anything {
    my ($r, $api, $what) = @_;
    ok !calls_of($api, 'ensure'),     "$what: no OCPNode written";
    ok !%{ $api->{ocpnodes} },        "$what: none in the cluster";
    ok !@{ $r->{steps} },             "$what: no SSH probe (no PIN2), no join"
        or diag explain $r->{steps};
    ok !calls_of($api, 'patch'),      "$what: nothing patched";
    unlike $r->{out}, qr/--node_ip/,  "$what: the refusal is not on STDOUT";
}

my $OLD_REFUSAL = qr{\A--node_ip: this cluster's OCPNode CRD \(ocpnodes\.ocp\.internal\) has no spec\.nodeIP};

subtest 'old CRD, robocop off: refused before the OCPNode is written or the host probed' => sub {
    my $api = CrdApi->new(crd => $OLD_CRD);
    my $r   = run_add($api, node_ip => $ASKED);

    like $r->{died}, $OLD_REFUSAL, 'dies with the diagnosis (bin/ocp prints it on STDERR, exit 1)'
        or return diag explain { died => $r->{died}, steps => $r->{steps} };
    like $r->{died}, qr/the API server would drop the field without an error/, 'says what would happen';
    like $r->{died}, qr/default route/, 'and what that does to the node';
    like $r->{died}, qr/Run `ocp apply` first: it updates the CRD\./, 'names the fix';
    like $r->{died}, qr/Nothing was written\.\n\z/, 'and that nothing happened';
    unlike $r->{died}, qr/deploy-robocop/, 'not deploy-robocop: it would deploy robocop as well';
    refused_before_anything($r, $api, 'old CRD');
    is scalar(crd_reads($api)), 1, 'the CRD was read, once';
    is scalar(calls_of($api, 'request')), 1, 'and only read: nothing re-applied from here';
};

subtest 'old CRD, robocop running: refused before robocop could take the OCPNode up' => sub {
    my $api = CrdApi->new(crd => $OLD_CRD, robocop => 1);
    my $r   = run_add($api, node_ip => $ASKED);
    like $r->{died}, $OLD_REFUSAL, 'the same refusal' or return diag $r->{died};
    refused_before_anything($r, $api, 'robocop running');
};

subtest 'old CRD with --nowait: refused, STDOUT stays empty' => sub {
    my $api = CrdApi->new(crd => $OLD_CRD);
    my $r   = run_add($api, node_ip => $ASKED, nowait => 1);
    like $r->{died}, $OLD_REFUSAL, 'refused' or return diag $r->{died};
    is $r->{out}, '', 'no node name on STDOUT: no node was added';
    refused_before_anything($r, $api, '--nowait');
};

subtest 'no OCPNode CRD at all (404): refused, naming ocp apply' => sub {
    my $api = CrdApi->new(crd => undef);
    my $r   = run_add($api, node_ip => $ASKED);
    like $r->{died}, qr{\A--node_ip: this cluster has no OCPNode CRD \(ocpnodes\.ocp\.internal\)},
        'absent is said as absent' or return diag $r->{died};
    like $r->{died}, qr/Run `ocp apply` first: it installs the CRD\./, 'names the fix';
    refused_before_anything($r, $api, 'no CRD');
};

subtest 'a CRD that does not serve v1, the version ocp writes: refused' => sub {
    my $crd = dclone($NEW_CRD);
    $_->{served} = JSON::PP::false for @{ $crd->{spec}{versions} };
    my $api = CrdApi->new(crd => $crd);
    my $r   = run_add($api, node_ip => $ASKED);
    like $r->{died}, $OLD_REFUSAL, 'it stores nothing as v1' or return diag $r->{died};
    refused_before_anything($r, $api, 'v1 not served');
};

subtest 'a CRD that cannot be read is no CRD that is fine: refused, with the cause' => sub {
    for my $case (
        [ '403', [ 403, '{"kind":"Status","reason":"Forbidden","code":403}' ], qr/HTTP 403 .*Forbidden/ ],
        [ '500', [ 500, '{"kind":"Status","reason":"InternalError","code":500}' ], qr/HTTP 500/ ],
        [ 'no response', "connection refused\n", qr/connection refused/ ],
        [ 'no JSON', [ 200, '<html>proxy</html>' ], qr/no JSON/ ],
    ) {
        my ($what, $answer, $cause) = @$case;
        my $api = CrdApi->new(crd_answer => $answer);
        my $r   = run_add($api, node_ip => $ASKED);
        like $r->{died}, qr{\A--node_ip: could not check that this cluster stores spec\.nodeIP: },
            "$what: refused" or next;
        like $r->{died}, qr{\Q$CRD_PATH\E}, "$what: names what it read";
        like $r->{died}, $cause, "$what: and why it could not";
        like $r->{died}, qr/Nothing was written\.\n\z/, "$what: nothing happened";
        refused_before_anything($r, $api, $what);
    }
};

subtest 'current CRD: --node_ip goes through and is stored' => sub {
    my $api = CrdApi->new;
    my $r   = run_add($api, node_ip => $ASKED);
    is $r->{died}, '', 'node add ran' or return diag $r->{died};
    is $api->{ocpnodes}{synapse}{spec}{nodeIP}, $ASKED, 'spec.nodeIP stored';
    is_deeply $r->{steps}, [ 'ssh probe', 'join' ], 'the host was probed and joined, in that order';
    is scalar(crd_reads($api)), 1, 'one CRD read';
};

subtest 'without --node_ip: the CRD is not read, an old one is no reason to refuse' => sub {
    my $api = CrdApi->new(crd => $OLD_CRD);
    my $r   = run_add($api);
    is $r->{died}, '', 'node add ran' or return diag $r->{died};
    ok !calls_of($api, 'request'), 'no CRD read';
    ok $api->{ocpnodes}{synapse}, 'the OCPNode was written';
};

# =============================================================================
# 4. stored without the spec.nodeIP asked for: said, on either path
# =============================================================================
#
# The CRD node add reads declares spec.nodeIP, but the store prunes by the old
# schema: an API server that serves an updated CRD before it stores by it.
# The OCPNode is then what amdlab had -- no spec.nodeIP -- and so is the
# install: none handed, no status.nodeIP recorded.

my $NOT_STORED = "[WARN] synapse: OCPNode synapse holds no spec.nodeIP, though --node_ip $ASKED "
    . 'was given: the API server dropped the field, as an OCPNode CRD from an older ocp does, '
    . 'and every install reads the node-ip from there. `ocp apply` updates the CRD.';

sub lagging_api {
    my (%o) = @_;
    my $api = CrdApi->new(store_crd => $OLD_CRD, %o);
    my $phase = $o{robocop} ? 'Ready' : 'Joining';
    $api->{ocpnodes}{synapse} = {
        metadata => { name => 'synapse', namespace => 'ocp-system' },
        status   => { phase => $phase,
                      ($phase eq 'Ready' ? (kubernetesNodeName => 'synapse',
                                            message => 'Node joined and Ready') : ()) },
    };
    $api->{nodes}{synapse} = node_with('synapse', $o{registered} // $WRONG);
    return $api;
}

subtest 'CLI path: stored without spec.nodeIP, registered elsewhere -> both said' => sub {
    my $api = lagging_api();
    my $r   = run_add($api, node_ip => $ASKED, join => 1);

    is $r->{died}, '', 'node add ran' or return diag $r->{died};
    ok !exists $api->{ocpnodes}{synapse}{spec}{nodeIP}, 'premise: stored without spec.nodeIP';
    is $api->{ocpnodes}{synapse}{status}{phase}, 'Ready', 'premise: OCP::Node turned it Ready here';
    ok !exists $api->{ocpnodes}{synapse}{status}{nodeIP}, 'premise: and recorded no node-ip';
    is $r->{rv}, 0, 'exit 0: the node is Ready';
    is_deeply [ warn_lines($r->{err}) ], [ $NOT_STORED, "[WARN] synapse: $DIAG" ],
        'why the node-ip went missing, then where the node registered -- not silence'
        or diag $r->{err};
    unlike $r->{out}, qr/\[WARN\]/, 'not on STDOUT';
};

subtest 'CLI path: stored without it, registered there anyway -> still said' => sub {
    my $api = lagging_api(registered => $ASKED);
    my $r   = run_add($api, node_ip => $ASKED, join => 1);
    is $r->{died}, '', 'node add ran' or return diag $r->{died};
    is_deeply [ warn_lines($r->{err}) ], [ $NOT_STORED ],
        'the OCPNode does not hold what was asked: the next install would lose it'
        or diag $r->{err};
};

subtest 'robocop path: stored without spec.nodeIP -> said beside the mismatch' => sub {
    my $api = lagging_api(robocop => 1);
    my $r   = run_add($api, node_ip => $ASKED);
    is $r->{died}, '', 'node add ran' or return diag $r->{died};
    is $r->{rv}, 0, 'exit 0';
    is_deeply [ warn_lines($r->{err}) ], [ $NOT_STORED, "[WARN] synapse: $DIAG" ],
        'both, once each' or diag $r->{err};
};

subtest 'stored as asked: neither line' => sub {
    my $api = lagging_api(robocop => 1, store_crd => $NEW_CRD, registered => $ASKED);
    my $r   = run_add($api, node_ip => $ASKED);
    is $r->{died}, '', 'node add ran' or return diag $r->{died};
    is $api->{ocpnodes}{synapse}{spec}{nodeIP}, $ASKED, 'premise: stored';
    is $r->{err}, '', 'STDERR empty';
};

# =============================================================================
# 5. ocp apply: the CRDs before every OCPNode that carries spec.nodeIP
# =============================================================================
#
# The two apply writers of spec.nodeIP are ensure_cp_ocpnode (police1, deploy
# and reconcile) and ensure_control_plane_ocpnodes (police2+, deploy only).
# Neither reads the CRD: they rely on _ensure_crds having applied the one this
# OCP ships first. Every other step of both paths is a no-op here; the CR
# steps record the order they ran in.

package BootOcp    { sub new { bless {}, shift } sub verbose { 0 } }
package ReconDrift { sub detect { [] } sub probe_targets { () } }
package NoApi      { sub new { bless {}, shift } }

package main;

sub config_for {
    my ($yaml) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8($yaml);
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my $HA = <<'YAML';
name: amdlab
nocert: true
kubernetes:
  dist: rke2
control_planes:
  - provider: ssh
    host: otho.lab
    node_ip: 10.230.30.52
  - provider: ssh
    host: crag.lab
    node_ip: 10.230.30.54
YAML

# The CR steps of both paths, recording; `crds` is what _ensure_crds does.
sub cr_steps {
    my ($order, %o) = @_;
    return (
        crds => sub { push @$order, 'crds'; die $o{crds_dies} if $o{crds_dies}; 1 },
        cp   => sub { push @$order, 'police1 OCPNode'; 1 },
        cps  => sub { push @$order, 'police2+ OCPNodes'; () },
    );
}

sub writes_after_crds {
    my ($order) = @_;
    my ($crds) = grep { $order->[$_] eq 'crds' } 0 .. $#$order;
    my @writes = grep { $order->[$_] ne 'crds' } 0 .. $#$order;
    return defined $crds && !grep { $_ < $crds } @writes;
}

subtest 'deploy: CRDs first, then the OCPNodes that carry spec.nodeIP' => sub {
    my @order;
    my %step = cr_steps(\@order);
    my $apply = OCP::Cmd::Apply->new(command_chain => [ BootOcp->new ]);
    my $done = sub { 'unchanged' };
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_setup_registry                       = $done;
    local *OCP::Cmd::Apply::_configure_registry_dns               = $done;
    local *OCP::Cmd::Apply::_setup_nfd                            = $done;
    local *OCP::Cmd::Apply::_setup_gpu_operator                   = $done;
    local *OCP::Cmd::Apply::_report_component                     = $done;
    local *OCP::Cmd::Apply::_apply_cert_manager                   = $done;
    local *OCP::Cmd::Apply::_wait_cert_manager_and_create_issuers = $done;
    local *OCP::Cmd::Apply::_save_deployed_hash                   = $done;
    local *OCP::Cmd::Apply::_setup_cilium_gateway                 = $done;
    local *OCP::Cmd::Apply::_setup_lb_ipam                        = $done;
    local *OCP::Cmd::Apply::_ensure_providers                     = $done;
    local *OCP::Cmd::Apply::_migrate_legacy_nodes                 = $done;
    local *OCP::Cmd::Apply::AMDGPU::step = sub { { failed => [] } };
    local *OCP::Cmd::Apply::_ensure_crds                    = $step{crds};
    local *OCP::Cmd::Apply::_ensure_cp_ocpnode              = $step{cp};
    local *OCP::Cmd::Apply::_ensure_control_plane_ocpnodes  = sub { $step{cps}->(); die "STOP\n" };
    my $r = capture { OCP::Cmd::Apply::Deploy::deploy($apply, {
        config => config_for($HA), api => NoApi->new, cp_name => 'otho', cp_ip => '10.230.30.52',
        provider => 'ssh', ssh_key_path => '/nonexistent', deploy_step => 2,
    }) };
    is $r->{died}, "STOP\n", 'deploy reached the police2+ OCPNodes' or return diag $r->{died};
    is_deeply \@order, [ 'crds', 'police1 OCPNode', 'police2+ OCPNodes' ], 'in this order';
    ok writes_after_crds(\@order), 'no spec.nodeIP written before the CRD that declares it';
};

sub reconcile_order {
    my (%o) = @_;
    my @order;
    my %step = cr_steps(\@order, %o);
    my $apply = OCP::Cmd::Apply->new(command_chain => [ BootOcp->new ]);
    $apply->{_k8s_api} = NoApi->new;
    my $noop = sub { 0 };
    no warnings 'redefine';
    local *OCP::Secrets::read_kubeconfig  = sub { "apiVersion: v1\n" };
    local *OCP::Cmd::Apply::_k8s_api      = sub { $_[0]{_k8s_api} };
    local *OCP::Cmd::Apply::rex_prober    = sub { undef };
    local *OCP::Drift::new                = sub { bless {}, 'ReconDrift' };
    local *OCP::Cmd::Apply::AMDGPU::step  = sub { { changed => 0, failed => [] } };
    local *OCP::Cmd::Apply::_setup_registry         = $noop;
    local *OCP::Cmd::Apply::_configure_registry_dns = $noop;
    local *OCP::Cmd::Apply::_setup_nfd              = $noop;
    local *OCP::Cmd::Apply::_setup_gpu_operator     = $noop;
    local *OCP::Cmd::Apply::_report_component       = $noop;
    local *OCP::Cmd::Apply::_setup_cilium_gateway   = $noop;
    local *OCP::Cmd::Apply::_setup_lb_ipam          = $noop;
    local *OCP::Cmd::Apply::_ensure_providers       = $noop;
    local *OCP::Cmd::Apply::_migrate_legacy_nodes   = $noop;
    local *OCP::Cmd::Apply::_run_remedy             = $noop;
    local *OCP::Cmd::Apply::_ensure_crds                   = $step{crds};
    local *OCP::Cmd::Apply::_ensure_cp_ocpnode             = $step{cp};
    local *OCP::Cmd::Apply::_ensure_control_plane_ocpnodes = $step{cps};
    my $r = capture { OCP::Cmd::Apply::Drift::reconcile_components($apply, config_for($HA)) };
    $r->{order} = \@order;
    return $r;
}

subtest 'reconcile: CRDs first, then police1\'s OCPNode' => sub {
    my $r = reconcile_order();
    is $r->{died}, '', 'the reconcile ran' or return diag $r->{died};
    is_deeply $r->{order}, [ 'crds', 'police1 OCPNode' ],
        'in this order; police2+ are not written here' or diag explain $r->{order};
    ok writes_after_crds($r->{order}), 'no spec.nodeIP written before the CRD that declares it';
};

subtest 'reconcile: a CRD apply that fails writes no OCPNode after it' => sub {
    my $r = reconcile_order(crds_dies => "server-side apply of CustomResourceDefinition failed: 403\n");
    is $r->{died}, '', 'the reconcile went on' or return diag $r->{died};
    is_deeply $r->{order}, [ 'crds' ], 'police1\'s OCPNode was not written onto the CRD that was there';
};

done_testing;

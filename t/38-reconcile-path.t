#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Config;
use OCP::Secrets;

#
# `ocp apply` has two paths: a fresh deploy, and a reconcile for a cluster that
# already has a kubeconfig. The health gate was built into the fresh-deploy
# path only, and the reconcile path returned before reaching it — so applying
# over an existing cluster printed component results and exited 0 without ever
# looking at the cluster:
#
#   [ok] Cluster already exists (kubeconfig.yaml found)
#        Checking components...
#     [ok] No drift detected
#     ...
#     1 component(s) updated, 5 checked.
#   <exit 0>
#
# The reconcile path was also missing every step that repairs cluster state it
# does not own. registry.local had been dropped from the Corefile by k3s' addon
# manager, and the "self-healing on the next apply" that ticket k19 assumes
# never happened, because _configure_registry_dns lived only in the deploy
# path. Same for the control-plane OCPNode: a cluster bootstrapped by an older
# OCP kept a CR with no status, so `ocp node ls` showed Pending forever.
#
# The invariant these tests defend: there is ONE health gate, ONE banner and
# ONE exit code, and no path may reach a return without passing them.
#

my $src = path('lib/OCP/Cmd/Apply.pm')->slurp_utf8;
my $drift_src = path('lib/OCP/Cmd/Apply/Drift.pm')->slurp_utf8;
my $health_src = path('lib/OCP/Cmd/Apply/Health.pm')->slurp_utf8;

subtest 'the health gate has exactly one call site' => sub {
    # If _check_cluster_health is called from more than one place, the paths
    # can drift apart again — which is precisely how this bug happened.
    # The call site moved to OCP::Cmd::Apply::Health::finish during the
    # Phase 10 dispatcher extraction, so we grep both files.
    my @calls = ($src . $health_src) =~ /\$self->(_check_cluster_health)\b/g;
    is scalar @calls, 1,
        '_check_cluster_health is invoked from a single place';

    my ($finish) = $health_src =~ /^sub finish \{\n(.*?)\n\}$/ms;
    ok defined $finish, 'finish exists in Health.pm';
    like $finish, qr/_check_cluster_health/,
        'and that place is finish';
    like $finish, qr/_health_is_fatal/, 'finish decides the exit code';
    like $finish, qr/_banner/,          'finish prints the banner';
};

subtest 'both apply paths return through the shared finisher' => sub {
    my ($execute) = $src =~ /^sub execute \{\n(.*?)\n\}$/ms;
    ok defined $execute, 'execute() found';

    my @finishes = $execute =~ /return \$self->(_finish_apply)\b/g;
    is scalar @finishes, 2,
        'execute returns through _finish_apply twice: reconcile and fresh deploy';

    # The reconcile branch specifically — the one that used to slip past.
    my ($branch) = $execute =~ /if \(\$config->cluster_exists\) \{(.*?)\n    \}/ms;
    ok defined $branch, 'cluster_exists branch found';
    like $branch, qr/_reconcile_components/, 'it reconciles components';
    like $branch, qr/return \$self->_finish_apply/,
        'and it returns through the gate instead of returning early';
    unlike $branch, qr/^\s*return\s*;/m,
        'no bare early return that would skip the gate';
};

subtest 'the banner is not printed anywhere but the finisher' => sub {
    my ($reconcile) = $drift_src =~ /^sub reconcile_components \{\n(.*?)\n\}$/ms;
    ok defined $reconcile, 'reconcile_components found in Drift.pm';
    unlike $reconcile, qr/DEPLOYED|_banner/,
        'reconcile does not claim success on its own';
};

#
# What the reconcile path must now actually do.
#

subtest 'reconcile repairs the things it does not own' => sub {
    my ($reconcile) = $drift_src =~ /^sub reconcile_components \{\n(.*?)\n\}$/ms;

    # k19 assumes this heals on the next apply; that is only true if the
    # reconcile path runs it.
    like $reconcile, qr/_configure_registry_dns/,
        'registry.local DNS is reconciled';

    # A pre-existing cluster otherwise keeps an OCPNode with no status.
    like $reconcile, qr/_ensure_cp_ocpnode/, 'control-plane OCPNode is ensured';
    like $reconcile, qr/_ensure_crds/,       'CRDs are ensured';
    like $reconcile, qr/_ensure_providers/,  'provider CRs are ensured';

    like $reconcile, qr/_setup_cilium_gateway/, 'Cilium Gateway is reconciled';
    like $reconcile, qr/_setup_lb_ipam/,        'LB-IPAM is reconciled';
};

subtest 'reconcile stays out of control-plane bootstrap' => sub {
    my ($reconcile) = $drift_src =~ /^sub reconcile_components \{\n(.*?)\n\}$/ms;

    # Installing the control plane is a one-time bootstrap step, not
    # convergence.
    #
    # This subtest used to claim more: that the body named none of
    # _drive_workers, _ensure_worker_ocpnodes, _ensure_robocop or
    # reconcile_until_ready — "reconcile never provisions workers". k26
    # replaced that claim on purpose (maintainer decision 2026-09-24): the
    # OCPNode is the reflection of desired state, so a worker listed in
    # ocp.yaml without one is created by reconcile too, and workers that have
    # one are left alone. That is asserted behaviourally further down ("k26:
    # ..."), not by grepping the source.
    unlike $reconcile, qr/install_server/, 'no control-plane install';
};

#
# The shared finisher itself: one verdict, whoever calls it.
#

package FakeList {
    sub new   { my ($c, $i) = @_; bless { items => $i }, $c }
    sub items { $_[0]{items} }
}
package HealthApi {
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }
    sub list { FakeList->new($_[0]{pods} // []) }
}
package FakeConfig {
    sub new     { bless {}, shift }
    sub name    { 'cortex' }
    sub api_url { "https://$_[1]:6443" }
}

package main;

sub capture_stdout (&) {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $rc;
    {
        local *STDOUT = $fh;
        $rc = $code->();
    }
    return ($out, $rc);
}

# _stamp_ocp_version writes to the project dir; stub it out.
{
    no warnings 'redefine';
    *OCP::Cmd::Apply::_stamp_ocp_version = sub { 1 };
}

my $healthy_pod = {
    metadata => { name => 'coredns', namespace => 'kube-system' },
    status   => { phase => 'Running',
                  containerStatuses => [{ ready => 1, state => { running => {} } }] },
};
my $broken_pod = {
    metadata => { name => 'coredns', namespace => 'kube-system' },
    status   => { phase => 'Running', containerStatuses => [{
        ready => 0, restartCount => 5,
        state => { waiting => { reason => 'CrashLoopBackOff' } },
    }] },
};

subtest 'the finisher gives the same verdict to whichever path calls it' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';

    # Called the way the fresh-deploy path calls it (with a step number)...
    my ($deploy_out, $deploy_rc) = capture_stdout {
        $apply->_finish_apply(
            config => FakeConfig->new, api => HealthApi->new(pods => [$broken_pod]),
            step => 5, cp_name => 'cortex', cp_ip => '10.230.30.155',
        );
    };

    # ...and the way the reconcile path calls it (without one).
    my ($rec_out, $rec_rc) = capture_stdout {
        $apply->_finish_apply(
            config => FakeConfig->new, api => HealthApi->new(pods => [$broken_pod]),
            cp_name => 'cortex', cp_ip => '10.230.30.155',
        );
    };

    is $deploy_rc, 1, 'fresh deploy exits non-zero over a broken core';
    is $rec_rc,    1, 'reconcile exits non-zero over the same broken core';
    like $deploy_out, qr/NOT HEALTHY/, 'deploy banner says so';
    like $rec_out,    qr/NOT HEALTHY/, 'reconcile banner says the same';
    unlike $rec_out,  qr/SUCCESSFULLY/,
        'reconcile can no longer report success over a crash-looping CoreDNS';

    like $deploy_out, qr/Step 5: Verify cluster health/, 'numbered when given a step';
    like $rec_out,    qr/Verifying cluster health/, 'unnumbered otherwise';
};

subtest 'a healthy cluster still succeeds on both paths' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';
    for my $label ('deploy', 'reconcile') {
        my ($out, $rc) = capture_stdout {
            $apply->_finish_apply(
                config => FakeConfig->new, api => HealthApi->new(pods => [$healthy_pod]),
                cp_name => 'cortex', cp_ip => '10.230.30.155',
                ($label eq 'deploy' ? (step => 5) : ()),
            );
        };
        is $rc, 0, "$label exits 0 on a healthy cluster";
        like $out, qr/SUCCESSFULLY/, "$label prints the success banner";
    }
};

subtest 'a health check that cannot run does not fail the apply' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my $api = bless {}, 'ExplodingApi';
    {
        no strict 'refs';
        no warnings 'once';
        *ExplodingApi::list = sub { die "connection refused\n" };
        *ExplodingApi::k8s  = sub { $_[0] };
    }
    my ($out, $rc) = capture_stdout {
        $apply->_finish_apply(config => FakeConfig->new, api => $api);
    };
    is $rc, 0, 'a broken check is not itself a deploy failure';
    like $out, qr/\[WARN\] could not verify cluster health/, 'and says so';
};

#
# Both paths must address the same control plane, or reconcile would write the
# status of a node that does not exist.
#

package CpConfig {
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub name           { $_[0]{name} }
    sub control_planes { $_[0]{cps} }
}

package main;

subtest 'control-plane identity is one rule, shared by both paths' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';

    my $ssh = $apply->_cp_identity(CpConfig->new(
        name => 'cortex',
        cps  => [{ provider => 'ssh', host => 'cortex.ai.citilan.de' }],
    ));
    is $ssh->{name}, 'cortex', 'ssh cluster is named after the first host label';
    is $ssh->{domain}, 'ai.citilan.de', 'domain split off';
    is $ssh->{provider}, 'ssh', 'provider carried';

    my $bare = $apply->_cp_identity(CpConfig->new(
        name => 'c', cps => [{ provider => 'ssh', host => 'nodots' }],
    ));
    is $bare->{name}, 'nodots', 'host without a dot is used whole';

    my $htz = $apply->_cp_identity(CpConfig->new(
        name => 'prod', cps => [{ provider => 'hetzner' }],
    ));
    is $htz->{name}, 'police1', 'hetzner keeps RoboCop naming';
    is $htz->{hostname}, 'prod-police1', 'hostname prefixed with the cluster name';
};

#
# _configure_registry_dns reports whether it changed anything, which is what
# lets reconcile print "up to date" instead of claiming an update every run.
#

package CoreDnsCm {
    sub new  { my ($c, $d) = @_; bless { data => $d }, $c }
    sub data { $_[0]{data} }
}
package DnsApi {
    sub new  { my ($c, %a) = @_; bless { applied => [], %a }, $c }
    sub get  { $_[0]{cm} }
    sub expand_class { undef }
    sub _request {
        my ($self, $method, $path, $body) = @_;
        push @{$self->{applied}}, $body;
        return DnsResponse->new;
    }
}
package DnsResponse {
    sub new     { bless {}, shift }
    sub status  { 200 }
    sub content { '{}' }
}

package main;

subtest 'registry DNS reconcile is idempotent and reports honestly' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';

    my $corefile = <<'COREFILE';
.:53 {
    errors
    hosts /etc/coredns/NodeHosts {
        ttl 60
        reload 15s
        fallthrough
    }
    forward . /etc/resolv.conf
}
COREFILE

    # First run: the record is missing (k3s reset the Corefile) -> repaired.
    my $api = DnsApi->new(cm => CoreDnsCm->new({ Corefile => $corefile }));
    $apply->{_k8s_api} = $api;
    my ($out, $changed) = capture_stdout {
        $apply->_configure_registry_dns('10.230.30.155');
    };
    ok $changed, 'a Corefile without the record is patched';
    is scalar @{$api->{applied}}, 1, 'one apply issued';
    my $patched = $api->{applied}[0]{data}{Corefile};
    like $patched, qr/10\.230\.30\.155 registry\.local/, 'record added';

    # Second run over the result: nothing to do, nothing claimed.
    my $api2 = DnsApi->new(cm => CoreDnsCm->new({ Corefile => $patched }));
    $apply->{_k8s_api} = $api2;
    my ($out2, $changed2) = capture_stdout {
        $apply->_configure_registry_dns('10.230.30.155');
    };
    ok !$changed2, 'a Corefile that already has the record is left alone';
    is scalar @{$api2->{applied}}, 0, 'no apply issued on the second run';
};

#
# --dry-run over a cluster that already exists.
#
# The flag was read in exactly one place, and that place sat in the bootstrap
# path behind `if ($config->cluster_exists) { ... return }`. A reconcile never
# reached it, so `ocp apply --dry-run` against cortex ran the whole convergence
# — "Creating Cilium Gateway...", several "[ok] ensured ..." lines, the success
# banner, no "[Dry run - no changes made]" anywhere. Nothing broke, but only
# because those writes are idempotent; the flag had no part in it.
#
# What is asserted below is the flag doing the work, not the idempotence:
# every mutating step the reconcile path owns is stubbed to record that it was
# reached, and the fake API records every non-GET request. A dry run must reach
# none of them and issue none. The same run with the flag off must reach them —
# otherwise the first half would pass for the wrong reason.
#
# The list is the classification, arrived at by reading what each forwarder
# calls: _run_remedy (a Rex task over SSH), _setup_registry, _setup_nfd,
# _setup_gpu_operator, _apply_cert_manager + _wait_cert_manager_and_create_issuers
# (server-side applies), _configure_registry_dns (GET first, then a ConfigMap
# apply when it differs — the read half is what OCP::Drift does read-only
# anyway), _setup_cilium_gateway, _setup_lb_ipam, _ensure_crds,
# _ensure_providers (writes Secrets), _migrate_legacy_nodes, _ensure_cp_ocpnode,
# and _save_deployed_hash, which writes .ocp/deployed.yaml on disk.
#

my @WRITERS = qw(
    _run_remedy
    _setup_registry
    _configure_registry_dns
    _setup_nfd
    _setup_gpu_operator
    _apply_cert_manager
    _wait_cert_manager_and_create_issuers
    _save_deployed_hash
    _setup_cilium_gateway
    _setup_lb_ipam
    _ensure_crds
    _ensure_providers
    _migrate_legacy_nodes
    _ensure_cp_ocpnode
    _ensure_robocop_credentials
    _ensure_robocop
);

# What each stub hands back so the reconcile path keeps running realistically:
# the three hash-gated components report an outcome, the two "did you change
# anything" calls report no.
my %STUB_RETURN = (
    _setup_registry         => 'unchanged',
    _setup_nfd              => 'unchanged',
    _setup_gpu_operator     => 'unchanged',
    _configure_registry_dns => 0,
    _run_remedy             => 0,
);

my @touched;

package DryRunResponse {
    sub new     { bless {}, shift }
    sub status  { 200 }
    sub content { '{}' }
}
package DryRunApi {
    sub new { my ($c, %a) = @_; bless { writes => [], reads => [], objects => {}, %a }, $c }

    # Two call shapes reach this: get($kind, $name, %opts) from
    # _resource_exists, get($kind, name => ..., namespace => ...) from
    # OCP::Drift. Both are reads either way.
    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : undef;
        my %opts = @rest;
        $name //= $opts{name};
        my $key = join '/', $kind, $opts{namespace} // '-', $name // '';
        push @{ $self->{reads} }, "GET $key";
        my $obj = $self->{objects}{$key} or die "404 $key\n";
        return $obj;
    }

    # OCPNodes live in $self->{ocpnodes} (name => struct) so the worker step
    # can be watched: ensure() is the write, list() is what it reads.
    sub list {
        my ($self, $kind) = @_;
        push @{ $self->{reads} }, "LIST $kind";
        return FakeList->new([ map { $self->{ocpnodes}{$_} }
            sort keys %{ $self->{ocpnodes} } ]) if $kind eq 'OCPNode';
        return FakeList->new([]);
    }

    sub ensure {
        my ($self, $obj) = @_;
        push @{ $self->{writes} }, "ENSURE $obj->{kind}/$obj->{metadata}{name}";
        $self->{ocpnodes}{ $obj->{metadata}{name} } = $obj if $obj->{kind} eq 'OCPNode';
        return $obj;
    }

    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }

    sub expand_class { undef }

    sub _request {
        my ($self, $method, $path) = @_;
        push @{ $method eq 'GET' ? $self->{reads} : $self->{writes} }, "$method $path";
        return DryRunResponse->new;
    }
}
package ReconcileOcp {
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub load_file { return {} }
    sub dump_file { return 1 }
}

package main;

use OCP::Versions;

# The CRD OCP::Drift reads the Gateway API bundle version off (k164).
# Cluster-scoped, hence the '-' DryRunApi files a namespace-less GET under.
my $GATEWAY_CRD_KEY = 'CustomResourceDefinition/-/gateways.gateway.networking.k8s.io';

sub gateway_bundle {
    my ($version) = @_;
    return { metadata => { annotations => {
        'gateway.networking.k8s.io/bundle-version' => $version,
        'gateway.networking.k8s.io/channel'        => 'standard',
    } } };
}

# Permanent for the rest of this file — everything above has already run.
{
    no strict 'refs';
    no warnings 'redefine';
    *OCP::Cmd::Apply::_k8s_api      = sub { $_[0]{_k8s_api} };
    *OCP::Secrets::read_kubeconfig  = sub { "apiVersion: v1\nkind: Config\n" };
    for my $name (@WRITERS) {
        my $writer = $name;
        *{"OCP::Cmd::Apply::$writer"} = sub {
            push @touched, $writer;
            return exists $STUB_RETURN{$writer} ? $STUB_RETURN{$writer} : 1;
        };
    }
}

# The worker step's expensive ends, recorded instead of run: the robocop wait,
# the drive (a 600s poll or an SSH install per worker) and the key lookup that
# can cost a PIN2 prompt. $ROBOCOP_READY, $DRIVE_PHASE and $KEY_FAILS steer
# them per test; @driven and $key_asked say what was reached.
our ($ROBOCOP_READY, $DRIVE_PHASE, $KEY_FAILS) = (0, 'Ready', 0);
my (@driven, $key_asked);
{
    no warnings qw( redefine once );
    *OCP::Cmd::Apply::_wait_robocop_ready = sub {
        push @touched, '_wait_robocop_ready';
        return $ROBOCOP_READY;
    };
    *OCP::Cmd::Apply::_drive_workers = sub {
        my ($self, $api, $config, $deps) = @_;
        push @touched, '_drive_workers';
        push @driven, { %$deps };
        return map { { name => $_, phase => $DRIVE_PHASE, message => '' } }
            @{ $deps->{names} };
    };
    *OCP::Cmd::Apply::cluster_ssh_key = sub {
        $key_asked++;
        die "no key for you\n" if $KEY_FAILS;
        return bless { path => '/nonexistent/cluster-key' }, 'FakeClusterKey';
    };
    *FakeClusterKey::path = sub { $_[0]{path} };
}

sub reconcile {
    my (%opt) = @_;

    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew(<<'YAML' . ($opt{yaml} // ''));
name: cortex
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: cortex.ocp.invalid
lbipam: true
YAML
    $dir->child('.ocp')->mkpath;
    $dir->child('.ocp', 'status.yaml')->spew(<<'YAML');
nodes:
  - name: cortex
    role: control-plane
    public_ip: 10.230.30.155
YAML

    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    my $apply  = OCP::Cmd::Apply->new(
        command_chain => [ ReconcileOcp->new ],
        dry_run       => $opt{dry_run} ? 1 : 0,
        ($opt{only} ? (only => $opt{only}) : ()),
    );
    $apply->{_k8s_api} = DryRunApi->new(
        # The Gateway API CRDs at the pin, as install_cilium leaves them: a
        # cluster without them is drifted with a Rex remedy (k164), which
        # every test here would otherwise count as unresolved.
        objects  => { $GATEWAY_CRD_KEY => gateway_bundle(
                          OCP::Versions->get_component_version('gateway_api')),
                      %{ $opt{objects} // {} } },
        ocpnodes => { map { $_ => {
            apiVersion => 'ocp.internal/v1',
            kind       => 'OCPNode',
            metadata   => { name => $_, namespace => 'ocp-system' },
            spec       => { role => 'worker', providerRef => 'ssh-default' },
            status     => { phase => 'Ready' },
        } } @{ $opt{ocpnodes} // [] } },
    );

    @touched = ();
    @driven  = ();
    $key_asked = 0;
    my $err = '';
    my ($out, $result);
    {
        open my $efh, '>', \$err or die $!;
        local *STDERR = $efh;
        ($out, $result) = capture_stdout { $apply->_reconcile_components($config) };
    }

    return {
        out       => $out,
        err       => $err,
        result    => $result,
        writes    => $apply->{_k8s_api}{writes},
        reads     => $apply->{_k8s_api}{reads},
        touched   => [@touched],
        driven    => [@driven],
        key_asked => $key_asked,
    };
}

sub touched { my ($r, $step) = @_; scalar grep { $_ eq $step } @{ $r->{touched} } }

subtest 'a dry run against an existing cluster writes nothing' => sub {
    my $r = reconcile(dry_run => 1);

    is_deeply $r->{touched}, [],
        'not one mutating step of the reconcile path was reached';
    is_deeply $r->{writes}, [],
        'and nothing but GETs reached the API';

    ok scalar @{ $r->{reads} },
        'it did look at the cluster — reading is how it can say anything at all';

    like $r->{out}, qr/\[Dry run - no changes made\]/,
        'it ends the way the bootstrap path already ends a dry run';
    ok !$r->{result},
        'and returns falsy, so execute stops short of the health gate';
};

subtest 'the same run with the flag off does write' => sub {
    my $r = reconcile(dry_run => 0);

    ok scalar @{ $r->{touched} },
        'the mutating steps are reachable — the dry run is not passing by accident';

    for my $step (qw(_setup_registry _setup_nfd _setup_gpu_operator
                     _setup_cilium_gateway _setup_lb_ipam _configure_registry_dns
                     _ensure_crds _ensure_cp_ocpnode)) {
        ok scalar(grep { $_ eq $step } @{ $r->{touched} }), "$step runs normally";
    }

    unlike $r->{out}, qr/\[Dry run/, 'and it does not claim to have been a dry run';
};

subtest 'a dry run reports what a real run would act on' => sub {
    my $r = reconcile(dry_run => 1);

    # The fake cluster has no cilium-operator and no cert-manager, which the
    # detector reads as "not deployed".
    like $r->{out}, qr/\[drift\] Cilium is not deployed/, 'names what differs';
    like $r->{out}, qr/difference\(s\) a real run would act on/, 'and counts it';

    # The blind spot, stated rather than implied: a manifest that changed
    # without its version changing is only visible to the deploy step itself.
    like $r->{out}, qr/manifest changed at an\s+unchanged version/,
        'the caveat is printed, not left for the user to discover';
};

#
# Drift with no Rex task behind it is not automatically drift a human has to
# act on. The GPU-stack probes carry no remedy — nothing upgrades NFD or the
# GPU operator in place — but their version sits in a manifest this very run
# regenerates and re-applies. Telling the user to go and run `ocp update`
# two lines before rolling the new version out would be advice against the
# machine's own behaviour.
#
subtest 'a difference this run closes is not sent to ocp update' => sub {
    my $r = reconcile(objects => {
        'Deployment/node-feature-discovery/nfd-master' => {
            spec => { template => { spec => { containers => [
                { image => 'registry.k8s.io/nfd/node-feature-discovery:v0.17.0' },
            ] } } },
        },
    });

    like $r->{out}, qr/\[drift\] NFD runs v0\.17\.0/, 'the outdated NFD is reported';
    unlike $r->{out}, qr/ocp update/,
        'and not handed to a command that would not fix it';
};

#
# k164: a bump of only the Gateway API pin used to be invisible — every probe
# read an image, and the CRD bundle has none. The drift entry it now gets
# carries a Rex remedy, so the reconcile path runs it like the Cilium upgrade,
# and a dry run names it without running it.
#
subtest 'k164: an outdated Gateway API bundle is repaired through its Rex task' => sub {
    my $old = { $GATEWAY_CRD_KEY => gateway_bundle('v1.2.0') };

    my $r = reconcile(objects => $old);
    like $r->{out}, qr/\[drift\] Gateway API CRD bundle runs v1\.2\.0, expected v1\.6\.1/,
        'the outdated bundle is reported';
    like $r->{out}, qr/Running update_gateway_api/, 'and its task is run';
    ok touched($r, '_run_remedy'), 'through the remedy step';

    my $dry = reconcile(objects => $old, dry_run => 1);
    like $dry->{out}, qr/would run update_gateway_api/, 'a dry run names the task';
    ok !touched($dry, '_run_remedy'), 'and does not run it';
};

subtest 'k164: a bundle at the pin is left alone' => sub {
    my $r = reconcile();
    unlike $r->{out}, qr/Gateway API CRD bundle/, 'no finding';
    ok !touched($r, '_run_remedy'), 'no remedy';
};

#
# k26: workers on a cluster that already exists.
#
# The reconcile path used to leave workers out entirely, so a worker added to
# ocp.yaml after bootstrap got no OCPNode, no machine and no message — on
# cortex, `ocp apply --only workers` printed "All 8 component(s) up to date"
# over a `brain` entry it had silently ignored. Maintainer decision
# 2026-09-24: the OCPNode is the reflection of desired state and goes hand in
# hand with the k8s Node. A worker in ocp.yaml without one is created on this
# path too, through the same CR-driven worker step the fresh deploy runs.
# Workers that already have one are not driven again — re-driving means
# re-provisioning and a 600s wait each — and when nothing is missing the path
# costs nothing beyond one list.
#

# nocert keeps cert-manager (never "up to date" against this fake cluster)
# out of the summary counts these tests read.
my $TWO_SSH_WORKERS = <<'YAML';
nocert: true
workers:
  - name: gpu
    provider: ssh
    nodes:
      - brain.ocp.invalid
      - pinky.ocp.invalid
YAML

subtest 'k26: a worker without an OCPNode is created, the others are left alone' => sub {
    my $r = reconcile(yaml => $TWO_SSH_WORKERS, ocpnodes => ['brain']);

    ok scalar(grep { $_ eq 'ENSURE OCPNode/pinky' } @{ $r->{writes} }),
        'the missing worker gets its OCPNode';
    ok !scalar(grep { $_ eq 'ENSURE OCPNode/brain' } @{ $r->{writes} }),
        'the existing worker\'s OCPNode is not rewritten';

    is scalar @{ $r->{driven} }, 1, 'the worker step is driven once';
    is_deeply $r->{driven}[0]{names}, ['pinky'],
        'and only for the missing worker — brain is not re-driven';
    is $r->{driven}[0]{cp_ip}, '10.230.30.155',
        'workers join the control plane the status file names';

    like $r->{out}, qr/pinky/, 'progress names the worker being created';
    like $r->{out}, qr/1 component\(s\) updated/,
        'a worker brought up counts as an update in the summary';
    is $r->{err}, '', 'nothing went wrong, nothing on STDERR';
};

subtest 'k26: nothing missing means no worker step at all' => sub {
    my $r = reconcile(yaml => $TWO_SSH_WORKERS, ocpnodes => ['brain', 'pinky']);

    ok !scalar(grep { /^ENSURE OCPNode/ } @{ $r->{writes} }), 'no OCPNode written';
    ok !touched($r, '_drive_workers'),      'no worker driven';
    ok !touched($r, '_ensure_robocop'),     'no robocop rollout';
    ok !touched($r, '_wait_robocop_ready'), 'no robocop wait';
    ok !$r->{key_asked}, 'and no key asked for (no PIN2 prompt)';
    like $r->{out}, qr/All \d+ component\(s\) up to date/, 'the summary stays clean';
};

subtest 'k26: no workers in ocp.yaml, path unchanged' => sub {
    my $r = reconcile();

    ok !scalar(grep { $_ eq 'LIST OCPNode' } @{ $r->{reads} }),
        'OCPNodes are not even listed';
    ok !touched($r, '_drive_workers') && !touched($r, '_ensure_robocop')
        && !touched($r, '_wait_robocop_ready'), 'no worker step';
    unlike $r->{out}, qr/worker/i, 'and no worker line in the output';
};

subtest 'k26: robocop drives the new worker when it is enabled' => sub {
    local $ROBOCOP_READY = 1;
    my $r = reconcile(yaml => "robocop: true\n" . $TWO_SSH_WORKERS, ocpnodes => ['brain']);

    ok touched($r, '_ensure_robocop'),     'robocop is ensured';
    ok touched($r, '_wait_robocop_ready'), 'and waited for';

    # k169: its credentials Secret first -- the Deployment mounts it, and a
    # pod started without it never runs. What the Secret carries, and when it
    # costs a key, is t/169's business; here only the order.
    my @order = grep { /^_ensure_robocop/ } @{ $r->{touched} };
    is_deeply \@order, [ '_ensure_robocop_credentials', '_ensure_robocop' ],
        'the credentials Secret is ensured before the Deployment';
    ok $r->{driven}[0]{robocop_ready}, 'the drive polls robocop instead of the CLI';
    ok !$r->{key_asked}, 'no SSH key needed when robocop does the work';
};

subtest 'k26: the CLI fallback gets the cluster key only when it needs it' => sub {
    my $r = reconcile(yaml => $TWO_SSH_WORKERS, ocpnodes => ['brain']);

    ok !$r->{driven}[0]{robocop_ready}, 'robocop off: CLI fallback';
    is $r->{key_asked}, 1, 'the key is asked for once';
    is $r->{driven}[0]{ssh_key_path}, '/nonexistent/cluster-key',
        'and handed to the drive as a path';

    local $KEY_FAILS = 1;
    my $nokey = reconcile(yaml => $TWO_SSH_WORKERS, ocpnodes => ['brain']);
    ok !touched($nokey, '_drive_workers'), 'no key, no drive';
    like $nokey->{err}, qr/pinky/,        'the failure names the worker on STDERR';
    like $nokey->{err}, qr/no key for you/, 'with the diagnosis';
    like $nokey->{out}, qr/did NOT bring the cluster back to spec/,
        'and the summary does not claim success';
};

subtest 'k26: a worker that does not come up is not reported as up to date' => sub {
    local $DRIVE_PHASE = 'Failed';
    my $r = reconcile(yaml => $TWO_SSH_WORKERS, ocpnodes => ['brain']);

    unlike $r->{out}, qr/All \d+ component\(s\) up to date/, 'no clean summary';
    like $r->{out}, qr/left as they were: .*pinky/, 'the worker is named as unresolved';
};

subtest 'k26: --dry-run names the worker it would create and creates nothing' => sub {
    my $r = reconcile(dry_run => 1, yaml => $TWO_SSH_WORKERS, ocpnodes => ['brain']);

    is_deeply $r->{writes}, [], 'nothing written';
    is_deeply $r->{touched}, [], 'no step reached, no robocop, no drive';
    ok !$r->{key_asked}, 'no key asked for';
    like $r->{out}, qr/would create OCPNode\/pinky/, 'the missing worker is named';
    unlike $r->{out}, qr/OCPNode\/brain/, 'the existing one is not';
    like $r->{out}, qr/\[Dry run - no changes made\]/, 'still a dry run';
};

subtest 'k26: --only gates the worker step the way the deploy path does' => sub {
    my $cp = reconcile(only => 'control-planes',
        yaml => $TWO_SSH_WORKERS, ocpnodes => ['brain']);
    ok !scalar(grep { /^ENSURE OCPNode/ } @{ $cp->{writes} }),
        '--only control-planes creates no worker';
    ok !touched($cp, '_drive_workers'), 'and drives none';

    my $w = reconcile(only => 'workers',
        yaml => $TWO_SSH_WORKERS, ocpnodes => ['brain']);
    ok scalar(grep { $_ eq 'ENSURE OCPNode/pinky' } @{ $w->{writes} }),
        '--only workers creates the missing one';

    my $dry = reconcile(dry_run => 1, only => 'control-planes',
        yaml => $TWO_SSH_WORKERS, ocpnodes => ['brain']);
    unlike $dry->{out}, qr/would create OCPNode/, 'and the dry run agrees';
};

#
# k173: robocop is made sure of on every apply, workers or not.
#
# robocop used to be rolled out only inside the worker step, which the
# reconcile path reaches only for a missing worker. So `robocop: true` without
# workers never got a robocop, and a cluster left with the Deployment but no
# credentials Secret (k169) was never repaired by apply. Maintainer decision:
# `robocop.enabled` means robocop runs -- every apply ensures Secret and
# Deployment, once per run, behind the worker gate of --only. What the Secret
# carries and when writing it costs a key is t/169's business; here only
# whether and how often the step is reached.
#

sub robocop_steps { [ grep { /^_ensure_robocop/ } @{ $_[0]{touched} } ] }

subtest 'k173: robocop without workers is ensured on reconcile' => sub {
    my $r = reconcile(yaml => "robocop: true\nnocert: true\n");

    is_deeply robocop_steps($r), [ '_ensure_robocop_credentials', '_ensure_robocop' ],
        'Secret, then Deployment';
    is touched($r, '_wait_robocop_ready'), 1, 'readiness looked at once, not waited for';
    ok !touched($r, '_drive_workers'), 'no worker driven';
    ok !$r->{key_asked}, 'no cluster key asked for (no PIN2 prompt)';
    like $r->{out}, qr/Checking robocop/, 'the step is named in the progress';
    like $r->{out}, qr/1 component\(s\) updated/,
        'a Deployment that was not there counts as an update';
    is $r->{err}, '', 'nothing on STDERR';
};

subtest 'k173: a running robocop with nothing to write is up to date' => sub {
    local $ROBOCOP_READY = 1;
    my $r = reconcile(yaml => "robocop: true\nnocert: true\n",
        objects => { 'Deployment/ocp-system/robocop' => { kind => 'Deployment' } });

    is scalar @{ robocop_steps($r) }, 2, 'still re-applied, like every component';
    like $r->{out}, qr/robocop ready/, 'reported ready';
    like $r->{out}, qr/All \d+ component\(s\) up to date/, 'and not counted as a change';
};

subtest 'k173: nothing missing among the workers -- robocop still ensured' => sub {
    my $r = reconcile(yaml => "robocop: true\n" . $TWO_SSH_WORKERS,
        ocpnodes => ['brain', 'pinky']);

    is_deeply robocop_steps($r), [ '_ensure_robocop_credentials', '_ensure_robocop' ],
        'robocop is ensured';
    ok !touched($r, '_drive_workers'), 'no worker driven';
    is touched($r, '_wait_robocop_ready'), 1, 'and no 60s wait -- nothing for it to drive';
};

subtest 'k173: with a missing worker robocop is ensured once, not twice' => sub {
    my $r = reconcile(yaml => "robocop: true\n" . $TWO_SSH_WORKERS, ocpnodes => ['brain']);

    is_deeply robocop_steps($r), [ '_ensure_robocop_credentials', '_ensure_robocop' ],
        'one rollout per run';
    my @deploying = $r->{out} =~ /Deploying robocop controller/g;
    is scalar @deploying, 1, 'and one progress line for it';
    is touched($r, '_wait_robocop_ready'), 2,
        'one look, then the wait the worker step needs to decide who drives';
    ok !$r->{driven}[0]{robocop_ready}, 'not ready: the CLI drives';
};

subtest 'k173: a robocop that cannot be deployed is unresolved, workers go to the CLI' => sub {
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_ensure_robocop_credentials = sub {
        push @touched, '_ensure_robocop_credentials';
        die "Wrong PIN2\n";
    };
    my $r = reconcile(yaml => "robocop: true\n" . $TWO_SSH_WORKERS, ocpnodes => ['brain']);

    ok !touched($r, '_ensure_robocop'), 'no Deployment without its Secret';
    like $r->{err}, qr/robocop deploy failed: Wrong PIN2/, 'STDERR, with the reason';
    ok !touched($r, '_wait_robocop_ready'), 'nothing waited for';
    ok !$r->{driven}[0]{robocop_ready}, 'the CLI drives the missing worker';
    like $r->{out}, qr/left as they were: robocop/, 'robocop is named as unresolved';
};

subtest 'k173: robocop disabled -- not rolled out, not torn down' => sub {
    my $r = reconcile(yaml => "robocop: false\nnocert: true\n",
        objects => { 'Deployment/ocp-system/robocop' => { kind => 'Deployment' } });

    is_deeply robocop_steps($r), [], 'no robocop step';
    unlike $r->{out}, qr/robocop/i, 'and no robocop line';
    ok !scalar(grep { /DELETE/ } @{ $r->{writes} }), 'nothing deleted';
};

subtest 'k173: robocop sits behind the worker gate of --only' => sub {
    my $cp = reconcile(only => 'control-planes', yaml => "robocop: true\n");
    is_deeply robocop_steps($cp), [], '--only control-planes leaves robocop alone';

    my $w = reconcile(only => 'workers', yaml => "robocop: true\n");
    is scalar @{ robocop_steps($w) }, 2, '--only workers ensures it';
};

subtest 'k173: --dry-run names what robocop is missing and writes nothing' => sub {
    my $r = reconcile(dry_run => 1, yaml => "robocop: true\n");

    is_deeply $r->{writes},  [], 'nothing written';
    is_deeply $r->{touched}, [], 'no step reached';
    ok !$r->{key_asked}, 'no key asked for';
    like $r->{out}, qr{Secret/robocop-credentials is missing\s+would write it \(secret\)},
        'the missing Secret is named';
    like $r->{out}, qr{Deployment/robocop is missing\s+would roll it out},
        'the missing Deployment too';

    my $cp = reconcile(dry_run => 1, only => 'control-planes', yaml => "robocop: true\n");
    unlike $cp->{out}, qr/robocop/, '--only control-planes: not even reported';
};

subtest 'k173: --dry-run on the k169 leftover -- Deployment there, Secret not' => sub {
    my $r = reconcile(dry_run => 1, yaml => "robocop: true\n",
        objects => { 'Deployment/ocp-system/robocop' => { kind => 'Deployment' } });

    like $r->{out}, qr{Secret/robocop-credentials is missing}, 'the Secret is named';
    unlike $r->{out}, qr{Deployment/robocop is missing}, 'the Deployment is not';
};

#
# k173 on the fresh deploy: robocop gets a step of its own, workers or not,
# between the control-plane joins and the workers.
#

sub deploy {
    my (%opt) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew(<<'YAML' . ($opt{yaml} // ''));
name: cortex
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: cortex.ocp.invalid
nocert: true
YAML
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    my $apply  = OCP::Cmd::Apply->new(
        command_chain => [ ReconcileOcp->new ],
        ($opt{only} ? (only => $opt{only}) : ()),
    );
    my $api = DryRunApi->new(objects => {});
    $apply->{_k8s_api} = $api;

    @touched = ();
    @driven  = ();
    my ($out, $step);
    {
        my $err = '';
        open my $efh, '>', \$err or die $!;
        local *STDERR = $efh;
        ($out, $step) = capture_stdout {
            OCP::Cmd::Apply::Deploy::deploy($apply, {
                config       => $config,
                secrets      => OCP::Secrets->new(project_dir => $dir),
                api          => $api,
                cp_name      => 'cortex',
                cp_ip        => '10.230.30.155',
                provider     => 'ssh',
                ssh_key_path => '/nonexistent/key',
                deploy_step  => 2,
            });
        };
    }
    return { out => $out, step => $step, touched => [@touched], driven => [@driven] };
}

subtest 'k173: fresh deploy without workers rolls robocop out' => sub {
    my $r = deploy(yaml => "robocop: true\n");

    is_deeply robocop_steps($r), [ '_ensure_robocop_credentials', '_ensure_robocop' ],
        'Secret, then Deployment';
    like $r->{out}, qr/Step 4: Deploy robocop controller/, 'in a step of its own';
    unlike $r->{out}, qr/Deploy workers/, 'no worker step';
    is $r->{step}, 5, 'the health gate follows as step 5';
    ok !touched($r, '_drive_workers'), 'nothing driven';
};

subtest 'k173: fresh deploy with workers rolls robocop out once, before them' => sub {
    local $ROBOCOP_READY = 1;
    my $r = deploy(yaml => "robocop: true\n" . <<'YAML');
workers:
  - name: gpu
    provider: ssh
    nodes:
      - brain.ocp.invalid
YAML

    is scalar @{ robocop_steps($r) }, 2, 'ensured once';
    like $r->{out}, qr/Step 4: Deploy robocop controller.*Step 5: Deploy workers/s,
        'robocop first, then the workers';
    is $r->{step}, 6, 'the health gate follows as step 6';
    ok $r->{driven}[0]{robocop_ready}, 'the ready robocop drives';
};

subtest 'k173: fresh deploy, robocop off or gated away: no robocop step' => sub {
    my $off = deploy();
    is_deeply robocop_steps($off), [], 'robocop disabled: nothing';
    is $off->{step}, 4, 'step count as before';

    my $cp = deploy(yaml => "robocop: true\n", only => 'control-planes');
    is_deeply robocop_steps($cp), [], '--only control-planes: nothing';
};

done_testing;

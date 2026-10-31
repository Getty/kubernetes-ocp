#!/usr/bin/env perl
use strict;
use warnings;

# Both wait loops this file runs for real pace themselves with sleep: `ocp node
# add` waits 5s before it polls robocop's CR, OCP::Node 5s between reconciles.
# Nothing here waits for anything that takes time, so sleep returns at once --
# set before the modules below are compiled, or they would keep the real one.
BEGIN { *CORE::GLOBAL::sleep = sub { 0 } }

use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Choices;
use OCP::Config;
use OCP::Secrets;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::AMDGPU;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Deploy;
use OCP::Cmd::Node::Add;
use OCP::Node;

no warnings 'once';

#
# k254, apply lane: the node-ip -- the address a node registers as its
# InternalIP -- from where the operator gives it to where it is installed and
# checked.
#
# Live 2026-10-31: synapse, joined by 10.230.30.50 (cluster VLAN), registered
# 192.168.0.165 (its default route). The control plane could not reach that,
# Cilium's tunnel broke one way, and the node showed Ready while OCP reported
# success.
#
# The claims here:
#   1. `ocp node add --node_ip` writes spec.nodeIP, refuses a malformed one
#      before the API is asked, and writes nothing without it;
#   2. once the node is Ready, a node that did not register at its node-ip is
#      said on STDERR as "[WARN] <name>: <diagnosis>" exactly once, whoever
#      drove the join -- OCP::Node on the CLI path (it says it at the Ready
#      transition, through the logger the command hands it), the command
#      itself with robocop running or for a node Ready already -- and the exit
#      code stays that of a Ready node;
#   3. `ocp apply`: an additional control plane's OCPNode carries its
#      control_planes[].node_ip, the bootstrapped one's carries
#      control_planes[0].node_ip as spec.nodeIP and, written by the run that
#      installed it, as status.nodeIP;
#   4. the bootstrap installs police1 with control_planes[0].node_ip when set
#      and with none otherwise, and checks the Ready Node against it;
#   5. a reconcile `ocp apply` keeps spec.nodeIP on police1's OCPNode -- the
#      ensure replaces the spec -- and claims no status.nodeIP, installing
#      nothing;
#   6. an additional control plane `ocp apply` joins says its mismatch as the
#      same "[WARN] <name>: <diagnosis>" on STDERR as `ocp node add`.
#
# The diagnosis is OCP::Node->node_ip_mismatch's (state lane); this file holds
# where it goes, not its words.
#

my $ASKED = '10.230.30.50';
my $WRONG = '192.168.0.165';

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

# What a node registered at $WRONG is told, in OCP::Node's words.
my $DIAG = OCP::Node->node_ip_mismatch(node_with('x', $WRONG), $ASKED);
ok defined $DIAG && $DIAG =~ /\Q$WRONG\E/ && $DIAG =~ /\Q$ASKED\E/,
    'premise: OCP::Node names both addresses for a node registered elsewhere'
    or diag $DIAG;
ok !defined OCP::Node->node_ip_mismatch(node_with('x', $ASKED), $ASKED),
    'premise: and nothing for one registered where it was told';

# =============================================================================
# 1. ocp node add --node_ip
# =============================================================================

package FakeIO   { sub new { bless {}, shift } sub object_to_struct { $_[1] } }
package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }

# A cluster with one ssh provider, OCPNodes and Nodes. ensure() replaces an
# OCPNode's spec and keeps its status (the status subresource); patch_status()
# merges into the status, undef deleting -- the API server's two writes.
package AddApi {
    my $io = FakeIO->new;
    sub new {
        my ($c, %a) = @_;
        return bless { ocpnodes => {}, nodes => {}, calls => [], %a }, $c;
    }
    sub k8s { $io }
    sub list {
        my ($self, $kind) = @_;
        push @{ $self->{calls} }, [ 'list', $kind ];
        return FakeList->new([ $self->provider ]) if $kind eq 'OCPNodeProvider';
        return FakeList->new([]);
    }
    sub provider {
        return { metadata => { name => 'ssh-default', annotations => {} },
                 spec     => { type => 'ssh' } };
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
            return { %$cr, status => { %{ $cr->{status} // {} } } };
        }
        if ($kind eq 'Node') {
            die $self->{node_error} if $self->{node_error};
            return $self->{nodes}{$name} // die "404 Node $name not found\n";
        }
        return undef;
    }
    sub ensure {
        my ($self, $obj) = @_;
        push @{ $self->{calls} }, [ 'ensure', $obj ];
        my $old = $self->{ocpnodes}{ $obj->{metadata}{name} } // {};
        $self->{ocpnodes}{ $obj->{metadata}{name} } = {
            %$obj, ($old->{status} ? (status => $old->{status}) : ()),
        };
        return $obj;
    }
    sub patch_status {
        my ($self, $kind, %a) = @_;
        push @{ $self->{calls} }, [ 'patch_status', $kind, $a{name} ];
        my $status = $self->{ocpnodes}{ $a{name} }{status} //= {};
        while (my ($k, $v) = each %{ $a{patch}{status} }) {
            defined $v ? ($status->{$k} = $v) : delete $status->{$k};
        }
        return 1;
    }
    sub patch { push @{ $_[0]{calls} }, [ 'patch', $_[1] ]; return {} }
}

# The project as `ocp node add` reads it: no control-plane address recorded,
# so the CLI path opens no SSH and reads no join token -- this file is about
# what happens once the node registers, not about the join.
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

sub add_cmd {
    my ($api, %opt) = @_;
    return OCP::Cmd::Node::Add->new(
        k8s      => $api,
        name     => 'synapse',
        provider => 'ssh-default',
        host     => $ASKED,
        %opt,
    );
}

sub run_add {
    my ($api, %opt) = @_;
    my $add = add_cmd($api, %opt);
    no warnings 'redefine';
    local *OCP::Cmd::Node::Add::_config = sub { AddConfig->new };
    return capture { $add->execute([], []) };
}

sub ensured_cr {
    my ($api) = @_;
    my ($call) = grep { $_->[0] eq 'ensure' } @{ $api->{calls} };
    return $call ? $call->[1] : undef;
}

sub warn_lines { my ($err) = @_; return grep { /^\[WARN\] / } split /\n/, $err }

subtest '--node_ip goes into spec.nodeIP as written' => sub {
    for my $ip ($ASKED, "$ASKED,fd00::50", 'fd00::50') {
        my $api = AddApi->new;
        my $r   = run_add($api, node_ip => $ip, nowait => 1);
        is $r->{died}, '', "--node_ip $ip accepted" or next;
        is ensured_cr($api)->{spec}{nodeIP}, $ip, "spec.nodeIP is '$ip'";
    }
};

subtest 'without --node_ip the OCPNode asks for none' => sub {
    my $api = AddApi->new;
    my $r   = run_add($api, nowait => 1);
    is $r->{died}, '', 'node add ran' or return;
    ok !exists ensured_cr($api)->{spec}{nodeIP}, 'no spec.nodeIP -- no default of any kind';
};

subtest 'a malformed --node_ip is refused before the API is asked' => sub {
    for my $bad ('synapse.lan', '10.230.30.50/24', '127.0.0.1', '10.0.0.1, fd00::1', '') {
        my $want = OCP::Choices::node_ip_error($bad);
        ok defined $want, "premise: '$bad' is malformed" or next;

        my $cmd = add_cmd(undef, node_ip => $bad);
        no warnings 'redefine';
        local *OCP::Cmd::Node::Add::_k8s = sub { die "the API was asked\n" };
        my $r = capture { $cmd->execute([], []) };
        is $r->{died}, "--node_ip: $want\n",
            "'$bad': dies with OCP::Choices' line under the option's name, the API unasked";
    }
};

# --- 2a. robocop drives the join ----------------------------------------------

sub robocop_api {
    my (%o) = @_;
    my $api = AddApi->new(robocop => 1, %o);
    # robocop's work, done: the OCPNode is Ready when node add first looks.
    $api->{ocpnodes}{synapse} = {
        metadata => { name => 'synapse', namespace => 'ocp-system' },
        status   => { phase => 'Ready', message => 'Node joined and Ready',
                      kubernetesNodeName => $o{k8s_name} // 'synapse',
                      ($o{status_node_ip} ? (nodeIP => $o{status_node_ip}) : ()) },
    };
    return $api;
}

subtest 'robocop path: registered elsewhere -> one [WARN] on STDERR, exit 0' => sub {
    my $api = robocop_api(status_node_ip => $ASKED);
    $api->{nodes}{synapse} = node_with('synapse', $WRONG);
    my $r = run_add($api, node_ip => $ASKED);

    is $r->{died}, '', 'node add ran' or return diag $r->{died};
    is $r->{rv}, 0, 'exit 0: the node is Ready, which is what node add promised';
    is_deeply [ warn_lines($r->{err}) ], [ "[WARN] synapse: $DIAG" ],
        'one line, "[WARN] <name>: <diagnosis>"';
    unlike $r->{out}, qr/\[WARN\]/, 'not on STDOUT';
    like $r->{out}, qr/Node 'synapse' is Ready\./, 'the Ready line stands';
};

subtest 'robocop path: a robocop that predates k254 records no status.nodeIP' => sub {
    # It hands no node-ip either, so its node registers on its default route
    # -- the case the check is for. Held against what node add asked for.
    my $api = robocop_api();
    $api->{nodes}{synapse} = node_with('synapse', $WRONG);
    my $r = run_add($api, node_ip => $ASKED);
    is_deeply [ warn_lines($r->{err}) ], [ "[WARN] synapse: $DIAG" ], 'still said, once';
};

subtest 'robocop path: the Node is read by status.kubernetesNodeName' => sub {
    my $api = robocop_api(status_node_ip => $ASKED, k8s_name => 'synapse.ai.lab');
    $api->{nodes}{'synapse.ai.lab'} = node_with('synapse.ai.lab', $WRONG);
    my $r = run_add($api, node_ip => $ASKED);
    is_deeply [ warn_lines($r->{err}) ], [ "[WARN] synapse: $DIAG" ],
        'the Node the OCPNode names, the warning under the OCPNode\'s name';
};

subtest 'robocop path: registered where it was told -> nothing said' => sub {
    my $api = robocop_api(status_node_ip => $ASKED);
    $api->{nodes}{synapse} = node_with('synapse', $ASKED);
    my $r = run_add($api, node_ip => $ASKED);
    is $r->{rv}, 0, 'exit 0';
    is $r->{err}, '', 'STDERR empty';
};

subtest 'robocop path: no --node_ip -> no check, no Node read' => sub {
    my $api = robocop_api();
    $api->{nodes}{synapse} = node_with('synapse', $WRONG);
    my $r = run_add($api);
    is $r->{rv}, 0, 'exit 0';
    is $r->{err}, '', 'nothing said';
    ok !(grep { $_->[0] eq 'get' && $_->[1] eq 'Node' } @{ $api->{calls} }),
        'the Node was not asked for';
};

subtest 'robocop path: a Node that cannot be read is said, not passed' => sub {
    my $api = robocop_api(status_node_ip => $ASKED, node_error => "503 apiserver busy\n");
    my $r = run_add($api, node_ip => $ASKED);
    is $r->{rv}, 0, 'still exit 0: the node is Ready';
    is_deeply [ warn_lines($r->{err}) ],
        [ "[WARN] synapse: InternalIP not checked against --node_ip $ASKED: "
          . "Node 'synapse' could not be read: 503 apiserver busy" ],
        'the check that did not happen is named, with why';
};

# --- 2b. the CLI drives the join (robocop not running) ------------------------
#
# The real OCP::Node, on an OCPNode its install already took to Joining with
# status.nodeIP recorded: the next reconcile finds the Node Ready, and that is
# where OCP::Node holds it against the node-ip and warns through its logger.

sub cli_api {
    my (%o) = @_;
    my $api = AddApi->new;
    $api->{ocpnodes}{synapse} = {
        metadata => { name => 'synapse', namespace => 'ocp-system' },
        status   => { phase => $o{phase} // 'Joining', nodeIP => $ASKED,
                      ($o{phase} && $o{phase} eq 'Ready'
                          ? (kubernetesNodeName => 'synapse',
                             message => 'Node joined and Ready') : ()) },
    };
    $api->{nodes}{synapse} = node_with('synapse', $o{registered} // $WRONG);
    return $api;
}

subtest 'CLI path: OCP::Node turns it Ready here -> its warning, once, as [WARN]' => sub {
    my $api = cli_api();
    my $r   = run_add($api, node_ip => $ASKED);

    is $r->{died}, '', 'node add ran' or return diag $r->{died};
    is $r->{rv}, 0, 'exit 0';
    is $api->{ocpnodes}{synapse}{status}{phase}, 'Ready', 'premise: the reconcile turned it Ready';
    is_deeply [ warn_lines($r->{err}) ], [ "[WARN] synapse: $DIAG" ],
        'one [WARN] line -- OCP::Node\'s, through the logger node add hands it';
    unlike $r->{err}, qr/\[node\]/, 'not the logger-less "[node] ..." form besides';
    is scalar(() = $r->{err} =~ /\Q$WRONG\E/g), 1, 'the diagnosis is on STDERR once';
};

subtest 'CLI path: registered where it was told -> nothing said' => sub {
    my $api = cli_api(registered => $ASKED);
    my $r   = run_add($api, node_ip => $ASKED);
    is $r->{rv}, 0, 'exit 0';
    is $r->{err}, '', 'STDERR empty';
};

subtest 'CLI path: a node Ready from the start is checked by node add itself' => sub {
    # No Ready transition happens in this run, so OCP::Node says nothing.
    my $api = cli_api(phase => 'Ready');
    my $r   = run_add($api, node_ip => $ASKED);
    is $r->{rv}, 0, 'exit 0';
    is_deeply [ warn_lines($r->{err}) ], [ "[WARN] synapse: $DIAG" ], 'said once all the same';
};

subtest 'the logger node add and ocp apply hand OCP::Node' => sub {
    my $log = OCP::Cmd::Apply::CR::node_logger();
    my $r = capture { $log->(warn => 'synapse: something'); $log->(info => 'host key of synapse pinned') };
    is $r->{err}, "[WARN] synapse: something\n[node] host key of synapse pinned\n",
        'a warning as [WARN], a note as OCP::Node writes it without one; both on STDERR';
    is $r->{out}, '', 'nothing on STDOUT';
};

# =============================================================================
# 3. ocp apply: the control planes' OCPNodes
# =============================================================================

package CrApi {
    sub new { bless { ensured => [], statuses => [] }, shift }
    sub k8s { FakeIO->new }
    sub ensure { push @{ $_[0]{ensured} }, $_[1]; $_[1] }
    sub patch_status {
        my ($self, $kind, %a) = @_;
        push @{ $self->{statuses} }, $a{patch}{status};
        return 1;
    }
    sub get { die "404 not found\n" }
}

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
kubernetes:
  dist: rke2
control_planes:
  - provider: ssh
    host: otho.lab
    node_ip: 10.230.30.52
  - provider: ssh
    host: crag.lab
    node_ip: 10.230.30.54,fd00::54
  - provider: ssh
    host: brain.lab
YAML

subtest 'additional control planes carry their own node_ip' => sub {
    my $api = CrApi->new;
    my @crs;
    capture { @crs = OCP::Cmd::Apply::CR::ensure_control_plane_ocpnodes(undef, $api, config_for($HA)) };
    my %by = map { $_->{metadata}{name} => $_->{spec} } @crs;
    is $by{police2}{nodeIP}, '10.230.30.54,fd00::54', 'police2: control_planes[1].node_ip';
    ok $by{police3} && !exists $by{police3}{nodeIP}, 'police3: none set, none asked for';
    ok !(grep { $_->{nodeIP} && $_->{nodeIP} eq '10.230.30.52' } values %by),
        'police1\'s is not handed to a joiner';
};

subtest 'the bootstrapped control plane\'s OCPNode records its node-ip' => sub {
    my $api = CrApi->new;
    capture { OCP::Cmd::Apply::CR::ensure_cp_ocpnode(undef, $api,
        { name => 'otho', provider => 'ssh', host => 'otho.lab',
          node_ip => '10.230.30.52', handed_node_ip => '10.230.30.52' }) };
    is $api->{ensured}[0]{spec}{nodeIP}, '10.230.30.52', 'spec.nodeIP: what ocp.yaml asks';
    is $api->{statuses}[0]{nodeIP}, '10.230.30.52', 'status.nodeIP: what the install was handed';

    my $later = CrApi->new;
    capture { OCP::Cmd::Apply::CR::ensure_cp_ocpnode(undef, $later,
        { name => 'otho', provider => 'ssh', host => 'otho.lab', node_ip => '10.230.30.52' }) };
    is $later->{ensured}[0]{spec}{nodeIP}, '10.230.30.52', 'a run that installed nothing: spec';
    ok !exists $later->{statuses}[0]{nodeIP},
        'but no status.nodeIP -- the merge patch keeps the one recorded';

    my $none = CrApi->new;
    capture { OCP::Cmd::Apply::CR::ensure_cp_ocpnode(undef, $none,
        { name => 'otho', provider => 'ssh', host => 'otho.lab' }) };
    ok !exists $none->{ensured}[0]{spec}{nodeIP}, 'no node_ip: no spec.nodeIP';
    ok !exists $none->{statuses}[0]{nodeIP}, 'and no status.nodeIP';
};

# Deploy hands ensure_cp_ocpnode the node-ip the bootstrap before it installed
# police1 with. Every step before that write is a recorder here; the write
# itself stops the run.
sub deploy_cp_info {
    my ($config) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ BootOcp->new ]);
    my $cp_info;
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
    local *OCP::Cmd::Apply::_ensure_crds                          = $done;
    local *OCP::Cmd::Apply::_ensure_providers                     = $done;
    local *OCP::Cmd::Apply::_migrate_legacy_nodes                 = $done;
    local *OCP::Cmd::Apply::AMDGPU::step = sub { { failed => [] } };
    local *OCP::Cmd::Apply::_ensure_cp_ocpnode = sub { $cp_info = $_[2]; die "STOP\n" };
    my $r = capture { OCP::Cmd::Apply::Deploy::deploy($apply, {
        config => $config, api => CrApi->new, cp_name => 'otho', cp_ip => '10.230.30.52',
        provider => 'ssh', ssh_key_path => '/nonexistent', deploy_step => 2,
    }) };
    is $r->{died}, "STOP\n", 'deploy reached the control plane\'s OCPNode' or diag $r->{died};
    return $cp_info;
}

subtest 'deploy: the OCPNode gets control_planes[0].node_ip as asked and handed' => sub {
    my $info = deploy_cp_info(config_for($HA . "nocert: true\n"));
    is $info->{node_ip},        '10.230.30.52', 'node_ip (spec.nodeIP)';
    is $info->{handed_node_ip}, '10.230.30.52', 'handed_node_ip (status.nodeIP)';

    my $none = deploy_cp_info(config_for(<<'YAML'));
name: amdlab
nocert: true
control_planes:
  provider: ssh
  host: otho.lab
YAML
    ok !defined $none->{node_ip} && !defined $none->{handed_node_ip}, 'unset: neither';
};

# =============================================================================
# 4. the bootstrap of police1
# =============================================================================

package BootOcp  { sub new { bless {}, shift } sub verbose { 0 } }
package BootProv {
    sub new { bless {}, shift }
    sub upload_ssh_key     { }
    sub create_server      { { ip => 'otho.lab', newly_created => 0 } }
    sub wait_for_running   { $_[1] }
    sub advertised_host    { my ($s, %o) = @_; $o{host} }
    sub cleanup_on_failure { }
}
package BootCond   { sub new { bless { t => $_[1], s => $_[2] }, $_[0] } sub type { $_[0]{t} } sub status { $_[0]{s} } }
package BootStatus { sub new { bless {}, shift } sub conditions { [ BootCond->new(Ready => 'True') ] } }
# A typed Node: methods for the Ready wait, its struct for object_to_struct.
package BootNode   { sub new { bless { struct => $_[1] }, $_[0] } sub status { BootStatus->new } }
package BootIO     { sub new { bless {}, shift } sub object_to_struct { $_[1]{struct} } }
package BootApi {
    sub new      { my ($c, @nodes) = @_; bless { nodes => [ map { BootNode->new($_) } @nodes ] }, $c }
    sub _request { 1 }
    sub list     { FakeList->new($_[0]{nodes}) }
    sub k8s      { BootIO->new }
}

package main;

sub run_bootstrap {
    my ($config, @nodes) = @_;
    my %server_opts;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ BootOcp->new ]);
    no warnings 'redefine';
    local *OCP::Provider::for_spec        = sub { BootProv->new };
    local *OCP::Cmd::Apply::_k8s_api      = sub { BootApi->new(@nodes) };
    local *OCP::Secrets::save_kubeconfig  = sub { 1 };
    local *OCP::Secrets::ensure_age_key   = sub { 1 };
    local *OCP::SSH::new                  = sub { bless {}, 'OCP::SSH' };
    local *OCP::SSH::wait_for_ssh         = sub { 1 };
    local *OCP::Rex::new                  = sub { bless {}, 'OCP::Rex' };
    local *OCP::Rex::install_server       = sub { shift; %server_opts = @_; { kubeconfig => "apiVersion: v1\n" } };
    local *OCP::Cmd::Apply::wait_seconds  = sub { };
    my $r = capture { OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
        $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
        admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
    ) };
    $r->{server_opts} = \%server_opts;
    return $r;
}

my $ONE_CP = <<'YAML';
name: amdlab
control_planes:
  provider: ssh
  host: otho.lab
YAML

subtest 'bootstrap: control_planes[0].node_ip goes to install_server' => sub {
    my $r = run_bootstrap(config_for($ONE_CP . "  node_ip: 10.230.30.52\n"),
                          node_with('otho', '10.230.30.52'));
    is $r->{died}, '', 'bootstrap ran' or return diag $r->{died};
    is $r->{server_opts}{node_ip}, '10.230.30.52', 'node_ip handed to the install';
    is $r->{err}, '', 'registered there: nothing said';
};

subtest 'bootstrap: none set -> none handed, nothing checked' => sub {
    my $r = run_bootstrap(config_for($ONE_CP), node_with('otho', $WRONG));
    is $r->{died}, '', 'bootstrap ran' or return diag $r->{died};
    ok !exists $r->{server_opts}{node_ip}, 'install_server gets no node_ip key at all';
    is $r->{err}, '', 'no check without a node-ip';
    is OCP::Cmd::Apply::Bootstrap::cp_node_ip(config_for($ONE_CP . "  node_ip: ''\n")), undef,
        'an empty node_ip is none';
};

subtest 'bootstrap: a Ready police1 registered elsewhere -> [WARN] on STDERR' => sub {
    my $r = run_bootstrap(config_for($ONE_CP . "  node_ip: $ASKED\n"),
                          node_with('worker-x', '10.230.30.99'), node_with('otho', $WRONG));
    is $r->{died}, '', 'bootstrap goes on: the control plane is Ready' or return diag $r->{died};
    is_deeply [ grep { /\[WARN\]/ } split /\n/, $r->{err} ], [ "  [WARN] otho: $DIAG" ],
        'one line, on its Node by name, in the apply narrative\'s indent';
    unlike $r->{out}, qr/\Q$WRONG\E/, 'not on STDOUT';
    like $r->{out}, qr/\[ok\] Node is Ready/, 'the Ready line stands';
};

subtest 'bootstrap: no Node by its name -> the check that did not happen is said' => sub {
    my $r = run_bootstrap(config_for($ONE_CP . "  node_ip: $ASKED\n"), node_with('police1', $ASKED));
    is $r->{died}, '', 'bootstrap ran' or return diag $r->{died};
    is_deeply [ grep { /\[WARN\]/ } split /\n/, $r->{err} ],
        [ "  [WARN] otho: InternalIP not checked against node_ip $ASKED: no Node named 'otho'" ],
        'named, not passed';
};

# =============================================================================
# 5. ocp apply on a running cluster: police1's OCPNode keeps its node-ip
# =============================================================================
#
# Every reconcile re-ensures the bootstrapped control plane's OCPNode, and an
# ensure replaces the spec (GET + PUT): a run that left the node-ip out took
# spec.nodeIP back off the OCPNode the deploy wrote it to. The steps around
# that write are no-ops here; the write itself is the real one, into AddApi,
# which keeps what an API server keeps.

package ReconDrift { sub detect { [] } sub probe_targets { () } }

package main;

sub reconcile_cp_ocpnode {
    my ($config, $api) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ BootOcp->new ]);
    $apply->{_k8s_api} = $api;
    my $noop = sub { 0 };
    no warnings 'redefine';
    local *OCP::Secrets::read_kubeconfig  = sub { "apiVersion: v1\n" };
    local *OCP::Cmd::Apply::_k8s_api      = sub { $_[0]{_k8s_api} };
    local *OCP::Cmd::Apply::rex_prober    = sub { undef };
    local *OCP::Drift::new                = sub { bless {}, 'ReconDrift' };
    local *OCP::Cmd::Apply::AMDGPU::step  = sub { { changed => 0, failed => [] } };
    local *OCP::Cmd::Apply::_setup_registry                       = $noop;
    local *OCP::Cmd::Apply::_configure_registry_dns               = $noop;
    local *OCP::Cmd::Apply::_setup_nfd                            = $noop;
    local *OCP::Cmd::Apply::_setup_gpu_operator                   = $noop;
    local *OCP::Cmd::Apply::_report_component                     = $noop;
    local *OCP::Cmd::Apply::_setup_cilium_gateway                 = $noop;
    local *OCP::Cmd::Apply::_setup_lb_ipam                        = $noop;
    local *OCP::Cmd::Apply::_ensure_crds                          = $noop;
    local *OCP::Cmd::Apply::_ensure_providers                     = $noop;
    local *OCP::Cmd::Apply::_migrate_legacy_nodes                 = $noop;
    local *OCP::Cmd::Apply::_run_remedy                           = $noop;
    return capture { OCP::Cmd::Apply::Drift::reconcile_components($apply, $config) };
}

sub ocpnode_ensures {
    my ($api, $name) = @_;
    return scalar grep { $_->[0] eq 'ensure' && $_->[1]{kind} eq 'OCPNode'
                         && $_->[1]{metadata}{name} eq $name } @{ $api->{calls} };
}

my $RECON = <<'YAML';
name: amdlab
nocert: true
control_planes:
  provider: ssh
  host: otho.lab
YAML

subtest 'reconcile: police1 keeps spec.nodeIP, and status.nodeIP what was handed' => sub {
    my $api = AddApi->new;
    capture { OCP::Cmd::Apply::CR::ensure_cp_ocpnode(undef, $api,
        { name => 'otho', provider => 'ssh', host => 'otho.lab',
          node_ip => '10.230.30.52', handed_node_ip => '10.230.30.52' }) };
    is $api->{ocpnodes}{otho}{spec}{nodeIP}, '10.230.30.52', 'premise: the deploy wrote it';

    my $r = reconcile_cp_ocpnode(config_for($RECON . "  node_ip: 10.230.30.52\n"), $api);
    is $r->{died}, '', 'the reconcile ran' or return diag $r->{died};
    unlike $r->{out}, qr/node CR reconcile failed/, 'its CR block went through' or diag $r->{out};
    is ocpnode_ensures($api, 'otho'), 2, 'premise: the reconcile re-ensured the OCPNode';
    is $api->{ocpnodes}{otho}{spec}{nodeIP}, '10.230.30.52', 'spec.nodeIP is still there';
    is $api->{ocpnodes}{otho}{status}{nodeIP}, '10.230.30.52', 'and so is status.nodeIP';
};

subtest 'reconcile: a node-ip set after the bootstrap is asked, not claimed handed' => sub {
    # police1 was installed before ocp.yaml named one: none was handed.
    my $api = AddApi->new;
    capture { OCP::Cmd::Apply::CR::ensure_cp_ocpnode(undef, $api,
        { name => 'otho', provider => 'ssh', host => 'otho.lab' }) };

    my $r = reconcile_cp_ocpnode(config_for($RECON . "  node_ip: 10.230.30.52\n"), $api);
    is $r->{died}, '', 'the reconcile ran' or return diag $r->{died};
    is $api->{ocpnodes}{otho}{spec}{nodeIP}, '10.230.30.52', 'spec.nodeIP: what ocp.yaml asks';
    ok !exists $api->{ocpnodes}{otho}{status}{nodeIP},
        'no status.nodeIP: the reconcile installs nothing, so it handed nothing';
};

subtest 'reconcile: none in ocp.yaml -> none on the OCPNode' => sub {
    my $api = AddApi->new;
    my $r = reconcile_cp_ocpnode(config_for($RECON), $api);
    is $r->{died}, '', 'the reconcile ran' or return diag $r->{died};
    is ocpnode_ensures($api, 'otho'), 1, 'premise: the OCPNode was ensured';
    ok !exists $api->{ocpnodes}{otho}{spec}{nodeIP}, 'no spec.nodeIP';
};

# =============================================================================
# 6. ocp apply: an additional control plane registered elsewhere
# =============================================================================
#
# police2 is driven by OCP::Node on the CLI path (cli_reconcile_workers), from
# Joining to Ready, like a node `ocp node add` drives: its Ready transition
# says the mismatch through the logger the caller hands it.

sub reconcile_extra_cp {
    my (%o) = @_;
    my $api = AddApi->new;
    $api->{ocpnodes}{police2} = {
        metadata => { name => 'police2', namespace => 'ocp-system' },
        spec     => { role => 'control-plane', providerRef => 'ssh-default', nodeIP => $ASKED },
        status   => { phase => 'Joining', nodeIP => $ASKED },
    };
    $api->{nodes}{police2} = node_with('police2', $o{registered} // $WRONG);
    my $apply = OCP::Cmd::Apply->new(command_chain => [ BootOcp->new ]);
    my @rows;
    no warnings 'redefine';
    local *OCP::SSH::new = sub { bless {}, 'OCP::SSH' };
    local *OCP::SSH::run = sub { { stdout => "K10jointoken\n" } };
    my $r = capture { @rows = OCP::Cmd::Apply::CR::cli_reconcile_workers(
        $apply, $api, config_for($HA), ['police2'],
        { ssh_key_path => '/nonexistent', cp_ip => '10.230.30.52' }) };
    $r->{rows} = \@rows;
    $r->{api}  = $api;
    return $r;
}

subtest 'extra control plane: registered elsewhere -> one [WARN] on STDERR' => sub {
    my $r = reconcile_extra_cp();
    is $r->{died}, '', 'the reconcile ran' or return diag $r->{died};
    is $r->{api}{ocpnodes}{police2}{status}{phase}, 'Ready', 'premise: OCP::Node turned it Ready here';
    is $r->{rows}[0]{phase}, 'Ready', 'and the row says Ready: the warning fails nothing';
    is_deeply [ warn_lines($r->{err}) ], [ "[WARN] police2: $DIAG" ],
        'one [WARN] line, as `ocp node add` says it';
    unlike $r->{err}, qr/\[node\]/, 'not the logger-less "[node] ..." form';
    unlike $r->{out}, qr/\Q$WRONG\E/, 'nothing of it on STDOUT';
};

subtest 'extra control plane: registered where it was told -> nothing said' => sub {
    my $r = reconcile_extra_cp(registered => $ASKED);
    is $r->{died}, '', 'the reconcile ran' or return diag $r->{died};
    is $r->{rows}[0]{phase}, 'Ready', 'Ready';
    is $r->{err}, '', 'STDERR empty';
};

done_testing;

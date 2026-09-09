use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use JSON::MaybeXS ();

use lib 'lib';

use OCP::Config;
use OCP::Node;
use OCP::Rex;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;

#
# Multi-control-plane for RKE2 (k8).
#
# The decision, which this test pins rather than re-litigates: multi-CP is
# RKE2-only with embedded etcd. police1 is bootstrapped unchanged (cluster-
# init, NO server:), and police2+ join police1's supervisor as additional
# RKE2 SERVERS (server: + token:). k3s HA is explicitly out of scope -- a k3s
# cluster with more than one control plane builds no HA and says so.
#
# This is a call-shape / contract test: mock K8s, mock Rex, no real machine.
# What only a real cluster (smoke / k29) can confirm -- that a second etcd
# member actually joins and stays healthy -- is deliberately NOT claimed here.
#
# The three coupled lanes and where each is asserted:
#   1. share/Rexfile install_rke2_server writes server: only when asked
#      -> 'the Rexfile gives install_rke2_server an optional server-join'
#   2. OCP::Node installs a control-plane role as an RKE2 server-join
#      -> 'OCP::Node ...' subtests
#   3. `ocp apply` loops over control_planes: [0] init, [1..] server-join,
#      one control-plane OCPNode CR per CP
#      -> 'ensure_control_plane_ocpnodes ...' and '_announce_control_planes ...'
#

# ---------------------------------------------------------------------------
# Doubles
# ---------------------------------------------------------------------------

package FakeRex {
    # Records run_task, the way t/16-node.t does: OCP::Node builds its own
    # %params and calls run_task directly, so the recorded call IS the contract.
    our @_instances;
    sub new { my ($c, %a) = @_; my $s = bless { %a, calls => [] }, $c; push @_instances, $s; $s }
    sub run_task { my ($s, $task, %p) = @_; push @{$s->{calls}}, [$task, \%p]; 1 }
}

package FakeSSH {
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub wait_for_ssh { 1 }
}

package FakeK8s {
    sub new { bless {}, shift }
    sub object_to_struct { $_[1] }
}

package FakeApi {
    # Enough of the Kubernetes::REST surface for the OCPNode CR helpers and
    # OCP::Node's status writes. patch_status carries the 1.107 house shape
    # (Kind positional, payload under 'patch'), unpacked strictly so a double
    # that also accepted the old flat form could not mask a regression.
    sub new { my ($c, %a) = @_; bless { calls => [], plain_nodes => $a{plain_nodes} // {} }, $c }
    sub k8s { FakeK8s->new }
    sub ensure {
        my ($self, $doc) = @_;
        push @{$self->{calls}}, ['ensure', $doc->{kind}, $doc->{metadata}{name}, $doc];
        return $doc;
    }
    sub patch_status {
        my ($self, $kind, @rest) = @_;
        die "patch_status: argument 0 must be a Kind\n"
            if ref $kind || !defined $kind || $kind !~ /\A[A-Z]\w+\z/;
        die "patch_status: odd args after Kind\n" if @rest % 2;
        my %args = @rest;
        die "patch_status requires 'patch'\n" unless ref $args{patch} eq 'HASH';
        push @{$self->{calls}}, ['patch_status', $kind, $args{name}, $args{patch}{status}];
        return 1;
    }
    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : undef;
        my %o = @rest;
        $name //= $o{name};
        return $self->{plain_nodes}{$name} if $kind eq 'Node';
        return undef;
    }
    sub list { FakeList->new() }
    sub calls_of { my ($self, $verb) = @_; grep { $_->[0] eq $verb } @{$self->{calls}} }
}
package FakeList { sub new { bless { items => [] }, shift } sub items { $_[0]{items} } }

package main;

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub config_for {
    my ($yaml) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew($yaml);
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub cp_ocpnode {
    my (%over) = @_;
    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => 'police2', namespace => 'ocp-system' },
        spec       => { role => 'control-plane', providerRef => 'hetzner-default' },
        status     => { phase => 'Installing', publicIP => '10.0.0.2' },
        %over,
    };
}

sub last_status {
    my ($api) = @_;
    my @s = $api->calls_of('patch_status');
    return $s[-1] ? $s[-1][3] : undef;
}

# ---------------------------------------------------------------------------
# Premise: OCP::Config already expands N control planes and builds the join URL
# ---------------------------------------------------------------------------

subtest 'control_planes expands nodes:N into N entries (the loop premise)' => sub {
    my $config = config_for(<<'YAML');
name: mycluster
kubernetes:
  dist: rke2
control_planes:
  provider: hetzner
  server_type: cx32
  location: fsn1
  nodes: 3
YAML
    my $cps = $config->control_planes;
    is scalar(@$cps), 3, 'nodes: 3 expands to three control-plane entries';
    is $cps->[1]{server_type}, 'cx32', 'each entry carries the shared spec';
};

subtest 'the join URL is police1 plus the RKE2 supervisor port' => sub {
    my $rke2 = config_for("name: c\nkubernetes:\n  dist: rke2\n");
    is $rke2->supervisor_port, 9345, 'RKE2 registers on the supervisor port';
    is $rke2->join_url('10.0.0.1'), 'https://10.0.0.1:9345',
        'server: URL for a joining CP is the police1 IP on 9345';

    my $k3s = config_for("name: c\nkubernetes:\n  dist: k3s\n");
    is $k3s->supervisor_port, 6443, 'k3s serves the supervisor from 6443';
};

# ---------------------------------------------------------------------------
# Lane 2: OCP::Node installs a control-plane as an RKE2 server-join
# ---------------------------------------------------------------------------

subtest 'OCP::Node installs a control-plane as an RKE2 server-join ([1..])' => sub {
    @FakeRex::_instances = ();
    my $api  = FakeApi->new;
    my $node = OCP::Node->from_cr(cp_ocpnode(), k8s => $api,
        provider   => undef,
        ssh_key    => 'PRIVATE',
        server_url => 'https://10.0.0.1:9345',   # police1 join URL (9345)
        join_token => 'JOINTOKEN',
        ssh_class  => 'FakeSSH', rex_class => 'FakeRex',
    );

    $node->_install_kubernetes;

    my $rex = $FakeRex::_instances[0];
    ok $rex, 'a Rex install ran for the additional control plane';
    my ($call) = @{ $rex->{calls} };
    is $call->[0], 'install_rke2_server',
        'a control-plane role installs via the SERVER task, not the agent task';
    is $call->[1]{server}, 'https://10.0.0.1:9345',
        'and it is pointed at police1 (server: join, embedded-etcd)';
    is $call->[1]{token}, 'JOINTOKEN', 'with police1 join token';
    is $call->[1]{node_name}, 'police2', 'node_name threaded';

    my $st = last_status($api);
    is $st->{phase}, 'Joining', 'phase advances to Joining';
    like $st->{message}, qr/RKE2 server/,
        'the message says server, not agent -- this is a control plane';
};

subtest 'a worker still installs as an agent, never as a server (lane 2 guard)' => sub {
    @FakeRex::_instances = ();
    my $api = FakeApi->new;
    my $cr  = cp_ocpnode(
        metadata => { name => 'worker-1', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'hetzner-default' },
        status   => { phase => 'Installing', publicIP => '10.0.0.9' },
    );
    my $node = OCP::Node->from_cr($cr, k8s => $api, provider => undef,
        ssh_key => 'K', server_url => 'https://10.0.0.1:9345', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');

    $node->_install_kubernetes;

    my ($call) = @{ $FakeRex::_instances[0]{calls} };
    is $call->[0], 'install_rke2_agent',
        'worker role stays on the agent task -- CP-join did not leak into workers';
};

subtest 'a k3s control-plane refuses to build HA (RKE2-only decision)' => sub {
    @FakeRex::_instances = ();
    my $api = FakeApi->new;
    my $node = OCP::Node->from_cr(cp_ocpnode(), k8s => $api, provider => undef,
        ssh_key => 'K', server_url => 'https://10.0.0.1:6443', join_token => 'T',
        distribution => 'k3s',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');

    $node->_install_kubernetes;

    is scalar(@{ $FakeRex::_instances[0]{calls} }), 0,
        'nothing is installed -- there is no k3s server-join';
    my $st = last_status($api);
    is $st->{phase}, 'Failed', 'the node is marked Failed, visibly';
    like $st->{message}, qr/RKE2-only|k3s/i,
        'and the message says k3s HA is not supported';
};

# ---------------------------------------------------------------------------
# Lane 1: the Rexfile makes the server: line optional (police1 = cluster-init)
# ---------------------------------------------------------------------------

subtest 'the Rexfile gives install_rke2_server an optional server-join' => sub {
    my $shipped = path('share/Rexfile');
    plan skip_all => 'share/Rexfile not found' unless -f $shipped;
    my $src = $shipped->slurp_utf8;

    my ($body) = $src =~ /task\s+"install_rke2_server",\s*sub\s*\{(.*?)\n\};/ms;
    ok defined $body, 'install_rke2_server task body found';

    like $body, qr/\$server\s*=\s*\$params->\{server\}/,
        'the task reads a server parameter';
    like $body, qr/\$config\s*\.=\s*"server: \$server\\n"\s+if\s+\$server/,
        'the server: line is CONDITIONAL -- present only when a URL is passed';

    # The init contract: police1 gets no server param, so no server: line, so
    # RKE2 does cluster-init exactly as before.
    unlike $body, qr/\$config\s*\.=\s*"server:[^"]*"\s*;\s*$/m,
        'the server: line is never written unconditionally';
};

subtest 'OCP::Rex::install_server does cluster-init: no server param ([0])' => sub {
    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 };
    local *OCP::Rex::fetch_kubeconfig_ssh = sub { "apiVersion: v1\n" };

    my $tmp = path(tempdir(CLEANUP => 1));
    my $key = $tmp->child('id'); $key->spew('k'); path("$key.pub")->spew('k');
    OCP::Rex->new(host => '10.0.0.1', key_file => $key->stringify)
        ->install_server(distribution => 'rke2', version => 'v1.31.3+rke2r1');

    my ($server_call) = grep { $_->[0] eq 'install_rke2_server' } @calls;
    ok $server_call, 'install_server runs the install_rke2_server task';
    ok !exists $server_call->[1]{server},
        'police1 passes NO server: -- cluster-init, unchanged from today';
    ok !exists $server_call->[1]{token} || length $server_call->[1]{token},
        'and it carries its own generated token';
};

# ---------------------------------------------------------------------------
# Lane 3: apply writes one control-plane OCPNode CR per additional CP,
#         and one per CP overall (police1 + police2..N)
# ---------------------------------------------------------------------------

my $RKE2_3CP = <<'YAML';
name: mycluster
kubernetes:
  dist: rke2
control_planes:
  provider: hetzner
  server_type: cx32
  location: fsn1
  nodes: 3
YAML

subtest 'ensure_control_plane_ocpnodes writes one Pending CR per ADDITIONAL CP' => sub {
    my $api    = FakeApi->new;
    my $config = config_for($RKE2_3CP);

    my @crs = OCP::Cmd::Apply::CR::ensure_control_plane_ocpnodes(undef, $api, $config);

    is scalar(@crs), 2, '3 control planes -> 2 additional CRs (police1 excluded)';
    my %by_name = map { $_->{metadata}{name} => $_ } @crs;
    ok $by_name{police2} && $by_name{police3}, 'named police2 and police3';

    is $by_name{police2}{spec}{role}, 'control-plane', 'role=control-plane';
    is $by_name{police2}{spec}{providerRef}, 'hetzner-default', 'providerRef=hetzner-default';
    is $by_name{police2}{spec}{serverType}, 'cx32',
        'serverType carried from the CP spec (provisioning hint, like a worker)';
    ok !exists $by_name{police2}{status},
        'Pending CRs carry no status -- OCP::Node owns the phase';

    my @ensured = map { $_->[2] } $api->calls_of('ensure');
    is_deeply [sort @ensured], ['police2', 'police3'],
        'exactly the additional CPs were ensured';
};

subtest 'together, N control planes yield N control-plane-role OCPNode CRs' => sub {
    # police1 comes from ensure_cp_ocpnode (observational Ready), police2+ from
    # the join loop. All role: control-plane -- the ticket's "one CR per CP".
    my $api    = FakeApi->new;
    my $config = config_for($RKE2_3CP);

    OCP::Cmd::Apply::CR::ensure_cp_ocpnode(undef, $api,
        { name => 'police1', provider => 'hetzner', host => '10.0.0.1' });
    OCP::Cmd::Apply::CR::ensure_control_plane_ocpnodes(undef, $api, $config);

    my @cp_crs = grep { $_->[1] eq 'OCPNode'
                        && $_->[3]{spec}{role} eq 'control-plane' }
                 $api->calls_of('ensure');
    my @names = sort map { $_->[2] } @cp_crs;
    is_deeply \@names, ['police1', 'police2', 'police3'],
        'one control-plane OCPNode CR per control plane, police1..police3';
};

subtest 'k3s with >1 control plane builds NO HA -- no join CRs written' => sub {
    my $api = FakeApi->new;
    my $config = config_for(<<'YAML');
name: mycluster
kubernetes:
  dist: k3s
control_planes:
  provider: hetzner
  server_type: cx32
  location: fsn1
  nodes: 3
YAML

    my @crs = OCP::Cmd::Apply::CR::ensure_control_plane_ocpnodes(undef, $api, $config);
    is scalar(@crs), 0, 'k3s HA is out of scope -- no server-join CRs';
    is scalar($api->calls_of('ensure')), 0, 'nothing was written to the cluster';
};

subtest 'a single control plane writes no additional join CRs either' => sub {
    my $api = FakeApi->new;
    my $config = config_for(<<'YAML');
name: mycluster
kubernetes:
  dist: rke2
control_planes:
  provider: hetzner
  server_type: cx32
  location: fsn1
YAML
    my @crs = OCP::Cmd::Apply::CR::ensure_control_plane_ocpnodes(undef, $api, $config);
    is scalar(@crs), 0, 'one CP -> nothing to join';
};

# ---------------------------------------------------------------------------
# Lane 3: the honest announce guard -- RKE2 now deploys all N, k3s still warns
# ---------------------------------------------------------------------------

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die $!;
    open my $efh, '>', \$err or die $!;
    { local *STDOUT = $ofh; local *STDERR = $efh; $code->() }
    return ($out, $err);
}

subtest '_announce_control_planes: RKE2 with >1 CP deploys all N, no warning' => sub {
    my $apply  = bless {}, 'OCP::Cmd::Apply';
    my $config = config_for($RKE2_3CP);

    my ($out, $err) = capture { $apply->_announce_control_planes($config, 3) };

    is $err, '', 'RKE2 multi-CP is supported now -- nothing warned to STDERR';
    like $out, qr/Count: 3/, 'the honest count is all three';
    unlike $out, qr/deploying 1/, 'STDOUT no longer says only one is deployed';
};

subtest '_announce_control_planes: k3s with >1 CP warns and deploys one' => sub {
    my $apply  = bless {}, 'OCP::Cmd::Apply';
    my $config = config_for(<<'YAML');
name: mycluster
kubernetes:
  dist: k3s
control_planes:
  provider: hetzner
  server_type: cx32
  location: fsn1
  nodes: 2
YAML

    my ($out, $err) = capture { $apply->_announce_control_planes($config, 3) };

    like $err, qr/2 control planes/, 'the warning names the configured count';
    like $err, qr/RKE2-only|not supported/i, 'and that k3s HA is out of scope';
    like $err, qr/police1/, 'and says what actually gets deployed';
    like $out, qr/deploying 1 \(police1\)/, 'STDOUT is honest about the one';
    unlike $out, qr/Count: 2/, 'STDOUT does not imply two are deployed';
};

subtest '_announce_control_planes: a single control plane stays silent' => sub {
    my $apply  = bless {}, 'OCP::Cmd::Apply';
    my $config = config_for("name: c\nkubernetes:\n  dist: rke2\ncontrol_planes:\n  provider: hetzner\n");

    my ($out, $err) = capture { $apply->_announce_control_planes($config, 2) };
    is $err, '', 'no warning for a single control plane';
    like $out, qr/Count: 1/, 'honest single count';
    like $out, qr/Step 2: Deploy control plane/, 'the banner still prints';
};

done_testing;

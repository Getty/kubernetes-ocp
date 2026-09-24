use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use JSON::MaybeXS ();

use lib 'lib';
use lib 't/lib';
use OCPTest::Rexfile;

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

# Since k155 the task hands its parameters to Rex::Rancher::Server::install_server,
# which writes config.yaml; the claim is now about what the task hands over
# (t/lib/OCPTest/Rexfile.pm runs it against recorders). That the library writes
# `server:` only when given one is pinned against the real library in
# t/155-rex-libraries.t.
subtest 'the Rexfile gives install_rke2_server an optional server-join' => sub {
    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_rke2_server', { token => 't0k3n' });
    my $init = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    ok $init, 'install_server is called';
    ok !defined $init->{server}, 'police1 (no server param) hands over NO server -- cluster-init';

    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_rke2_server',
        { token => 't0k3n', server => 'https://10.0.0.1:9345' });
    my $join = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    is $join->{server}, 'https://10.0.0.1:9345', 'a passed server URL is handed over (join)';
    is $join->{token}, 't0k3n', 'with the token';
};

subtest 'OCP::Rex::install_server does cluster-init: no server param ([0])' => sub {
    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 };
    local *OCP::Rex::fetch_kubeconfig_ssh = sub { "apiVersion: v1\n" };
    # Fresh cluster-init: no machine to read a prior token from (k150).
    local *OCP::Rex::_existing_server_token = sub { undef };

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

# ---------------------------------------------------------------------------
# k137, point 1: every control plane advertises EVERY control-plane address in
# its apiserver tls-san -- not just its own, and not just police1. police1 is
# bootstrapped through OCP::Rex::install_server; police2+ join through OCP::Node.
# The RKE2 config each generates must therefore carry ALL CP addresses, or TLS
# against any server other than police1 fails -- the joined servers' serving
# certs would omit the very addresses clients reach them at.
#
# This is the code half of k137. Point 2 -- a client-facing HA endpoint
# (LB / VIP / DNS round-robin) -- is a separate, still-undecided design and is
# deliberately NOT asserted here: only the individual per-CP addresses, which
# are correct no matter how that endpoint eventually lands.
#
# A call-shape test, like the rest of this file: the addresses come from three
# ssh control planes whose hosts are pinned in ocp.yaml, so the full set is
# knowable without provisioning a single machine.
# ---------------------------------------------------------------------------

my $RKE2_3CP_SSH = <<'YAML';
name: mycluster
kubernetes:
  dist: rke2
control_planes:
  - provider: ssh
    host: 10.0.0.1
  - provider: ssh
    host: 10.0.0.2
  - provider: ssh
    host: 10.0.0.3
YAML

subtest 'cp_tls_sans collects EVERY control-plane address, deduped' => sub {
    my $config = config_for($RKE2_3CP_SSH);

    my @sans = OCP::Cmd::Apply::Bootstrap::cp_tls_sans($config);
    is_deeply \@sans, ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
        'all three configured control-plane hosts -- not just the first';

    # Runtime addresses a caller already holds (police1's advertised IP, say)
    # fold in, and an address already in the spec does not appear twice.
    my @with_extra = OCP::Cmd::Apply::Bootstrap::cp_tls_sans(
        $config, '10.0.0.1', '203.0.113.9');
    is_deeply \@with_extra,
        ['10.0.0.1', '10.0.0.2', '10.0.0.3', '203.0.113.9'],
        'extra runtime addresses fold in; duplicates collapse';
};

subtest 'police1 (install_server) advertises all CP addresses as a tls-san list' => sub {
    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 };
    local *OCP::Rex::fetch_kubeconfig_ssh = sub { "apiVersion: v1\n" };
    # Fresh cluster-init: no machine to read a prior token from (k150).
    local *OCP::Rex::_existing_server_token = sub { undef };

    my $config = config_for($RKE2_3CP_SSH);
    my @sans   = OCP::Cmd::Apply::Bootstrap::cp_tls_sans($config, '10.0.0.1');

    my $tmp = path(tempdir(CLEANUP => 1));
    my $key = $tmp->child('id'); $key->spew('k'); path("$key.pub")->spew('k');
    OCP::Rex->new(host => '10.0.0.1', key_file => $key->stringify)->install_server(
        distribution => 'rke2', version => 'v1.36.4+rke2r1',
        node_name => 'police1', tls_san => \@sans);

    my ($server_call) = grep { $_->[0] eq 'install_rke2_server' } @calls;
    ok $server_call, 'install_server ran the server task';
    is ref $server_call->[1]{tls_san}, 'ARRAY',
        'tls-san travels as a LIST, not a single value';
    is_deeply [sort @{ $server_call->[1]{tls_san} }],
        ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
        'police1 advertises every CP address, not only its own';
};

subtest 'police2 (OCP::Node join) advertises all CP addresses as a tls-san list' => sub {
    @FakeRex::_instances = ();
    my $api    = FakeApi->new;
    my $config = config_for($RKE2_3CP_SSH);
    my @sans   = OCP::Cmd::Apply::Bootstrap::cp_tls_sans($config, '10.0.0.1');

    # police2's OCPNode: control-plane role, own address 10.0.0.2 in status.
    my $node = OCP::Node->from_cr(
        cp_ocpnode(status => { phase => 'Installing', publicIP => '10.0.0.2' }),
        k8s => $api, provider => undef,
        ssh_key => 'K', server_url => 'https://10.0.0.1:9345', join_token => 'T',
        tls_san => \@sans,
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
    );

    $node->_install_kubernetes;

    my ($call) = @{ $FakeRex::_instances[0]{calls} };
    is $call->[0], 'install_rke2_server',
        'a control-plane join installs as a server';
    is ref $call->[1]{tls_san}, 'ARRAY',
        'the join install carries a tls-san LIST (today it carries none)';
    is_deeply [sort @{ $call->[1]{tls_san} }],
        ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
        'police2 advertises every CP address -- not just police1, not just its own';
};

subtest 'a joined worker carries no tls-san (guard: CP-only)' => sub {
    @FakeRex::_instances = ();
    my $api = FakeApi->new;
    my $cr  = cp_ocpnode(
        metadata => { name => 'worker-1', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'hetzner-default' },
        status   => { phase => 'Installing', publicIP => '10.0.0.9' },
    );
    my $node = OCP::Node->from_cr($cr, k8s => $api, provider => undef,
        ssh_key => 'K', server_url => 'https://10.0.0.1:9345', join_token => 'T',
        tls_san => ['10.0.0.1', '10.0.0.2'],
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');

    $node->_install_kubernetes;

    my ($call) = @{ $FakeRex::_instances[0]{calls} };
    is $call->[0], 'install_rke2_agent', 'worker still installs as an agent';
    ok !exists $call->[1]{tls_san},
        'a worker never gets a tls-san -- only control planes advertise one';
};

subtest 'k184: a control-plane join repeats the cluster pod CIDR, a worker does not' => sub {
    # RKE2 refuses a joining server whose cluster-cidr differs from the first
    # server's. robocop's joins used to carry none, so the Rexfile's
    # 10.42.0.0/16 fallback broke every join on a cluster with its own
    # network.pod_cidr.
    for my $case (
        [ 'control-plane', 'install_rke2_server', '10.44.0.0/16' ],
        [ 'worker',        'install_rke2_agent',  undef          ],
    ) {
        my ($role, $task, $want) = @$case;
        @FakeRex::_instances = ();
        my $node = OCP::Node->from_cr(
            cp_ocpnode(
                spec   => { role => $role, providerRef => 'hetzner-default' },
                status => { phase => 'Installing', publicIP => '10.0.0.2' }),
            k8s => FakeApi->new, provider => undef,
            ssh_key => 'K', server_url => 'https://10.0.0.1:9345', join_token => 'T',
            pod_cidr => '10.44.0.0/16',
            ssh_class => 'FakeSSH', rex_class => 'FakeRex',
        );
        $node->_install_kubernetes;

        my ($call) = @{ $FakeRex::_instances[0]{calls} };
        is $call->[0], $task, "$role installs via $task";
        is $call->[1]{pod_cidr}, $want,
            $want ? "$role: pod_cidr reaches the join" : "$role: no pod_cidr";
    }
};

subtest 'the Rexfile emits one tls-san entry per address (list-aware)' => sub {
    # tls_san arrives as a JSON array (the list form) or, for a hand-run
    # `rex ... --tls_san=1.2.3.4`, as a bare scalar. Either way the library
    # gets a list, one entry per address (it writes one tls-san line each).
    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_rke2_server',
        { token => 't', tls_san => [ '10.0.0.1', '10.0.0.2', 'cp.example.com' ] });
    my $opts = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    is_deeply $opts->{tls_san}, [ '10.0.0.1', '10.0.0.2', 'cp.example.com' ],
        'a list stays a list, in order';

    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_rke2_server', { token => 't', tls_san => '10.0.0.1' });
    $opts = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    is_deeply $opts->{tls_san}, [ '10.0.0.1' ], 'a bare scalar becomes a one-entry list';

    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_rke2_server', { token => 't' });
    $opts = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    ok !exists $opts->{tls_san}, 'no tls_san, no tls_san option';
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);
use YAML::XS ();

use lib 'lib';
use OCP;
use OCP::Config;
use OCP::Drift;
use OCP::Rex;

no warnings 'once';   # the stub package is filled by a string eval

#
# k182: on RKE2, OCP let Cilium run its own default pod pool, 10.0.0.0/8
# (clusterPoolIPv4PodCIDRList). That overlaps most host LANs -- the lab this
# was found on is 10.5.8.0/22 -- so pods could not reach machines on it. k178
# had already given k3s 10.42.0.0/16, on both sides.
#
# The claims here:
#   1. one pod CIDR for both distributions: network.pod_cidr in ocp.yaml,
#      default 10.42.0.0/16 (the built-in cluster-cidr of RKE2 and k3s alike);
#      the Rexfile's fallback for hand-runs and robocop joins is the same value;
#   2. validation refuses a pod CIDR that is no CIDR, has host bits, leaves
#      Cilium no room for its per-node /24, or overlaps the service network,
#      a node address or the LB pool;
#   3. a fresh server writes it as cluster-cidr, on RKE2 as on k3s, and Cilium
#      is installed with it as its cluster pool, on RKE2 as on k3s;
#   4. an existing Cilium keeps the pool it runs: upgrade_cilium (the drift
#      remedy) and install_cilium's upgrade branch pass the LIVE pool, never
#      the ocp.yaml value -- a running cluster is never reconfigured;
#   5. a pool that differs from ocp.yaml is reported as drift, with no remedy.
#
# Network-free: Rexfile helpers are lifted and run against stubs (t/178).
#

my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

sub config_for {
    my ($spec) = @_;
    my $name = 'c' . int(rand(1_000_000));
    my $f = path($tmpdir)->child("$name.yaml");
    $ocp->dump_file($f->stringify, { name => $name, %$spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

my $local = { control_planes => [{ provider => 'local' }] };

sub errors_for {
    my ($net, %extra) = @_;
    return grep { /pod_cidr/ } config_for({ %$local, network => $net, %extra })->validate;
}

# --- 1. one value, one default ------------------------------------------------

subtest 'network.pod_cidr defaults to 10.42.0.0/16' => sub {
    is config_for($local)->pod_cidr, '10.42.0.0/16', 'default';
    is $OCP::Config::DEFAULT_POD_CIDR, '10.42.0.0/16', 'exposed as $DEFAULT_POD_CIDR';
    is config_for({ %$local, network => { pod_cidr => '172.20.0.0/16' } })->pod_cidr,
        '172.20.0.0/16', 'set in ocp.yaml wins';
    ok !config_for($local)->pod_cidr_is_set, 'default is not "set"';
    ok config_for({ %$local, network => { pod_cidr => '172.20.0.0/16' } })->pod_cidr_is_set,
        'an ocp.yaml value is';
};

# --- 2. validation ------------------------------------------------------------

subtest 'a good pod CIDR passes' => sub {
    is_deeply [ errors_for({ pod_cidr => '172.20.0.0/16' }) ], [], '172.20.0.0/16';
    is_deeply [ errors_for({}) ], [], 'absent (default)';
    is_deeply [ errors_for({ pod_cidr => '10.0.0.0/12' }) ], [], '10.0.0.0/12 (clear of 10.43)';
};

subtest 'bad pod CIDRs are refused with a reason' => sub {
    my @e = errors_for({ pod_cidr => '10.42.0.0/40' });
    like "@e", qr/network\.pod_cidr: '10\.42\.0\.0\/40' is not an IPv4 CIDR/, 'no CIDR';

    @e = errors_for({ pod_cidr => [ '10.42.0.0/16' ] });
    like "@e", qr/network\.pod_cidr: .*IPv4 CIDR/, 'a list is no CIDR';

    @e = errors_for({ pod_cidr => '10.42.7.0/16' });
    like "@e", qr/host bits.*10\.42\.0\.0\/16/, 'host bits set: names the network address';

    @e = errors_for({ pod_cidr => '172.20.0.0/24' });
    like "@e", qr/\/24.*too small|too small.*\/24/, 'a /24 leaves one node';

    @e = errors_for({ pod_cidr => '10.43.0.0/16' });
    like "@e", qr/overlaps the service network 10\.43\.0\.0\/16/, 'service CIDR';

    # What an RKE2 cluster ran before k182 -- Cilium's default. It contains
    # the service network, so it cannot be a pod_cidr OCP installs with.
    @e = errors_for({ pod_cidr => '10.0.0.0/8' });
    like "@e", qr/'10\.0\.0\.0\/8' overlaps the service network/, 'Cilium\'s 10.0.0.0/8';

    @e = errors_for({ pod_cidr => '10.0.0.0/12' },
        control_planes => [{ provider => 'ssh', host => '10.5.10.9' }]);
    like "@e", qr/overlaps.*control_planes\[1\].*10\.5\.10\.9/, 'a control plane address';

    @e = errors_for({ pod_cidr => '10.0.0.0/12' },
        control_planes => [{ provider => 'hetzner', server_type => 'cx32',
                             location => 'fsn1', public_ip => '10.1.2.3' }]);
    like "@e", qr/overlaps.*10\.1\.2\.3/, 'a pinned public_ip';

    @e = errors_for({ pod_cidr => '10.0.0.0/12' },
        control_planes => [{ provider => 'ssh', host => 'pichu.cihq' }]);
    is_deeply \@e, [], 'a host name is not resolved, not guessed';

    @e = errors_for({ pod_cidr => '10.0.0.0/12' },
        workers => [{ name => 'w', provider => 'ssh', host => '10.5.10.20' }]);
    like "@e", qr/overlaps.*worker pool 'w'.*10\.5\.10\.20/, 'a worker pool address';

    @e = errors_for({ pod_cidr => '10.42.0.0/16', lb_pool => { cidr => '10.42.5.0/28' } });
    like "@e", qr/overlaps network\.lb_pool/, 'the LB pool (cidr)';

    @e = errors_for({ pod_cidr => '10.42.0.0/16',
                      lb_pool => { start => '10.42.9.1', stop => '10.42.9.9' } });
    like "@e", qr/overlaps network\.lb_pool/, 'the LB pool (start/stop)';

    @e = errors_for({}, control_planes => [{ provider => 'ssh', host => '10.42.0.5' }]);
    like "@e", qr/network\.pod_cidr \(default 10\.42\.0\.0\/16\) overlaps/,
        'the default is checked too, and the message says it is the default';
    like "@e", qr/set network\.pod_cidr/, 'and tells the human what to do';
};

# --- 3 + 4. the Rexfile -------------------------------------------------------

my $root = path(__FILE__)->parent->parent;
my $src  = $root->child('share/Rexfile')->slurp_utf8;

my @subs;
for my $name (qw( _default_pod_cidr _k3s_server_config _cilium_install_args
                  _cilium_pool_args _live_cilium_pool )) {
    my ($body) = $src =~ /^(sub \Q$name\E \{[^\n]*\})$/m;
    ($body) = $src =~ /^(sub \Q$name\E \{.*?^\})/ms unless defined $body;
    ok defined $body, "share/Rexfile defines $name"
        or BAIL_OUT("k182 fix absent: $name is not in the Rexfile");
    push @subs, $body;
}

my $stubs = <<'PERL';
package RexfilePodCidr;
use constant { TRUE => 1, FALSE => 0 };
our (@RUNS, $EXIT, $OUT);
sub run {
    my ($cmd, %o) = @_;
    push @RUNS, [ $cmd, \%o ];
    $? = $EXIT // 0;
    return $OUT // '';
}
sub say { }
PERL

ok eval("$stubs\n" . join("\n", @subs) . "\n1;"),
    'the lifted helpers compile against stubs'
    or BAIL_OUT("cannot compile the lifted helpers: $@");

sub task_body {
    my ($name) = @_;
    my ($body) = $src =~ /^task "\Q$name\E", sub \{\n(.*?)\n\};$/ms;
    return $body;
}

subtest 'the Rexfile fallback is OCP::Config\'s default' => sub {
    is RexfilePodCidr::_default_pod_cidr(), $OCP::Config::DEFAULT_POD_CIDR, 'one value';
};

subtest 'k3s server config.yaml: cluster-cidr from pod_cidr' => sub {
    my $c = YAML::XS::Load(RexfilePodCidr::_k3s_server_config(token => 't', pod_cidr => '172.20.0.0/16'));
    is $c->{'cluster-cidr'}, '172.20.0.0/16', 'passed value';
    $c = YAML::XS::Load(RexfilePodCidr::_k3s_server_config(token => 't'));
    is $c->{'cluster-cidr'}, '10.42.0.0/16', 'fallback';
};

subtest 'install_rke2_server writes cluster-cidr' => sub {
    my $body = task_body('install_rke2_server');
    ok defined $body, 'task found' or return;
    like $body, qr/cluster-cidr: /, 'cluster-cidr line';
    like $body, qr/\$params->\{pod_cidr\}\s*\|\|\s*_default_pod_cidr\(\)/,
        'from the pod_cidr parameter, falling back to the default';
};

subtest 'Cilium install flags carry the pool on both distributions' => sub {
    my $rke2 = RexfilePodCidr::_cilium_install_args(distribution => 'rke2', pod_cidr => '172.20.0.0/16');
    like $rke2, qr/--set ipam\.operator\.clusterPoolIPv4PodCIDRList=172\.20\.0\.0\/16\b/,
        'rke2: no longer Cilium\'s 10.0.0.0/8 default';
    like $rke2, qr/k8sServiceHost=localhost /, 'rke2 still localhost';

    my $k3s = RexfilePodCidr::_cilium_install_args(distribution => 'k3s',
        k8s_service_host => '203.0.113.7', pod_cidr => '172.20.0.0/16');
    like $k3s, qr/clusterPoolIPv4PodCIDRList=172\.20\.0\.0\/16\b/, 'k3s: the same value';

    like RexfilePodCidr::_cilium_install_args(distribution => 'rke2'),
        qr/clusterPoolIPv4PodCIDRList=10\.42\.0\.0\/16\b/, 'fallback on a hand-run';
};

subtest '_live_cilium_pool reads cilium-config, read-only' => sub {
    local @RexfilePodCidr::RUNS = ();
    local $RexfilePodCidr::EXIT = 0;
    local $RexfilePodCidr::OUT  = "10.0.0.0/8\n";
    is_deeply [ RexfilePodCidr::_live_cilium_pool(kubectl => 'K', kubeconfig => '/k') ],
        [ '10.0.0.0/8' ], 'one CIDR';
    my $cmd = $RexfilePodCidr::RUNS[0][0];
    like $cmd, qr/^K -n kube-system get configmap cilium-config -o jsonpath=/, 'a get, nothing else';
    like $cmd, qr/cluster-pool-ipv4-cidr/, 'the pool key';
    is $RexfilePodCidr::RUNS[0][1]{env}{KUBECONFIG}, '/k', 'kubeconfig';

    local $RexfilePodCidr::OUT = "10.0.0.0/8 172.30.0.0/16";
    is_deeply [ RexfilePodCidr::_live_cilium_pool(kubectl => 'K', kubeconfig => '/k') ],
        [ '10.0.0.0/8', '172.30.0.0/16' ], 'a list is space-separated';

    local $RexfilePodCidr::EXIT = 1;
    local $RexfilePodCidr::OUT  = 'Error from server (NotFound)';
    is_deeply [ RexfilePodCidr::_live_cilium_pool(kubectl => 'K', kubeconfig => '/k') ], [],
        'unreadable: nothing, not the error text';
};

subtest '_cilium_pool_args keeps the live pool' => sub {
    is RexfilePodCidr::_cilium_pool_args('10.0.0.0/8'),
        '--set ipam.operator.clusterPoolIPv4PodCIDRList=10.0.0.0/8', 'one CIDR';
    is RexfilePodCidr::_cilium_pool_args('10.0.0.0/8', '172.30.0.0/16'),
        "--set 'ipam.operator.clusterPoolIPv4PodCIDRList={10.0.0.0/8,172.30.0.0/16}'",
        'several: a helm list';
    is RexfilePodCidr::_cilium_pool_args(), '', 'nothing known: no flag, the release keeps its value';
};

subtest 'an upgrade never moves the pool to ocp.yaml\'s value' => sub {
    for my $task (qw( upgrade_cilium install_cilium )) {
        my $body = task_body($task);
        ok defined $body, "$task found" or next;
        my ($upgrade) = $body =~ /(run\s+(?:"|')cilium upgrade[^;]*;)/s;
        ok $upgrade, "$task runs cilium upgrade" or next;
        like $upgrade, qr/_cilium_pool_args\(\s*_live_cilium_pool\(/,
            "$task: the upgrade passes the LIVE pool";
        unlike $upgrade, qr/pod_cidr/, "$task: never the configured one";
    }
};

# --- OCP::Rex and the bootstrap thread the value through -----------------------

subtest 'OCP::Rex::install_server passes pod_cidr to the server and to Cilium' => sub {
    for my $dist (qw( rke2 k3s )) {
        my @calls;
        no warnings 'redefine';
        local *OCP::Rex::run_task = sub { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 };
        local *OCP::Rex::fetch_kubeconfig_ssh   = sub { "apiVersion: v1\n" };
        local *OCP::Rex::_existing_server_token = sub { undef };

        my $key = path($tmpdir)->child("id-$dist"); $key->spew('k'); path("$key.pub")->spew('k');
        OCP::Rex->new(host => '127.0.0.1', advertised_host => '203.0.113.7',
                      key_file => $key->stringify)
            ->install_server(distribution => $dist, version => 'v1', pod_cidr => '172.20.0.0/16');

        my ($server) = grep { $_->[0] =~ /^install_\w+_server$/ } @calls;
        is $server->[1]{pod_cidr}, '172.20.0.0/16', "$dist: server task";
        my ($cilium) = grep { $_->[0] eq 'install_cilium' } @calls;
        is $cilium->[1]{pod_cidr}, '172.20.0.0/16', "$dist: install_cilium";
    }
};

subtest 'the bootstrap hands install_server the configured pod CIDR' => sub {
    my $boot = $root->child('lib/OCP/Cmd/Apply/Bootstrap.pm')->slurp_utf8;
    my ($call) = $boot =~ /(\$rex->install_server\(.*?\);)/s;
    like $call, qr/pod_cidr\s*=>\s*\$config->pod_cidr/, 'pod_cidr => $config->pod_cidr';
};

# --- 5. drift -----------------------------------------------------------------

package FakeApi {
    sub new { my ($class, %o) = @_; bless { %o }, $class }
    sub get {
        my ($self, $kind, %a) = @_;
        my $obj = $self->{objects}{ join '/', $kind, $a{namespace} // '', $a{name} // '' };
        die "$kind not found\n" unless $obj;
        return $obj;
    }
    sub list { +{ items => [] } }
}

sub pool_drift {
    my ($spec, $live) = @_;
    my $api = FakeApi->new(objects => defined $live
        ? { 'ConfigMap/kube-system/cilium-config' => { data => $live } } : {});
    return OCP::Drift->new(config => config_for($spec), api => $api)->pod_cidr_drift;
}

subtest 'pool matches: no drift' => sub {
    is_deeply [ pool_drift($local, { 'cluster-pool-ipv4-cidr' => '10.42.0.0/16' }) ], [], 'default';
    is_deeply [ pool_drift({ %$local, network => { pod_cidr => '172.16.0.0/12' } },
                           { 'cluster-pool-ipv4-cidr' => '172.16.0.0/12' }) ], [],
        'an existing cluster whose ocp.yaml states its pool';
};

subtest 'nothing to read: no drift' => sub {
    is_deeply [ pool_drift($local, undef) ], [], 'no cilium-config';
    is_deeply [ pool_drift($local, { ipam => 'kubernetes' }) ], [],
        'no cluster-pool key (another IPAM mode)';
};

subtest 'an RKE2 cluster on Cilium\'s 10.0.0.0/8: reported, never fixed' => sub {
    my @d = pool_drift($local, { 'cluster-pool-ipv4-cidr' => '10.0.0.0/8' });
    is scalar @d, 1, 'one entry' or return;
    my $e = $d[0];
    is $e->{component}, 'pod_cidr', 'component';
    is $e->{kind}, 'spec', 'spec kind: a human decides';
    ok !$e->{remedy}, 'no remedy -- no automatic migration';
    ok !$e->{self_healing}, 'and apply does not heal it either';
    is $e->{expected}, '10.42.0.0/16', 'expected';
    is $e->{actual},   '10.0.0.0/8',   'actual';
    like $e->{message}, qr/Cilium pod pool is 10\.0\.0\.0\/8/, 'says what runs';
    like $e->{message}, qr/10\.42\.0\.0\/16 \(default\)/, 'says what is expected and why';
    like $e->{message}, qr/not changed automatically/, 'says it is not auto-fixed';
    unlike $e->{manual_step}, qr/set network\.pod_cidr/,
        'does not suggest stating a pool validation would refuse';
    like $e->{manual_step}, qr/overlaps the service network 10\.43\.0\.0\/16/, 'says why';
    like $e->{manual_step}, qr/rebuild/i, 'and that a move means a rebuild';
};

subtest 'a running pool that ocp.yaml could state' => sub {
    my @d = pool_drift($local, { 'cluster-pool-ipv4-cidr' => '172.16.0.0/12' });
    is scalar @d, 1, 'reported' or return;
    like $d[0]{manual_step}, qr/set network\.pod_cidr: 172\.16\.0\.0\/12/,
        'tells how to accept the running pool';
    like $d[0]{manual_step}, qr/rebuild/i, 'or that a move means a rebuild';
};

subtest 'a changed network.pod_cidr on a running cluster' => sub {
    my @d = pool_drift({ %$local, network => { pod_cidr => '172.20.0.0/16' } },
                       { 'cluster-pool-ipv4-cidr' => '10.42.0.0/16' });
    is scalar @d, 1, 'reported';
    like $d[0]{message}, qr/172\.20\.0\.0\/16 \(network\.pod_cidr\)/, 'names the ocp.yaml key';
    ok !$d[0]{remedy}, 'still no remedy';
};

subtest 'detect includes the pool check' => sub {
    my $api = FakeApi->new(objects => {
        'ConfigMap/kube-system/cilium-config' => { data => { 'cluster-pool-ipv4-cidr' => '10.0.0.0/8' } } });
    my $d = OCP::Drift->new(config => config_for($local), api => $api)->detect;
    ok((grep { $_->{component} eq 'pod_cidr' } @$d), 'pod_cidr entry in detect()');
};

subtest q{status shows the manual step under the entry} => sub {
    my @l = OCP::Drift->format_lines([ { message => q{m}, manual_step => q{do x} } ]);
    is_deeply \@l, [ q{  [drift] m}, q{          do x} ], q{two lines};
};

subtest 'reconcile prints the manual step instead of pointing at ocp update' => sub {
    my $src = $root->child('lib/OCP/Cmd/Apply/Drift.pm')->slurp_utf8;
    like $src, qr/\$entry->\{manual_step\}/, 'Apply::Drift knows manual_step';
};

done_testing;

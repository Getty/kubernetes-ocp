#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);
use YAML::XS ();

use lib 'lib';
use lib 't/lib';
use OCPTest::Rexfile;
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
# Network-free: the Rexfile runs against recorders (t/lib/OCPTest/Rexfile.pm).
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
#
# Since k155 the Rexfile hands the install to Rex::Rancher; the claims hold
# against what the tasks hand the library and write themselves, with the
# Rexfile loaded against recorders (t/lib/OCPTest/Rexfile.pm).

my $root = path(__FILE__)->parent->parent;

my $KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n";

# A node whose Cilium is $live: undef (none yet), or { ipam, pool, host }.
sub cilium_node {
    my ($live) = @_;
    return sub {
        my ($cmd) = @_;
        return ($KUBECONFIG, 0) if $cmd =~ /^cat \S+\.yaml$/;
        if ($cmd =~ /get configmap cilium-config/) {
            return ('Error from server (NotFound): configmaps "cilium-config" not found', 1)
                unless $live;
            return (($live->{ipam} // '') . '|' . join(' ', @{ $live->{pool} // [] }), 0);
        }
        return (($live && $live->{host}) // '', 0) if $cmd =~ /get daemonset cilium/;
        return ('', 0);
    };
}

my %PINS = (version => '1.20.0', cli_version => 'v0.19.7', gateway_api_version => 'v1.6.1');

sub cilium_opts_after {
    my ($task, $live, %params) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = cilium_node($live);
    OCPTest::Rexfile->run_task($task, { %PINS, %params });
    my $fn = $task eq 'upgrade_cilium' ? 'upgrade_cilium' : 'install_cilium';
    return OCPTest::Rexfile->lib_opts("Rex::Rancher::Cilium::$fn");
}

subtest 'the Rexfile fallback is OCP::Config\'s default' => sub {
    is(OCPTest::Rexfile->helper('_default_pod_cidr')->(), $OCP::Config::DEFAULT_POD_CIDR, 'one value');
};

subtest 'a fresh server writes cluster-cidr from pod_cidr, on both distributions' => sub {
    for my $dist (qw( rke2 k3s )) {
        for my $case ([ '172.20.0.0/16', '172.20.0.0/16' ], [ undef, '10.42.0.0/16' ]) {
            my ($given, $want) = @$case;
            OCPTest::Rexfile->reset;
            OCPTest::Rexfile->run_task("install_${dist}_server",
                { token => 't', (defined $given ? (pod_cidr => $given) : ()) });

            my ($file) = grep { $_->{args}[0] =~ /cluster-cidr/ } OCPTest::Rexfile->calls('file');
            ok $file, "$dist: a cluster-cidr file" or next;
            is $file->{args}[0], "/etc/rancher/$dist/config.yaml.d/50-ocp-cluster-cidr.yaml",
                "$dist: a config.yaml.d drop-in, which wins over config.yaml (rex-rancher k41)";
            is $file->{args}[1]{content}, "cluster-cidr: $want\n",
                "$dist: " . (defined $given ? 'the passed value' : 'the fallback');

            my $written = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'file' && $_->{args}[0] =~ /cluster-cidr/ });
            my $install = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::Rancher::Server::install_server' });
            ok $written >= 0 && $install > $written, "$dist: written before the server starts";
        }
    }
};

subtest 'a pod CIDR that is no CIDR never reaches a node' => sub {
    OCPTest::Rexfile->reset;
    ok !eval { OCPTest::Rexfile->run_task('install_rke2_server', { token => 't', pod_cidr => '10.42.0.0/16; rm -rf /' }); 1 },
        'dies';
    like $@, qr/not an IPv4 CIDR/, 'and says why';
    is scalar(OCPTest::Rexfile->calls('Rex::Rancher::Server::install_server')), 0, 'before the install';
};

subtest 'a fresh Cilium gets the pool on both distributions' => sub {
    my $rke2 = cilium_opts_after('install_cilium', undef, distribution => 'rke2', pod_cidr => '172.20.0.0/16');
    is_deeply $rke2->{helm_values}{ipam},
        { mode => 'cluster-pool', operator => { clusterPoolIPv4PodCIDRList => ['172.20.0.0/16'] } },
        'rke2: cluster-pool on pod_cidr -- no longer Cilium\'s 10.0.0.0/8, nor the library\'s kubernetes mode';

    my $k3s = cilium_opts_after('install_cilium', undef, distribution => 'k3s',
        k8s_service_host => '203.0.113.7', pod_cidr => '172.20.0.0/16');
    is_deeply $k3s->{helm_values}{ipam}{operator}{clusterPoolIPv4PodCIDRList}, ['172.20.0.0/16'],
        'k3s: the same value';

    my $hand = cilium_opts_after('install_cilium', undef, distribution => 'rke2');
    is_deeply $hand->{helm_values}{ipam}{operator}{clusterPoolIPv4PodCIDRList}, ['10.42.0.0/16'],
        'fallback on a hand-run';
};

subtest '_live_cilium reads cilium-config and the DaemonSet, read-only' => sub {
    my $live = OCPTest::Rexfile->helper('_live_cilium');

    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = cilium_node({ ipam => 'cluster-pool', pool => ['10.0.0.0/8'], host => 'localhost' });
    is_deeply $live->(kubectl => 'K', kubeconfig => '/k'),
        { ipam => 'cluster-pool', pool => ['10.0.0.0/8'], k8s_service_host => 'localhost' }, 'mode, pool, API address';
    my @cmds = OCPTest::Rexfile->commands;
    like $cmds[0], qr/^K -n kube-system get configmap cilium-config -o jsonpath=/, 'a get';
    like $cmds[0], qr/\{\.data\.ipam\}.*cluster-pool-ipv4-cidr/, 'mode and pool keys';
    like $cmds[1], qr/^K -n kube-system get daemonset cilium -o jsonpath=.*KUBERNETES_SERVICE_HOST/, 'a get';
    ok !(grep { !/ get / } @cmds), 'nothing but gets';
    is( (OCPTest::Rexfile->calls('run'))[0]{args}[1]{env}{KUBECONFIG}, '/k', 'kubeconfig');

    local $OCPTest::Rexfile::RUN = cilium_node({ ipam => 'cluster-pool', pool => ['10.0.0.0/8', '172.30.0.0/16'] });
    is_deeply $live->(kubectl => 'K', kubeconfig => '/k')->{pool}, ['10.0.0.0/8', '172.30.0.0/16'],
        'a list is space-separated';

    local $OCPTest::Rexfile::RUN = cilium_node(undef);
    is $live->(kubectl => 'K', kubeconfig => '/k'), undef, 'no cilium-config: no Cilium';

    local $OCPTest::Rexfile::RUN = sub { ('The connection to the server was refused', 1) };
    ok !eval { $live->(kubectl => 'K', kubeconfig => '/k'); 1 }, 'unreadable for another reason: dies';
    like $@, qr/Cannot read the running Cilium's configuration/, 'rather than guess an IPAM mode';
};

subtest 'an upgrade never moves the pool to ocp.yaml\'s value' => sub {
    my $live = { ipam => 'cluster-pool', pool => ['10.0.0.0/8'], host => '203.0.113.7' };
    for my $task (qw( upgrade_cilium install_cilium )) {
        my $o = cilium_opts_after($task, $live, distribution => 'rke2', pod_cidr => '172.20.0.0/16');
        ok $o, "$task calls the library" or next;
        is_deeply $o->{helm_values}{ipam},
            { mode => 'cluster-pool', operator => { clusterPoolIPv4PodCIDRList => ['10.0.0.0/8'] } },
            "$task: the LIVE pool, never the configured one";
    }

    my $o = cilium_opts_after('upgrade_cilium', { ipam => 'kubernetes' }, distribution => 'rke2');
    is_deeply $o->{helm_values}{ipam}, { mode => 'kubernetes' }, 'a running IPAM mode is kept too';

    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = cilium_node(undef);
    ok !eval { OCPTest::Rexfile->run_task('upgrade_cilium', { %PINS }); 1 }, 'no Cilium: upgrade_cilium dies';
    is scalar(OCPTest::Rexfile->calls('Rex::Rancher::Cilium::upgrade_cilium')), 0, 'without upgrading anything';
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

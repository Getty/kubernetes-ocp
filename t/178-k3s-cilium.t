#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);
use YAML::XS ();

use lib 'lib';
use OCP::Rex;

no warnings 'once';   # the stub package is filled by a string eval

#
# k178: a k3s cluster came up with Flannel and kube-proxy next to Cilium.
#
# install_k3s_server wrote only `token:` into /etc/rancher/k3s/config.yaml (k156)
# and the installer line carried --disable=traefik/servicelb, nothing about the
# CNI. So k3s started Flannel (flannel.1, cni0, pods on 10.42.x), its
# kube-router network policy controller and kube-proxy; Cilium, installed with
# kubeProxyReplacement=true, managed 0 of 5 pods, and `cilium status --wait`
# ran its full 10 minutes. Rex's `run` does not die on a non-zero exit without
# auto_die, so the apply then printed "Cilium installed successfully".
#
# The claims here:
#   1. the k3s server config.yaml carries the whole server configuration --
#      token, flannel-backend: none, disable-network-policy, disable-kube-proxy,
#      the packaged traefik/servicelb switched off, the kubeconfig mode, the
#      node name and tls-san -- and the installer line is bare;
#   2. Cilium on k3s is pointed at an API server address that exists on every
#      node (the control plane's, not localhost: k3s agents proxy the API on
#      127.0.0.1:6444, not 6443), and its IPAM pool matches k3s' cluster-cidr;
#   3. Cilium never becoming ready fails the task, loudly and by name.
#
# Network-free and Rex-session-free, like t/86, t/90 and t/93: helpers are
# lifted out of the Rexfile and run against stubs. Whether a real k3s node now
# runs without Flannel is a live question and is NOT claimed here.
#

my $root    = path(__FILE__)->parent->parent;
my $rexfile = $root->child('share/Rexfile');

plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

my $src = $rexfile->slurp_utf8;

my $TOKEN = 'K10deadbeef::server:s3cr3t-token-value-0123456789';

my @subs;
for my $name (qw( _default_pod_cidr _k3s_server_config _k3s_install_cmd
                  _cilium_install_args _cilium_pool_args _wait_for_cilium )) {
    # one-liners first, or the block pattern runs on to the next sub's brace
    my ($body) = $src =~ /^(sub \Q$name\E \{[^\n]*\})$/m;
    ($body) = $src =~ /^(sub \Q$name\E \{.*?^\})/ms unless defined $body;
    ok defined $body, "share/Rexfile defines $name"
        or BAIL_OUT("k178 fix absent: $name is not in the Rexfile");
    push @subs, $body;
}

my $stubs = <<'PERL';
package RexfileK3sCilium;
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

my $config_for = RexfileK3sCilium->can('_k3s_server_config');
my $cmd        = RexfileK3sCilium->can('_k3s_install_cmd');
my $args_for   = RexfileK3sCilium->can('_cilium_install_args');
my $wait       = RexfileK3sCilium->can('_wait_for_cilium');

# --- 1. the server config.yaml ----------------------------------------------

subtest 'k3s server config.yaml hands CNI, policy and kube-proxy to Cilium' => sub {
    my $yaml = $config_for->(
        token     => $TOKEN,
        node_name => 'police1',
        tls_sans  => [ '203.0.113.7', 'cp.example.com' ],
    );
    my $c = eval { YAML::XS::Load($yaml) };
    ok $c, 'parses as YAML' or return diag "$@\n$yaml";

    is $c->{token}, $TOKEN, 'token';
    is $c->{'flannel-backend'}, 'none', 'flannel-backend: none -- no Flannel';
    ok $c->{'disable-network-policy'}, 'disable-network-policy: true -- Cilium enforces policy';
    ok $c->{'disable-kube-proxy'}, 'disable-kube-proxy: true -- Cilium replaces kube-proxy';
    is_deeply [ sort @{ $c->{disable} // [] } ], [qw( servicelb traefik )],
        'disable: traefik, servicelb (were installer flags)';
    is $c->{'write-kubeconfig-mode'}, '0644',
        'write-kubeconfig-mode stays a quoted string, not an octal-looking number';
    like $yaml, qr/^write-kubeconfig-mode: "0644"$/m, 'written quoted';
    is $c->{'node-name'}, 'police1', 'node-name';
    is_deeply $c->{'tls-san'}, [ '203.0.113.7', 'cp.example.com' ], 'tls-san, one entry per address';
    is $c->{'cluster-cidr'}, '10.42.0.0/16', 'cluster-cidr spelled out (matches Cilium IPAM)';
};

subtest 'optional keys stay out when not given' => sub {
    my $c = YAML::XS::Load($config_for->(token => $TOKEN));
    ok !exists $c->{'node-name'}, 'no node-name';
    ok !exists $c->{'tls-san'},   'no tls-san';
    is $c->{'flannel-backend'}, 'none', 'the CNI switches are unconditional';
};

subtest 'the k3s server installer line is bare' => sub {
    my $c = $cmd->(role => 'server', version => 'v1.36.4+k3s1', node_name => 'police1');
    like   $c, qr/\bsh -s - server$/, 'ends in the explicit server argument';
    unlike $c, qr/--/, 'no flags left on the line -- config.yaml has them';
    unlike $c, qr/\Q$TOKEN\E|K3S_TOKEN/, 'and still no token (k156)';
};

sub task_body {
    my ($name) = @_;
    my ($body) = $src =~ /^task "\Q$name\E", sub \{\n(.*?)\n\};$/ms;
    return $body;
}

subtest 'install_k3s_server writes the built config before installing' => sub {
    my $body = task_body('install_k3s_server');
    ok defined $body, 'task found' or return;
    like $body, qr/_k3s_server_config\(/, 'builds config.yaml with _k3s_server_config';
    like $body, qr/tls_san/, 'reads the tls_san parameter';
    my $write_at = index $body, '_write_secret_file("/etc/rancher/k3s/config.yaml", $config)';
    my $run_at   = index $body, 'run _k3s_install_cmd(';
    ok $write_at >= 0, 'through the 0600 writer';
    ok $write_at >= 0 && $run_at > $write_at, 'before the installer runs';
};

# --- 2. Cilium install flags --------------------------------------------------

subtest 'rke2: Cilium flags' => sub {
    my $a = $args_for->(distribution => 'rke2');
    like   $a, qr/--set kubeProxyReplacement=true/, 'kube-proxy replacement';
    like   $a, qr/--set k8sServiceHost=localhost /, 'localhost (the RKE2 agent LB listens on 6443)';
    like   $a, qr/--set k8sServicePort=6443\b/, 'port 6443';
    like   $a, qr/--set gatewayAPI\.enabled=true/, 'Gateway API';
    # k182: RKE2 gets the same pool as k3s now, not Cilium's 10.0.0.0/8
    like   $a, qr/--set ipam\.operator\.clusterPoolIPv4PodCIDRList=10\.42\.0\.0\/16\b/,
        'IPAM pool = cluster-cidr (k182)';
};

subtest 'k3s: Cilium reaches the API server at the control plane address' => sub {
    my $a = $args_for->(distribution => 'k3s', k8s_service_host => '203.0.113.7');
    like   $a, qr/--set kubeProxyReplacement=true/, 'kube-proxy replacement';
    like   $a, qr/--set k8sServiceHost=203\.0\.113\.7 /, 'control plane address';
    like   $a, qr/--set k8sServicePort=6443\b/, 'port 6443';
    unlike $a, qr/k8sServiceHost=localhost/, 'not localhost -- a k3s agent has no 6443 there';
    like   $a, qr/--set ipam\.operator\.clusterPoolIPv4PodCIDRList=10\.42\.0\.0\/16\b/,
        'IPAM pool = k3s cluster-cidr';
    like   $a, qr/--set gatewayAPI\.enabled=true/, 'Gateway API';
};

subtest 'k3s without an API server address is refused, not guessed' => sub {
    ok !eval { $args_for->(distribution => 'k3s'); 1 }, 'dies';
    like $@, qr/k8s_service_host/, 'and names the missing parameter';
};

subtest 'install_cilium uses the helpers' => sub {
    my $body = task_body('install_cilium');
    ok defined $body, 'task found' or return;
    like $body, qr/_cilium_install_args\(/, 'install flags from _cilium_install_args';
    like $body, qr/k8s_service_host/, 'passes k8s_service_host through';
    like $body, qr/_wait_for_cilium\(/, 'waits through _wait_for_cilium';
    unlike $body, qr/run 'cilium status --wait/, 'no bare, unchecked status wait left';
    like task_body('upgrade_cilium'), qr/_wait_for_cilium\(/,
        'upgrade_cilium waits the same checked way';
};

# --- 3. a Cilium that never gets ready fails the task -------------------------

subtest '_wait_for_cilium: ready passes' => sub {
    local @RexfileK3sCilium::RUNS = ();
    local $RexfileK3sCilium::EXIT = 0;
    ok eval { $wait->(kubeconfig => '/etc/rancher/k3s/k3s.yaml', duration => '10m'); 1 },
        'no exception' or diag $@;
    like $RexfileK3sCilium::RUNS[0][0], qr/^cilium status --wait --wait-duration=10m/, 'waits';
    is $RexfileK3sCilium::RUNS[0][1]{env}{KUBECONFIG}, '/etc/rancher/k3s/k3s.yaml', 'kubeconfig';
};

subtest '_wait_for_cilium: not ready dies and says so' => sub {
    local @RexfileK3sCilium::RUNS = ();
    local $RexfileK3sCilium::EXIT = 1;
    local $RexfileK3sCilium::OUT  = "Cluster Pods: 0/5 managed by Cilium\n";
    ok !eval { $wait->(kubeconfig => '/k', duration => '10m'); 1 }, 'dies';
    like $@, qr/Cilium did not become ready within 10m/, 'names the failure and the wait';
    like $@, qr{0/5 managed by Cilium}, 'carries the status output';
};

subtest '_wait_for_cilium: a Rex timeout dies too' => sub {
    local @RexfileK3sCilium::RUNS = ();
    local $RexfileK3sCilium::EXIT = 300;
    ok !eval { $wait->(kubeconfig => '/k', duration => '5m'); 1 }, 'dies';
    like $@, qr/within 5m/, 'with the duration';
};

# --- OCP::Rex hands install_cilium the control plane address -------------------

subtest 'OCP::Rex::install_server passes tls_san and k8s_service_host for k3s' => sub {
    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 };
    local *OCP::Rex::fetch_kubeconfig_ssh   = sub { "apiVersion: v1\n" };
    local *OCP::Rex::_existing_server_token = sub { undef };

    my $tmp = path(tempdir(CLEANUP => 1));
    my $key = $tmp->child('id'); $key->spew('k'); path("$key.pub")->spew('k');
    OCP::Rex->new(host => '127.0.0.1', advertised_host => '203.0.113.7',
                  key_file => $key->stringify)
        ->install_server(distribution => 'k3s', version => 'v1.36.4+k3s1');

    my ($server) = grep { $_->[0] eq 'install_k3s_server' } @calls;
    ok $server, 'install_k3s_server ran' or return;
    is $server->[1]{tls_san}, '203.0.113.7', 'tls_san = advertised address';

    my ($cilium) = grep { $_->[0] eq 'install_cilium' } @calls;
    ok $cilium, 'install_cilium ran' or return;
    is $cilium->[1]{distribution},     'k3s',         'distribution';
    is $cilium->[1]{k8s_service_host}, '203.0.113.7', 'the advertised address, not the SSH transport';
};

done_testing;

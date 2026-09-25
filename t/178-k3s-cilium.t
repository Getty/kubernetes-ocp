#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);

use lib 'lib';
use lib 't/lib';
use OCP::Rex;
use OCPTest::Rexfile;

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
# Since k155 the server config and the Cilium install are Rex::Rancher's
# (rex-rancher k36 took over exactly the configuration verified live here). The
# claims split accordingly:
#   1. install_k3s_server hands Rex::Rancher::Server::install_server a k3s
#      server with Cilium as its CNI (the library's default; that it writes
#      flannel-backend: none, disable-network-policy, disable-kube-proxy and
#      disables traefik/servicelb is held against the real library in
#      t/155-rex-libraries.t), with node name and every tls-san address;
#   2. Cilium on k3s is pointed at an API server address that exists on every
#      node (the control plane's, not localhost: k3s agents proxy the API on
#      127.0.0.1:6444, not 6443), and its IPAM pool matches k3s' cluster-cidr;
#   3. Cilium never becoming ready fails the task, loudly and by name: OCP asks
#      Rex::Rancher to wait (0.003, rex-rancher k43), which dies naming the
#      DaemonSet's and the operator's state -- held against the real library
#      in t/155-rex-libraries.t, like the k3s address it reads off a running
#      Cilium and the refusal when there is none.
#
# Network-free: the Rexfile runs against recorders (t/lib/OCPTest/Rexfile.pm).
# Whether a real k3s node now runs without Flannel is a live question and is
# NOT claimed here.
#

my $TOKEN = 'K10deadbeef::server:s3cr3t-token-value-0123456789';

my $KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n";
my %PINS = (version => '1.20.0', cli_version => 'v0.19.7', gateway_api_version => 'v1.6.1');

# A node with its admin kubeconfig readable.
sub fresh_node {
    my ($cmd) = @_;
    return ($KUBECONFIG, 0) if $cmd =~ /^cat /;
    return ('', 0);
}

# --- 1. the server --------------------------------------------------------------

subtest 'install_k3s_server hands the library a Cilium-only k3s server' => sub {
    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_k3s_server', {
        token     => $TOKEN,
        node_name => 'police1',
        tls_san   => [ '203.0.113.7', 'cp.example.com' ],
        version   => 'v1.36.4+k3s1',
    });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    ok $o, 'install_server called' or return;
    is $o->{distribution}, 'k3s', 'k3s';
    is $o->{token}, $TOKEN, 'token';
    is $o->{node_name}, 'police1', 'node-name';
    is_deeply $o->{tls_san}, [ '203.0.113.7', 'cp.example.com' ], 'tls-san, one entry per address';
    is $o->{version}, 'v1.36.4+k3s1', 'version pin';
    ok !exists $o->{cilium}, 'cilium left at the library default (on): Cilium is the only CNI';
    ok !exists $o->{disable}, 'disable left at the library default (traefik, servicelb)';
};

subtest 'optional keys stay out when not given' => sub {
    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_k3s_server', { token => $TOKEN });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    ok !defined $o->{node_name}, 'no node-name';
    ok !exists $o->{tls_san}, 'no tls-san';
};

subtest 'install_k3s_server waits for the API before it reports ready' => sub {
    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_k3s_server', { token => $TOKEN });
    my $install = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::Rancher::Server::install_server' });
    my $wait    = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'run' && $_->{args}[0] =~ /kubectl .*get nodes/ });
    ok $install >= 0 && $wait > $install, 'kubectl get nodes, after the install';

    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = sub { $_[0] =~ /get nodes/ ? ('', 1) : ('', 0) };
    ok !eval { OCPTest::Rexfile->run_task('install_k3s_server', { token => $TOKEN }); 1 },
        'an API that never answers fails the task';
    like $@, qr/did not answer/, 'and says so';
};

# --- 2. Cilium install options -----------------------------------------------------

subtest 'rke2: Cilium options' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = \&fresh_node;
    OCPTest::Rexfile->run_task('install_cilium', { %PINS, distribution => 'rke2' });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::install_cilium');
    ok $o, 'install_cilium called' or return;
    is $o->{distribution}, 'rke2', 'rke2';
    ok !exists $o->{k8s_service_host},
        'no k8s_service_host: the library uses 127.0.0.1:6443, which every RKE2 node serves';
    ok $o->{gateway_api}, 'Gateway API';
    is_deeply $o->{helm_values}{ipam}, { mode => 'cluster-pool' }, 'cluster-pool IPAM';
    is $o->{cluster_cidr}, '10.42.0.0/16', 'its pool = cluster-cidr (k182)';
};

subtest 'k3s: Cilium reaches the API server at the control plane address' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = \&fresh_node;
    OCPTest::Rexfile->run_task('install_cilium',
        { %PINS, distribution => 'k3s', k8s_service_host => '203.0.113.7' });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::install_cilium');
    ok $o, 'install_cilium called' or return;
    is $o->{k8s_service_host}, '203.0.113.7', 'control plane address';
    is $o->{cluster_cidr}, '10.42.0.0/16', 'IPAM pool = k3s cluster-cidr';
    ok $o->{gateway_api}, 'Gateway API';
};

subtest 'k3s without an API server address: nothing guessed' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = \&fresh_node;
    OCPTest::Rexfile->run_task('install_cilium', { %PINS, distribution => 'k3s' });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::install_cilium');
    ok !exists $o->{k8s_service_host},
        'none passed: the library takes the running Cilium\'s, or dies before the node is touched';

    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_cilium', { %PINS, distribution => 'k3s', k8s_service_host => '' });
    ok !exists OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::install_cilium')->{k8s_service_host},
        'an empty one is none';
};

subtest 'the library talks to the API through a kubeconfig pointed at the node' => sub {
    my $ext = OCPTest::Rexfile->helper('_external_kubeconfig')->(
        "clusters:\n- cluster:\n    certificate-authority-data: QUJD\n    server: https://127.0.0.1:6443\n",
        '203.0.113.7');
    like $ext, qr{server: https://203\.0\.113\.7:6443}, 'server at the Rex host';
    unlike $ext, qr/certificate-authority-data/, 'CA dropped';
    like $ext, qr/insecure-skip-tls-verify: true/, 'as for every kubeconfig OCP uses';

    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = \&fresh_node;
    OCPTest::Rexfile->run_task('install_cilium', { %PINS, distribution => 'rke2' });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::install_cilium');
    ok $o->{kubeconfig} && $o->{kubeconfig} =~ /ocp-kubeconfig-\w+\.yaml$/, 'a local temp file';
    ok !-e $o->{kubeconfig}, 'gone again once the task is done';
    ok((grep { $_ eq 'cat /etc/rancher/rke2/rke2.yaml' } OCPTest::Rexfile->commands),
        'read off the node');
};

# --- 3. a Cilium that never gets ready fails the task -------------------------

subtest 'install_cilium and upgrade_cilium have the library wait, bounded' => sub {
    for my $t ([ install_cilium => 600 ], [ upgrade_cilium => 300 ]) {
        my ($task, $secs) = @$t;
        OCPTest::Rexfile->reset;
        local $OCPTest::Rexfile::RUN = \&fresh_node;
        OCPTest::Rexfile->run_task($task, { %PINS, distribution => 'rke2' });
        my $o = OCPTest::Rexfile->lib_opts("Rex::Rancher::Cilium::$task");
        ok $o->{wait}, "$task: wait";
        is $o->{wait_duration}, $secs, "$task: at most ${secs}s";
        ok !(grep { /^cilium / } OCPTest::Rexfile->commands), "$task: no cilium status of its own";
    }
};

subtest 'a Cilium that is not ready fails the task with the library\'s message' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = \&fresh_node;
    local $OCPTest::Rexfile::LIB_DIE{'Rex::Rancher::Cilium::install_cilium'} =
        "Cilium was not ready within 600s: cilium 0/5 ready, 5/5 updated\n";
    ok !eval { OCPTest::Rexfile->run_task('install_cilium', { %PINS, distribution => 'k3s',
        k8s_service_host => '203.0.113.7' }); 1 }, 'dies';
    like $@, qr{not ready within 600s: cilium 0/5 ready}, 'naming the state';
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

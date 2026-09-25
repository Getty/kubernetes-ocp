#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

#
# k160: upgrade_cilium re-applies the pinned Gateway API CRDs BEFORE it
# upgrades Cilium.
#
# Gateway API is version-locked to Cilium (OCP::Versions): 1.20 refuses to
# start its Gateway controller without TLSRoute v1 and BackendTLSPolicy v1,
# which only the v1.5+ bundles carry. install_cilium applies the bundle
# (k157), but the drift remedy upgrade_cilium once went straight to
# `cilium upgrade` -- a Cilium bump on an existing cluster kept whatever CRDs
# it was installed with, and the new Cilium came up without a Gateway
# controller.
#
# Since k155 upgrade_cilium is Rex::Rancher::Cilium::upgrade_cilium with
# gateway_api on: the library applies the bundle first and dies before the
# Helm upgrade when that fails (held against the real library in
# t/155-rex-libraries.t). Held here: OCP asks for exactly that, with the pin,
# and refuses to start without the pins. The Rexfile runs against recorders
# (t/lib/OCPTest/Rexfile.pm). What a live `cilium upgrade` does with the new
# CRDs is NOT claimed here.
#

my %params = (
    version             => '1.20.0',
    cli_version         => 'v0.19.7',
    gateway_api_version => 'v1.6.1',
);

my $KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n";

sub node {
    my ($cmd) = @_;
    return ($KUBECONFIG, 0) if $cmd =~ /^cat /;
    return ('', 0);
}

sub upgrade {
    my (%p) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = \&node;
    local %ENV = %ENV;
    delete @ENV{qw(OCP_GATEWAY_API_VERSION OCP_CILIUM_CLI_VERSION)};
    my $ok  = eval { OCPTest::Rexfile->run_task('upgrade_cilium', {%p}); 1 };
    return ($ok, $@, OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::upgrade_cilium'));
}

subtest 'the pinned CRDs travel with the upgrade (rke2)' => sub {
    my ($ok, $err, $o) = upgrade(%params);
    ok $ok, 'the task succeeds' or diag $err;
    ok $o, 'Rex::Rancher::Cilium::upgrade_cilium called' or return;
    is $o->{version}, '1.20.0', 'to the pinned Cilium';
    is $o->{cli_version}, 'v0.19.7', 'with the pinned CLI';
    ok $o->{gateway_api}, 'Gateway API CRDs applied (by the library, before the upgrade)';
    is $o->{gateway_api_version}, 'v1.6.1', 'the pinned bundle';
    is $o->{gateway_api_channel}, 'standard', 'standard channel';
    like $o->{kubeconfig}, qr/ocp-kubeconfig-/, 'through a kubeconfig fetched from the node';
    ok((grep { $_ eq 'cat /etc/rancher/rke2/rke2.yaml' } OCPTest::Rexfile->commands),
        'the RKE2 admin kubeconfig');
};

subtest 'k3s: its own kubeconfig, and the API address the agents already use' => sub {
    my ($ok, $err, $o) = upgrade(%params, distribution => 'k3s');
    ok $ok, 'the task succeeds' or diag $err;
    is $o->{distribution}, 'k3s', 'k3s';
    ok !exists $o->{k8s_service_host},
        'no k8sServiceHost passed: the library reads the running DaemonSet\'s (t/155-rex-libraries.t)';
    ok((grep { $_ eq 'cat /etc/rancher/k3s/k3s.yaml' } OCPTest::Rexfile->commands),
        'the k3s admin kubeconfig');
};

for my $pin (qw( gateway_api_version cli_version version )) {
    subtest "no $pin: refused before anything runs" => sub {
        my %p = %params;
        delete $p{$pin};
        my ($ok, $err) = upgrade(%p);
        ok !$ok, 'dies';
        like $err, qr/required/, 'names the missing pin';
        is scalar(@OCPTest::Rexfile::CALLS), 0, 'before touching the node';
    };
}

subtest 'OCP_GATEWAY_API_VERSION serves hand-runs' => sub {
    my %p = %params;
    delete $p{gateway_api_version};
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = \&node;
    local $ENV{OCP_GATEWAY_API_VERSION} = 'v1.6.1';
    ok eval { OCPTest::Rexfile->run_task('upgrade_cilium', {%p}); 1 }, 'the task succeeds' or diag $@;
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::upgrade_cilium');
    is $o->{gateway_api_version}, 'v1.6.1', 'the env pin is applied';
};

subtest 'a failed upgrade (e.g. the CRD apply) fails the task' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = \&node;
    local $OCPTest::Rexfile::LIB_DIE{'Rex::Rancher::Cilium::upgrade_cilium'} =
        "denied by safe-upgrades.gateway.networking.k8s.io\n";
    ok !eval { OCPTest::Rexfile->run_task('upgrade_cilium', {%params}); 1 }, 'dies';
    like $@, qr/safe-upgrades/, 'with the library\'s error';
    ok !(grep { /^cilium / } OCPTest::Rexfile->commands), 'and runs no cilium command of its own';
};

# k182: the pool a running Cilium hands out survives the upgrade. Rex::Rancher
# reads it off cilium-config through the API and keeps it (t/155-rex-libraries.t);
# the task hands it neither a pool nor pod_cidr to override it with.
subtest 'the running pod pool is not overridden by the upgrade' => sub {
    my ($ok, $err, $o) = upgrade(%params, pod_cidr => '172.20.0.0/16');
    ok $ok, 'the task succeeds' or diag $err;
    is_deeply $o->{helm_values}{ipam}, { mode => 'cluster-pool' }, 'the mode stated, no pool';
    ok !exists $o->{cluster_cidr}, 'no cluster_cidr: pod_cidr does not reach the upgrade';
};

done_testing;

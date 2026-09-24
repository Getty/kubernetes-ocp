#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

#
# k164: update_gateway_api, the remedy OCP::Drift names when the Gateway API
# CRD bundle on the cluster is behind the gateway_api pin, from the wrong
# channel, or missing.
#
# It does what install_cilium does for the CRDs and nothing else: apply the
# pinned standard bundle through _apply_gateway_api_crds, with the node's
# kubectl and kubeconfig for the distribution, then bounce a running
# cilium-operator so it reads the new schemas (controller-runtime caches CRD
# schemas at startup, and unlike upgrade_cilium no new image rolls the pods).
# The name follows `ocp update`'s update_<component> fallback, so
# `ocp update --component gateway_api` reaches the same task.
#
# It stays OCP's own after k155: Rex::Rancher::Cilium applies the CRDs only as
# part of install/upgrade and keeps that step private (rex-rancher k43). The
# Rexfile runs against recorders (t/lib/OCPTest/Rexfile.pm). What a live
# operator does with the new CRDs is NOT claimed here.
#

# A node whose cilium-operator runs (or not); a CRD apply that fails on demand.
sub runs_for {
    my (%p) = @_;
    my $operator = delete $p{operator} // 1;
    my $fail     = delete $p{fail_apply};
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = sub {
        my ($cmd) = @_;
        return ('denied by safe-upgrades', 1) if $fail && $cmd =~ /standard-install/;
        return ($operator ? "deployment.apps/cilium-operator\n" : '', $operator ? 0 : 1)
            if $cmd =~ /get deployment cilium-operator/;
        return ("ok\n", 0);
    };
    local %ENV = %ENV;
    delete $ENV{OCP_GATEWAY_API_VERSION} unless delete $p{keep_env};
    my $ok  = eval { OCPTest::Rexfile->run_task('update_gateway_api', {%p}); 1 };
    my $err = $@;
    return ($ok, $err, [ OCPTest::Rexfile->calls('run') ]);
}

sub index_of {
    my ($runs, $re) = @_;
    for my $i (0 .. $#$runs) { return $i if $runs->[$i]{args}[0] =~ $re }
    return -1;
}

subtest 'rke2: the pinned standard bundle, then the operator bounce' => sub {
    my ($ok, $err, $runs) = runs_for(version => 'v1.6.1');
    ok $ok, 'the task succeeds' or diag $err;

    my $crds = index_of($runs, qr{gateway-api/releases/download/v1\.6\.1/standard-install\.yaml});
    my $bounce = index_of($runs, qr/rollout restart deployment cilium-operator/);
    cmp_ok $crds, '>=', 0, 'the bundle of the passed version is applied';
    cmp_ok $bounce, '>', $crds, 'and cilium-operator is restarted after it';

    my ($cmd, $o) = @{ $runs->[$crds]{args} };
    like $cmd, qr{^/var/lib/rancher/rke2/bin/kubectl apply --server-side\b},
        'through the RKE2 node kubectl, server-side';
    is_deeply $o->{env}, { KUBECONFIG => '/etc/rancher/rke2/rke2.yaml' },
        'against the RKE2 kubeconfig';
    is_deeply $runs->[$bounce]{args}[1]{env}, { KUBECONFIG => '/etc/rancher/rke2/rke2.yaml' },
        'the restart too';
    is index_of($runs, qr/^cilium /), -1, 'Cilium itself is not touched';
    is scalar(grep { $_->{name} =~ /^Rex::Rancher::Cilium::/ } @OCPTest::Rexfile::CALLS), 0,
        'nor through the library';
};

subtest 'k3s uses its own kubectl and kubeconfig' => sub {
    my ($ok, $err, $runs) = runs_for(version => 'v1.6.1', distribution => 'k3s');
    ok $ok, 'the task succeeds' or diag $err;

    my $crds = index_of($runs, qr/standard-install\.yaml/);
    my ($cmd, $o) = @{ $runs->[$crds]{args} };
    like $cmd, qr{^kubectl apply }, 'plain kubectl on k3s';
    is_deeply $o->{env}, { KUBECONFIG => '/etc/rancher/k3s/k3s.yaml' },
        'against the k3s kubeconfig';
};

subtest 'no cilium-operator running: nothing to restart' => sub {
    my ($ok, $err, $runs) = runs_for(version => 'v1.6.1', operator => 0);
    ok $ok, 'the task succeeds' or diag $err;
    cmp_ok index_of($runs, qr/standard-install\.yaml/), '>=', 0, 'CRDs applied';
    is index_of($runs, qr/rollout restart/), -1, 'no restart of an operator that is not there';
};

subtest 'no version: refused before anything runs' => sub {
    my ($ok, $err, $runs) = runs_for();
    ok !$ok, 'dies';
    like $err, qr/OCP_GATEWAY_API_VERSION.*required/, 'names the missing pin';
    is scalar(@$runs), 0, 'before touching the node';
};

subtest 'OCP_GATEWAY_API_VERSION serves hand-runs' => sub {
    local $ENV{OCP_GATEWAY_API_VERSION} = 'v1.6.1';
    my ($ok, $err, $runs) = runs_for(keep_env => 1);
    ok $ok, 'the task succeeds' or diag $err;
    cmp_ok index_of($runs, qr/v1\.6\.1\/standard-install\.yaml/), '>=', 0, 'the env pin is applied';
};

subtest 'a failed CRD apply stops before the restart' => sub {
    my ($ok, $err, $runs) = runs_for(version => 'v1.6.1', fail_apply => 1);
    ok !$ok, 'dies';
    like $err, qr/Gateway API/, 'with the helper\'s error';
    is index_of($runs, qr/rollout restart/), -1,
        'the operator is not bounced onto a half-applied bundle';
};

done_testing;

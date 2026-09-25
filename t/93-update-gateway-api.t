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
# pinned standard bundle and bounce a running cilium-operator so it reads the
# new schemas (controller-runtime caches CRD schemas at startup, and unlike
# upgrade_cilium no new image rolls the pods). The name follows `ocp update`'s
# update_<component> fallback, so `ocp update --component gateway_api`
# reaches the same task.
#
# Since Rex::Rancher 0.003 that is Rex::Rancher::Cilium::ensure_gateway_api_crds
# (rex-rancher k43): the standard bundle through the API from this machine,
# skipped when version and channel already match, the operator restarted only
# when it was applied, a failure dying before the restart -- held against the
# real library in t/155-rex-libraries.t. Held here: OCP asks for exactly that,
# through a kubeconfig fetched off the node, and nothing else. The Rexfile runs
# against recorders (t/lib/OCPTest/Rexfile.pm). What a live operator does with
# the new CRDs is NOT claimed here.
#

my $KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n";

sub update {
    my (%p) = @_;
    my $keep_env = delete $p{keep_env};
    my $lib_die  = delete $p{lib_die};
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_DIE{'Rex::Rancher::Cilium::ensure_gateway_api_crds'} = $lib_die;
    local $OCPTest::Rexfile::RUN = sub { $_[0] =~ /^cat / ? ($KUBECONFIG, 0) : ('', 0) };
    local %ENV = %ENV;
    delete $ENV{OCP_GATEWAY_API_VERSION} unless $keep_env;
    my $out;
    my $ok  = eval { $out = OCPTest::Rexfile->run_task('update_gateway_api', {%p}); 1 };
    return ($ok, $@, OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::ensure_gateway_api_crds'), $out);
}

subtest 'rke2: the pinned standard bundle, through the library' => sub {
    my ($ok, $err, $o) = update(version => 'v1.6.1');
    ok $ok, 'the task succeeds' or diag $err;
    ok $o, 'ensure_gateway_api_crds called' or return;
    is $o->{version}, 'v1.6.1', 'the passed version';
    is $o->{channel}, 'standard', 'standard channel';
    like $o->{kubeconfig}, qr/ocp-kubeconfig-\w+\.yaml$/, 'through a local kubeconfig';
    ok((grep { $_ eq 'cat /etc/rancher/rke2/rke2.yaml' } OCPTest::Rexfile->commands),
        'fetched off the node: the RKE2 admin kubeconfig');
    is scalar(grep { $_->{name} =~ /^Rex::Rancher::Cilium::(?:install|upgrade)_cilium$/ } @OCPTest::Rexfile::CALLS), 0,
        'Cilium itself is not touched';
    ok !(grep { !/^cat / } OCPTest::Rexfile->commands), 'and nothing is run on the node but that read';
};

subtest 'k3s uses its own kubeconfig' => sub {
    my ($ok, $err) = update(version => 'v1.6.1', distribution => 'k3s');
    ok $ok, 'the task succeeds' or diag $err;
    ok((grep { $_ eq 'cat /etc/rancher/k3s/k3s.yaml' } OCPTest::Rexfile->commands),
        'the k3s admin kubeconfig');
};

subtest 'it says whether it applied anything' => sub {
    my (undef, undef, undef, $out) = update(version => 'v1.6.1');
    like $out, qr/Gateway API CRDs at v1\.6\.1 \(standard channel\)/, 'applied';

    no warnings qw( redefine once );
    local *Rex::Rancher::Cilium::ensure_gateway_api_crds = sub { 0 };
    (undef, undef, undef, $out) = update(version => 'v1.6.1');
    like $out, qr/already at v1\.6\.1 .*nothing applied/, 'already current';
};

subtest 'no version: refused before anything runs' => sub {
    my ($ok, $err) = update();
    ok !$ok, 'dies';
    like $err, qr/OCP_GATEWAY_API_VERSION.*required/, 'names the missing pin';
    is scalar(@OCPTest::Rexfile::CALLS), 0, 'before touching the node';
};

subtest 'OCP_GATEWAY_API_VERSION serves hand-runs' => sub {
    local $ENV{OCP_GATEWAY_API_VERSION} = 'v1.6.1';
    my ($ok, $err, $o) = update(keep_env => 1);
    ok $ok, 'the task succeeds' or diag $err;
    is $o->{version}, 'v1.6.1', 'the env pin is applied';
};

subtest 'a failed CRD apply fails the task' => sub {
    my ($ok, $err) = update(version => 'v1.6.1', lib_die =>
        "Kubernetes API error (PATCH ...): 422 denied by safe-upgrades.gateway.networking.k8s.io\n");
    ok !$ok, 'dies';
    like $err, qr/safe-upgrades/, 'with the library\'s error';
};

done_testing;

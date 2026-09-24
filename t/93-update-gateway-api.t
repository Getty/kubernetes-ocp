#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

no warnings 'once';   # the stub package is filled by a string eval

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
# Network-free and Rex-session-free, like t/90 and t/91: the task and its
# helpers are lifted out of the Rexfile and run against a `run` stub. What a
# live operator does with the new CRDs is NOT claimed here.
#

my $root    = path(__FILE__)->parent->parent;
my $rexfile = $root->child('share/Rexfile');

plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

my $src = $rexfile->slurp_utf8;

my ($helper)  = $src =~ /^(sub _apply_gateway_api_crds \{.*?^\})/ms;
my ($restart) = $src =~ /^(sub _restart_cilium_operator \{.*?^\})/ms;
my ($task)    = $src =~ /^(task "update_gateway_api", sub \{\n.*?\n\};)$/ms;
ok defined $helper,  'share/Rexfile defines _apply_gateway_api_crds';
ok defined $restart, 'share/Rexfile defines _restart_cilium_operator';
ok defined $task,    'share/Rexfile defines the update_gateway_api task'
    or BAIL_OUT('update_gateway_api not found in the Rexfile');

my $stubs = <<'PERL';
package RexfileUpdateGatewayApi;
use constant { TRUE => 1, FALSE => 0 };
our (@RUNS, %TASKS, $OPERATOR);
sub run {
    my ($cmd, %o) = @_;
    push @RUNS, [ $cmd, \%o ];
    $? = 0;
    return $OPERATOR ? "deployment.apps/cilium-operator\n" : ''
        if $cmd =~ /get deployment cilium-operator/;
    return "ok\n";
}
sub say { }
sub task { my ($name, $code) = @_; $TASKS{$name} = $code }
sub task_params { my ($p) = @_; return $p }
PERL

ok eval("$stubs\n$helper\n$restart\n$task\n1;"), 'the lifted task compiles against a run stub'
    or BAIL_OUT("cannot compile the lifted task: $@");

my $update = $RexfileUpdateGatewayApi::TASKS{update_gateway_api}
    or BAIL_OUT('lifted update_gateway_api did not register');

sub runs_for {
    my (%p) = @_;
    local @RexfileUpdateGatewayApi::RUNS = ();
    local $RexfileUpdateGatewayApi::OPERATOR = delete $p{operator} // 1;
    local %ENV = %ENV;
    delete $ENV{OCP_GATEWAY_API_VERSION};
    my $ok  = eval { $update->({%p}); 1 };
    my $err = $@;
    return ($ok, $err, [ @RexfileUpdateGatewayApi::RUNS ]);
}

sub index_of {
    my ($runs, $re) = @_;
    for my $i (0 .. $#$runs) { return $i if $runs->[$i][0] =~ $re }
    return -1;
}

subtest 'rke2: the pinned standard bundle, then the operator bounce' => sub {
    my ($ok, $err, $runs) = runs_for(version => 'v1.6.1');
    ok $ok, 'the task succeeds' or diag $err;

    my $crds = index_of($runs, qr{gateway-api/releases/download/v1\.6\.1/standard-install\.yaml});
    my $bounce = index_of($runs, qr/rollout restart deployment cilium-operator/);
    cmp_ok $crds, '>=', 0, 'the bundle of the passed version is applied'
        or diag explain [ map { $_->[0] } @$runs ];
    cmp_ok $bounce, '>', $crds, 'and cilium-operator is restarted after it';

    my ($cmd, $o) = @{ $runs->[$crds] };
    like $cmd, qr{^/var/lib/rancher/rke2/bin/kubectl apply --server-side\b},
        'through the RKE2 node kubectl, server-side';
    is_deeply $o->{env}, { KUBECONFIG => '/etc/rancher/rke2/rke2.yaml' },
        'against the RKE2 kubeconfig';
    is_deeply $runs->[$bounce][1]{env}, { KUBECONFIG => '/etc/rancher/rke2/rke2.yaml' },
        'the restart too';
    is index_of($runs, qr/^cilium /), -1, 'Cilium itself is not touched';
};

subtest 'k3s uses its own kubectl and kubeconfig' => sub {
    my ($ok, $err, $runs) = runs_for(version => 'v1.6.1', distribution => 'k3s');
    ok $ok, 'the task succeeds' or diag $err;

    my $crds = index_of($runs, qr/standard-install\.yaml/);
    my ($cmd, $o) = @{ $runs->[$crds] // [ '', {} ] };
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
    local @RexfileUpdateGatewayApi::RUNS = ();
    local $RexfileUpdateGatewayApi::OPERATOR = 1;
    local $ENV{OCP_GATEWAY_API_VERSION} = 'v1.6.1';
    ok eval { $update->({}); 1 }, 'the task succeeds' or diag $@;
    cmp_ok index_of(\@RexfileUpdateGatewayApi::RUNS, qr/v1\.6\.1\/standard-install\.yaml/), '>=', 0,
        'the env pin is applied';
};

subtest 'a failed CRD apply stops before the restart' => sub {
    local @RexfileUpdateGatewayApi::RUNS = ();
    local $RexfileUpdateGatewayApi::OPERATOR = 1;
    no warnings 'redefine';
    local *RexfileUpdateGatewayApi::run = sub {
        my ($cmd, %o) = @_;
        push @RexfileUpdateGatewayApi::RUNS, [ $cmd, \%o ];
        $? = $cmd =~ /standard-install/ ? 1 << 8 : 0;
        return $cmd =~ /standard-install/ ? 'denied by safe-upgrades'
             : "deployment.apps/cilium-operator\n";
    };
    ok !eval { $update->({ version => 'v1.6.1' }); 1 }, 'dies';
    like $@, qr/Gateway API/, 'with the helper\'s error';
    is index_of(\@RexfileUpdateGatewayApi::RUNS, qr/rollout restart/), -1,
        'the operator is not bounced onto a half-applied bundle';
};

subtest 'install_cilium bounces the operator through the same helper' => sub {
    (my $code = $src) =~ s/^\s*#.*\n//mg;
    my ($install) = $code =~ /^task "install_cilium", sub \{\n(.*?)\n\};$/ms;
    like $install, qr/_restart_cilium_operator\(/, 'one restart, two callers';
    unlike $install, qr/rollout restart/, 'no second copy of the restart';
};

done_testing;

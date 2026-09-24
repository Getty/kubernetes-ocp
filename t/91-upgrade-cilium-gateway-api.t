#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

no warnings 'once';   # the stub package is filled by a string eval

#
# k160: upgrade_cilium re-applies the pinned Gateway API CRDs BEFORE it
# upgrades Cilium.
#
# Gateway API is version-locked to Cilium (OCP::Versions): 1.20 refuses to
# start its Gateway controller without TLSRoute v1 and BackendTLSPolicy v1,
# which only the v1.5+ bundles carry. install_cilium applies the bundle
# (k157), but the drift remedy upgrade_cilium went straight to
# `cilium upgrade` -- a Cilium bump on an existing cluster kept whatever CRDs
# it was installed with, and the new Cilium came up without a Gateway
# controller.
#
# Network-free and Rex-session-free, like t/90: the task and the helpers it
# calls are lifted out of the Rexfile and run against a `run` stub. What a
# live `cilium upgrade` does with the new CRDs is NOT claimed here.
#

my $root    = path(__FILE__)->parent->parent;
my $rexfile = $root->child('share/Rexfile');

plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

my $src = $rexfile->slurp_utf8;

my ($helper) = $src =~ /^(sub _apply_gateway_api_crds \{.*?^\})/ms;
my ($arch)   = $src =~ /^(sub _node_arch \{.*?^\})/ms;
my ($task)   = $src =~ /^(task "upgrade_cilium", sub \{\n.*?\n\};)$/ms;
ok defined $helper, 'share/Rexfile defines _apply_gateway_api_crds';
ok defined $arch,   'share/Rexfile defines _node_arch';
ok defined $task,   'share/Rexfile defines the upgrade_cilium task'
    or BAIL_OUT('upgrade_cilium not found in the Rexfile');

my $stubs = <<'PERL';
package RexfileUpgradeCilium;
use constant { TRUE => 1, FALSE => 0 };
our (@RUNS, %TASKS);
sub run {
    my ($cmd, %o) = @_;
    push @RUNS, [ $cmd, \%o ];
    $? = 0;
    return "Linux\n"  if $cmd eq 'uname -s';
    return "x86_64\n" if $cmd eq 'uname -m';
    return "ok\n";
}
sub say { }
sub task { my ($name, $code) = @_; $TASKS{$name} = $code }
sub task_params { my ($p) = @_; return $p }
PERL

ok eval("$stubs\n$helper\n$arch\n$task\n1;"), 'the lifted task compiles against a run stub'
    or BAIL_OUT("cannot compile the lifted task: $@");

my $upgrade = $RexfileUpgradeCilium::TASKS{upgrade_cilium}
    or BAIL_OUT('lifted upgrade_cilium did not register');

my %params = (
    version             => '1.20.0',
    cli_version         => 'v0.19.7',
    gateway_api_version => 'v1.6.1',
);

sub runs_for {
    my (%p) = @_;
    local @RexfileUpgradeCilium::RUNS = ();
    local %ENV = %ENV;
    delete @ENV{qw(OCP_GATEWAY_API_VERSION OCP_CILIUM_CLI_VERSION)};
    my $ok  = eval { $upgrade->({%p}); 1 };
    my $err = $@;
    return ($ok, $err, [ @RexfileUpgradeCilium::RUNS ]);
}

sub index_of {
    my ($runs, $re) = @_;
    for my $i (0 .. $#$runs) { return $i if $runs->[$i][0] =~ $re }
    return -1;
}

subtest 'the pinned CRDs are applied before cilium upgrade (rke2)' => sub {
    my ($ok, $err, $runs) = runs_for(%params);
    ok $ok, 'the task succeeds' or diag $err;

    my $crds = index_of($runs, qr/gateway-api\/releases\/download\/v1\.6\.1\/standard-install\.yaml/);
    my $up   = index_of($runs, qr/^cilium upgrade --version 1\.20\.0\b/);
    cmp_ok $crds, '>=', 0, 'the Gateway API bundle of the pinned version is applied'
        or diag explain [ map { $_->[0] } @$runs ];
    cmp_ok $up, '>', $crds, 'and that happens BEFORE cilium upgrade';

    my ($cmd, $o) = @{ $runs->[$crds] };
    like $cmd, qr{^/var/lib/rancher/rke2/bin/kubectl apply --server-side\b},
        'through the RKE2 node kubectl, server-side';
    is_deeply $o->{env}, { KUBECONFIG => '/etc/rancher/rke2/rke2.yaml' },
        'against the RKE2 kubeconfig';
};

subtest 'k3s uses its own kubectl and kubeconfig' => sub {
    my ($ok, $err, $runs) = runs_for(%params, distribution => 'k3s');
    ok $ok, 'the task succeeds' or diag $err;

    my $crds = index_of($runs, qr/standard-install\.yaml/);
    cmp_ok $crds, '>=', 0, 'CRDs applied';
    my ($cmd, $o) = @{ $runs->[$crds] // [ '', {} ] };
    like $cmd, qr{^kubectl apply }, 'plain kubectl on k3s';
    is_deeply $o->{env}, { KUBECONFIG => '/etc/rancher/k3s/k3s.yaml' },
        'against the k3s kubeconfig';
};

subtest 'no Gateway API version: refused before anything runs' => sub {
    my %p = %params;
    delete $p{gateway_api_version};
    my ($ok, $err, $runs) = runs_for(%p);
    ok !$ok, 'dies';
    like $err, qr/OCP_GATEWAY_API_VERSION.*required/, 'names the missing pin';
    is scalar(@$runs), 0, 'before touching the node'
        or diag explain [ map { $_->[0] } @$runs ];
};

subtest 'OCP_GATEWAY_API_VERSION serves hand-runs' => sub {
    my %p = %params;
    delete $p{gateway_api_version};
    local @RexfileUpgradeCilium::RUNS = ();
    local $ENV{OCP_GATEWAY_API_VERSION} = 'v1.6.1';
    ok eval { $upgrade->({%p}); 1 }, 'the task succeeds' or diag $@;
    cmp_ok index_of(\@RexfileUpgradeCilium::RUNS, qr/v1\.6\.1\/standard-install\.yaml/), '>=', 0,
        'the env pin is applied';
};

subtest 'a failed CRD apply stops the upgrade' => sub {
    local @RexfileUpgradeCilium::RUNS = ();
    no warnings 'redefine';
    local *RexfileUpgradeCilium::run = sub {
        my ($cmd, %o) = @_;
        push @RexfileUpgradeCilium::RUNS, [ $cmd, \%o ];
        $? = $cmd =~ /standard-install/ ? 1 << 8 : 0;
        return $cmd =~ /standard-install/ ? 'denied by safe-upgrades' : "Linux\n";
    };
    ok !eval { $upgrade->({%params}); 1 }, 'dies';
    like $@, qr/Gateway API/, 'with the helper\'s error';
    is index_of(\@RexfileUpgradeCilium::RUNS, qr/^cilium upgrade/), -1,
        'cilium upgrade never runs';
};

done_testing;

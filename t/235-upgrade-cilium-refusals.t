#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

#
# k206: Rex::Rancher's upgrade_cilium refuses a cluster without a deployed
# Cilium release and one with a Helm operation hanging over it, and its advice
# ("Use install_cilium") has no user path in OCP. The upgrade_cilium task now
# gives it one, for both `ocp apply` (drift remedy) and `ocp update`:
#
#   - no deployed release: Cilium is a core component, so the task installs it
#     with install_cilium (the library removes a release left behind), the pool
#     being network.pod_cidr;
#   - a stuck release: nothing is done automatically, the error carries the
#     command that clears it.
#
# The messages below are the library's own (Rex::Rancher::Cilium,
# _require_deployed_release and _die_release_stuck). The Rexfile runs against
# recorders; what a real install does on a cluster without Cilium is NOT
# claimed here.
#

my %params = (
    version             => '1.20.0',
    cli_version         => 'v0.19.7',
    gateway_api_version => 'v1.6.1',
    pod_cidr            => '10.77.0.0/16',
);

my $KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n";
sub node { my ($cmd) = @_; return $cmd =~ /^cat / ? ($KUBECONFIG, 0) : ('', 0) }

sub upgrade {
    my ($die, %p) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = \&node;
    local %ENV = %ENV;
    delete @ENV{qw(OCP_GATEWAY_API_VERSION OCP_CILIUM_CLI_VERSION)};
    $OCPTest::Rexfile::LIB_DIE{'Rex::Rancher::Cilium::upgrade_cilium'} = $die if defined $die;
    my $out = eval { OCPTest::Rexfile->run_task('upgrade_cilium', {%params, %p}) };
    return ($out, $@);
}

my $NO_RELEASE = "upgrade_cilium found no deployed revision of Helm release cilium in kube-system "
  . "(no release): cilium upgrade upgrades a deployed Helm release and cannot install one, whether "
  . "or not cilium-config or the cilium DaemonSet exist. Install Cilium with install_cilium\n";
my $FAILED = "upgrade_cilium found no deployed revision of Helm release cilium in kube-system "
  . "(latest revision 1 is failed): cilium upgrade upgrades a deployed Helm release and cannot install "
  . "one, whether or not cilium-config or the cilium DaemonSet exist. Use install_cilium, which "
  . "removes the release left behind and installs Cilium again\n";
my $STUCK = "Helm release cilium is stuck in pending-upgrade (revision 3): an earlier run was "
  . "interrupted or another deploy is still running. Once none is, delete Secret "
  . "sh.helm.release.v1.cilium.v3 in kube-system and re-run.\n";

for my $case ([ 'no release' => $NO_RELEASE ], [ 'a failed release' => $FAILED ]) {
    my ($name, $msg) = @$case;
    subtest "$name: Cilium is installed instead" => sub {
        my ($out, $err) = upgrade($msg);
        ok !$err, 'the task succeeds' or diag $err;
        my $i = OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::install_cilium');
        ok $i, 'install_cilium called' or return;
        is $i->{version}, '1.20.0', 'at the pin';
        is $i->{cli_version}, 'v0.19.7', 'with the pinned CLI';
        is $i->{gateway_api_version}, 'v1.6.1', 'and the pinned Gateway API bundle';
        is $i->{cluster_cidr}, '10.77.0.0/16', 'the pool is network.pod_cidr';
        like $out, qr/no deployed Cilium release.*installing Cilium 1\.20\.0/s,
            'said, as a warning the apply narrative carries';
    };
}

subtest 'a stuck release: no install, the command that clears it' => sub {
    my ($out, $err) = upgrade($STUCK);
    like $err, qr/is stuck in pending-upgrade/, 'the library\'s diagnosis stays';
    like $err, qr/^\s+kubectl -n kube-system delete secret sh\.helm\.release\.v1\.cilium\.v3$/m,
        'the Secret to delete, as a command';
    ok !OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::install_cilium'),
        'install_cilium is not tried over a hanging operation';
};

subtest 'any other refusal is passed on untouched' => sub {
    my ($out, $err) = upgrade("Cilium runs 1.17.0, version 1.20.0 is more than one minor version away\n");
    like $err, qr/more than one minor version away/, 'dies with the library\'s message';
    ok !OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::install_cilium'), 'no install';
};

subtest 'a successful upgrade installs nothing' => sub {
    my ($out, $err) = upgrade(undef);
    ok !$err, 'ok';
    ok !OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::install_cilium'), 'no install';
};

done_testing;

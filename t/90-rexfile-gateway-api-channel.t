#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

#
# k157: the Gateway API CRDs come from exactly ONE channel, and a failed apply
# stops the install.
#
# install_cilium used to apply standard-install.yaml and then
# experimental-install.yaml on top, the second with auto_die => FALSE. From
# Gateway API v1.5 both bundles carry the ValidatingAdmissionPolicy
# safe-upgrades.gateway.networking.k8s.io, installed by the first apply, which
# refuses experimental CRDs over standard ones. With the v1.6.1 pin every
# experimental CRD update was denied and nobody saw it.
#
# The channel is standard: v1.6.1's standard bundle carries everything Cilium
# 1.20 requires (TLSRoute v1, BackendTLSPolicy v1, ReferenceGrant, GRPCRoute),
# plus TCPRoute/UDPRoute. It is also the only channel every existing OCP
# cluster can be re-applied with: the ones installed under the v1.6.1 pin are
# on standard already (experimental was refused), and older ones on
# experimental may move to standard -- the policy only refuses the other
# direction.
#
# Since k155 install_cilium and upgrade_cilium apply the CRDs through
# Rex::Rancher::Cilium (before Cilium, dying on failure -- held against the
# real library in t/155-rex-libraries.t), whose default channel is
# experimental; so the claim here is that OCP always hands it `standard`. The
# CRD-only remedy update_gateway_api keeps OCP's own server-side kubectl apply
# (rex-rancher k43), whose helper is exercised directly. The Rexfile runs
# against recorders (t/lib/OCPTest/Rexfile.pm). Whether the apply succeeds
# against a live v1.6.1 cluster is NOT claimed here.
#

my $apply = OCPTest::Rexfile->helper('_apply_gateway_api_crds');

my %args = (
    kubectl    => '/var/lib/rancher/rke2/bin/kubectl',
    kubeconfig => '/etc/rancher/rke2/rke2.yaml',
    version    => 'v1.6.1',
);

subtest 'exactly one apply, of the standard channel' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = sub {
        ("customresourcedefinition.apiextensions.k8s.io/gateways.gateway.networking.k8s.io serverside-applied\n", 0)
    };

    ok eval { $apply->(%args); 1 }, 'succeeds when kubectl does' or diag $@;

    my @runs = OCPTest::Rexfile->calls('run');
    is scalar(@runs), 1, 'one kubectl call';
    my ($cmd, $o) = @{ $runs[0]{args} };

    like $cmd, qr{^/var/lib/rancher/rke2/bin/kubectl apply },
        'the node kubectl applies it';
    like $cmd, qr{ -f https://github\.com/kubernetes-sigs/gateway-api/releases/download/v1\.6\.1/standard-install\.yaml\b},
        'the standard bundle of the pinned version';
    unlike $cmd, qr/experimental/, 'no experimental bundle';
    like $cmd, qr/--server-side\b/,
        'server-side apply: no last-applied annotation to outgrow';
    like $cmd, qr/--force-conflicts\b/,
        'takes over fields a previous client-side apply owned';
    is_deeply $o->{env}, { KUBECONFIG => '/etc/rancher/rke2/rke2.yaml' },
        'against the node kubeconfig';
};

subtest 'a failed apply dies with kubectl output' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = sub {
        ('The customresourcedefinitions "tlsroutes.gateway.networking.k8s.io" is invalid: '
         . 'ValidatingAdmissionPolicy safe-upgrades.gateway.networking.k8s.io denied request', 1)
    };

    ok !eval { $apply->(%args); 1 }, 'dies';
    like $@, qr/Gateway API/, 'names what failed';
    like $@, qr/v1\.6\.1/, 'and the version';
    like $@, qr/safe-upgrades/, "carries kubectl's own reason";
};

subtest 'a missing version is refused, not guessed' => sub {
    OCPTest::Rexfile->reset;
    ok !eval { $apply->(%args, version => ''); 1 }, 'dies';
    is scalar(OCPTest::Rexfile->calls('run')), 0, 'before running anything';
};

# --- install_cilium and upgrade_cilium hand the library the standard channel ----

my $KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n";

for my $task (qw( install_cilium upgrade_cilium )) {
    subtest "$task: Rex::Rancher applies the pinned standard bundle" => sub {
        OCPTest::Rexfile->reset;
        local $OCPTest::Rexfile::RUN = sub {
            my ($cmd) = @_;
            return ($KUBECONFIG, 0) if $cmd =~ /^cat /;
            return ('cluster-pool|10.42.0.0/16', 0) if $cmd =~ /configmap cilium-config/;
            return ('', 0);
        };
        OCPTest::Rexfile->run_task($task, {
            distribution => 'rke2', version => '1.20.0', cli_version => 'v0.19.7',
            gateway_api_version => 'v1.6.1',
        });
        my $o = OCPTest::Rexfile->lib_opts("Rex::Rancher::Cilium::$task");
        ok $o, "Rex::Rancher::Cilium::$task called" or return;
        ok $o->{gateway_api}, 'the CRDs are applied (before Cilium, by the library)';
        is $o->{gateway_api_version}, 'v1.6.1', 'at the pinned version';
        is $o->{gateway_api_channel}, 'standard', 'standard -- never the library default, experimental';
        ok !(grep { /-install\.yaml/ } OCPTest::Rexfile->commands),
            'and the Rexfile applies no bundle of its own on top';
    };
}

(my $code = OCPTest::Rexfile->rexfile->slurp_utf8) =~ s/^\s*#.*\n//mg;   # comments may name it
unlike $code, qr/experimental/, 'no experimental channel anywhere in the Rexfile code';
is scalar(() = $code =~ /-install\.yaml/g), 1, 'exactly one Gateway API bundle URL in the Rexfile code';

done_testing;

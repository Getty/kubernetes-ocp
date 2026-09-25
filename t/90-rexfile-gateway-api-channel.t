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
# experimental; so the claim here is that OCP always hands it `standard`.
# Since Rex::Rancher 0.003 the CRD-only remedy update_gateway_api goes through
# the library too (ensure_gateway_api_crds, rex-rancher k43), so the Rexfile
# applies no bundle of its own anywhere. The Rexfile runs against recorders
# (t/lib/OCPTest/Rexfile.pm). Whether the apply succeeds against a live v1.6.1
# cluster is NOT claimed here.
#

# --- install_cilium and upgrade_cilium hand the library the standard channel ----

my $KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n";

for my $task (qw( install_cilium upgrade_cilium )) {
    subtest "$task: Rex::Rancher applies the pinned standard bundle" => sub {
        OCPTest::Rexfile->reset;
        local $OCPTest::Rexfile::RUN = sub {
            my ($cmd) = @_;
            return ($KUBECONFIG, 0) if $cmd =~ /^cat /;
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

subtest 'update_gateway_api: the standard channel too' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = sub { $_[0] =~ /^cat / ? ($KUBECONFIG, 0) : ('', 0) };
    OCPTest::Rexfile->run_task('update_gateway_api', { version => 'v1.6.1' });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::ensure_gateway_api_crds');
    ok $o, 'Rex::Rancher::Cilium::ensure_gateway_api_crds called' or return;
    is $o->{channel}, 'standard', 'standard -- never the library default, experimental';
};

(my $code = OCPTest::Rexfile->rexfile->slurp_utf8) =~ s/^\s*#.*\n//mg;   # comments may name it
unlike $code, qr/experimental/, 'no experimental channel anywhere in the Rexfile code';
unlike $code, qr/-install\.yaml/, 'no Gateway API bundle URL of its own in the Rexfile code';

done_testing;

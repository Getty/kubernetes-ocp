#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

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
# Network-free and Rex-session-free, following t/68, t/85 and t/86: the helper
# is lifted out of the Rexfile and run against a `run` stub that sets $?.
# Whether the apply succeeds against a live v1.6.1 cluster is NOT claimed here.
#

my $root    = path(__FILE__)->parent->parent;
my $rexfile = $root->child('share/Rexfile');

plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

my $src = $rexfile->slurp_utf8;

my ($helper) = $src =~ /^(sub _apply_gateway_api_crds \{.*?^\})/ms;
ok defined $helper, 'share/Rexfile defines _apply_gateway_api_crds'
    or BAIL_OUT('k157 fix absent: _apply_gateway_api_crds is not in the Rexfile');

my $stubs = <<'PERL';
package RexfileGatewayApi;
use constant { TRUE => 1, FALSE => 0 };
our (@RUNS, $EXIT, $OUT);
sub run {
    my ($cmd, %o) = @_;
    push @RUNS, [ $cmd, \%o ];
    $? = $EXIT << 8;
    return $OUT;
}
sub say { }
PERL

ok eval("$stubs\n$helper\n1;"), 'the lifted helper compiles against a run stub'
    or BAIL_OUT("cannot compile the lifted helper: $@");

my $apply = RexfileGatewayApi->can('_apply_gateway_api_crds');

my %args = (
    kubectl    => '/var/lib/rancher/rke2/bin/kubectl',
    kubeconfig => '/etc/rancher/rke2/rke2.yaml',
    version    => 'v1.6.1',
);

subtest 'exactly one apply, of the standard channel' => sub {
    local @RexfileGatewayApi::RUNS = ();
    local $RexfileGatewayApi::EXIT = 0;
    local $RexfileGatewayApi::OUT  = "customresourcedefinition.apiextensions.k8s.io/gateways.gateway.networking.k8s.io serverside-applied\n";

    ok eval { $apply->(%args); 1 }, 'succeeds when kubectl does' or diag $@;

    my @runs = @RexfileGatewayApi::RUNS;
    is scalar(@runs), 1, 'one kubectl call' or diag explain \@runs;
    my ($cmd, $o) = @{ $runs[0] };

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
    local @RexfileGatewayApi::RUNS = ();
    local $RexfileGatewayApi::EXIT = 1;
    local $RexfileGatewayApi::OUT  = 'The customresourcedefinitions "tlsroutes.gateway.networking.k8s.io" is invalid: '
        . 'ValidatingAdmissionPolicy safe-upgrades.gateway.networking.k8s.io denied request';

    ok !eval { $apply->(%args); 1 }, 'dies';
    like $@, qr/Gateway API/, 'names what failed';
    like $@, qr/v1\.6\.1/, 'and the version';
    like $@, qr/safe-upgrades/, "carries kubectl's own reason";
};

subtest 'a missing version is refused, not guessed' => sub {
    local @RexfileGatewayApi::RUNS = ();
    ok !eval { $apply->(%args, version => ''); 1 }, 'dies';
    is scalar(@RexfileGatewayApi::RUNS), 0, 'before running anything';
};

# --- the task wires it ------------------------------------------------------

(my $code = $src) =~ s/^\s*#.*\n//mg;   # comments may name it; code may not

my ($task) = $code =~ /^task "install_cilium", sub \{\n(.*?)\n\};$/ms;
ok defined $task, 'install_cilium task found';

like $task, qr/_apply_gateway_api_crds\(/, 'install_cilium applies the CRDs through the helper';
unlike $code, qr/experimental-install\.yaml/, 'no experimental bundle anywhere in the Rexfile code';
is scalar(() = $code =~ /-install\.yaml/g), 1, 'exactly one Gateway API bundle URL in the Rexfile code';

my $helper_at = index $task, '_apply_gateway_api_crds(';
my $cilium_at = index $task, 'cilium install';
ok $helper_at >= 0 && $cilium_at > $helper_at, 'the CRDs are applied BEFORE cilium install';

done_testing;

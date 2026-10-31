#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Network;

#
# k300: `ocp apply` printed "Creating Cilium Gateway..." on every run, waited
# for Accepted and then called the Gateway up to date -- over a Gateway created
# once and still at generation 1 after six applies (amdlab, 2026-10-31). Now
# the Gateway is read first: absent (a 404, and only that, k269) is
# "Creating Cilium Gateway...", the generation unmoved by the apply is
# "already deployed (up to date)" -- the wording of the registry, NFD, the GPU
# operator and the AMD GPU stack -- and a moved one is "updated". The step
# returns which, in report_component's vocabulary. The Accepted wait is skipped
# only when the read after the apply already says Accepted for the generation
# the Gateway has; a Gateway never accepted, or accepted only for an earlier
# spec, is still waited for.
#

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $code->() };
        $died = $@;
    }
    return ($rv, $out, $err, $died);
}

{
    package FakeResponse;
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}
{
    # _request answers each GET of the Gateway from a queue, the last answer
    # repeating; the reads are recorded.
    package GatewayApi;
    sub new { my ($c, @answers) = @_; bless { answers => [ @answers ], reads => 0 }, $c }
    sub _request {
        my ($self, $method, $path) = @_;
        die "unexpected $method $path\n" unless $method eq 'GET' && $path eq $main::GW_PATH;
        $self->{reads}++;
        my $q = $self->{answers};
        my $answer = @$q > 1 ? shift @$q : $q->[0];
        return FakeResponse->new(@$answer);
    }
}
{
    package FakeOCP;
    sub new     { bless {}, shift }
    sub verbose { 0 }
}

our $GW_PATH = '/apis/gateway.networking.k8s.io/v1/namespaces/kube-system/gateways/cilium-gateway';

my $NONE = [ 404, '{"kind":"Status","code":404}' ];

# A Gateway as the API server returns it: its generation, and the Accepted
# condition when the controller wrote one (status, observedGeneration).
sub gw {
    my ($generation, $accepted, $observed) = @_;
    my $gw = { metadata => { name => 'cilium-gateway', namespace => 'kube-system',
                             generation => $generation } };
    $gw->{status}{conditions} = [ { type => 'Accepted', status => $accepted,
                                    observedGeneration => $observed // $generation } ]
        if defined $accepted;
    return [ 200, JSON::PP->new->encode($gw) ];
}

sub run_gateway {
    my (@answers) = @_;
    my $api = GatewayApi->new(@answers);
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    $apply->{_k8s_api} = $api;
    my (@applied, $waited);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_server_side_apply = sub { push @applied, $_[2]; 1 };
    local *OCP::Cmd::Apply::wait_seconds       = sub { $waited++ };
    my ($rv, $out, $err, $died) = capture { $apply->_setup_cilium_gateway(undef) };
    return { outcome => $rv, out => $out, err => $err, died => $died,
             applied => \@applied, waited => $waited // 0, reads => $api->{reads} };
}

subtest 'none there: "Creating Cilium Gateway...", waited for, deployed' => sub {
    my $r = run_gateway($NONE, gw(1), gw(1, 'True'));
    is $r->{died}, '', 'ran' or return diag $r->{died};
    is $r->{outcome}, 'deployed', 'deployed';
    is $r->{out}, "      Creating Cilium Gateway...\n"
                . "      Waiting for Gateway to be Accepted by Cilium...\n"
                . "      Gateway is accepted (Programmed will follow once cert-manager provides the Secret)\n",
        'says it creates it, then waits for Accepted';
    is scalar @{ $r->{applied} }, 1, 'applied once';
    is $r->{applied}[0]{kind}, 'Gateway', 'the Gateway';
    is $r->{applied}[0]{metadata}{name}, 'cilium-gateway', 'cilium-gateway';
    is $r->{err}, '', 'nothing on STDERR';
};

subtest 'there, unchanged, accepted: "already deployed (up to date)", no wait' => sub {
    my $r = run_gateway(gw(1, 'True'));
    is $r->{died}, '', 'ran' or return diag $r->{died};
    is $r->{outcome}, 'unchanged', 'unchanged';
    is $r->{out}, "      Cilium Gateway already deployed (up to date)\n",
        'the one line the other components say, and nothing else';
    unlike $r->{out}, qr/Creating/, 'not called created';
    is scalar @{ $r->{applied} }, 1, 'still applied: the forced apply takes back a field someone changed';
    is $r->{reads}, 2, 'read before and after the apply, no polling';
    is $r->{waited}, 0, 'not waited for';
};

subtest 'there, unchanged, not accepted: up to date, and waited for all the same' => sub {
    my $r = run_gateway(gw(1), gw(1), gw(1, 'True'));
    is $r->{died}, '', 'ran' or return diag $r->{died};
    is $r->{outcome}, 'unchanged', 'unchanged';
    like $r->{out}, qr/\A      Cilium Gateway already deployed \(up to date\)\n      Waiting for Gateway to be Accepted by Cilium\.\.\.\n/,
        'up to date, then the wait';
    like $r->{out}, qr/Gateway is accepted/, 'until accepted';

    $r = run_gateway(gw(1, 'False'));
    is $r->{died}, "Gateway 'cilium-gateway' did not become Accepted within 60s\n",
        'Accepted=False: the wait runs out and says so, as before';
    is $r->{waited}, 30, 'after the whole wait';
};

subtest 'there, unchanged, accepted only for an earlier generation: waited for' => sub {
    my $r = run_gateway(gw(2, 'True', 1), gw(2, 'True', 1), gw(2, 'True', 1), gw(2, 'True', 2));
    is $r->{died}, '', 'ran' or return diag $r->{died};
    is $r->{outcome}, 'unchanged', 'unchanged: the apply did not move the generation';
    like $r->{out}, qr/Waiting for Gateway to be Accepted/, 'a stale Accepted is no reason to skip the wait';
    is $r->{waited}, 1, 'past a stale read, until the condition is for generation 2';
};

subtest 'there, the apply changed the spec: updated, waited for the new generation' => sub {
    my $r = run_gateway(gw(1, 'True'), gw(2, 'True', 1), gw(2, 'True', 1), gw(2, 'True', 2));
    is $r->{died}, '', 'ran' or return diag $r->{died};
    is $r->{outcome}, 'updated', 'updated';
    is $r->{out}, "      Cilium Gateway updated (spec changed)\n"
                . "      Waiting for Gateway to be Accepted by Cilium...\n"
                . "      Gateway is accepted (Programmed will follow once cert-manager provides the Secret)\n",
        'says so, and waits';
    is $r->{waited}, 1, 'the Accepted of generation 1 did not count for generation 2, twice';
};

subtest 'a read before the apply that fails: no verdict, no apply' => sub {
    my $r = run_gateway([ 403, 'forbidden' ]);
    is $r->{died}, "GET $GW_PATH failed: HTTP 403 forbidden\n", 'dies with the cause';
    is $r->{out}, '', 'neither created nor up to date';
    is scalar @{ $r->{applied} }, 0, 'nothing applied';
};

subtest 'gateway_accepted' => sub {
    my $accepted = \&OCP::Cmd::Apply::Network::gateway_accepted;
    my $cond = sub { { metadata => { generation => $_[0] },
                       status => { conditions => [ { type => 'Accepted', status => $_[1],
                                                     (defined $_[2] ? (observedGeneration => $_[2]) : ()) } ] } } };
    ok !$accepted->(undef), 'no Gateway: no';
    ok !$accepted->({ metadata => { generation => 1 } }), 'no status: no';
    ok !$accepted->($cond->(1, 'False', 1)), 'Accepted=False: no';
    ok  $accepted->($cond->(1, 'True', 1)), 'Accepted=True for this generation: yes';
    ok  $accepted->($cond->(1, 'True', 2)), 'for a later one (a read racing the controller): yes';
    ok !$accepted->($cond->(3, 'True', 2)), 'for an earlier one: no';
    ok  $accepted->($cond->(3, 'True')), 'a condition that names no generation: as before, yes';
    ok !$accepted->({ status => { conditions => [ { type => 'Programmed', status => 'True' } ] } }),
        'another condition: no';
};

done_testing;

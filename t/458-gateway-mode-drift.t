#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);

use lib 'lib';
use OCP;
use OCP::Config;
use OCP::Drift;

#
# k458 (follow-up to k454): gateway.mode: host_network renders
# gatewayAPI.hostNetwork.* into the Cilium Helm values, and switching it on a
# running cluster takes `ocp update --component cilium --force` -- ocp apply
# does not re-run the Cilium Helm release at the same version. Nothing said
# that a cluster ran another mode than ocp.yaml asks for. OCP::Drift now reads
# gateway-api-hostnetwork-enabled from the cilium-config ConfigMap Cilium
# renders its values into and compares it with Config->gateway_host_network:
# a difference is a spec entry with no remedy and the manual step.
#
# Network-free: OCP::Config on temp files, the API a hash of objects.
#

my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

sub config_for {
    my ($spec) = @_;
    my $name = 'c' . int(rand(1_000_000));
    my $f = path($tmpdir)->child("$name.yaml");
    $ocp->dump_file($f->stringify, { name => $name, %$spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

my $local = { control_planes => [{ provider => 'local' }] };
my $HOST  = { %$local, gateway => { mode => 'host_network', node_selector => { 'ocp.io/gateway' => 'true' } } };

package FakeApi {
    sub new { my ($class, %o) = @_; bless { %o }, $class }
    sub get {
        my ($self, $kind, %a) = @_;
        die $self->{dies} if $self->{dies};
        my $obj = $self->{objects}{ join '/', $kind, $a{namespace} // '', $a{name} // '' };
        die "Kubernetes API error (get $kind): 404 $kind not found\n" unless $obj;
        return $obj;
    }
    sub list { +{ items => [] } }
    sub _request { FakeResponse->new }
}

package FakeResponse {
    sub new     { bless {}, shift }
    sub status  { 404 }
    sub content { '{"kind":"Status","code":404}' }
}

package main;

sub mode_drift {
    my ($spec, $live, %api) = @_;
    my $api = FakeApi->new(%api, objects => defined $live
        ? { 'ConfigMap/kube-system/cilium-config' => { data => $live } } : {});
    return OCP::Drift->new(config => config_for($spec), api => $api)->gateway_mode_drift;
}

subtest 'the mode matches: no drift' => sub {
    is_deeply [ mode_drift($local, { 'gateway-api-hostnetwork-enabled' => 'false' }) ], [],
        'load_balancer, Cilium not in host-network mode';
    is_deeply [ mode_drift($HOST, { 'gateway-api-hostnetwork-enabled' => 'true' }) ], [],
        'host_network, Cilium in host-network mode';
    is_deeply [ mode_drift($local, { 'cluster-pool-ipv4-cidr' => '10.42.0.0/16' }) ], [],
        'load_balancer, the key absent (a Cilium that renders none): not host-network';
};

subtest 'nothing to read: no drift' => sub {
    is_deeply [ mode_drift($HOST, undef) ], [], 'no cilium-config (a 404)';
};

subtest 'ocp.yaml asks for host_network, Cilium runs load_balancer' => sub {
    for my $live ({ 'gateway-api-hostnetwork-enabled' => 'false' }, {}) {
        my @d = mode_drift($HOST, $live);
        is scalar @d, 1, 'one entry' or next;
        my $e = $d[0];
        is $e->{kind}, 'spec', 'spec kind: a human runs the step';
        is $e->{component}, 'cilium_gateway', 'component';
        is $e->{expected}, 'host_network', 'expected';
        is $e->{actual}, 'load_balancer', 'actual';
        ok !$e->{remedy}, 'no remedy: apply does not re-run the Helm release';
        like $e->{message}, qr/load_balancer/, 'says what runs';
        like $e->{message}, qr/host_network/, 'and what ocp.yaml asks for';
        like $e->{manual_step}, qr/ocp update --component cilium --force/, 'names the step';
        ok !OCP::Drift->apply_closes($e), 'not one apply closes';
    }
};

subtest 'ocp.yaml asks for load_balancer, Cilium runs host_network' => sub {
    my @d = mode_drift($local, { 'gateway-api-hostnetwork-enabled' => 'true' });
    is scalar @d, 1, 'one entry' or return;
    is $d[0]{expected}, 'load_balancer', 'expected';
    is $d[0]{actual}, 'host_network', 'actual';
    like $d[0]{manual_step}, qr/ocp update --component cilium --force/, 'names the step';
};

subtest 'a read that fails otherwise: drift unknown, not "no drift"' => sub {
    my @d;
    {
        local $SIG{__WARN__} = sub { };
        @d = mode_drift($HOST, undef, dies => "Kubernetes API error (get ConfigMap): 403 forbidden\n");
    }
    is scalar @d, 1, 'one entry' or return;
    is $d[0]{kind}, 'error', 'an error entry';
    is $d[0]{component}, 'cilium_gateway', 'for the gateway mode';
    like $d[0]{message}, qr/drift unknown/, 'says so';
};

subtest 'detect includes the gateway mode check' => sub {
    my $api = FakeApi->new(objects => {
        'ConfigMap/kube-system/cilium-config' => { data => { 'gateway-api-hostnetwork-enabled' => 'false' } } });
    my $d = OCP::Drift->new(config => config_for($HOST), api => $api)->detect;
    ok((grep { ($_->{component} // '') eq 'cilium_gateway' } @$d), 'cilium_gateway entry in detect()');
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use YAML::XS ();
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Drift;

#
# k228 point 3 (lab 2026-10-16): a ClusterPolicy CRD in the cluster that
# differs from the shipped one (an old stub that required nothing) went
# unnoticed by the drift check and by apply; only the local hash in
# .ocp/deployed.yaml was compared.
#

my %shipped = map {
    $_->[0] => YAML::XS::LoadFile("share/gpu-operator/crds/$_->[1]")
} @OCP::Drift::GPU_CRDS;

my $stub = { spec => { versions => [ { name => 'v1', served => JSON::PP::true, storage => JSON::PP::true,
    schema => { openAPIV3Schema => { type => 'object', 'x-kubernetes-preserve-unknown-fields' => JSON::PP::true } } } ] } };

sub getter {
    my (%cluster) = @_;
    return sub {
        my ($name) = $_[0] =~ m{/customresourcedefinitions/(.+)\z} or return undef;
        return $cluster{$name};
    };
}

subtest 'fingerprint: version names and spec field names' => sub {
    my $fp = OCP::Drift->crd_fingerprint($shipped{'clusterpolicies.nvidia.com'});
    like $fp, qr/\Av1:.*\bdaemonsets\b.*\btoolkit\b/, 'the shipped ClusterPolicy CRD';
    is(OCP::Drift->crd_fingerprint($stub), 'v1:', 'the stub has no spec fields');

    # What the apiserver hands back is normalised -- defaults, re-encoded
    # values -- but carries the same names: no drift.
    my $stored = JSON::PP::decode_json(JSON::PP::encode_json($shipped{'clusterpolicies.nvidia.com'}));
    $stored->{spec}{conversion} = { strategy => 'None' };
    $stored->{status} = { acceptedNames => {} };
    is(OCP::Drift->crd_fingerprint($stored), $fp, 'normalised copy, same fingerprint');
};

subtest 'gpu_crds_differing' => sub {
    is_deeply [ OCP::Drift->gpu_crds_differing(getter(%shipped)) ], [], 'cluster has the shipped CRDs';
    is_deeply [ OCP::Drift->gpu_crds_differing(getter()) ], [], 'no CRDs in the cluster: not drift';
    is_deeply [ OCP::Drift->gpu_crds_differing(getter(%shipped, 'clusterpolicies.nvidia.com' => $stub)) ],
        ['clusterpolicies.nvidia.com'], 'the stub is found';
};

subtest 'drift entry: self-healing, counted as an action' => sub {
    {
        package FakeResp;
        sub new { my ($c, $code, $body) = @_; bless { c => $code, b => $body }, $c }
        sub status  { $_[0]{c} }
        sub content { $_[0]{b} }
    }
    {
        package FakeRawApi;
        sub new { my ($c, %crds) = @_; bless { crds => \%crds }, $c }
        sub _request {
            my ($self, $m, $path) = @_;
            my ($name) = $path =~ m{/customresourcedefinitions/(.+)\z};
            my $crd = $name && $self->{crds}{$name};
            return $crd ? FakeResp->new(200, JSON::PP::encode_json($crd)) : FakeResp->new(404, '{}');
        }
    }
    my $drift = OCP::Drift->new(config => bless({}, 'OCP::Config'),
        api => FakeRawApi->new(%shipped, 'clusterpolicies.nvidia.com' => $stub));
    my @e = $drift->gpu_crd_drift;
    is scalar @e, 1, 'one entry';
    is $e[0]{component}, 'gpu_operator_crd', 'component';
    like $e[0]{message}, qr/clusterpolicies\.nvidia\.com .*differs.*ocp apply re-applies it/, 'message';
    ok $e[0]{self_healing}, 'self-healing: the GPU step re-applies the CRDs';
};

subtest 'apply compares the cluster CRDs before calling the operator up to date' => sub {
    my $src = path('lib/OCP/Cmd/Apply/Workloads.pm')->slurp_utf8;
    like $src, qr/gpu_crds_differing.*?\$gpu_running && !\@crd_differ/s, 'a differing CRD is not "unchanged"';
};

done_testing;

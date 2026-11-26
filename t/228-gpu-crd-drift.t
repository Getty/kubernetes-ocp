#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use YAML::XS ();
use Path::Tiny qw(path);
use Storable ();
use IO::K8s;

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

# The ClusterPolicy CRD with a stub schema: what the apiserver stores of a CRD
# (group, names, scope -- required, and IO::K8s holds the typed read to them,
# k471), with a v1 that declares no spec fields.
my $stub = { %{ Storable::dclone($shipped{'clusterpolicies.nvidia.com'}) } };
$stub->{spec}{versions} = [ { name => 'v1', served => JSON::PP::true, storage => JSON::PP::true,
    schema => { openAPIV3Schema => { type => 'object', 'x-kubernetes-preserve-unknown-fields' => JSON::PP::true } } } ];

# gpu_crds_differing asks for a CRD by name (k471; by its path before).
sub getter {
    my (%cluster) = @_;
    return sub { $cluster{ $_[0] } };
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

subtest 'drift entry: self-healing where the GPU step runs, counted as an action' => sub {
    {
        # The CRDs by name, through a typed get of CustomResourceDefinition
        # as Kubernetes::REST hands them back: IO::K8s objects (k471).
        package FakeCrdApi;
        sub new { my ($c, %crds) = @_; bless { crds => \%crds, io => IO::K8s->new }, $c }
        sub k8s { $_[0]{io} }
        sub get {
            my ($self, $kind, %a) = @_;
            my $crd = $kind eq 'CustomResourceDefinition' && $self->{crds}{ $a{name} }
                or die "Kubernetes API error (get $kind): 404 NotFound\n";
            return $self->{io}->json_to_object($kind, JSON::PP::encode_json($crd));
        }
        # A node NFD labelled NVIDIA: the GPU step runs, and re-applies the
        # CRDs (k413; t/313 has the clusters where it skips).
        sub list { +{ items => [ { metadata => { name => 'gpu1' } } ] } }
    }
    { package FakeGpuConfig; sub new { bless {}, shift } sub gpu_enabled { 1 } }
    my $drift = OCP::Drift->new(config => FakeGpuConfig->new,
        api => FakeCrdApi->new(%shipped, 'clusterpolicies.nvidia.com' => $stub));
    my @e = $drift->gpu_crd_drift;
    is scalar @e, 1, 'one entry';
    is $e[0]{component}, 'gpu_operator_crd', 'component';
    like $e[0]{message}, qr/clusterpolicies\.nvidia\.com .*differs.*ocp apply re-applies it/, 'message';
    ok $e[0]{self_healing}, 'self-healing: the GPU step re-applies the CRDs where it runs';
};

subtest 'apply compares the cluster CRDs before calling the operator up to date' => sub {
    my $src = path('lib/OCP/Cmd/Apply/Workloads.pm')->slurp_utf8;
    like $src, qr/gpu_crds_differing.*?\$gpu_running\s*&& !\@crd_differ/s, 'a differing CRD is not "unchanged"';
};

done_testing;

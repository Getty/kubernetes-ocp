#!/usr/bin/env perl
# karr k471 -- a CRD is read with a typed get of CustomResourceDefinition.
#
# OCP::Cmd::Apply::K8s::crd_get (the writers: ensure_crds, deploy-robocop,
# the reconcile path's GPU step, node add's --node_ip check) and
# OCP::Drift::_read_crd (the drift check) read a CRD with a raw GET over
# Kubernetes::REST's private _request and decode_json. Both read it now
# through OCP::Drift::cluster_crd: a typed get, made plain with
# object_to_struct. The drift check compares what the writers are about to
# write, so what it compares must not move. The claims, for each of the four
# CRDs OCP ships (share/robocop/crds, share/gpu-operator/crds), as an
# apiserver hands them back (what it adds on its own included), through a
# real Kubernetes::REST client over a canned transport:
#
#   * the typed read asks for the CRD's own path, a GET
#   * the writers' read (crd_read) and the drift check's (cluster_crd) hand
#     back the same struct
#   * that struct is what the raw GET and decode_json handed back: spec in
#     full, so crd_fingerprint, crd_property_paths and crd_schema_diff are
#     the same -- for the CRD as shipped (no drift) and for one an older ocp
#     installed (the same "lacks")
#   * end to end: ocp_crd_drift and gpu_crd_drift find nothing on a cluster
#     with the shipped CRDs, and the older OCPNode CRD as before
#   * a 404 is no CRD for both readers; any other answer is said, never
#     taken for absent
#
# Network-free and cluster-free.

use strict;
use warnings;
use Test::More;

use JSON::MaybeXS ();
use Path::Tiny qw(path);
use Storable qw(dclone);
use YAML::XS ();

use Kubernetes::REST;
use Kubernetes::REST::HTTPResponse;

use lib 'lib';

use OCP;
use OCP::Cmd::Apply::K8s;
use OCP::Cmd::Node::Add;
use OCP::Drift;
use OCP::ErrorLine;

OCP::ErrorLine::set_cluster_endpoint(undef);

my $JSON = JSON::MaybeXS->new(utf8 => 1, canonical => 1);
my $BASE = '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/';

my %SHIPPED = map { $_->{metadata}{name} => $_ }
    grep { ref $_ eq 'HASH' && ($_->{kind} // '') eq 'CustomResourceDefinition' }
    map { YAML::XS::LoadFile("$_") }
    sort(path('share/robocop/crds')->children(qr/\.ya?ml\z/)),
    sort(path('share/gpu-operator/crds')->children(qr/\.ya?ml\z/));

is_deeply [ sort keys %SHIPPED ],
    [ sort 'ocpnodes.ocp.internal', 'ocpnodeproviders.ocp.internal',
      'clusterpolicies.nvidia.com', 'nvidiadrivers.nvidia.com' ],
    'the four CRDs OCP ships';

# As the apiserver hands a CRD back: JSON, with what it adds on its own.
sub stored {
    my ($crd) = @_;
    my $copy = $JSON->decode($JSON->encode($crd));
    $copy->{metadata}{uid}               = '6f1c2b2e-0d47-4a52-9a8f-4b1e2c3d4e5f';
    $copy->{metadata}{resourceVersion}   = '4711';
    $copy->{metadata}{generation}        = 3;
    $copy->{metadata}{creationTimestamp} = '2026-11-01T10:00:00Z';
    $copy->{spec}{conversion} = { strategy => 'None' };
    $copy->{status} = {
        acceptedNames  => { kind => $crd->{spec}{names}{kind}, plural => $crd->{spec}{names}{plural} },
        storedVersions => [ map { $_->{name} } @{ $crd->{spec}{versions} } ],
        conditions     => [ { type => 'Established', status => 'True', reason => 'InitialNamesAccepted',
                              message => 'the initial names have been accepted',
                              lastTransitionTime => '2026-11-01T10:00:01Z' } ],
    };
    return $copy;
}

{
    # The transport of a Kubernetes::REST client: the CRDs it has by name, as
    # JSON bodies; a 404 Status for any other path, or the [ status, body ]
    # in {fail}. Every request is kept.
    package Local::IO;
    sub new { my ($c, %a) = @_; bless { crds => {}, fail => {}, calls => [], %a }, $c }
    sub call {
        my ($self, $req) = @_;
        push @{ $self->{calls} }, [ $req->method, $req->url ];
        my ($name) = $req->url =~ m{/customresourcedefinitions/([^/?]+)\z};
        my $fail = defined $name && $self->{fail}{$name};
        return Kubernetes::REST::HTTPResponse->new(status => $fail->[0], content => $fail->[1]) if $fail;
        my $body = defined $name && $self->{crds}{$name};
        return Kubernetes::REST::HTTPResponse->new(status => 200, content => $body) if $body;
        return Kubernetes::REST::HTTPResponse->new(status => 404,
            content => '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}');
    }
}

sub client {
    my (%crds) = @_;
    my $io = Local::IO->new(crds => { map { $_ => $JSON->encode($crds{$_}) } keys %crds });
    my $api = Kubernetes::REST->new(
        server                    => { endpoint => 'https://10.9.8.7:6443' },
        credentials               => { token => 'k471-not-a-token' },
        resource_map_from_cluster => 0,
        io                        => $io,
    );
    return ($api, $io);
}

my %STORED = map { $_ => stored($SHIPPED{$_}) } keys %SHIPPED;

# The OCPNode CRD of an OCP from before k254: no nodeIP in spec or status.
my $OLD_NODE = dclone($SHIPPED{'ocpnodes.ocp.internal'});
for my $part (qw(spec status)) {
    my ($v1) = grep { $_->{name} eq 'v1' } @{ $OLD_NODE->{spec}{versions} };
    delete $v1->{schema}{openAPIV3Schema}{properties}{$part}{properties}{nodeIP};
}

for my $name (sort keys %SHIPPED) {
    subtest "$name: the typed read hands back what the raw GET did" => sub {
        my ($api, $io) = client(%STORED);
        my $raw    = $JSON->decode($io->{crds}{$name});   # what _request + decode_json gave
        my $drift  = OCP::Drift->cluster_crd($api, $name);
        my $writer = OCP::Cmd::Apply::K8s::crd_read(undef, $api, $name);

        is ref $drift, 'HASH', 'a plain hashref, not an object';
        is_deeply $io->{calls}, [ [ GET => "https://10.9.8.7:6443$BASE$name" ],
                                  [ GET => "https://10.9.8.7:6443$BASE$name" ] ],
            "one GET of the CRD's own path per read";
        is_deeply $writer, $drift, 'the writers read what the drift check reads';
        is_deeply $drift->{spec}, $raw->{spec}, 'spec as the raw GET had it, in full';
        is $drift->{metadata}{name}, $name, 'its name';

        is(OCP::Drift->crd_fingerprint($drift), OCP::Drift->crd_fingerprint($raw), 'the same fingerprint');
        is_deeply(OCP::Drift->crd_property_paths($drift), OCP::Drift->crd_property_paths($raw),
            'the same property paths');
        is_deeply [ OCP::Drift->crd_schema_diff($drift, $SHIPPED{$name}) ], [ [], [] ],
            'against the shipped one: no difference';
        is(OCP::Drift->crd_fingerprint($drift), OCP::Drift->crd_fingerprint($SHIPPED{$name}),
            "and the fingerprint the shipped one has");
    };
}

subtest 'an older CRD: the typed read finds what the raw GET found' => sub {
    my $name = 'ocpnodes.ocp.internal';
    my $old  = stored($OLD_NODE);
    my ($api, $io) = client(%STORED, $name => $old);
    my $raw   = $JSON->decode($io->{crds}{$name});
    my $typed = OCP::Drift->cluster_crd($api, $name);
    my @want  = OCP::Drift->crd_schema_diff($raw, $SHIPPED{$name});
    is_deeply \@want, [ [ 'spec.nodeIP', 'status.nodeIP' ], [] ], 'the raw read: it lacks nodeIP';
    is_deeply [ OCP::Drift->crd_schema_diff($typed, $SHIPPED{$name}) ], \@want, 'the typed read: the same';
    isnt(OCP::Drift->crd_fingerprint($typed), OCP::Drift->crd_fingerprint($SHIPPED{$name}),
        'and a fingerprint that differs');
    ok(!OCP::Cmd::Node::Add->_crd_declares_node_ip($typed), "node add's check: no spec.nodeIP");
    my ($current) = client(%STORED);
    ok(OCP::Cmd::Node::Add->_crd_declares_node_ip(OCP::Drift->cluster_crd($current, $name)),
        'the current one: it has');
};

subtest 'served: false survives the typed read' => sub {
    my $name = 'ocpnodes.ocp.internal';
    my $off  = stored($SHIPPED{$name});
    $_->{served} = JSON::MaybeXS::false() for @{ $off->{spec}{versions} };
    my ($api) = client(%STORED, $name => $off);
    my $typed = OCP::Drift->cluster_crd($api, $name);
    ok !$typed->{spec}{versions}[0]{served}, 'v1 is not served';
    ok(!OCP::Cmd::Node::Add->_crd_declares_node_ip($typed), "node add's check refuses it");
};

subtest 'end to end: the drift probes over the typed read' => sub {
    my ($api) = client(%STORED);
    my $drift = OCP::Drift->new(config => {}, api => $api);
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, @_ };
    is_deeply [ $drift->ocp_crd_drift ], [], "OCP's CRDs as shipped: no drift";
    is_deeply [ $drift->gpu_crd_drift ], [], "the GPU Operator's CRDs as shipped: no drift";

    ($api) = client(%STORED, 'ocpnodes.ocp.internal' => stored($OLD_NODE));
    my @e = OCP::Drift->new(config => {}, api => $api)->ocp_crd_drift;
    is scalar @e, 1, 'the older OCPNode CRD: one entry';
    like $e[0]{message}, qr/\AOCPNode CRD \(ocpnodes\.ocp\.internal\) in the cluster lacks spec\.nodeIP, status\.nodeIP, /,
        'it lacks nodeIP';
    ok $e[0]{self_healing}, 'one ocp apply closes';
    is_deeply \@warn, [], 'nothing on stderr';
};

subtest 'a 404 is no CRD; any other answer is said' => sub {
    my ($api) = client();
    is(OCP::Drift->cluster_crd($api, 'ocpnodes.ocp.internal'), undef, 'cluster_crd: undef');
    is(OCP::Cmd::Apply::K8s::crd_read(undef, $api, 'ocpnodes.ocp.internal'), undef, 'crd_read: undef');

    my $io;
    ($api, $io) = client(%STORED);
    $io->{fail}{'ocpnodes.ocp.internal'} = [ 403,
        '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}' ];
    my $err = eval { OCP::Drift->cluster_crd($api, 'ocpnodes.ocp.internal'); 1 } ? '' : $@;
    is eval { $err->code }, 403, 'cluster_crd dies with the APIError';
    $err = eval { OCP::Cmd::Apply::K8s::crd_read(undef, $api, 'ocpnodes.ocp.internal'); 1 } ? '' : $@;
    is $err, "could not read CustomResourceDefinition ocpnodes.ocp.internal:"
        . " The cluster API denied the request (403 Forbidden)\n", 'crd_read: in one line';
};

done_testing;

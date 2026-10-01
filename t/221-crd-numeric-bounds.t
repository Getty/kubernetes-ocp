#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use Path::Tiny qw(path);

use lib 'lib';

#
# k221: with IO::K8s 1.109 every install_cilium died creating the Gateway API
# CRDs, a 400 from the API server ("cannot unmarshal string into ... of type
# float64"): JSONSchemaProps.minimum / maximum / multipleOf were typed Str, and
# 1.109 serialises every Str as a JSON string, so "minimum": 1 went out as
# "minimum": "1". Fixed in io-k8s-p5 k196 (IO::K8s 1.110, cpanfile floor).
#
# No test in this suite sent a real CRD with numeric bounds anywhere, so the
# break showed only on a live cluster. This one sends CRDs through exactly the
# path install_cilium takes -- Rex::Rancher::Cilium::ensure_gateway_api_crds:
# the bundle parsed with YAML::PP (boolean => JSON::PP), each document handed
# to Kubernetes::REST->ensure as a hashref, typed by IO::K8s, POSTed -- against
# a fake API server that records the request bodies, and asserts the bounds
# leave as JSON numbers.
#
# The documents: a Gateway API CRD with the numeric bounds the real bundle
# carries (port 1..65535, weight 0..1000000), and NVIDIA's ClusterPolicy CRD
# that OCP ships under share/, which is full of them.
#

BEGIN {
    eval { require Rex::Rancher::Cilium; require Kubernetes::REST; 1 }
        or plan skip_all => "Rex::Rancher::Cilium / Kubernetes::REST not loadable: $@";
}

my $GATEWAY_CRD = <<'YAML';
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: gateways.gateway.networking.k8s.io
  annotations:
    gateway.networking.k8s.io/bundle-version: v1.2.0
    gateway.networking.k8s.io/channel: standard
spec:
  group: gateway.networking.k8s.io
  names:
    kind: Gateway
    listKind: GatewayList
    plural: gateways
    singular: gateway
  scope: Namespaced
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            properties:
              listeners:
                type: array
                maxItems: 64
                minItems: 1
                items:
                  type: object
                  properties:
                    port:
                      type: integer
                      format: int32
                      minimum: 1
                      maximum: 65535
                    weight:
                      type: integer
                      format: int32
                      default: 1
                      minimum: 0
                      maximum: 1000000
                    ratio:
                      type: number
                      multipleOf: 0.5
YAML

my $CLUSTERPOLICY = path(__FILE__)->parent->parent
    ->child('share/gpu-operator/crds/clusterpolicy-crd.yaml')->slurp_utf8;

{
    # Answers like an API server that has none of these objects yet and
    # establishes every CRD it is given. Records what was POSTed.
    package RecordingIO;
    use JSON::PP ();
    sub new { bless { posted => [], have => {} }, shift }
    sub _resp {
        my ($status, $body) = @_;
        Kubernetes::REST::HTTPResponse->new(status => $status,
            content => ref $body ? JSON::PP->new->canonical->encode($body) : $body);
    }
    sub call {
        my ($self, $req) = @_;
        my ($path) = $req->url =~ m{^https?://[^/]+(/[^?]*)};
        if ($req->method eq 'POST') {
            push @{ $self->{posted} }, $req->content;
            my $obj = JSON::PP->new->decode($req->content);
            $obj->{metadata}{resourceVersion} = '1';
            $obj->{status} = { conditions => [ { type => 'Established', status => 'True' } ] };
            $self->{have}{"$path/$obj->{metadata}{name}"} = $obj;
            return _resp(201, $obj);
        }
        if ($req->method eq 'GET') {
            return _resp(200, { apiVersion => 'v1', kind => 'SecretList', items => [],
                                metadata => {} })
                if $path =~ m{/secrets$};
            my $obj = $self->{have}{$path};
            return $obj ? _resp(200, $obj)
                        : _resp(404, { kind => 'Status', code => 404, reason => 'NotFound' });
        }
        return _resp(405, { kind => 'Status', code => 405 });
    }
}

sub send_bundle {
    my ($bundle) = @_;
    my $io  = RecordingIO->new;
    my $api = Kubernetes::REST->new(
        server      => Kubernetes::REST::Server->new(endpoint => 'https://cp.example:6443'),
        credentials => { token => 't' },
        io          => $io,
        resource_map_from_cluster => 0,
    );

    no warnings 'redefine';
    local *Rex::Rancher::Cilium::_api   = sub { $api };
    local *Rex::Rancher::Cilium::_sleep = sub { };
    local *HTTP::Tiny::get = sub { { success => 1, status => 200, content => $bundle } };
    local *Rex::Logger::info = sub { };

    my $applied = eval {
        Rex::Rancher::Cilium::ensure_gateway_api_crds(
            kubeconfig => '/nonexistent', version => 'v1.2.0', channel => 'standard');
    };
    return ($applied, $@, $io->{posted});
}

# Every value under a numeric-bound key in a JSON text, with whether it went
# out as a number (not a quoted string). Read off the text, not a decode: a
# decoder would turn "1" and 1 into the same Perl scalar.
sub bounds_in {
    my ($json) = @_;
    my @b;
    while ($json =~ /"(minimum|maximum|multipleOf)":("?)([^",}\]]*)/g) {
        push @b, { key => $1, quoted => length $2, value => $3 };
    }
    return @b;
}

subtest 'a Gateway API CRD: bounds leave as JSON numbers' => sub {
    my ($applied, $err, $posted) = send_bundle($GATEWAY_CRD);
    is $err, '', 'ensure_gateway_api_crds went through' or return;
    ok $applied, 'and applied the bundle';
    is scalar @$posted, 1, 'one CRD POSTed' or return;

    my @b = bounds_in($posted->[0]);
    is scalar @b, 5, 'all five bounds are in the body';
    my @quoted = grep { $_->{quoted} } @b;
    is_deeply \@quoted, [], 'none of them as a JSON string'
        or diag explain \@quoted;
    like $posted->[0], qr/"maximum":65535\b/, 'port maximum 65535';
    like $posted->[0], qr/"multipleOf":0\.5\b/, 'a fractional bound stays fractional';
};

subtest "OCP's shipped ClusterPolicy CRD through the same path" => sub {
    my ($applied, $err, $posted) = send_bundle($CLUSTERPOLICY);
    is $err, '', 'ensure went through' or return;
    ok scalar @$posted, 'the CRD was POSTed' or return;

    my @b = map { bounds_in($_) } @$posted;
    ok scalar @b, 'it carries numeric bounds (' . scalar(@b) . ')';
    my @quoted = grep { $_->{quoted} } @b;
    is_deeply \@quoted, [], 'none of them as a JSON string'
        or diag explain [ @quoted[0 .. ($#quoted < 4 ? $#quoted : 4)] ];
};

done_testing;

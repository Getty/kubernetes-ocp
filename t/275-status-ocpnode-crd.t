#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS ();
use Path::Tiny qw(path);
use Scalar::Util qw(blessed);

use lib 'lib';

use Kubernetes::REST::LWPIO;
use OCP::Config;
use OCP::Drift;
use OCP::Kubernetes;

#
# k275: the api `ocp status` builds (OCP::Kubernetes) knew Kubernetes' own
# Kinds and the CRD providers, but not OCP's own: OCPNode and OCPNodeProvider
# were never put into its resource map, the way the apply api
# (OCP::Cmd::Apply::K8s::api) does with OCP::K8s->register. On a cluster that
# does not serve the OCPNode CRD -- an apply that never got that far --
# list('OCPNode') then died "unknown resource" before any request was made,
# and since k268 the host probes read that as a failed read: a
# worker_host_probes error entry, drift unknown. The honest answer is a 404:
# no OCPNode CRD, so no workers recorded.
#
# Through a real Kubernetes::REST built by OCP::Kubernetes, with only its HTTP
# transport replaced (as in t/10-kubernetes.t): the resource map, the path
# and the status check are all the shipped code.
#

my $JSON = JSON::MaybeXS->new(utf8 => 1, canonical => 1);

package Resp {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
    sub headers { {} }
}

package main;

my $OCPNODES = '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes';

# Aggregated discovery: the core group always, ocp.internal/v1 only where the
# cluster serves the CRD.
sub discovery {
    my (%a) = @_;
    my $res = sub {
        my ($plural, $kind, $scope) = @_;
        return { resource => $plural, responseKind => { kind => $kind }, scope => $scope };
    };
    return (
        '/api' => {
            kind  => 'APIGroupDiscoveryList',
            items => [ { metadata => { name => '' }, versions => [
                { version => 'v1', resources => [ $res->('nodes', 'Node', 'Cluster') ] },
            ] } ],
        },
        '/apis' => {
            kind  => 'APIGroupDiscoveryList',
            items => [ $a{serves_ocpnode} ? ({ metadata => { name => 'ocp.internal' }, versions => [
                { version => 'v1', resources => [
                    $res->('ocpnodes',         'OCPNode',         'Namespaced'),
                    $res->('ocpnodeproviders', 'OCPNodeProvider', 'Namespaced'),
                ] },
            ] }) : () ],
        },
    );
}

# Every path asked lands in @ASKED; a path with no answer is a 404 with the
# apiserver's Status body, the way a cluster without the CRD answers.
our @ASKED;
sub loopback_io {
    my (%answers) = @_;
    return sub {
        my ($self, $req) = @_;
        (my $path = $req->url) =~ s{^https?://[^/]+}{};
        $path =~ s{\?.*\z}{};
        push @ASKED, $path;
        my $answer = $answers{$path}
            // return Resp->new(status => 404, content =>
                '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}');
        return $answer if ref $answer eq 'Resp';
        return Resp->new(status => 200, content => $JSON->encode($answer));
    };
}

my $KUBECONFIG = <<'YAML';
apiVersion: v1
kind: Config
current-context: ocp
clusters:
- name: cl
  cluster:
    server: https://k8s.example:6443
    insecure-skip-tls-verify: true
contexts:
- name: ocp
  context:
    cluster: cl
    user: u
users:
- name: u
  user:
    token: kc-token
YAML

# The api `ocp status` hands OCP::Drift, built the way Status builds it.
sub status_api { OCP::Kubernetes->new(kubeconfig => $KUBECONFIG)->api }

# An ssh control plane at an address: the host probes name it.
my $CP = '10.230.30.155';
sub config {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(<<"YAML");
name: k275
kubernetes:
  distribution: k3s
control_planes:
  provider: ssh
  host: $CP
YAML
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# rex_probe_drift and probe_targets on the status api, warnings collected.
sub host_probes {
    my ($api) = @_;
    my @seen;
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, $_[0] };
    my $drift = OCP::Drift->new(config => config(), api => $api,
        rex_prober => sub { push @seen, $_[0]; return { stdout => '' } });
    my @entries = $drift->rex_probe_drift;
    my @targets = $drift->probe_targets;
    return (\@seen, \@entries, \@targets, \@warn);
}

#### the status api knows OCP's Kinds

subtest 'the status api resolves OCPNode and OCPNodeProvider to OCP::K8s' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(discovery());
    my $api = status_api();
    is $api->expand_class('OCPNode'), 'OCP::K8s::OCPNode', 'OCPNode';
    is $api->expand_class('OCPNodeProvider'), 'OCP::K8s::OCPNodeProvider', 'OCPNodeProvider';

    # ensure_crd and friends invalidate discovery, which drops a resource map
    # built from it; the registration rides on the `with` list, which the
    # client re-applies on every rebuild (D12), as the CRD providers do.
    $api->invalidate_discovery;
    is $api->expand_class('OCPNode'), 'OCP::K8s::OCPNode', 'OCPNode after a rebuild';
};

#### and knowing them costs a cluster that does not answer nothing

# The registration may not reach the cluster on its own: `ocp status` against
# an API that does not answer says so once, on STDERR, from list_nodes (k257).
# A registration that forced the discovery fetch while the api was built
# would ask first, wait for that to fail as well and add a "Falling back to
# the built-in resource map" warning in front of the real error.
subtest 'an API that does not answer: one request, no warning before the error' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = sub {
        push @ASKED, $_[1]->url;
        return Resp->new(status => 599, content => 'connection refused');
    };
    local @ASKED;
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, $_[0] };

    local $@;
    my $nodes = eval { OCP::Kubernetes->new(kubeconfig => $KUBECONFIG)->list_nodes };
    like "$@", qr/\b599\b.*connection refused/, 'list_nodes dies with the cause';
    is scalar @ASKED, 1, 'after one request' or diag explain \@ASKED;
    is_deeply \@warn, [], 'nothing warned on the way';
};

#### a cluster without the CRD answers with a 404

subtest 'no OCPNode CRD: the list is asked and answered 404' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(discovery());
    local @ASKED;
    my $api = status_api();

    local $@;
    my $list = eval { $api->list('OCPNode', namespace => 'ocp-system') };
    my $err  = $@;
    ok !defined $list, 'no list';
    unlike "$err", qr/unknown resource/, 'not "unknown resource": OCP knows the Kind';
    ok blessed($err) && $err->isa('Kubernetes::REST::APIError'), 'an API error'
        or diag "got: $err";
    ok blessed($err) && $err->can('is_not_found') && $err->is_not_found, '... a 404';
    ok((grep { $_ eq $OCPNODES } @ASKED), 'the request went to the OCPNode path')
        or diag explain \@ASKED;
};

subtest 'no OCPNode CRD: the host probes see no workers, not drift unknown' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(discovery());
    my ($seen, $entries, $targets, $warn) = host_probes(status_api());

    is_deeply $entries, [], 'no entry: no worker_host_probes error';
    is_deeply $seen, [ $CP ], 'the control plane alone is probed';
    is_deeply $targets, [ $CP ], 'probe_targets names the control plane';
    is_deeply $warn, [], 'nothing on stderr';
};

#### the controls: the same api reads a served CRD, and a refused list is still unknown

subtest 'OCPNode CRD served: a recorded worker is probed' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(discovery(serves_ocpnode => 1),
        $OCPNODES => {
            apiVersion => 'ocp.internal/v1',
            kind       => 'OCPNodeList',
            items      => [ {
                apiVersion => 'ocp.internal/v1',
                kind       => 'OCPNode',
                metadata   => { name => 'w1', namespace => 'ocp-system' },
                spec       => { role => 'worker', providerRef => 'ssh-default', host => 'w1.host' },
                status     => { publicIP => '10.0.0.5' },
            } ],
        },
    );
    my ($seen, $entries, $targets, $warn) = host_probes(status_api());

    is_deeply $entries, [], 'no entry';
    is_deeply $seen, [ $CP, '10.0.0.5' ], 'control plane and worker probed';
    is_deeply $targets, [ $CP, '10.0.0.5' ], 'probe_targets names both';
    is_deeply $warn, [], 'nothing on stderr';
};

subtest 'OCPNode list refused (403): still drift unknown' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(discovery(serves_ocpnode => 1),
        $OCPNODES => Resp->new(status => 403, content =>
            '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}'),
    );
    my ($seen, $entries, $targets, $warn) = host_probes(status_api());

    is scalar @$entries, 1, 'one entry';
    is $entries->[0]{kind}, 'error', 'an error entry';
    is $entries->[0]{component}, 'worker_host_probes', 'for the worker host probes';
    like $entries->[0]{message}, qr/\b403\b/, 'naming the status';
    is_deeply $seen, [ $CP ], 'the control plane is probed all the same';
};

done_testing;

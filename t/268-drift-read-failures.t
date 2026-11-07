#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use JSON::PP ();

use lib 'lib';

use OCP::Config;
use OCP::Drift;
use Kubernetes::REST::APIError;

#
# k268: a failed read is "drift unknown", never "not there".
#
# k256 drew that line for component_drift: only a 404 says the object is
# absent. The probes below it read every failure as absent all the same --
# gpu_crd_drift, registry_dns_drift and pod_cidr_drift came out clean on a
# cluster OCP could not read, and the OCPNode list behind the host probes fell
# back to an empty list, so an RBAC denial looked like a cluster without
# workers. Each now gives one error entry of the k119/k256 shape for anything
# but a 404, with its cause carped to stderr once.
#

# What Kubernetes::REST dies with for an HTTP error status.
sub api_error {
    my ($code, $reason, $context) = @_;
    return Kubernetes::REST::APIError->new(
        code    => $code,
        context => $context,
        body    => status_body($code, $reason),
    );
}

sub status_body {
    my ($code, $reason) = @_;
    return qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code});
}

package FakeResponse {
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }

# Objects by "<Kind>/<namespace>/<name>"; anything not there answers 404, the
# way the apiserver does. get_fail / list_fail / raw_fail make one read fail
# with the given error instead; raw answers a _request path with a response.
package FakeApi {
    sub new { my ($c, %a) = @_; bless { objects => {}, lists => {}, raw => {}, asked => [], %a }, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }

    sub get {
        my ($self, $kind, %a) = @_;
        my $key = join '/', $kind, $a{namespace} // '', $a{name} // '';
        push @{ $self->{asked} }, $key;
        die $self->{get_fail}{$key} if $self->{get_fail}{$key};
        return $self->{objects}{$key}
            // die "Kubernetes API error (get $kind): 404 " . main::status_body(404, 'NotFound') . "\n";
    }

    sub list {
        my ($self, $kind) = @_;
        die $self->{list_fail}{$kind} if $self->{list_fail}{$kind};
        my $items = $self->{lists}{$kind} // [];
        return $self->{hash_lists} ? { items => $items } : FakeList->new($items);
    }

    sub _request {
        my ($self, $method, $path) = @_;
        die $self->{raw_fail}{$path} if $self->{raw_fail}{$path};
        return $self->{raw}{$path} // FakeResponse->new(404, main::status_body(404, 'NotFound'));
    }
}

package main;

# An ssh control plane at an address: cluster_status hands it back as the
# public_ip registry_dns_drift expects, and the host probes name it.
my $CP = '10.230.30.155';

sub config {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(<<"YAML");
name: k268
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: $CP
YAML
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# Runs $code with warnings collected: (\@warnings, @its result).
sub warned {
    my ($code) = @_;
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, $_[0] };
    my @r = $code->();
    return (\@warn, @r);
}

# The k119/k256 error entry, and the one diagnosis on stderr.
sub is_unknown {
    my ($what, $entries, $warn, %want) = @_;
    is scalar @$entries, 1, "$what: one entry";
    my ($d) = @$entries;
    is $d->{kind},      'error',          "$what: an error entry, drift unknown";
    is $d->{component}, $want{component}, "$what: component $want{component}";
    is $d->{label},     $want{label},     "$what: label";
    is $d->{actual},    undef,            "$what: no actual value claimed";
    is $d->{remedy},    undef,            "$what: nothing to run";
    ok !$d->{self_healing},               "$what: not one a plain apply closes";
    like $d->{message}, qr/^\Q$want{label}\E: could not \Q$want{could}\E, drift unknown: /,
        "$what: the message names the read and says drift is unknown";
    like $d->{message}, qr/\b$want{code}\b.*\Q$want{reason}\E/, "$what: and carries the cause";
    is scalar @$warn, 1, "$what: one diagnosis on stderr";
    like $warn->[0], qr/^OCP::Drift::\Q$want{in}\E: \Q$want{failed}\E failed: .*\b$want{code}\b/,
        "$what: the diagnosis names the probe, the read and the status";
}

my @FAILURES = ([ 403, 'Forbidden' ], [ 500, 'InternalError' ]);

#
# gpu_crd_drift: the raw GET of the GPU Operator CRDs
#

my $CRD = 'clusterpolicies.nvidia.com';
my $CRD_PATH = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/$CRD";

subtest 'gpu_crd_drift: a 404 is a cluster without the CRD' => sub {
    my ($warn, @e) = warned(sub { OCP::Drift->new(config => config(), api => FakeApi->new)->gpu_crd_drift });
    is_deeply \@e, [], 'no entry';
    is_deeply $warn, [], 'nothing on stderr';
};

for my $f (@FAILURES) {
    my ($code, $reason) = @$f;
    subtest "gpu_crd_drift: $code is drift unknown" => sub {
        my $api = FakeApi->new(raw => { $CRD_PATH => FakeResponse->new($code, status_body($code, $reason)) });
        my ($warn, @e) = warned(sub { OCP::Drift->new(config => config(), api => $api)->gpu_crd_drift });
        is_unknown("CRD answering $code", \@e, $warn,
            component => 'gpu_operator_crd', label => "CRD $CRD",
            could => "read CustomResourceDefinition $CRD", in => 'gpu_crd_drift',
            failed => "get CustomResourceDefinition $CRD", code => $code, reason => $reason);
    };
}

subtest 'gpu_crd_drift: a transport failure and an undecodable body are drift unknown too' => sub {
    my $api = FakeApi->new(raw_fail => { $CRD_PATH => "Could not load resource map from cluster: connection refused\n" });
    my ($warn, @e) = warned(sub { OCP::Drift->new(config => config(), api => $api)->gpu_crd_drift });
    is scalar @e, 1, 'a _request that dies: one entry';
    is $e[0]{kind}, 'error', 'an error entry';
    like $e[0]{message}, qr/connection refused/, 'carrying the reason';
    is scalar @$warn, 1, 'said on stderr';

    $api = FakeApi->new(raw => { $CRD_PATH => FakeResponse->new(200, '<html>proxy</html>') });
    ($warn, @e) = warned(sub { OCP::Drift->new(config => config(), api => $api)->gpu_crd_drift });
    is scalar @e, 1, 'a 200 whose body is no JSON: one entry';
    is $e[0]{kind}, 'error', 'an error entry, not a missing CRD';
    like $e[0]{message}, qr/undecodable response body/, 'saying why';
};

#
# registry_dns_drift: the CoreDNS ConfigMap, under either distribution's name
#

my $K3S_CM  = 'ConfigMap/kube-system/coredns';
my $RKE2_CM = 'ConfigMap/kube-system/rke2-coredns-rke2-coredns';
my $COREFILE_OK = { data => { Corefile => ".:53 {\n    hosts {\n      $CP registry.local\n      fallthrough\n    }\n}\n" } };

subtest 'registry_dns_drift: a 404 is not the distribution\'s name' => sub {
    my $api = FakeApi->new(objects => { $RKE2_CM => $COREFILE_OK });
    my ($warn, @e) = warned(sub { OCP::Drift->new(config => config(), api => $api)->registry_dns_drift });
    is_deeply \@e, [], 'k3s name 404, RKE2 name holds the record: no drift';
    is_deeply $api->{asked}, [ $K3S_CM, $RKE2_CM ], 'both names were read, in order';
    is_deeply $warn, [], 'nothing on stderr';

    # k393: both names 404 is known, not unknown: no CoreDNS ConfigMap,
    # where ocp apply's step stops with an error (k319). The probe used to
    # say nothing; it says that now, as a spec entry, not an error entry.
    ($warn, @e) = warned(sub { OCP::Drift->new(config => config(), api => FakeApi->new)->registry_dns_drift });
    is scalar @e, 1, 'both names 404: one entry';
    is $e[0]{kind}, 'spec', 'a spec entry, not drift unknown';
    like $e[0]{message}, qr/found no CoreDNS ConfigMap in kube-system/, 'saying no CoreDNS ConfigMap was found';
    is_deeply $warn, [], 'nothing on stderr';
};

for my $f (@FAILURES) {
    my ($code, $reason) = @$f;
    subtest "registry_dns_drift: $code is drift unknown" => sub {
        my $api = FakeApi->new(objects => { $RKE2_CM => $COREFILE_OK },
            get_fail => { $K3S_CM => api_error($code, $reason, 'get ConfigMap') });
        my ($warn, @e) = warned(sub { OCP::Drift->new(config => config(), api => $api)->registry_dns_drift });
        is_unknown("coredns answering $code", \@e, $warn,
            component => 'registry_dns', label => 'registry.local DNS',
            could => 'read ConfigMap kube-system/coredns', in => 'registry_dns_drift',
            failed => 'get ConfigMap kube-system/coredns', code => $code, reason => $reason);
        is $e[0]{expected}, $CP, 'expected is the address the record should carry';
        is_deeply $api->{asked}, [ $K3S_CM ],
            'the probe ends there: the name it could not read may be the one that answers';

        $api = FakeApi->new(get_fail => { $RKE2_CM => api_error($code, $reason, 'get ConfigMap') });
        ($warn, @e) = warned(sub { OCP::Drift->new(config => config(), api => $api)->registry_dns_drift });
        is_unknown("k3s name 404, RKE2 name answering $code", \@e, $warn,
            component => 'registry_dns', label => 'registry.local DNS',
            could => 'read ConfigMap kube-system/rke2-coredns-rke2-coredns', in => 'registry_dns_drift',
            failed => 'get ConfigMap kube-system/rke2-coredns-rke2-coredns', code => $code, reason => $reason);
    };
}

#
# pod_cidr_drift: Cilium's cilium-config
#

my $CILIUM_CM = 'ConfigMap/kube-system/cilium-config';

subtest 'pod_cidr_drift: a 404 is nothing to compare' => sub {
    my ($warn, @e) = warned(sub { OCP::Drift->new(config => config(), api => FakeApi->new)->pod_cidr_drift });
    is_deeply \@e, [], 'no entry';
    is_deeply $warn, [], 'nothing on stderr';
};

for my $f (@FAILURES) {
    my ($code, $reason) = @$f;
    subtest "pod_cidr_drift: $code is drift unknown" => sub {
        my $api = FakeApi->new(get_fail => { $CILIUM_CM => api_error($code, $reason, 'get ConfigMap') });
        my ($warn, @e) = warned(sub { OCP::Drift->new(config => config(), api => $api)->pod_cidr_drift });
        is_unknown("cilium-config answering $code", \@e, $warn,
            component => 'pod_cidr', label => 'Pod CIDR',
            could => 'read ConfigMap kube-system/cilium-config', in => 'pod_cidr_drift',
            failed => 'get ConfigMap kube-system/cilium-config', code => $code, reason => $reason);
        is $e[0]{expected}, '10.42.0.0/16', 'expected is the configured pool';
        ok !$e[0]{manual_step}, 'no manual step: nothing is known to be wrong';
    };
}

#
# The OCPNode list behind the host probes' 'machines' selector
#

my @WORKERS = (
    { metadata => { name => 'w1' }, spec => { role => 'worker', providerRef => 'ssh-default', host => 'w1.host' },
      status => { publicIP => '10.0.0.5' } },
);

sub probed {
    my ($api) = @_;
    my @seen;
    my $drift = OCP::Drift->new(config => config(), api => $api,
        rex_prober => sub { push @seen, $_[0]; return { stdout => '' } });
    my ($warn, @e) = warned(sub { $drift->rex_probe_drift });
    return (\@seen, $warn, @e);
}

subtest 'host probes: a 404 on the OCPNode list is no workers' => sub {
    my ($seen, $warn, @e) = probed(FakeApi->new(lists => { OCPNode => \@WORKERS }));
    is_deeply $seen, [ $CP, '10.0.0.5' ], 'the list read: control plane and worker probed';

    ($seen, $warn, @e) = probed(FakeApi->new(lists => { OCPNode => \@WORKERS }, hash_lists => 1));
    is_deeply $seen, [ $CP, '10.0.0.5' ], 'a list as a plain hash reads the same';
    is_deeply $warn, [], 'and is no failure';

    ($seen, $warn, @e) = probed(FakeApi->new(
        list_fail => { OCPNode => api_error(404, 'NotFound', 'list OCPNode') }));
    is_deeply $seen, [ $CP ], 'a 404 (no OCPNode CRD): the control plane alone';
    is_deeply \@e, [], 'no entry';
    is_deeply $warn, [], 'nothing on stderr';
};

for my $f (@FAILURES) {
    my ($code, $reason) = @$f;
    subtest "host probes: $code on the OCPNode list is drift unknown, not no workers" => sub {
        my ($seen, $warn, @e) = probed(FakeApi->new(lists => { OCPNode => \@WORKERS },
            list_fail => { OCPNode => api_error($code, $reason, 'list OCPNode') }));
        is_deeply $seen, [ $CP ], 'the control plane is probed all the same';
        is_unknown("OCPNode list answering $code", \@e, $warn,
            component => 'worker_host_probes', label => 'Worker host probes',
            could => 'list OCPNode in ocp-system', in => 'rex_probe_drift',
            failed => 'list OCPNode in ocp-system', code => $code, reason => $reason);

        my $targets = OCP::Drift->new(config => config(),
            api => FakeApi->new(list_fail => { OCPNode => api_error($code, $reason, 'list OCPNode') }));
        my ($twarn, @hosts) = warned(sub { $targets->probe_targets });
        is_deeply \@hosts, [ $CP ], 'probe_targets names what it can';
        is scalar @$twarn, 1, 'and says on stderr why the workers are missing';
        like $twarn->[0], qr/^OCP::Drift::probe_targets: list OCPNode in ocp-system failed: .*\b$code\b/,
            'naming the list and the status';
    };
}

#
# detect carries every one of them
#

subtest 'detect surfaces the error entries' => sub {
    my $fail = api_error(403, 'Forbidden', 'get');
    my $api = FakeApi->new(
        get_fail  => { $K3S_CM => $fail, $CILIUM_CM => $fail },
        list_fail => { OCPNode => api_error(403, 'Forbidden', 'list OCPNode') },
        raw       => { $CRD_PATH => FakeResponse->new(403, status_body(403, 'Forbidden')) },
    );
    my $drift = OCP::Drift->new(config => config(), api => $api, rex_prober => sub { { stdout => '' } });
    my ($warn, $d) = warned(sub { $drift->detect });
    my %error = map { $_->{component} => 1 } grep { $_->{kind} eq 'error' } @$d;
    ok $error{$_}, "$_: an error entry in detect()"
        for qw(gpu_operator_crd registry_dns pod_cidr worker_host_probes);
};

done_testing;

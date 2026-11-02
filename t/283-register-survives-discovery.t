#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp ();
use JSON::MaybeXS ();
use Scalar::Util qw(blessed);

use lib 'lib';

use Kubernetes::REST::Kubeconfig;
use Kubernetes::REST::LWPIO;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::K8s;
use OCP::K8s;
use OCP::Kubernetes;

#
# k283: OCP::K8s->register wrote OCPNode and OCPNodeProvider into
# $api->resource_map. On the default client that map is built from the
# cluster's discovery, and invalidate_discovery -- what Kubernetes::REST's
# ensure_crd ends with, and what its documentation prescribes after a CRD is
# installed -- throws a built map away and builds the next one from discovery
# again, without what register wrote into the old one. Every api register had
# been called on lost the two Kinds at the first rebuild: on a cluster whose
# discovery does not list ocp.internal, list('OCPNode') died "unknown
# resource" before any request; on one that does, OCPNodes came back as
# IO::K8s::Unstructured instead of OCP::K8s::OCPNode.
#
# register now puts the two Kinds on the client's `with` list, which the
# client reads again every time it rebuilds its inner IO::K8s -- the way
# OCP::Kubernetes registers the CRD providers (k131/k132) and, under k275, did
# for these two Kinds by hand.
#
# Through the real Kubernetes::REST the apply path builds
# (OCP::Cmd::Apply::K8s::api), with only its HTTP transport replaced (as in
# t/275-status-ocpnode-crd.t): resource map, path and status check are all the
# shipped code.
#

my $JSON = JSON::MaybeXS->new(utf8 => 1, canonical => 1);

package Resp {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
    sub headers { {} }
}

package main;

my $NS        = '/apis/ocp.internal/v1/namespaces/ocp-system';
my $OCPNODES  = "$NS/ocpnodes";
my $PROVIDERS = "$NS/ocpnodeproviders";

# Aggregated discovery: the core group always, ocp.internal/v1 only where the
# cluster serves the CRDs.
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

# The api `ocp apply` works with, built the way apply builds it, on the apply
# command, which keeps the kubeconfig file alive. A command object, not a bare
# hash: the build is OCP::Role::Cmd's connect_cluster_api (k399).
my $APPLY = OCP::Cmd::Apply->new;
sub apply_api { OCP::Cmd::Apply::K8s::api($APPLY, $KUBECONFIG) }

# A plain client from the kubeconfig, before anything is registered on it.
sub bare_api {
    my $file = File::Temp->new(SUFFIX => '.yaml');
    print {$file} $KUBECONFIG;
    close $file;
    return Kubernetes::REST::Kubeconfig->new(kubeconfig_path => $file->filename)->api;
}

# How often register's map is on the `with` list.
sub ocp_entries {
    my ($api) = @_;
    return scalar grep { ref $_ eq 'HASH' && exists $_->{OCPNode} } @{ $api->with };
}

#### the rebuild: a cluster whose discovery does not list the CRD

subtest 'apply api, CRD not listed: OCPNode survives invalidate_discovery' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(discovery());
    my $api = apply_api();
    is $api->expand_class('OCPNode'), 'OCP::K8s::OCPNode', 'OCPNode before';

    $api->invalidate_discovery;
    is $api->expand_class('OCPNode'), 'OCP::K8s::OCPNode', 'OCPNode after the rebuild';
    is $api->expand_class('OCPNodeProvider'), 'OCP::K8s::OCPNodeProvider',
        'OCPNodeProvider after the rebuild';

    local @ASKED;
    local $@;
    my $list = eval { $api->list('OCPNode', namespace => 'ocp-system') };
    my $err  = $@;
    ok !defined $list, 'no list';
    unlike "$err", qr/unknown resource/, 'not "unknown resource"';
    ok blessed($err) && $err->isa('Kubernetes::REST::APIError') && $err->is_not_found,
        'the 404 the cluster answered' or diag "got: $err";
    ok((grep { $_ eq $OCPNODES } @ASKED), 'the request went to the OCPNode path')
        or diag explain \@ASKED;
};

#### the rebuild: a cluster that lists the CRD

subtest 'apply api, CRD listed: OCPNodes stay typed after invalidate_discovery' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(discovery(serves_ocpnode => 1),
        $OCPNODES => {
            apiVersion => 'ocp.internal/v1',
            kind       => 'OCPNodeList',
            items      => [ {
                apiVersion => 'ocp.internal/v1',
                kind       => 'OCPNode',
                metadata   => { name => 'w1', namespace => 'ocp-system' },
                spec       => { role => 'worker', providerRef => 'ssh-default' },
                status     => { phase => 'Ready' },
            } ],
        },
        "$PROVIDERS/ssh-default" => {
            apiVersion => 'ocp.internal/v1',
            kind       => 'OCPNodeProvider',
            metadata   => { name => 'ssh-default', namespace => 'ocp-system' },
            spec       => { type => 'ssh' },
        },
    );
    my $api = apply_api();
    $api->invalidate_discovery;

    my $list = $api->list('OCPNode', namespace => 'ocp-system');
    is ref $list->items->[0], 'OCP::K8s::OCPNode', 'the listed OCPNode is an OCP::K8s::OCPNode';
    is $api->k8s->object_to_struct($list->items->[0])->{status}{phase}, 'Ready',
        '... with its status';
    my $provider = $api->get('OCPNodeProvider', 'ssh-default', namespace => 'ocp-system');
    is ref $provider, 'OCP::K8s::OCPNodeProvider', 'the OCPNodeProvider is an OCP::K8s::OCPNodeProvider';
};

#### register itself

# What lets OCP::Kubernetes (ocp status) register through here: register only
# names the Kinds, it does not build the resource map, which would fetch
# discovery right away -- against an API that does not answer, a request and a
# "Falling back to the built-in resource map" warning ahead of anything the
# command asked for (k275).
subtest 'register asks the cluster nothing' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(discovery());
    my $api = bare_api();

    local @ASKED;
    OCP::K8s->register($api);
    is_deeply \@ASKED, [], 'no request' or diag explain \@ASKED;
    is $api->expand_class('OCPNode'), 'OCP::K8s::OCPNode', 'and OCPNode resolves when asked';
};

# A client whose inner IO::K8s was built before register (ocp ssh lists the
# Nodes first): that instance read `with` already, so it has to be built again.
subtest 'register on an api already in use' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(discovery());
    my $api = bare_api();
    $api->k8s;   # the inner IO::K8s exists

    OCP::K8s->register($api);
    is $api->expand_class('OCPNode'), 'OCP::K8s::OCPNode', 'OCPNode';
    is $api->expand_class('OCPNodeProvider'), 'OCP::K8s::OCPNodeProvider', 'OCPNodeProvider';
};

# robocop's controller and ocp ssh register on top of the api OCP::Kubernetes
# built, which has registered already.
subtest 'registering twice is harmless' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(discovery());
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, $_[0] };

    my $api = OCP::Kubernetes->new(kubeconfig => $KUBECONFIG)->api;
    is ocp_entries($api), 1, 'OCP::Kubernetes registered once';
    OCP::K8s->register($api);
    OCP::K8s->register($api);
    is ocp_entries($api), 1, 'two more registers add nothing';

    $api->invalidate_discovery;
    is $api->expand_class('OCPNode'), 'OCP::K8s::OCPNode', 'OCPNode after a rebuild';
    local $@;
    eval { $api->list('OCPNode', namespace => 'ocp-system') };
    ok blessed($@) && $@->isa('Kubernetes::REST::APIError') && $@->is_not_found,
        'list(OCPNode) is answered, with a 404' or diag "got: $@";
    is_deeply \@warn, [], 'nothing warned';
};

done_testing;

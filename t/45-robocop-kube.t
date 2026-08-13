#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::MaybeXS ();
use Path::Tiny qw(path);

use lib 'lib';

use Kubernetes::REST;
use Kubernetes::REST::Kubeconfig;
use Kubernetes::REST::LWPIO;
use OCP::K8s;
use OCP::Kubernetes;
use OCP::Robocop::Controller;

#
# How robocop gets a Kubernetes client, and what it does with it.
#
# OCP::Robocop::Controller::_build_kube called Kubernetes::REST->new(%opts)
# with either a `kubeconfig` argument or nothing at all, the second case
# annotated "Kubernetes::REST uses in-cluster config automatically". Neither
# is true of Kubernetes::REST 1.106: there is no `kubeconfig` attribute and no
# in-cluster automatism, `server` and `credentials` are required, so BOTH
# branches died with "Missing required arguments: credentials, server" before
# a request was ever built. `kube` is the first thing run() touches -- the
# list_ocp_nodes at the top of the loop -- so the controller could not survive
# its own first iteration, and nothing behind that call ever ran.
#
# Nothing caught it because nothing exercised _build_kube: t/00-load.t loads
# the module, and every other controller test would have had to reach a
# cluster. So the two modes are pinned here, both of them through the real
# client:
#
#   * out-of-cluster (kubeconfig, as a path or as content) is driven end to
#     end -- the only thing faked is the HTTP transport, so the request that
#     leaves the client proves which cluster and which credentials were used;
#   * in-cluster is routed into the client's own service-account fallback
#     (Kubernetes::REST::Kubeconfig::_in_cluster_api). Its leaf is stubbed
#     because the paths it reads are file-scoped lexicals in the dependency
#     ('/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt}'), not
#     something a test can point elsewhere. Everything up to that leaf is the
#     shipped code, and the unstubbed croak is asserted too.
#
# A test that only checked "an object comes back" would not have caught the
# original bug either -- no object came back, it died. What matters is which
# server and which token, so that is what gets asserted.
#

our $JSON = JSON::MaybeXS->new(utf8 => 1, canonical => 1, convert_blessed => 1);

# A cluster's OpenAPI answer, minimal but real: Kubernetes::REST fetches
# /openapi/v2 while building its resource map (resource_map_from_cluster
# defaults to 1), and this keeps that fetch from falling back with a warning.
my $OPENAPI = $JSON->encode({
    paths => {
        '/api/v1/nodes/{name}' => {
            get => { 'x-kubernetes-group-version-kind' =>
                     { group => '', version => 'v1', kind => 'Node' } },
        },
    },
});

package Resp {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
    sub headers { {} }
}

package main;

# Replaces the real HTTP transport for every Kubernetes::REST built anywhere in
# the process, including the ones Kubernetes::REST::Kubeconfig builds for
# itself -- which is the point: _build_kube does not construct the client, so
# there is no `io` argument to inject.
my @requests;

sub loopback_io {
    my (%answers) = @_;
    @requests = ();
    return sub {
        my ($self, $req) = @_;
        my $path = $req->url;
        $path =~ s{^https?://[^/]+}{};
        push @requests, {
            method => $req->method,
            url    => $req->url,
            path   => $path,
            auth   => $req->headers->{Authorization},
        };
        return Resp->new(status => 200, content => $OPENAPI) if $path eq '/openapi/v2';
        my $body = $answers{$path} // {};
        return Resp->new(status => 200, content => $JSON->encode($body));
    };
}

sub kubeconfig_yaml {
    my (%a) = @_;
    my $endpoint = $a{endpoint} // 'https://k8s.example:6443';
    my $token    = $a{token}    // 'kc-token';
    return <<"YAML";
apiVersion: v1
kind: Config
current-context: ocp
clusters:
- name: cl
  cluster:
    server: $endpoint
    insecure-skip-tls-verify: true
contexts:
- name: ocp
  context:
    cluster: cl
    user: u
users:
- name: u
  user:
    token: $token
YAML
}

my $tmp = Path::Tiny->tempdir;

sub controller {
    my (%a) = @_;
    return OCP::Robocop::Controller->new(
        ssh_key    => 'ROBO-KEY',
        server_url => 'https://cp:9345',
        join_token => 'JOIN',
        %a,
    );
}

#
# 1. The claim the old code rested on, stated against the shipped client.
#

subtest 'Kubernetes::REST cannot be built the way _build_kube built it' => sub {
    ok !Kubernetes::REST->can('kubeconfig'),
        'there is no kubeconfig attribute to pass';

    my $bare = do { local $@; eval { Kubernetes::REST->new }; $@ };
    like $bare, qr/Missing required arguments/,
        'a bare new() dies: there is no in-cluster automatism';
    like $bare, qr/server/, '... server is required';
    like $bare, qr/credentials/, '... and so are credentials';

    my $with_kc = do {
        local $@;
        eval { Kubernetes::REST->new(kubeconfig => kubeconfig_yaml()) };
        $@;
    };
    like $with_kc, qr/Missing required arguments/,
        'and handing it a kubeconfig supplies neither of them';
};

#
# 2. The decision itself, with no I/O attached to it.
#

subtest 'the controller decides where its credentials come from' => sub {
    my $file = $tmp->child('decide.yaml');
    $file->spew_utf8(kubeconfig_yaml());

    is_deeply [ controller()->_kube_source ], [ in_cluster => 1 ],
        'no kubeconfig means the pod service account';
    is_deeply [ controller(kubeconfig => '')->_kube_source ], [ in_cluster => 1 ],
        'an empty kubeconfig is not a kubeconfig';

    is_deeply [ controller(kubeconfig => "$file")->_kube_source ],
        [ kubeconfig_path => "$file" ],
        'an existing file is passed on as a path';

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };
    my $content = kubeconfig_yaml();
    is_deeply [ controller(kubeconfig => $content)->_kube_source ],
        [ kubeconfig => $content ],
        'a whole kubeconfig document is passed on as content';
    is_deeply \@warnings, [],
        'and is never fed to -f, which warns on a filename containing newline';
};

#
# 3. Out-of-cluster, end to end through the real client.
#

subtest 'a kubeconfig path builds a client aimed at that cluster' => sub {
    my $file = $tmp->child('path-mode.yaml');
    $file->spew_utf8(kubeconfig_yaml(endpoint => 'https://path.example:6443',
                                     token    => 'path-token'));

    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(
        '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes' => {
            apiVersion => 'ocp.internal/v1', kind => 'OCPNodeList', items => [],
        },
    );

    my $c   = controller(kubeconfig => "$file");
    my $api = $c->kube;

    isa_ok $api, 'Kubernetes::REST', 'the built client';
    is $api->server->endpoint, 'https://path.example:6443',
        'the endpoint comes from the kubeconfig';
    is $api->credentials->token, 'path-token', 'and so do the credentials';
    is $api->k8s->expand_class('OCPNode'), 'OCP::K8s::OCPNode',
        'OCP::K8s->register ran: OCPNode is addressable';
    is $api->k8s->expand_class('OCPNodeProvider'), 'OCP::K8s::OCPNodeProvider',
        'and so is OCPNodeProvider';

    $c->list_ocp_nodes;

    my ($ls) = grep { $_->{path} =~ m{/ocpnodes$} } @requests;
    ok $ls, 'the first thing run() does reaches the cluster';
    is $ls->{url},
        'https://path.example:6443/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes',
        'listing OCPNodes addresses the namespaced CRD path on that server';
    is $ls->{auth}, 'Bearer path-token',
        'authenticated with the token from the kubeconfig';
};

subtest 'a kubeconfig passed as content builds the same client' => sub {
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };

    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(
        '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes' => {
            apiVersion => 'ocp.internal/v1', kind => 'OCPNodeList', items => [],
        },
    );

    my $c = controller(kubeconfig => kubeconfig_yaml(
        endpoint => 'https://content.example:6443', token => 'content-token'));

    $c->list_ocp_nodes;

    my ($ls) = grep { $_->{path} =~ m{/ocpnodes$} } @requests;
    is $ls->{url},
        'https://content.example:6443/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes',
        'the content is written out and parsed, not passed as a filename';
    is $ls->{auth}, 'Bearer content-token', 'credentials survive the round trip';
    is_deeply \@warnings, [], 'and nothing warns on the way';
};

#
# 4. In-cluster.
#

subtest 'in-cluster mode asks the client for its service-account fallback' => sub {
    my $decoy = $tmp->child('decoy.yaml');
    $decoy->spew_utf8(kubeconfig_yaml(endpoint => 'https://decoy.example:6443',
                                      token    => 'decoy-token'));
    my $home = Path::Tiny->tempdir;
    $home->child('.kube')->mkpath;
    $home->child('.kube', 'config')->spew_utf8("$decoy");

    my $sa = Kubernetes::REST->new(
        server                    => { endpoint => 'https://kubernetes.default.svc:443' },
        credentials               => { token => 'service-account-token' },
        resource_map_from_cluster => 0,
    );

    my @asked;
    no warnings 'redefine';
    local *Kubernetes::REST::Kubeconfig::_in_cluster_api = sub {
        push @asked, $_[0]->kubeconfig_path;
        return $sa;
    };

    # Both of the paths the client would otherwise fall back to are laid with a
    # readable kubeconfig. If the controller ever stopped naming a path of its
    # own, one of these would win and robocop would authenticate as whoever
    # that file says -- silently, because it is a perfectly valid client.
    local $ENV{KUBECONFIG} = "$decoy";
    local $ENV{HOME}       = "$home";

    my $api = controller()->kube;

    is scalar @asked, 1, "the client's own in-cluster fallback was reached";
    ok !-e $asked[0],
        '... because it was handed a kubeconfig path that cannot exist';
    is $api->server->endpoint, 'https://kubernetes.default.svc:443',
        'the service-account client is what comes back';
    is $api->credentials->token, 'service-account-token',
        'with the service-account token, not the one lying in $KUBECONFIG';
    is $api->k8s->expand_class('OCPNode'), 'OCP::K8s::OCPNode',
        'and the CRDs are registered on it too';
};

subtest 'in-cluster mode outside a pod fails with the reason' => sub {
    plan skip_all => 'running inside a pod: the service account token exists'
        if -f '/var/run/secrets/kubernetes.io/serviceaccount/token';

    # Unstubbed. This is the half of the fallback the subtest above replaces:
    # it proves the routing into _in_cluster_api is the shipped client's, and
    # that the failure mode is a legible croak rather than a client pointed at
    # nothing.
    my $err = do { local $@; eval { controller()->kube }; $@ };
    like $err, qr/not running in-cluster/,
        'the client says so itself instead of being built half-configured';
};

#
# 5. What the controller does with the client once it has one.
#

package MockTransport {
    sub new { my ($c, %a) = @_; bless { seen => [], %a }, $c }

    sub call {
        my ($self, $req) = @_;
        my $path = $req->url;
        $path =~ s{^https?://[^/]+}{};
        push @{ $self->{seen} }, { method => $req->method, path => $path };
        my $body = $self->{answers}{$path};
        return main::Resp->new(status => 404, content => '{"message":"not found"}')
            unless $body;
        return main::Resp->new(status => 200, content => $main::JSON->encode($body));
    }
}

package main;

sub strict_k8s {
    my (%answers) = @_;
    my $t   = MockTransport->new(answers => \%answers);
    my $api = Kubernetes::REST->new(
        server                    => { endpoint => 'https://cluster.invalid:6443' },
        credentials               => { token => 'fake' },
        io                        => $t,
        resource_map_from_cluster => 0,
    );
    OCP::K8s->register($api);
    return ($api, $t);
}

sub ocpnode_cr {
    my (%over) = @_;
    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => 'w1', namespace => 'ocp-system',
                        resourceVersion => '11' },
        spec       => { role => 'worker', providerRef => 'p1' },
        status     => { phase => 'Ready', kubernetesNodeName => 'w1' },
        %over,
    };
}

subtest 'list_ocp_nodes returns plain structs from the namespaced list' => sub {
    my ($api, $t) = strict_k8s(
        '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes' => {
            apiVersion => 'ocp.internal/v1', kind => 'OCPNodeList',
            items      => [ ocpnode_cr() ],
        },
    );

    my $nodes = controller(kube => $api)->list_ocp_nodes;

    is $t->{seen}[0]{method}, 'GET', 'listed with a GET';
    is $t->{seen}[0]{path},
        '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes',
        'from the controller namespace';

    is scalar @$nodes, 1, 'one CR came back';
    is ref $nodes->[0], 'HASH',
        'as a plain hash: OCP::Node reads cr as a struct, never as a typed object';
    is $nodes->[0]{spec}{providerRef}, 'p1', 'spec survives the conversion';
    is $nodes->[0]{status}{phase}, 'Ready', 'and so does status';
    is $nodes->[0]{metadata}{resourceVersion}, '11',
        'resourceVersion too -- the lease PUT needs it to collide instead of clobber';
};

subtest '_on_node_event loads the provider CR and drives OCP::Node' => sub {
    my ($api, $t) = strict_k8s(
        '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodeproviders/p1' => {
            apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
            metadata   => { name => 'p1', namespace => 'ocp-system' },
            spec       => { type => 'local' },
        },
        '/api/v1/nodes/w1' => {
            apiVersion => 'v1', kind => 'Node',
            metadata   => { name => 'w1' },
            status     => { conditions => [ { type => 'Ready', status => 'True' } ] },
        },
    );

    my $out = '';
    {
        open my $fh, '>', \$out or die $!;
        local *STDOUT = $fh;
        controller(kube => $api)->_on_node_event(ocpnode_cr());
    }

    my @paths = map { "$_->{method} $_->{path}" } @{ $t->{seen} };
    ok scalar(grep {
        $_ eq 'GET /apis/ocp.internal/v1/namespaces/ocp-system/ocpnodeproviders/p1'
    } @paths), 'the provider named in spec.providerRef is read by Kind and name';
    ok scalar(grep { $_ eq 'GET /api/v1/nodes/w1' } @paths),
        'and the CR reached OCP::Node, which verified the Kubernetes Node';
    is $out, '', 'nothing was logged: no step failed';
};

subtest '_on_node_event without a providerRef touches nothing' => sub {
    my ($api, $t) = strict_k8s();

    my $out = '';
    {
        open my $fh, '>', \$out or die $!;
        local *STDOUT = $fh;
        controller(kube => $api)->_on_node_event(
            ocpnode_cr(spec => { role => 'worker' }));
    }

    like $out, qr/No providerRef/, 'it says which CR it skipped';
    is scalar @{ $t->{seen} }, 0, 'and issues no request at all';
};

done_testing;

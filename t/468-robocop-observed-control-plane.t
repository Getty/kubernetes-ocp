use strict;
use warnings;
use Test::More;
use JSON::MaybeXS ();

use lib 'lib';

#
# k468: since k417, `ocp apply` writes police1's OCPNode Joining while its Node
# is not Ready (OCP::Cmd::Apply::CR::ensure_cp_ocpnode). robocop's resync
# enqueues every Joining OCPNode, and _on_node_event loaded the OCPNodeProvider
# its spec.providerRef names before anything else -- a provider that could not
# be loaded marked the OCPNode Failed, which is terminal. A local control plane
# points at local-default, and ensure_providers never writes that one.
#
# An OCPNode in Joining or Ready only waits for, or checks, its Node: OCP::Node
# never asks the provider in those phases. So robocop mirrors the Node of a
# control plane in those phases without loading the provider, and never marks
# it Failed for one it cannot load. A REAL Kubernetes::REST over a recording
# transport, as in t/33-robocop-controller.t; no cluster.
#

package MockResponse {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
    sub headers { {} }
}

package MockTransport {
    my $JSON = JSON::MaybeXS->new(utf8 => 1, canonical => 1, convert_blessed => 1);

    sub new { my ($c, %a) = @_; bless {%a}, $c }

    sub call {
        my ($self, $req) = @_;
        my $api = $self->{api};

        my $path = $req->url;
        $path =~ s{^https?://[^/]+}{};
        $path =~ s{\?.*}{};

        push @{ $api->requests }, {
            method => $req->method,
            path   => $path,
            body   => $req->content,
        };

        my ($status, $struct) = $self->_respond($api, $req->method, $path);
        return MockResponse->new(status => $status, content => $JSON->encode($struct));
    }

    sub _respond {
        my ($self, $api, $method, $path) = @_;

        if ($method eq 'PATCH' && $path =~ m{/status$}) {
            my ($req) = grep { $_->{path} eq $path } reverse @{ $api->requests };
            my $cr = $api->cr;
            my $sent = JSON::MaybeXS::decode_json($req->{body});
            $cr->{status}{$_} = $sent->{status}{$_} for keys %{ $sent->{status} // {} };
            return (200, $cr);
        }
        if ($path =~ m{/ocpnodes/([^/]+)$}) {
            my $cr = $api->cr;
            return $cr ? (200, $cr) : (404, { message => "ocpnodes \"$1\" not found" });
        }
        if ($path =~ m{/ocpnodeproviders/([^/]+)$}) {
            return (404, { kind => 'Status', apiVersion => 'v1', status => 'Failure',
                code => 404, reason => 'NotFound',
                message => "ocpnodeproviders.ocp.internal \"$1\" not found" });
        }
        if ($path =~ m{/api/v1/nodes/([^/]+)$}) {
            my $node = $api->node;
            return $node ? (200, $node) : (404, { kind => 'Status', apiVersion => 'v1',
                status => 'Failure', code => 404, reason => 'NotFound',
                message => "nodes \"$1\" not found" });
        }
        return (404, { message => "unexpected path $path" });
    }
}

package StrictK8s {
    use Moo;
    use OCP::K8s;
    extends 'Kubernetes::REST';
    use namespace::clean;

    has requests => (is => 'ro', default => sub { [] });
    has cr       => (is => 'rw');
    has node     => (is => 'rw');

    sub build {
        my (%args) = @_;
        my $transport = MockTransport->new;
        my $self = StrictK8s->new(
            server                    => { endpoint => 'https://cluster.invalid:6443' },
            credentials               => { token => 'fake-token' },
            resource_map_from_cluster => 0,
            io                        => $transport,
            %args,
        );
        $transport->{api} = $self;
        OCP::K8s->register($self);
        return $self;
    }

    sub reqs {
        my ($self, $method) = @_;
        return grep { !$method || $_->{method} eq $method } @{ $self->requests };
    }

    sub status_patches {
        my ($self) = @_;
        return map { JSON::MaybeXS::decode_json($_->{body})->{status} }
               grep { $_->{path} =~ m{/status$} } $self->reqs('PATCH');
    }

    sub provider_gets {
        my ($self) = @_;
        return grep { $_->{path} =~ m{/ocpnodeproviders/} } $self->reqs('GET');
    }
}

package main;

use Future;
use OCP::Robocop::Controller;

# The reconcile child's body in-process, as in t/33: watch or resync ->
# enqueue -> re-read -> _reconcile_cr, minus the fork.
{
    no warnings 'redefine';
    *OCP::Robocop::Controller::_spawn = sub {
        my ($self, $cr) = @_;
        $self->_reconcile_child($cr);
        return Future->done(0);
    };
}

# police1 as ensure_cp_ocpnode writes it for a local control plane whose Node
# is not Ready.
sub police1 {
    my (%over) = @_;
    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => 'police1', namespace => 'ocp-system',
                        resourceVersion => '7' },
        spec       => { role => 'control-plane', providerRef => 'local-default' },
        status     => {
            phase              => 'Joining',
            message            => 'Node police1 not Ready: its Ready condition is False',
            kubernetesNodeName => 'police1',
            reconciler         => 'cli',
        },
        %over,
    };
}

sub k8s_node {
    my ($ready) = @_;
    return {
        apiVersion => 'v1',
        kind       => 'Node',
        metadata   => { name => 'police1', resourceVersion => '3' },
        status     => {
            conditions => [ { type => 'Ready', status => $ready ? 'True' : 'False' } ],
            addresses  => [ { type => 'InternalIP', address => '10.0.0.1' } ],
        },
    };
}

sub controller {
    my ($k) = @_;
    return OCP::Robocop::Controller->new(
        kube => $k, ssh_key => 'K', server_url => 'U', join_token => 'T',
        distribution => 'rke2', pod_cidr => '10.42.0.0/16',
        reconciler_id => 'robocop@pod-1');
}

subtest 'the resync leaves a Joining local police1 with a NotReady Node Joining' => sub {
    my $k = StrictK8s::build(cr => police1(), node => k8s_node(0));
    my $ctrl = controller($k);

    no warnings 'redefine';
    local *OCP::Robocop::Controller::list_ocp_nodes = sub { [ police1() ] };
    $ctrl->_resync;

    my @failed = grep { ($_->{phase} // '') eq 'Failed' } $k->status_patches;
    is scalar(@failed), 0, 'not marked Failed'
        or diag explain \@failed;
    is $k->cr->{status}{phase}, 'Joining', 'the phase stays Joining';
    is scalar($k->provider_gets), 0,
        'the OCPNodeProvider is not looked up: Joining never needs it';
    ok scalar(grep { $_->{path} eq '/api/v1/nodes/police1' } $k->reqs('GET')),
        'the Node was read';
};

subtest 'a Joining local police1 whose Node turned Ready is written Ready' => sub {
    my $k = StrictK8s::build(cr => police1(), node => k8s_node(1));
    my $ctrl = controller($k);

    $ctrl->_handle_watch_object($k->get('OCPNode', name => 'police1', namespace => 'ocp-system'));

    my @phases = map { $_->{phase} // () } $k->status_patches;
    is_deeply \@phases, ['Ready'], 'one status write, phase Ready';
    is $k->cr->{status}{phase}, 'Ready', 'stored Ready';
    is scalar($k->provider_gets), 0, 'no OCPNodeProvider lookup';
};

subtest 'a watch event on a Ready local police1 does not fail it either' => sub {
    my $k = StrictK8s::build(
        cr   => police1(status => { phase => 'Ready', kubernetesNodeName => 'police1',
                                    reconciler => 'cli' }),
        node => k8s_node(1),
    );
    my $ctrl = controller($k);

    $ctrl->_handle_watch_object($k->get('OCPNode', name => 'police1', namespace => 'ocp-system'));

    my @failed = grep { ($_->{phase} // '') eq 'Failed' } $k->status_patches;
    is scalar(@failed), 0, 'not marked Failed';
    is $k->cr->{status}{phase}, 'Ready', 'stays Ready';
    is scalar($k->provider_gets), 0, 'no OCPNodeProvider lookup';
};

subtest 'a Pending control plane still needs its provider' => sub {
    # police2+ are written Pending and installed by robocop: their provider is
    # needed, and one that cannot be loaded is a Failed node, as before.
    my $k = StrictK8s::build(cr => police1(
        metadata => { name => 'police2', namespace => 'ocp-system', resourceVersion => '1' },
        status   => { phase => 'Pending' },
    ));
    my $ctrl = controller($k);

    $ctrl->_handle_watch_object($k->get('OCPNode', name => 'police2', namespace => 'ocp-system'));

    ok scalar($k->provider_gets), 'the provider was looked up';
    my ($sent) = $k->status_patches;
    is $sent->{phase}, 'Failed', 'phase Failed';
    like $sent->{message}, qr{^Failed to load OCPNodeProvider/local-default: },
        'naming the provider';
};

done_testing;

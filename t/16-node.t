use strict;
use warnings;
use Test::More;
use JSON::MaybeXS ();

use lib 'lib';

#
# The double used here is a REAL Kubernetes::REST with a recording transport
# bolted underneath, not a hand-written stand-in.
#
# Its predecessor was a stand-in, and it accepted everything:
#
#     sub get { push @{$s->{calls}}, [get => \@a]; $s->{cr} }
#
# Every signature was legal, every call returned the same canned CR. That is
# how OCP::Node shipped calls like
#
#     $k8s->get('ocp.internal/v1', 'OCPNode', $name, namespace => $ns)
#     $k8s->update($plain_hashref)
#     $k8s->delete('v1', 'Node', $name)
#
# and stayed green the whole time. Kubernetes::REST has no api-version-first
# form: argument 0 is the Kind and goes to expand_class(), so those calls do
# not mis-address a request, they die -- "argument is not a module name".
# update() calls ->metadata on its argument and dies on an unblessed hash.
# _acquire_lease is the first thing _provision does, so worker provisioning
# could never have worked against a real cluster.
#
# The lesson is not "assert harder on the recorded calls" -- the old file did
# have a regression subtest for exactly this seam, and it passed, because it
# checked that argument 0 was a non-ref string and 'ocp.internal/v1' is one.
# A double that answers questions the real client would refuse to answer
# cannot be made strict by inspecting what it recorded. So the double is gone:
# argument parsing, expand_class, path building and status-subresource
# addressing are now done by the shipped Kubernetes::REST, and the only thing
# that is faked is the HTTP call itself. A wrong signature dies here for the
# same reason it dies in production, in the same code.
#
# What the transport serves is set per test via `cr` (the OCPNode) and `node`
# (the core/v1 Node). Both are serialised to JSON on the way out, so the CR
# the node reads back is a copy -- the old double handed back the very
# hashref the test held, which hid aliasing between reads and writes.
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

        push @{ $api->requests }, {
            method => $req->method,
            path   => $path,
            body   => $req->content,
        };

        my ($status, $struct) = $self->_respond($api, $req->method, $path, $req->content);
        return MockResponse->new(
            status  => $status,
            content => $JSON->encode($struct),
        );
    }

    sub _respond {
        my ($self, $api, $method, $path, $body) = @_;

        # Writes echo the object back, the way the API server does.
        return (200, $JSON->decode($body)) if $method eq 'PUT' || $method eq 'PATCH';
        return (200, {}) if $method eq 'DELETE';

        if ($api->read_fails && $api->reads_ok_first <= 0) {
            return ($api->read_fails, { message => 'injected read failure' });
        }
        $api->reads_ok_first($api->reads_ok_first - 1) if $api->read_fails;

        if ($path =~ m{/ocpnodes/([^/]+)$}) {
            my $cr = $api->cr;
            return $cr ? (200, $cr) : (404, { message => "ocpnodes \"$1\" not found" });
        }
        if ($path =~ m{^/api/v1/nodes/([^/]+)$}) {
            my $node = $api->node;
            return $node ? (200, $node) : (404, { message => "nodes \"$1\" not found" });
        }
        return (404, { message => "unexpected path $path" });
    }
}

package StrictK8s {
    use Moo;
    use OCP::K8s;
    extends 'Kubernetes::REST';

    has requests   => (is => 'ro', default => sub { [] });
    has cr         => (is => 'rw');
    has node       => (is => 'rw');
    has read_fails     => (is => 'rw', default => 0);  # HTTP status to inject on reads
    has reads_ok_first => (is => 'rw', default => 0);  # let this many reads through first

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
        $transport->{api} = $self;   # what the transport serves is set per test
        OCP::K8s->register($self);
        return $self;
    }

    # Every assertion below is made against the requests that actually left
    # the client -- verb and path -- which is the level the bug lived at.
    sub reqs {
        my ($self, $method) = @_;
        return grep { !$method || $_->{method} eq $method } @{ $self->requests };
    }
}

package FakeProvider {
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub create_server { my ($s, %a) = @_; $s->{create_cb} ? $s->{create_cb}->(%a) : { id => 'SRV1', ip => '1.2.3.4' } }
    sub delete_server { my ($s, @a) = @_; $s->{delete_cb} ? $s->{delete_cb}->(@a) : 1 }
}

package FakeSSH {
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub wait_for_ssh { my ($s, $n) = @_; $s->{ssh_cb} ? $s->{ssh_cb}->($n) : 1 }
}

package FakeRex {
    our @_instances;
    sub new { my ($c, %a) = @_; my $s = bless { %a, calls => [] }, $c; push @_instances, $s; $s }
    sub run_task { my ($s, $task, %p) = @_;
        push @{$s->{calls}}, [$task, \%p];
        $s->{run_cb} ? $s->{run_cb}->($task, %p) : 1;
    }
}

package main;

use OCP::Node;

sub ocpnode {
    my (%over) = @_;
    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => 'worker-1', namespace => 'ocp-system',
                        resourceVersion => '100' },
        spec       => { role => 'worker', providerRef => 'hetzner-a' },
        status     => { phase => 'Pending' },
        %over,
    };
}

sub ready_node {
    my ($name, $ready) = @_;
    return {
        apiVersion => 'v1', kind => 'Node',
        metadata => { name => $name },
        status   => { conditions => [{ type => 'Ready', status => $ready }] },
    };
}

my $cr = ocpnode();

subtest 'from_cr constructs with deps' => sub {
    my $node = OCP::Node->from_cr(
        $cr,
        k8s        => StrictK8s::build(),
        provider   => FakeProvider->new,
        ssh_key    => 'KEY',
        server_url => 'https://cp:9345',
        join_token => 'TOKEN',
    );

    is $node->name,  'worker-1', 'name accessor from metadata';
    is $node->role,  'worker',   'role accessor from spec';
    is $node->phase, 'Pending',  'phase accessor from status';
    is $node->reconciler_id, 'cli', 'reconciler_id defaults to cli';
    is $node->distribution,  'rke2', 'distribution defaults to rke2';
};

subtest 'reconciler_id override' => sub {
    my $node = OCP::Node->from_cr($cr, k8s => StrictK8s::build(), reconciler_id => 'robocop');
    is $node->reconciler_id, 'robocop', 'reconciler_id can be overridden';
};

subtest 'phase defaults to Pending when status missing' => sub {
    my $cr2 = { %$cr, status => {} };
    my $node = OCP::Node->from_cr($cr2, k8s => StrictK8s::build());
    is $node->phase, 'Pending', 'missing status.phase defaults to Pending';
};

#
# The seam itself. These are the assertions the old double could not make:
# they are about the HTTP request that actually leaves the client.
#

subtest 'lease acquisition addresses the CR by Kind and PUTs it back' => sub {
    my $k = StrictK8s::build(cr => ocpnode(metadata => {
        name => 'w1', namespace => 'ocp-system', resourceVersion => '100' }));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    $node->_acquire_lease;

    my ($get) = $k->reqs('GET');
    ok $get, 'the CR is read before the lease is written';
    is $get->{path}, '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/w1',
        'read addresses the namespaced CRD path';

    my ($put) = $k->reqs('PUT');
    ok $put, 'lease is written with a PUT';
    is $put->{path}, '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/w1',
        'write addresses the same path';

    my $sent = JSON::MaybeXS::decode_json($put->{body});
    like $sent->{metadata}{annotations}{'ocp.internal/reconciler-lease'},
         qr/^cli\@.+\@300$/, 'lease annotation written with cli holder and 300s ttl';
    is $sent->{metadata}{resourceVersion}, '100',
        'resourceVersion travels with the PUT, so a racing reconciler gets a 409';
};

subtest 'lease held by another reconciler dies' => sub {
    my $now = OCP::Node::_rfc3339_now();
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'w2', namespace => 'ocp-system', resourceVersion => '1',
                      annotations => { 'ocp.internal/reconciler-lease' => "robocop\@$now\@300" } },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k,
        provider => FakeProvider->new, ssh_key => 'K', server_url => 'U', join_token => 'T');

    eval { $node->_acquire_lease };
    like $@, qr/lease held/i, 'refuses to steal live lease held by another';
    is scalar($k->reqs('PUT')), 0, 'and writes nothing';
};

subtest 'lease expired is stealable' => sub {
    my $old = '2000-01-01T00:00:00Z';
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'w3', namespace => 'ocp-system', resourceVersion => '1',
                      annotations => { 'ocp.internal/reconciler-lease' => "robocop\@$old\@300" } },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    eval { $node->_acquire_lease };
    is $@, '', 'expired lease is stealable';
    my ($put) = $k->reqs('PUT');
    my $sent = JSON::MaybeXS::decode_json($put->{body});
    like $sent->{metadata}{annotations}{'ocp.internal/reconciler-lease'},
         qr/^cli\@/, 'new lease owned by cli';
};

subtest 'lease acquisition falls back to the in-memory CR when it is not stored yet' => sub {
    # get() croaks on 404; a CR that has not been persisted must not be fatal.
    my $k = StrictK8s::build(cr => undef);
    my $node = OCP::Node->from_cr(ocpnode(metadata =>
        { name => 'w404', namespace => 'ocp-system' }), k8s => $k,
        provider => FakeProvider->new, ssh_key => 'K', server_url => 'U', join_token => 'T');

    eval { $node->_acquire_lease };
    is $@, '', 'a 404 on read is survivable';
    ok scalar($k->reqs('PUT')), 'lease still written from the in-memory copy';
};

subtest 'a failed read is not an absent CR' => sub {
    # Falling back to the in-memory copy on *any* error would take the lease on
    # the strength of a CR nobody managed to read -- including one another
    # reconciler is holding. Only 404 means "not stored yet".
    my $k = StrictK8s::build(cr => ocpnode(metadata =>
        { name => 'w503', namespace => 'ocp-system' }));
    $k->read_fails(503);
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    ok !eval { $node->_acquire_lease; 1 }, 'a 503 on read aborts lease acquisition';
    is scalar($k->reqs('PUT')), 0, 'and nothing is written';
};

subtest 'a failed read mid-poll is survivable' => sub {
    # _refresh runs in a loop; one API blip must not fail the worker.
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'p1', namespace => 'ocp-system' },
        status   => { phase => 'Ready' }));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    $k->read_fails(503);

    my $ok = eval { $node->_refresh; 1 };
    ok $ok, '_refresh swallows the failure';
    is $node->phase, 'Ready', 'and keeps the phase it already had';
};

subtest '_release_lease re-reads before writing and removes the annotation' => sub {
    my $now = OCP::Node::_rfc3339_now();
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'w5', namespace => 'ocp-system', resourceVersion => '7',
                      annotations => { 'ocp.internal/reconciler-lease' => "cli\@$now\@300" } },
        status   => { phase => 'Installing' },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    $node->_release_lease;

    ok scalar($k->reqs('GET')),
        're-reads first: the status patch in between bumped resourceVersion';
    my ($put) = $k->reqs('PUT');
    ok $put, 'update called to release';
    my $sent = JSON::MaybeXS::decode_json($put->{body});
    ok !exists $sent->{metadata}{annotations}{'ocp.internal/reconciler-lease'},
        'lease annotation removed';
};

subtest '_provision calls provider->create_server and transitions to Installing' => sub {
    my $create_args;
    my $prov = FakeProvider->new(create_cb => sub {
        $create_args = { @_ };
        return { id => 'SRV42', ip => '5.6.7.8' };
    });
    my $k = StrictK8s::build(cr => ocpnode(metadata =>
        { name => 'w4', namespace => 'ocp-system', resourceVersion => '1' }));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    $node->_provision;

    ok $create_args, 'provider->create_server was called';
    is $create_args->{name}, 'w4', 'node name passed to create_server';
    is $create_args->{node}, 'w4', 'node param passed for label-based idempotency';

    my ($status_patch) = grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH');
    ok $status_patch, 'status patched';
    is $status_patch->{path},
        '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/w4/status',
        'phase transition goes to the /status subresource, not the main endpoint';
    my $sent = JSON::MaybeXS::decode_json($status_patch->{body});
    is $sent->{status}{phase}, 'Installing', 'phase advanced to Installing';
    is $sent->{status}{providerId}, 'SRV42', 'provider id recorded';
};

subtest 'a server that came up is not marked Failed because the lease release failed' => sub {
    # _provision reads once to acquire and once to release. Fail only the
    # second: the machine exists and the phase is written, so letting that
    # error out of _provision would drop the node into Failed -- terminal --
    # while its server kept running. The lease just stands until its TTL.
    my $k = StrictK8s::build(cr => ocpnode(metadata =>
        { name => 'w7', namespace => 'ocp-system', resourceVersion => '1' }));
    $k->read_fails(503);
    $k->reads_ok_first(1);

    my $node = OCP::Node->from_cr($k->cr, k8s => $k,
        provider => FakeProvider->new(create_cb => sub { { id => 'S7', ip => '7.7.7.7' } }),
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    is $node->reconcile, 1, 'reconcile still reports success';

    my @phases = map { JSON::MaybeXS::decode_json($_->{body})->{status}{phase} // '' }
                 grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH');
    ok scalar(grep { $_ eq 'Installing' } @phases), 'phase advanced to Installing';
    ok !scalar(grep { $_ eq 'Failed' } @phases),
        'and was never written as Failed';
};

subtest '_provision failure keeps lease (for TTL-based retry)' => sub {
    my $prov = FakeProvider->new(create_cb => sub { die "hetzner 5xx\n" });
    my $k = StrictK8s::build(cr => ocpnode(metadata =>
        { name => 'w6', namespace => 'ocp-system', resourceVersion => '1' }));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    eval { $node->_provision };
    ok $@, 'provision failure propagates';
    is scalar($k->reqs('PUT')), 1, 'only the lease acquire PUT — no release-on-failure';
};

subtest '_install_kubernetes calls Rex with install_rke2_agent for workers' => sub {
    @FakeRex::_instances = ();
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'w1', namespace => 'ocp-system' },
        status   => { phase => 'Installing', publicIP => '1.2.3.4' },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'KEY', server_url => 'https://cp:9345', join_token => 'TOKEN',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
    );

    $node->_install_kubernetes;

    my $r = $FakeRex::_instances[0];
    ok $r, 'FakeRex instantiated';
    is $r->{host}, '1.2.3.4', 'rex constructed with publicIP';
    my ($call) = @{ $r->{calls} };
    is $call->[0], 'install_rke2_agent', 'rke2 task for worker';
    is $call->[1]{server}, 'https://cp:9345', 'server URL threaded';
    is $call->[1]{token},  'TOKEN',            'join token threaded';
    is $call->[1]{node_name}, 'w1',            'node_name set';

    my ($status_patch) = grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH');
    ok $status_patch, 'status patched to Joining';
    is JSON::MaybeXS::decode_json($status_patch->{body})->{status}{phase}, 'Joining',
        'phase advanced to Joining';
};

subtest '_install_kubernetes uses k3s task when distribution=k3s' => sub {
    @FakeRex::_instances = ();
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'w2', namespace => 'ocp-system' },
        status   => { phase => 'Installing', publicIP => '1.2.3.4' },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k,
        provider => FakeProvider->new, ssh_key => 'K',
        server_url => 'U', join_token => 'T',
        distribution => 'k3s',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
    );
    $node->_install_kubernetes;
    my ($call) = @{ $FakeRex::_instances[0]{calls} };
    is $call->[0], 'install_k3s_agent', 'k3s task when distribution=k3s';
};

subtest '_wait_ready returns true when k8s Node is Ready' => sub {
    my $k = StrictK8s::build(
        cr   => ocpnode(metadata => { name => 'w3', namespace => 'ocp-system' },
                        status   => { phase => 'Joining', kubernetesNodeName => 'w3' }),
        node => ready_node('w3', 'True'),
    );
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    ok $node->_wait_ready, 'returns true on Ready';

    my ($node_get) = grep { $_->{path} eq '/api/v1/nodes/w3' } $k->reqs('GET');
    ok $node_get, 'the core/v1 Node is read from the core API path';
    ok scalar(grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH')), 'status patched on Ready';
};

subtest '_wait_ready returns false when Node not yet Ready' => sub {
    my $k = StrictK8s::build(
        cr   => ocpnode(metadata => { name => 'w4', namespace => 'ocp-system' },
                        status   => { phase => 'Joining', kubernetesNodeName => 'w4' }),
        node => ready_node('w4', 'False'),
    );
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    ok !$node->_wait_ready, 'returns false when not Ready';
};

subtest '_verify returns true when k8s Node is Ready' => sub {
    my $k = StrictK8s::build(
        cr   => ocpnode(metadata => { name => 'w5', namespace => 'ocp-system' },
                        status   => { phase => 'Ready', kubernetesNodeName => 'w5' }),
        node => ready_node('w5', 'True'),
    );
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    ok $node->_verify, '_verify returns true when Ready';
};

subtest '_verify returns false when k8s Node not Ready' => sub {
    my $k = StrictK8s::build(
        cr   => ocpnode(metadata => { name => 'w6', namespace => 'ocp-system' },
                        status   => { phase => 'Ready', kubernetesNodeName => 'w6' }),
        node => ready_node('w6', 'False'),
    );
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    ok !$node->_verify, '_verify returns false when not Ready';
};

subtest 'reconcile dispatches to _provision on Pending phase' => sub {
    @FakeRex::_instances = ();
    my $k = StrictK8s::build(cr => ocpnode(metadata =>
        { name => 'r1', namespace => 'ocp-system', resourceVersion => '1' }));
    my $prov = FakeProvider->new(create_cb => sub { { id => 'S1', ip => '1.1.1.1' } });
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');
    ok $node->reconcile, 'reconcile returns truthy';
};

subtest 'reconcile from Installing actually installs Kubernetes' => sub {
    # _provision writes phase=Installing, and 'Installing' used to dispatch to
    # _wait_ready. _install_kubernetes was then reachable only from
    # 'Provisioning' -- a phase no code in OCP ever writes -- so the Rex agent
    # install was dead code and the node waited for a registration that could
    # never come. This is the assertion that says the install runs.
    @FakeRex::_instances = ();
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'i1', namespace => 'ocp-system' },
        status   => { phase => 'Installing', publicIP => '1.2.3.4' },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'https://cp:9345', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');

    $node->reconcile;

    my $r = $FakeRex::_instances[0];
    ok $r, 'reconcile on Installing reached the Rex install';
    is $r->{calls}[0][0], 'install_rke2_agent', 'and ran the agent install task';
};

subtest 'reconcile catches exception and patches Failed' => sub {
    my $k = StrictK8s::build(cr => ocpnode(metadata =>
        { name => 'r2', namespace => 'ocp-system', resourceVersion => '1' }));
    my $prov = FakeProvider->new(create_cb => sub { die "boom\n" });
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    is $node->reconcile, 0, 'reconcile returns 0 on failure';
    my ($failed) = grep {
        $_->{path} =~ m{/status$}
            && (JSON::MaybeXS::decode_json($_->{body})->{status}{phase} // '') eq 'Failed';
    } $k->reqs('PATCH');
    ok $failed, 'status patched to Failed';
};

subtest 'reconcile_until_ready returns 1 on Ready CR' => sub {
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'r3', namespace => 'ocp-system' },
        status   => { phase => 'Ready' }));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    is $node->reconcile_until_ready(timeout => 1, interval => 0), 1, 'Ready short-circuits';
};

subtest 'reconcile_until_ready returns 0 on Failed CR' => sub {
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'r4', namespace => 'ocp-system' },
        status   => { phase => 'Failed' }));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    is $node->reconcile_until_ready(timeout => 1, interval => 0), 0, 'Failed short-circuits';
};

subtest 'teardown drains, deletes the server, and deletes both objects' => sub {
    my $delete_called;
    my $prov = FakeProvider->new(delete_cb => sub {
        my ($server_id, %opts) = @_;
        $delete_called = { id => $server_id, %opts };
        1;
    });
    my $k = StrictK8s::build(
        cr => ocpnode(
            metadata => { name => 't1', namespace => 'ocp-system' },
            status   => { phase => 'Ready', kubernetesNodeName => 't1',
                          publicIP => '1.2.3.4', providerId => 'SRV1' }),
        node => ready_node('t1', 'True'),
    );
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    $node->teardown;

    my ($terminating) = grep {
        $_->{path} =~ m{/status$}
            && (JSON::MaybeXS::decode_json($_->{body})->{status}{phase} // '') eq 'Terminating';
    } $k->reqs('PATCH');
    ok $terminating, 'status patched to Terminating';

    ok $delete_called, 'provider->delete_server called';
    is $delete_called->{id}, 'SRV1', 'provider id from status passed as first argument';
    is $delete_called->{host}, '1.2.3.4', 'host passed for host-based providers';
    is $delete_called->{name}, 't1', 'node name passed';

    # Both deletes used to lead with an api-version and die inside their eval,
    # so teardown returned 1 while leaving the Node and the CR in the cluster.
    my @deleted = map { $_->{path} } $k->reqs('DELETE');
    ok scalar(grep { $_ eq '/api/v1/nodes/t1' } @deleted),
        'the core/v1 Node object is actually deleted';
    ok scalar(grep { $_ eq '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/t1' } @deleted),
        'the OCPNode CR is actually deleted';
};

subtest 'reconcile returns 0 on Failed phase (terminal)' => sub {
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => {name=>'f1',namespace=>'ocp-system'}, status => {phase => 'Failed'}));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k,
        provider => FakeProvider->new, ssh_key => 'K', server_url => 'U', join_token => 'T');
    is $node->reconcile, 0, 'Failed terminal: reconcile returns 0';
};

subtest 'reconcile returns 0 on Terminating phase (terminal)' => sub {
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => {name=>'tt1',namespace=>'ocp-system'}, status => {phase => 'Terminating'}));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k,
        provider => FakeProvider->new, ssh_key => 'K', server_url => 'U', join_token => 'T');
    is $node->reconcile, 0, 'Terminating terminal: reconcile returns 0';
};

#
# ssh_class and rex_class are plain strings in the attribute defaults, so
# nothing in OCP::Node pulls those packages in. _install_kubernetes then calls
# ->new on them by name and dies with "Can't locate object method new via
# package OCP::Rex" — but only on a real reconcile against a real host, which
# is exactly the path no test drives (karr #29).
#
# This has to run in its own interpreter. In-process the check would pass as
# soon as any other module in the same run happens to load OCP::Rex, which is
# how the gap stayed invisible in the first place.
#
subtest 'default ssh_class and rex_class are loaded by OCP::Node alone' => sub {
    for my $class (qw(OCP::SSH OCP::Rex)) {
        my $code = "use OCP::Node; print $class->can('new') ? 'yes' : 'no'";
        my $out  = qx{$^X -Ilib -e "$code" 2>&1};
        is $out, 'yes', "OCP::Node makes $class usable without help";
    }
};

done_testing;

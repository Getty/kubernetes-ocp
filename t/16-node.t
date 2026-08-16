use strict;
use warnings;
use Test::More;
use File::Temp ();
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

        # `delete_fails` is an HTTP status to answer every DELETE with. 403 is
        # the case that matters (a ClusterRole without the verb), 404 the one
        # that must stay quiet.
        if ($method eq 'DELETE') {
            return ($api->delete_fails, { message => 'injected delete failure' })
                if $api->delete_fails;
            return (200, {});
        }

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
    has delete_fails   => (is => 'rw', default => 0);  # HTTP status to inject on deletes

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
    sub new { my ($c, %a) = @_; bless { waits => [], %a }, $c }
    sub create_server { my ($s, %a) = @_; $s->{create_cb} ? $s->{create_cb}->(%a) : { id => 'SRV1', ip => '1.2.3.4' } }
    sub delete_server { my ($s, @a) = @_; $s->{delete_cb} ? $s->{delete_cb}->(@a) : 1 }
    # Every real provider has this: Hetzner blocks on the cloud API,
    # OCP::Role::Provider::ExistingHost hands the hashref straight back. What
    # matters to the tests is whether it was called at all.
    sub wait_for_running {
        my ($s, $info, $timeout) = @_;
        push @{ $s->{waits} }, { id => $info->{id}, timeout => $timeout };
        return $s->{wait_cb}->($info, $timeout) if $s->{wait_cb};
        $info->{ip} = '9.9.9.9';
        return $info;
    }
}

package FakeSSH {
    our @_waits;
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    # Records what the caller ASKED for, which is not the same as what it got:
    # undef means it named no budget and takes OCP::SSH's, and that is the
    # whole of karr #109.
    sub wait_for_ssh {
        my ($s, $n) = @_;
        push @_waits, $n;
        return $s->{ssh_cb} ? $s->{ssh_cb}->($n) : 1;
    }
}

package FakeRex {
    our @_instances;
    sub new { my ($c, %a) = @_; my $s = bless { %a, calls => [] }, $c; push @_instances, $s; $s }
    sub run_task { my ($s, $task, %p) = @_;
        push @{$s->{calls}}, [$task, \%p];
        $s->{run_cb} ? $s->{run_cb}->($task, %p) : 1;
    }
}

# The Hetzner adapter is exercised for real further down -- only the cloud
# client under it is faked, so nothing here reaches the network. `cloud` is a
# lazy attribute, so handing one in replaces the builder.
package FakeHetznerServer {
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub id   { $_[0]{id} }
    sub ipv4 { $_[0]{ipv4} }
}

package FakeHetznerServers {
    sub new { my ($c, %a) = @_; bless { created => [], waited => [], %a }, $c }
    sub list_by_label { $_[0]{existing} // [] }
    # A freshly created server has an id and no address -- that is the real
    # shape, and the whole of karr #99.
    sub create {
        my ($self, %params) = @_;
        push @{ $self->{created} }, \%params;
        return FakeHetznerServer->new(id => 'SRV-' . scalar @{ $self->{created} });
    }
    # WWW::Hetzner::Cloud::API::Servers croaks on timeout rather than returning
    # a server that is not there yet; `never_running` reproduces that.
    sub wait_for_status {
        my ($self, $id, $status, $timeout) = @_;
        push @{ $self->{waited} },
            { id => $id, status => $status, timeout => $timeout };
        die "Timeout waiting for server $id to reach status '$status'"
            if $self->{never_running};
        return FakeHetznerServer->new(
            id => $id, ipv4 => $self->{running_ip} // '203.0.113.7');
    }
}

package FakeHetznerCloud {
    sub new     { my ($c, %a) = @_; bless { servers => FakeHetznerServers->new(%a) }, $c }
    sub servers { $_[0]{servers} }
}

package main;

use Path::Tiny ();
use OCP::Node;
use OCP::Provider::Hetzner;
# Loaded by OCP::Node anyway; named here because the budget assertions below
# read $OCP::SSH::WAIT_TIMEOUT straight out of it.
use OCP::SSH;

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

subtest '_provision through the real Hetzner adapter gives the server an SSH key' => sub {
    # FakeProvider above cannot show this: the defect is not in _provision and
    # not in create_server, it is in the seam between them. _provision names
    # none of the provider options and passes `spec => $cr->{spec}` instead,
    # so a create_server that reads only its options fell through to
    # `ssh_keys => []` -- a Hetzner worker with an empty authorized_keys, up
    # and billing and unreachable for good (karr #92, the Hetzner half of #51).
    #
    # So the adapter here is the real one, with only the cloud client faked.
    my $cloud = FakeHetznerCloud->new;
    my $prov  = OCP::Provider::Hetzner->new(
        token        => 'fake-token',
        cluster_name => 'cortex',
        ssh_key_name => 'ocp-cortex-admin',   # from spec.hetzner.sshKeyName
        cloud        => $cloud,
    );

    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'w9', namespace => 'ocp-system', resourceVersion => '1' },
        spec     => {
            role        => 'worker',
            providerRef => 'hetzner-default',
            serverType  => 'cx42',
            location    => 'nbg1',
            image       => 'debian-12',
        },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    $node->_provision;

    my $sent = $cloud->servers->{created}[0];
    ok $sent, 'a server was created through _provision';
    ok scalar @{ $sent->{ssh_keys} }, 'the server has at least one SSH key';
    is_deeply $sent->{ssh_keys}, ['ocp-cortex-admin'],
        'and it is the cluster admin key bootstrap uploaded';

    is $sent->{server_type}, 'cx42',      'spec.serverType survived _provision';
    is $sent->{location},    'nbg1',      'spec.location survived _provision';
    is $sent->{image},       'debian-12', 'spec.image survived _provision';
    is $sent->{labels}{'ocp-node'}, 'w9', 'labelled for the idempotency lookup';
};

subtest '_provision refuses a keyless Hetzner worker instead of creating it' => sub {
    # A provider CR written before sshKeyName existed. The node ends up Failed,
    # which is terminal and needs a human -- that is the intended outcome: the
    # alternative is a machine that costs money and can never be reached.
    my $cloud = FakeHetznerCloud->new;
    my $prov  = OCP::Provider::Hetzner->new(
        token => 'fake-token', cluster_name => 'cortex', cloud => $cloud,
    );

    my $k = StrictK8s::build(cr => ocpnode(metadata =>
        { name => 'w10', namespace => 'ocp-system', resourceVersion => '1' }));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    is $node->reconcile, 0, 'reconcile reports failure';
    is scalar @{ $cloud->servers->{created} }, 0, 'no server was created';

    my ($status_patch) = grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH');
    my $sent = JSON::MaybeXS::decode_json($status_patch->{body});
    is $sent->{status}{phase}, 'Failed', 'the node is marked Failed';
    like $sent->{status}{message}, qr/without an SSH key/,
        'and the message says what is missing, not just that something broke';
};

#
# The address a Hetzner worker does not have yet (karr #99).
#
# create_server returns `ip => undef` for a fresh server: Hetzner allocates the
# IP when the machine reaches `running`, and only wait_for_running reads it
# back. _provision wrote that undef straight into status.publicIP and advanced
# to Installing; _install_kubernetes then read `status.publicIP || spec.host`,
# found neither -- a hetzner node has no spec.host -- and patched
#
#     phase => 'Failed', message => 'No host IP in status or spec'
#
# which is terminal, on a machine that had just been created and had started
# billing, before a single connection was attempted. wait_for_running had
# exactly one caller in the whole distribution, OCP::Cmd::Apply::Bootstrap, so
# no worker ever asked.
#
# The tests below drive the two reconcile passes as two passes, because that is
# what they are: robocop builds a fresh OCP::Node from the stored CR on every
# tick, and `ocp node add` loops through reconcile_until_ready.
#

# Replay the recorded status writes onto a CR the way the API server would.
# The mock transport serves one fixed document; pass 2 has to start from what
# pass 1 actually stored, not from what the test set up.
sub stored_after {
    my ($k, $cr) = @_;
    my %status = %{ $cr->{status} // {} };
    for my $req (grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH')) {
        my $patch = JSON::MaybeXS::decode_json($req->{body})->{status};
        $status{$_} = $patch->{$_} for keys %$patch;
    }
    return { %$cr, status => \%status };
}

sub hetzner_provider {
    my (%over) = @_;
    my $cloud = FakeHetznerCloud->new(%over);
    return (OCP::Provider::Hetzner->new(
        token        => 'fake-token',
        cluster_name => 'cortex',
        ssh_key_name => 'ocp-cortex-admin',
        cloud        => $cloud,
    ), $cloud);
}

subtest '_provision writes no publicIP when the server has none yet' => sub {
    my ($prov) = hetzner_provider();
    my $k = StrictK8s::build(cr => ocpnode(metadata =>
        { name => 'w11', namespace => 'ocp-system', resourceVersion => '1' }));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    $node->_provision;

    my ($status_patch) = grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH');
    my $sent = JSON::MaybeXS::decode_json($status_patch->{body})->{status};

    is $sent->{phase}, 'Installing',
        'the phase still advances -- the server exists, that part worked';
    is $sent->{providerId}, 'SRV-1',
        'and its id is written down before anything starts waiting on it';
    ok !exists $sent->{publicIP},
        'no publicIP key at all: this is a merge patch, so undef would delete one';
    like $sent->{message}, qr/address/,
        'and the message says what the node is waiting for';
};

subtest 'the Installing pass asks the provider for the address and installs on it' => sub {
    # THE assertion of karr #99: a Hetzner worker that goes through _provision
    # ends up with a publicIP in status, and the install runs against it.
    @FakeRex::_instances = ();
    my ($prov, $cloud) = hetzner_provider();
    my $k = StrictK8s::build(cr => ocpnode(metadata =>
        { name => 'w12', namespace => 'ocp-system', resourceVersion => '1' }));

    my $pass1 = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    $pass1->_provision;

    my $stored = stored_after($k, $k->cr);
    is $stored->{status}{publicIP}, undef, 'pass 1 leaves no address behind';
    $k->cr($stored);

    my $pass2 = OCP::Node->from_cr($stored, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'https://cp:9345', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');
    is $pass2->reconcile, 1, 'the second pass reconciles cleanly';

    my $waited = $cloud->servers->{waited}[0];
    ok $waited, 'the provider was asked';
    is $waited->{id}, 'SRV-1',   'about the server _provision created';
    is $waited->{status}, 'running', 'waiting for it to be running';
    is $waited->{timeout}, 120,
        'with the same budget OCP::Cmd::Apply::Bootstrap spends on this wait';

    my $r = $FakeRex::_instances[0];
    ok $r, 'the agent install ran';
    is $r->{host}, '203.0.113.7',
        'against the address the provider handed back';

    my @status = map { JSON::MaybeXS::decode_json($_->{body})->{status} }
                 grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH');
    is scalar(grep { ($_->{publicIP} // '') eq '203.0.113.7' } @status), 1,
        'the address is written back to status.publicIP, once';
    is scalar(grep { ($_->{message} // '') =~ /No host IP/ } @status), 0,
        'and nothing was ever failed for "No host IP"';
    is $status[-1]{phase}, 'Joining', 'the node reached Joining';
};

subtest 'a server that never comes up fails with what was waited for' => sub {
    # Bounded, not endless -- but the message has to name the machine, the
    # budget and the fact that it is still costing money. "No host IP in status
    # or spec" said none of that and blamed the CR for it.
    @FakeRex::_instances = ();
    my ($prov) = hetzner_provider(never_running => 1);
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'w13', namespace => 'ocp-system' },
        status   => { phase => 'Installing', providerId => 'SRV-9' },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');

    $node->reconcile;

    my ($sent) = map { JSON::MaybeXS::decode_json($_->{body})->{status} }
                 grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH');
    is $sent->{phase}, 'Failed', 'the node fails visibly instead of waiting forever';
    like $sent->{message}, qr/SRV-9/,  'the message names the server';
    like $sent->{message}, qr/120s/,   'and how long it was given';
    like $sent->{message}, qr/billed/, 'and that the machine is still costing money';
    unlike $sent->{message}, qr/No host IP/,
        'not the old message, which pointed at the CR instead of the server';
    is scalar @FakeRex::_instances, 0,
        'and nothing tried to install on a machine with no address';
};

subtest 'a node with spec.host never asks a provider for its address' => sub {
    # The ssh and local providers keep the address in spec.host and hand it
    # straight back from create_server, so status.providerId stays undef. Both
    # guards have to hold: their wait_for_running (via
    # OCP::Role::Provider::ExistingHost) is a passthrough that never sets `ip`,
    # so asking it would look like a server that came up without an address.
    @FakeRex::_instances = ();
    my $prov = FakeProvider->new;
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 's1', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'ssh-default',
                      host => '10.0.0.5' },
        status   => { phase => 'Installing' },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');

    $node->_install_kubernetes;

    is scalar @{ $prov->{waits} }, 0, 'the provider was not asked';
    is $FakeRex::_instances[0]{host}, '10.0.0.5',
        'and the install ran against spec.host, unchanged';
};

subtest 'no address and no server to ask is still a visible failure' => sub {
    @FakeRex::_instances = ();
    my $prov = FakeProvider->new;
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 's2', namespace => 'ocp-system' },
        status   => { phase => 'Installing' },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');

    $node->_install_kubernetes;

    is scalar @{ $prov->{waits} }, 0,
        'no providerId means there is nothing to ask about';
    my ($sent) = map { JSON::MaybeXS::decode_json($_->{body})->{status} }
                 grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH');
    is $sent->{phase}, 'Failed', 'still terminal -- nobody said where this node is';
    like $sent->{message}, qr/no provider server to ask/,
        'and the message says the provider had nothing to be asked about';
};

subtest 'a server that already had an address is not waited on again' => sub {
    # The idempotent branch of Hetzner::create_server (a labelled server that
    # already exists) returns its ipv4, so _provision writes publicIP and the
    # install must go straight through.
    @FakeRex::_instances = ();
    my $prov = FakeProvider->new;
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 's3', namespace => 'ocp-system' },
        status   => { phase => 'Installing', providerId => 'SRV-3',
                      publicIP => '1.2.3.4' },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');

    $node->_install_kubernetes;

    is scalar @{ $prov->{waits} }, 0, 'a known address is not re-resolved';
    is $FakeRex::_instances[0]{host}, '1.2.3.4', 'the install used it directly';
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

#
# The key files OCP::Node hands to Rex (karr #93).
#
# OCP::Rex sets REX_PUBLIC_KEY to key_file . '.pub' unconditionally and never
# looks to see whether anything is there. _build_ssh_key_file wrote a bare
# File::Temp with the private half and nothing else, so on EVERY worker
# install — robocop's as much as the CLI's — Rex was pointed at a path that
# did not exist. The identical defect was fixed in OCP::Cmd::Apply::Bootstrap
# by karr #87; the worker path was outside that ticket and stayed broken.
#
# These assertions are made where the defect lived: at the arguments Rex is
# actually constructed with.
#

# Drive _install_kubernetes on a node in Installing phase and return the
# key_file Rex was handed, plus the node (so the caller controls its lifetime,
# which is what owns the files).
sub installing_node {
    my (%over) = @_;
    @FakeRex::_instances = ();
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'kf1', namespace => 'ocp-system' },
        status   => { phase => 'Installing', publicIP => '1.2.3.4' },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'PRIVATE-KEY-MATERIAL', server_url => 'U', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex', %over);
    $node->_install_kubernetes;
    return ($node, $FakeRex::_instances[0]{key_file});
}

subtest 'Rex is handed a key file that has its .pub beside it' => sub {
    my ($node, $key_file) = installing_node();

    ok $key_file, 'Rex was constructed with a key_file';
    ok -f $key_file, 'and the private key is really there';

    # This is the assertion the old builder could not pass.
    ok -f "$key_file.pub",
        'the public half exists at the exact path OCP::Rex builds for '
      . 'REX_PUBLIC_KEY';

    # SSH gets the same file, so wait_for_ssh and the Rex run cannot disagree
    # about which key opened the machine.
    my $ssh_key_file = $node->_ssh_key_file->path;
    is $ssh_key_file, $key_file, 'OCP::SSH and OCP::Rex share one key file';
};

subtest 'the derived .pub is the real public half of the key material' => sub {
    # Not merely "a file exists". Nothing in OCP::Node is ever handed a public
    # key: `ocp node add` holds an OCP::ClusterKey that has both halves, but
    # OCP::Robocop::Controller is given private key material over a socket and
    # has no key store, no project directory and no ocp.yaml in its container.
    # So the public half is derived from the private one, which is the only
    # answer that works for both triggers — and this says it comes out right.
    plan skip_all => 'needs ssh-keygen to make a fixture'
        unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

    my $dir = File::Temp->newdir;
    my $f   = "$dir/k";
    system("ssh-keygen -q -t ed25519 -N '' -C 'ocp-cluster-key' -f '$f' >/dev/null 2>&1") == 0
        or die "ssh-keygen failed";
    my $private = do { open my $fh, '<', $f or die $!; local $/; <$fh> };
    my $public  = do { open my $fh, '<', "$f.pub" or die $!; local $/; <$fh> };

    my ($node, $key_file) = installing_node(ssh_key => $private);
    ok -f "$key_file.pub", 'a public half was written at all'
        or return;
    my $written = do { open my $fh, '<', "$key_file.pub" or die $!; local $/; <$fh> };

    # ssh-keygen writes a third field, the comment. It lives in the section a
    # passphrase encrypts and authenticates nothing.
    my @want = split ' ', $public;
    my @got  = split ' ', $written;
    is "$got[0] $got[1]", "$want[0] $want[1]",
        'the .pub holds the public key that belongs to this private key';
};

subtest 'neither key file outlives the node, even when something dies' => sub {
    my ($priv, $pub);
    {
        my ($node, $key_file) = installing_node();
        ($priv, $pub) = ($key_file, "$key_file.pub");
        ok -f $priv && -f $pub, 'both exist while the node does';
    }
    ok !-e $priv, 'the private key is gone with the node';
    ok !-e $pub,  'and so is the public half';

    # The case that matters: a Rex task blowing up mid-install. Whatever
    # unwinds the stack must not leave a readable private key in /tmp.
    my ($dpriv, $dpub);
    my $err = do {
        local $@;
        eval {
            my ($node, $key_file) = installing_node();
            ($dpriv, $dpub) = ($key_file, "$key_file.pub");
            die "the install blew up\n";
        };
        $@;
    };
    like $err, qr/the install blew up/, 'the failure propagated';
    ok $dpriv && !-e $dpriv, 'the private key did not survive it';
    ok $dpub  && !-e $dpub,  'nor the public half';
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

#
# A delete that fails must not fail teardown -- but it must not be invisible
# either. robocop's ClusterRole granted core `nodes` no `delete`, so the Node
# delete came back 403 and the bare eval around it threw the answer away:
# teardown returned 1, the OCPNode CR was gone, and the Node object stayed in
# the cluster as NotReady with nothing in the log to say so (karr #35, the same
# shape as the api-version defect in karr #21). The RBAC fix is in
# share/robocop/rbac.yaml and asserted in t/55-robocop-rbac.t; this is the
# other half -- the next time a delete is refused for some other reason, it
# says so.
#
subtest 'a refused delete is reported, and teardown still completes' => sub {
    my $k = StrictK8s::build(
        cr => ocpnode(
            metadata => { name => 't2', namespace => 'ocp-system' },
            status   => { phase => 'Ready', kubernetesNodeName => 't2',
                          providerId => 'SRV1' }),
        node         => ready_node('t2', 'True'),
        delete_fails => 403,
    );
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    my @warnings;
    my $ok = do {
        local $SIG{__WARN__} = sub { push @warnings, $_[0] };
        $node->teardown;
    };

    is $ok, 1,
        'teardown still returns 1 -- visibility, not a new failure path';

    my $said = join "\n", @warnings;
    like $said, qr{delete of Node/t2 failed},
        'the refused Node delete is warned about';
    like $said, qr{\b403\b},
        'and the warning carries the status that explains it (403 = missing RBAC verb)';
    like $said, qr{delete of OCPNode/t2 failed},
        'the CR delete is reported the same way';

    # Both were still attempted: one failing delete does not stop the other.
    my @deleted = map { $_->{path} } $k->reqs('DELETE');
    ok scalar(grep { $_ eq '/api/v1/nodes/t2' } @deleted), 'the Node delete was attempted';
    ok scalar(grep { $_ eq '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/t2' } @deleted),
        'the CR delete was attempted';
};

subtest 'a delete that 404s stays quiet -- the object is already gone' => sub {
    my $k = StrictK8s::build(
        cr => ocpnode(
            metadata => { name => 't3', namespace => 'ocp-system' },
            status   => { phase => 'Ready', kubernetesNodeName => 't3' }),
        delete_fails => 404,
    );
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    my @warnings;
    my $ok = do {
        local $SIG{__WARN__} = sub { push @warnings, $_[0] };
        $node->teardown;
    };

    is $ok, 1, 'teardown returns 1';
    is_deeply \@warnings, [],
        'nothing is warned: a node that never registered, or a CR someone '
      . 'already removed, is the normal outcome here'
        or diag "unexpected warnings:\n@warnings";
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
# Two callers waited for the same thing with two budgets: the control plane got
# 120s to answer on SSH (OCP::Cmd::Apply::Bootstrap), a worker got 60 -- and on
# the worker side running out is TERMINAL (phase => Failed, which nothing
# retries), so a machine whose sshd needed 70s was lost for good while its bill
# kept running. Nobody had noticed, because before karr #99 a Hetzner worker
# died one step earlier, at "No host IP in status or spec".
#
# The assertions below are about the seam, not about either number: two numbers
# for one question is the defect, so they are compared to each other rather
# than each pinned on its own. Bootstrap's side is read from source because
# bootstrap_control_plane cannot be driven without a provider, a key and a real
# install -- same reason, same shape as t/28.
#
subtest 'the SSH wait is one budget, not one per caller' => sub {
    # The budget a call site actually spends: the number it names, or the
    # module's when it names none.
    my $budget_in = sub {
        my ($file) = @_;
        my $src = Path::Tiny::path(__FILE__)->parent->parent->child($file)->slurp_utf8;
        my @named = $src =~ /->wait_for_ssh\s*(?:\(\s*([^)]*?)\s*\))?/g;
        is scalar @named, 1, "$file waits for SSH in exactly one place";
        return defined $named[0] && length $named[0]
            ? $named[0]
            : $OCP::SSH::WAIT_TIMEOUT;
    };

    is $budget_in->('lib/OCP/Node.pm'),
       $budget_in->('lib/OCP/Cmd/Apply/Bootstrap.pm'),
       'a worker and a control plane wait for SSH with the same budget';

    is $OCP::SSH::WAIT_TIMEOUT, 120,
        'and it is the 120s the control-plane path has always spent';

    # That the constant is the number, not a comment next to one: at zero the
    # loop body never runs, so this reaches no network and dials no host.
    {
        local $OCP::SSH::WAIT_TIMEOUT = 0;
        local $@;
        eval { OCP::SSH->new(host => '203.0.113.9')->wait_for_ssh };
        like $@, qr/after 0s/,
            'an argument-less wait_for_ssh counts down from $OCP::SSH::WAIT_TIMEOUT';
    }
};

subtest 'the worker install names no SSH budget of its own' => sub {
    @FakeSSH::_waits = ();
    @FakeRex::_instances = ();
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'i9', namespace => 'ocp-system' },
        status   => { phase => 'Installing', publicIP => '1.2.3.4' },
    ));
    my $node = OCP::Node->from_cr($k->cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'https://cp:9345', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');

    $node->reconcile;

    is scalar @FakeSSH::_waits, 1, 'the install waited for SSH once';
    is $FakeSSH::_waits[0], undef,
        'and asked for no budget -- so it spends OCP::SSH::WAIT_TIMEOUT, not the 60 it used to name';
};

#
# One budget has to cover everything between "there is a CR" and "there is a
# Ready node": the address wait, the SSH wait, the whole Rex install and the
# join. Three callers named 600 for it, and the sum underneath had grown past
# that -- karr #109 alone added 60s of it. The number lives in OCP::Node now,
# with the arithmetic written next to it.
#
subtest 'reconcile_until_ready has one budget for every caller' => sub {
    is $OCP::Node::READY_TIMEOUT, 900,
        'the budget covers the waits it is made of, with room for a slow mirror';

    # Not a literal that happens to match: at zero the loop never looks, so a
    # CR that is already Ready still comes back 0.
    {
        local $OCP::Node::READY_TIMEOUT = 0;
        my $k = StrictK8s::build(cr => ocpnode(
            metadata => { name => 'b0', namespace => 'ocp-system' },
            status   => { phase => 'Ready' }));
        my $node = OCP::Node->from_cr($k->cr, k8s => $k,
            provider => FakeProvider->new, ssh_key => 'K',
            server_url => 'U', join_token => 'T');
        is $node->reconcile_until_ready, 0,
            'the default comes from $OCP::Node::READY_TIMEOUT';
    }

    for my $file (qw(lib/OCP/Cmd/Node/Add.pm lib/OCP/Cmd/Apply/CR.pm)) {
        my $src = Path::Tiny::path(__FILE__)->parent->parent->child($file)->slurp_utf8;
        my @calls = $src =~ /->reconcile_until_ready\(([^)]*)/g;
        ok scalar @calls, "$file drives a node to Ready";
        unlike $_, qr/timeout/, "$file names no budget of its own" for @calls;
    }
};

#
# Fifteen minutes is a long time to look at a cursor. OCP::Node must not print
# -- robocop runs the same code -- so it hands the phase to whoever asked.
#
package PhaseTape {
    our @ISA = ('OCP::Node');
    our @tape;
    sub _refresh  { }
    sub phase     { shift @tape }
    sub reconcile { 1 }
}

subtest 'reconcile_until_ready reports each phase once, and only when asked' => sub {
    my $k = StrictK8s::build(cr => ocpnode(metadata =>
        { name => 'p1', namespace => 'ocp-system' }));

    @PhaseTape::tape = qw(Pending Installing Installing Installing Joining Ready);
    my @seen;
    my $node = PhaseTape->new(cr => $k->cr, k8s => $k);
    is $node->reconcile_until_ready(interval => 0,
        on_phase => sub { push @seen, $_[0] }), 1, 'still returns the verdict';
    is_deeply \@seen, [qw(Pending Installing Joining Ready)],
        'one line per phase, not per tick, and the phase it returns on is reported too';

    @PhaseTape::tape = qw(Pending Failed);
    my $quiet = PhaseTape->new(cr => $k->cr, k8s => $k);
    is $quiet->reconcile_until_ready(interval => 0), 0,
        'and without a sink it says nothing and still answers';
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

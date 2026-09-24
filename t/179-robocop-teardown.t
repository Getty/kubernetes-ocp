#!/usr/bin/env perl
# karr k179 -- robocop tears down a deleted worker OCPNode.
#
# Deleting an OCPNode used to leave its machine running: robocop skipped
# Terminating, ignored DELETED, and nothing held the CR back -- a Hetzner
# server kept billing with no record left in the cluster. Now a worker
# OCPNode carries the finalizer ocp.internal/teardown, a delete only sets
# deletionTimestamp, and robocop runs OCP::Node::teardown on it and removes
# the finalizer as the last step.
#
# This file pins:
#   - who gets the finalizer (workers from `ocp apply` / `ocp node add`, and
#     robocop adds it to older CRs), and who never does (control planes,
#     synthesized legacy nodes, a node in the middle of `ocp node rm`);
#   - robocop tears down a deleted worker with the robo key as a temp file that
#     is gone again afterwards, and the finalizer comes off before the delete;
#   - a failed teardown keeps the finalizer and is retried by the resync, not
#     by its own status write;
#   - inject mode without a key: an ssh node waits (SSHKeyAvailable=False), a
#     Hetzner node does not need the key;
#   - the lease keeps `ocp node rm` and robocop from tearing down the same
#     node at once.
#
# No cluster: Kubernetes::REST over a mock transport, the provider faked.

use strict;
use warnings;
use Test::More;
use JSON::MaybeXS ();
use Time::Piece ();

use lib 'lib';

my $JSON = JSON::MaybeXS->new(utf8 => 1, canonical => 1, convert_blessed => 1);

package MockResponse {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
    sub headers { {} }
}

# Serves one OCPNode and its OCPNodeProvider. PUTs replace the stored CR and
# status PATCHes merge into it, so later reads see earlier writes the way the
# API server answers them.
package MockTransport {
    sub new { my ($c, %a) = @_; bless {%a}, $c }

    sub call {
        my ($self, $req) = @_;
        my $api  = $self->{api};
        my $path = $req->url;
        $path =~ s{^https?://[^/]+}{};
        push @{ $api->requests }, {
            method => $req->method, path => $path, body => $req->content };
        my ($status, $struct) = $self->_respond($api, $req->method, $path, $req->content);
        return MockResponse->new(status => $status, content => $JSON->encode($struct));
    }

    sub _respond {
        my ($self, $api, $method, $path, $body) = @_;
        my $in = defined $body && length $body ? $JSON->decode($body) : undef;

        if ($path =~ m{/ocpnodes/[^/]+/status$}) {
            my $cr = $api->cr or return (404, { message => 'not found' });
            $cr->{status}{$_} = $in->{status}{$_} for keys %{ $in->{status} // {} };
            return (200, $cr);
        }
        if ($path =~ m{/ocpnodes/([^/?]+)$}) {
            my $cr = $api->cr;
            return (404, { message => "ocpnodes \"$1\" not found" }) unless $cr;
            if ($method eq 'PUT') {
                $in->{status} = $cr->{status};
                $api->cr($in);
                return (200, $in);
            }
            if ($method eq 'PATCH') {
                $cr->{metadata}{$_} = $in->{metadata}{$_} for keys %{ $in->{metadata} // {} };
                return (200, $cr);
            }
            return (200, {}) if $method eq 'DELETE';
            return (200, $cr);
        }
        if ($path =~ m{/ocpnodeproviders/([^/?]+)$}) {
            my $p = $api->provider;
            return $p ? (200, $p) : (404, { message => "ocpnodeproviders \"$1\" not found" });
        }
        # No Node object: cordon answers 404, so there is nothing to drain.
        return (404, { message => 'nodes not found' }) if $path =~ m{^/api/v1/nodes/};
        return (404, { message => "unexpected $method $path" });
    }
}

package MockK8s {
    use Moo;
    use OCP::K8s;
    extends 'Kubernetes::REST';
    use namespace::clean;

    has requests => (is => 'ro', default => sub { [] });
    has cr       => (is => 'rw');
    has provider => (is => 'rw');

    sub build {
        my (%args) = @_;
        my $t = MockTransport->new;
        my $self = MockK8s->new(
            server                    => { endpoint => 'https://cluster.invalid:6443' },
            credentials               => { token => 'fake-token' },
            resource_map_from_cluster => 0,
            io                        => $t,
            %args,
        );
        $t->{api} = $self;
        OCP::K8s->register($self);
        return $self;
    }

    sub reqs {
        my ($self, $method, $re) = @_;
        return grep { (!$method || $_->{method} eq $method) && (!$re || $_->{path} =~ $re) }
            @{ $self->requests };
    }

    sub status_writes {
        my ($self) = @_;
        return map { $JSON->decode($_->{body})->{status} } $self->reqs('PATCH', qr{/status$});
    }
}

package FakeProvider {
    sub new { my ($c, %a) = @_; bless { deletes => [], %a }, $c }
    sub delete_server {
        my ($self, $id, %opt) = @_;
        push @{ $self->{deletes} }, { id => $id, %opt,
            key_file_there => (defined $self->{key_path} && -f $self->{key_path}) ? 1 : 0 };
        die $self->{fail} if $self->{fail};
        return 1;
    }
}

package main;

use OCP::Node;
use OCP::Provider;
use OCP::Robocop::Controller;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Node::Add;

my $F = OCP::Node::TEARDOWN_FINALIZER;

sub now_rfc3339 { Time::Piece::gmtime->strftime('%Y-%m-%dT%H:%M:%SZ') }

sub ocpnode {
    my (%o) = @_;
    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => {
            name => 'w1', namespace => 'ocp-system', resourceVersion => '7',
            %{ $o{metadata} // {} },
        },
        spec   => { role => 'worker', providerRef => 'p', %{ $o{spec} // {} } },
        status => { phase => 'Ready', providerId => 'SRV9', publicIP => '10.0.0.9',
                    %{ $o{status} // {} } },
    };
}

sub deleted_node {
    my (%o) = @_;
    return ocpnode(%o, metadata => { deletionTimestamp => '2026-09-24T10:00:00Z',
                                     finalizers => [ $F ], %{ $o{metadata} // {} } });
}

sub provider_cr {
    my ($type) = @_;
    return { apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
             metadata => { name => 'p', namespace => 'ocp-system' },
             spec => { type => $type } };
}

sub ctrl {
    my (%o) = @_;
    return OCP::Robocop::Controller->new(
        ssh_key => "ROBO-KEY\n", server_url => 'U', join_token => 'T', %o);
}

sub capture_std {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    {
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $code->();
    }
    return ($out, $err);
}

# Runs one CR through the controller with the provider faked; returns what
# from_cr was handed and the fake provider.
sub run_ctrl {
    my ($c, $k, $cr, %prov) = @_;
    my ($from_cr_opts, $prov);
    no warnings 'redefine';
    local *OCP::Provider::from_cr = sub {
        my ($class, $pcr, %opt) = @_;
        $from_cr_opts = \%opt;
        $prov = FakeProvider->new(key_path => $opt{ssh_key_path}, %prov);
        return $prov;
    };
    my ($out, $err) = capture_std(sub { $c->_reconcile_cr($cr) });
    return ($out, $err, $from_cr_opts, $prov);
}

sub finalizer_puts {
    my ($k) = @_;
    return map { $JSON->decode($_->{body})->{metadata}{finalizers} // [] }
        $k->reqs('PUT', qr{/ocpnodes/w1$});
}

# ---------------------------------------------------------------------------
# Who carries the finalizer
# ---------------------------------------------------------------------------

subtest 'OCP::Node says which OCPNodes carry the finalizer' => sub {
    is $F, 'ocp.internal/teardown', 'the finalizer name';
    ok( OCP::Node->wants_finalizer(ocpnode()), 'a worker does' );
    ok !OCP::Node->wants_finalizer(ocpnode(spec => { role => 'control-plane' })),
        'a control plane never does -- robocop must not tear down a CP';
    ok !OCP::Node->wants_finalizer(ocpnode(metadata => { annotations => {
            'ocp.internal/synthetic' => 'true' } })),
        'nor a synthesized legacy node OCP did not install';
    ok( OCP::Node->has_finalizer(deleted_node()), 'has_finalizer sees it' );
    ok !OCP::Node->has_finalizer(ocpnode()), 'and its absence';
};

subtest 'the CLI creates worker OCPNodes with the finalizer' => sub {
    my $config = bless { workers => [
        { name => 'pool', provider => 'hetzner', nodes => 2 },
        { provider => 'ssh', host => 'box.lan' },
    ] }, 'FakeConfig';
    { no strict 'refs'; *{'FakeConfig::workers'} = sub { $_[0]{workers} } }
    my @crs = OCP::Cmd::Apply::CR::worker_ocpnodes($config);
    is scalar @crs, 3, 'three workers';
    is_deeply $_->{metadata}{finalizers}, [ $F ],
        "ocp apply: $_->{metadata}{name} carries it" for @crs;

    my $w = OCP::Cmd::Node::Add->new(name => 'w9', role => 'worker')->_build_cr('p');
    is_deeply $w->{metadata}{finalizers}, [ $F ], 'ocp node add: a worker carries it';
    my $cp = OCP::Cmd::Node::Add->new(name => 'cp2', role => 'control-plane')->_build_cr('p');
    ok !exists $cp->{metadata}{finalizers}, 'ocp node add: a control plane does not';
};

subtest 'robocop adds the finalizer to a worker created before k179' => sub {
    my $k = MockK8s::build(cr => ocpnode(), provider => provider_cr('hetzner'));
    my ($out, $err) = run_ctrl(ctrl(kube => $k), $k, ocpnode());

    my ($patch) = $k->reqs('PATCH', qr{/ocpnodes/w1$});
    ok $patch, 'a patch on the OCPNode itself';
    my $body = $JSON->decode($patch->{body});
    is_deeply $body->{metadata}{finalizers}, [ $F ], 'adding the finalizer';
    is $body->{metadata}{resourceVersion}, '7',
        'with the resourceVersion it read, so a concurrent change is a 409, not a lost finalizer';
    like $out, qr/w1: teardown finalizer added/, 'and says so';
};

subtest 'robocop adds no finalizer where none belongs' => sub {
    for my $case (
        [ 'already there',  ocpnode(metadata => { finalizers => [ $F ] }) ],
        [ 'control plane',  ocpnode(spec => { role => 'control-plane' }) ],
        [ 'synthetic',      ocpnode(metadata => { annotations => { 'ocp.internal/synthetic' => 'true' } }) ],
        [ 'ocp node rm at work (Terminating)', ocpnode(status => { phase => 'Terminating' }) ],
    ) {
        my ($what, $cr) = @$case;
        my $k = MockK8s::build(cr => $cr, provider => provider_cr('hetzner'));
        run_ctrl(ctrl(kube => $k), $k, $cr);
        is scalar($k->reqs('PATCH', qr{/ocpnodes/w1$})), 0, "$what: no finalizer patch";
    }
};

# ---------------------------------------------------------------------------
# robocop tears down a deleted worker
# ---------------------------------------------------------------------------

subtest 'a deleted ssh worker is torn down, the key only lives for the teardown' => sub {
    my $k = MockK8s::build(cr => deleted_node(), provider => provider_cr('ssh'));
    my ($out, $err, $opts, $prov) = run_ctrl(ctrl(kube => $k), $k, deleted_node());

    is scalar @{ $prov->{deletes} }, 1, 'provider->delete_server ran once';
    is $prov->{deletes}[0]{id},   'SRV9',     'with the provider id';
    is $prov->{deletes}[0]{host}, '10.0.0.9', 'and the host';
    ok $opts->{ssh_key_path}, 'the ssh provider was handed the robo key as a file';
    ok $prov->{deletes}[0]{key_file_there}, 'which existed while the uninstall ran';
    ok !-e $opts->{ssh_key_path}, 'and is gone once the teardown is done';

    my @fin = finalizer_puts($k);
    is_deeply $fin[-1], [], 'the last write takes the finalizer off';
    my @order = map { "$_->{method} $_->{path}" } @{ $k->requests };
    my ($put_i)  = grep { $order[$_] =~ m{^PUT .*/ocpnodes/w1$} } reverse 0 .. $#order;
    my ($del_i)  = grep { $order[$_] =~ m{^DELETE .*/ocpnodes/w1$} } 0 .. $#order;
    ok defined $del_i && $put_i < $del_i,
        'before the OCPNode delete -- otherwise the delete only marks it again';

    my ($term) = grep { ($_->{phase} // '') eq 'Terminating' } $k->status_writes;
    is $term->{reconciler}, 'robocop', 'the teardown is recorded as robocop\'s';
    like $out, qr/w1: deleted, tearing down/, 'logged: start';
    like $out, qr/w1: torn down, finalizer removed/, 'logged: done';
    is $err, '', 'nothing on STDERR';
};

subtest 'a deleted Hetzner worker needs no key file' => sub {
    my $k = MockK8s::build(cr => deleted_node(), provider => provider_cr('hetzner'));
    my (undef, undef, $opts, $prov) = run_ctrl(ctrl(kube => $k), $k, deleted_node());
    is scalar @{ $prov->{deletes} }, 1, 'the server is deleted';
    ok !exists $opts->{ssh_key_path}, 'through the API, without writing the key anywhere';
};

subtest 'a Failed node that is deleted is torn down too -- it still has a machine' => sub {
    my $cr = deleted_node(status => { phase => 'Failed',
        lastReconcileTime => '2026-09-24T09:00:00Z', message => 'SSH not reachable' });
    my $k = MockK8s::build(cr => $cr, provider => provider_cr('hetzner'));
    my (undef, undef, undef, $prov) = run_ctrl(ctrl(kube => $k), $k, $cr);
    is scalar @{ $prov->{deletes} }, 1, 'the server is deleted';
};

subtest 'a deleted node without the finalizer, or a control plane, is left alone' => sub {
    my $plain = ocpnode(metadata => { deletionTimestamp => '2026-09-24T10:00:00Z' });
    my $k = MockK8s::build(cr => $plain, provider => provider_cr('hetzner'));
    my ($out, undef, $opts) = run_ctrl(ctrl(kube => $k), $k, $plain);
    ok !$opts, 'no provider built';
    like $out, qr/no teardown finalizer/, 'said once';

    my $cp = deleted_node(spec => { role => 'control-plane' });
    $k = MockK8s::build(cr => $cp, provider => provider_cr('hetzner'));
    my (undef, $err, $opts2) = run_ctrl(ctrl(kube => $k), $k, $cp);
    ok !$opts2, 'a control plane is never torn down by robocop';
    like $err, qr/only tears down workers/, 'and the finalizer on it is reported';
    is scalar($k->reqs('PUT')), 0, 'nothing is written';
};

subtest 'a failed teardown keeps the finalizer and waits for the resync' => sub {
    my $k = MockK8s::build(cr => deleted_node(), provider => provider_cr('hetzner'));
    my $c = ctrl(kube => $k);
    my ($out, $err, undef, $prov) = run_ctrl($c, $k, deleted_node(),
        fail => "Hetzner API: 503\n");

    is scalar @{ $prov->{deletes} }, 1, 'the delete was tried';
    is_deeply [ map { @$_ } finalizer_puts($k) ], [ ($F) x scalar finalizer_puts($k) ],
        'no write takes the finalizer off';
    is scalar($k->reqs('DELETE')), 0, 'nothing is deleted';
    my ($last) = reverse $k->status_writes;
    is $last->{phase}, 'Failed', 'the OCPNode is Failed ...';
    like $last->{message}, qr/503/, '... with the reason';
    like $err, qr/w1: teardown failed, retried every 60s: .*503/, 'logged on STDERR';

    # Its own status write comes back as an event at once: not a retry.
    my $again = deleted_node(status => { phase => 'Failed', lastReconcileTime => now_rfc3339() });
    my (undef, undef, $opts) = run_ctrl($c, $k, $again);
    ok !$opts, 'a teardown that failed just now is not retried by the event of that write';

    my $older = deleted_node(status => { phase => 'Failed',
        lastReconcileTime => Time::Piece::gmtime(time - 45)->strftime('%Y-%m-%dT%H:%M:%SZ') });
    my (undef, undef, $opts3) = run_ctrl($c, $k, $older);
    ok $opts3, 'the next resync pass retries it';
};

subtest 'the resync enqueues deleted OCPNodes whatever their phase' => sub {
    my $c = ctrl();
    my @queued;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::list_ocp_nodes = sub { [
        deleted_node(status => { phase => 'Failed' }),
        ocpnode(metadata => { name => 'ready' }),
    ] };
    local *OCP::Robocop::Controller::enqueue = sub { push @queued, $_[1]{metadata}{name} };
    $c->_resync;
    is_deeply \@queued, [ 'w1' ], 'the deleted one, not the Ready one';
};

subtest 'a missing provider blocks the teardown visibly, finalizer kept' => sub {
    my $k = MockK8s::build(cr => deleted_node(), provider => undef);
    my ($out, $err) = run_ctrl(ctrl(kube => $k), $k, deleted_node());
    my ($last) = reverse $k->status_writes;
    is $last->{phase}, 'Failed', 'Failed ...';
    like $last->{message}, qr{Teardown not started: cannot load OCPNodeProvider/p},
        '... saying why';
    like $err, qr/Teardown not started/, 'and on STDERR';
    is scalar($k->reqs('PUT')), 0, 'the finalizer is not touched';
};

# ---------------------------------------------------------------------------
# inject mode
# ---------------------------------------------------------------------------

sub key_condition {
    my ($k) = @_;
    my ($c) = map { grep { $_->{type} eq 'SSHKeyAvailable' } @{ $_->{conditions} // [] } }
              reverse $k->status_writes;
    return $c;
}

subtest 'inject without a key: an ssh node waits for it, finalizer kept' => sub {
    my $k = MockK8s::build(cr => deleted_node(), provider => provider_cr('ssh'));
    my $c = ctrl(kube => $k, security_level => 'inject', ssh_key => undef,
                 ready_file => '/nonexistent/ready');
    my (undef, undef, $opts) = run_ctrl($c, $k, deleted_node());
    ok !$opts, 'no teardown';
    my $cond = key_condition($k);
    is $cond->{status}, 'False', 'SSHKeyAvailable=False';
    is $cond->{reason}, 'KeyInjectionRequired', 'waiting for ocp inject-key';
    is scalar($k->reqs('PUT')), 0, 'the finalizer stays';
};

subtest 'inject without a key: a Hetzner node is deleted through the API anyway' => sub {
    my $k = MockK8s::build(cr => deleted_node(), provider => provider_cr('hetzner'));
    my $c = ctrl(kube => $k, security_level => 'inject', ssh_key => undef,
                 ready_file => '/nonexistent/ready');
    my (undef, undef, undef, $prov) = run_ctrl($c, $k, deleted_node());
    is scalar @{ $prov->{deletes} }, 1, 'the server is deleted';
    ok !key_condition($k), 'no key condition';
};

# ---------------------------------------------------------------------------
# CLI and robocop: the lease
# ---------------------------------------------------------------------------

subtest 'a teardown under someone else\'s live lease touches nothing' => sub {
    my $lease = 'cli@' . now_rfc3339() . '@300';
    my $cr = deleted_node(metadata => { annotations => { 'ocp.internal/reconciler-lease' => $lease } });
    my $k = MockK8s::build(cr => $cr, provider => provider_cr('hetzner'));
    my ($out, $err, undef, $prov) = run_ctrl(ctrl(kube => $k), $k, $cr);
    is scalar @{ $prov->{deletes} }, 0, 'no provider delete';
    is_deeply [ $k->status_writes ], [], 'no status write';
    is scalar($k->reqs('PUT')), 0, 'no write at all';
    like $out, qr/left to the reconciler holding the lease/, 'robocop says it steps back';
    is $err, '', 'which is not an error';
};

subtest 'ocp node rm (OCP::Node::teardown as cli) takes the finalizer off before its delete' => sub {
    my $cr = ocpnode(metadata => { finalizers => [ $F ] });
    my $k = MockK8s::build(cr => $cr);
    my $prov = FakeProvider->new;
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => $prov);
    is $node->teardown, 1, 'teardown succeeds';

    my @order = map { "$_->{method} $_->{path}" } @{ $k->requests };
    my ($first_put) = grep { $order[$_] =~ m{^PUT .*/ocpnodes/w1$} } 0 .. $#order;
    my ($term)      = grep { $order[$_] =~ m{^PATCH .*/status$} } 0 .. $#order;
    ok $first_put < $term, 'the lease is taken before anything is marked Terminating';
    my $lease = $JSON->decode($k->requests->[$first_put]{body})->{metadata}{annotations}
        {'ocp.internal/reconciler-lease'};
    like $lease, qr/^cli@/, 'held as cli';

    my @fin = finalizer_puts($k);
    is_deeply $fin[-1], [], 'finalizer removed';
    my $last_put = $JSON->decode(($k->reqs('PUT'))[-1]{body});
    ok !exists(($last_put->{metadata}{annotations} // {})->{'ocp.internal/reconciler-lease'}),
        'together with the lease';
    ok scalar($k->reqs('DELETE', qr{/ocpnodes/w1$})), 'then the OCPNode is deleted';
    is scalar @{ $prov->{deletes} }, 1, 'and the machine was cleaned';
};

subtest 'ocp node rm while robocop holds the lease refuses before touching anything' => sub {
    my $lease = 'robocop@' . now_rfc3339() . '@300';
    my $cr = deleted_node(metadata => { annotations => { 'ocp.internal/reconciler-lease' => $lease } });
    my $k = MockK8s::build(cr => $cr);
    my $prov = FakeProvider->new;
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => $prov);
    my $ok = eval { $node->teardown; 1 };
    my $err = $@;
    ok !$ok, 'teardown dies';
    like $err, qr/not started, nothing was touched: lease held by another reconciler: robocop@/,
        'naming the holder';
    is_deeply [ $k->status_writes ], [], 'no status write';
    is scalar @{ $prov->{deletes} }, 0, 'the machine is not touched';
};

done_testing;

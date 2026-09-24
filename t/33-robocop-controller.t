use strict;
use warnings;
use Test::More;
use File::Temp ();
use JSON::MaybeXS ();
use Path::Tiny ();

use lib 'lib';

#
# robocop's controller lane, tested the way t/16-node.t tests OCP::Node: a REAL
# Kubernetes::REST with a recording transport bolted underneath, never a
# hand-written stand-in and never a live cluster. See k33.
#
# The bug this file guards against had two halves. First, bin/robocop never read
# @ARGV: `robocop controller` fell through to OCP::Robocop->run, which blocks on
# the disabled port-9999 key-injection listener instead of constructing the
# controller. Second, even once constructed the controller polled in a
# while(1)+sleep loop rather than watching. This file pins the dispatch, the
# env-driven construction, and that a watch event reaches the existing
# _on_node_event / _mark_failed error-handling seam unchanged.
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

        my ($status, $struct) = $self->_respond($api, $req->method, $path);
        return MockResponse->new(
            status  => $status,
            content => $JSON->encode($struct),
        );
    }

    sub _respond {
        my ($self, $api, $method, $path) = @_;

        # The status subresource echoes its patch back, the way the API server
        # does. Strip the trailing /status so a read of the CR still matches.
        if ($method eq 'PATCH' && $path =~ m{/status$}) {
            my ($req) = grep { $_->{path} eq $path } reverse @{ $api->requests };
            return (200, JSON::MaybeXS::decode_json($req->{body}));
        }

        if ($path =~ m{/ocpnodes/([^/]+)$}) {
            my $cr = $api->cr;
            return $cr ? (200, $cr) : (404, { message => "ocpnodes \"$1\" not found" });
        }
        if ($path =~ m{/ocpnodeproviders/([^/]+)$}) {
            my $p = $api->provider_cr;
            return $p ? (200, $p) : (404, { message => "ocpnodeproviders \"$1\" not found" });
        }
        return (404, { message => "unexpected path $path" });
    }
}

package StrictK8s {
    use Moo;
    use OCP::K8s;
    extends 'Kubernetes::REST';
    # Kubernetes::REST 1.108 grew a `with` attribute, and its k8s builder reads
    # $self->with. `use Moo` installs Moo's own `with` keyword into this package,
    # shadowing the inherited accessor, so without this clean $self->with tries
    # to compose $self as a role and dies "is not a module name" (k132).
    use namespace::clean;

    has requests    => (is => 'ro', default => sub { [] });
    has cr          => (is => 'rw');
    has provider_cr => (is => 'rw');

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
}

package main;

use Future;
use OCP::Robocop::Controller;

# k159: robocop reconciles in a forked child, where this recording transport
# would never see the requests. Run the child's body in-process instead: the
# whole watch -> enqueue -> re-read -> _reconcile_cr path, minus the fork.
# The fork itself is t/92-robocop-async-reconcile.t's business.
{
    no warnings 'redefine';
    *OCP::Robocop::Controller::_spawn = sub {
        my ($self, $cr) = @_;
        $self->_reconcile_child($cr);
        return Future->done(0);
    };
}

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

# ---------------------------------------------------------------------------
# from_env: env-driven construction (the values bin/robocop feeds the controller)
# ---------------------------------------------------------------------------

subtest 'from_env builds the controller from the environment' => sub {
    local %ENV = %ENV;
    $ENV{ROBO_SSH_KEY}    = "PRIVATE-KEY\n";
    $ENV{RKE2_SERVER_URL} = 'https://police1:9345';
    $ENV{RKE2_TOKEN}      = 'JOIN-TOKEN';
    $ENV{NAMESPACE}       = 'ocp-custom';
    $ENV{OCP_DISTRIBUTION} = 'k3s';
    $ENV{OCP_POD_CIDR}     = '10.44.0.0/16';

    my $ctrl = OCP::Robocop::Controller->from_env;

    isa_ok $ctrl, 'OCP::Robocop::Controller';
    is $ctrl->ssh_key,      "PRIVATE-KEY\n",        'ssh_key from ROBO_SSH_KEY';
    is $ctrl->server_url,   'https://police1:9345', 'server_url from RKE2_SERVER_URL';
    is $ctrl->join_token,   'JOIN-TOKEN',           'join_token from RKE2_TOKEN';
    is $ctrl->namespace,    'ocp-custom',           'namespace from NAMESPACE';
    is $ctrl->distribution, 'k3s',                  'distribution from OCP_DISTRIBUTION';
    is $ctrl->pod_cidr,     '10.44.0.0/16',         'pod_cidr from OCP_POD_CIDR';
};

subtest 'from_env defaults namespace when unset -- and nothing else' => sub {
    # distribution used to default to rke2 here, which is how robocop came to
    # join RKE2 agents to a k3s cluster (k186). t/186 pins that it is required.
    local %ENV = %ENV;
    $ENV{ROBO_SSH_KEY}     = 'K';
    $ENV{RKE2_SERVER_URL}  = 'U';
    $ENV{RKE2_TOKEN}       = 'T';
    $ENV{OCP_DISTRIBUTION} = 'rke2';
    $ENV{OCP_POD_CIDR}     = '10.42.0.0/16';
    delete $ENV{NAMESPACE};

    my $ctrl = OCP::Robocop::Controller->from_env;
    is $ctrl->namespace, 'ocp-system', 'namespace default kept';
};

subtest 'from_env dies naming every missing required variable' => sub {
    for my $var (qw(ROBO_SSH_KEY RKE2_SERVER_URL RKE2_TOKEN)) {
        local %ENV = %ENV;
        $ENV{ROBO_SSH_KEY}    = 'K';
        $ENV{RKE2_SERVER_URL} = 'U';
        $ENV{RKE2_TOKEN}      = 'T';
        $ENV{OCP_DISTRIBUTION} = 'rke2';
        $ENV{OCP_POD_CIDR}     = '10.42.0.0/16';
        delete $ENV{$var};

        my $err = do { local $@; eval { OCP::Robocop::Controller->from_env }; $@ };
        like $err, qr/\Q$var\E/, "missing $var is named in the error";
        like $err, qr/required/i, "and it says the variable is required ($var)";
    }
};

# ---------------------------------------------------------------------------
# The watch path: an event object reaches the existing _on_node_event seam
# ---------------------------------------------------------------------------

subtest 'a watch event with no providerRef is marked Failed via the status subresource' => sub {
    my $k = StrictK8s::build(cr => ocpnode(
        metadata => { name => 'w1', namespace => 'ocp-system', resourceVersion => '1' },
        spec     => { role => 'worker' },   # no providerRef
    ));
    my $ctrl = OCP::Robocop::Controller->new(
        kube => $k, ssh_key => 'K', server_url => 'U', join_token => 'T',
        distribution => 'rke2', pod_cidr => '10.42.0.0/16');

    # The inflated IO::K8s object is exactly what the watcher hands its callbacks.
    my $obj = $k->get('OCPNode', name => 'w1', namespace => 'ocp-system');
    $ctrl->_handle_watch_object($obj);

    my ($status_patch) = grep { $_->{path} =~ m{/status$} } $k->reqs('PATCH');
    ok $status_patch, 'the event reached _mark_failed and patched status';
    is $status_patch->{path},
        '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/w1/status',
        'the write addresses the /status subresource, not the main endpoint';
    my ($sent) = $k->status_patches;
    is $sent->{phase}, 'Failed', 'phase Failed';
    like $sent->{message}, qr/providerRef/, 'and the message says what is missing';
    is $sent->{reconciler}, 'robocop', 'marked by the robocop reconciler';
};

subtest 'a watch event whose provider cannot be loaded reaches _on_node_event' => sub {
    # providerRef is set but no OCPNodeProvider is stored: this drives past the
    # first guard, into _on_node_event's provider load, proving the real event
    # path runs -- not just the missing-field short-circuit.
    my $k = StrictK8s::build(
        cr          => ocpnode(metadata =>
            { name => 'w2', namespace => 'ocp-system', resourceVersion => '1' }),
        provider_cr => undef,   # 404 on GET OCPNodeProvider
    );
    my $ctrl = OCP::Robocop::Controller->new(
        kube => $k, ssh_key => 'K', server_url => 'U', join_token => 'T',
        distribution => 'rke2', pod_cidr => '10.42.0.0/16');

    my $obj = $k->get('OCPNode', name => 'w2', namespace => 'ocp-system');
    $ctrl->_handle_watch_object($obj);

    ok scalar($k->reqs('GET') > 0), 'the provider was looked up';
    my ($sent) = $k->status_patches;
    is $sent->{phase}, 'Failed', 'phase Failed';
    like $sent->{message}, qr/OCPNodeProvider/,
        'the message names the provider that could not be loaded';
};

subtest 'k186/k184: the controller hands its distribution and pod CIDR to OCP::Node' => sub {
    my $k = StrictK8s::build(
        cr          => ocpnode(metadata =>
            { name => 'w3', namespace => 'ocp-system', resourceVersion => '1' }),
        provider_cr => {
            apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
            metadata   => { name => 'hetzner-a', namespace => 'ocp-system' },
            spec       => { type => 'ssh' },
        },
    );
    my $ctrl = OCP::Robocop::Controller->new(
        kube => $k, ssh_key => 'K', server_url => 'U', join_token => 'T',
        distribution => 'k3s', pod_cidr => '10.44.0.0/16');

    my %got;
    {
        no warnings 'redefine';
        local *OCP::Provider::from_cr = sub { bless {}, 'FakeProviderObj' };
        local *OCP::Node::from_cr = sub {
            my ($class, $cr, %args) = @_;
            %got = %args;
            die "stop here\n";
        };
        my $obj = $k->get('OCPNode', name => 'w3', namespace => 'ocp-system');
        $ctrl->_handle_watch_object($obj);
    }

    is $got{distribution}, 'k3s',          'distribution reaches OCP::Node';
    is $got{pod_cidr},     '10.44.0.0/16', 'pod_cidr reaches OCP::Node';
};

# ---------------------------------------------------------------------------
# bin/robocop dispatch: `controller` reaches the controller, not the stub
# ---------------------------------------------------------------------------

sub run_robocop {
    my ($argv, %env) = @_;

    my $out = File::Temp->new;
    my $err = File::Temp->new;

    my $pid = fork;
    defined $pid or die "fork: $!";
    if ($pid == 0) {
        delete @ENV{qw(RKE2_SERVER_URL RKE2_TOKEN ROBO_SSH_KEY
                       NAMESPACE OCP_DISTRIBUTION OCP_POD_CIDR CHECKPOINT_DIR)};
        $ENV{$_} = $env{$_} for keys %env;
        open STDOUT, '>', $out->filename or die "reopen stdout: $!";
        open STDERR, '>', $err->filename or die "reopen stderr: $!";
        exec $^X, '-Ilib', 'bin/robocop', @$argv;
        exit 127;
    }

    my $timed_out = 0;
    eval {
        local $SIG{ALRM} = sub { kill 'KILL', $pid; die "timeout\n" };
        alarm 30;
        waitpid $pid, 0;
        alarm 0;
        1;
    } or do {
        $timed_out = ($@ eq "timeout\n");
        waitpid $pid, 0;
    };

    return {
        timed_out => $timed_out,
        stdout    => Path::Tiny::path($out->filename)->slurp,
        stderr    => Path::Tiny::path($err->filename)->slurp,
    };
}

subtest 'bin/robocop controller reads argv and dies on missing env (STDERR)' => sub {
    # The regression itself: on the old bin/robocop, `controller` was ignored,
    # OCP::Robocop->run started the port-9999 stub, and this blocked (timed_out).
    my $r = run_robocop(['controller']);

    ok !$r->{timed_out},
        'the controller path returned instead of blocking on the key-injection stub';
    like $r->{stderr}, qr/RKE2_SERVER_URL/,
        'the missing required env var is named on STDERR (diagnosis to STDERR)';
    unlike $r->{stdout}, qr/key injection/i,
        'the port-9999 key-injection stub was never entered';
};

done_testing;

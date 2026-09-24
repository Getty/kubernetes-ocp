#!/usr/bin/env perl
# karr k2 -- the controller side of robocop.security_level: inject.
#
# In inject mode robocop starts with NO key: the admin injects it at runtime
# (`ocp inject-key`), and a pod restart loses it again. Until a key is held the
# controller must neither provision nor pretend: OCPNodes that would need SSH
# are held and carry a visible SSHKeyAvailable=False condition, the ready file
# the readiness probe checks is absent, and nothing reaches OCP::Node. Once the
# key arrives the condition flips and every OCPNode is reconciled again.
#
# Same harness as t/33-robocop-controller.t: a REAL Kubernetes::REST with a
# recording transport, never a live cluster.

use strict;
use warnings;
use Test::More;
use IO::Async::Loop;
use IPC::Run ();
use JSON::MaybeXS ();
use Path::Tiny ();

use lib 'lib';

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
            method => $req->method, path => $path, body => $req->content,
        };
        my ($status, $struct) = $self->_respond($api, $req->method, $path);
        return MockResponse->new(status => $status, content => $JSON->encode($struct));
    }

    sub _respond {
        my ($self, $api, $method, $path) = @_;
        if ($method eq 'PATCH' && $path =~ m{/status$}) {
            my ($req) = grep { $_->{path} eq $path } reverse @{ $api->requests };
            return (200, JSON::MaybeXS::decode_json($req->{body}));
        }
        if ($path =~ m{/ocpnodes$}) {
            return (200, { apiVersion => 'ocp.internal/v1', kind => 'OCPNodeList',
                           metadata => {}, items => [ grep { $_ } $api->cr ] });
        }
        if ($path =~ m{/ocpnodes/([^/]+)$}) {
            my $cr = $api->cr;
            return $cr ? (200, $cr) : (404, { message => "ocpnodes \"$1\" not found" });
        }
        if ($path =~ m{/ocpnodeproviders/([^/]+)$}) {
            return (404, { message => "ocpnodeproviders \"$1\" not found" });
        }
        return (404, { message => "unexpected path $path" });
    }
}

package StrictK8s {
    use Moo;
    use OCP::K8s;
    extends 'Kubernetes::REST';
    use namespace::clean;   # see t/33 (k132)

    has requests => (is => 'ro', default => sub { [] });
    has cr       => (is => 'rw');

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

# Records start() instead of binding a socket.
package FakeInjection {
    sub new   { my ($c, %a) = @_; bless { started => 0, %a }, $c }
    sub start { $_[0]{started}++; $_[0]{loop} = $_[1]; Future->done }
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

my $ROBO_PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKPHUsASqmtfbkGGiow5Nhq0uJZMVSnnJndB5FUUREQs fixture-robo';

sub ocpnode {
    my (%over) = @_;
    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => 'worker-1', namespace => 'ocp-system', resourceVersion => '1' },
        spec       => { role => 'worker', providerRef => 'hetzner-a' },
        status     => { phase => 'Pending' },
        %over,
    };
}

my @KEEP;   # tempdirs live as long as the test
sub inject_ctrl {
    my ($k, %over) = @_;
    my $dir = Path::Tiny->tempdir;
    push @KEEP, $dir;
    return OCP::Robocop::Controller->new(
        kube                => $k,
        security_level      => 'inject',
        expected_public_key => $ROBO_PUB,
        server_url          => 'U',
        join_token          => 'T',
        distribution        => 'rke2',
        pod_cidr            => '10.42.0.0/16',
        ready_file          => $dir->child('robocop-key-ready')->stringify,
        %over,
    );
}

sub key_condition {
    my ($status) = @_;
    my ($c) = grep { $_->{type} eq 'SSHKeyAvailable' } @{ $status->{conditions} // [] };
    return $c;
}

# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

subtest 'from_env in inject mode needs no private key, but the public one' => sub {
    local %ENV = %ENV;
    delete $ENV{ROBO_SSH_KEY};
    $ENV{ROBOCOP_SECURITY_LEVEL} = 'inject';
    $ENV{ROBO_SSH_PUBLIC_KEY}    = $ROBO_PUB;
    $ENV{RKE2_SERVER_URL}        = 'https://police1:9345';
    $ENV{RKE2_TOKEN}             = 'T';
    $ENV{OCP_DISTRIBUTION}       = 'rke2';
    $ENV{OCP_POD_CIDR}           = '10.42.0.0/16';

    my $ctrl = OCP::Robocop::Controller->from_env;
    is $ctrl->security_level, 'inject', 'security_level from ROBOCOP_SECURITY_LEVEL';
    ok !defined $ctrl->ssh_key, 'starts without a key';
    is $ctrl->expected_public_key, $ROBO_PUB, 'expected public key from ROBO_SSH_PUBLIC_KEY';

    delete $ENV{ROBO_SSH_PUBLIC_KEY};
    my $err = do { local $@; eval { OCP::Robocop::Controller->from_env }; $@ };
    like $err, qr/ROBO_SSH_PUBLIC_KEY/, 'without the public key it refuses, naming it';

    $ENV{ROBO_SSH_PUBLIC_KEY} = $ROBO_PUB;
    $ENV{ROBO_SSH_KEY}        = 'PRIVATE';
    $err = do { local $@; eval { OCP::Robocop::Controller->from_env }; $@ };
    like $err, qr/ROBO_SSH_KEY.*inject|inject.*ROBO_SSH_KEY/s,
        'a private key in the environment contradicts inject and is refused';
};

subtest 'outside inject mode the key is still required' => sub {
    my $err = do { local $@; eval {
        OCP::Robocop::Controller->new(kube => StrictK8s::build(), server_url => 'U', join_token => 'T',
            distribution => 'rke2', pod_cidr => '10.42.0.0/16');
    }; $@ };
    like $err, qr/ssh_key/, 'secret mode without ssh_key dies';
};

# ---------------------------------------------------------------------------
# No key: hold, make it visible, never provision
# ---------------------------------------------------------------------------

subtest 'no key: a Pending node is held with SSHKeyAvailable=False, not provisioned' => sub {
    my $k = StrictK8s::build(cr => ocpnode());
    my $ctrl = inject_ctrl($k);

    $ctrl->_handle_watch_object($k->get('OCPNode', name => 'worker-1', namespace => 'ocp-system'));

    is scalar($k->provider_gets), 0,
        'the provider was never even loaded -- nothing towards provisioning';
    my @patches = $k->status_patches;
    is scalar @patches, 1, 'one status write';
    my $st = $patches[0];
    ok !exists $st->{phase}, 'the phase is left alone (not Failed, not advanced)';
    my $c = key_condition($st);
    ok $c, 'an SSHKeyAvailable condition is written';
    is $c->{status}, 'False',                'status False';
    is $c->{reason}, 'KeyInjectionRequired', 'reason KeyInjectionRequired';
    like $c->{message}, qr/ocp inject-key/,  'the message says what to run';
    like $st->{message}, qr/ocp inject-key/, 'and so does status.message';
    is $st->{reconciler}, 'robocop', 'written by robocop';
};

subtest 'no key: an already-held node is not patched again (no event loop)' => sub {
    my $held = ocpnode(status => {
        phase      => 'Pending',
        conditions => [ { type => 'SSHKeyAvailable', status => 'False',
                          reason => 'KeyInjectionRequired' } ],
    });
    my $k = StrictK8s::build(cr => $held);
    my $ctrl = inject_ctrl($k);

    $ctrl->_handle_watch_object($k->get('OCPNode', name => 'worker-1', namespace => 'ocp-system'));

    is scalar($k->status_patches), 0, 'no second write for the same state';
    is scalar($k->provider_gets),  0, 'and still no provisioning';
};

subtest 'no key: a node that needs no SSH is reconciled as usual' => sub {
    my $k = StrictK8s::build(cr => ocpnode(status => { phase => 'Ready' }));
    my $ctrl = inject_ctrl($k);

    $ctrl->_handle_watch_object($k->get('OCPNode', name => 'worker-1', namespace => 'ocp-system'));

    ok scalar($k->provider_gets), 'a Ready node goes on to the normal path';
    ok !grep({ key_condition($_) } $k->status_patches),
        'and is not marked as waiting for a key';
};

# ---------------------------------------------------------------------------
# The key arrives
# ---------------------------------------------------------------------------

subtest 'accept_key: held in memory, ready file written, every node reconciled again' => sub {
    my $k = StrictK8s::build(cr => ocpnode());
    my $loop = IO::Async::Loop->new;
    my $ctrl = inject_ctrl($k, loop => $loop);

    ok !-e $ctrl->ready_file, 'no ready file before a key';

    my @reconciled;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::_reconcile_cr = sub { push @reconciled, $_[1]{metadata}{name} };

    $ctrl->accept_key("KEY-MATERIAL\n", 'SHA256:abc');

    is $ctrl->ssh_key, "KEY-MATERIAL\n", 'the key is held';
    ok -e $ctrl->ready_file, 'the ready file exists (readiness probe passes)';
    unlike Path::Tiny::path($ctrl->ready_file)->slurp, qr/KEY-MATERIAL/,
        'and it carries no key material';
    is scalar @reconciled, 0, 'reconcile is deferred -- the injector gets its ack first';

    $loop->loop_once(0) for 1 .. 3;
    is_deeply \@reconciled, ['worker-1'], 'then every OCPNode is reconciled again';
};

subtest 'with a key: the waiting condition flips to True and provisioning proceeds' => sub {
    my $held = ocpnode(status => {
        phase      => 'Pending',
        conditions => [ { type => 'SSHKeyAvailable', status => 'False',
                          reason => 'KeyInjectionRequired' } ],
    });
    my $k = StrictK8s::build(cr => $held);
    my $ctrl = inject_ctrl($k);
    $ctrl->accept_key("KEY\n", 'SHA256:abc');

    $ctrl->_handle_watch_object($k->get('OCPNode', name => 'worker-1', namespace => 'ocp-system'));

    my ($first) = $k->status_patches;
    my $c = key_condition($first);
    ok $c, 'the condition is rewritten';
    is $c->{status}, 'True',        'to True';
    is $c->{reason}, 'KeyInjected', 'reason KeyInjected';
    ok scalar($k->provider_gets), 'and the node goes on towards provisioning';
};

subtest 'run() in inject mode starts the injection listener and clears a stale ready file' => sub {
    my $k    = StrictK8s::build();
    my $loop = IO::Async::Loop->new;
    my $fake = FakeInjection->new;
    my $ctrl = inject_ctrl($k, loop => $loop, key_injection => $fake);

    Path::Tiny::path($ctrl->ready_file)->spew('stale');
    $ctrl->_start_key_injection;

    is $fake->{started}, 1, 'the listener was started';
    is $fake->{loop}, $loop, 'on the controller loop';
    ok !-e $ctrl->ready_file,
        'a ready file left over from before a container restart is removed';
};

# ---------------------------------------------------------------------------
# bin/robocop: the CRIU / port-9999 stub is gone
# ---------------------------------------------------------------------------

subtest 'bin/robocop without a subcommand explains itself instead of blocking' => sub {
    my ($out, $err) = ('', '');
    my $ok = eval {
        IPC::Run::run([ $^X, '-Ilib', 'bin/robocop' ], \undef, \$out, \$err,
            IPC::Run::timeout(30));
        1;
    };
    ok defined $ok || $@ !~ /timeout/, 'returned instead of waiting on a listener';
    isnt $? >> 8, 0, 'non-zero exit';
    like $err, qr/robocop controller/, 'usage on STDERR names the controller subcommand';
    unlike $out . $err, qr/CRIU|criu/, 'no CRIU';
};

done_testing;

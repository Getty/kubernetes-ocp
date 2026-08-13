#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::K8s;
use OCP::Node;
use OCP::Cmd::Apply;
use OCP::Cmd::Node::Ls;

#
# The OCPNode CRD declares `subresources: {status: {}}`. Once a CRD does that,
# the Kubernetes API server SILENTLY DISCARDS the status stanza of
# every write aimed at the main resource endpoint — create, update, merge-patch
# and server-side apply alike — and still answers 2xx.
#
# OCP wrote status that way everywhere: _ensure_cp_ocpnode passed it inside the
# ensure() payload, _migrate_legacy_nodes did the same, and OCP::Node
# _patch_status merge-patched the main endpoint. All of them looked like they
# worked. On a live single-node cluster the result was three views disagreeing
# about the same node:
#
#   ocp apply  ->  [ok] ensured OCPNode/cortex (control-plane, Ready)
#   ocp status ->  cortex   Ready   control-plane   v1.36.3+k3s1   10.230.30.155
#   ocp node ls->  cortex   control-plane   Pending   ssh-default   <no ip>
#
# `ocp node ls` was the honest one: the stored CR really had no status at all.
# Status only lands through the separate /status endpoint.
#

sub capture_stdout (&) {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die "open stdout capture: $!";
    local *STDOUT = $fh;
    $code->();
    return $out;
}

package FakeResponse {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}

# An api that offers only the raw transport, so OCP::K8s::patch_status has to
# take the _request escape and build the /status path itself.
package RawApi {
    sub new { my ($c, %a) = @_; bless { calls => [], %a }, $c }
    sub expand_class { "+OCP::K8s::$_[1]" }
    sub _build_path {
        my ($self, $class, %args) = @_;
        return "/apis/ocp.internal/v1/namespaces/$args{namespace}/ocpnodes/$args{name}";
    }
    sub _request {
        my ($self, $method, $path, $body, %opts) = @_;
        push @{$self->{calls}}, [$method, $path, $body, \%opts];
        return FakeResponse->new(
            status  => $self->{status}  // 200,
            content => $self->{content} // '{}',
        );
    }
    sub _check_response {
        my ($self, $response, $context) = @_;
        die "Kubernetes API error ($context): " . $response->status . "\n"
            if $response->status >= 400;
        return $response;
    }
}

# Reader side: the `ocp node ls` view of whatever the CR ends up holding.
package LsIO   { sub object_to_struct { $_[1] } }
package LsList {
    sub new   { my ($c, $i) = @_; bless { items => $i }, $c }
    sub items { $_[0]{items} }
}
package LsApi {
    my $io = bless {}, 'LsIO';
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s  { $io }
    sub list { LsList->new($_[0]{nodes}) }
}

package main;

subtest 'patch_status writes the /status subresource, not the main endpoint' => sub {
    my $api = RawApi->new;
    OCP::K8s->patch_status($api,
        kind      => 'OCPNode',
        name      => 'cortex',
        namespace => 'ocp-system',
        status    => { phase => 'Ready', publicIP => '10.230.30.155' },
    );

    is scalar @{$api->{calls}}, 1, 'one request issued';
    my ($method, $path, $body, $opts) = @{$api->{calls}[0]};

    is $method, 'PATCH', 'PATCH verb';
    like $path, qr{/ocpnodes/cortex/status$},
        'path addresses the /status subresource';
    unlike $path, qr{/ocpnodes/cortex$},
        'not the main resource endpoint, where status would be dropped';
    is $opts->{content_type}, 'application/merge-patch+json',
        'merge-patch content type';
    is $body->{status}{phase}, 'Ready', 'phase in the body';
    is $body->{status}{publicIP}, '10.230.30.155', 'IP in the body';
};

subtest 'patch_status does not swallow an API error' => sub {
    for my $status (403, 404, 409, 500) {
        my $api = RawApi->new(status => $status);
        my $ok = eval {
            OCP::K8s->patch_status($api,
                kind => 'OCPNode', name => 'cortex',
                namespace => 'ocp-system', status => { phase => 'Ready' });
            1;
        };
        ok !$ok, "HTTP $status makes the status write fail";
        like $@, qr/\b$status\b/, "HTTP $status appears in the message";
    }
};

subtest 'patch_status prefers a native writer when the client grows one' => sub {
    # Kubernetes::REST has no status-subresource method today; the raw escape
    # retires itself the moment it does.
    my @seen;
    my $api = bless {}, 'NativeApi';
    {
        no strict 'refs';
        no warnings 'once';
        *NativeApi::patch_status = sub { my ($s, %a) = @_; push @seen, \%a; 1 };
        *NativeApi::_request = sub { die "must not reach the raw transport\n" };
    }
    OCP::K8s->patch_status($api,
        kind => 'OCPNode', name => 'w1',
        namespace => 'ocp-system', status => { phase => 'Ready' });

    is scalar @seen, 1, 'native writer used';
    is $seen[0]{status}{phase}, 'Ready', 'status handed through unchanged';
};

#
# Apply's control-plane CR: spec via ensure, status via /status.
#

package ApplyApi {
    sub new { my ($c, %a) = @_; bless { ensured => [], statuses => [], %a }, $c }
    sub ensure {
        my ($self, $doc) = @_;
        push @{$self->{ensured}}, $doc;
        return $doc;
    }
    sub patch_status {
        my ($self, %a) = @_;
        push @{$self->{statuses}}, \%a;
        return 1;
    }
    sub get {
        my ($self, $kind, $name) = @_;
        return $kind eq 'Node' ? $self->{node} : undef;
    }
}

package main;

subtest 'apply gives the control plane a real phase and IP' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my $api = ApplyApi->new(
        node => {
            metadata => { name => 'cortex' },
            status   => { addresses => [
                { type => 'InternalIP', address => '10.230.30.155' },
            ] },
        },
    );

    my $out = capture_stdout {
        $apply->_ensure_cp_ocpnode($api, {
            name     => 'cortex',
            provider => 'ssh',
            host     => 'cortex.ai.citilan.de',
        });
    };

    my ($cr) = @{$api->{ensured}};
    ok $cr, 'OCPNode CR ensured';
    is $cr->{spec}{role}, 'control-plane', 'role written to spec';
    ok !exists $cr->{status},
        'ensure payload carries no status — the API server would drop it';

    my ($status) = @{$api->{statuses}};
    ok $status, 'status written separately';
    is $status->{kind}, 'OCPNode', 'targets OCPNode';
    is $status->{name}, 'cortex', 'targets the CP node';
    is $status->{namespace}, 'ocp-system', 'in ocp-system';
    is $status->{status}{phase}, 'Ready', 'phase=Ready — never Pending';
    is $status->{status}{reconciler}, 'cli',
        'stamped reconciler=cli: apply owns the CP it bootstrapped';
    is $status->{status}{publicIP}, '10.230.30.155',
        'IP taken from the Node object, not the configured DNS host';

    like $out, qr/\[ok\] ensured OCPNode\/cortex/, 'reports success';
};

subtest 'apply does not claim Ready when the status write fails' => sub {
    # The old code printed "(control-plane, Ready)" unconditionally, which is
    # how a CR with no status still produced a confident success line.
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my $api = ApplyApi->new;
    {
        no strict 'refs';
        no warnings 'redefine';
        local *ApplyApi::patch_status = sub { die "403 Forbidden\n" };
        my $out = capture_stdout {
            $apply->_ensure_cp_ocpnode($api, { name => 'cortex', provider => 'ssh' });
        };
        like $out, qr/WARN/, 'warns instead of claiming Ready';
        unlike $out, qr/\[ok\].*Ready/, 'no success line for an unwritten status';
    }
};

subtest 'the three views agree: apply, the CR, and node ls' => sub {
    # End-to-end shape of the reported bug: take exactly what apply now sends,
    # assemble the CR the API server would store, and render it through
    # `ocp node ls`. Pending or a blank IP here means the bug is back.
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my $api = ApplyApi->new(
        node => {
            metadata => { name => 'cortex' },
            status   => { addresses => [
                { type => 'InternalIP', address => '10.230.30.155' },
            ] },
        },
    );
    capture_stdout {
        $apply->_ensure_cp_ocpnode($api, {
            name => 'cortex', provider => 'ssh', host => 'cortex.ai.citilan.de',
        });
    };

    my $stored = {
        metadata => {
            name              => 'cortex',
            creationTimestamp => '2026-08-12T14:04:17Z',
        },
        spec   => $api->{ensured}[0]{spec},
        status => $api->{statuses}[0]{status},
    };

    my $ls = OCP::Cmd::Node::Ls->new(k8s => LsApi->new(nodes => [$stored]));
    my $out = capture_stdout { $ls->execute([], []) };

    like $out, qr/cortex\s+control-plane\s+Ready\s+ssh-default\s+10\.230\.30\.155/,
        'node ls shows Ready with the IP';
    unlike $out, qr/Pending/, 'no Pending row';
};

#
# OCP::Node phase transitions must persist, or every reader outside the running
# process (ocp node ls, the Apply poll loop, a restarted robocop) sees Pending
# forever.
#

package NodeApi {
    sub new { my ($c, %a) = @_; bless { calls => [], %a }, $c }
    sub patch_status {
        my ($self, %a) = @_;
        push @{$self->{calls}}, ['patch_status', \%a];
        return 1;
    }
    sub patch {
        my ($self, @a) = @_;
        push @{$self->{calls}}, ['patch', \@a];
        return {};
    }
}

package main;

subtest 'OCP::Node routes phase transitions to /status' => sub {
    my $cr = {
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'p' },
        status   => { phase => 'Pending' },
    };
    my $api  = NodeApi->new;
    my $node = OCP::Node->from_cr($cr, k8s => $api);

    $node->_patch_status(phase => 'Installing', message => 'server created');

    my @status_calls = grep { $_->[0] eq 'patch_status' } @{$api->{calls}};
    is scalar @status_calls, 1, 'one status write';
    is $status_calls[0][1]{kind}, 'OCPNode', 'typed Kind, no path => form';
    is $status_calls[0][1]{name}, 'w1', 'targets the node';
    is $status_calls[0][1]{status}{phase}, 'Installing', 'phase carried';

    my @main_patches = grep { $_->[0] eq 'patch' } @{$api->{calls}};
    is scalar @main_patches, 0,
        'nothing sent to the main endpoint, where status would be dropped';

    is $node->phase, 'Installing', 'in-memory CR advanced too';
};

done_testing;

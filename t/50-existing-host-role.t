#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# Pure role test for OCP::Role::Provider::ExistingHost.
#
# The role is the seam every host-based provider is supposed to consume.
# Exercising it through a stand-in adapter means we test the seam itself
# (default no-ops, hash shape, host plumbing) without paying for a real
# SSH connection or shelling out to uninstall scripts.

use OCP::Role::Provider::ExistingHost;

# `requires` must reject a class that omits one of the required methods.
{
    eval {
        package MissingRequire;
        use Moo;
        with 'OCP::Role::Provider::ExistingHost';
        # resolve_host, host_reachable, run_command deliberately absent.
    };
    like $@, qr/resolve_host|host_reachable|run_command/,
        'composition fails when a required method is missing';
}

# Stand-in host adapter: tracks commands, lets us toggle reachability.
package FakeHostAdapter {
    use Moo;
    with 'OCP::Role::Provider::ExistingHost';

    has commands  => (is => 'ro', default => sub { [] });
    has reachable => (is => 'rw', default => 1);
    has fixed_host => (is => 'ro');   # when set, resolve_host ignores %opts
    has result     => (is => 'ro', default => sub { { stdout => '', stderr => '', exit => 0 } });

    sub resolve_host {
        my ($self, %opts) = @_;
        return $self->fixed_host if $self->fixed_host;
        my $host = $opts{host};
        $host = $opts{spec}{host}
            if (!defined $host || !length $host) && ref $opts{spec} eq 'HASH';
        die "host required\n" unless defined $host && length $host;
        return $host;
    }
    sub host_reachable { $_[0]->reachable }
    sub run_command {
        my ($self, $host, $command) = @_;
        push @{ $self->commands }, [$host, $command];
        return $self->result;
    }
}

package main;

#
# No-op defaults: the four methods that have nothing to do for a host OCP
# does not control.
#

subtest 'upload_ssh_key, cleanup_on_failure, list_servers_by_cluster are no-ops' => sub {
    my $p = FakeHostAdapter->new;

    is $p->upload_ssh_key('k', 'pk'), undef,
        'upload_ssh_key returns nothing';
    is $p->cleanup_on_failure('server-id'), undef,
        'cleanup_on_failure returns nothing';
    is_deeply $p->list_servers_by_cluster('any-cluster'), [],
        'list_servers_by_cluster returns []';
};

#
# server_exists: reachable host returns { ip => $host }; unreachable does not
#

subtest 'server_exists reflects reachability' => sub {
    my $up = FakeHostAdapter->new;
    is_deeply $up->server_exists('w1', host => '10.0.0.5'),
        { ip => '10.0.0.5' },
        'reachable host reports its IP';

    my $down = FakeHostAdapter->new(reachable => 0);
    is $down->server_exists('w1', host => '10.0.0.5'), undef,
        'unreachable host reports missing';

    # resolve_host that dies is not an exception the caller has to handle
    # — server_exists swallows it (the role decides what to do with a
    # unresolvable host: pretend nothing is there).
    my $broken = FakeHostAdapter->new;   # no fixed_host, no host passed
    is $broken->server_exists('w1'), undef,
        'unresolvable host reports missing';
};

#
# create_server returns a hash with the keys callers read
#

subtest 'create_server returns the documented hash shape' => sub {
    my $p = FakeHostAdapter->new;

    my $info = $p->create_server(host => '10.0.0.5', name => 'w1');
    is $info->{ip},            '10.0.0.5', 'ip from resolve_host';
    is $info->{id},            undef,      'id is undef (host has no provider id)';
    ok !$info->{newly_created},            'newly_created is false';
};

#
# wait_for_running is a passthrough
#

subtest 'wait_for_running is a passthrough' => sub {
    my $p = FakeHostAdapter->new;
    my $info = { ip => '10.0.0.5', id => undef, newly_created => 0 };
    is $p->wait_for_running($info), $info,
        'returns the same hashref unchanged';
};

#
# delete_server: host-based providers remove what they installed, not the
# machine itself. The uninstall command runs on the resolved host.
#

subtest 'delete_server runs uninstall on the host, not the machine' => sub {
    my $p = FakeHostAdapter->new;
    $p->delete_server(undef, host => '10.0.0.5');

    is scalar @{ $p->commands }, 1, 'one command issued';
    is $p->commands->[0][0], '10.0.0.5', 'on the resolved host';
    # What the line does -- every uninstaller of both distributions and both
    # roles (we do not know which is there), the leftovers, Cilium's datapath
    # and ip rules (k147), its own outcome check -- is Rex::Rancher's
    # (rex-rancher k71, held in its t/uninstall.t); what it does on a host is
    # held in t/29-destroy-cleanup.t and t/190-cilium-leftovers.t.
    is $p->commands->[0][1], Rex::Rancher::Uninstall->uninstall_cmd,
        'the command is Rex::Rancher::Uninstall\'s uninstall line';
};

subtest 'delete_server without a host does nothing' => sub {
    my $p = FakeHostAdapter->new(fixed_host => '');
    $p->delete_server(undef);   # resolve_host dies -> swallowed -> no-op
    is scalar @{ $p->commands }, 0,
        'no command issued when the host cannot be resolved';
};

#
# k175: `ocp node rm` on an ssh worker reported success while rke2-agent kept
# running. OCP::SSH::run reports a refused login as exit 255, not as an
# exception, and delete_server handed that result back to a caller
# (OCP::Node::teardown) that only looked for exceptions. An uninstall that
# did not complete is now an exception, with ssh's own words in it -- the one
# failure shape every caller already handles.
#

subtest 'delete_server dies when the uninstall does not complete' => sub {
    my $p = FakeHostAdapter->new(result => {
        stdout => '',
        stderr => "root\@10.0.0.5: Permission denied (publickey).\n",
        exit   => 255,
    });
    my $ok = eval { $p->delete_server(undef, host => '10.0.0.5'); 1 };
    my $err = $@;
    ok !$ok, 'a non-zero exit is an exception, not a return value';
    like $err, qr/10\.0\.0\.5/,           'naming the host';
    like $err, qr/\bexit 255\b/,          'the exit status';
    like $err, qr/Permission denied/,     "and the remote side's diagnosis";
};

subtest 'delete_server returns the result when the uninstall completes' => sub {
    my $p = FakeHostAdapter->new;
    my $res = $p->delete_server(undef, host => '10.0.0.5');
    is $res->{exit}, 0, 'the run_command result is handed back';
};

#
# verbose attribute is rw-readable and has a default
#

subtest 'verbose attribute has the documented default' => sub {
    my $p = FakeHostAdapter->new;
    is $p->verbose, 0, 'verbose defaults to 0';

    my $loud = FakeHostAdapter->new(verbose => 1);
    is $loud->verbose, 1, 'verbose accepted from the constructor';
};

#
# The role rejects a class that does not implement the three required methods.
# (Covered in the first subtest; one re-assertion here with the full message.)
#

subtest 'composition fails when any required method is missing' => sub {
    eval {
        package HalfAdapter;
        use Moo;
        with 'OCP::Role::Provider::ExistingHost';
        sub resolve_host   { 'h' }
        # host_reachable missing
        sub run_command    { { stdout => '', stderr => '', exit => 0 } }
    };
    like $@, qr/host_reachable/,
        'composition fails when host_reachable is missing';
};

done_testing;

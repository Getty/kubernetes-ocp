package OCP::Role::Provider::ExistingHost;
# ABSTRACT: Provider behaviour for hosts OCP does not create

use Moo::Role;

our $VERSION = '0.001';

# Uninstall both distributions — we don't track which one is on the host.
our $UNINSTALL_CMD =
    'rke2-uninstall.sh 2>/dev/null || k3s-uninstall.sh 2>/dev/null || true';

# A consumer only has to say which host it talks to, how to check that the
# host is there, and how to run a command on it. Everything else is the same
# for every provider that works on pre-existing machines.
requires 'resolve_host';     # (%opts)           -> host, or dies
requires 'host_reachable';   # ($host, $timeout) -> bool
requires 'run_command';      # ($host, $command) -> output

has verbose => (is => 'ro', default => 0);

# Nothing to create, so nothing to prepare or clean up.
sub upload_ssh_key         { return }
sub cleanup_on_failure     { return }
sub list_servers_by_cluster { return [] }

sub server_exists {
    my ($self, $node_name, %opts) = @_;

    my $host = eval { $self->resolve_host(%opts) };
    return unless defined $host && length $host;

    return $self->host_reachable($host, $opts{timeout} // 10)
        ? { ip => $host }
        : undef;
}

sub create_server {
    my ($self, %opts) = @_;

    my $host = $self->resolve_host(%opts);

    return {
        id            => undef,
        ip            => $host,
        newly_created => 0,
    };
}

sub wait_for_running {
    my ($self, $server_info, $timeout) = @_;
    return $server_info;   # it was running before we got here
}

# We can't delete the machine, so we remove what we installed on it.
sub delete_server {
    my ($self, $server_id, %opts) = @_;

    my $host = eval { $self->resolve_host(%opts) };
    return unless defined $host && length $host;

    return $self->run_command($host, $UNINSTALL_CMD);
}

1;

__END__

=head1 NAME

OCP::Role::Provider::ExistingHost - Provider behaviour for hosts OCP does not create

=head1 SYNOPSIS

    package OCP::Provider::SSH;
    use Moo;
    with 'OCP::Role::Provider::ExistingHost';

    sub resolve_host   { $_[1] ... }
    sub host_reachable { ... }
    sub run_command    { ... }

=head1 DESCRIPTION

Some providers manage machines, others just use machines that are already
there. This role holds everything the second kind has in common: creation is
a no-op that reports the host back, waiting is instant, there is no key to
upload and no server list to query, and deletion means uninstalling the
Kubernetes distribution instead of destroying hardware.

Consumers supply the three things that actually differ: which host to talk
to, how to test it, and how to run a command on it. L<OCP::Provider::SSH>
does that over SSH, L<OCP::Provider::Local> does it on the local machine.

=head1 REQUIRED METHODS

=head2 resolve_host

    my $host = $provider->resolve_host(%opts);

The host to act on. Dies when it cannot be determined.

=head2 host_reachable

    my $bool = $provider->host_reachable($host, $timeout);

Whether the host answers.

=head2 run_command

    my $output = $provider->run_command($host, $command);

Runs a shell command on the host.

=head1 METHODS

=head2 server_exists

Returns C<< { ip => $host } >> when the host is reachable, undef otherwise.

=head2 create_server

Reports the host back as an existing, not newly created server.

=head2 wait_for_running

Returns its argument unchanged.

=head2 delete_server

Runs the RKE2/K3s uninstall script on the host.

=head2 upload_ssh_key, cleanup_on_failure, list_servers_by_cluster

No-ops. There is no provider API behind these hosts.

=cut

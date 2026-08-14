package OCP::Role::Provider::ExistingHost;
# ABSTRACT: Provider behaviour for hosts OCP does not create

use Moo::Role;

our $VERSION = '0.001';

# Uninstall both distributions — we don't track which one is on the host.
#
# The vendor uninstallers stop at their own footprint and leave behind what OCP
# put there on top: the Cilium CLI (installed by the install_cilium task), the
# CNI plugin directory, and the k3s runtime dir. Leaving those is not cosmetic —
# a later bootstrap finds the stale `cilium` binary and, if its version happens
# to match what is wanted, keeps it instead of installing the pinned one.
#
# So this cleans up after itself by default rather than behind a flag: every
# path below is something OCP or its distribution installed, never user data.
our @LEFTOVER_PATHS = qw(
    /usr/local/bin/cilium
    /opt/cni
    /run/k3s
);

our $UNINSTALL_CMD = join ' ; ',
    'rke2-uninstall.sh 2>/dev/null || k3s-uninstall.sh 2>/dev/null || true',
    'rm -rf ' . join(' ', @LEFTOVER_PATHS) . ' 2>/dev/null || true';

# A consumer only has to say which host it talks to, how to check that the
# host is there, and how to run a command on it. Everything else is the same
# for every provider that works on pre-existing machines.
requires 'resolve_host';     # (%opts)           -> host, or dies
requires 'host_reachable';   # ($host, $timeout) -> bool
requires 'run_command';      # ($host, $command) -> output

=attr verbose

    my $p = MyProvider->new(verbose => 1);

Boolean verbosity flag, consumed by subclasses (e.g. L<OCP::Provider::Local>
prints command output when set). Default C<0>.

=cut

has verbose => (is => 'ro', default => 0);

# Nothing to create, so nothing to prepare or clean up.
sub upload_ssh_key          { return }
sub cleanup_on_failure      { return }
sub list_servers_by_cluster { return [] }

=method server_exists

    my $info = $p->server_exists($node_name, host => '10.0.0.5');

Returns C<< { ip => $host } >> when the host resolves and answers; C<undef>
when C<resolve_host> dies or the host is unreachable. Used by callers that
want to know whether to provision or to skip.

=method create_server

    my $info = $p->create_server(host => '10.0.0.5', name => 'w1');

Reports the host back as an existing, not newly created server.
C<id> is C<undef>; C<newly_created> is C<0>. The caller treats both fields
the same way as the cloud adapter would.

=method wait_for_running

    my $info = $p->wait_for_running($info, 120);

No-op: the host was running before we got here. Returns its argument.

=method delete_server

    $p->delete_server(undef, host => '10.0.0.5');

Runs the RKE2/K3s uninstall script on the host. C<$server_id> is ignored
(the machine does not belong to OCP); C<host> is read through C<resolve_host>.

=cut

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

=synopsis

    package My::Provider::New;
    use Moo;
    with 'OCP::Role::Provider::ExistingHost';

    sub resolve_host   { ... }   # where to talk
    sub host_reachable { ... }   # how to check it
    sub run_command    { ... }   # how to run things on it

=description

Some providers manage machines; others just use machines that are already
there. This role holds everything the second kind has in common: creation is
a no-op that reports the host back, waiting is instant, there is no key to
upload and no server list to query, and deletion means uninstalling the
Kubernetes distribution instead of destroying hardware.

B<Any adapter that wraps a host the user already controls MUST consume this
role.> Adapter-specific overrides are for IP discovery or transport
(SSH vs serial vs local execution), NOT for the lifecycle shape
(create/delete/run_command). The lifecycle methods here are the seam:
callers depend on them, and a host adapter that re-implements them in its
own way will silently drift from the cloud adapter's contract.

Consumers supply the three things that actually differ: which host to talk
to, how to test it, and how to run a command on it.
L<OCP::Provider::SSH> does that over SSH;
L<OCP::Provider::Local> does it on the local machine.

=method required

These methods B<must> be implemented by the consuming class. The role calls
each in the methods below (C<server_exists>, C<create_server>,
C<delete_server>), so an undefined body is a hard error at composition
time — Moo::Role's C<requires> enforces it.

=over 4

=item C<resolve_host(%opts) — str, dies on failure>

Returns the host to act on. Callers pass C<host => ...> when they have one;
OCP::Node::_provision passes C<spec => $cr->{spec}> instead, so an
adapter reading only C<$opts{host}> will die there. The SSH adapter shows
the pattern: prefer an explicit C<host>, fall back to C<spec.host>.

=item C<host_reachable($host, $timeout) — bool>

Whether the host answers within C<$timeout> seconds. Used by
C<server_exists> to decide between C<< { ip => $host } >> and C<undef>.

=item C<run_command($host, $command) — output>

Runs a shell command on the host and returns its output (shape matching
L<OCP::SSH/run>). Used by C<delete_server> to uninstall the distribution.

=back

=method upload_ssh_key, cleanup_on_failure, list_servers_by_cluster

    $p->upload_ssh_key($name, $pubkey);   # no-op
    $p->cleanup_on_failure($server_id);   # no-op
    my $servers = $p->list_servers_by_cluster($cluster);  # []

No-ops. There is no provider API behind these hosts, and callers know it.

=seealso

L<OCP::Provider::SSH>, L<OCP::Provider::Local>, L<OCP::Provider::Hetzner>,
L<OCP::Provider>

=cut

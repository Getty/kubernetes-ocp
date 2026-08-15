package OCP::Provider::SSH;
# ABSTRACT: SSH infrastructure provider (existing servers)

use Moo;
use OCP::SSH;

with 'OCP::Role::Provider::ExistingHost';

=attr ssh_key_path

    my $p = OCP::Provider::SSH->new(ssh_key_path => '/path/to/id_ed25519');

Path to the SSH private key used to reach the hosts. Root login is assumed.
Empty/undef is allowed: the SSH client then falls back to the user's default
key and C<ssh-agent>.

=cut

has ssh_key_path => (is => 'ro');

# Callers reach this two ways. Some pass the host directly; OCP::Node::_provision
# hands over the whole CR instead, as spec => $cr->{spec}, and the host sits in
# there. Reading only $opts{host} made every ssh worker die in provisioning
# before a single command ran, while the control plane stayed unaffected because
# it never goes through _provision. Accept both shapes; a direct host wins.
=method resolve_host

    my $host = $p->resolve_host(host => '10.0.0.5');

Returns the C<host> option. Falls back to C<$opts{spec}{host}> when an
explicit C<host> is missing — OCP::Node::_provision passes the CR spec,
not a C<host> field. Dies when neither is present.

=cut

sub resolve_host {
    my ($self, %opts) = @_;
    my $host = $opts{host};
    $host = $opts{spec}{host}
        if !(defined $host && length $host) && ref $opts{spec} eq 'HASH';
    die "SSH provider requires 'host'\n" unless defined $host && length $host;
    return $host;
}

=method host_reachable

    my $ok = $p->host_reachable($host, $timeout);

C<True> when SSH answers within C<$timeout> seconds (default 10).
Implementation: opens an L<OCP::SSH> client and calls C<wait_for_ssh>;
any exception is treated as unreachable.

=cut

sub host_reachable {
    my ($self, $host, $timeout) = @_;
    return eval { $self->_ssh($host)->wait_for_ssh($timeout // 10); 1 } ? 1 : 0;
}

=method run_command

    my $result = $p->run_command($host, 'uptime');

Runs the command over SSH as root. Returns the L<OCP::SSH/run> shape
(C<{ stdout, stderr, exit }>).

=cut

sub run_command {
    my ($self, $host, $command) = @_;
    return $self->_ssh($host)->run($command);
}

sub _ssh {
    my ($self, $host) = @_;
    return OCP::SSH->new(
        host     => $host,
        key_file => $self->ssh_key_path,
        user     => 'root',
    );
}

1;

__END__

=synopsis

    use OCP::Provider::SSH;

    my $p = OCP::Provider::SSH->new(ssh_key_path => '/path/to/id_ed25519');
    my $info = $p->create_server(host => '10.0.0.5', name => 'w1');
    # { id => undef, ip => '10.0.0.5', newly_created => 0 }

    $p->delete_server(undef, host => '10.0.0.5');   # uninstalls RKE2/K3s

=description

Wraps existing SSH-accessible servers as an OCP provider. Server creation
is a no-op that reports the host back, destruction runs the RKE2/K3s
uninstall script over SSH. The shared behaviour — C<create_server>,
C<delete_server>, C<server_exists>, the no-op trio — lives in
L<OCP::Role::Provider::ExistingHost>.

This adapter owns only the three transport-level methods the role requires:
where the host is (C<resolve_host>, with the C<spec.host> fallback for
OCP::Node's call shape), how to test it (C<host_reachable>), and how to
run a command on it (C<run_command>, through L<OCP::SSH>).

=seealso

L<OCP::Provider::Local>, L<OCP::Provider::Hetzner>,
L<OCP::Role::Provider::ExistingHost>, L<OCP::SSH>

=cut

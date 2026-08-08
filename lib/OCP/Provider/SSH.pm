package OCP::Provider::SSH;
# ABSTRACT: SSH infrastructure provider (existing servers)

use Moo;
use OCP::SSH;

with 'OCP::Role::Provider::ExistingHost';

our $VERSION = '0.001';

has ssh_key_path => (is => 'ro');

sub resolve_host {
    my ($self, %opts) = @_;
    my $host = $opts{host};
    die "SSH provider requires 'host'\n" unless defined $host && length $host;
    return $host;
}

sub host_reachable {
    my ($self, $host, $timeout) = @_;
    return eval { $self->_ssh($host)->wait_for_ssh($timeout // 10); 1 } ? 1 : 0;
}

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

=head1 NAME

OCP::Provider::SSH - SSH provider for existing servers

=head1 DESCRIPTION

Wraps existing SSH-accessible servers as an OCP provider. Server creation is
a no-op that reports the host back, destruction runs the RKE2/K3s uninstall
script over SSH. The shared behaviour lives in
L<OCP::Role::Provider::ExistingHost>.

=head1 ATTRIBUTES

=head2 ssh_key_path

Private key used to reach the hosts. Root login is assumed.

=head1 METHODS

=head2 resolve_host

    my $host = $provider->resolve_host(host => '10.0.0.5');

Returns the C<host> option, dies without it.

=head2 host_reachable

    my $bool = $provider->host_reachable($host, $timeout);

True when SSH answers within C<$timeout> seconds.

=head2 run_command

    my $output = $provider->run_command($host, 'uptime');

Runs the command over SSH as root.

=cut

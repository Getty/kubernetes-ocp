package OCP::Provider::SSH;
# ABSTRACT: SSH infrastructure provider (existing servers)

use Moo;
use OCP::SSH;

our $VERSION = '0.1.0';

has ssh_key_path => (is => 'ro');

sub upload_ssh_key {
    # No-op for SSH provider — keys are pre-deployed
    return;
}

sub server_exists {
    my ($self, $node_name, %opts) = @_;
    my $host = $opts{host} or return;

    # Check SSH reachability
    my $ssh = OCP::SSH->new(
        host     => $host,
        key_file => $self->ssh_key_path,
        user     => 'root',
    );

    my $reachable = eval { $ssh->wait_for_ssh(10); 1 };
    return $reachable ? { ip => $host } : undef;
}

sub create_server {
    my ($self, %opts) = @_;

    my $host = $opts{host} or die "SSH provider requires 'host'\n";

    return {
        id            => undef,
        ip            => $host,
        newly_created => 0,
    };
}

sub wait_for_running {
    my ($self, $server_info, $timeout) = @_;
    # SSH servers are already running
    return $server_info;
}

sub delete_server {
    my ($self, $server_id, %opts) = @_;
    my $host = $opts{host} or return;

    my $ssh = OCP::SSH->new(
        host     => $host,
        key_file => $self->ssh_key_path,
        user     => 'root',
    );

    $ssh->run('rke2-uninstall.sh 2>/dev/null || k3s-uninstall.sh 2>/dev/null || true');
}

sub cleanup_on_failure {
    # No-op — we don't delete SSH servers on failure
    return;
}

sub list_servers_by_cluster {
    # SSH provider has no API to list servers
    return [];
}

1;

__END__

=head1 NAME

OCP::Provider::SSH - SSH provider for existing servers

=head1 DESCRIPTION

Wraps existing SSH-accessible servers as an OCP provider.
Server creation is a no-op (returns the host). Destruction
runs the RKE2/K3s uninstall script.

=cut

package OCP::Provider::Local;
# ABSTRACT: Local infrastructure provider (localhost)

use Moo;

our $VERSION = '0.1.0';

has verbose => (is => 'ro', default => 0);

sub upload_ssh_key {
    # No-op for local provider
    return;
}

sub server_exists {
    # Local is always "existing"
    return { ip => '127.0.0.1' };
}

sub create_server {
    my ($self, %opts) = @_;
    return {
        id            => undef,
        ip            => '127.0.0.1',
        newly_created => 0,
    };
}

sub wait_for_running {
    my ($self, $server_info, $timeout) = @_;
    return $server_info;
}

sub delete_server {
    # Local uninstall handled by OCP::Local
    return;
}

sub cleanup_on_failure {
    return;
}

sub list_servers_by_cluster {
    return [];
}

1;

__END__

=head1 NAME

OCP::Provider::Local - Local provider for localhost installations

=head1 DESCRIPTION

Provider for local installations that run directly on the current machine.
All server lifecycle methods are no-ops since there is no remote infrastructure.

=cut

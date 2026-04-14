package OCP::Provider::Hetzner;
# ABSTRACT: Hetzner Cloud infrastructure provider

use Moo;
use WWW::Hetzner::Cloud;

our $VERSION = '0.001';

has token => (is => 'ro', required => 1);
has cluster_name => (is => 'ro', default => '');

has cloud => (
    is      => 'lazy',
    builder => sub { WWW::Hetzner::Cloud->new(token => shift->token) },
);

sub upload_ssh_key {
    my ($self, $key_name, $pubkey) = @_;

    die "SSH public key is empty or undefined\n" unless $pubkey && $pubkey =~ /\S/;
    die "SSH key name is required\n" unless $key_name;

    $self->cloud->ssh_keys->ensure($key_name, $pubkey);
}

sub server_exists {
    my ($self, $node_name) = @_;

    my $cluster = $self->cluster_name;
    return unless $cluster;

    my $servers = $self->cloud->servers->list_by_label(
        "ocp-cluster=$cluster,ocp-node=$node_name"
    );

    return $servers->[0] if @$servers;
    return;
}

sub create_server {
    my ($self, %opts) = @_;

    my $name      = $opts{name} or die "Server name required\n";
    my $node_name = $opts{node} // $name;
    my $cluster   = $opts{cluster} // $self->cluster_name;

    # Idempotency: check if server already exists with matching labels
    if ($cluster) {
        my $existing = $self->server_exists($node_name);
        if ($existing) {
            return {
                id           => $existing->id,
                ip           => $existing->ipv4,
                newly_created => 0,
            };
        }
    }

    my $server = $self->cloud->servers->create(
        name        => $name,
        server_type => $opts{server_type} // 'cx32',
        image       => $opts{image} // 'debian-13',
        location    => $opts{location} // 'fsn1',
        ssh_keys    => $opts{ssh_keys} // [],
        labels      => {
            'ocp-cluster' => $cluster,
            'ocp-role'    => $opts{role} // 'control-plane',
            'ocp-node'    => $node_name,
        },
    );

    return {
        id            => $server->id,
        ip            => undef,  # not yet available, need wait_for_running
        newly_created => 1,
        _server       => $server,
    };
}

sub wait_for_running {
    my ($self, $server_info, $timeout) = @_;
    $timeout //= 120;

    my $server = $self->cloud->servers->wait_for_status(
        $server_info->{id}, 'running', $timeout
    );

    $server_info->{ip} = $server->ipv4;
    return $server_info;
}

sub get_server_ip {
    my ($self, $server_id) = @_;
    my $server = $self->cloud->servers->get($server_id);
    return $server->ipv4;
}

sub delete_server {
    my ($self, $server_id) = @_;
    $self->cloud->servers->delete($server_id);
}

sub cleanup_on_failure {
    my ($self, $server_id) = @_;
    return unless $server_id;
    eval { $self->delete_server($server_id) };
    warn "Cleanup failed for server $server_id: $@\n" if $@;
}

sub list_servers_by_cluster {
    my ($self, $cluster_name) = @_;
    $cluster_name //= $self->cluster_name;
    return $self->cloud->servers->list_by_label("ocp-cluster=$cluster_name");
}

1;

__END__

=head1 NAME

OCP::Provider::Hetzner - Hetzner Cloud infrastructure provider

=head1 DESCRIPTION

Manages server lifecycle on Hetzner Cloud with idempotent creation
(checks labels before creating), failure cleanup, and cluster-scoped
server listing.

=cut

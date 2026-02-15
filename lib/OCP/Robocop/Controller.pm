package OCP::Robocop::Controller;
# ABSTRACT: Kubernetes controller for OCP nodes

use Moo;
use IO::Async::Loop;
use Net::Async::Kubernetes;
use IO::K8s::APIObject;
use Try::Tiny;
use Types::Standard qw(Str Int Bool HashRef);

our $VERSION = '0.1.0';

has loop => (
    is      => 'lazy',
    builder => sub { IO::Async::Loop->new },
);

has k8s => (
    is      => 'lazy',
    builder => '_build_k8s',
);

has namespace => (
    is      => 'ro',
    default => 'ocp-system',
);

has verbose => (
    is      => 'ro',
    default => 0,
);

sub _build_k8s {
    my ($self) = @_;

    # Use in-cluster config
    my $k8s = Net::Async::Kubernetes->new(
        namespace => $self->namespace,
    );

    $self->loop->add($k8s);

    return $k8s;
}

sub run {
    my ($self) = @_;

    $self->log("Robocop controller starting...");

    # Watch OCPNode resources
    my $node_watcher = $self->k8s->watch_resource(
        resource    => 'OCPNode',
        on_added    => sub { $self->handle_node_added(@_) },
        on_modified => sub { $self->handle_node_modified(@_) },
        on_deleted  => sub { $self->handle_node_deleted(@_) },
    );

    # Watch OCPNodeProvider resources
    my $provider_watcher = $self->k8s->watch_resource(
        resource    => 'OCPNodeProvider',
        on_added    => sub { $self->handle_provider_added(@_) },
        on_modified => sub { $self->handle_provider_modified(@_) },
        on_deleted  => sub { $self->handle_provider_deleted(@_) },
    );

    $self->log("Watching OCPNode and OCPNodeProvider resources");

    # Run event loop
    $self->loop->run;
}

#
# OCPNode handlers
#

sub handle_node_added {
    my ($self, $node) = @_;

    my $name = $node->metadata->name;
    my $role = $node->spec->{role} // 'worker';
    my $provider_ref = $node->spec->{providerRef};

    $self->log("OCPNode added: $name (role=$role, provider=$provider_ref)");

    # Check if node already exists (status.phase = Ready)
    if ($node->status && $node->status->{phase} eq 'Ready') {
        $self->log("  Node $name already Ready, skipping");
        return;
    }

    # Reconcile node
    $self->reconcile_node($node);
}

sub handle_node_modified {
    my ($self, $node) = @_;

    my $name = $node->metadata->name;
    my $phase = $node->status->{phase} // 'Unknown';

    $self->log("OCPNode modified: $name (phase=$phase)");

    # Reconcile node
    $self->reconcile_node($node);
}

sub handle_node_deleted {
    my ($self, $node) = @_;

    my $name = $node->metadata->name;
    $self->log("OCPNode deleted: $name");

    # Delete infrastructure if needed
    try {
        $self->delete_node_infrastructure($node);
    } catch {
        $self->log("ERROR deleting node infrastructure: $_");
    };
}

#
# OCPNodeProvider handlers
#

sub handle_provider_added {
    my ($self, $provider) = @_;

    my $name = $provider->metadata->name;
    my $type = $provider->spec->{type};

    $self->log("OCPNodeProvider added: $name (type=$type)");

    # Validate provider configuration
    $self->validate_provider($provider);
}

sub handle_provider_modified {
    my ($self, $provider) = @_;

    my $name = $provider->metadata->name;
    $self->log("OCPNodeProvider modified: $name");

    # Validate provider configuration
    $self->validate_provider($provider);
}

sub handle_provider_deleted {
    my ($self, $provider) = @_;

    my $name = $provider->metadata->name;
    $self->log("OCPNodeProvider deleted: $name");

    # Check if any nodes are still using this provider
    my $nodes = $self->k8s->list_resource('OCPNode')->get;
    my @using_provider = grep { $_->spec->{providerRef} eq $name } @{$nodes->items};

    if (@using_provider) {
        my $names = join(', ', map { $_->metadata->name } @using_provider);
        $self->log("WARNING: Provider $name deleted but still used by: $names");
    }
}

#
# Reconciliation logic
#

sub reconcile_node {
    my ($self, $node) = @_;

    my $name = $node->metadata->name;
    my $phase = $node->status->{phase} // 'Pending';

    # Reconciliation state machine
    if ($phase eq 'Pending') {
        $self->provision_node($node);
    }
    elsif ($phase eq 'Provisioning') {
        $self->install_kubernetes($node);
    }
    elsif ($phase eq 'Installing') {
        $self->wait_for_ready($node);
    }
    elsif ($phase eq 'Ready') {
        $self->verify_node($node);
    }
    elsif ($phase eq 'Failed') {
        # Check if we should retry
        # TODO: Implement exponential backoff
        $self->log("Node $name in Failed state");
    }
}

sub provision_node {
    my ($self, $node) = @_;

    my $name = $node->metadata->name;
    my $provider_ref = $node->spec->{providerRef};

    $self->log("Provisioning node $name...");

    # Get provider
    my $provider = $self->k8s->get_resource(
        resource => 'OCPNodeProvider',
        name     => $provider_ref,
    )->get;

    unless ($provider) {
        $self->update_node_status($node, {
            phase   => 'Failed',
            message => "Provider '$provider_ref' not found",
        });
        return;
    }

    my $type = $provider->spec->{type};

    try {
        if ($type eq 'hetzner') {
            $self->provision_hetzner_node($node, $provider);
        }
        elsif ($type eq 'ssh') {
            $self->provision_ssh_node($node, $provider);
        }
        else {
            die "Unknown provider type: $type\n";
        }
    } catch {
        $self->log("ERROR provisioning node: $_");
        $self->update_node_status($node, {
            phase   => 'Failed',
            message => "Provisioning failed: $_",
        });
    };
}

sub provision_hetzner_node {
    my ($self, $node, $provider) = @_;

    # TODO: Implement Hetzner provisioning
    # - Get Hetzner token from secret
    # - Create server via WWW::Hetzner::Cloud
    # - Update node status with providerId, publicIP
    # - Set phase to Provisioning

    $self->log("Hetzner provisioning not implemented yet");
}

sub provision_ssh_node {
    my ($self, $node, $provider) = @_;

    my $name = $node->metadata->name;
    my $host = $node->spec->{host};

    unless ($host) {
        die "SSH node requires 'host' in spec\n";
    }

    # SSH nodes are pre-existing, just mark as provisioned
    $self->update_node_status($node, {
        phase    => 'Provisioning',
        publicIP => $host,
        message  => 'SSH node pre-existing, ready for Kubernetes install',
    });
}

sub install_kubernetes {
    my ($self, $node) = @_;

    # TODO: Implement Kubernetes installation
    # - SSH to node via OCP::SSH
    # - Run Rex tasks via OCP::Rex
    # - Install RKE2/K3s
    # - Update status to Installing

    my $name = $node->metadata->name;
    $self->log("Kubernetes installation for $name not implemented yet");
}

sub wait_for_ready {
    my ($self, $node) = @_;

    # TODO: Wait for node to join cluster
    # - Check Kubernetes Node object
    # - Verify node conditions
    # - Update status to Ready

    my $name = $node->metadata->name;
    $self->log("Readiness check for $name not implemented yet");
}

sub verify_node {
    my ($self, $node) = @_;

    # TODO: Periodic health check
    # - Verify Kubernetes Node still exists
    # - Check node conditions
    # - Update lastChecked timestamp

    # For now, do nothing
}

sub delete_node_infrastructure {
    my ($self, $node) = @_;

    my $provider_id = $node->status->{providerId};
    my $provider_ref = $node->spec->{providerRef};

    return unless $provider_id;

    # Get provider
    my $provider = $self->k8s->get_resource(
        resource => 'OCPNodeProvider',
        name     => $provider_ref,
    )->get;

    return unless $provider;

    my $type = $provider->spec->{type};

    if ($type eq 'hetzner') {
        # TODO: Delete Hetzner server
        $self->log("Would delete Hetzner server $provider_id");
    }
    elsif ($type eq 'ssh') {
        # SSH nodes are not owned by us, nothing to delete
        $self->log("SSH node, no infrastructure to delete");
    }
}

#
# Helpers
#

sub validate_provider {
    my ($self, $provider) = @_;

    my $name = $provider->metadata->name;
    my $type = $provider->spec->{type};

    my $ready = 1;
    my $message = "Provider configured";

    if ($type eq 'hetzner') {
        # Check if token secret exists
        my $secret_ref = $provider->spec->{hetzner}{tokenSecretRef};
        unless ($secret_ref && $secret_ref->{name}) {
            $ready = 0;
            $message = "Hetzner tokenSecretRef not configured";
        }
    }
    elsif ($type eq 'ssh') {
        # SSH provider always ready (credentials in secrets)
        $ready = 1;
    }
    else {
        $ready = 0;
        $message = "Unknown provider type: $type";
    }

    # Update provider status
    $self->k8s->patch_resource(
        resource => 'OCPNodeProvider',
        name     => $name,
        patch    => {
            status => {
                ready       => $ready ? JSON::PP::true : JSON::PP::false,
                message     => $message,
                lastChecked => _timestamp(),
            },
        },
    );
}

sub update_node_status {
    my ($self, $node, $updates) = @_;

    my $name = $node->metadata->name;

    $self->k8s->patch_resource(
        resource => 'OCPNode',
        name     => $name,
        patch    => {
            status => $updates,
        },
    )->get;

    $self->log("Updated node $name status: " . ($updates->{phase} // 'no phase'));
}

sub log {
    my ($self, $msg) = @_;

    my $timestamp = scalar localtime;
    print "[$timestamp] $msg\n";
}

sub _timestamp {
    my @t = gmtime;
    return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
}

1;

__END__

=head1 NAME

OCP::Robocop::Controller - Kubernetes controller for OCP nodes

=head1 SYNOPSIS

    use OCP::Robocop::Controller;

    my $controller = OCP::Robocop::Controller->new(
        namespace => 'ocp-system',
        verbose   => 1,
    );

    $controller->run;

=head1 DESCRIPTION

Robocop is the Kubernetes controller component of OCP. It watches OCPNode and
OCPNodeProvider CRDs and reconciles the desired cluster state:

- Provisions infrastructure (Hetzner Cloud, SSH hosts)
- Installs Kubernetes (RKE2/K3s) on nodes
- Manages node lifecycle (join, ready, delete)
- Updates status in CRD objects

Built on L<Net::Async::Kubernetes> for async event handling and L<IO::K8s>
for typed Kubernetes API objects.

=head1 METHODS

=head2 run

Start the controller and watch for CRD changes. Blocks forever.

=head2 reconcile_node

Main reconciliation loop for OCPNode. State machine:

  Pending -> Provisioning -> Installing -> Ready
                  |
                  v
              Failed (retry later)

=head2 provision_node

Provision infrastructure based on OCPNodeProvider type:

- B<hetzner>: Create server via Hetzner Cloud API
- B<ssh>: Use existing host (mark as provisioned)

=head2 install_kubernetes

Install RKE2/K3s on provisioned node via Rex tasks.

=head2 validate_provider

Check OCPNodeProvider configuration and update status.

=cut

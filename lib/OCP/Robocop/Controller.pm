package OCP::Robocop::Controller;
# ABSTRACT: Kubernetes controller for OCP nodes

use Moo;
use Carp qw(croak);
use Path::Tiny qw(path);
use Try::Tiny;

use Kubernetes::REST;
use OCP::Node;
use OCP::Provider;

our $VERSION = '0.001';

#
# Configuration
#

has namespace => (
    is      => 'ro',
    default => 'ocp-system',
);

has kubeconfig => (
    is  => 'ro',
    doc => 'Kubeconfig content or file path (for out-of-cluster testing)',
);

has ssh_key => (
    is       => 'ro',
    required => 1,
    doc      => 'SSH private key content (robo-key)',
);

has server_url => (
    is       => 'ro',
    required => 1,
    doc      => 'RKE2 server URL, e.g. https://192.168.122.1:9345',
);

has join_token => (
    is       => 'ro',
    required => 1,
    doc      => 'RKE2 node join token',
);

has distribution => (
    is      => 'ro',
    default => 'rke2',
);

has poll_interval => (
    is      => 'ro',
    default => 10,   # seconds
);

has verbose => (
    is      => 'ro',
    default => 0,
);

#
# Lazy-built Kubernetes client
#

has kube => (
    is      => 'lazy',
    builder => '_build_kube',
);

sub _build_kube {
    my ($self) = @_;

    my %opts;
    if ($self->kubeconfig) {
        if (-f $self->kubeconfig) {
            $opts{kubeconfig} = path($self->kubeconfig)->slurp;
        } else {
            $opts{kubeconfig} = $self->kubeconfig;
        }
    }
    # else: Kubernetes::REST uses in-cluster config automatically

    return Kubernetes::REST->new(%opts);
}

#
# Main loop: poll and reconcile
#

sub run {
    my ($self) = @_;

    $self->log("Robocop controller starting (namespace=" . $self->namespace . ")");
    $self->log("Server URL:   " . $self->server_url);
    $self->log("Distribution: " . $self->distribution);

    while (1) {
        my $nodes = eval { $self->list_ocp_nodes };
        if ($@) {
            $self->log("ERROR listing OCPNodes: $@");
        } else {
            for my $cr (@$nodes) {
                try {
                    $self->_on_node_event($cr);
                } catch {
                    my $name = $cr->{metadata}{name} // '?';
                    $self->log("ERROR reconciling $name: $_");
                };
            }
        }

        sleep $self->poll_interval;
    }
}

#
# Event dispatcher → OCP::Node
#

sub _on_node_event {
    my ($self, $cr) = @_;

    my $provider_name = $cr->{spec}{providerRef};
    unless ($provider_name) {
        $self->log("No providerRef on " . ($cr->{metadata}{name} // '?'));
        return;
    }

    my $ns = $cr->{metadata}{namespace} // $self->namespace;

    my $provider_cr = eval {
        $self->kube->get(
            path => "/apis/ocp.internal/v1/namespaces/$ns/ocpnodeproviders/$provider_name",
        );
    };
    if ($@ || !$provider_cr) {
        $self->log("Failed to load provider CR $provider_name: " . ($@ // 'not found'));
        return;
    }

    my $provider = OCP::Provider->from_cr($provider_cr, k8s => $self->kube);

    my $node = OCP::Node->from_cr(
        $cr,
        k8s           => $self->kube,
        provider      => $provider,
        ssh_key       => $self->ssh_key,
        server_url    => $self->server_url,
        join_token    => $self->join_token,
        distribution  => $self->distribution,
        verbose       => $self->verbose,
        reconciler_id => 'robocop',
    );

    $node->reconcile;
}

#
# Kubernetes API helpers
#

sub list_ocp_nodes {
    my ($self) = @_;

    my $resp = $self->kube->get(
        path => "/apis/ocp.internal/v1/namespaces/" . $self->namespace . "/ocpnodes",
    );

    return $resp->{items} // [];
}

#
# Helpers
#

sub log {
    my ($self, $msg) = @_;
    my $ts = scalar localtime;
    print "[$ts] $msg\n";
}

1;

__END__

=head1 NAME

OCP::Robocop::Controller - Kubernetes controller for OCP nodes

=head1 SYNOPSIS

    use OCP::Robocop::Controller;

    my $controller = OCP::Robocop::Controller->new(
        namespace    => 'ocp-system',
        kubeconfig   => '/path/to/kubeconfig.yaml',  # or undef for in-cluster
        ssh_key      => $robo_key_content,
        server_url   => 'https://192.168.122.1:9345',
        join_token   => $token,
        distribution => 'rke2',
    );

    $controller->run;  # blocks, polls OCPNodes, reconciles via OCP::Node

=head1 DESCRIPTION

Watches OCPNode custom resources and dispatches each event to L<OCP::Node>
for reconciliation. The state machine lives entirely in C<OCP::Node>.

=head2 Reconciliation state machine

    Pending → Provisioning → Installing → Joining → Ready
                     └──────────────┴──────────→ Failed

=cut

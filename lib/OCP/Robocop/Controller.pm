package OCP::Robocop::Controller;
# ABSTRACT: Kubernetes controller for OCP nodes

use Moo;
use Carp qw(croak);
use Path::Tiny qw(path);
use File::Temp ();
use JSON::PP ();
use Try::Tiny;
use Types::Standard qw(Str Int Bool HashRef);

use Kubernetes::REST;
use OCP::SSH;
use OCP::Rex;
use OCP::Versions;

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
        # File path or YAML content
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
# Lazy-built temp SSH key file (chmod 600)
#

has _ssh_key_file => (
    is      => 'lazy',
    builder => '_build_ssh_key_file',
);

sub _build_ssh_key_file {
    my ($self) = @_;

    my $tmp = File::Temp->new(SUFFIX => '.key', UNLINK => 1);
    print $tmp $self->ssh_key;
    close $tmp;
    chmod 0600, $tmp->filename;
    return $tmp;   # keep object alive for auto-cleanup
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
            for my $node (@$nodes) {
                try {
                    $self->reconcile_node($node);
                } catch {
                    my $name = $node->{metadata}{name} // '?';
                    $self->log("ERROR reconciling $name: $_");
                };
            }
        }

        sleep $self->poll_interval;
    }
}

#
# Reconciliation state machine
#

sub reconcile_node {
    my ($self, $node) = @_;

    my $name  = $node->{metadata}{name};
    my $phase = $node->{status}{phase} // 'Pending';

    $self->log("Reconcile $name (phase=$phase)") if $self->verbose;

    if    ($phase eq 'Pending')      { $self->provision_node($node) }
    elsif ($phase eq 'Provisioning') { $self->install_kubernetes($node) }
    elsif ($phase eq 'Installing')   { $self->wait_for_ready($node) }
    elsif ($phase eq 'Joining')      { $self->wait_for_ready($node) }
    elsif ($phase eq 'Ready')        { $self->verify_node($node) }
    elsif ($phase eq 'Failed')       { $self->log("  $name in Failed state") }
}

sub provision_node {
    my ($self, $node) = @_;

    my $name     = $node->{metadata}{name};
    my $role     = $node->{spec}{role};
    my $host     = $node->{spec}{host};
    my $provider = $node->{spec}{providerRef};

    if ($role eq 'control-plane') {
        $self->log("  $name: control-plane provisioning not supported via Robocop (use 'ocp apply')");
        $self->update_node_status($node, phase => 'Failed',
            message => 'control-plane must be bootstrapped externally');
        return;
    }

    $self->log("[$name] Provisioning (provider=$provider)...");

    if (!$host) {
        # TODO: resolve via OCPNodeProvider for hetzner
        $self->update_node_status($node, phase => 'Failed',
            message => "No host specified (only SSH provider with .spec.host supported for now)");
        return;
    }

    # SSH provider: pre-existing host, just mark as ready for install
    $self->update_node_status($node,
        phase    => 'Provisioning',
        publicIP => $host,
        message  => 'Host reachable, ready for Kubernetes install',
    );
}

sub install_kubernetes {
    my ($self, $node) = @_;

    my $name = $node->{metadata}{name};
    my $host = $node->{status}{publicIP} || $node->{spec}{host};
    my $role = $node->{spec}{role};
    my $gpu  = $node->{spec}{gpu} ? 1 : 0;

    unless ($host) {
        $self->update_node_status($node, phase => 'Failed',
            message => 'No host IP in status or spec');
        return;
    }

    $self->log("[$name] Installing $role on $host...");

    # 1. Wait for SSH
    my $ssh = OCP::SSH->new(
        host     => $host,
        key_file => $self->_ssh_key_file->filename,
        user     => 'root',
    );
    eval { $ssh->wait_for_ssh(60) };
    if ($@) {
        $self->update_node_status($node, phase => 'Failed',
            message => "SSH not reachable: $@");
        return;
    }

    # 2. Run Rex task install_rke2_agent
    my $rex = OCP::Rex->new(
        host     => $host,
        key_file => $self->_ssh_key_file->filename,
        user     => 'root',
        verbose  => $self->verbose,
    );

    my $rke2_version = OCP::Versions->get_component_version('rke2');

    $self->update_node_status($node, phase => 'Installing',
        message => "Running RKE2 agent install");

    my $task = $self->distribution eq 'k3s'
        ? 'install_k3s_agent'
        : 'install_rke2_agent';

    my %params = (
        server    => $self->server_url,
        token     => $self->join_token,
        version   => $rke2_version,
        node_name => $name,
        hostname  => $name,
        ntp       => 1,
    );

    my $ok = eval { $rex->run_task($task, %params) };
    if (!$ok || $@) {
        $self->update_node_status($node, phase => 'Failed',
            message => "Rex task failed: " . ($@ // 'unknown'));
        return;
    }

    $self->update_node_status($node, phase => 'Joining',
        message => 'RKE2 agent installed, waiting for node registration');
}

sub wait_for_ready {
    my ($self, $node) = @_;

    my $name        = $node->{metadata}{name};
    my $k8s_name    = $node->{status}{kubernetesNodeName} // $name;

    # Query the cluster for this node
    my $k8s_node = eval {
        $self->kube->get(
            path => "/api/v1/nodes/$k8s_name",
        );
    };

    unless ($k8s_node) {
        $self->log("[$name] Not yet registered in cluster");
        return;
    }

    # Check Ready condition
    my $ready = 0;
    for my $cond (@{ $k8s_node->{status}{conditions} // [] }) {
        if ($cond->{type} eq 'Ready' && $cond->{status} eq 'True') {
            $ready = 1;
            last;
        }
    }

    if ($ready) {
        $self->log("[$name] Ready in cluster!");
        $self->update_node_status($node,
            phase              => 'Ready',
            kubernetesNodeName => $k8s_name,
            joinedAt           => _timestamp(),
            message            => 'Node joined and Ready',
        );
    } else {
        $self->log("[$name] Registered but not Ready yet");
    }
}

sub verify_node {
    my ($self, $node) = @_;
    # Periodic health check - for now just a no-op
}

#
# Kubernetes API helpers (Kubernetes::REST based)
#

sub list_ocp_nodes {
    my ($self) = @_;

    my $resp = $self->kube->get(
        path => "/apis/ocp.internal/v1/namespaces/" . $self->namespace . "/ocpnodes",
    );

    return $resp->{items} // [];
}

sub update_node_status {
    my ($self, $node, %patch) = @_;

    my $name = $node->{metadata}{name};
    my $ns   = $node->{metadata}{namespace} // $self->namespace;

    # Merge patch into existing status
    my $new_status = { %{ $node->{status} // {} }, %patch };

    my $body = { status => $new_status };

    eval {
        $self->kube->patch(
            path        => "/apis/ocp.internal/v1/namespaces/$ns/ocpnodes/$name/status",
            body        => $body,
            contentType => 'application/merge-patch+json',
        );
    };
    if ($@) {
        $self->log("  WARNING: failed to update status for $name: $@");
        return;
    }

    # Also update the in-memory copy so chained calls see the new phase
    $node->{status} = $new_status;

    $self->log("[$name] status: phase=" . ($patch{phase} // '(unchanged)')
             . ($patch{message} ? " ($patch{message})" : ""));
}

#
# Helpers
#

sub log {
    my ($self, $msg) = @_;
    my $ts = scalar localtime;
    print "[$ts] $msg\n";
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
        namespace    => 'ocp-system',
        kubeconfig   => '/path/to/kubeconfig.yaml',  # or undef for in-cluster
        ssh_key      => $robo_key_content,
        server_url   => 'https://192.168.122.1:9345',
        join_token   => $token,
        distribution => 'rke2',
    );

    $controller->run;  # blocks, polls OCPNodes, reconciles

=head1 DESCRIPTION

Watches OCPNode custom resources and reconciles them towards the desired state.
Currently supports the SSH provider (pre-existing reachable hosts). Handles
worker nodes only — control planes must be bootstrapped externally via
C<ocp apply>.

=head2 Reconciliation state machine

    Pending → Provisioning → Installing → Joining → Ready
                     └──────────────┴──────────→ Failed

=cut

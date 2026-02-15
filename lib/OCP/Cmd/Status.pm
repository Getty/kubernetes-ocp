package OCP::Cmd::Status;
# ABSTRACT: Show cluster status

use Moo;
use MooX::Cmd;
use MooX::Options;

use OCP::Config;

our $VERSION = '0.1.0';

option live => (
    is      => 'ro',
    short   => 'l',
    doc     => 'Check live status (SSH + K8s API)',
    default => 0,
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $chain->[0]->config;

    unless (-f $file) {
        die "Config file '$file' not found. Run 'ocp init' first.\n";
    }

    my $config = OCP::Config->new(file => $file);

    print "Cluster: ", $config->name, "\n";
    print "Config:  $file\n";
    print "\n";

    # Spec summary
    my $cp = $config->control_planes;
    my @workers = @{$config->workers};

    print "=== Spec ===\n";
    my $k8s = $config->kubernetes;
    my $dist = $k8s->{dist} || $k8s->{distribution} || 'rke2';
    my $version = $k8s->{version} || 'latest';
    print "Distribution: $dist $version\n";

    my $cp_nodes = $cp->{nodes} // $cp->{count} // 1;
    my $cp_provider = $cp->{provider} || 'hetzner';
    my $cp_type = $cp->{serverType} || 'ssh';
    print "Control Planes: $cp_nodes ($cp_type, $cp_provider)\n";

    for my $pool (@workers) {
        my $nodes = $pool->{nodes} // $pool->{count} // 0;
        my $provider = $pool->{provider} // 'ssh';
        print "Workers ($pool->{name}): $nodes ($provider)\n";
    }
    print "\n";

    # Status from .ocp/status.yaml
    my $nodes = $config->nodes_status;

    unless ($nodes && @$nodes) {
        print "=== Status ===\n";
        print "No nodes deployed yet. Run 'ocp apply' to deploy.\n";
        return;
    }

    print "=== Status ===\n";
    print "Last reconciled: ", ($config->last_reconciled // 'never'), "\n";
    print "Phase: ", $config->phase, "\n\n";

    printf "%-15s %-15s %-12s %-16s %s\n",
        'NAME', 'ROLE', 'PHASE', 'IP', 'PROVIDER';
    print "-" x 70, "\n";

    for my $node (@$nodes) {
        printf "%-15s %-15s %-12s %-16s %s\n",
            $node->{name} // '-',
            $node->{role} // '-',
            $node->{phase} // '-',
            $node->{publicIp} // '-',
            $node->{provider} // '-';
    }

    # Kubeconfig info
    my $cluster = $config->cluster_status;
    if ($cluster && $cluster->{kubeconfig}) {
        print "\nKubeconfig available. Export with: ocp kubeconfig\n";
    }
}

1;

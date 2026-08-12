package OCP::Cmd::Status;
# ABSTRACT: Show cluster status

use Moo;
use MooX::Cmd;
use MooX::Options;

use OCP;
use OCP::Config;
use OCP::Drift;
use OCP::Kubernetes;
use OCP::Secrets;
use OCP::Versions;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;

    unless (-f $file) {
        die "Config file '$file' not found. Run 'ocp init' first.\n";
    }

    my $config = OCP::Config->new(file => $file);

    print "Cluster: ", $config->name, "\n";
    print "Config:  $file\n";
    print "\n";

    # Spec summary
    my $cps = $config->control_planes;
    my @workers = @{$config->workers};

    print "=== Spec ===\n";
    # Show what would actually be installed, not the word 'latest' — an unpinned
    # version means the manifest decides, and that is a concrete number.
    my $dist = $config->distribution;
    my $dist_version = $config->version
        || OCP::Versions->get_component_version($dist)
        || 'latest';
    print "Distribution: $dist $dist_version\n";

    my $cp_count = scalar @$cps;
    my $cp_provider = $cps->[0]{provider} || 'hetzner';
    my $cp_type     = $cps->[0]{server_type};
    print "Control Planes: $cp_count (",
          join(', ', ($cp_type ? $cp_type : ()), $cp_provider), ")\n";

    for my $pool (@workers) {
        my $nodes = ref($pool->{nodes}) eq 'ARRAY' ? scalar(@{$pool->{nodes}}) : ($pool->{nodes} // $pool->{count} // 0);
        my $provider = $pool->{provider} // 'ssh';
        print "Workers ($pool->{name}): $nodes ($provider)\n";
    }
    print "\n";

    # Live status via the Kubernetes API (typed client)
    unless ($config->cluster_exists) {
        print "=== Status ===\n";
        print "No cluster deployed yet. Run 'ocp apply' to deploy.\n";
        return 0;
    }

    print "=== Status ===\n";
    print "Cluster exists (kubeconfig.yaml found)\n\n";

    # Decrypt kubeconfig to temp file
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    my $kc_content = $secrets->read_kubeconfig;

    unless ($kc_content) {
        print "ERROR: Cannot decrypt kubeconfig.yaml\n";
        print "Make sure .ocp/age.key exists.\n";
        return 1;
    }

    my $k8s = OCP::Kubernetes->new(kubeconfig => $kc_content);

    my $nodes = eval { $k8s->list_nodes };
    if (!$nodes || $@) {
        my $error = $@ || 'Unknown Kubernetes API error';
        print "WARNING: Cannot connect to cluster API\n";
        print "Error: $error\n";
        print "\nKubeconfig available. Export with: ocp kubeconfig -e\n";
        return 1;
    }
    my @nodes = @$nodes;

    unless (@nodes) {
        print "No nodes found in cluster.\n";
        return 0;
    }

    # Show nodes
    printf "%-20s %-10s %-20s %-16s %s\n",
        'NAME', 'STATUS', 'ROLES', 'VERSION', 'INTERNAL-IP';
    print "-" x 80, "\n";

    for my $node (@nodes) {
        my $name = $k8s->node_name($node);
        my $version = $k8s->node_version($node);
        my $ready = $k8s->node_ready($node) ? 'Ready' : 'NotReady';
        my $roles = $k8s->node_roles($node);
        my $internal_ip = $k8s->node_internal_ip($node);

        printf "%-20s %-10s %-20s %-16s %s\n",
            $name, $ready, $roles, $version, $internal_ip;
    }

    # GPU Status
    my $gpu_nodes = $k8s->gpu_nodes;
    if (@$gpu_nodes) {
        print "\n=== GPU Status ===\n";
        for my $gnode (@$gpu_nodes) {
            my $gname = $k8s->node_name($gnode);
            my $gcount = $k8s->node_gpu_count($gnode);
            printf "  %s: %dx NVIDIA GPU\n", $gname, $gcount;
        }
    }

    # Drift between what ocp.yaml/the version manifest say and what runs
    my $drift = eval {
        OCP::Drift->new(config => $config, api => $k8s->api)->detect;
    } // [];

    if (@$drift) {
        print "\n=== Drift ===\n";
        print "$_\n" for OCP::Drift->format_lines($drift);

        my $fixable = grep { $_->{remedy} } @$drift;
        print "\n$fixable of ", scalar(@$drift),
              " can be reconciled automatically: run 'ocp apply'.\n" if $fixable;
    }

    print "\n";
    print "Kubeconfig: ocp kubeconfig -e\n";

    return 0;
}

1;

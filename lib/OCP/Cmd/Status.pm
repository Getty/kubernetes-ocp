package OCP::Cmd::Status;
# ABSTRACT: Show cluster status

use Moo;
use MooX::Cmd;
use MooX::Options;
use JSON::MaybeXS;
use Path::Tiny qw(path);
use File::Temp;

use OCP;
use OCP::Config;
use OCP::Secrets;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

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
        my $nodes = ref($pool->{nodes}) eq 'ARRAY' ? scalar(@{$pool->{nodes}}) : ($pool->{nodes} // $pool->{count} // 0);
        my $provider = $pool->{provider} // 'ssh';
        print "Workers ($pool->{name}): $nodes ($provider)\n";
    }
    print "\n";

    # Live status via kubectl (BITSOW!)
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

    # Write to temp file
    my $kc_file = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_file $kc_content;
    close $kc_file;
    my $kc_path = $kc_file->filename;

    # Get nodes via kubectl (LIVE!)
    my $nodes_json = `kubectl --kubeconfig=$kc_path get nodes -o json 2>&1`;

    if ($? != 0) {
        print "WARNING: Cannot connect to cluster\n";
        print "Error: $nodes_json\n";
        print "\nKubeconfig available. Export with: ocp kubeconfig -e\n";
        return 1;
    }

    my $json = JSON::MaybeXS->new;
    my $data = eval { $json->decode($nodes_json) };

    if ($@ || !$data->{items}) {
        print "ERROR parsing kubectl output\n";
        return 1;
    }

    my @nodes = @{$data->{items}};

    unless (@nodes) {
        print "No nodes found in cluster.\n";
        return 0;
    }

    # Show nodes
    printf "%-20s %-10s %-15s %-12s %s\n",
        'NAME', 'STATUS', 'ROLES', 'VERSION', 'INTERNAL-IP';
    print "-" x 80, "\n";

    for my $node (@nodes) {
        my $name = $node->{metadata}{name};
        my $version = $node->{status}{nodeInfo}{kubeletVersion};

        # Status
        my $ready = 'NotReady';
        for my $cond (@{$node->{status}{conditions} // []}) {
            if ($cond->{type} eq 'Ready' && $cond->{status} eq 'True') {
                $ready = 'Ready';
                last;
            }
        }

        # Roles
        my $labels = $node->{metadata}{labels} // {};
        my @roles;
        push @roles, 'control-plane' if $labels->{'node-role.kubernetes.io/control-plane'};
        push @roles, 'master' if $labels->{'node-role.kubernetes.io/master'};
        my $roles = @roles ? join(',', @roles) : '<none>';

        # Internal IP
        my $internal_ip = '';
        for my $addr (@{$node->{status}{addresses} // []}) {
            if ($addr->{type} eq 'InternalIP') {
                $internal_ip = $addr->{address};
                last;
            }
        }

        printf "%-20s %-10s %-15s %-12s %s\n",
            $name, $ready, $roles, $version, $internal_ip;
    }

    print "\n";
    print "Kubeconfig: ocp kubeconfig -e\n";
    print "kubectl: kubectl --kubeconfig=.kube/config get pods -A\n";

    return 0;
}

1;

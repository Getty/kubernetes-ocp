package OCP::Cmd::DeployRobocop;
# ABSTRACT: Deploy robocop controller to the cluster

use Moo;
use MooX::Cmd;
use OCP;
use Path::Tiny qw(path);
use File::ShareDir::ProjectDistDir;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

sub execute {
    my ($self, $args, $chain) = @_;

    my $config_file = $self->ocp->config;
    my $config = OCP::Config->new(file => $config_file);

    unless ($config->cluster_exists) {
        die "No cluster deployed yet. Run 'ocp apply' first.\n";
    }

    print "╔═══════════════════════════════════════════════════════════════╗\n";
    print "║  DEPLOY ROBOCOP CONTROLLER                                   ║\n";
    print "╚═══════════════════════════════════════════════════════════════╝\n\n";

    print "This will deploy the robocop controller to your cluster.\n";
    print "Robocop will wait for robo-key injection before activating.\n\n";

    # Find manifests directory
    my $manifest_file;

    # Try local development path first
    my $local_manifest = path('manifests/robocop-deployment.yaml');
    if (-f $local_manifest) {
        $manifest_file = $local_manifest->stringify;
        print "[ok] Using local manifest: $manifest_file\n";
    } else {
        # Try installed location
        eval {
            my $dist_dir = File::ShareDir::ProjectDistDir::dist_dir('OCP');
            $manifest_file = path($dist_dir)->child('manifests/robocop-deployment.yaml')->stringify;
        };
        if ($@ || !-f $manifest_file) {
            die "ERROR: Could not find robocop deployment manifest!\n" .
                "       Looked in: manifests/robocop-deployment.yaml\n";
        }
        print "[ok] Using installed manifest: $manifest_file\n";
    }

    # Apply manifest
    print "[..] Deploying robocop to cluster...\n";

    my $ret = system('kubectl', 'apply', '-f', $manifest_file);

    if ($ret != 0) {
        die "ERROR: Failed to deploy robocop manifest!\n";
    }

    print "[ok] Robocop deployed to ocp-system namespace\n\n";

    # Wait for pod to be running
    print "[..] Waiting for robocop pod to start...\n";

    for my $i (1..30) {
        my $status = `kubectl get pod -n ocp-system -l app=robocop -o jsonpath='{.items[0].status.phase}' 2>/dev/null`;
        chomp $status;

        if ($status eq 'Running') {
            print "[ok] Robocop pod is running!\n\n";
            last;
        }

        print "    Waiting... ($i/30)\n";
        sleep(2);
    }

    print "╔═══════════════════════════════════════════════════════════════╗\n";
    print "║  ROBOCOP DEPLOYED (waiting for activation)                   ║\n";
    print "╚═══════════════════════════════════════════════════════════════╝\n\n";

    print "Robocop is deployed but NOT yet activated.\n";
    print "It is waiting for robo-key injection.\n\n";

    print "Next step:\n";
    print "  ocp inject-key  # Requires PIN2 (admin approval)\n\n";

    print "After key injection:\n";
    print "  - Robocop will create CRIU checkpoint in RAM\n";
    print "  - Robocop will start managing workers\n";
    print "  - You can add workers via CRDs (kubectl apply)\n\n";
}

1;

__END__

=head1 NAME

OCP::Cmd::DeployRobocop - Deploy robocop controller to the cluster

=head1 SYNOPSIS

    # Deploy robocop (no admin approval needed yet!)
    ocp deploy robocop

    # Then inject key (requires PIN2)
    ocp inject-key

=head1 DESCRIPTION

Deploys the robocop Kubernetes controller to the cluster.

Robocop will start but wait for robo-key injection before activating.

B<Security:> Deploying robocop does NOT require admin approval. However,
activating robocop (injecting the robo-key) DOES require PIN2.

=cut

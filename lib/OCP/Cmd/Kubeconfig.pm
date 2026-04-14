package OCP::Cmd::Kubeconfig;
# ABSTRACT: Export kubeconfig

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::Secrets;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

option export => (
    is    => 'ro',
    short => 'e',
    doc   => 'Export to ~/.kube/config',
);

option output => (
    is     => 'ro',
    format => 's',
    short  => 'o',
    doc    => 'Write to specific file',
);

option refresh => (
    is    => 'ro',
    short => 'r',
    doc   => 'Fetch fresh kubeconfig from server',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;

    unless (-f $file) {
        die "Config file '$file' not found.\n";
    }

    my $config = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $kubeconfig;

    if ($self->refresh) {
        # Fetch fresh kubeconfig from server (BITSOW - need to find CP IP!)
        # TODO: Implement refresh via Hetzner API or kubectl
        die "--refresh not yet implemented in v0. Use kubeconfig.yaml.\n";
    } else {
        # Decrypt kubeconfig.yaml (BITSOW!)
        unless ($config->cluster_exists) {
            die "No cluster deployed. Run 'ocp apply' first.\n";
        }

        $kubeconfig = $secrets->read_kubeconfig;

        unless ($kubeconfig) {
            die "Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n";
        }
    }

    if ($self->output) {
        # Write to specific file
        my $out_file = $self->output;
        path($out_file)->parent->mkpath;
        path($out_file)->spew($kubeconfig);
        path($out_file)->chmod(0600);
        print "Kubeconfig written to $out_file\n";
    } elsif ($self->export) {
        # Export to .kube/config (local project dir)
        my $kube_dir = $config->project_dir->child('.kube');
        $kube_dir->mkpath unless -d $kube_dir;
        my $kube_file = $kube_dir->child('config');

        $kube_file->spew($kubeconfig);
        $kube_file->chmod(0600);

        print "Kubeconfig exported to $kube_file\n";
        print "Use: export KUBECONFIG=.kube/config\n";
        print "Or:  kubectl --kubeconfig=.kube/config get nodes\n";
    } else {
        # Print to stdout
        print $kubeconfig;
    }

    return 0;
}

1;

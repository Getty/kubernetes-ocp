package OCP::Cmd::Kubeconfig;
# ABSTRACT: Export kubeconfig

use Moo;
use MooX::Cmd;
use MooX::Options;

use OCP::Config;

our $VERSION = '0.1.0';

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

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $chain->[0]->config;

    unless (-f $file) {
        die "Config file '$file' not found.\n";
    }

    my $config = OCP::Config->new(file => $file);
    my $cluster = $config->cluster_status;

    unless ($cluster && $cluster->{kubeconfig}) {
        die "No kubeconfig available. Run 'ocp apply' first.\n";
    }

    my $kubeconfig = $cluster->{kubeconfig};

    if ($self->output) {
        # Write to specific file
        my $out_file = $self->output;
        open my $fh, '>', $out_file or die "Cannot write $out_file: $!";
        print $fh $kubeconfig;
        close $fh;
        chmod 0600, $out_file;
        print "Kubeconfig written to $out_file\n";
    } elsif ($self->export) {
        # Export to ~/.kube/config
        my $kube_dir = "$ENV{HOME}/.kube";
        mkdir $kube_dir unless -d $kube_dir;

        my $kube_file = "$kube_dir/config";
        open my $fh, '>', $kube_file or die "Cannot write $kube_file: $!";
        print $fh $kubeconfig;
        close $fh;
        chmod 0600, $kube_file;

        print "Kubeconfig exported to $kube_file\n";
    } else {
        # Print to stdout
        print $kubeconfig;
    }
}

1;

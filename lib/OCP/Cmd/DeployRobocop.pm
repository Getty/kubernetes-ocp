package OCP::Cmd::DeployRobocop;
# ABSTRACT: Deploy robocop controller to the cluster

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use YAML::XS ();
use File::Temp ();
use Kubernetes::REST::Kubeconfig;

use OCP;
use OCP::Config;
use OCP::Secrets;
use OCP::Share;

with 'OCP::Role::Cmd';

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config  = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $kc_content = $secrets->read_kubeconfig;
    die "ERROR: Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
        unless $kc_content;

    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$kc_fh} $kc_content;
    close $kc_fh;

    my $api = Kubernetes::REST::Kubeconfig->new(
        kubeconfig_path => $kc_fh->filename,
    )->api;

    my $share_dir = $self->_find_share_dir;
    my $robocop_dir = $share_dir->child('robocop');
    die "Robocop manifests not found under $robocop_dir\n" unless -d $robocop_dir;

    my @crd_files   = sort $robocop_dir->child('crds')->children(qr/\.ya?ml$/);
    my @other_files = grep { $_->basename ne 'kustomization.yaml' }
                           $robocop_dir->children(qr/\.ya?ml$/);

    for my $file_path (@crd_files, @other_files) {
        my @docs = YAML::XS::LoadFile($file_path->stringify);
        for my $doc (@docs) {
            next unless ref $doc eq 'HASH' && $doc->{kind} && $doc->{metadata}{name};
            my $kind = $doc->{kind};
            my $name = $doc->{metadata}{name};
            $api->ensure($doc);
            print "  [ok] ensured $kind/$name\n";
        }
    }

    print "Robocop deployed.\n";
    return 0;
}

sub _find_share_dir {
    my ($self) = @_;
    return OCP::Share->dir;
}

1;

__END__

=head1 NAME

OCP::Cmd::DeployRobocop - Deploy robocop controller to the cluster

=head1 SYNOPSIS

    ocp deploy-robocop

Reads manifests from the OCP share directory (C<share/robocop/>), applies CRDs
first and then remaining resources (skipping C<kustomization.yaml>) via
L<Kubernetes::REST/ensure> against the encrypted kubeconfig for the current
project.

=cut

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
use OCP::Robocop::Manifest;
use OCP::Secrets;
use OCP::Share;

with 'OCP::Role::Cmd';
# The robocop-credentials Secret -- one implementation, shared with `ocp
# apply` (k169). deploy-robocop always writes it: running this command is the
# way to refresh it.
with 'OCP::Role::Cmd::RobocopCredentials';

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config  = OCP::Config->new(file => $file);

    # The key-delivery model decides what goes into the Secret and which
    # Deployment variant is applied (inject: no private key in either, k2).
    my $level = $config->robocop_security_level;

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

    # Populate the credentials Secret the controller mounts. Done before the
    # manifests so the namespace and Secret exist by the time the Deployment's
    # pods start; a pod that races ahead restarts and self-heals.
    $self->_apply_credentials_secret($api, $config, $secrets, $level);

    $self->_apply_manifests($api, $config);

    print "Robocop deployed.\n";
    print "robocop holds no SSH key yet (security_level inject): run "
        . "'ocp inject-key' once the pod is running.\n"
        if $level eq 'inject';
    return 0;
}

# CRDs first, then the rest of share/robocop/ (skipping kustomization.yaml),
# each document shaped from the config (OCP::Robocop::Manifest->for_config):
# the security level's variant, plus the distribution and pod CIDR robocop
# refuses to start without (k186, k184).
sub _apply_manifests {
    my ($self, $api, $config) = @_;

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
            $api->ensure(OCP::Robocop::Manifest->for_config($doc, $config));
            print "  [ok] ensured $kind/$name\n";
        }
    }
    return;
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

Before the manifests, populates the C<robocop-credentials> Secret in
C<ocp-system> that the controller mounts (k129), through
L<OCP::Role::Cmd::RobocopCredentials> -- the same code C<ocp apply> uses. Per
C<robocop.security_level> it writes three keys: C<robo-ssh-key> (the decrypted
private robo key), C<server-url> (the RKE2 join URL) and C<rke2-token> (the
node-join token, read off the control-plane disk over SSH). C<secret> gates the
write behind PIN1 for the age key and whatever key reaches the control plane;
C<secret_approved> additionally requires an explicit PIN2 admin approval, reused
for the SSH read. C<inject> writes C<robo-ssh-public-key> (the public half)
instead of C<robo-ssh-key>, applies the inject variant of the Deployment (see
L<OCP::Robocop::Manifest>) and leaves the private key to C<ocp inject-key>.

Then reads manifests from the OCP share directory (C<share/robocop/>), applies
CRDs first and then remaining resources (skipping C<kustomization.yaml>) via
L<Kubernetes::REST/ensure> against the encrypted kubeconfig for the current
project. The Deployment carries the cluster's distribution and pod CIDR from
F<ocp.yaml> (C<OCP_DISTRIBUTION>, C<OCP_POD_CIDR>); robocop does not start
without them.

=cut

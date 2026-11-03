package OCP::Cmd::DeployRobocop;
# ABSTRACT: Deploy robocop controller to the cluster

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use YAML::XS ();

use OCP;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::K8s ();
use OCP::Config;
use OCP::Robocop::Manifest;
use OCP::Secrets;
use OCP::Share;

with 'OCP::Role::Cmd';
# The robocop-credentials Secret -- one implementation, shared with `ocp
# apply` (k169). deploy-robocop always writes it: running this command is the
# way to refresh it.
with 'OCP::Role::Cmd::RobocopCredentials';

# What deploy-robocop reads of ocp.yaml, declared as its spec_paths:
# OCP::Role::Cmd refuses their lines, validate()'s own, before anything is
# asked or sent (k400). robocop.security_level picks the Secret and the
# Deployment variant; the credentials read the first control plane's address
# (cluster_status) and the bootstrap key's path (ssh:, cluster_ssh_key); the
# Deployment carries robocop.image, the distribution (kubernetes) and the pod
# CIDR (network.pod_cidr, OCP::Robocop::Manifest).
sub spec_paths {
    return (
        'robocop', 'robocop.security_level', 'robocop.image',
        'control_planes', 'control_planes[1]',
        map({ "control_planes[1].$_" } qw( provider public_ip host name )),
        'ssh', 'kubernetes', 'network', 'network.pod_cidr',
    );
}

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config  = OCP::Config->new(file => $file);

    # The key-delivery model decides what goes into the Secret and which
    # Deployment variant is applied (inject: no private key in either, k2).
    my $level = $config->robocop_security_level;

    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    # The key, kubeconfig.yaml, the client and one GET /version: an API that
    # does not answer, or answers /version with an error, is said there, in
    # one line (k389, k399).
    my $api = $self->cluster_api;

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
# refuses to start without (k186, k184). A CRD in the cluster that is newer
# than this ocp is left as it is, judged and said the way `ocp apply` does
# (OCP::Cmd::Apply::CR::skip_newer_crd, k311); one that cannot be read dies
# with the cause.
sub _apply_manifests {
    my ($self, $api, $config) = @_;

    my $share_dir = $self->_find_share_dir;
    my $robocop_dir = $share_dir->child('robocop');
    die "Robocop manifests not found under $robocop_dir\n" unless -d $robocop_dir;

    my @crd_files   = sort $robocop_dir->child('crds')->children(qr/\.ya?ml$/);
    my @other_files = grep { $_->basename ne 'kustomization.yaml' }
                           $robocop_dir->children(qr/\.ya?ml$/);

    if (defined(my $notice = OCP::Robocop::Manifest->image_notice($config))) {
        print "  $notice\n";
    }

    for my $file_path (@crd_files, @other_files) {
        my @docs = YAML::XS::LoadFile($file_path->stringify);
        for my $doc (@docs) {
            next unless ref $doc eq 'HASH' && $doc->{kind} && $doc->{metadata}{name};
            my $kind = $doc->{kind};
            my $name = $doc->{metadata}{name};
            next if OCP::Cmd::Apply::CR::skip_newer_crd($self, $api, $doc);
            $api->ensure(OCP::Robocop::Manifest->for_config($doc, $config));
            print "  [ok] ensured $kind/$name\n";
        }
    }
    OCP::Cmd::Apply::CR::retire_unannotated_robocop_pods($self, $api);
    return;
}

sub _find_share_dir {
    my ($self) = @_;
    return OCP::Share->dir;
}

# The raw read skip_newer_crd judges a CRD by, as OCP::Cmd::Apply has it:
# undef only for a 404, a death with the cause for anything else (k269).
sub _crd_get {
    my ($self, $api, $resource_path) = @_;
    return OCP::Cmd::Apply::K8s::crd_get($self, $api, $resource_path);
}

1;

__END__

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
project. A CRD in the cluster that declares fields this ocp's does not -- one
a newer ocp installed -- is left as it is, with the C<[skip]> line C<ocp apply>
gives it (L<OCP::Cmd::Apply::CR>, k311); a CRD it cannot read stops the
command with the cause instead of being written over blind. The Deployment
carries the cluster's distribution and pod CIDR from F<ocp.yaml>
(C<OCP_DISTRIBUTION>, C<OCP_POD_CIDR>); robocop does not start without them.

Before any of it, what it reads of F<ocp.yaml> -- C<robocop>, the first
control plane, C<ssh>, C<kubernetes> and C<network.pod_cidr> -- is checked,
and a value L<OCP::Config/validate> refuses there stops it with that line
before a PIN is asked (L<OCP::Role::Cmd/refuse_spec_errors>, C<k400>).

=cut

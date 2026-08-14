package OCP::Cmd::DeployImage;
# ABSTRACT: Roll out a new robocop image into the running cluster

use Moo;
use MooX::Cmd;
use MooX::Options;

use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use Time::Piece ();

use OCP;
use OCP::Config;
use OCP::K8s;
use OCP::Secrets;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

# --- Defaults --------------------------------------------------------------
#
# Verified against share/robocop/deployment.yaml:
#   metadata.namespace: ocp-system
#   metadata.name:      robocop
#   containers[0].name: controller
#
# OCP today is a one-cluster-per-spec tool, so --cluster has nothing to choose
# between -- but it does let CI override the target without rewriting the spec.
#
# The image repo defaults to raudssus/ocp (the project's public registry).
# Override via --repo on the CLI or OCP_IMAGE_REPO in the environment; this is
# the path for air-gapped registries and forks without touching the spec.

our $DEFAULT_NAMESPACE = 'ocp-system';
our $DEFAULT_REPO      = 'raudssus/ocp';

# --- Options ---------------------------------------------------------------

=opt tag

    --tag TAG

Image tag (e.g. C<v1.2.3>, C<latest>). Combined with the repository as
C<< <repo>:<tag> >>. Required.

=cut

option tag => (
    is       => 'ro',
    format   => 's',
    required => 1,
    doc      => 'Image tag, e.g. v1.2.3 (combined with --repo as REPO:TAG)',
);

=opt repo

    --repo REPO

Image repository (default: C<raudssus/ocp>, or C<OCP_IMAGE_REPO>).

=cut

option repo => (
    is     => 'ro',
    format => 's',
    doc    => 'Image repository (default: raudssus/ocp or OCP_IMAGE_REPO)',
);

=opt cluster

    --cluster NAME

Cluster name to operate on (default: the single cluster in C<ocp.yaml>,
or C<OCP_CLUSTER>). Must match the spec name.

=cut

option cluster => (
    is     => 'ro',
    format => 's',
    doc    => 'Cluster name (default: ocp.yaml spec, or OCP_CLUSTER env)',
);

=opt namespace

    --namespace NS

Namespace of the robocop Deployment (default: C<ocp-system>).

=cut

option namespace => (
    is     => 'ro',
    format => 's',
    doc    => 'Namespace of the robocop deployment (default: ocp-system)',
);

=opt wait

    --wait

Wait until every robocop pod is Ready before returning. Use C<--timeout> to
cap the wait.

=cut

option wait => (
    is      => 'ro',
    is_bool => 1,
    doc     => 'Wait until all robocop pods are Ready before returning',
);

=opt timeout

    --timeout SECONDS

Maximum wait time when C<--wait> is set (default: C<300>). Ignored unless
C<--wait> is given.

=cut

option timeout => (
    is     => 'ro',
    format => 'i',
    doc    => 'Wait timeout in seconds (default: 300, requires --wait)',
);

=opt restart

    --restart / --no_restart

Trigger a rollout restart by patching the
C<kubectl.kubernetes.io/restartedAt> annotation (default: on). Pass
C<--no_restart> to update the image without restarting.

=cut

# `is_bool => 1` makes MooX::Options treat the flag as boolean; the leading
# `--no-` is peeled off before dash/underscore substitution, so --no_restart
# negates this attribute. The default keeps the legacy "patch and restart"
# behaviour; pass --no_restart to leave the old pod running.
option restart => (
    is      => 'ro',
    is_bool => 1,
    default => 1,
    doc     => 'Trigger rollout restart via annotation (default: on; --no_restart to skip)',
);

# Tests override the sleep interval to keep the suite fast; production uses
# the documented 5-second poll cadence.
has _poll_interval => (
    is      => 'rw',
    default => 5,
);

# --- Execute ---------------------------------------------------------------

=method execute

    $cmd->execute($args, $chain)

Reads the encrypted C<kubeconfig.yaml>, patches the robocop Deployment's
container image, optionally restarts the pods via the
C<kubectl.kubernetes.io/restartedAt> annotation, and optionally waits until
all robocop pods are Ready.

Returns C<0> on success, C<1> on a wait timeout. Dies loud on a missing
project, missing kubeconfig, missing Deployment, or a mismatching
C<--cluster>.

=cut

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config = OCP::Config->new(file => $file);

    if (defined $self->timeout && !$self->wait) {
        die "--timeout is only valid with --wait\n";
    }

    my $cluster = $self->_resolve_cluster($config);
    my $ns      = $self->namespace // $DEFAULT_NAMESPACE;
    my $repo    = $self->repo // $ENV{OCP_IMAGE_REPO} // $DEFAULT_REPO;
    my $image   = $repo . ':' . $self->tag;

    print "Cluster:  $cluster\n";
    print "Namespace: $ns\n";
    print "Image:    $image\n";
    print "\n";

    my $api = $self->_build_api($config);

    # Fail loud if the Deployment isn't there -- patching nothing is the kind
    # of silent success that turns a deploy outage into a "wait why didn't
    # anything roll out?" mystery tomorrow morning.
    my $existing = eval { $api->get('Deployment', 'robocop', namespace => $ns) };
    die "robocop Deployment not found in namespace '$ns'. "
      . "Run 'ocp deploy-robocop' first.\n"
        unless $existing;

    $self->_patch_image($api, $ns, $image);

    if ($self->restart) {
        $self->_patch_restart($api, $ns);
    }
    else {
        print "[--] rollout restart skipped (--no_restart)\n";
    }

    if ($self->wait) {
        my $timeout = $self->timeout // 300;
        return $self->_wait_for_ready($api, $ns, $timeout) ? 0 : 1;
    }

    return 0;
}

# --- Internals -------------------------------------------------------------

sub _resolve_cluster {
    my ($self, $config) = @_;

    my $spec_name = $config->name;

    # OCP is single-cluster-per-spec today. Detect a future multi-cluster spec
    # by walking the spec for any unexpected 'clusters' / 'cluster' keys; if we
    # find more than one entry we fail loud with the list, exactly as the
    # ticket asks.
    my $spec = $config->spec;
    my @spec_clusters;
    if (ref $spec eq 'HASH') {
        for my $key (qw(clusters cluster)) {
            push @spec_clusters, @{ $spec->{$key} // [] }
                if ref $spec->{$key} eq 'ARRAY';
        }
    }
    if (@spec_clusters > 1 && !$self->cluster && !$ENV{OCP_CLUSTER}) {
        die "Multiple clusters in ocp.yaml but no --cluster given: "
          . join(', ', map { $_->{name} // '?' } @spec_clusters) . "\n";
    }

    my $chosen = $self->cluster // $ENV{OCP_CLUSTER} // $spec_name;

    if ($self->cluster && defined $ENV{OCP_CLUSTER} && $self->cluster ne $ENV{OCP_CLUSTER}) {
        die "--cluster '$self->cluster' contradicts OCP_CLUSTER='$ENV{OCP_CLUSTER}'\n";
    }

    return $chosen;
}

sub _build_api {
    my ($self, $config) = @_;

    my $secrets    = OCP::Secrets->new(project_dir => $config->project_dir);
    my $kc_content = $secrets->read_kubeconfig;
    die "Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
        unless $kc_content;

    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$kc_fh} $kc_content;
    close $kc_fh;

    # Keep the temp file alive on the instance -- without an anchor the
    # File::Temp destructor unlinks it before Kubernetes::REST reads it.
    $self->{_kc_temp} = $kc_fh;

    my $api = Kubernetes::REST::Kubeconfig->new(
        kubeconfig_path => $kc_fh->filename,
    )->api;

    OCP::K8s->register($api);
    return $api;
}

# Strategic merge by container name: addresses the controller container in
# place, leaves siblings and unrelated fields alone. Matches what `kubectl
# set image deployment/robocop controller=...` does on the wire.
sub _patch_image {
    my ($self, $api, $ns, $image) = @_;

    $api->patch(
        'Deployment', 'robocop',
        namespace => $ns,
        patch => {
            spec => {
                template => {
                    spec => {
                        containers => [
                            { name => 'controller', image => $image },
                        ],
                    },
                },
            },
        },
        type => 'strategic',
    );

    print "[ok] image patched to $image\n";
}

# kubectl rollout restart's wire form: a strategic merge that adds/updates
# exactly one annotation. Annotation maps merge by key, so a stale value is
# replaced and unrelated annotations survive.
sub _patch_restart {
    my ($self, $api, $ns) = @_;

    my $now = Time::Piece::gmtime->strftime('%Y-%m-%dT%H:%M:%SZ');

    $api->patch(
        'Deployment', 'robocop',
        namespace => $ns,
        patch => {
            spec => {
                template => {
                    metadata => {
                        annotations => {
                            'kubectl.kubernetes.io/restartedAt' => $now,
                        },
                    },
                },
            },
        },
        type => 'strategic',
    );

    print "[ok] rollout restart triggered (restartedAt=$now)\n";
}

# Poll the Deployment's status until the new generation is observed AND every
# desired replica is available. observedGeneration guards against reporting
# success on a stale status object; availableReplicas >= replicas guards
# against reporting success on a mid-recreate (Recreate briefly drops
# availableReplicas to 0 -- exactly the window we want to keep polling).
sub _wait_for_ready {
    my ($self, $api, $ns, $timeout) = @_;

    my $interval = $self->_poll_interval;
    my $deadline = time + $timeout;

    while (time < $deadline) {
        my $deploy = eval { $api->get('Deployment', 'robocop', namespace => $ns) };
        if ($deploy) {
            my $h = $api->k8s->object_to_struct($deploy);
            my $available  = $h->{status}{availableReplicas}  // 0;
            my $replicas   = $h->{spec}{replicas}             // 1;
            my $observed   = $h->{status}{observedGeneration} // 0;
            my $generation = $h->{metadata}{generation}       // 0;

            if ($available >= $replicas && $observed >= $generation) {
                print "[ok] robocop is Ready ($available/$replicas replica(s))\n";
                return 1;
            }
        }

        last if time >= $deadline;
        sleep $interval if $interval > 0;
    }

    print STDERR "Timed out after ${timeout}s waiting for robocop to be Ready\n";
    return 0;
}

1;

__END__

=synopsis

    ocp deploy-image --tag v1.2.3
    ocp deploy-image --tag latest --wait
    ocp deploy-image --tag v1.2.3 --no_restart
    ocp deploy-image --tag v1.2.3 --wait --timeout 60
    ocp deploy-image --tag v1.2.3 --repo my-registry.example/ocp

=description

Updates the running robocop Deployment to a new image without touching
C<kubectl> (ADR 0007: no kubectl in code paths).

The default target is the C<robocop> Deployment in the C<ocp-system>
namespace on the cluster named in the project's C<ocp.yaml>. Two patches
are issued against the live Deployment:

=over 4

=item 1.

A strategic-merge patch that addresses the C<controller> container by name
and updates only its C<image> field. Sibling containers and the rest of the
pod template are left untouched.

=item 2.

When C<--restart> is in effect (the default), a second strategic-merge patch
writes C<spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"]>
to the current UTC timestamp -- exactly what C<kubectl rollout restart
deployment/robocop> does on the wire. Pass C<--no_restart> to update the
image without rolling the pods.

=back

If C<--wait> is set the command polls the Deployment's status until
C<status.observedGeneration> catches up with C<metadata.generation> AND
C<status.availableReplicas> reaches C<spec.replicas>, capped by C<--timeout>
seconds (default C<300>). On success the exit status is C<0>; on timeout it
is C<1>.

The image repository is C<raudssus/ocp> by default; override via
C<--repo REPO> on the command line or C<OCP_IMAGE_REPO> in the environment.
The final image string is always C<< REPO:TAG >>.

B<Pre-requisites:> the cluster must already be able to pull from the
target repository (imagePullSecret, public registry, etc.) -- this command
does not configure credentials.

=method execute

See L</execute> in the inline =method block above.

=seealso

L<OCP::Cmd::DeployRobocop>, L<OCP::K8s>, L<Kubernetes::REST>, L<OCP::Config>

=cut

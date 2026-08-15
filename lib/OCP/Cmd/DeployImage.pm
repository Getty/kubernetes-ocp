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

=opt image

    --image REF

Shorthand for the full image reference. Accepts the tag form
C<< <repo>:<tag> >> (e.g. C<ghcr.io/foo/bar:v1.2.3>, or C<foo/bar:v1.2.3> with
implicit Docker Hub) and the digest form C<< <repo>@sha256:<64hex> >> for
content-addressable rollouts. Mutually exclusive with both C<--repo> and
C<--tag>.

=cut

option image => (
    is     => 'ro',
    format => 's',
    doc    => 'Full image reference: REPO:TAG or REPO@sha256:DIGEST (mutually exclusive with --repo/--tag)',
);

=opt tag

    --tag TAG

Image tag (e.g. C<v1.2.3>, C<latest>). Combined with the repository as
C<< <repo>:<tag> >>. Mutually exclusive with C<--image>; together with
C<--repo> it forms the legacy two-flag form.

=cut

option tag => (
    is     => 'ro',
    format => 's',
    doc    => 'Image tag, e.g. v1.2.3 (combined with --repo as REPO:TAG; mutually exclusive with --image)',
);

=opt repo

    --repo REPO

Image repository (default: C<raudssus/ocp>, or C<OCP_IMAGE_REPO>).
Mutually exclusive with C<--image>.

=cut

option repo => (
    is     => 'ro',
    format => 's',
    doc    => 'Image repository (default: raudssus/ocp or OCP_IMAGE_REPO; mutually exclusive with --image)',
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
    --no-wait

Wait until every robocop pod is Ready before returning. Use C<--timeout> to
cap the wait. Off by default; C<--no-wait> states that explicitly.

=cut

# `negatable` is what makes Getopt::Long accept the --no- form: it puts the
# `!` in the option spec, and it is also the flag MooX::Options checks before
# it hands a stripped `--no-` back as a negation rather than as part of the
# name. Without it `--no-wait` died with "Unknown option: no_wait" — see
# `nowait` in OCP::Cmd::Node::Add for the other half of that trap. The default
# is unchanged: no waiting unless asked.
option wait => (
    is        => 'ro',
    negatable => 1,
    doc       => 'Wait until all robocop pods are Ready before returning (default: off)',
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

    --restart / --no-restart

Trigger a rollout restart by patching the
C<kubectl.kubernetes.io/restartedAt> annotation (default: on). Pass
C<--no-restart> to update the image without restarting.

=cut

# `negatable` is what turns the attribute into a real on/off pair. It used to
# say `is_bool => 1`, which MooX::Options does not know at all — the key was
# handed straight through to `has` and quietly ignored, so the documented
# --no_restart had no spelling that worked and the flag could not be switched
# off from the command line. The default keeps the "patch and restart"
# behaviour; --no-restart leaves the old pod running.
option restart => (
    is        => 'ro',
    negatable => 1,
    default   => 1,
    doc       => 'Trigger rollout restart via annotation (default: on; --no-restart to skip)',
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

    # Mutual exclusion + at-least-one guard. We do this once at the top so
    # every downstream branch can assume either (--image) xor (--repo + --tag)
    # and never the awkward middle of "both filled in partially".
    if ($self->image) {
        if (defined $self->tag) {
            die "--image and --tag are mutually exclusive -- pass them as one ref, e.g. --image ghcr.io/foo/bar:\${tag}\n";
        }
        if (defined $self->repo) {
            die "--image and --repo are mutually exclusive -- the repo part of --image already names the registry\n";
        }
    }
    elsif (!defined $self->tag) {
        die "either --image or --tag is required\n";
    }

    # Resolve (repo, tag, optional digest) from whichever flag path the
    # caller chose. --image takes precedence and is parsed here; the
    # --repo + --tag path stays backwards-compatible.
    my ($repo, $tag, $digest);
    if ($self->image) {
        my $parsed     = $self->_parse_image_ref($self->image);
        $repo   = $parsed->{repo};
        $tag    = $parsed->{tag};
        $digest = $parsed->{digest};
    }
    else {
        $repo = $self->repo // $ENV{OCP_IMAGE_REPO} // $DEFAULT_REPO;
        $tag  = $self->tag;
    }

    # Docker accepts both "repo:tag" and "repo@digest" -- keep the separator
    # the user gave us, since the cluster's pull resolver treats them
    # differently (digest is content-addressable, tag is mutable).
    my $image = defined $digest ? "$repo\@$digest" : "$repo:$tag";

    my $cluster = $self->_resolve_cluster($config);
    my $ns      = $self->namespace // $DEFAULT_NAMESPACE;

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
        print "[--] rollout restart skipped (--no-restart)\n";
    }

    if ($self->wait) {
        my $timeout = $self->timeout // 300;
        return $self->_wait_for_ready($api, $ns, $timeout) ? 0 : 1;
    }

    return 0;
}

# --- Internals -------------------------------------------------------------

=method _parse_image_ref

    my $parts = $cmd->_parse_image_ref('ghcr.io/foo/bar:v1.2.3');
    # $parts->{repo} = 'ghcr.io/foo/bar'
    # $parts->{tag}  = 'v1.2.3'

    my $digest = $cmd->_parse_image_ref('foo/bar@sha256:<64hex>');
    # $digest->{repo}   = 'foo/bar'
    # $digest->{digest} = 'sha256:<64hex>'

Splits an image reference into its parts. Pure function -- no instance
state is read, so it is also exposed for direct testing:

    OCP::Cmd::DeployImage->_parse_image_ref('ghcr.io/foo/bar:v1.2.3');

Recognises both the tag form C<< <repo>:<tag> >> and the digest form
C<< <repo>@sha256:<64-hex> >>. Dies loud on every malformed input. The
deliberate non-feature is the rejection of a bare C<REPO> without tag or
digest: there is no implicit C<latest>, because content-addressable
deploys want a name and a number, not a moving target.

=cut

# Pure parsing helper: takes a string like "ghcr.io/foo/bar:v1.2.3" or
# "foo/bar@sha256:<64hex>" and returns {repo => ..., tag => ...} or
# {repo => ..., digest => ...}. We accept this as a class-method-shaped sub
# (no $self state needed) so t/54-deploy-image.t can call it directly without
# going through execute(). Failloud with a precise message on every malformed
# input -- we deliberately do NOT default to 'latest' because content-
# addressable deploys need explicit pins.
sub _parse_image_ref {
    my ($class_or_self, $ref) = @_;

    # First arg is the class or instance; we don't read its state. Keeping
    # the signature as a method lets both call sites share the same code:
    #   $self->_parse_image_ref($self->image)        # runtime
    #   OCP::Cmd::DeployImage->_parse_image_ref(...) # tests
    $ref = defined $ref ? "$ref" : '';

    die "_parse_image_ref: empty image reference\n"
        if $ref eq '';

    die "_parse_image_ref: image reference cannot start with ':' or '@' (got '$ref')\n"
        if $ref =~ /^[:@]/;

    # Digest form: REPO@sha256:<64hex>. Reject anything that smells like
    # a tag bolted onto a digest, and reject any digest whose hex part is
    # the wrong length -- the lazy "@sha256:abc" shortcut has wasted enough
    # mornings already.
    if ($ref =~ /\@/) {
        my ($repo_part, $after) = split /\@/, $ref, 2;
        die "_parse_image_ref: empty repository in '$ref'\n"
            unless defined $repo_part && $repo_part ne '';
        die "_parse_image_ref: multiple '@' in '$ref'\n"
            if $after =~ /\@/;
        die "_parse_image_ref: digest ref must not carry a ':' / tag (got '$ref')\n"
            if $repo_part =~ /:/;
        die "_parse_image_ref: invalid digest format in '$ref' (expected sha256:<64 hex chars>)\n"
            unless $after =~ /\Asha256:[a-f0-9]{64}\z/;
        return { repo => $repo_part, digest => $after };
    }

    # Tag form: REPO:TAG. Split on the LAST ':' so registry:port survives
    # intact (ghcr.io:5000/foo:bar -> repo=ghcr.io:5000/foo, tag=bar).
    die "_parse_image_ref: missing tag or digest in '$ref' -- no implicit 'latest' here, pin the version you want\n"
        unless $ref =~ /:/;

    my $i    = rindex $ref, ':';
    my $repo = substr($ref, 0, $i);
    my $tag  = substr($ref, $i + 1);

    die "_parse_image_ref: empty repository in '$ref'\n"
        unless defined $repo && $repo ne '';
    die "_parse_image_ref: empty tag in '$ref'\n"
        unless defined $tag && $tag ne '';

    # foo/bar:baz/qux is ambiguous -- the slash could belong to the repo path
    # or to the tag. Force callers to disambiguate by writing the registry
    # explicitly (ghcr.io/foo/bar:baz/qux parses cleanly because 'ghcr.io'
    # anchors the repo side).
    if ($tag =~ m{/}) {
        my ($first) = split m{/}, $repo, 2;
        unless ($first =~ /\./ || $first eq 'localhost') {
            die "_parse_image_ref: ambiguous tag-with-slashes in '$ref' -- add an explicit registry prefix (e.g. registry.example/foo/bar:tag)\n";
        }
    }

    return { repo => $repo, tag => $tag };
}

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
    ocp deploy-image --tag v1.2.3 --no-restart
    ocp deploy-image --tag v1.2.3 --wait --timeout 60
    ocp deploy-image --tag v1.2.3 --repo my-registry.example/ocp
    ocp deploy-image --image ghcr.io/foo/bar:v1.2.3
    ocp deploy-image --image ghcr.io/foo/bar@sha256:<64hex>

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
deployment/robocop> does on the wire. Pass C<--no-restart> to update the
image without rolling the pods.

=back

If C<--wait> is set the command polls the Deployment's status until
C<status.observedGeneration> catches up with C<metadata.generation> AND
C<status.availableReplicas> reaches C<spec.replicas>, capped by C<--timeout>
seconds (default C<300>). On success the exit status is C<0>; on timeout it
is C<1>.

The image is specified either as the full reference via C<--image REF>
(tag form C<REPO:TAG> or digest form C<REPO@sha256:<64hex>>) or as the
two-flag pair C<--repo REPO --tag TAG>. Reach for C<--image> when you have
the reference at hand; reach for C<--repo>/C<--tag> when only one half
changes (e.g. promoting the same tag across registries without rewriting
the tag value). C<--image> is mutually exclusive with both C<--repo> and
C<--tag> -- a digest or tag cannot be combined with the pre-split flags.

The image repository defaults to C<raudssus/ocp> when neither C<--image>
nor C<--repo> is given; override via the environment with C<OCP_IMAGE_REPO>.
A digest form pins the rollout to a content-addressable identifier
(C<repo@sha256:<64hex>>); a tag form is mutable. Both produce a normal
strategic-merge patch on the C<image> field.

B<Pre-requisites:> the cluster must already be able to pull from the
target repository (imagePullSecret, public registry, etc.) -- this command
does not configure credentials.

=method execute

See L</execute> in the inline =method block above.

=seealso

L<OCP::Cmd::DeployRobocop>, L<OCP::K8s>, L<Kubernetes::REST>, L<OCP::Config>

=cut

package OCP::Robocop::Controller;
# ABSTRACT: Kubernetes controller for OCP nodes

use Moo;
use Carp qw(croak);
use File::Temp ();
use IO::Async::Loop;
use IO::K8s;
use Net::Async::Kubernetes;
use Scalar::Util qw(weaken);
use Time::Piece ();
use Try::Tiny;

use OCP::K8s;
use OCP::Kubernetes;
use OCP::Node;
use OCP::Provider;

#
# Configuration
#

has namespace => (
    is      => 'ro',
    default => 'ocp-system',
);

has kubeconfig => (
    is  => 'ro',
    doc => 'Kubeconfig content or file path (for out-of-cluster testing)',
);

has ssh_key => (
    is       => 'ro',
    required => 1,
    doc      => 'SSH private key content (robo-key)',
);

has server_url => (
    is       => 'ro',
    required => 1,
    doc      => 'RKE2 server URL, e.g. https://192.168.122.1:9345',
);

has join_token => (
    is       => 'ro',
    required => 1,
    doc      => 'RKE2 node join token',
);

has distribution => (
    is      => 'ro',
    default => 'rke2',
);

has watch_timeout => (
    is      => 'ro',
    default => 300,   # seconds: server-side watch cycle, then reconnect
);

has verbose => (
    is      => 'ro',
    default => 0,
);

#
# Construction from the environment (how bin/robocop builds the controller)
#
# The three required values have no default and no other source inside the pod,
# so a missing one is fatal here -- croaked, which reaches STDERR -- rather than
# surfacing as an obscure failure deep in the first reconcile. namespace mirrors
# the deployment's NAMESPACE fieldRef; distribution is optional and defaults to
# rke2. Secret wiring in the Deployment is a separate lane (karr #33 / #101).
#
sub from_env {
    my ($class, %overrides) = @_;

    my %env_of = (
        ssh_key    => 'ROBO_SSH_KEY',
        server_url => 'RKE2_SERVER_URL',
        join_token => 'RKE2_TOKEN',
    );

    my %args;
    for my $attr (keys %env_of) {
        my $val = $ENV{ $env_of{$attr} };
        $args{$attr} = $val if defined $val && length $val;
    }

    my @missing = sort map { $env_of{$_} }
        grep { !defined $args{$_} || !length $args{$_} }
        keys %env_of;
    croak "robocop controller: missing required environment variable(s): "
        . join(', ', @missing)
        if @missing;

    $args{namespace} = $ENV{NAMESPACE}
        if defined $ENV{NAMESPACE} && length $ENV{NAMESPACE};
    $args{distribution} = $ENV{OCP_DISTRIBUTION}
        if defined $ENV{OCP_DISTRIBUTION} && length $ENV{OCP_DISTRIBUTION};

    return $class->new(%args, %overrides);
}

#
# Lazy-built Kubernetes client
#

has kube => (
    is      => 'lazy',
    builder => '_build_kube',
);

# The watch stream runs on Net::Async::Kubernetes; the reconcile side keeps the
# synchronous `kube` above that OCP::Node, list_ocp_nodes and _mark_failed use.
# Two clients, one decision about where to authenticate (_kube_source).
has loop => (
    is      => 'lazy',
    builder => sub { IO::Async::Loop->new },
);

has async_kube => (
    is      => 'lazy',
    builder => '_build_async_kube',
);

# Both branches of this builder used to die.
#
#     Kubernetes::REST->new(kubeconfig => $yaml)  # and ->new() bare
#
# Kubernetes::REST 1.106 has no `kubeconfig` argument and no in-cluster
# automatism at all: `server` and `credentials` are required, so either call
# dies with "Missing required arguments: credentials, server" before a single
# request is built. The comment claiming the client picks up in-cluster config
# by itself described a feature it never had. `kube` is the first thing run()
# touches (list_ocp_nodes), so the controller could not survive its own first
# iteration.
#
# Client construction belongs to OCP::Kubernetes, which is how the CLI already
# reaches a cluster: Kubernetes::REST::Kubeconfig->new(...)->api. The
# controller adds only the CRD registration, without which OCPNode and
# OCPNodeProvider are not addressable.
sub _build_kube {
    my ($self) = @_;

    my $api = OCP::Kubernetes->new($self->_kube_source)->api;
    OCP::K8s->register($api);
    return $api;
}

# Where the credentials come from, as a plain decision with no I/O of its own.
#
# `kubeconfig` is the out-of-cluster testing hatch and takes either a file path
# or the kubeconfig itself; unset means "we are the pod, use the service
# account". The file test is guarded by the newline check because -f on a whole
# kubeconfig document warns ("Unsuccessful stat on filename containing
# newline") before answering false.
sub _kube_source {
    my ($self) = @_;

    my $kc = $self->kubeconfig;
    return (in_cluster => 1) unless defined $kc && $kc =~ /\S/;
    return (kubeconfig_path => $kc) if $kc !~ /\n/ && -f $kc;
    return (kubeconfig => $kc);
}

# The async client for the watch stream, built from the same credential
# decision as the sync client so both authenticate identically.
sub _build_async_kube {
    my ($self) = @_;

    my %source = $self->_kube_source;
    my %args = (resource_map => $self->_async_resource_map);

    if (my $path = $source{kubeconfig_path}) {
        $args{kubeconfig} = $path;
    } elsif (defined(my $content = $source{kubeconfig})) {
        # Net::Async::Kubernetes takes a kubeconfig path, not a document, so a
        # kubeconfig handed in as content (the out-of-cluster testing hatch) is
        # materialized to a temp file kept alive on $self.
        my $fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
        print {$fh} $content;
        close $fh;
        $self->{_async_kubeconfig_tmp} = $fh;
        $args{kubeconfig} = $fh->filename;
    }
    # in_cluster: no kubeconfig/server args -- Net::Async::Kubernetes
    # auto-detects the pod's service account token.

    return Net::Async::Kubernetes->new(%args);
}

# OCPNode and OCPNodeProvider are CRDs, so the async client needs them in its
# resource map the way OCP::K8s->register adds them to the sync client.
sub _async_resource_map {
    return {
        %{ IO::K8s->default_resource_map },
        OCPNode         => '+OCP::K8s::OCPNode',
        OCPNodeProvider => '+OCP::K8s::OCPNodeProvider',
    };
}

#
# Main loop: watch OCPNode and reconcile on every event
#
# This replaces the former while(1)+sleep poll (karr #1, the #33 follow-up). A
# fresh watch with no resourceVersion replays a synthetic ADDED for every
# existing OCPNode before it streams changes, so nodes already in the cluster
# are reconciled at startup exactly as the initial poll pass used to do.
#
# Reconciliation stays synchronous on purpose: the lease check and the whole
# OCP::Node state machine run inside the callback, on the sync `kube`, precisely
# as they did under the poll. Only the trigger changed -- from a timer to a
# watch event -- so the tested error handling (_on_node_event / _mark_failed) is
# untouched. A long-running reconcile blocks the loop for its duration, the same
# way it blocked the poll; making reconcile itself async is a separate step.
#
sub run {
    my ($self) = @_;

    $self->log("Robocop controller starting (namespace=" . $self->namespace . ")");
    $self->log("Server URL:   " . $self->server_url);
    $self->log("Distribution: " . $self->distribution);
    $self->log("Watching OCPNode via Net::Async::Kubernetes");

    my $loop = $self->loop;
    my $kube = $self->async_kube;
    $loop->add($kube);

    weaken(my $wself = $self);

    $self->{_watcher} = $kube->watcher('OCPNode',
        namespace   => $self->namespace,
        timeout     => $self->watch_timeout,
        on_added    => sub { $wself && $wself->_handle_watch_object($_[0]) },
        on_modified => sub { $wself && $wself->_handle_watch_object($_[0]) },
        on_error    => sub {
            my ($status) = @_;
            return unless $wself;
            my $msg = ref $status eq 'HASH' ? ($status->{message} // 'unknown')
                    : (defined $status ? $status : 'unknown');
            $wself->log("watch ERROR: " . $msg);
        },
    );

    $loop->run;
}

# The watcher hands its callbacks an inflated IO::K8s object; the rest of the
# controller (and OCP::Node) speaks the plain struct _on_node_event expects, so
# convert once here at the boundary and hand it to the shared reconcile path.
sub _handle_watch_object {
    my ($self, $obj) = @_;
    return unless $obj;
    my $cr = $self->kube->k8s->object_to_struct($obj);
    $self->_reconcile_cr($cr);
}

# One CR through the state machine, with the same guard the poll loop had.
sub _reconcile_cr {
    my ($self, $cr) = @_;

    try {
        $self->_on_node_event($cr);
    } catch {
        my $name = $cr->{metadata}{name} // '?';
        $self->log("ERROR reconciling $name: $_");
        # Defense in depth: _on_node_event already patches status on every
        # failure it knows about, but a crash past those paths (a transport
        # exception in the middle of a status patch, a croak from a test stub)
        # used to leave the CR with whatever phase it had -- usually Pending --
        # and the operator with only robocop's pod logs to read. Mark the CR
        # Failed so the failure is visible without the logs.
        $self->_mark_failed($cr, $_);
    };
}

#
# Event dispatcher → OCP::Node
#
# Every path that fails before OCP::Node takes over MUST patch the OCPNode's
# status to Failed with the reason: an OCPNode that the controller saw but
# could not start reconciling used to stay Pending forever, with no message
# and no diagnostic outside robocop's pod logs (karr #123). The status write
# goes to /status because the CRD enables that subresource, and it goes
# through OCP::K8s->patch_status because that is the only place in OCP that
# writes it correctly. Anything that can fail before OCP::Node owns the CR
# routes through _mark_failed below.
#

sub _on_node_event {
    my ($self, $cr) = @_;

    my $provider_name = $cr->{spec}{providerRef};
    unless ($provider_name) {
        $self->_mark_failed($cr,
            "spec.providerRef is missing on this OCPNode; "
          . "robocop will not provision it until the field is set");
        return;
    }

    my $ns = $cr->{metadata}{namespace} // $self->namespace;

    my $provider_cr_obj = eval {
        $self->kube->get('OCPNodeProvider', name => $provider_name, namespace => $ns);
    };
    if ($@ || !$provider_cr_obj) {
        $self->_mark_failed($cr,
            "Failed to load OCPNodeProvider/$provider_name: "
          . ($@ ? $@ : 'not found'));
        return;
    }
    my $provider_cr = $self->kube->k8s->object_to_struct($provider_cr_obj);

    my $provider = eval { OCP::Provider->from_cr($provider_cr, k8s => $self->kube) };
    if ($@) {
        chomp $@;
        $self->_mark_failed($cr,
            "Failed to build provider from OCPNodeProvider/$provider_name: $@");
        return;
    }

    # The cluster-wide gpu.enabled / gpu.driver from ocp.yaml live nowhere
    # robocop can see them except the provider CR -- `ocp apply` copies them
    # there, and this is the whole reason they can reach a worker robocop joins
    # (karr #31). Read them off the same CR from_cr just consumed and hand them
    # to OCP::Node; absent from a CR that predates the field means OCP::Node
    # keeps OCP::Rex's default.
    my %gpu_flags = OCP::Provider->gpu_flags_from_cr($provider_cr);

    my $node = eval {
        OCP::Node->from_cr(
            $cr,
            k8s           => $self->kube,
            provider      => $provider,
            ssh_key       => $self->ssh_key,
            server_url    => $self->server_url,
            join_token    => $self->join_token,
            distribution  => $self->distribution,
            verbose       => $self->verbose,
            reconciler_id => 'robocop',
            %gpu_flags,
        );
    };
    if ($@) {
        chomp $@;
        $self->_mark_failed($cr, "Failed to construct OCPNode: $@");
        return;
    }

    $node->reconcile;
}

# Patches the OCPNode's status to Failed with the given message, and logs.
#
# Best-effort: the status write itself can fail (the CR was deleted between
# list and patch, the API is unreachable). In that case the failure is logged
# and the caller keeps going -- the alternative is to throw, which would
# bounce the CR back through run()'s catch and try to patch Failed again, or
# if THAT also fails, take the controller down on a single bad CR. The
# operator reads both the status and the logs; one of them is enough to make
# a stuck CR diagnosable.
#
# The two timestamp/reconciler fields are the ones OCP::Node::_patch_status
# adds by default. We write them ourselves here because the controller sits
# outside OCP::Node on every path that calls _mark_failed.
sub _mark_failed {
    my ($self, $cr, $message) = @_;

    my $name = $cr->{metadata}{name}     // '?';
    my $ns   = $cr->{metadata}{namespace} // $self->namespace;

    $self->log("marking $name Failed: $message");

    my $status = {
        phase             => 'Failed',
        message           => $message,
        lastReconcileTime => Time::Piece::gmtime->strftime('%Y-%m-%dT%H:%M:%SZ'),
        reconciler        => 'robocop',
    };

    eval {
        OCP::K8s->patch_status(
            $self->kube,
            kind      => 'OCPNode',
            name      => $name,
            namespace => $ns,
            status    => $status,
        );
        1;
    } or $self->log("ERROR patching status for $name: $@");
}

#
# Kubernetes API helpers
#

sub list_ocp_nodes {
    my ($self) = @_;

    my $list = $self->kube->list('OCPNode', namespace => $self->namespace);
    return [
        map { $self->kube->k8s->object_to_struct($_) } @{ $list->items // [] }
    ];
}

#
# Helpers
#

sub log {
    my ($self, $msg) = @_;
    my $ts = scalar localtime;
    print "[$ts] $msg\n";
}

1;

__END__

=head1 NAME

OCP::Robocop::Controller - Kubernetes controller for OCP nodes

=head1 SYNOPSIS

    use OCP::Robocop::Controller;

    my $controller = OCP::Robocop::Controller->new(
        namespace    => 'ocp-system',
        kubeconfig   => '/path/to/kubeconfig.yaml',  # or undef for in-cluster
        ssh_key      => $robo_key_content,
        server_url   => 'https://192.168.122.1:9345',
        join_token   => $token,
        distribution => 'rke2',
    );

    # Or, the way bin/robocop builds it, from the environment:
    my $controller = OCP::Robocop::Controller->from_env;

    $controller->run;  # blocks: watches OCPNodes, reconciles via OCP::Node

=head1 DESCRIPTION

Watches OCPNode custom resources over L<Net::Async::Kubernetes> and dispatches
each event to L<OCP::Node> for reconciliation. The state machine lives entirely
in C<OCP::Node>.

The watch stream runs on an async L<Net::Async::Kubernetes> client, while
reconciliation itself stays synchronous on the L<Kubernetes::REST> C<kube>
client: each event triggers the lease check and the C<OCP::Node> state machine
inline. A fresh watch replays existing OCPNodes as C<ADDED> events, so nodes
already in the cluster are reconciled on startup.

=head2 from_env

Class method. Builds a controller from the environment C<bin/robocop> runs in:
C<ROBO_SSH_KEY>, C<RKE2_SERVER_URL> and C<RKE2_TOKEN> are required (a missing one
is fatal), C<NAMESPACE> and C<OCP_DISTRIBUTION> are optional. Extra arguments
override the environment-derived ones.

=head2 Reconciliation state machine

    Pending → Provisioning → Installing → Joining → Ready
                     └──────────────┴──────────→ Failed

=cut

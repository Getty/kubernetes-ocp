package OCP::Robocop::Controller;
# ABSTRACT: Kubernetes controller for OCP nodes

use Moo;
use Carp qw(croak);
use File::Temp ();
use IO::Async::Loop;
use IO::Async::Timer::Periodic;
use IO::Handle ();
use Path::Tiny ();
use IO::K8s;
use Net::Async::Kubernetes;
use Scalar::Util qw(weaken);
use Time::Piece ();
use Try::Tiny;

use OCP::K8s;
use OCP::Kubernetes;
use OCP::Node;
use OCP::Provider;
use OCP::Robocop::KeyInjection;
use OCP::Robocop::Manifest;

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

# The robo key. From the environment in the secret levels; in `inject` (k2)
# it starts empty and is set at runtime by accept_key, which is why this is
# the one attribute with a writer -- a private one.
has ssh_key => (
    is  => 'rwp',
    doc => 'SSH private key content (robo-key), held in memory only',
);

# robocop.security_level as the Deployment hands it over (ROBOCOP_SECURITY_LEVEL).
# Only `inject` changes anything here: no key at start, a key-injection
# listener, and OCPNodes held until the key arrives.
has security_level => (
    is      => 'ro',
    default => 'secret',
);

# The robo key's public half, for checking an injected key (inject only).
has expected_public_key => (
    is => 'ro',
);

# What the Deployment's readinessProbe checks in inject mode: present exactly
# while a key is held. It carries no key material. On the Memory-backed /tmp
# emptyDir it survives a container restart, so a restart removes it first.
has ready_file => (
    is      => 'ro',
    default => OCP::Robocop::Manifest::READY_FILE,
);

has key_injection => (
    is      => 'lazy',
    builder => '_build_key_injection',
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

# How many OCPNodes may be reconciled at the same time (k159). Each one is a
# forked process that may run a Rex install for minutes, inside the pod's
# memory limit, so the default stays small.
has max_reconciles => (
    is      => 'ro',
    default => 2,
);

# Seconds between two resync passes (k159): every OCPNode still on its way to
# Ready that is not being reconciled right now is enqueued again, because
# nothing else would look at it before the next write to its CR.
has resync_interval => (
    is      => 'ro',
    default => 60,
);

# Scheduler state (k159). _inflight: node key => Future of the running child.
# _pending: node key => the latest CR copy of a node waiting for its turn --
# queued, or due for one rerun once its running reconcile ends. _queue: the
# keys waiting for a free slot, oldest first.
has _inflight => ( is => 'ro', default => sub { {} } );
has _pending  => ( is => 'ro', default => sub { {} } );
has _queue    => ( is => 'ro', default => sub { [] } );

sub BUILD {
    my ($self) = @_;
    croak "robocop controller: ssh_key is required unless security_level is 'inject'"
        unless $self->is_inject || (defined $self->ssh_key && length $self->ssh_key);
}

sub is_inject { ($_[0]->security_level // '') eq 'inject' }

#
# Construction from the environment (how bin/robocop builds the controller)
#
# The three required values have no default and no other source inside the pod,
# so a missing one is fatal here -- croaked, which reaches STDERR -- rather than
# surfacing as an obscure failure deep in the first reconcile. namespace mirrors
# the deployment's NAMESPACE fieldRef; distribution is optional and defaults to
# rke2. Secret wiring in the Deployment is a separate lane (k33 / k101).
#
sub from_env {
    my ($class, %overrides) = @_;

    # inject (k2): the private key must NOT come from the environment -- it is
    # handed over at runtime -- and the public half it is checked against must.
    my $inject = ($ENV{ROBOCOP_SECURITY_LEVEL} // '') eq 'inject';

    croak "robocop controller: ROBO_SSH_KEY is set, but ROBOCOP_SECURITY_LEVEL "
        . "is inject -- in inject mode the key is never put in the environment"
        if $inject && defined $ENV{ROBO_SSH_KEY} && length $ENV{ROBO_SSH_KEY};

    my %env_of = (
        server_url => 'RKE2_SERVER_URL',
        join_token => 'RKE2_TOKEN',
        ($inject ? (expected_public_key => 'ROBO_SSH_PUBLIC_KEY')
                 : (ssh_key             => 'ROBO_SSH_KEY')),
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

    $args{security_level} = 'inject' if $inject;
    $args{namespace} = $ENV{NAMESPACE}
        if defined $ENV{NAMESPACE} && length $ENV{NAMESPACE};
    $args{distribution} = $ENV{OCP_DISTRIBUTION}
        if defined $ENV{OCP_DISTRIBUTION} && length $ENV{OCP_DISTRIBUTION};

    my %count_of = (
        resync_interval => 'ROBOCOP_RESYNC_INTERVAL',
        max_reconciles  => 'ROBOCOP_MAX_RECONCILES',
    );
    for my $attr (sort keys %count_of) {
        my $val = $ENV{ $count_of{$attr} };
        next unless defined $val && length $val;
        croak "robocop controller: " . $count_of{$attr}
            . " must be a positive whole number, got '" . $val . "'"
            unless $val =~ /\A[0-9]+\z/ && $val > 0;
        $args{$attr} = $val;
    }

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
# This replaces the former while(1)+sleep poll (k1, the k33 follow-up). A
# fresh watch with no resourceVersion replays a synthetic ADDED for every
# existing OCPNode before it streams changes, so nodes already in the cluster
# are reconciled at startup exactly as the initial poll pass used to do.
#
# The loop itself never reconciles (k159). A watch event, the resync timer and
# an injected key only enqueue the node; the reconcile -- lease check and the
# whole OCP::Node state machine, synchronous as ever -- runs in a forked child
# (see "Scheduler" below). So a Rex install that takes minutes no longer holds
# up other watch events or the inject listener.
#
sub run {
    my ($self) = @_;

    $self->log("Robocop controller starting (namespace=" . $self->namespace . ")");
    $self->log("Server URL:   " . $self->server_url);
    $self->log("Distribution: " . $self->distribution);
    $self->log("Watching OCPNode via Net::Async::Kubernetes");
    $self->log("Reconciling at most " . $self->max_reconciles . " node(s) at once, "
        . "resync every " . $self->resync_interval . "s");

    my $loop = $self->loop;
    my $kube = $self->async_kube;
    $loop->add($kube);

    # Built once here so every forked reconcile inherits the client instead of
    # rebuilding it. It keeps no connection open (LWP without keep-alive), so
    # parent and children never share a socket.
    $self->kube;

    $self->_start_key_injection if $self->is_inject;
    $self->_start_resync;

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

#
# Scheduler (k159)
#
# One forked child per reconcile. Why a process and not a Future-based
# reconcile: OCP::Node, OCP::SSH and OCP::Rex are synchronous through and
# through (Rex keeps per-process global state, so two installs could not even
# share one interpreter), and OCP::Node is shared with the CLI. A fork keeps
# every line of that unchanged and inherits the robo key from memory --
# nothing is written for it beyond the TempKeyPair OCP::Node already makes.
# IO::Async's fork leaves the child through POSIX::_exit, so the child never
# runs the destructors that would shut down the parent's watch and listener
# sockets.
#
# Two rules the scheduler keeps:
#
#   * Never two reconciles of the same OCPNode at once. OCP::Node's lease does
#     not cover this: every robocop reconcile holds it as 'robocop', so a
#     second robocop child would find the lease "mine" and provision again.
#     Events for a node that is running are collapsed into its pending copy
#     and give exactly one rerun when it ends.
#   * At most max_reconciles children at once; the rest wait in order.
#
# The child re-reads the CR before reconciling (_reconcile_child): the copy an
# event carried can be older than what the previous child wrote, and a stale
# Pending handed to OCP::Node would provision a second server.
#

sub _node_key {
    my ($self, $cr) = @_;
    return ($cr->{metadata}{namespace} // $self->namespace) . '/'
         . ($cr->{metadata}{name} // '?');
}

sub reconciling {
    my ($self, $cr) = @_;
    return exists $self->_inflight->{ $self->_node_key($cr) } ? 1 : 0;
}

sub enqueue {
    my ($self, $cr) = @_;
    my $key = $self->_node_key($cr);

    my $running = exists $self->_inflight->{$key};
    my $queued  = !$running && exists $self->_pending->{$key};

    $self->_pending->{$key} = $cr;
    push @{ $self->_queue }, $key unless $running || $queued;
    $self->_start_next;
    return;
}

sub _start_next {
    my ($self) = @_;
    my $queue = $self->_queue;
    while (@$queue && keys %{ $self->_inflight } < $self->max_reconciles) {
        my $key = shift @$queue;
        $self->_launch($key, delete $self->_pending->{$key});
    }
    return;
}

sub _launch {
    my ($self, $key, $cr) = @_;
    weaken(my $wself = $self);
    my $f = $self->_spawn($cr);
    $self->_inflight->{$key} = $f;
    $f->on_ready(sub { $wself->_finished($key, $_[0]) if $wself });
    return;
}

sub _finished {
    my ($self, $key, $f) = @_;
    delete $self->_inflight->{$key};

    my $status = $f->is_done ? ($f->result // 0) : -1;
    $self->log("reconcile of $key ended abnormally (exit code " . ($status >> 8)
        . ", wait status $status); the next event or resync retries it")
        if $status;

    push @{ $self->_queue }, $key if exists $self->_pending->{$key};
    $self->_start_next;
    return;
}

# The process boundary: resolves to the child's wait status once it exits.
sub _spawn {
    my ($self, $cr) = @_;
    my $f = $self->loop->new_future;
    $self->loop->fork(
        code => sub {
            $self->_reconcile_child($cr);
            # _exit skips the stdio flush; the log lines must not be lost.
            STDOUT->flush;
            STDERR->flush;
            return 0;
        },
        on_exit => sub { $f->done($_[1]) },
    );
    return $f;
}

# Runs in the child: the CR as stored now, through the same guarded path the
# event handler always used. A CR deleted meanwhile is simply done; a read that
# fails otherwise is left for the next event or resync rather than reconciled
# from a copy that may be stale.
sub _reconcile_child {
    my ($self, $cr) = @_;
    my $name = $cr->{metadata}{name} // '?';
    my $ns   = $cr->{metadata}{namespace} // $self->namespace;

    my $obj = eval { $self->kube->get('OCPNode', name => $name, namespace => $ns) };
    if (my $err = $@) {
        chomp $err;
        $self->log($err =~ /\b404\b/ ? "$name: gone, nothing to reconcile"
            : "ERROR re-reading $name before reconcile, retried later: $err");
        return;
    }
    return unless $obj;

    $self->_reconcile_cr($self->kube->k8s->object_to_struct($obj));
    return;
}

#
# Periodic resync (k159)
#
# A watch only reports changes. A node waiting on something outside the
# cluster (an SSH port, the provider) or a Joining node waiting for its kubelet
# writes nothing and so gets no event. Every resync_interval the nodes still on
# their way to Ready are enqueued again. Ready (steady state), Failed
# (terminal, by OCP::Node's decision) and Terminating are left alone.
#

my %RESYNC = map { $_ => 1 } qw( Pending Provisioning Installing Joining );

sub _start_resync {
    my ($self) = @_;
    weaken(my $wself = $self);
    my $timer = IO::Async::Timer::Periodic->new(
        interval => $self->resync_interval,
        on_tick  => sub { $wself->_resync if $wself },
    );
    $self->loop->add($timer);
    $timer->start;
    $self->{_resync_timer} = $timer;
    return;
}

sub _resync {
    my ($self) = @_;
    my $crs = eval { $self->list_ocp_nodes };
    unless ($crs) {
        $self->log("ERROR listing OCPNodes for resync: $@");
        return;
    }
    for my $cr (@$crs) {
        next unless $RESYNC{ $cr->{status}{phase} // 'Pending' };
        next if $self->reconciling($cr);
        $self->enqueue($cr);
    }
    return;
}

#
# Key injection (security_level inject, k2)
#
# No checkpoint, no restore: a robocop that starts in inject mode holds no key
# until `ocp inject-key` delivers one, and says so -- in the log, in the
# readiness probe (no ready file) and on every OCPNode that is waiting for it.
#

sub _build_key_injection {
    my ($self) = @_;
    weaken(my $wself = $self);
    return OCP::Robocop::KeyInjection->new(
        expected_public_key => $self->expected_public_key,
        on_key    => sub {
            die "robocop is shutting down\n" unless $wself;   # never ack an unheld key
            $wself->accept_key(@_);
        },
        on_reject => sub { $wself->log("key injection refused: $_[0]") if $wself },
    );
}

sub _start_key_injection {
    my ($self) = @_;

    # A ready file from before a container restart would claim a key this
    # process does not have.
    unlink $self->ready_file if -e $self->ready_file;

    $self->key_injection->start($self->loop)->get;
    $self->log("security_level inject: holding NO SSH key. Waiting for "
        . "'ocp inject-key' (port-forward to 127.0.0.1:"
        . OCP::Robocop::KeyInjection::PORT . "); OCPNodes that need SSH are held");
}

# The key is in (already validated by OCP::Robocop::KeyInjection). Hold it,
# mark the pod ready, and go over every OCPNode again -- the held ones got no
# further event. The pass is scheduled rather than run here: the injector is
# still waiting for its answer on the connection this is called from, and the
# pass lists the nodes over the API before it enqueues them.
sub accept_key {
    my ($self, $material, $fingerprint) = @_;

    $self->_set_ssh_key($material);
    Path::Tiny::path($self->ready_file)->spew("key held\n");
    $self->log("SSH key injected (" . ($fingerprint // '?') . "), held in memory");

    weaken(my $wself = $self);
    $self->loop->later(sub { $wself->_reconcile_all if $wself });
    return;
}

sub _reconcile_all {
    my ($self) = @_;
    my $crs = eval { $self->list_ocp_nodes };
    unless ($crs) {
        $self->log("ERROR listing OCPNodes after key injection: $@");
        return;
    }
    $self->enqueue($_) for @$crs;
}

# The phases whose next step needs SSH to the machine (OCP::Node::reconcile:
# Pending provisions, Provisioning/Installing install over Rex). Joining, Ready,
# Failed and Terminating do not touch the key and run as usual.
my %NEEDS_KEY = map { $_ => 1 } qw( Pending Provisioning Installing );

sub _needs_key {
    my ($self, $cr) = @_;
    return $NEEDS_KEY{ $cr->{status}{phase} // 'Pending' } ? 1 : 0;
}

# Write SSHKeyAvailable onto an OCPNode -- only when it changes, because every
# status write comes back as a watch event and an unconditional write would
# loop. The phase is left alone: the node is neither failed nor progressing,
# it is waiting, and the condition says on what.
sub _set_key_condition {
    my ($self, $cr, $available) = @_;

    my @conds = @{ $cr->{status}{conditions} // [] };
    my ($cur) = grep { ($_->{type} // '') eq 'SSHKeyAvailable' } @conds;
    my $want = $available ? 'True' : 'False';

    return if $cur && ($cur->{status} // '') eq $want;
    return if !$cur && $available;   # never held, nothing to clear

    my $now = Time::Piece::gmtime->strftime('%Y-%m-%dT%H:%M:%SZ');
    my $msg = $available
        ? 'robocop holds the injected SSH key'
        : "robocop holds no SSH key (robocop.security_level inject; a pod "
        . "restart loses it). Run 'ocp inject-key' to continue.";

    my %status = (
        conditions => [
            (grep { ($_->{type} // '') ne 'SSHKeyAvailable' } @conds),
            {
                type               => 'SSHKeyAvailable',
                status             => $want,
                reason             => $available ? 'KeyInjected' : 'KeyInjectionRequired',
                message            => $msg,
                lastTransitionTime => $now,
            },
        ],
        lastReconcileTime => $now,
        reconciler        => 'robocop',
        ($available ? () : (message => "Waiting for SSH key: run 'ocp inject-key'")),
    );

    my $name = $cr->{metadata}{name} // '?';
    $self->log($available ? "$name: SSH key available again"
                          : "$name: held, waiting for 'ocp inject-key'");

    eval {
        OCP::K8s->patch_status(
            $self->kube,
            kind      => 'OCPNode',
            name      => $name,
            namespace => $cr->{metadata}{namespace} // $self->namespace,
            status    => \%status,
        );
        1;
    } or $self->log("ERROR patching key condition for $name: $@");
    return;
}

# The watcher hands its callbacks an inflated IO::K8s object; the rest of the
# controller (and OCP::Node) speaks the plain struct _on_node_event expects, so
# convert once here at the boundary and hand it to the scheduler.
sub _handle_watch_object {
    my ($self, $obj) = @_;
    return unless $obj;
    $self->enqueue($self->kube->k8s->object_to_struct($obj));
}

# One CR through the state machine, with the same guard the poll loop had.
# Runs in the reconcile child (_reconcile_child).
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
# and no diagnostic outside robocop's pod logs (k123). The status write
# goes to /status because the CRD enables that subresource, and it goes
# through OCP::K8s->patch_status because that is the only place in OCP that
# writes it correctly. Anything that can fail before OCP::Node owns the CR
# routes through _mark_failed below.
#

sub _on_node_event {
    my ($self, $cr) = @_;

    # inject mode: nothing that needs SSH runs without the key.
    if ($self->is_inject && $self->_needs_key($cr)) {
        my $has_key = defined $self->ssh_key && length $self->ssh_key;
        $self->_set_key_condition($cr, $has_key);
        return unless $has_key;
    }

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
    # (k31). Read them off the same CR from_cr just consumed and hand them
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

    # security_level inject: no key yet, `ocp inject-key` delivers it
    my $controller = OCP::Robocop::Controller->new(
        security_level      => 'inject',
        expected_public_key => $robo_public_key,
        server_url          => 'https://192.168.122.1:9345',
        join_token          => $token,
    );

    # Or, the way bin/robocop builds it, from the environment:
    my $controller = OCP::Robocop::Controller->from_env;

    $controller->run;  # blocks: watches OCPNodes, reconciles via OCP::Node

=head1 DESCRIPTION

Watches OCPNode custom resources over L<Net::Async::Kubernetes> and dispatches
each event to L<OCP::Node> for reconciliation. The state machine lives entirely
in C<OCP::Node>.

The watch stream runs on an async L<Net::Async::Kubernetes> client. The loop
never reconciles itself: an event only enqueues the node, and each reconcile
-- the lease check and the synchronous C<OCP::Node> state machine on the
L<Kubernetes::REST> C<kube> client -- runs in a forked child. The loop stays
free for further events and the key-injection listener while an install runs.
A fresh watch replays existing OCPNodes as C<ADDED> events, so nodes already in
the cluster are reconciled on startup.

=head2 Scheduling

Never two reconciles of the same OCPNode run at once: events for a node that is
being reconciled collapse into one rerun after it ends. At most
C<max_reconciles> children run at the same time (C<ROBOCOP_MAX_RECONCILES>,
default 2); the rest wait in order. The child reads the OCPNode again before it
reconciles, so it never acts on an older copy than the one stored.

Every C<resync_interval> seconds (C<ROBOCOP_RESYNC_INTERVAL>, default 60) the
OCPNodes in C<Pending>, C<Provisioning>, C<Installing> or C<Joining> that are
not being reconciled are enqueued again, because a node waiting on something
outside the cluster gets no watch event. C<Ready>, C<Failed> and
C<Terminating> are left alone.

=head2 enqueue

    $controller->enqueue($ocpnode_struct);

Schedules a reconcile of one OCPNode (plain struct).

=head2 reconciling

    $controller->reconciling($ocpnode_struct);   # 1 or 0

True while a reconcile of that OCPNode is running.

=head2 from_env

Class method. Builds a controller from the environment C<bin/robocop> runs in:
C<ROBO_SSH_KEY>, C<RKE2_SERVER_URL> and C<RKE2_TOKEN> are required (a missing one
is fatal), C<NAMESPACE>, C<OCP_DISTRIBUTION>, C<ROBOCOP_RESYNC_INTERVAL> and
C<ROBOCOP_MAX_RECONCILES> are optional (the last two must be positive whole
numbers). Extra arguments override the environment-derived ones.

With C<ROBOCOP_SECURITY_LEVEL=inject> the private key must B<not> be in the
environment (a set C<ROBO_SSH_KEY> is fatal); C<ROBO_SSH_PUBLIC_KEY>, the robo
key's public half, is required instead.

=head2 Key injection (security_level inject)

In inject mode the controller starts without a key and listens on
C<127.0.0.1:9999> for C<ocp inject-key>, which reaches it through a Kubernetes
port-forward (protocol: L<OCP::Robocop::KeyInjection>). The key is held in
memory only. A pod restart loses it and the admin injects again; nothing is
checkpointed. Until a key is held:

=over 4

=item * OCPNodes in C<Pending>, C<Provisioning> or C<Installing> -- the phases
whose next step needs SSH -- are not handed to L<OCP::Node>. They keep their
phase and carry the condition C<SSHKeyAvailable=False> (reason
C<KeyInjectionRequired>) plus a C<status.message> naming C<ocp inject-key>.
Other phases reconcile as usual.

=item * The ready file (C</tmp/robocop-key-ready>) is absent, so the
Deployment's readiness probe keeps the pod not Ready.

=back

=head2 accept_key

    $controller->accept_key($material, $fingerprint);

Called by the injection listener with an already validated key: holds it,
writes the ready file, and schedules a pass over every OCPNode, in which the
waiting conditions flip to C<SSHKeyAvailable=True> (reason C<KeyInjected>).

=head2 Reconciliation state machine

    Pending → Provisioning → Installing → Joining → Ready
                     └──────────────┴──────────→ Failed

=cut

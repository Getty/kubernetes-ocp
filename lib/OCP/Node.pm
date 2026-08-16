package OCP::Node;
# ABSTRACT: Trigger-neutral node reconcile state machine

use Moo;
use Time::Piece ();
use OCP::K8s;
# ssh_class and rex_class default to these by name. Nothing else in the
# reconcile path loads them, so without these two lines _install_kubernetes
# dies on ->new the first time it runs against a real host.
use OCP::Rex;
use OCP::SSH;
use OCP::TempKeyPair;
use OCP::Versions;
use namespace::clean;

has cr            => (is => 'ro', writer => '_set_cr', required => 1);
has k8s           => (is => 'ro', required => 1);
has provider      => (is => 'ro');
has ssh_key       => (is => 'ro');
has server_url    => (is => 'ro');
has join_token    => (is => 'ro');
has distribution  => (is => 'ro', default => sub { 'rke2' });
has registry_cfg  => (is => 'ro');
has verbose       => (is => 'ro', default => 0);
has reconciler_id => (is => 'ro', default => sub { 'cli' });
has ssh_class     => (is => 'ro', default => sub { 'OCP::SSH' });
has rex_class     => (is => 'ro', default => sub { 'OCP::Rex' });

# The key pair this node's Rex and SSH calls run on, alive as long as the node
# object and removed with it.
#
# It used to be a bare File::Temp holding the private half, which left every
# worker install pointing REX_PUBLIC_KEY at a file nobody had written:
# OCP::Rex sets it to key_file . '.pub' unconditionally, and nothing here put
# anything there (karr #93, the worker-path twin of #87). OCP::TempKeyPair
# writes both halves and owns both.
#
# The public half is DERIVED from `ssh_key` rather than passed in, and that is
# what keeps this class trigger-neutral: `ocp node add` could hand one over
# (it holds an OCP::ClusterKey, which has both), but robocop cannot -- the
# controller is handed private key material and nothing else, with no key
# store and no project directory in the container. A public half that only
# the CLI could supply would fix the CLI and leave the controller exactly as
# broken.
has _ssh_key_file => (is => 'lazy', builder => '_build_ssh_key_file');

sub _build_ssh_key_file {
    my ($self) = @_;
    return OCP::TempKeyPair->for_private_key($self->ssh_key);
}

sub name      { $_[0]->cr->{metadata}{name} }
sub role      { $_[0]->cr->{spec}{role} }
sub phase     { $_[0]->cr->{status}{phase} // 'Pending' }
sub namespace { $_[0]->cr->{metadata}{namespace} // 'ocp-system' }

sub from_cr {
    my ($class, $cr, %deps) = @_;
    return $class->new(cr => $cr, %deps);
}

sub _rfc3339_now { Time::Piece::gmtime->strftime('%Y-%m-%dT%H:%M:%SZ') }

sub _lease_parse {
    my $v = shift;
    return unless $v;
    $v =~ /^([^@]+)\@([^@]+)\@(\d+)$/ or return;
    return { holder => $1, ts => $2, ttl => $3 };
}

sub _lease_live {
    my $l = _lease_parse(shift);
    return 0 unless $l;
    my $t = Time::Piece->strptime($l->{ts}, '%Y-%m-%dT%H:%M:%SZ')->epoch;
    return (time - $t) < $l->{ttl};
}

sub _lease_mine {
    my ($v, $id) = @_;
    my $l = _lease_parse($v);
    return 0 unless $l;
    return $l->{holder} eq $id;
}

sub _kind { 'OCPNode' }

# --- Kubernetes::REST seam -------------------------------------------------
#
# Kubernetes::REST addresses resources by their registered Kind, never by
# api-version: get('OCPNode', $name, namespace => $ns). The first argument is
# fed to expand_class(), so passing an api-version there ('ocp.internal/v1')
# does not mis-address the request, it dies outright -- "argument is not a
# module name". Every call below therefore goes through these three helpers,
# and OCP::Node no longer knows an api-version at all: the CR hash carries
# apiVersion, and there is nothing left to accidentally pass as arg 0.
#
# The other half of the seam is typing. get() and update() return typed
# IO::K8s objects, while everything else in this class treats `cr` as a plain
# hash. Convert in exactly one place so a typed object can never leak into the
# state machine.

sub _struct {
    my ($self, $obj) = @_;
    return undef unless defined $obj;
    return $obj if ref($obj) eq 'HASH';
    return $self->k8s->k8s->object_to_struct($obj);
}

# get() croaks on 404 rather than returning undef. A CR that is not stored yet
# is not fatal -- callers fall back to the copy they were constructed with.
# Anything else (auth, 5xx, TLS) is fatal and must not be mistaken for
# "absent": treating a failed read as an empty one would take the lease on the
# strength of a CR nobody managed to read. Kubernetes::REST::ensure draws the
# same 404-vs-rest line the same way.
sub _get_cr {
    my $self = shift;
    my $obj = eval {
        $self->k8s->get($self->_kind, $self->name, namespace => $self->namespace);
    };
    if (my $err = $@) {
        die $err unless $err =~ /\b404\b/;
        return undef;
    }
    return $self->_struct($obj);
}

# update() takes a blessed IO::K8s object and calls ->metadata on it; handing
# it a plain hash dies with "Can't call method metadata on unblessed
# reference". Build the typed object from the struct we just read, which keeps
# its resourceVersion -- that is what makes two reconcilers racing for the
# lease collide with a 409 instead of silently overwriting each other.
sub _put_cr {
    my ($self, $struct) = @_;
    my $api   = $self->k8s;
    my $class = $api->k8s->expand_class($self->_kind);
    my $updated = $self->_struct($api->update($api->k8s->struct_to_object($class, $struct)));
    $self->_set_cr($updated) if $updated;
    return $updated;
}

sub _acquire_lease {
    my $self = shift;
    my $cr = $self->_get_cr // $self->cr;
    my $ann = $cr->{metadata}{annotations} //= {};
    my $existing = $ann->{'ocp.internal/reconciler-lease'};
    if ($existing && _lease_live($existing) && !_lease_mine($existing, $self->reconciler_id)) {
        die "lease held by another reconciler: $existing\n";
    }
    $ann->{'ocp.internal/reconciler-lease'} = sprintf "%s@%s@%d",
        $self->reconciler_id, _rfc3339_now(), 300;
    return $self->_put_cr($cr);
}

sub _release_lease {
    my $self = shift;
    # Re-read before writing. Between acquire and release the caller patched
    # /status, and a status write bumps the object's resourceVersion -- PUTting
    # the copy held in memory would send a stale one and 409, leaving the lease
    # stuck until its TTL expired.
    my $cr = $self->_get_cr // $self->cr;
    my $ann = $cr->{metadata}{annotations} // {};
    return unless exists $ann->{'ocp.internal/reconciler-lease'};
    delete $ann->{'ocp.internal/reconciler-lease'};
    return $self->_put_cr($cr);
}

sub _patch_status {
    my ($self, %updates) = @_;
    $updates{lastReconcileTime} //= _rfc3339_now();
    $updates{reconciler}        //= $self->reconciler_id;

    my $status = $self->cr->{status} //= {};
    $status->{$_} = $updates{$_} for keys %updates;

    my $name = $self->name;
    my $ns   = $self->namespace;

    # Must go to /status: the OCPNode CRD enables the status subresource, so a patch
    # against the main endpoint returns 2xx and drops the status silently —
    # every phase transition would live only in this process's memory and no
    # other reader (ocp node ls, the Apply poll loop, a restarted robocop)
    # would ever see it. See OCP::K8s::patch_status.
    return OCP::K8s->patch_status(
        $self->k8s,
        kind      => 'OCPNode',
        name      => $name,
        namespace => $ns,
        status    => \%updates,
    );
}

sub _provision {
    my $self = shift;

    die "cannot provision: phase is not Pending (got: " . $self->phase . ")\n"
        unless $self->phase eq 'Pending';

    $self->_acquire_lease;

    my $result = $self->provider->create_server(
        name => $self->name,
        node => $self->name,
        role => $self->role,
        spec => $self->cr->{spec},
    );

    # An address is not something provisioning knows. The host-based providers
    # hand theirs straight back (it came out of spec.host in the first place),
    # but a cloud provider allocates it when the machine reaches `running`,
    # seconds after create returns -- Hetzner's create_server documents the
    # `ip => undef` it returns for a fresh server.
    #
    # So write the key only when there is one. Two reasons: this is a merge
    # patch, so `publicIP => undef` would DELETE an address an earlier pass had
    # already found; and the message is the only place a human sees what this
    # node is actually waiting on. _install_kubernetes resolves what is missing
    # on the next pass -- that is the phase where the address is needed, and it
    # is re-enterable, whereas a wait here would hold the lease with the
    # provider id not yet written down (karr #99).
    my $ip = $result->{ip} // $result->{ipv4};
    $ip = undef unless defined $ip && length $ip;

    $self->_patch_status(
        phase      => 'Installing',
        providerId => $result->{id},
        ($ip ? (publicIP => $ip) : ()),
        message    => $ip
            ? 'Server provisioned, installing Kubernetes'
            : 'Server provisioned, waiting for it to report an address',
    );

    # Best-effort. The server exists and the phase is written; a failed release
    # only leaves the lease standing until its 300s TTL, and this same holder
    # re-acquires it on the next pass. Letting that failure out would send
    # reconcile down its catch-all and mark a machine that was provisioned
    # perfectly well as Failed -- which is terminal, so the node would never be
    # picked up again while the server kept running.
    eval { $self->_release_lease };

    return $result;
}

# How long to wait for a freshly created server to report an address.
#
# The same 120s the control-plane path spends on the same question in
# OCP::Cmd::Apply::Bootstrap. One number for one wait: a region that is slow
# enough to make `ocp apply` sit there must not be fast enough to make a worker
# give up. `our` so a test can shorten it without timing the real thing.
our $ADDRESS_TIMEOUT = 120;

# Where this node can be reached, in the order the answer is cheapest.
#
#   1. status.publicIP  -- already known, and what every later pass sees
#   2. spec.host        -- the ssh/local providers; the user typed it
#   3. the provider     -- the server exists but has not been given an address
#
# Only step 3 is new (karr #99). It is a completion of the same lookup, not a
# new lifecycle step: `Installing` already means "the server exists, Kubernetes
# is going onto it", and finding out where the machine is belongs to getting
# onto it, exactly like the wait_for_ssh below. A phase of its own would have
# needed a new value in the OCPNode CRD's status.phase enum -- which the API
# server rejects until every deployed cluster's CRD is re-applied -- to make a
# distinction nobody reconciles on.
#
# ssh/local never reach step 3 twice over: their address is in spec.host, and
# their create_server returns `id => undef`, so there is no providerId to ask
# about. Their wait_for_running (OCP::Role::Provider::ExistingHost) is a
# passthrough that would hand back the hashref unchanged anyway.
sub _resolve_host {
    my $self = shift;

    my $host = $self->cr->{status}{publicIP} || $self->cr->{spec}{host};
    return $host if defined $host && length $host;

    my $id = $self->cr->{status}{providerId};
    return undef unless defined $id && length $id;

    # A provider double that does not implement it degrades to the old "nothing
    # to go on" answer rather than dying with a method-resolution error.
    my $provider = $self->provider;
    return undef unless $provider && $provider->can('wait_for_running');

    my $info = { id => $id };
    my $ok = eval { $provider->wait_for_running($info, $ADDRESS_TIMEOUT); 1 };
    unless ($ok) {
        my $err = $@ // '';
        chomp $err;
        die "No address for provider server $id after waiting up to "
          . "${ADDRESS_TIMEOUT}s for it to come up. The server exists and is "
          . "still billed -- check it with the provider. Provider said: "
          . ($err || 'nothing') . "\n";
    }

    $host = $info->{ip};
    die "Provider server $id came up without a public address\n"
        unless defined $host && length $host;

    # Persist before using it. `ocp node ls` prints status.publicIP, teardown
    # deletes host-based servers by it, and a robocop that restarts mid-install
    # must not have to ask the provider again.
    $self->_patch_status(publicIP => $host);

    return $host;
}

sub _install_kubernetes {
    my $self = shift;

    my $name = $self->name;
    my $role = $self->role;

    my $host = eval { $self->_resolve_host };
    unless (defined $host && length $host) {
        # $@ carries the reason when there was one to give. The bare fallback
        # is the case it used to report for everything, including a Hetzner
        # worker that simply had not been asked yet.
        $self->_patch_status(phase => 'Failed', message => $@
            || "No host IP in status or spec, and no provider server to ask\n");
        return;
    }

    my $ssh = $self->ssh_class->new(
        host     => $host,
        key_file => $self->_ssh_key_file->path,
        user     => 'root',
    );
    eval { $ssh->wait_for_ssh(60) };
    if ($@) {
        $self->_patch_status(phase => 'Failed', message => "SSH not reachable: $@");
        return;
    }

    my $rex = $self->rex_class->new(
        host     => $host,
        key_file => $self->_ssh_key_file->path,
        user     => 'root',
        verbose  => $self->verbose,
    );

    my $rke2_version = OCP::Versions->get_component_version('rke2');

    my $task = $self->distribution eq 'k3s'
        ? 'install_k3s_agent'
        : 'install_rke2_agent';

    my %params = (
        server    => $self->server_url,
        token     => $self->join_token,
        version   => $rke2_version,
        node_name => $name,
        hostname  => $name,
        ntp       => 1,
    );

    my $ok = eval { $rex->run_task($task, %params) };
    if (!$ok || $@) {
        $self->_patch_status(phase => 'Failed',
            message => "Rex task failed: " . ($@ // 'unknown'));
        return;
    }

    $self->_patch_status(phase => 'Joining',
        message => 'RKE2 agent installed, waiting for node registration');
}

sub _wait_ready {
    my $self = shift;

    my $name     = $self->name;
    my $k8s_name = $self->cr->{status}{kubernetesNodeName} // $name;

    my $k8s_node = eval {
        $self->k8s->get('Node', name => $k8s_name);
    };

    return 0 unless $k8s_node;

    my $node_hash = ref($k8s_node) eq 'HASH'
        ? $k8s_node
        : $self->k8s->k8s->object_to_struct($k8s_node);

    my $ready = 0;
    for my $cond (@{ $node_hash->{status}{conditions} // [] }) {
        if ($cond->{type} eq 'Ready' && $cond->{status} eq 'True') {
            $ready = 1;
            last;
        }
    }

    if ($ready) {
        $self->_patch_status(
            phase              => 'Ready',
            kubernetesNodeName => $k8s_name,
            joinedAt           => _rfc3339_now(),
            message            => 'Node joined and Ready',
        );
    }

    return $ready;
}

sub reconcile {
    my $self = shift;
    my $p = $self->phase;

    return 0 if $p eq 'Failed' || $p eq 'Terminating';

    eval {
        # 'Installing' means "the server exists, Kubernetes is going on it" --
        # it is what _provision writes, and the only phase from which the Rex
        # install can start. It used to dispatch to _wait_ready, which left
        # _install_kubernetes reachable only from 'Provisioning', a phase
        # nothing in OCP ever writes: the agent was never installed and the
        # node sat waiting for a registration that could not happen.
        if    ($p eq 'Pending')      { $self->_provision }
        elsif ($p eq 'Provisioning') { $self->_install_kubernetes }
        elsif ($p eq 'Installing')   { $self->_install_kubernetes }
        elsif ($p eq 'Joining')      { $self->_wait_ready }
        elsif ($p eq 'Ready')        { $self->_verify }
        else                         { die "unknown phase: $p\n" }
    };
    if ($@) {
        $self->_patch_status(phase => 'Failed', message => "$@");
        return 0;
    }
    return 1;
}

sub _refresh {
    my $self = shift;
    # This one runs inside a poll loop, so a failed read is not terminal: keep
    # the phase we already have and look again on the next tick, rather than
    # failing a worker over one API blip.
    my $fresh = eval { $self->_get_cr };
    $self->_set_cr($fresh) if $fresh;
}

sub reconcile_until_ready {
    my ($self, %opt) = @_;
    my $timeout  = $opt{timeout}  // 600;
    my $interval = $opt{interval} // 5;
    my $deadline = time + $timeout;

    while (time < $deadline) {
        $self->_refresh;
        return 1 if $self->phase eq 'Ready';
        return 0 if $self->phase eq 'Failed';
        $self->reconcile;
        sleep $interval;
    }
    return 0;
}

sub teardown {
    my $self = shift;
    $self->_patch_status(phase => 'Terminating', message => 'Teardown initiated');

    my $k8s_name = $self->cr->{status}{kubernetesNodeName} // $self->name;
    eval {
        $self->k8s->patch(
            'Node',
            name  => $k8s_name,
            patch => { spec => { unschedulable => \1 } },
        );
    };

    if ($self->provider) {
        # Providers take the id they handed out at creation time; the
        # host-based ones need the address instead. Pass both.
        my $status = $self->cr->{status} // {};
        eval {
            $self->provider->delete_server(
                $status->{providerId},
                name => $self->name,
                host => $status->{publicIP} // $self->cr->{spec}{host},
            );
            1;
        } or warn "[node] provider delete failed for @{[ $self->name ]}: $@";
    }

    # Both deletes are Kind-first. They used to lead with an api-version
    # ('v1' / 'ocp.internal/v1'), which dies in expand_class -- and since both
    # were wrapped in a bare eval, teardown reported success while the k8s Node
    # object and the OCPNode CR were both left behind.
    #
    # The eval is still there, because a node that is already gone is a normal
    # outcome here, but it no longer swallows the answer: see _delete_object.
    $self->_delete_object('Node', $k8s_name);
    $self->_delete_object($self->_kind, $self->name, namespace => $self->namespace);

    return 1;
}

# Delete one object, best-effort but never silently.
#
# Teardown must not fail over a delete: by the time it runs the server is gone,
# and a Node object that was never registered (or a CR someone already removed)
# is a legitimate outcome, not an error. That is what 404 means, and it stays
# quiet.
#
# Everything else is a real failure that used to disappear into a bare eval:
# robocop's ClusterRole had no `delete` on core nodes, so the Node delete came
# back 403 and teardown still returned 1 -- the OCPNode CR gone, the Node
# object left behind as NotReady, nothing in the log (karr #35, same shape as
# the api-version defect in karr #21). Warn the way the provider delete above
# warns; the caller keeps going either way.
sub _delete_object {
    my ($self, $kind, $name, @args) = @_;

    return 1 if eval { $self->k8s->delete($kind, $name, @args); 1 };

    my $err = $@;
    return 1 if $err =~ /\b404\b/;

    warn "[node] delete of $kind/$name failed: $err";
    return 0;
}

sub _verify {
    my $self = shift;

    my $name     = $self->name;
    my $k8s_name = $self->cr->{status}{kubernetesNodeName} // $name;

    my $k8s_node = eval {
        $self->k8s->get('Node', name => $k8s_name);
    };

    return 0 unless $k8s_node;

    my $node_hash = ref($k8s_node) eq 'HASH'
        ? $k8s_node
        : $self->k8s->k8s->object_to_struct($k8s_node);

    for my $cond (@{ $node_hash->{status}{conditions} // [] }) {
        if ($cond->{type} eq 'Ready' && $cond->{status} eq 'True') {
            return 1;
        }
    }

    return 0;
}

1;

__END__

=head1 NAME

OCP::Node - Trigger-neutral node reconcile state machine

=head1 SYNOPSIS

    use OCP::Node;

    my $node = OCP::Node->from_cr($cr,
        k8s           => $api,
        provider      => $provider,
        ssh_key       => $key,
        server_url    => "https://cp-1:9345",
        join_token    => $token,
        reconciler_id => 'cli',
    );

    # Single step (called by Robocop watch-loop)
    $node->reconcile;

    # Block until Ready or Failed (called by ocp node add)
    $node->reconcile_until_ready(timeout => 600);

    # Drain + delete provider server + delete CRs
    $node->teardown;

=head1 DESCRIPTION

OCP::Node drives a single OCPNode CR through its lifecycle:

    Pending -> Installing -> Joining -> Ready

Each call to C<reconcile> advances the node by one phase based on the
current C<status.phase> stored in the CR.  The method is idempotent and
trigger-neutral: the same code runs whether called from the CLI one-shot
path (C<ocp node add>) or from Robocop's in-cluster watch-loop.

C<Provisioning> is also accepted and behaves exactly like C<Installing>,
but nothing in OCP writes it: C<_provision> creates the server and moves
straight to C<Installing>.  The CRD keeps it in its enum, so a CR that
arrived there some other way still reconciles instead of dying on an
unknown phase.

=head2 Where the node is

C<_provision> records the address only when the provider already knows one.
A cloud provider does not: Hetzner allocates the IP when the machine reaches
C<running>, seconds after C<create_server> returns, so a freshly created
worker enters C<Installing> with C<status.publicIP> unset and a message
saying so.

The C<Installing> pass resolves it, in this order: C<status.publicIP>,
then C<spec.host> (which is where the C<ssh> and C<local> providers keep
it), then the provider itself — bounded by
C<$OCP::Node::ADDRESS_TIMEOUT> (120 s, the same budget
L<OCP::Cmd::Apply::Bootstrap> spends on the same wait).  A resolved address
is written back to C<status.publicIP> before it is used, so later passes,
C<ocp node ls> and C<teardown> all see it.

Waiting there rather than in C<_provision> is deliberate.  C<Installing> is
re-enterable and the provider id is already in status by the time the wait
starts; a wait inside C<_provision> would sit on the reconciler lease with
the id of a running, billing server written down nowhere.  It needs no new
phase either: the C<status.phase> enum in the OCPNode CRD is closed, so an
extra value would be rejected by the API server until every deployed
cluster's CRD had been re-applied.

All Kubernetes access goes through C<_get_cr> / C<_put_cr> / C<_struct>.
L<Kubernetes::REST> takes the B<Kind> in its first argument and resolves it
through C<expand_class>, so an api-version passed there is fatal rather than
merely wrong; and C<update> requires a blessed L<IO::K8s> object while this
class handles C<cr> as a plain hash.  Both rules are honoured in those three
methods and nowhere else.

=head2 Lease Mechanics

Before provisioning infrastructure, C<OCP::Node> writes a
C<ocp.internal/reconciler-lease> annotation to the OCPNode CR.  The
annotation encodes the holder id, timestamp, and TTL (300 s).  A second
reconciler will refuse to proceed while a live lease is held by a
different C<reconciler_id>.  The lease is released after the phase
transition is written to status.

=head2 Key Attributes

=over 4

=item cr

The OCPNode CR as a plain hash.  Updated in place via C<_set_cr> after
every K8s write.

=item k8s

A L<Kubernetes::REST> API instance, pre-registered with
C<OCP::K8s->register>.

=item provider

An C<OCP::Provider::*> instance used for server create/delete.  Optional
when the node already has a public IP in status.

=item reconciler_id

String identifying the reconciler holding the lease.  Defaults to
C<'cli'>.  Robocop sets this to a pod-scoped identifier.

=back

=head1 SEE ALSO

L<OCP::Provider>, L<OCP::K8s>, L<OCP::Cmd::Node::Add>

=cut

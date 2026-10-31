package OCP::Cmd::Node::Add;
# ABSTRACT: Add an OCPNode CR and optionally reconcile it

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use JSON::PP ();
use Path::Tiny ();
use Socket ();
use Kubernetes::REST::Kubeconfig;
use OCP::Choices;
use OCP::Cmd::Apply::AMDGPU ();
use OCP::Cmd::Apply::CR ();
use OCP::Cmd::Apply::K8s ();
use OCP::Cmd::Apply::Workloads ();
use OCP::Config;
use OCP::Secrets;
use OCP::K8s;
use OCP::Node;
use OCP::NodeMeta;
use OCP::Provider;
use OCP::SSH;

with 'OCP::Role::Cmd';

option name => (
    is     => 'rw',
    format => 's',
    doc    => 'Node name (may also be given as the first argument)',
);

option role => (
    is      => 'ro',
    format  => 's',
    default => sub { 'worker' },
    doc     => 'Node role (worker|control-plane)',
);

option provider => (
    is     => 'ro',
    format => 's',
    doc    => "OCPNodeProvider name, e.g. ssh-default - not the type 'ssh' (see 'ocp provider ls')",
);

option host => (
    is     => 'ro',
    format => 's',
    doc    => 'Host IP or FQDN (ssh provider only)',
);

option server_type => (
    is     => 'ro',
    format => 's',
    doc    => 'Server type override (hetzner only)',
);

option location => (
    is     => 'ro',
    format => 's',
    doc    => 'Location override (hetzner only)',
);

option image => (
    is     => 'ro',
    format => 's',
    doc    => 'Image override (hetzner only)',
);

option gpu => (
    is  => 'ro',
    doc => 'Enable GPU support',
);

# Repeatable (k211): spec.labels / spec.taints, which OCP::Node puts on the
# Kubernetes Node.
option label => (
    is         => 'ro',
    format     => 's',
    repeatable => 1,
    default    => sub { [] },
    doc        => 'Node label key=value (repeatable)',
);

option taint => (
    is         => 'ro',
    format     => 's',
    repeatable => 1,
    default    => sub { [] },
    doc        => 'Node taint key=value:Effect or key:Effect (repeatable)',
);

# spec.nodeIP (k254): the address the node registers as its InternalIP. Only
# ever what is given here -- absent, no node-ip is asked for at all.
option node_ip => (
    is     => 'ro',
    format => 's',
    doc    => 'Address the node registers by (RKE2/K3s node-ip): one IP, or v4,v6',
);

# Spelled without a dash on purpose, like --nogit and --nopassword in
# `ocp init`. MooX::Options strips a literal "no-" as Getopt::Long's negation
# marker before it turns dashes into underscores, so `--no-wait` asked to
# negate a "wait" option that does not exist and died with "Unknown option:
# wait". `--no_wait` stays as an alias for anything that already uses it.
option nowait => (
    is    => 'ro',
    short => 'no_wait',
    doc   => 'Write CR and exit without waiting for Ready',
);

has k8s => (is => 'rw');

sub _k8s {
    my $self = shift;
    return $self->k8s if $self->k8s;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config  = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $kc_content = $secrets->read_kubeconfig;
    die OCP::Secrets->no_kubeconfig_refusal
        unless $kc_content;

    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$kc_fh} $kc_content;
    close $kc_fh;

    my $api = Kubernetes::REST::Kubeconfig->new(
        kubeconfig_path => $kc_fh->filename,
    )->api;

    # Kept with the command: the AMD GPU stack's library reads the kubeconfig
    # as a file (_apply_cmd hands it on), and the file goes when this does.
    $self->{_kc_temp} = $kc_fh;

    OCP::K8s->register($api);
    $self->k8s($api);
    return $api;
}

sub _resolve_provider {
    my ($self, $api) = @_;

    my $ns = 'ocp-system';

    # Both rejections below name the providers that exist, with their types:
    # --provider takes the CR name and the type is what gets typed instead.
    # OCP::Role::Cmd owns the wording so `ocp provider rm` says the same thing.
    return $self->provider_cr($api, $self->provider, namespace => $ns)
        if $self->provider;

    # A synthetic provider (OCPNodeProvider/legacy, written by apply for nodes
    # that joined outside OCP) only names where an observed node came from;
    # nothing is ever provisioned through it, so it is no implicit choice
    # (lab 2026-10-15: it made --provider mandatory next to ssh-default).
    my @items = grep {
        (($_->{metadata}{annotations} // {})->{'ocp.internal/synthetic'} // '') ne 'true'
    } $self->provider_crs($api, namespace => $ns);

    if (@items == 1) {
        return $items[0];
    }

    if (@items == 0) {
        die $self->provider_choices();
    }

    for my $p (@items) {
        my $ann = $p->{metadata}{annotations} // {};
        return $p if ($ann->{'ocp.internal/default'} // '') eq 'true';
    }

    die "Multiple providers found, --provider required.\n"
      . $self->provider_choices(@items);
}

sub _validate_flags {
    my ($self, $provider_type, $provider_name) = @_;

    # The type came out of a provider CR, not off this command line, so the
    # rejection names the CR that carries it — telling the operator a word
    # they never typed is invalid explains nothing about where to go and
    # fix it. known_type is the same source OCP::Choices::unknown reads
    # below via OCP::Provider->types (k121): a fourth provider added
    # to OCP::Provider is accepted here, not classified as unknown.
    die OCP::Choices::unknown('provider type', $provider_type,
        [ OCP::Provider->types ],
        hint => defined $provider_name
            ? "OCPNodeProvider '$provider_name' declares spec.type"
              . " '$provider_type'.\n"
            : '',
    ) unless OCP::Provider->known_type($provider_type);

    # --host is ssh's contract: the SSH provider works by reaching an
    # existing machine, so ssh requires it and every other known type
    # rejects it. A future provider that does take a host would land here
    # too; the existing types are the only ones that do.
    if ($provider_type eq 'ssh') {
        die "--host is required for provider type 'ssh'\n"
            unless $self->host;
    }
    else {
        die "--host is not valid for provider type '$provider_type'\n"
            if $self->host;
    }

    # --server-type, --location and --image are hetzner overrides; ssh,
    # local and every future provider reject them. hetzner accepts them
    # because they are its own.
    return if $provider_type eq 'hetzner';

    die "--server-type is only valid for provider type 'hetzner' (given for '$provider_type')\n"
        if $self->server_type;
    die "--location is only valid for provider type 'hetzner' (given for '$provider_type')\n"
        if $self->location;
    die "--image is only valid for provider type 'hetzner' (given for '$provider_type')\n"
        if $self->image;
}

sub _build_cr {
    my ($self, $provider_name) = @_;

    # spec.gpu is declared `type: boolean` in the OCPNode CRD. The bare Perl 1
    # that MooX::Options hands over serializes as a JSON integer and the API
    # rejects the CR with a 422, so it has to go out as a JSON boolean.
    my %labels = map { OCP::NodeMeta->parse_label($_) } @{ $self->label };
    my @taints = map { OCP::NodeMeta->parse_taint($_) } @{ $self->taint };

    my %spec = (
        role        => $self->role,
        providerRef => $provider_name,
        ($self->host        ? (host       => $self->host)        : ()),
        ($self->server_type ? (serverType => $self->server_type) : ()),
        ($self->location    ? (location   => $self->location)    : ()),
        ($self->image       ? (image      => $self->image)       : ()),
        ($self->gpu         ? (gpu        => JSON::PP::true)     : ()),
        (%labels            ? (labels     => \%labels)           : ()),
        (@taints            ? (taints     => \@taints)           : ()),
        ($self->node_ip     ? (nodeIP     => $self->node_ip)     : ()),
    );

    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => {
            name      => $self->name,
            namespace => 'ocp-system',
            # A worker's machine is torn down when its OCPNode is deleted
            # (k179); a control plane never is.
            ($self->role eq 'worker'
                ? (finalizers => [ OCP::Node::TEARDOWN_FINALIZER ]) : ()),
        },
        spec       => \%spec,
    };
}

sub _robocop_ready {
    my ($self, $api) = @_;

    my $deploy = eval {
        $api->get('Deployment', name => 'robocop', namespace => 'ocp-system')
    };
    return 0 unless $deploy;

    my $h = $api->k8s->object_to_struct($deploy);
    return ($h->{status}{readyReplicas} // 0) >= 1;
}

# Robocop is doing the work; this only watches the CR it writes.
#
# Same budget as the CLI path below, from the same place: the machine takes as
# long as it takes, and who drives it changes nothing about that -- if anything
# this side is slower, since every phase has to wait for robocop's next tick.
sub _poll_until_ready {
    my ($self, $api, %opt) = @_;

    my $timeout  = $opt{timeout}  // $OCP::Node::READY_TIMEOUT;
    my $interval = $opt{interval} // 5;
    my $deadline = time + $timeout;
    my $reported = '';

    while (time < $deadline) {
        my $cr = eval {
            $api->get('OCPNode', name => $self->name, namespace => 'ocp-system')
        };
        if ($cr) {
            my $h     = $api->k8s->object_to_struct($cr);
            my $phase = $h->{status}{phase} // 'Pending';
            $reported = $self->_report_phase($reported, $phase,
                $h->{status}{message});
            return 1 if $phase eq 'Ready';
            return 0 if $phase eq 'Failed';
        }
        sleep $interval;
    }
    return 0;
}

# Say what is being waited for, once per phase.
#
# Both wait paths can sit here for a quarter of an hour (OCP::Node's
# READY_TIMEOUT, and the sum it is made of), and both used to do it in complete
# silence: the operator saw the command hang and, if the budget ran out, a bare
# "did not reach Ready state" with nothing to say how far it got. Returns the
# phase now reported, so the caller can pass it back in on the next tick.
#
# Failed is not progress: its message is the reason the node did not come up,
# often with the fix, so it goes to STDERR in the [!!] style (k204). It is the
# only place that reason is said -- execute's "did not reach Ready state" only
# names the node.
sub _report_phase {
    my ($self, $reported, $phase, $message) = @_;

    return $reported if $phase eq $reported;

    my $line = "$phase"
        . (defined $message && length $message ? ": $message" : '');
    $line .= "\n" unless $line =~ /\n\z/;

    if ($phase eq 'Failed') { print STDERR "  [!!] $line" }
    else                    { print "  [..] $line" }

    return $phase;
}

sub _cli_reconcile {
    my ($self, $cr, $api, $config, $secrets) = @_;

    my $provider_cr = eval {
        $api->get('OCPNodeProvider',
            name      => $cr->{spec}{providerRef},
            namespace => 'ocp-system',
        )
    };
    my $provider_h = $provider_cr
        ? $api->k8s->object_to_struct($provider_cr)
        : undef;

    my $provider_obj = $provider_h
        ? eval { OCP::Provider->from_cr($provider_h, k8s => $api) }
        : undef;

    # The control plane's address lives in two places: ocp.yaml (spec) names
    # what the operator wants, .ocp/status.yaml records what the cluster
    # actually has. cluster_status reads the latter first and falls back to
    # the former only when nothing has been recorded -- so a server whose IP
    # drifted since the last `ocp apply` (or never had an `ocp apply`) is
    # still reached. Reading control_planes straight, as this used to, gave
    # back the spec address and SSH'd to a machine that may not exist
    # (k120, sibling of k98).
    my $cp_ip = $config->cluster_status->{public_ip};

    # $key outlives the block on purpose: the failure it explains happens at
    # the bottom of this sub, long after the join token was read.
    my ($ssh_key, $server_url, $join_token, $key);

    if ($cp_ip) {
        # The key has to be the one the CONTROL PLANE trusts: this reads the
        # join token off it over SSH. Reading $config->ssh_private_key_path
        # straight was right for dev mode and wrong for every secure-mode
        # cluster, where machines trust the admin key and that file is not
        # even created — `ocp node add` died with "Cannot read SSH key" on the
        # one path it was most needed. k87.
        #
        # The same key goes on to OCP::Node as ssh_key, which is what the
        # deploy path does too (OCP::Cmd::Apply::CR::cli_reconcile_workers
        # slurps the very file bootstrap picked): one key for the control
        # plane and the workers it brings up.
        $key = $self->cluster_ssh_key($config, reason => 'ocp node add');
        my $ssh_key_path = $key->path;
        $ssh_key = $key->content;

        $server_url = $config->join_url($cp_ip);

        my $dist = $config->distribution || 'rke2';
        my $token_path = $dist eq 'k3s'
            ? $OCP::Node::K3S_TOKEN_PATH
            : $OCP::Node::RKE2_TOKEN_PATH;

        require OCP::SSH;
        my $cp_ssh = OCP::SSH->new(
            host     => $cp_ip,
            key_file => $ssh_key_path,
            user     => 'root',
        );
        my $result = $cp_ssh->run("cat $token_path");
        $join_token = $result->{stdout};
        chomp $join_token if $join_token;
        die "Could not retrieve join token from control plane\n"
          . $key->migration_hint
            unless $join_token;
    }

    # The project's kubeconfig (k196): OCP::Node hands it to a worker's agent
    # install, which checks the agent's version against the control plane's
    # before it touches the machine.
    my $kubeconfig = $secrets && $secrets->read_kubeconfig;

    my $node = OCP::Node->from_cr($cr,
        k8s           => $api,
        ($provider_obj ? (provider => $provider_obj) : ()),
        ($ssh_key      ? (ssh_key  => $ssh_key)      : ()),
        # A refused key named as the operator knows it, not as the temp copy
        # OCP::Node writes (k226).
        ($key          ? (ssh_key_label => $key->label) : ()),
        # Which key, so a refusal names the one missing (k209); the bootstrap
        # key of dev mode is neither.
        ($key && $key->origin eq 'admin' ? (ssh_key_purpose => 'admin') : ()),
        ($server_url   ? (server_url => $server_url) : ()),
        ($join_token   ? (join_token => $join_token) : ()),
        ($kubeconfig   ? (kubeconfig => $kubeconfig) : ()),
        distribution  => ($config->distribution || 'rke2'),
        pod_cidr      => $config->pod_cidr,   # a control-plane join repeats it (k184)
        reconciler_id => 'cli',
        # ocp.yaml's system: block, off the provider CR like robocop reads it
        # (k217) -- one source for every join path.
        ($provider_h ? OCP::Provider->system_flags_from_cr($provider_h) : ()),
        # ocp.yaml's gpu: switches off the same CR, all of them, as robocop
        # and `ocp apply` hand them over (k31): gpu.enabled false is the
        # cluster kill switch, which wins over this node's spec.gpu (--gpu)
        # here as it does when robocop joins the node; gpu.driver operator
        # leaves the driver to the GPU Operator; gpu.toolkit (k223) and
        # gpu.amd.integrated (k253) as before. Each absent from a CR that
        # predates its field. Until k358 only those last two came here: k31
        # wired the robocop and apply paths and left this one out.
        ($provider_h ? OCP::Provider->gpu_flags_from_cr($provider_h) : ()),
        # Its warnings as this command's own (k254), the line `ocp apply`
        # hands it too (OCP::Cmd::Apply::CR::node_logger).
        logger        => OCP::Cmd::Apply::CR::node_logger(),
    );

    # No budget named here: OCP::Node owns it ($OCP::Node::READY_TIMEOUT), and
    # it is one question -- how long may a machine take to become a node --
    # regardless of who is watching. The 600 this used to name did not cover
    # the sum of the waits underneath it.
    my $reported = '';
    my $unready;
    my $ok = $node->reconcile_until_ready(on_phase => sub {
        my ($phase, $message) = @_;
        $unready = 1 if $phase ne 'Ready';
        $reported = $self->_report_phase($reported, $phase, $message);
    });

    # It was seen short of Ready and then Ready: OCP::Node made the Ready
    # transition in this run, and said a node-ip mismatch through
    # its logger as it did. A node Ready from the start was turned Ready by
    # an earlier run, so nothing was said, and _check_node_ip asks.
    #
    # Only if what it held the node against was this --node_ip: it holds it
    # against status.nodeIP, what the install was handed off the stored
    # OCPNode. One stored without spec.nodeIP (k290) is handed none, records
    # none and so checks nothing -- and _check_node_ip has to ask.
    $self->{_ready_said} = 1 if $ok && $unready
        && ($node->cr->{status}{nodeIP} // '') eq ($self->node_ip // '');

    # Ran out of budget rather than reaching a verdict. Worth separating: the
    # node is not broken, nobody rolled anything back, and the very next run
    # continues from the phase in the CR.
    #
    # Told apart by what the sink last reported, not by asking the node again:
    # a phase of Failed means OCP::Node reached a verdict and said so, and
    # anything else means the loop stopped watching mid-flight. Nothing
    # reported at all (nothing was ever waited for) says nothing here either.
    if (!$ok && length $reported && $reported ne 'Failed') {
        print STDERR "  [!!] Still in phase '$reported' after "
          . $OCP::Node::READY_TIMEOUT . "s -- the install may well still be "
          . "running on the machine. The CR keeps its phase; re-running this "
          . "command or `ocp apply` continues from there.\n";
    }

    # The worker never came up, and this project still has the pre-ADR-0027
    # bootstrap key on disk: most likely a machine whose authorized_keys were
    # written back when that key was what OCP handed out, so it refuses the
    # admin key this run offered. migration_hint says nothing unless both
    # halves of that are true.
    #
    # It is said HERE and not in OCP::Node, which is trigger-neutral: the same
    # class runs inside robocop, where `ocp keys show` is not a command anyone
    # can type and nobody reads the output (k97).
    #
    # Diagnosis, not preflight — nothing looked ahead to see which key this
    # machine accepts, and the hint's own wording says so. Nothing falls back
    # to the bootstrap key either, and $ok is passed through untouched: a
    # worker that did not come up still fails, with the same exit code.
    #
    # Once per run comes free here — `ocp node add` adds one node. The other
    # place this key is named is the join-token failure above, which dies
    # before ever reaching this line.
    print STDERR $key->migration_hint if !$ok && $key;

    return $ok;
}

sub execute {
    my ($self, $args, $chain) = @_;

    $self->name($self->name // ($self->positional_args($args))[0]);
    die "Usage: ocp node add NAME [--role worker|control-plane]\n"
        unless defined $self->name && length $self->name;

    # Before the API client is even built. --role is copied straight into
    # spec.role, where the OCPNode CRD declares `enum: [control-plane,
    # worker]`, so an unchecked typo used to travel all the way to the API
    # server and come back as a raw 422 about a schema the operator never
    # wrote: the CLI explained Kubernetes instead of explaining the input
    # (k103). The set is OCP::Node's, held against the CRD by a test.
    die OCP::Choices::unknown('role', $self->role, [ OCP::Node->roles ])
        unless OCP::Node->known_role($self->role);

    # --label / --taint, before the API is asked anything (k211).
    for my $l (@{ $self->label }) {
        my $err = OCP::NodeMeta->label_error($l);
        die "--label: $err\n" if defined $err;
    }
    for my $t (@{ $self->taint }) {
        my $err = OCP::NodeMeta->taint_error($t);
        die "--taint: $err\n" if defined $err;
    }
    # --node_ip likewise (k254), in the words ocp.yaml and OCP::Node use.
    if (defined(my $err = OCP::Choices::node_ip_error($self->node_ip))) {
        die "--node_ip: $err\n";
    }
    # --gpu: the gpu: block of ocp.yaml, before the kubeconfig (PIN1) and the
    # cluster are asked anything (k333).
    $self->_refuse_invalid_gpu_config if $self->gpu && !$self->nowait;

    my $api           = $self->_k8s;
    my $provider_hash = $self->_resolve_provider($api);
    my $provider_type = $provider_hash->{spec}{type}
        or die "Provider has no spec.type\n";
    my $provider_name = $provider_hash->{metadata}{name};

    $self->_validate_flags($provider_type, $provider_name);

    # Before the first write, and before the host preflight's SSH probe and
    # its PIN2 (k290).
    $self->_refuse_unstored_node_ip($api);

    # Who drives the node decides what happens to a host that cannot be
    # reached (k238). Asked only with --host: without it --nowait never reads
    # the Deployment, and the value read here is reused further down, not read
    # twice.
    my $robocop_ready;
    my $has_host = defined $self->host && length $self->host;
    if ($has_host) {
        $robocop_ready = $self->_robocop_ready($api);

        # Robocop off: this machine does the join, so what it cannot resolve or
        # reach fails here, BEFORE the first cluster write -- a refusal leaves
        # no OCPNode behind. With robocop on the OCPNode stays the request (the
        # name may resolve only in the cluster, k236) and a failure shows up as
        # Failed with the message.
        $self->_preflight_host($provider_type) unless $robocop_ready;
    }

    my $cr = $self->_build_cr($provider_name);
    $api->ensure($cr);

    my $key_note = $self->_ssh_keys_note($provider_type);

    # robocop reaches the machine by this name from inside the cluster (k236).
    print STDERR $self->_host_name_note($self->host) if $robocop_ready;

    if ($self->nowait) {
        print $self->name . "\n";
        # STDOUT is the node name and nothing else; the hints are not payload.
        print STDERR $key_note;
        print STDERR "Node '" . $self->name . "' asks for a GPU: once it is Ready, "
          . "run `ocp apply` to deploy its GPU stack.\n"
            if $self->gpu;
        return 0;
    }

    print "  [..] $key_note" if length $key_note;

    my ($ok, $config);
    if ($robocop_ready // $self->_robocop_ready($api)) {
        sleep 5;
        $ok = $self->_poll_until_ready($api);
    }
    else {
        $config = $self->_config;
        my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
        $ok = $self->_cli_reconcile($cr, $api, $config, $secrets);
    }

    unless ($ok) {
        print STDERR "Node '" . $self->name . "' did not reach Ready state.\n";
        return 1;
    }

    print "Node '" . $self->name . "' is Ready.\n";
    $self->_check_node_ip($api);
    $self->_ensure_gpu_stack($api, $config // $self->_config) if $self->gpu;
    return 0;
}

# Did the node register at the --node_ip it was given (k254)? Asked once it is
# Ready, of the Node the cluster holds (OCP::Node->node_ip_mismatch), and said
# as a [WARN] on STDERR -- the very line OCP::Node writes when it turns a node
# Ready in this process, which is why that case is left to it (_ready_said):
# said once. Asked here when robocop did the join, whose own warning goes to
# its log, and for a node that was Ready already. Held against what this
# command asked for, not status.nodeIP: a robocop that predates k254 hands no
# node-ip and records none, and its node registers elsewhere all the same.
#
# Never fatal: the node is Ready, and only a human can say which address is
# right. Returns 1 when it registered there or nothing was asked.
#
# First, though, whether the OCPNode holds it at all (k290): the CRD was read
# before the write (_refuse_unstored_node_ip), but an API server can serve an
# updated CRD a moment before it stores by it, and every install reads the
# node-ip off the stored OCPNode. Said when it holds none -- the trace a
# pruned field leaves -- and not when it cannot be read; the Node check below
# goes on with the OCPNode's name then, as before.
sub _check_node_ip {
    my ($self, $api) = @_;
    my $node_ip = $self->node_ip;
    return 1 unless $node_ip;
    return 1 if $self->{_ready_said};

    my $ok = 1;
    my $h  = $self->_stored_ocpnode($api);
    if ($h && !length($h->{spec}{nodeIP} // '')) {
        print STDERR '[WARN] ' . $self->name . ': OCPNode ' . $self->name
            . ' holds no spec.nodeIP, though --node_ip ' . $node_ip . ' was given: the API '
            . 'server dropped the field, as an OCPNode CRD from an older ocp does, and every '
            . "install reads the node-ip from there. `ocp apply` updates the CRD.\n";
        $ok = 0;
    }

    my $k8s_name = $self->_kubernetes_node_name($api, $h);
    my $node     = eval { $api->get('Node', name => $k8s_name) };
    unless ($node) {
        my $err = $@ || "not found\n";
        $err .= "\n" unless $err =~ /\n\z/;
        print STDERR '[WARN] ' . $self->name . ': InternalIP not checked against --node_ip '
            . $node_ip . ": Node '$k8s_name' could not be read: $err";
        return 0;
    }

    my $diag = OCP::Node->node_ip_mismatch($api->k8s->object_to_struct($node), $node_ip);
    return $ok unless defined $diag;
    print STDERR '[WARN] ' . $self->name . ': ' . $diag . "\n";
    return 0;
}

# Can this cluster store spec.nodeIP (k290)? Asked with --node_ip only. An
# OCPNode CRD from before k254 does not declare it, and the API server drops a
# field its structural schema does not declare without an error: the OCPNode
# is stored without it, the install (which reads the stored OCPNode) is handed
# no node-ip, and the node registers the address of its default route --
# live on amdlab, with nothing said. So the CRD is read before the first write
# and a CRD that cannot store it refuses the command, on STDERR via bin/ocp.
#
# Read, never re-applied from here: an ocp older than the cluster's CRD would
# take the newer schema back. `ocp apply` updates it, in its "Checking node
# CRs" step; `ocp deploy-robocop` does too, but deploys robocop with it.
#
# Read rather than a server-side dry-run create: one GET whether the OCPNode
# exists or not (a dry-run create of an existing one is a 409, a dry-run
# update needs its resourceVersion), and the refusal names the cause. v1 is
# the only version the CRD ever had and the one ocp writes.
#
# Only a 404 is "no CRD" (crd_get, k269); any other failed read refuses with
# its cause -- a CRD nobody could read is not one that is fine.
my $OCPNODE_CRD = 'ocpnodes.ocp.internal';

sub _refuse_unstored_node_ip {
    my ($self, $api) = @_;
    return 1 unless $self->node_ip;

    my $crd = eval {
        OCP::Cmd::Apply::K8s::crd_get($self, $api,
            '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/' . $OCPNODE_CRD);
    };
    if (my $err = $@) {
        $err .= "\n" unless $err =~ /\n\z/;
        die "--node_ip: could not check that this cluster stores spec.nodeIP: $err"
          . "  Nothing was written.\n";
    }

    die "--node_ip: this cluster has no OCPNode CRD ($OCPNODE_CRD), so nothing can store\n"
      . "  spec.nodeIP. Run `ocp apply` first: it installs the CRD. Then run this command\n"
      . "  again. Nothing was written.\n"
        unless $crd;

    return 1 if $self->_crd_declares_node_ip($crd);

    die "--node_ip: this cluster's OCPNode CRD ($OCPNODE_CRD) has no spec.nodeIP -- an\n"
      . "  older ocp installed it -- so the API server would drop the field without an error\n"
      . "  and the node would register the address of its default route.\n"
      . "  Run `ocp apply` first: it updates the CRD. Then run this command again.\n"
      . "  Nothing was written.\n";
}

# spec.nodeIP in the schema of the CRD's v1, which must be served.
sub _crd_declares_node_ip {
    my ($self, $crd) = @_;
    my $versions = ref $crd eq 'HASH' && ref $crd->{spec} eq 'HASH'
        ? $crd->{spec}{versions} : undef;
    my ($v1) = grep { ref $_ eq 'HASH' && ($_->{name} // '') eq 'v1' }
        @{ ref $versions eq 'ARRAY' ? $versions : [] };
    return 0 unless $v1 && $v1->{served};

    my $at = $v1;
    for my $key (qw( schema openAPIV3Schema properties spec properties nodeIP )) {
        return 0 unless ref $at eq 'HASH';
        $at = $at->{$key};
    }
    return ref $at eq 'HASH' ? 1 : 0;
}

# Robocop off, `--host` given (k238): look at the host BEFORE the OCPNode is
# written, so a refusal leaves nothing in the cluster. First the name -- it
# must resolve on this machine, which is the machine that does the join; an IP
# literal needs no lookup (same test as _host_name_note) -- then, without
# --nowait, the SSH probe. --nowait defers every contact with the machine to the
# join that comes later, so it checks the name and nothing else.
#
# A refusal dies with a "\n"-terminated message (OCP::SSH's own text), which
# bin/ocp prints on STDERR with exit 1. Returns 1 when the host passed.
sub _preflight_host {
    my ($self, $provider_type) = @_;

    my $host = $self->host;
    return 1 unless defined $host && length $host;

    unless ($host =~ /\A\d+\.\d+\.\d+\.\d+\z/ || $host =~ /:/) {
        die OCP::SSH->unresolved_message($host)
            unless $self->_resolves_here($host);
    }

    $self->_host_probe_ssh($host) unless $self->nowait;
    return 1;
}

# The SSH probe of _preflight_host: the same wait the join does (OCP::SSH
# wait_for_ssh), with the key _cli_reconcile will use, so a refused key or an
# unreachable host is said now and not as a Failed OCPNode. Dies with OCP::SSH's
# message (unresolved_message / rejection_message / "not reachable").
#
# Skipped, not failed, when there is nothing to probe with: no control-plane
# address recorded means _cli_reconcile gets no key either (it reads the join
# token off the control plane), and inventing a new error here would turn a
# state that path tolerates into a refusal. The join then reports as before.
#
# The probe trusts host keys into a throwaway known_hosts file: a preflight
# must not record anything in the project's file (OCP::Node pins the keys on
# the join), and a changed key is the join's to report.
sub _host_probe_ssh {
    my ($self, $host) = @_;

    my $config = $self->_config;
    return 1 unless $config->cluster_status->{public_ip};

    my $key   = $self->cluster_ssh_key($config, reason => 'ocp node add');
    my $known = Path::Tiny->tempfile;
    my $ssh   = OCP::SSH->new(
        host        => $host,
        key_file    => $key->path,
        user        => 'root',
        known_hosts => "$known",
        (defined $key->label ? (key_label => $key->label) : ()),
        ($key->origin eq 'admin' ? (key_purpose => 'admin') : ()),
    );

    eval { $ssh->wait_for_ssh; 1 } and return 1;
    my $err = $@;
    $err = "$err";
    $err .= "\n" unless $err =~ /\n\z/;
    die $err;
}

# The hint for `--host NAME` with robocop on (k236), '' when there is nothing to
# say: an IP address needs no lookup, anywhere. A name is resolved by robocop in
# the cluster (CoreDNS, then the node's resolver), not by this machine, so what
# resolves here proves nothing -- least of all a name only /etc/hosts or a
# container's --add-host knows, which no pod sees. The CLI-side lookup only
# picks the wording. No in-cluster test is made. Only said with robocop on; with
# it off the name is checked before the OCPNode is written (_preflight_host,
# k238).
sub _host_name_note {
    my ($self, $host) = @_;
    return '' unless defined $host && length $host;
    return '' if $host =~ /\A\d+\.\d+\.\d+\.\d+\z/ || $host =~ /:/;

    my $why = !$self->_resolves_here($host)
            ? "it does not resolve from this machine either"
            : $self->_in_etc_hosts($host)
            ? "here it resolves through /etc/hosts or similar, which no pod sees"
            : "whether it does cannot be checked from here";
    return "  [!!] --host '$host' is a name, and robocop resolves it inside the cluster\n"
         . "       (CoreDNS), not on this machine: $why.\n"
         . "       If the cluster cannot resolve it the node fails; use the IP or a name\n"
         . "       the cluster's DNS knows.\n";
}

sub _resolves_here {
    my ($self, $host) = @_;
    my ($err, @res) = Socket::getaddrinfo($host, undef, { socktype => Socket::SOCK_STREAM() });
    return !$err && @res ? 1 : 0;
}

# Overridable seam for tests.
sub _etc_hosts_file { '/etc/hosts' }

sub _in_etc_hosts {
    my ($self, $host) = @_;
    my $file = $self->_etc_hosts_file;
    return 0 unless -r $file;
    for my $line (Path::Tiny::path($file)->lines({ chomp => 1 })) {
        $line =~ s/#.*//;
        my (undef, @names) = split ' ', $line;
        return 1 if grep { lc $_ eq lc $host } @names;
    }
    return 0;
}

sub _config {
    my ($self) = @_;
    return OCP::Config->new(file => $self->ocp->config);
}

# An ssh-provider machine in secure mode needs BOTH public keys in root's
# authorized_keys (k209): robocop joins and tears it down with the robo key,
# `ocp node rm`, `ocp ssh` and a CLI join reach it with the admin key. Which of
# them comes knocking depends on who drives the node, so a machine with only
# one of them works until the other one is needed -- live, a robocop join that
# went through and an `ocp node rm` left Failed with rke2 still running.
#
# Nothing here can look into authorized_keys on the far side, so this says it
# before the join instead of checking; the refusal itself names the missing
# key (OCP::SSH key_purpose). Empty for every other provider and in dev mode,
# where a single key reaches everything.
sub _ssh_keys_note {
    my ($self, $provider_type) = @_;

    return '' unless $provider_type eq 'ssh';
    return '' unless eval { -f $self->_config->project_dir->child('keys.yaml') };

    return 'Host ' . $self->host . " needs both public keys in root's "
      . "authorized_keys (secure mode): robo for robocop, admin for the CLI and "
      . "`ocp node rm`. `ocp keys authorized-keys` prints both.\n";
}

# validate()'s lines for the gpu: block of ocp.yaml, all at once, with --gpu
# and without --nowait (k333): before the kubeconfig is decrypted (PIN1), the
# provider looked up, the OCPNode written, the host probed (PIN2) or joined.
# The block is read once the node is Ready -- gpu.enabled by _ensure_gpu_stack
# below, gpu.driver and gpu.toolkit by the GPU Operator check, gpu.amd by the
# AMD GPU stack -- and since k320 a malformed gpu.enabled croaked there,
# outside an eval, with the node in the cluster; a malformed gpu.driver or
# gpu.amd key failed its check there, for a line validate() had before
# anything began. Dies "\n"-terminated: bin/ocp prints it on STDERR, exit 1.
#
# Only those lines, not all of validate() as `ocp keys secure` has it (k321).
# Its reasons do not carry over: node add is how a node joins a running
# cluster between two `ocp apply` runs, not a command one follows, and it
# reads little else of ocp.yaml -- the kubeconfig alone with robocop; the
# control plane's address, the key, the distribution and the pod CIDR without
# it. A refusal over a cilium: or lbipam: line it never reads, or one a newer
# validate() adds, would hold a node up over something that has nothing to do
# with it. What else the GPU steps read, apply's code, they read inside their
# evals: a failure there is a stack "not ensured", said with `ocp apply`, not
# a command that dies after the join. The control_planes and workers shapes
# this command reads are k306's.
#
# Not with --nowait, which reads none of the block: it leaves the GPU stack to
# `ocp apply`, and that refuses the same lines before it touches anything
# (k255). The lines are validate()'s for the key path gpu, or under it, as
# spec_errors('gpu') has them without running the rest of validate() (k306).
# An ocp.yaml that is empty or no mapping holds no gpu: block: spec_errors
# stops with the file's line, so that is refused here too. A filter over
# validate() dropped that line: the command went on to the kubeconfig (PIN1)
# and the OCPNode write, and stopped where a reader came to the spec first --
# in the join without robocop, at the GPU stack after the join with it.
sub _refuse_invalid_gpu_config {
    my ($self) = @_;
    my $config = $self->_config;
    my @errors = $config->spec_errors('gpu');
    return 1 unless @errors;

    my $file = $config->file;
    my $s    = @errors == 1 ? '' : 's';
    die "$file has " . scalar(@errors) . " error$s in its gpu: block:\n"
      . join('', map { "  - $_\n" } @errors)
      . "Nothing was done: ocp node add --gpu sets up the node's GPU stack from that block once "
      . "the node is Ready, and checks it before it asks the cluster anything or touches a "
      . "machine. Fix the line$s above and run it again.\n";
}

# k220, k251: a GPU node joined after the last `ocp apply` gets its GPU stack
# here, by the very checks `ocp apply` runs -- not a second copy of them: the
# GPU Operator (OCP::Cmd::Apply::Workloads::setup_gpu_operator) for an NVIDIA
# card, the AMD GPU stack (OCP::Cmd::Apply::AMDGPU) for an AMD one. Which one
# the node needs, its labels say: the AMD marker, which the host step sets at
# registration, or NFD's NVIDIA label, which NFD's worker sets about a minute
# after the node turned Ready. So it waits for either (gpu_label_timeout); a
# node that shows both gets both, one that shows the AMD marker first gets the
# GPU Operator with the next `ocp apply`. gpu.enabled: false needs no label:
# the GPU Operator check skips at once, as in apply.
#
# That wait has the apply side's budget for NFD on a freshly joined node, read
# from there (OCP::Cmd::Apply::Workloads gpu_label_timeout, k309): NFD's
# worker pod gets no sandbox until Cilium's first BPF compile on the node is
# done, ~5.5 min on synapse (k286). A budget of its own, 300 s, gave up on
# such a node where `ocp apply` would have waited.
#
# The GPU Operator check waits for nvidia.com/gpu in status.allocatable on the
# NVIDIA nodes it detects, this one among them (k273,
# OCP::Cmd::Apply::Workloads wait_gpu_allocatable). It says a node that does
# not get there itself, as a [WARN]. No `ocp apply` hint is added: an apply
# would only wait again. The AMD GPU stack check waits for amd.com/gpu in
# status.allocatable (a ResourceSlice under DRA) on every node its components
# select, this one among them and up to date or not, with the budget of a
# freshly joined node (k286, OCP::Cmd::Apply::AMDGPU join_ready_timeout). A
# node that does not get there fails the component, said with `ocp apply`.
#
# Never fatal: the node is Ready, which is what `ocp node add` promised. No GPU
# in time or a failed rollout is said on STDERR together with the way to get
# the stack anyway, `ocp apply`. Returns whether the checks completed.
sub gpu_label_timeout  { OCP::Cmd::Apply::Workloads::gpu_label_timeout() }
sub gpu_label_interval { 10 }

my @GPU_LABELS = map { "feature.node.kubernetes.io/pci-${_}.present" } qw(0300_10de 0302_10de);

sub _ensure_gpu_stack {
    my ($self, $api, $config) = @_;
    return $self->_ensure_gpu_operator($api, $config) unless $config->gpu_enabled;

    my $k8s_name = $self->_kubernetes_node_name($api);
    print "  [..] Waiting for node '$k8s_name' to show its GPU...\n";
    my %vendor = map { $_ => 1 } $self->_wait_gpu_vendors($api, $k8s_name);
    unless (%vendor) {
        print STDERR "  [!!] No GPU stack ensured: node '$k8s_name' shows no GPU after "
            . gpu_label_timeout() . "s -- neither the AMD GPU\n"
            . "       marker ($OCP::Config::AMD_GPU_PRESENT_LABEL=true) nor an NFD NVIDIA label\n"
            . "       (" . join(' / ', @GPU_LABELS) . ").\n"
            . "       The marker comes with the registration of a node whose AMD GPU the host step\n"
            . "       set up; an NVIDIA card shows once NFD labels it. Then run `ocp apply`.\n";
        return 0;
    }

    my $ok = 1;
    $ok = 0 if $vendor{nvidia} && !$self->_ensure_gpu_operator($api, $config);
    $ok = 0 if $vendor{amd}    && !$self->_ensure_amd_gpu_stack($api, $config);
    return $ok;
}

sub _ensure_gpu_operator {
    my ($self, $api, $config) = @_;

    print "  [..] Checking GPU Operator...\n";
    my $done = eval {
        my $apply = $self->_apply_cmd($api);
        $apply->_report_component('GPU Operator', $apply->_setup_gpu_operator($config));
        1;
    };
    return 1 if $done;

    my $err = $@ || "unknown error\n";
    $err .= "\n" unless $err =~ /\n\z/;
    print STDERR "  [!!] GPU Operator not ensured: $err"
        . "       Run `ocp apply` to deploy it.\n";
    return 0;
}

# The step reports each component itself, a failure on STDERR with its cause;
# what is left to say is the way to try again. It waits for the node that
# just joined, up to date or not, with the budget of a fresh node (k286,
# OCP::Cmd::Apply::AMDGPU join_ready_timeout).
sub _ensure_amd_gpu_stack {
    my ($self, $api, $config) = @_;

    print "  [..] Checking AMD GPU stack...\n";
    my $r = OCP::Cmd::Apply::AMDGPU::step($self->_apply_cmd($api), $config, joined => 1);
    return 0 if $r->{warned};
    return 1 unless @{ $r->{failed} };
    print STDERR "       AMD GPU stack not ensured. Run `ocp apply` to deploy it.\n";
    return 0;
}

# The Node's name as the stored OCPNode records it ($h when that was read
# already), the OCPNode's own until it records one.
sub _kubernetes_node_name {
    my ($self, $api, $h) = @_;
    $h //= $self->_stored_ocpnode($api) // {};
    return $h->{status}{kubernetesNodeName} // $self->name;
}

# The OCPNode as stored, or undef when it cannot be read.
sub _stored_ocpnode {
    my ($self, $api) = @_;
    my $cr = eval { $api->get('OCPNode', name => $self->name, namespace => 'ocp-system') };
    return $cr ? $api->k8s->object_to_struct($cr) : undef;
}

# The GPU vendors node $k8s_name shows, as soon as it shows one: 'amd' for the
# AMD marker, 'nvidia' for an NFD NVIDIA label. Empty after gpu_label_timeout.
sub _wait_gpu_vendors {
    my ($self, $api, $k8s_name) = @_;

    my $interval = gpu_label_interval();
    my $tries    = int(gpu_label_timeout() / $interval);
    for my $try (0 .. $tries) {
        my $node   = eval { $api->get('Node', name => $k8s_name) };
        my $labels = $node ? ($api->k8s->object_to_struct($node)->{metadata}{labels} // {}) : {};
        my @seen   = (
            (($labels->{$OCP::Config::AMD_GPU_PRESENT_LABEL} // '') eq 'true' ? 'amd' : ()),
            ((grep { ($labels->{$_} // '') eq 'true' } @GPU_LABELS) ? 'nvidia' : ()),
        );
        return @seen if @seen;
        $self->wait_seconds($interval) if $try < $tries;
    }
    return;
}

# An `ocp apply` command object for its GPU steps, talking to the cluster
# this command already has a client for (the cache OCP::Cmd::Apply's _k8s_api
# reads) and its kubeconfig file (OCP::Cmd::Apply::K8s::kubeconfig_path), so
# the kubeconfig is not decrypted a second time.
sub _apply_cmd {
    my ($self, $api) = @_;
    require OCP::Cmd::Apply;
    my $apply = OCP::Cmd::Apply->new(command_chain => $self->command_chain);
    $apply->{_k8s_api} = $api;
    $apply->{_kc_temp} = $self->{_kc_temp} if $self->{_kc_temp};
    return $apply;
}

1;

__END__

=head1 NAME

OCP::Cmd::Node::Add - Add an OCPNode CR and optionally reconcile it

=head1 SYNOPSIS

    ocp node add worker-1 --role worker
    ocp node add gpu-1    --role worker --provider hetzner-default --gpu
    ocp node add ssh-1    --role worker --provider ssh-default --host 10.0.0.5
    ocp node add worker-2 --role worker --nowait
    ocp node add crag-gpu --role worker --host 10.230.30.250 \
        --label ai.citilan.de/node-class=rtx3090 --taint nvidia.com/gpu=present:NoSchedule
    ocp node add synapse  --provider ssh-default --host 10.230.30.50 --node_ip 10.230.30.50

=head1 DESCRIPTION

Creates an OCPNode CR in the C<ocp-system> namespace, then waits for the
node to reach C<Ready> status.  If Robocop is running in the cluster, the
command polls the CR status and lets Robocop do the work.  Otherwise it
drives reconciliation directly via L<OCP::Node>.

Either way the wait is bounded by C<$OCP::Node::READY_TIMEOUT> — one budget for
both paths, because the machine takes as long as it takes whoever is driving it
— and every phase the node passes through is printed as it happens.  Running
out of it is reported as that and not as a failure of the machine: the CR keeps
its phase, and re-running the command carries on from there.

With C<--gpu>, a node that reached C<Ready> also gets its GPU stack, by the
same checks C<ocp apply> runs.  It waits for the node to show its GPU (up to
ten minutes, what C<ocp apply> gives NFD on a freshly joined node; k309): the
AMD GPU marker C<ocp.internal/amd-gpu.present=true>, which the host step sets
when the node registers, or Node Feature Discovery's label for an NVIDIA
card.  Then it deploys or confirms the AMD GPU stack ("Checking
AMD GPU stack") or the GPU Operator ("Checking GPU Operator"), both for a node
that shows both.  A node joined after the last C<ocp apply> would otherwise sit
there without C<amd.com/gpu> or C<nvidia.com/gpu> until the next one (k220,
k251).  When that cannot be done -- no GPU shown in time, a failed rollout, or
C<--nowait> -- it says so on STDERR and names C<ocp apply> as the way to get
the stack; the exit code still reflects only whether the node is Ready.

The join takes the C<gpu:> switches of F<ocp.yaml> off the OCPNodeProvider
CR, as a join by robocop does (k358). Under C<gpu.enabled: false> the node's
host step sets up no GPU, C<--gpu> or not; C<gpu.driver: operator> leaves the
NVIDIA driver to the GPU Operator. Otherwise C<--gpu> also sets up the node's
integrated AMD GPU (a Ryzen iGPU or APU), which a node without it gets only
under C<gpu.amd.integrated: true>.

Before any of that -- before the kubeconfig is decrypted (PIN1), the cluster
is asked anything, the OCPNode is written or the host is probed or joined --
C<--gpu> checks the C<gpu:> block of F<ocp.yaml> the stack is set up from, and
refuses on every line L<OCP::Config/validate> has for it, all at once, on
STDERR with exit 1 (k333).  A malformed switch used to stop the command only
after the node had joined:

    Error: ocp.yaml has 1 error in its gpu: block:
      - gpu.enabled: must be true or false, not 'no'; write enabled: false
    Nothing was done: ocp node add --gpu sets up the node's GPU stack from that block once the node is Ready, and checks it before it asks the cluster anything or touches a machine. Fix the line above and run it again.

Only that block: a line C<validate()> has elsewhere in F<ocp.yaml> is none
this command reads, and C<ocp apply> refuses it.  An F<ocp.yaml> that is
empty or no mapping has no C<gpu:> block: C<--gpu> refuses it before
anything, with the one line C<ocp apply> refuses it with too (k306).  With
C<--nowait> the block is neither read nor checked; the stack is left to
C<ocp apply>, which checks it first.

After that, the GPU Operator check waits up to five minutes for
C<nvidia.com/gpu> in C<status.allocatable> (not capacity) on every NVIDIA
node, this one among them, as it does in C<ocp apply> (k273).  A node that
does not show it gets a C<[WARN]> on STDERR that says what the node shows
instead.  The exit code does not change:

    [WARN] NVIDIA GPU not ready after 300s: node 'brain' shows no nvidia.com/gpu in status.allocatable

The AMD GPU stack check waits up to ten minutes, also when the stack was up
to date, for C<amd.com/gpu> in C<status.allocatable> (for the DRA driver, a
ResourceSlice) on every AMD node its components select, this one among them
(k286).  The budget is that of a freshly joined node, whose pods get no
sandbox until Cilium is done with it.  A node that does not get there fails
the component, with the cause and C<ocp apply> named on STDERR:

    [!!] AMD GPU device plugin setup failed: AMD GPU device plugin not ready after 600s: node 'synapse' shows no amd.com/gpu in status.allocatable

Pass C<--nowait> to write the CR and return immediately.  The older
C<--no_wait> spelling is kept as an alias.  There is deliberately no
C<--no-wait>: L<MooX::Options> reads a literal C<no-> as Getopt::Long's
negation marker before it maps dashes to underscores, so the dashed form
would ask to negate a C<wait> option that does not exist.

=head1 LABELS AND TAINTS

C<--label key=value> and C<--taint key=value:Effect> (or C<key:Effect>; effect
C<NoSchedule>, C<PreferNoSchedule> or C<NoExecute>), each repeatable, go into
the OCPNode's C<spec.labels> and C<spec.taints>.  Malformed ones are refused
before the cluster is asked anything.  L<OCP::Node> passes the labels the
kubelet may set itself to the join and puts all labels and taints on the
Kubernetes Node once it registers; see L<OCP::NodeMeta>.

=head1 NODE IP

C<--node_ip> is the address the node registers as its C<InternalIP> --
RKE2's and K3s's C<node-ip> -- written to the OCPNode's C<spec.nodeIP>: one
IP address, or C<v4,v6> for dual-stack (one of each family), with no
whitespace.  Give it on a multi-homed host: without it the node registers the
address of its default route, which the other nodes may not reach, and the
node still turns Ready -- live, C<synapse> joined by 10.230.30.50 registered
192.168.0.165 and its Cilium tunnel broke (k254).  It is only ever what is
given here; without it no node-ip is asked for.  A value that is no such
address -- a hostname, a CIDR, loopback, link-local -- is refused before the
cluster is asked anything, in the words of L<OCP::Choices/node_ip_error>.

With C<--node_ip> the command then reads the cluster's OCPNode CRD,
C<ocpnodes.ocp.internal>, and refuses when it cannot store C<spec.nodeIP> --
before anything is written, before the host is probed over SSH, before PIN2
is asked for.  A CRD that an older C<ocp> installed does not declare the
field, and the API server drops a field its schema does not declare without
an error: the OCPNode would be stored without it, the install, which reads
the stored OCPNode, would be handed no node-ip, and the node would register
the address of its default route with nothing said (k290, live on amdlab).
The refusal goes to STDERR, exit 1:

    Error: --node_ip: this cluster's OCPNode CRD (ocpnodes.ocp.internal) has no spec.nodeIP -- an
      older ocp installed it -- so the API server would drop the field without an error
      and the node would register the address of its default route.
      Run `ocp apply` first: it updates the CRD. Then run this command again.
      Nothing was written.

C<ocp apply> updates the CRD in its "Checking node CRs" step, with or
without Robocop.  This command only reads the CRD and never applies it: an
C<ocp> older than the cluster's CRD would take the newer schema back.  A
cluster with no OCPNode CRD is refused the same way, and so is a CRD that
cannot be read -- a 403, a 5xx, no answer -- with the cause: only a 404 says
the CRD is not there.  Without C<--node_ip> the CRD is not read.

Once the node is Ready its C<InternalIP>s are held against the node-ip.  A
node that did not register there says so on STDERR, once, whoever did the
join:

    [WARN] synapse: registered InternalIP 192.168.0.165, not the node-ip 10.230.30.50 it was installed with

On the CLI path that line is L<OCP::Node>'s, written as it turns the node
Ready, when it held the node against this node-ip; with Robocop running, for
a node that was Ready already, or when the install was handed no node-ip,
this command asks the Node itself (L<OCP::Node/node_ip_mismatch>).  It
changes nothing else: the node joined, the exit code is that of a Ready
node, and only a human can say which address is right.

An OCPNode that holds no C<spec.nodeIP> though C<--node_ip> was given -- an
API server can serve an updated CRD a moment before it stores by it -- is
said as well, before that line and whether or not the node registered
elsewhere:

    [WARN] synapse: OCPNode synapse holds no spec.nodeIP, though --node_ip 10.230.30.50 was given: the API server dropped the field, as an OCPNode CRD from an older ocp does, and every install reads the node-ip from there. `ocp apply` updates the CRD.

An OCPNode written by hand onto a cluster whose CRD predates C<spec.nodeIP>
loses the field the same way.  C<kubectl> refuses it with its default
C<--validate=strict>; with C<--validate=ignore> (or C<false>) it is dropped
silently, and from a client that does not ask for strict field validation
the API server drops it with no more than a warning header the client may
never show.  Nothing downstream can tell: L<OCP::Node>, on the CLI path and
inside Robocop, only ever sees the OCPNode as stored.  Run C<ocp apply>
first.

=head1 CHOOSING THE PROVIDER

C<--provider> takes the B<name> of an C<OCPNodeProvider> CR, not a provider
type: C<--provider ssh-default>, not C<--provider ssh>.  C<ocp apply> writes
one CR per provider in F<ocp.yaml> and names it C<< <type>-default >>, so a
bootstrapped cluster has C<ssh-default> or C<hetzner-default>; C<ocp provider
ls> lists them.  A type is never resolved to the CR that carries it — names
and types are separate namespaces and nothing stops a provider from being
named C<ssh>.  Naming one that does not exist is refused with the providers
that do, and their types (see L<OCP::Role::Cmd/provider_cr>).

Without C<--provider> the single provider is used, or the one annotated
C<ocp.internal/default>; with several and no default, the command asks for
C<--provider> and lists the candidates.

=head1 SSH ACCESS

The CLI reconcile path — the one taken when Robocop is not running — reads
the cluster's join token off the control plane over SSH and hands the same
key to L<OCP::Node> for the new machine.  That key is chosen by
L<OCP::ClusterKey>: the PIN2-protected admin key in secure mode, on every
provider, and the bootstrap key F<.ocp/id_ed25519> in a C<--nopassword>
project.  So a secure-mode project prompts for PIN2 here, once.

C<--nowait> and the Robocop path never reach it and never prompt: both stop
at the CR.

When a worker driven this way never reaches Ready, this command prints
L<OCP::ClusterKey/migration_hint> alongside its failure — the machine most
likely has C<authorized_keys> from before the bootstrap key left secure mode
and refuses the admin key.  It is said here rather than in L<OCP::Node>,
because that class is trigger-neutral and also runs inside Robocop, where
C<ocp keys show> is not a command anyone can type.  A diagnosis only: nothing
looked ahead to see which key the machine accepts, nothing falls back to the
bootstrap key, and the command still exits non-zero.

=head1 HOST BY NAME

With C<--host NAME> (not an IP address) and Robocop running, Robocop reaches the
machine by that name from inside the cluster (CoreDNS, then the node's
resolver), not from the machine running C<ocp>.  A name that resolves only here
-- through F</etc/hosts> or a container's C<--add-host> -- is unknown to every
pod, so the join would fail.  The command says so on STDERR (never on STDOUT,
which stays the node name with C<--nowait>) and notes whether the name resolves
on this machine; it makes no lookup inside the cluster (k236).  An IP address
gets no note.

A name that does not resolve where it is tried is reported as that -- "does not
resolve ... not a key problem" (L<OCP::SSH/unresolved_message>) -- and not as a
rejected key.  Use the IP address or a DNS entry the cluster knows.

Without Robocop this machine does the join, so the host is checked B<before> the
OCPNode is written (k238): the name must resolve here (an IP address is not
looked up) and, unless C<--nowait> is given, the host must answer SSH with the
key the join will use.  A failure prints the L<OCP::SSH> message on STDERR, exits
1 and leaves no OCPNode behind.  With C<--nowait> only the name is checked; the
SSH contact is part of the join that comes later.  The SSH check is skipped when
the project records no control-plane address, since no key is known then.  With
Robocop running the OCPNode stays the request, as above: the name may resolve
only in the cluster, and a failure is the node's C<Failed> status with the
message.

=head1 SEE ALSO

L<OCP::Node>, L<OCP::ClusterKey>, L<OCP::Cmd::Node::Rm>, L<OCP::Cmd::Node::Ls>

=cut

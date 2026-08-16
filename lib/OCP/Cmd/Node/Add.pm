package OCP::Cmd::Node::Add;
# ABSTRACT: Add an OCPNode CR and optionally reconcile it

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use JSON::PP ();
use Kubernetes::REST::Kubeconfig;
use OCP::Config;
use OCP::Secrets;
use OCP::K8s;
use OCP::Node;
use OCP::Provider;

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
    is      => 'ro',
    is_bool => 1,
    doc     => 'Enable GPU support',
);

# Spelled without a dash on purpose, like --nogit and --nopassword in
# `ocp init`. MooX::Options strips a literal "no-" as Getopt::Long's negation
# marker before it turns dashes into underscores, so `--no-wait` asked to
# negate a "wait" option that does not exist and died with "Unknown option:
# wait". `--no_wait` stays as an alias for anything that already uses it.
option nowait => (
    is      => 'ro',
    is_bool => 1,
    short   => 'no_wait',
    doc     => 'Write CR and exit without waiting for Ready',
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
    die "ERROR: Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
        unless $kc_content;

    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$kc_fh} $kc_content;
    close $kc_fh;

    my $api = Kubernetes::REST::Kubeconfig->new(
        kubeconfig_path => $kc_fh->filename,
    )->api;

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

    my @items = $self->provider_crs($api, namespace => $ns);

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
    my ($self, $provider_type) = @_;

    if ($provider_type eq 'hetzner') {
        die "--host is not valid for provider type 'hetzner'\n"
            if $self->host;
    }
    elsif ($provider_type eq 'ssh') {
        die "--host is required for provider type 'ssh'\n"
            unless $self->host;
        die "--server-type is only valid for provider type 'hetzner' (given for 'ssh')\n"
            if $self->server_type;
        die "--location is only valid for provider type 'hetzner' (given for 'ssh')\n"
            if $self->location;
        die "--image is only valid for provider type 'hetzner' (given for 'ssh')\n"
            if $self->image;
    }
    elsif ($provider_type eq 'local') {
        die "--host is not valid for provider type 'local'\n"
            if $self->host;
        die "--server-type is only valid for provider type 'hetzner' (given for 'local')\n"
            if $self->server_type;
        die "--location is only valid for provider type 'hetzner' (given for 'local')\n"
            if $self->location;
        die "--image is only valid for provider type 'hetzner' (given for 'local')\n"
            if $self->image;
    }
    else {
        die "Unknown provider type '$provider_type'\n";
    }
}

sub _build_cr {
    my ($self, $provider_name) = @_;

    # spec.gpu is declared `type: boolean` in the OCPNode CRD. The bare Perl 1
    # that MooX::Options hands over serializes as a JSON integer and the API
    # rejects the CR with a 422, so it has to go out as a JSON boolean.
    my %spec = (
        role        => $self->role,
        providerRef => $provider_name,
        ($self->host        ? (host       => $self->host)        : ()),
        ($self->server_type ? (serverType => $self->server_type) : ()),
        ($self->location    ? (location   => $self->location)    : ()),
        ($self->image       ? (image      => $self->image)       : ()),
        ($self->gpu         ? (gpu        => JSON::PP::true)     : ()),
    );

    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => $self->name, namespace => 'ocp-system' },
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
sub _report_phase {
    my ($self, $reported, $phase, $message) = @_;

    return $reported if $phase eq $reported;

    print "  [..] $phase"
        . (defined $message && length $message ? ": $message" : '') . "\n";

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

    my $cp_ip = do {
        my $cps = $config->control_planes;
        ($cps && @$cps) ? ($cps->[0]{public_ip} // $cps->[0]{host}) : undef;
    };

    # $key outlives the block on purpose: the failure it explains happens at
    # the bottom of this sub, long after the join token was read.
    my ($ssh_key, $server_url, $join_token, $key);

    if ($cp_ip) {
        # The key has to be the one the CONTROL PLANE trusts: this reads the
        # join token off it over SSH. Reading $config->ssh_private_key_path
        # straight was right for dev mode and wrong for every secure-mode
        # cluster, where machines trust the admin key and that file is not
        # even created — `ocp node add` died with "Cannot read SSH key" on the
        # one path it was most needed. karr #87.
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
            ? '/var/lib/rancher/k3s/server/node-token'
            : '/var/lib/rancher/rke2/server/node-token';

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

    my $node = OCP::Node->from_cr($cr,
        k8s           => $api,
        ($provider_obj ? (provider => $provider_obj) : ()),
        ($ssh_key      ? (ssh_key  => $ssh_key)      : ()),
        ($server_url   ? (server_url => $server_url) : ()),
        ($join_token   ? (join_token => $join_token) : ()),
        distribution  => ($config->distribution || 'rke2'),
        reconciler_id => 'cli',
    );

    # No budget named here: OCP::Node owns it ($OCP::Node::READY_TIMEOUT), and
    # it is one question -- how long may a machine take to become a node --
    # regardless of who is watching. The 600 this used to name did not cover
    # the sum of the waits underneath it.
    my $reported = '';
    my $ok = $node->reconcile_until_ready(on_phase => sub {
        my ($phase, $message) = @_;
        $reported = $self->_report_phase($reported, $phase, $message);
    });

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
    # can type and nobody reads the output (karr #97).
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

    $self->name($self->name // ($args && $args->[0]));
    die "Usage: ocp node add NAME [--role worker|control-plane]\n"
        unless defined $self->name && length $self->name;

    my $api           = $self->_k8s;
    my $provider_hash = $self->_resolve_provider($api);
    my $provider_type = $provider_hash->{spec}{type}
        or die "Provider has no spec.type\n";
    my $provider_name = $provider_hash->{metadata}{name};

    $self->_validate_flags($provider_type);

    my $cr = $self->_build_cr($provider_name);
    $api->ensure($cr);

    if ($self->nowait) {
        print $self->name . "\n";
        return 0;
    }

    if ($self->_robocop_ready($api)) {
        sleep 5;
        my $ok = $self->_poll_until_ready($api);
        if ($ok) {
            print "Node '" . $self->name . "' is Ready.\n";
            return 0;
        }
        else {
            print STDERR "Node '" . $self->name . "' did not reach Ready state.\n";
            return 1;
        }
    }

    my $file   = $self->ocp->config;
    my $config = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $ok = $self->_cli_reconcile($cr, $api, $config, $secrets);

    if ($ok) {
        print "Node '" . $self->name . "' is Ready.\n";
        return 0;
    }
    else {
        print STDERR "Node '" . $self->name . "' did not reach Ready state.\n";
        return 1;
    }
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

Pass C<--nowait> to write the CR and return immediately.  The older
C<--no_wait> spelling is kept as an alias.  There is deliberately no
C<--no-wait>: L<MooX::Options> reads a literal C<no-> as Getopt::Long's
negation marker before it maps dashes to underscores, so the dashed form
would ask to negate a C<wait> option that does not exist.

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

=head1 SEE ALSO

L<OCP::Node>, L<OCP::ClusterKey>, L<OCP::Cmd::Node::Rm>, L<OCP::Cmd::Node::Ls>

=cut

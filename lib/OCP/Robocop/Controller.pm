package OCP::Robocop::Controller;
# ABSTRACT: Kubernetes controller for OCP nodes

use Moo;
use Carp qw(croak);
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

has poll_interval => (
    is      => 'ro',
    default => 10,   # seconds
);

has verbose => (
    is      => 'ro',
    default => 0,
);

#
# Lazy-built Kubernetes client
#

has kube => (
    is      => 'lazy',
    builder => '_build_kube',
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

#
# Main loop: poll and reconcile
#

sub run {
    my ($self) = @_;

    $self->log("Robocop controller starting (namespace=" . $self->namespace . ")");
    $self->log("Server URL:   " . $self->server_url);
    $self->log("Distribution: " . $self->distribution);

    while (1) {
        my $nodes = eval { $self->list_ocp_nodes };
        if ($@) {
            $self->log("ERROR listing OCPNodes: $@");
        } else {
            for my $cr (@$nodes) {
                try {
                    $self->_on_node_event($cr);
                } catch {
                    my $name = $cr->{metadata}{name} // '?';
                    $self->log("ERROR reconciling $name: $_");
                    # Defense in depth: _on_node_event already patches status
                    # on every failure it knows about, but a crash past those
                    # paths (a transport exception in the middle of a status
                    # patch, a croak from a test stub) used to leave the CR
                    # with whatever phase it had -- usually Pending -- and the
                    # operator with only robocop's pod logs to read. Mark the
                    # CR Failed so the failure is visible without the logs.
                    $self->_mark_failed($cr, $_);
                };
            }
        }

        sleep $self->poll_interval;
    }
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

    $controller->run;  # blocks, polls OCPNodes, reconciles via OCP::Node

=head1 DESCRIPTION

Watches OCPNode custom resources and dispatches each event to L<OCP::Node>
for reconciliation. The state machine lives entirely in C<OCP::Node>.

=head2 Reconciliation state machine

    Pending → Provisioning → Installing → Joining → Ready
                     └──────────────┴──────────→ Failed

=cut

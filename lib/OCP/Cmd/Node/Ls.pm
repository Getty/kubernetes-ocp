package OCP::Cmd::Node::Ls;
# ABSTRACT: List OCPNode CRs

use Moo;
use MooX::Cmd;
use MooX::Options;
use OCP::Config;
use JSON::MaybeXS ();
use Time::Piece;

with 'OCP::Role::Cmd';

has k8s => (is => 'rw');


option json => (
    is  => 'ro',
    doc => 'Print the node inventory as canonical JSON (name, role, pool, host, address, GPU, runtime, versions)',
);

# What node ls reads of ocp.yaml, declared as its spec_paths: with --json,
# the worker pools, whose OCPNode names give each node its pool (_pools_of,
# OCP::Cmd::Apply::CR::worker_ocpnodes); the table reads nothing of
# ocp.yaml. OCP::Role::Cmd refuses their lines, validate()'s own, before the
# cluster is asked -- as the one JSON error object on STDOUT (k400).
sub spec_paths {
    my ($self) = @_;
    return () unless $self->json;
    return (
        'workers', 'workers[*]',
        map({ "workers[*].$_" } qw( name provider nodes host server_type image location labels taints )),
    );
}

sub _k8s {
    my $self = shift;
    return $self->k8s if $self->k8s;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    # The key, kubeconfig.yaml, the client and one GET /version: an API that
    # does not answer, or answers /version with an error, is said there, in
    # one line (k384, k387, k399).
    return $self->k8s($self->cluster_api);
}

# --json answers on STDOUT when the nodes could not be listed too (k388), as
# ocp status --json and ocp health --json do: an object whose error is the
# line, where the inventory is an array -- so the type tells a list that
# could not be made from an empty one. OCP.pm prints that object for every
# --json command that dies (k398); the error dies on to it, which says it on
# STDOUT as the object, on STDERR as without --json, and exits 1.
sub execute {
    my ($self, $args, $chain) = @_;
    return $self->_ls;
}

sub _ls {
    my ($self) = @_;

    my $api = $self->_k8s;
    my $ns  = 'ocp-system';

    # An error the API answers with is one line naming the server (k387).
    my $list = $self->cluster_api_call($api, sub { $api->list('OCPNode', namespace => $ns) });
    my @nodes = map { $api->k8s->object_to_struct($_) } @{ $list->items // [] };

    if ($self->json) {
        # The pools come from ocp.yaml; without one (an injected client in
        # tests, a kubeconfig used from elsewhere) only the annotation counts.
        my $pools = eval {
            my $file = $self->ocp->config;
            -f $file ? _pools_of(OCP::Config->new(file => $file)) : {};
        } // {};
        return $self->_execute_json($api, \@nodes, $pools);
    }

    printf "%-16s %-13s %-12s %-14s %-15s %s\n",
        qw(NAME ROLE PHASE PROVIDER IP AGE);
    for my $n (sort { $a->{metadata}{name} cmp $b->{metadata}{name} } @nodes) {
        printf "%-16s %-13s %-12s %-14s %-15s %s\n",
            $n->{metadata}{name},
            $n->{spec}{role}              // '',
            $n->{status}{phase}           // 'Pending',
            $n->{spec}{providerRef}       // '',
            $n->{status}{address} // $n->{status}{publicIP} // '',
            _age($n->{metadata}{creationTimestamp});
    }

    return 0;
}

# OCPNode name -> worker pool, from ocp.yaml the way `ocp apply` names the
# OCPNodes of its pools (OCP::Cmd::Apply::CR::worker_ocpnodes). An OCPNode's
# spec does not carry its pool; a worker added with `ocp node add` has none.
sub _pools_of {
    my ($config) = @_;
    require OCP::Cmd::Apply::CR;
    my %pool;
    for my $pool (@{ $config->workers }) {
        my $pname = $pool->{name} // next;
        my $one   = OCP::Config->new(file => $config->file,
                                     spec => { %{ $config->spec }, workers => [ $pool ] });
        $pool{ $_->{metadata}{name} } = $pname
            for eval { OCP::Cmd::Apply::CR::worker_ocpnodes($one) };
    }
    return \%pool;
}

# The machine-readable inventory: OCPNode joined with the Kubernetes Node it
# became (status.kubernetesNodeName, else the OCPNode's own name). Kubernetes
# API only -- no SSH, no PIN. Every key is always present (null when unknown),
# gpu is always a number, the list is sorted by name and the encoder is
# canonical, so two runs against an unchanged cluster print identical bytes.
sub _execute_json {
    my ($self, $api, $ocpnodes, $pool_of) = @_;
    $pool_of //= {};

    my $nlist = $self->_list_nodes($api);
    my %k8s_node;
    for my $item (@{ $nlist->items // [] }) {
        my $n = $api->k8s->object_to_struct($item);
        $k8s_node{ $n->{metadata}{name} } = $n if defined $n->{metadata}{name};
    }

    my @rows;
    for my $n (@$ocpnodes) {
        my $name   = $n->{metadata}{name};
        my $kname  = $n->{status}{kubernetesNodeName};
        my $node   = $k8s_node{ $kname // $name } // {};
        my $info   = $node->{status}{nodeInfo} // {};
        my $gpu    = $node->{status}{allocatable}{'nvidia.com/gpu'};
        push @rows, {
            name               => $name,
            role               => $n->{spec}{role},
            pool               => $n->{metadata}{annotations}{'ocp.internal/pool'}
                                      // $pool_of->{$name},
            host               => $n->{spec}{host},
            address            => $n->{status}{address},
            publicIP           => $n->{status}{publicIP},
            phase              => $n->{status}{phase} // 'Pending',
            reconciler         => $n->{status}{reconciler},
            kubernetesNodeName => $kname,
            labels             => $n->{spec}{labels},
            gpu                => ($gpu // 0) + 0,
            runtime            => $info->{containerRuntimeVersion},
            kubelet            => $info->{kubeletVersion},
            os                 => $info->{osImage},
            kernel             => $info->{kernelVersion},
        };
    }
    @rows = sort { $a->{name} cmp $b->{name} } @rows;

    print JSON::MaybeXS->new(canonical => 1, pretty => 1)->encode(\@rows);
    return 0;
}

# The Kubernetes Nodes, for the inventory. An error the API answers with is
# its one line (k387). The client resolves 'Node' from the cluster's
# discovery once it has read it, and the OCPNode list above read it: a
# discovery that answers without Node leaves the client no class for it, and
# Kubernetes::REST croaks "unknown resource 'Node'" before sending anything,
# with the caller's location -- an internal error where the cluster is what
# is odd (k395; seen with a test's fake API, a real API server lists Node in
# its core group). A discovery that cannot be read at all is no such case:
# the client falls back to IO::K8s's built-in map, where Node resolves.
sub _list_nodes {
    my ($self, $api) = @_;
    my $list;
    return $list
        if eval { $list = $self->cluster_api_call($api, sub { $api->list('Node') }); 1 };
    my $err = $@;
    die $err if ref $err || $err !~ /\Aunknown resource 'Node'/;
    my $at = $api->can('server') ? ' at ' . $api->server->endpoint : '';
    die "The cluster API$at does not list the Kind Node in its discovery,"
      . " so the Nodes cannot be read.\n";
}

sub _age {
    my $ts = shift;
    return '?' unless $ts;
    my $created = eval { Time::Piece->strptime($ts, '%Y-%m-%dT%H:%M:%SZ')->epoch };
    return '?' unless $created;
    my $diff = time - $created;
    return $diff < 60   ? "${diff}s"
         : $diff < 3600 ? sprintf('%dm', $diff / 60)
         : $diff < 86400 ? sprintf('%dh', $diff / 3600)
         :                 sprintf('%dd', $diff / 86400);
}

1;

__END__

=head1 SYNOPSIS

    ocp node ls
    ocp node ls --json

=head1 DESCRIPTION

Lists all OCPNode CRs in the C<ocp-system> namespace.  Columns: NAME, ROLE,
PHASE, PROVIDER, IP, AGE.

=head1 JSON OUTPUT

C<ocp node ls --json> prints a JSON array, one object per OCPNode, sorted by
name, as canonical pretty JSON (sorted keys, no timestamps) on STDOUT and
nothing else.  It reads the OCPNode CRs and the Kubernetes Nodes through the
API; no SSH, no PIN.  Every key is always present; an unknown value is
C<null>, C<gpu> is always a number.

    [
       {
          "address" : "10.0.0.20",
          "gpu" : 1,
          "host" : "10.0.0.20",
          "kernel" : "6.1.0-18-amd64",
          "kubelet" : "v1.32.1+rke2r1",
          "kubernetesNodeName" : "crag",
          "labels" : { "tier" : "gpu" },
          "name" : "crag",
          "os" : "Debian GNU/Linux 12",
          "phase" : "Ready",
          "pool" : null,
          "publicIP" : "10.0.0.20",
          "reconciler" : "robocop@robocop-5dd68bf544-wwxdl",
          "role" : "worker",
          "runtime" : "containerd://1.7.23-k3s2"
       }
    ]

C<address>, C<publicIP>, C<phase>, C<reconciler> (C<cli>, or C<robocop@POD>
while robocop drives the node; null when none did) and C<kubernetesNodeName>
come from the OCPNode C<status>, C<host> and C<labels> from its C<spec>; C<gpu> is the
C<nvidia.com/gpu> allocatable of the Kubernetes Node (0 when it has none or
the Node is not joined yet), C<runtime>, C<kubelet>, C<os> and C<kernel> its
C<status.nodeInfo>.

B<pool> is the named C<workers:> pool of C<ocp.yaml> the OCPNode belongs to.
The OCPNode CR carries no pool name (only C<providerRef>), so the OCPNode's
name is matched against the names C<ocp apply> gives the OCPNodes of each
pool. An annotation C<ocp.internal/pool> on the OCPNode takes precedence;
OCP itself never writes one. Without it, C<pool> is null for a node no named
pool produces (a control plane, a worker C<ocp node add> created under a name
of its own, the nodes of a pool without C<name>), and for every node when
there is no readable C<ocp.yaml>. A worker pool L<OCP::Config/validate>
refuses stops C<--json> before the cluster is asked, with that line as the
error object below (L<OCP::Role::Cmd/refuse_spec_errors>).

When the nodes cannot be listed -- the API server the kubeconfig names does
not answer or answers with an error, its discovery does not list the Kind
C<Node>, or there is no C<ocp.yaml> or no kubeconfig -- STDOUT carries one
object instead of the array, its C<error> the message the command stopped on
as one line, without an C<Error:> label (for the API, the one line of
L<OCP::Role::Cmd/cluster_api_error>), and the exit code is 1, as with
C<ocp status --json> and C<ocp health --json>. STDERR says it as
without C<--json>.

    {
       "error" : "The cluster API at https://10.0.0.1:6443 could not be reached: Can't connect to 10.0.0.1:6443 (Connection refused)"
    }

An empty array is a cluster without OCPNodes; an object is a list that could
not be made.

=head1 SEE ALSO

L<OCP::Cmd::Node::Add>, L<OCP::Cmd::Node::Rm>

=cut

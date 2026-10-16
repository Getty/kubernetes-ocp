package OCP::Cmd::Node::Ls;
# ABSTRACT: List OCPNode CRs

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use OCP::Config;
use OCP::Secrets;
use JSON::MaybeXS ();
use OCP::K8s;
use Time::Piece;

with 'OCP::Role::Cmd';

has k8s => (is => 'rw');


option json => (
    is  => 'ro',
    doc => 'Print the node inventory as canonical JSON (name, role, pool, host, address, GPU, runtime, versions)',
);

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

sub execute {
    my ($self, $args, $chain) = @_;

    my $api = $self->_k8s;
    my $ns  = 'ocp-system';

    my $list = $api->list('OCPNode', namespace => $ns);
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

    my $nlist = $api->list('Node');
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

=head1 NAME

OCP::Cmd::Node::Ls - List OCPNode CRs

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

B<pool> may be null today: the OCPNode CR carries no pool name (only
C<providerRef>), so C<pool> is read from the annotation C<ocp.internal/pool>
and is null where that annotation is absent.

=head1 SEE ALSO

L<OCP::Cmd::Node::Add>, L<OCP::Cmd::Node::Rm>

=cut

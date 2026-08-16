package OCP::Kubernetes;
# ABSTRACT: Shared typed Kubernetes helpers for OCP

use Moo;
use Carp qw(croak);
use File::Temp ();
use Kubernetes::REST::Kubeconfig;

has kubeconfig => (
    is => 'ro',
);

has kubeconfig_path => (
    is => 'ro',
);

# Run off the pod's service account instead of a kubeconfig. Opt-in rather
# than "no kubeconfig means in-cluster": a caller that lost its kubeconfig by
# accident must keep failing with the message that says so, instead of quietly
# authenticating as something else.
has in_cluster => (
    is      => 'ro',
    default => 0,
);

has api => (
    is      => 'lazy',
    builder => '_build_api',
);

# Kubernetes::REST::Kubeconfig->api falls back to the pod's service account
# (its _in_cluster_api) in exactly one case: when its kubeconfig_path does not
# name a readable file. Asking for that fallback therefore means handing it a
# path that cannot exist -- not leaving kubeconfig_path unset, because the
# attribute's own default is $ENV{KUBECONFIG} // ~/.kube/config, and a stray
# kubeconfig anywhere in the image would then silently outrank the service
# account the controller is supposed to run as. /dev/null is not a directory,
# so nothing can ever appear underneath it.
my $IN_CLUSTER_ONLY = '/dev/null/ocp-in-cluster';

sub _build_api {
    my ($self) = @_;

    my %args;
    if ($self->kubeconfig_path) {
        $args{kubeconfig_path} = $self->kubeconfig_path;
    } elsif (defined $self->kubeconfig) {
        my $fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
        print {$fh} $self->kubeconfig;
        close $fh;
        $self->{_temp_kubeconfig} = $fh;
        $args{kubeconfig_path} = $fh->filename;
    } elsif ($self->in_cluster) {
        $args{kubeconfig_path} = $IN_CLUSTER_ONLY;
    } else {
        croak "kubeconfig, kubeconfig_path or in_cluster required";
    }

    my $api = Kubernetes::REST::Kubeconfig->new(%args)->api;
    $self->register_resource_providers($api);

    return $api;
}

# The resource-map providers for the Kinds OCP addresses by name. All three
# ship inside IO::K8s itself, which cpanfile pins to 1.107, and IO::K8s::add
# loads each one for us.
#
# Nothing here is probed or eval'd any more. The old body asked
# $api->can('k8s'), skipped a provider whose require failed, and swallowed the
# result of add(): three ways to end up with an api that answers every call
# but has no idea what a CiliumNetworkPolicy is, and no way to hear about it
# until an untyped lookup fails somewhere else entirely. The pin is the
# promise that these classes are there; a second, quieter promise at runtime
# only gives it somewhere to drift to.
my @RESOURCE_PROVIDERS = qw(
    IO::K8s::Cilium
    IO::K8s::CertManager
    IO::K8s::GatewayAPI
);

sub register_resource_providers {
    my ($self, $api) = @_;

    $api->k8s->add(@RESOURCE_PROVIDERS);

    return $api;
}

# Kubernetes::REST 1.107 answers list() with an IO::K8s::List whose items is a
# required arrayref, and croaks on the way there for anything the API server
# did not answer 2xx to. So there is one shape, and exactly one meaning for an
# empty arrayref: the cluster has no nodes.
#
# This used to guess -- undef, an object with items, a plain arrayref, else []
# -- and the else was the whole problem. An api that is not a Kubernetes::REST,
# or one too old to inflate a list, came back as "no nodes", which OCP::Cmd::Status
# prints as a successful reading of an empty cluster. Now an unreachable
# cluster or an unexpected client dies where it happened, and the callers that
# want to survive that (Status) already wrap it in an eval.
sub list_nodes {
    my ($self) = @_;
    return $self->api->list('Node')->items;
}

sub node_name {
    my ($self, $node) = @_;
    return $self->_dig($node, qw(metadata name)) // '';
}

sub node_ready {
    my ($self, $node) = @_;
    for my $cond (@{ $self->_array($self->_dig($node, qw(status conditions))) }) {
        next unless ($self->_dig($cond, 'type') // '') eq 'Ready';
        return ($self->_dig($cond, 'status') // '') eq 'True' ? 1 : 0;
    }
    return 0;
}

sub node_roles {
    my ($self, $node) = @_;
    my $labels = $self->_dig($node, qw(metadata labels)) || {};
    my @roles;

    push @roles, 'control-plane' if exists $labels->{'node-role.kubernetes.io/control-plane'};
    push @roles, 'master' if exists $labels->{'node-role.kubernetes.io/master'};

    return @roles ? join(',', @roles) : '<none>';
}

sub node_version {
    my ($self, $node) = @_;
    return $self->_dig($node, qw(status nodeInfo kubeletVersion)) // '';
}

sub node_internal_ip {
    my ($self, $node) = @_;
    for my $addr (@{ $self->_array($self->_dig($node, qw(status addresses))) }) {
        next unless ($self->_dig($addr, 'type') // '') eq 'InternalIP';
        return $self->_dig($addr, 'address') // '';
    }
    return '';
}

sub node_external_ip {
    my ($self, $node) = @_;
    for my $addr (@{ $self->_array($self->_dig($node, qw(status addresses))) }) {
        next unless ($self->_dig($addr, 'type') // '') eq 'ExternalIP';
        return $self->_dig($addr, 'address') // '';
    }
    return '';
}

sub node_gpu_count {
    my ($self, $node) = @_;
    my $capacity = $self->_dig($node, qw(status capacity)) || {};
    return $capacity->{'nvidia.com/gpu'} // 0;
}

sub gpu_nodes {
    my ($self) = @_;
    my $nodes = $self->list_nodes;
    return [ grep { $self->node_gpu_count($_) > 0 } @$nodes ];
}

sub _array {
    my ($self, $value) = @_;
    return [] unless $value;
    return $value if ref $value eq 'ARRAY';
    return [];
}

sub _dig {
    my ($self, $value, @path) = @_;

    for my $part (@path) {
        return undef unless defined $value;
        if (ref($value) eq 'HASH') {
            $value = $value->{$part};
        } elsif (ref($value) && eval { $value->can($part) }) {
            $value = $value->$part();
        } else {
            return undef;
        }
    }

    return $value;
}

1;

__END__

=synopsis

    use OCP::Kubernetes;

    # From a decrypted kubeconfig string (the common path for ocp status)
    my $k8s = OCP::Kubernetes->new(kubeconfig => $kc_yaml);
    my $nodes = $k8s->list_nodes;
    for my $node (@$nodes) {
        printf "%-20s %s\n", $k8s->node_name($node), $k8s->node_internal_ip($node);
    }

    # From robocop, running in-cluster as the pod's service account
    my $k8s = OCP::Kubernetes->new(in_cluster => 1);

=description

C<OCP::Kubernetes> wraps L<Kubernetes::REST::Kubeconfig> with two helpers
the CLI and the controller both need: a typed-resource bootstrap
(C<register_resource_providers>) and the node-extraction methods that
L<OCP::Cmd::Status>, L<OCP::Drift> and L<OCP::Cmd::Node::Ls> all reach
for.

Three ways to authenticate, picked by which attribute is set:

=over 4

=item C<kubeconfig>

A kubeconfig document as a string.  Written to a C<File::Temp> so
L<Kubernetes::REST::Kubeconfig> can take a path; the temp file is
auto-unlinked.

=item C<kubeconfig_path>

A path to a kubeconfig file.  Useful in tests and on the host where
the decrypted file already lives on disk.

=item C<in_cluster>

Boolean.  Off by default — a caller that lost its kubeconfig by accident
must keep failing with the message that says so, instead of quietly
authenticating as the pod's service account.  When on, the path
C</dev/null/ocp-in-cluster> is handed to L<Kubernetes::REST::Kubeconfig>;
that path cannot exist, so its in-cluster fallback is the only way the
resulting API can authenticate.

=back

Without any of the three, the constructor croaks.

=attr kubeconfig

Kubeconfig document as a string.  Mutually exclusive with
C<kubeconfig_path> and C<in_cluster>.

=attr kubeconfig_path

Path to a kubeconfig file on disk.

=attr in_cluster

Boolean.  When true, the API authenticates via the pod's service account.
Defaults to false.

=attr api

Lazy-built L<Kubernetes::REST> client.  Built once on first access; do
not construct it directly — it relies on C<register_resource_providers>
being run.

=method register_resource_providers

    $k8s->register_resource_providers($api);

Adds the typed IO::K8s classes OCP relies on (C<IO::K8s::Cilium>,
C<IO::K8s::CertManager>, C<IO::K8s::GatewayAPI>) to C<$api->k8s>.  Called
automatically from the C<api> builder; exposed for callers that already
hold an API object.

Requires a real L<Kubernetes::REST> — an C<$api> without C<k8s>, or an
IO::K8s install missing one of the three providers, dies here rather than
leaving the Kinds unregistered for a later lookup to trip over.

=method list_nodes

    my $nodes = $k8s->list_nodes;

Returns the arrayref of C<Node> resources from C<< $api->list('Node') >>.

Empty means empty: the cluster has no nodes.  A cluster that could not be
reached, or an API object that is not a L<Kubernetes::REST>, dies instead
of reporting nothing — the two are not the same answer.  Callers that must
survive an unreachable cluster (L<OCP::Cmd::Status>) wrap the call.

=method node_name

    my $name = $k8s->node_name($node);

Extracts C<metadata.name>.  Empty string when absent.

=method node_ready

    my $bool = $k8s->node_name($node);

Walks C<status.conditions> and returns 1 when a C<Ready=True> condition
is present, 0 otherwise.

=method node_roles

    my $csv = $k8s->node_roles($node);

Returns a comma-joined list of C<control-plane>/C<master> for the
C<node-role.kubernetes.io/> labels that are present, or C<< <none> >>.

=method node_version

    my $v = $k8s->node_version($node);

Returns C<status.nodeInfo.kubeletVersion>.

=method node_internal_ip

    my $ip = $k8s->node_internal_ip($node);

First C<InternalIP> entry from C<status.addresses>, or the empty string.

=method node_external_ip

    my $ip = $k8s->node_external_ip($node);

First C<ExternalIP> entry from C<status.addresses>, or the empty string.

=method node_gpu_count

    my $n = $k8s->node_gpu_count($node);

Reads C<status.capacity.nvidia.com/gpu>; 0 when absent.

=method gpu_nodes

    my $gpu_nodes = $k8s->gpu_nodes;

Returns the subset of C<list_nodes> whose C<node_gpu_count> is greater
than zero.

=seealso

L<Kubernetes::REST>, L<OCP::Drift>, L<OCP::Cmd::Status>,
L<OCP::Cmd::Node::Ls>

=cut

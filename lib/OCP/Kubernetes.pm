package OCP::Kubernetes;
# ABSTRACT: Shared typed Kubernetes helpers for OCP

use Moo;
use Carp qw(croak);
use File::Temp ();
use Kubernetes::REST::Kubeconfig;

our $VERSION = '0.001';

has kubeconfig => (
    is => 'ro',
);

has kubeconfig_path => (
    is => 'ro',
);

has api => (
    is      => 'lazy',
    builder => '_build_api',
);

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
    } else {
        croak "kubeconfig or kubeconfig_path required";
    }

    my $api = Kubernetes::REST::Kubeconfig->new(%args)->api;
    $self->register_resource_providers($api);

    return $api;
}

sub register_resource_providers {
    my ($self, $api) = @_;

    return unless $api && $api->can('k8s');

    for my $provider (qw(
        IO::K8s::Cilium
        IO::K8s::CertManager
        IO::K8s::GatewayAPI
    )) {
        eval "require $provider; 1" or next;
        eval { $api->k8s->add($provider) };
    }

    return $api;
}

sub list_nodes {
    my ($self) = @_;
    my $list = $self->api->list('Node');
    return [] unless $list;
    return $list->items if $list->can('items');
    return $list if ref $list eq 'ARRAY';
    return [];
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

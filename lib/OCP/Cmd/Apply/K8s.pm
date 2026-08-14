package OCP::Cmd::Apply::K8s;
# ABSTRACT: K8s API helpers used by the in-cluster apply phases

use strict;
use warnings;

use File::Temp ();
use JSON::MaybeXS qw( decode_json );
use Kubernetes::REST::Kubeconfig;
use Path::Tiny qw(path);
use YAML::XS ();

use OCP::K8s;

our $VERSION = '0.001';

=head1 SYNOPSIS

    my $api = OCP::Cmd::Apply::K8s::api($apply, $kubeconfig);
    OCP::Cmd::Apply::K8s::server_side_apply($apply, $api, $resource);

=head1 DESCRIPTION

Small helpers that the in-cluster components share: build a L<Kubernetes::REST>
api from a kubeconfig string, server-side apply a hash, parse and apply a
multi-document YAML, poll a Deployment until ready, raw C<GET> on a CRD path.
L<OCP::Cmd::Apply> re-exports every helper as a C<_method> thin forwarder so
the existing test surface (C<local *OCP::Cmd::Apply::_server_side_apply = ...>)
keeps working.

=cut

sub api {
    my ($self, $kubeconfig) = @_;

    # Return cached API if available and no new kubeconfig given
    return $self->{_k8s_api} if $self->{_k8s_api} && !$kubeconfig;

    if ($kubeconfig) {
        my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
        print $kc_fh $kubeconfig;
        close $kc_fh;

        # Keep temp file alive on $self so it doesn't get cleaned up
        $self->{_kc_temp} = $kc_fh;

        $self->{_k8s_api} = Kubernetes::REST::Kubeconfig->new(
            kubeconfig_path => $kc_fh->filename,
        )->api;

        # Register CRD providers for typed access
        $self->{_k8s_api}->k8s->add(
            'IO::K8s::Cilium',
            'IO::K8s::CertManager',
            'IO::K8s::GatewayAPI',
        );

        # Register OCP's own CRD classes (OCPNode, OCPNodeProvider).
        OCP::K8s->register($self->{_k8s_api});

        return $self->{_k8s_api};
    }

    die "No kubeconfig available and no cached API\n";
}

sub pluralize_kind {
    my ($self, $kind) = @_;
    my $plural = lc($kind);

    # Standard pluralization rules (matches Kubernetes conventions)
    if ($plural =~ /(?:s|x|z|sh|ch)$/) {
        return "${plural}es";
    } elsif ($plural =~ /[^aeiou]y$/) {
        $plural =~ s/y$/ies/;
        return $plural;
    } else {
        return "${plural}s";
    }
}

sub build_resource_path {
    my ($self, $resource) = @_;

    my $api_version = $resource->{apiVersion};
    my $kind = $resource->{kind};
    my $name = $resource->{metadata}{name};
    my $ns = $resource->{metadata}{namespace};

    my $plural = pluralize_kind($self, $kind);

    my $base;
    if ($api_version =~ m{/}) {
        $base = "/apis/$api_version";
    } else {
        $base = "/api/$api_version";
    }

    if ($ns) {
        return "$base/namespaces/$ns/$plural/$name";
    } else {
        return "$base/$plural/$name";
    }
}

sub server_side_apply {
    my ($self, $api, $resource) = @_;

    my $kind = $resource->{kind};
    my $name = $resource->{metadata}{name};
    my $ns   = $resource->{metadata}{namespace};

    # Use API's path building when the kind is registered (correct resource_plural)
    my $class = eval { $api->expand_class($kind) };
    my $path;
    if ($class) {
        # May fail if class lacks api_version() (e.g. auto-generated CRD classes)
        $path = eval { $api->_build_path($class, name => $name, ($ns ? (namespace => $ns) : ())) };
    }
    if (!$path) {
        # Fallback: build path from resource hash (works for all resources)
        $path = build_resource_path($self, $resource);
    }

    my $response = $api->_request('PATCH', $path, $resource,
        content_type => 'application/apply-patch+yaml',
        parameters   => { fieldManager => 'ocp', force => 'true' },
    );

    # _request is the raw transport: it returns whatever the API answered and
    # never inspects the status (only the typed methods run _check_response).
    # Without this check every failed apply was silent — a 404 for a CRD the
    # API server had not registered yet looked exactly like success, and the
    # run reported resources it had not created.
    my $status = eval { $response->status };
    if (defined $status && $status >= 400) {
        my $body = eval { $response->content } // '';
        $body =~ s/\s+/ /g;
        $body = substr($body, 0, 400);
        die "apply $kind/$name failed: HTTP $status $body\n";
    }

    return $response;
}

sub server_side_apply_all {
    my ($self, $api, @resources) = @_;

    for my $resource (@resources) {
        server_side_apply($self, $api, $resource);
    }
}

sub apply_yaml_string {
    my ($self, $api, $yaml_string) = @_;

    my @resources = grep { $_ && ref $_ eq 'HASH' && $_->{kind} }
        YAML::XS::Load($yaml_string);

    for my $resource (@resources) {
        server_side_apply($self, $api, $resource);
    }
}

sub apply_yaml_file {
    my ($self, $api, $file_path) = @_;
    apply_yaml_string($self, $api, path($file_path)->slurp_utf8);
}

sub poll_deployment_ready {
    my ($self, $api, $name, $namespace, $timeout) = @_;
    $timeout //= 120;

    my $polls = int($timeout / 5) || 1;
    for my $i (1..$polls) {
        my $deploy = eval { $api->get('Deployment', $name, namespace => $namespace) };
        if ($deploy && $deploy->status && ($deploy->status->availableReplicas // 0) > 0) {
            return 1;
        }
        sleep 5;
    }
    return 0;
}

sub resource_exists {
    my ($self, $api, $kind, $name, %opts) = @_;
    my $obj = eval { $api->get($kind, $name, %opts) };
    return defined $obj;
}

sub crd_get {
    my ($self, $api, $resource_path) = @_;
    my $response = eval { $api->_request('GET', $resource_path) };
    return undef unless $response && $response->status < 400;
    return eval { decode_json($response->content) };
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::K8s>, L<Kubernetes::REST::Kubeconfig>.

=cut

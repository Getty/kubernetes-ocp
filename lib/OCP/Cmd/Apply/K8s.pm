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
use OCP::Kubernetes ();

=head1 SYNOPSIS

    my $api = OCP::Cmd::Apply::K8s::api($apply, $kubeconfig);
    OCP::Cmd::Apply::K8s::server_side_apply($apply, $api, $resource);

=head1 DESCRIPTION

Small helpers that the in-cluster components share: build a L<Kubernetes::REST>
api from a kubeconfig string, server-side apply a hash, parse and apply a
multi-document YAML, poll a Deployment until ready, raw C<GET> on a CRD path,
and the reads a readiness wait and a single lookup make, which tell a 404 from
a read that failed.
L<OCP::Cmd::Apply> keeps a C<_method> thin forwarder for C<api> (as
C<_k8s_api>), C<pluralize_kind>, C<build_resource_path>, C<server_side_apply>,
C<server_side_apply_all>, C<apply_yaml_string>, C<apply_yaml_file>,
C<poll_deployment_ready>, C<resource_exists> and C<crd_get>, so the existing
test surface (C<local *OCP::Cmd::Apply::_server_side_apply = ...>) keeps
working. The newer C<kubeconfig_path>, C<read_or_why> and C<read_or_absent>
have no forwarder; callers use their full name,
C<OCP::Cmd::Apply::K8s::read_or_absent(...)>.

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

        # Register CRD providers for typed access via the Kubernetes::REST
        # `with` list (not a runtime $api->k8s->add), so they survive a rebuild
        # of the inner IO::K8s cache — see
        # OCP::Kubernetes::register_resource_providers (design D12, k131/k132).
        OCP::Kubernetes->register_resource_providers($self->{_k8s_api});

        # Register OCP's own CRD classes (OCPNode, OCPNodeProvider).
        OCP::K8s->register($self->{_k8s_api});

        return $self->{_k8s_api};
    }

    die "No kubeconfig available and no cached API\n";
}

# The kubeconfig api() wrote, as a local path: what a library that takes a
# kubeconfig file (Rex::Rancher::K8s) reads. The same cluster, the same
# credentials, decrypted once. Dies when no kubeconfig was handed to api().
sub kubeconfig_path {
    my ($self) = @_;
    my $kc = $self->{_kc_temp} or die "No kubeconfig file at hand for the cluster\n";
    return $kc->filename;
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

# Bytes, not characters: YAML::XS::Load decodes UTF-8 itself and dies on a
# decoded string with anything outside Latin-1 in it ("Wide character in
# YAML::XS::Load()"). apply_yaml_string gets bytes from YAML::XS::Dump already;
# the file has to arrive the same way. NVIDIA's ClusterPolicy CRD carries a
# typographic apostrophe in two descriptions, which slurp_utf8 turned into an
# apply that could never run.
sub apply_yaml_file {
    my ($self, $api, $file_path) = @_;
    apply_yaml_string($self, $api, path($file_path)->slurp_raw);
}

# 1 once the Deployment has an available replica, 0 when it has none within
# $timeout -- one that is not there (a 404) included: the caller says "not
# ready" in its words. A read that fails otherwise is polled again; when the
# last one failed too, this dies with its cause instead (k277).
sub poll_deployment_ready {
    my ($self, $api, $name, $namespace, $timeout) = @_;
    $timeout //= 120;

    my $polls = int($timeout / 5) || 1;
    my $read_err;
    for my $i (1..$polls) {
        my $deploy = eval { $api->get('Deployment', $name, namespace => $namespace) };
        $read_err = $@;
        $read_err = undef if $read_err && "$read_err" =~ /\b404\b/;
        if ($deploy && $deploy->status && ($deploy->status->availableReplicas // 0) > 0) {
            return 1;
        }
        $self->wait_seconds(5);
    }
    if ($read_err) {
        my $reason = "$read_err";
        chomp $reason;
        die "Deployment $namespace/$name not ready within ${timeout}s; the last read failed: $reason\n";
    }
    return 0;
}

# Whether the cluster has $kind $name. Only a 404 says it has not: the client
# dies on every error status, and an RBAC denial, an apiserver 5xx or a TLS
# error says nothing about the object. Those die with their cause instead of
# reading as absent -- which made apply redeploy what it could not see, or
# remove it (k269, the class of k256). The caller's step reports the death.
sub resource_exists {
    my ($self, $api, $kind, $name, %opts) = @_;
    my $obj = eval { $api->get($kind, $name, %opts) };
    if (my $err = $@) {
        return 0 if $err =~ /\b404\b/;
        my $reason = "$err";
        chomp $reason;
        my $where = join '/', grep { defined } $opts{namespace}, $name;
        die "could not read $kind $where: $reason\n";
    }
    return defined $obj;
}

# A read for a readiness wait (the AMD GPU stack's not_ready, the NVIDIA
# allocatable wait in OCP::Cmd::Apply::Workloads): what $read returns, or
# undef and why not -- "<what> not found" for a 404, "could not read <what>:
# <cause>" for any other failure, which is no verdict on the object (k269).
# Not a death: the wait reads again, and says the last why when it runs out.
sub read_or_why {
    my ($what, $read) = @_;
    my $object = eval { $read->() };
    my $err = $@ or return ($object, undef);
    my $reason = "$err";
    chomp $reason;
    return (undef, $reason =~ /\b404\b/ ? "$what not found" : "could not read $what: $reason");
}

# A read asked once: what $read returns, or undef for a 404 -- and only for
# one. Any other failure says nothing about the object and dies "could not
# read <what>: <cause>"; the step it is part of reports it (k277). A wait
# that reads again takes read_or_why.
sub read_or_absent {
    my ($what, $read) = @_;
    my $object = eval { $read->() };
    my $err = $@ or return $object;
    my $reason = "$err";
    chomp $reason;
    return undef if $reason =~ /\b404\b/;
    die "could not read $what: $reason\n";
}

# A raw GET of $resource_path (a CRD's object has no IO::K8s class OCP
# reads), decoded. undef only for a 404; a failed request, any other error
# status and a body that is no JSON die with the cause (k269).
sub crd_get {
    my ($self, $api, $resource_path) = @_;
    my $response = eval { $api->_request('GET', $resource_path) };
    unless ($response) {
        my $reason = "$@" || 'no response';
        chomp $reason;
        die "GET $resource_path failed: $reason\n";
    }
    my $status = $response->status;
    return undef if $status == 404;
    if ($status >= 400) {
        my $body = eval { $response->content } // '';
        $body =~ s/\s+/ /g;
        $body = substr($body, 0, 400);
        die "GET $resource_path failed: HTTP $status $body\n";
    }
    my $object = eval { decode_json($response->content) };
    unless ($object) {
        my $reason = "$@" || 'empty body';
        chomp $reason;
        die "GET $resource_path: the answer is no JSON: $reason\n";
    }
    return $object;
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::K8s>, L<Kubernetes::REST::Kubeconfig>.

=cut

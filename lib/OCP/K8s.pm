package OCP::K8s;
# ABSTRACT: Register OCP's CRD classes with a Kubernetes::REST api instance

use strict;
use warnings;
use Carp qw(croak);
# Load without import: IO::K8s <= 1.002 makes APIObject classes inherit from
# IO::K8s::Resource, so they also inherit its import(), which would inject the
# k8s DSL into every package that says "use OCP::K8s;" and collide with a local
# "has k8s".
use OCP::K8s::OCPNode ();
use OCP::K8s::OCPNodeProvider ();

# OCPNode and OCPNodeProvider as an IO::K8s provider map, the form an entry of
# the Kubernetes::REST `with` list takes.
my %KINDS = (
    OCPNode         => '+OCP::K8s::OCPNode',
    OCPNodeProvider => '+OCP::K8s::OCPNodeProvider',
);

# On the client's `with` list, not in $api->resource_map (k283). The default
# client builds that map from the cluster's discovery, and invalidate_discovery
# -- what Kubernetes::REST's ensure_crd ends with, and what its docs prescribe
# after a CRD is installed -- throws a built map away and builds the next one
# from discovery again, without what was written into the old one: OCPNode was
# then an unknown resource, or an IO::K8s::Unstructured. The inner IO::K8s
# merges `with` every time it is built, so the Kinds survive every rebuild, the
# way OCP::Kubernetes registers the CRD providers. It also leaves the map
# unbuilt: writing into it fetched discovery right here, one request ahead of
# the caller's own -- and against an API that does not answer, a warning too.
#
# The entry is %KINDS itself, so a second register finds it and adds nothing:
# calling it on an api OCP::Kubernetes built, which is registered already, is
# harmless -- and unneeded (k295). add_provider (Kubernetes::REST 1.111, the
# pinned version) puts that same reference on `with` and merges it into an
# inner IO::K8s that is already built, as in
# OCP::Kubernetes::register_resource_providers.
sub register {
    my ($class, $api) = @_;
    return $api if grep { ref $_ && $_ == \%KINDS } @{ $api->with };
    $api->add_provider(\%KINDS);
    return $api;
}

=head1 METHODS

=method register

    OCP::K8s->register($api);

Puts OCP's CRD classes on C<$api>'s C<with> list, the provider list
L<Kubernetes::REST> merges into its inner L<IO::K8s> every time it builds one.
So the two Kinds survive C<invalidate_discovery>, which C<ensure_crd> calls and
which rebuilds the resource map from the cluster's discovery: written into
C<< $api->resource_map >> they were lost there, and C<OCPNode> became an
unknown resource or an L<IO::K8s::Unstructured>.

Makes no request: the resource map is built when a name is first resolved, not
here. Registering an api a second time adds nothing. Returns C<$api>.

=cut

# Write to a CR's /status subresource.
#
# OCPNode declares `subresources: {status: {}}`, and once a CRD does that the
# API server SILENTLY DROPS the status stanza of every write to the main
# resource endpoint — create, update, merge-patch and server-side apply alike.
# It answers 2xx, so nothing looks wrong; the status just never lands. That is
# how `ocp apply` could print
# "ensured OCPNode/cortex (control-plane, Ready)" while the stored CR had no
# status at all and `ocp node ls` correctly reported Pending with no IP.
#
# Status is only writable through the separate /status endpoint. Kubernetes::REST
# grew a native writer for it in 1.107 (the version this dist pins) and that is
# what the first branch below uses; it also lets test fakes stub `patch_status`
# instead of emulating the transport. The hand-built fallback underneath stays
# for clients that predate it — `make test` runs against whatever CPAN state the
# host has, not against the pin — and is the one place in OCP allowed to reach
# for the raw _request escape.
#
# Note the two branches differ in what they hand back: the native writer returns
# an inflated IO::K8s object, the fallback the raw HTTP response. Nothing reads
# either — the return value is not part of this method's contract, callers only
# care that it did not die. Do not start reading it without making both branches
# agree first.
sub patch_status {
    my ($class, $api, %args) = @_;

    my $kind   = $args{kind}   or croak "patch_status: 'kind' required";
    my $name   = $args{name}   or croak "patch_status: 'name' required";
    my $status = $args{status} or croak "patch_status: 'status' required";
    my $ns     = $args{namespace};

    # Kubernetes::REST >= 1.107 house form: typed Kind first, then named args.
    # The payload key is 'patch' (not 'status'), the method appends /status to
    # the path itself and defaults to merge-patch.
    if ($api->can('patch_status')) {
        return $api->patch_status($kind,
            name      => $name,
            namespace => $ns,
            patch     => { status => $status },
        );
    }

    my $target = $api->expand_class($kind);
    my $path   = $api->_build_path($target, name => $name, namespace => $ns);

    my $response = $api->_request(
        'PATCH', "$path/status",
        { status => $status },
        content_type => 'application/merge-patch+json',
    );
    $api->_check_response($response, "patch status $kind/$name")
        if $api->can('_check_response');

    return $response;
}

=method patch_status

    OCP::K8s->patch_status($api,
        kind      => 'OCPNode',
        name      => 'worker-1',
        namespace => 'ocp-system',
        status    => { phase => 'Ready', publicIP => '10.0.0.5' },
    );

Merge-patches C<$status> into the CR's C</status> subresource.

C<OCPNode> enables the C<status> subresource, which means the Kubernetes API
server B<silently discards> the C<status> stanza of any write aimed at the main
resource endpoint — C<ensure>, C<update> and C<patch> all included. Such a write
still returns 2xx, so a dropped status is invisible at the call site. Status
therefore has to go through the separate C</status> endpoint, and this is the
only method in OCP that writes it.

The method itself is kind-agnostic, so it works for any resource whose CRD
enables the subresource.

It delegates to L<Kubernetes::REST/patch_status> (1.107 and later) and falls
back to a hand-built C</status> request for older clients. The two paths return
different things — an inflated object versus the raw response — so the return
value is deliberately not part of this method's contract: it either writes the
status or it dies.

=cut

# Evict one pod through the policy/v1 Eviction subresource -- what
# `kubectl drain` does, without kubectl. Kubernetes::REST has no verb for it,
# so the request is built from its public request seam (build_path /
# prepare_request / io->call) rather than from _request.
#
# Hands back the HTTP status instead of croaking on 4xx, because the caller
# must tell the answers apart: 429 is a PodDisruptionBudget saying "not now"
# and is retried, 404 is a pod that already left, anything else is a failure.
sub evict {
    my ($class, $api, %args) = @_;

    my $name = $args{name}      or croak "evict: 'name' required";
    my $ns   = $args{namespace} or croak "evict: 'namespace' required";

    my $path = $api->build_path($api->expand_class('Pod'),
        name        => $name,
        namespace   => $ns,
        subresource => 'eviction',
    );
    my $response = $api->io->call($api->prepare_request('POST', $path,
        body => {
            apiVersion => 'policy/v1',
            kind       => 'Eviction',
            metadata   => { name => $name, namespace => $ns },
        },
    ));

    return ($response->status, $response->content);
}

=method evict

    my ($status, $body) = OCP::K8s->evict($api,
        name      => 'web-1',
        namespace => 'apps',
    );

Asks the API server to evict one pod through the C<policy/v1> Eviction
subresource, the call C<kubectl drain> makes.  Unlike a plain delete, an
eviction honours PodDisruptionBudgets.

Returns the HTTP status and the raw response body and does B<not> die on a 4xx:
the caller has to tell C<429> (a budget refuses for now; try again), C<404>
(the pod is already gone) and everything else apart.  Used by
L<OCP::Node/Teardown> to drain a node.

=cut

1;

__END__

=head1 SYNOPSIS

    use OCP::K8s;

    OCP::K8s->register($api);

    # OCPNode and OCPNodeProvider are now typed
    my $node = $api->get('OCPNode', name => 'worker-1', namespace => 'ocp-system');

=head1 DESCRIPTION

Registers L<OCP::K8s::OCPNode> and L<OCP::K8s::OCPNodeProvider> with a
L<Kubernetes::REST> instance so that C<get>, C<list>, C<ensure>, and C<delete>
calls return typed objects instead of bare hashes.

Call C<register> on an API instance before issuing any CRD requests. The api
L<OCP::Kubernetes> builds has them registered already.

=head1 SEE ALSO

L<OCP::K8s::OCPNode>, L<OCP::K8s::OCPNodeProvider>, L<Kubernetes::REST>

=cut

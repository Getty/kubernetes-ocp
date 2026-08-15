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

sub register {
    my ($class, $api) = @_;
    $api->resource_map->{OCPNode}         = '+OCP::K8s::OCPNode';
    $api->resource_map->{OCPNodeProvider} = '+OCP::K8s::OCPNodeProvider';
    return $api;
}

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
# Status is only writable through the separate /status endpoint, and
# Kubernetes::REST has no method for it (patch/update both go through
# _build_path, which cannot address a subresource). So this is the one place
# in OCP allowed to reach for the raw _request escape; every status write goes
# through here. If Kubernetes::REST grows a native writer we prefer it, which
# also lets test fakes stub `patch_status` instead of emulating the transport.
sub patch_status {
    my ($class, $api, %args) = @_;

    my $kind   = $args{kind}   or croak "patch_status: 'kind' required";
    my $name   = $args{name}   or croak "patch_status: 'name' required";
    my $status = $args{status} or croak "patch_status: 'status' required";
    my $ns     = $args{namespace};

    return $api->patch_status(%args) if $api->can('patch_status');

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

1;

__END__

=head1 NAME

OCP::K8s - Register OCP CRD classes with a Kubernetes::REST api instance

=head1 SYNOPSIS

    use OCP::K8s;

    OCP::K8s->register($api);

    # OCPNode and OCPNodeProvider are now typed
    my $node = $api->get('OCPNode', name => 'worker-1', namespace => 'ocp-system');

=head1 DESCRIPTION

Registers L<OCP::K8s::OCPNode> and L<OCP::K8s::OCPNodeProvider> into the
resource map of a L<Kubernetes::REST> instance so that C<get>, C<list>,
C<ensure>, and C<delete> calls return typed objects instead of bare hashes.

Call C<register> once per API instance before issuing any CRD requests.

=head1 METHODS

=head2 register

    OCP::K8s->register($api);

Registers OCP's CRD classes into C<$api>'s resource map.

=head2 patch_status

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

=head1 SEE ALSO

L<OCP::K8s::OCPNode>, L<OCP::K8s::OCPNodeProvider>, L<Kubernetes::REST>

=cut

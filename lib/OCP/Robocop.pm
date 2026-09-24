package OCP::Robocop;
# ABSTRACT: Kubernetes controller for automated worker management

use strict;
use warnings;

1;

__END__

=head1 NAME

OCP::Robocop - Kubernetes controller for automated worker management

=head1 SYNOPSIS

    robocop controller      # how the Deployment in ocp-system starts it

=head1 DESCRIPTION

Robocop is the in-cluster controller that manages worker nodes. This package
is the namespace and the overview; the controller is
L<OCP::Robocop::Controller>, the in-memory key delivery
L<OCP::Robocop::KeyInjection>.

=head1 SECURITY MODEL

Robocop's SSH key is the robo (automation) key from F<keys.yaml>. How its
private half gets into the pod is C<robocop.security_level> in F<ocp.yaml>:

=over 4

=item C<secret> (default), C<secret_approved>

C<ocp deploy-robocop> writes it into the C<robocop-credentials> Secret
(C<secret_approved> behind a PIN2 approval). A pod restart self-heals.

=item C<inject>

The key is never put in a Secret and never written to the pod's disk. The
admin runs C<ocp inject-key> (PIN1 and PIN2), which sends it through a
Kubernetes port-forward into the running pod's memory. There is no
checkpoint: after a pod restart robocop holds no key, stays not Ready and
marks the OCPNodes that need it with C<SSHKeyAvailable=False> until the key is
injected again.

=back

=head1 CRDs

Robocop watches for these CRDs:

=over 4

=item * B<OCPNode> - Individual nodes (SSH provider, Hetzner, GPU servers)

=item * B<OCPNodeProvider> - Infrastructure provider configuration (Hetzner, SSH)

=back

=cut

package OCP::Cmd::DeployRobocop;
# ABSTRACT: Deploy robocop controller to the cluster

use Moo;
use MooX::Cmd;
use OCP;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

sub execute {
    my ($self, $args, $chain) = @_;

    die <<'MSG';
ERROR: 'ocp deploy-robocop' is currently disabled.

Robocop deployment was previously implemented by shelling out to kubectl.
That dependency has been removed; reimplementation against
Kubernetes::REST is pending until robocop itself is in active use.

MSG
}

1;

__END__

=head1 NAME

OCP::Cmd::DeployRobocop - Deploy robocop controller to the cluster

=head1 STATUS

Currently disabled. Robocop is not in active use yet; the previous
kubectl-based implementation was removed together with the kubectl
dependency from the OCP image. Will be reimplemented via
L<Kubernetes::REST> when robocop comes online.

=head1 SYNOPSIS

    ocp deploy-robocop  # currently dies with a TODO message

=cut

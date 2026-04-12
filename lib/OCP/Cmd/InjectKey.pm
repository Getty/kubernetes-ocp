package OCP::Cmd::InjectKey;
# ABSTRACT: Inject robocop SSH key into memory (requires admin approval)

use Moo;
use MooX::Cmd;
use MooX::Options;
use OCP;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

sub execute {
    my ($self, $args, $chain) = @_;

    die <<'MSG';
ERROR: 'ocp inject-key' is currently disabled.

Robo-key injection was previously implemented by shelling out to
'kubectl port-forward'. That dependency has been removed; reimplementation
against Kubernetes::REST's port_forward (via Net::Async::Kubernetes) is
pending until robocop itself is in active use.

MSG
}

1;

__END__

=head1 NAME

OCP::Cmd::InjectKey - Inject robo-ssh key into robocop memory

=head1 STATUS

Currently disabled. Robocop is not in active use yet; the previous
kubectl-port-forward-based implementation was removed together with the
kubectl dependency from the OCP image. Will be reimplemented via
L<Kubernetes::REST/port_forward> backed by L<Net::Async::Kubernetes>
when robocop comes online.

=head1 SYNOPSIS

    ocp inject-key  # currently dies with a TODO message

=cut

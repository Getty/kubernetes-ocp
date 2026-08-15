package OCP::Cmd::Keys;
# ABSTRACT: Inspect the encrypted keys in keys.yaml

use Moo;
# Subcommands live directly under OCP::Cmd::Keys, not the default
# OCP::Cmd::Keys::Cmd.
use MooX::Cmd base => 'OCP::Cmd::Keys';
use MooX::Options;

with 'OCP::Role::Cmd';

sub execute {
    my ($self, $args, $chain) = @_;
    die "subcommand required: ocp keys [show]\n";
}

1;

__END__

=head1 NAME

OCP::Cmd::Keys - Inspect the encrypted keys in keys.yaml

=head1 SYNOPSIS

    ocp keys show                     # admin public key
    ocp keys show --purpose automation
    ocp keys show --name admin-ssh-20260815

=head1 DESCRIPTION

Entry point for the C<ocp keys> subcommand group. Dispatches to
L<OCP::Cmd::Keys::Show>.

Read-only by design: the group prints B<public> key material only. Private
keys are reached through the commands that need them — L<OCP::Cmd::SSH> for
admin SSH access, L<OCP::Cmd::Apply> for control-plane deployment — so a
decrypted private key never has to touch the filesystem.

=head1 SEE ALSO

L<OCP::Cmd::Keys::Show>, L<OCP::Keys>

=cut

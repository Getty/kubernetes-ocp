package OCP::Cmd::Keys;
# ABSTRACT: Inspect the encrypted keys in keys.yaml, and move a dev-mode project to them

use Moo;
# Subcommands live directly under OCP::Cmd::Keys, not the default
# OCP::Cmd::Keys::Cmd.
use MooX::Cmd base => 'OCP::Cmd::Keys';
use MooX::Options;

with 'OCP::Role::Cmd';

sub execute {
    my ($self, $args, $chain) = @_;
    die "subcommand required: ocp keys [show|authorized-keys|recipients|operator|secure|add-pin2]\n";
}

1;

__END__

=head1 SYNOPSIS

    ocp keys show                     # admin public key
    ocp keys show --purpose automation
    ocp keys show --name admin-ssh-20260815
    ocp keys authorized-keys          # admin + robo: what an ssh worker needs
    ocp keys authorized-keys --purpose admin   # what a control plane needs
    ocp keys recipients ls            # age recipients of the SOPS files
    ocp keys recipients add age1...
    ocp keys recipients rm  age1...
    ocp keys operator add --name leitstand --ssh-pubkey leitstand.pub --age age1...
    ocp keys operator rm leitstand    # its SSH key off every machine, its age key out
    ocp keys secure                   # dev mode -> secure mode, machines first
    ocp keys secure --drop-bootstrap  # ...and remove .ocp/id_ed25519 from them
    ocp keys add-pin2                 # PIN2 layer onto an admin key stored without it

=head1 DESCRIPTION

Entry point for the C<ocp keys> subcommand group. Dispatches to
L<OCP::Cmd::Keys::Show>, L<OCP::Cmd::Keys::AuthorizedKeys>,
L<OCP::Cmd::Keys::Recipients>, L<OCP::Cmd::Keys::Operator>,
L<OCP::Cmd::Keys::Secure> and L<OCP::Cmd::Keys::AddPin2>.

C<operator> registers and revokes an operator -- a Leitstand that runs
C<ocp apply> unattended with its own age identity and SSH key: the key
onto or off every machine, the age recipient into or out of F<.sops.yaml>.

C<show> prints one key, picked by purpose or name. C<authorized-keys> answers
the question an operator setting up a machine has: which lines go into its
F<authorized_keys>. In secure mode a control plane needs the admin key and a
worker the C<ssh> provider reaches needs the admin B<and> the robo key, since
robocop joins and tears down workers with the robo key while C<ocp node rm>,
C<ocp ssh> and a CLI join use the admin key.

C<secure> moves a C<--nopassword> project into secure mode: it creates
the admin and robo keys, puts their public halves onto every machine while the
bootstrap key still opens them, checks the admin key on each, and only then
writes F<keys.yaml>.

C<add-pin2> re-adds an admin key stored without its PIN2 layer -- a PIN2 of
C<"0"> before that was fixed -- under age and a new PIN2. The key itself does
not change.

Apart from C<secure>, C<operator> and C<add-pin2>, the group prints B<public> key material only
(C<recipients add|rm> rewrite who the SOPS files are encrypted for, never a
key). Private
keys are reached through the commands that need them — L<OCP::Cmd::SSH> for
admin SSH access, L<OCP::Cmd::Apply> for control-plane deployment — so a
decrypted private key never has to touch the filesystem.

=head1 SEE ALSO

L<OCP::Cmd::Keys::Show>, L<OCP::Cmd::Keys::AuthorizedKeys>,
L<OCP::Cmd::Keys::Operator>, L<OCP::Cmd::Keys::Secure>,
L<OCP::Cmd::Keys::AddPin2>, L<OCP::Keys>

=cut

package OCP::Cmd::Keys::Operator;
# ABSTRACT: Operators (a Leitstand) that run ocp apply unattended with their own keys

use Moo;
# Subcommands live directly under OCP::Cmd::Keys::Operator.
use MooX::Cmd base => 'OCP::Cmd::Keys::Operator';
use MooX::Options;

with 'OCP::Role::Cmd';

sub execute {
    my ($self, $args, $chain) = @_;
    die "subcommand required: ocp keys operator [add|rm]\n";
}

1;

__END__

=head1 NAME

OCP::Cmd::Keys::Operator - Operators (a Leitstand) that run ocp apply unattended with their own keys

=head1 SYNOPSIS

    # where the project key is (PIN1, PIN2):
    ocp keys operator add --name leitstand --ssh-pubkey leitstand.pub --age age1...
    ocp keys operator rm leitstand

    # on the operator's machine, unattended:
    SOPS_AGE_KEY_FILE=~/.config/ocp/age.key \
    OCP_OPERATOR_KEY=~/.ssh/ocp-leitstand \
    ocp apply

=head1 DESCRIPTION

An operator -- a Leitstand machine -- runs C<ocp apply> without anybody at a
PIN prompt (k216). It brings two keys of its own and hands over only their
public halves:

=over 4

=item * an B<age identity>: it decrypts the project's SOPS files with it
(C<SOPS_AGE_KEY_FILE>, as for sops), so it becomes one of their recipients;

=item * an B<SSH key>: the machines of the cluster trust it, and
L<OCP::ClusterKey> picks it -- from C<OCP_OPERATOR_KEY> -- whenever the run's
age identity is the operator's. No PIN2.

=back

C<add> runs where the project key is: it puts the SSH public key onto every
machine of the cluster with the admin key (PIN2), and only then records the
operator in F<keys.yaml> (purpose C<operator>, no private half) and adds its
age recipient to F<.sops.yaml>, re-encrypting the files. C<rm> takes the SSH
key off every machine, the entry out of F<keys.yaml> and the recipient out of
F<.sops.yaml>, and says what to rotate.

What an operator cannot do: open the private SSH keys in F<keys.yaml> (admin
and robo), whose inner age layer is the project key's alone; give the PIN2
approval of C<secret_approved> or C<ocp inject-key>; make the first
C<ocp apply> of a cluster. robocop's credentials Secret it leaves as it is.

See L<OCP::Cmd::Keys::Operator::Add>, L<OCP::Cmd::Keys::Operator::Rm>,
F<docs/security.md>.

=cut

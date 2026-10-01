package OCP::Cmd::Keys::Recipients;
# ABSTRACT: Who the project's SOPS files are encrypted for

use Moo;
# Subcommands live directly under OCP::Cmd::Keys::Recipients.
use MooX::Cmd base => 'OCP::Cmd::Keys::Recipients';
use MooX::Options;

with 'OCP::Role::Cmd';

sub execute {
    my ($self, $args, $chain) = @_;
    die "subcommand required: ocp keys recipients [ls|add|rm]\n";
}

1;

__END__

=head1 NAME

OCP::Cmd::Keys::Recipients - Who the project's SOPS files are encrypted for

=head1 SYNOPSIS

    ocp keys recipients ls
    ocp keys recipients add age1...
    ocp keys recipients rm  age1...

=head1 DESCRIPTION

F<keys.yaml>, F<secrets.yaml> and F<kubeconfig.yaml> are SOPS files. They are
always encrypted for the project key (F<.ocp/age.key>, behind PIN1 in
F<age.key.enc>), and additionally for every age recipient the governing
F<.sops.yaml> names for them -- a Leitstand machine, a second operator. The
list lives there, in sops' own C<creation_rules>, so the C<sops> CLI and OCP
agree on it.

A recipient is added by its B<public> key only; its private key never leaves
its machine. Adding or removing one re-encrypts the files with a new data key
(L<File::SOPS/rotate>), which needs the project key (PIN1).

OCP writes the recipient list into the project's own F<.sops.yaml>. When a
F<.sops.yaml> further up -- the project living inside another repository --
has the rule for the project's files, OCP reads it and does not rewrite it:
edit it there, then run C<add> or C<rm> to re-encrypt.

The private SSH keys inside F<keys.yaml> keep their own age layer for the
project key alone; another recipient can read F<keys.yaml>, not those keys.

See L<OCP::Cmd::Keys::Recipients::Ls>, L<OCP::Cmd::Keys::Recipients::Add>,
L<OCP::Cmd::Keys::Recipients::Rm>.

=cut

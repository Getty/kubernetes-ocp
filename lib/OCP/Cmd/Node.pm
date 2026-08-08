package OCP::Cmd::Node;
# ABSTRACT: Manage OCPNode CRs

use Moo;
# Subcommands live directly under OCP::Cmd::Node, not the default
# OCP::Cmd::Node::Cmd.
use MooX::Cmd base => 'OCP::Cmd::Node';
use MooX::Options;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

sub execute {
    my ($self, $args, $chain) = @_;
    die "subcommand required: ocp node [add|rm|ls]\n";
}

1;

__END__

=head1 NAME

OCP::Cmd::Node - Manage OCPNode CRs

=head1 SYNOPSIS

    ocp node add NAME --role worker
    ocp node rm  NAME
    ocp node ls

=head1 DESCRIPTION

Entry point for the C<ocp node> subcommand group.  Dispatches to
L<OCP::Cmd::Node::Add>, L<OCP::Cmd::Node::Rm>, and L<OCP::Cmd::Node::Ls>.

=head1 SEE ALSO

L<OCP::Cmd::Node::Add>, L<OCP::Cmd::Node::Rm>, L<OCP::Cmd::Node::Ls>

=cut

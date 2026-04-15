package OCP::Cmd::Provider;
# ABSTRACT: Manage OCPNodeProvider CRs

use Moo;
use MooX::Cmd;
use MooX::Options;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

sub execute {
    my ($self, $args, $chain) = @_;
    die "subcommand required: ocp provider [add|rm|ls]\n";
}

1;

__END__

=head1 NAME

OCP::Cmd::Provider - Manage OCPNodeProvider CRs

=head1 SYNOPSIS

    ocp provider add --name hetzner-a --type hetzner --token-file token.txt
    ocp provider rm  NAME
    ocp provider ls

=head1 DESCRIPTION

Entry point for the C<ocp provider> subcommand group.  Dispatches to
L<OCP::Cmd::Provider::Add>, L<OCP::Cmd::Provider::Rm>, and
L<OCP::Cmd::Provider::Ls>.

=head1 SEE ALSO

L<OCP::Cmd::Provider::Add>, L<OCP::Cmd::Provider::Rm>, L<OCP::Cmd::Provider::Ls>

=cut

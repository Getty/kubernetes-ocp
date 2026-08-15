package OCP::Cmd::Hetzner;
# ABSTRACT: Debug commands against the Hetzner Cloud API

use Moo;
# Subcommands live directly under OCP::Cmd::Hetzner, not the default
# OCP::Cmd::Hetzner::Cmd.
use MooX::Cmd base => 'OCP::Cmd::Hetzner';
use MooX::Options;

with 'OCP::Role::Cmd';

sub execute {
    my ($self, $args, $chain) = @_;
    die "subcommand required: ocp hetzner [list]\n";
}

1;

__END__

=synopsis

    ocp hetzner list
    ocp hetzner list --label ocp-cluster=prod

=description

Entry point for the C<ocp hetzner> subcommand group.  Dispatches to
L<OCP::Cmd::Hetzner::List>, which lists the servers the configured
Hetzner API token can see.  The cluster adapter lives in
L<OCP::Provider::Hetzner> — that is what C<ocp apply> calls; this group
is for debugging only.

=seealso

L<OCP::Cmd::Hetzner::List>, L<OCP::Provider::Hetzner>,
L<OCP::Hetzner::Picker>

=cut

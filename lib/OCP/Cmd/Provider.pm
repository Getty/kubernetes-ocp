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

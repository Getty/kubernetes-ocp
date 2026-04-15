package OCP::Cmd::Node;
# ABSTRACT: Manage OCPNode CRs

use Moo;
use MooX::Cmd;
use MooX::Options;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

sub execute {
    my ($self, $args, $chain) = @_;
    die "subcommand required: ocp node [ls]\n";
}

1;

package OCP::Role::Cmd;
# ABSTRACT: Base role for OCP commands

use Moo::Role;

sub ocp { $_[0]->command_chain->[0] }

1;

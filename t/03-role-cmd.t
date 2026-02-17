#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::Role::Cmd;

#
# Test: Role can be composed into a Moo class
#

{
    package TestCmd;
    use Moo;
    with 'OCP::Role::Cmd';

    # Simulate MooX::Cmd's command_chain attribute
    has command_chain => (
        is      => 'ro',
        default => sub { ['the_root_ocp_object'] },
    );
}

{
    my $cmd = TestCmd->new;
    isa_ok($cmd, 'TestCmd');
    ok($cmd->does('OCP::Role::Cmd'), 'TestCmd does OCP::Role::Cmd');
    is($cmd->ocp, 'the_root_ocp_object', 'ocp returns command_chain->[0]');
}

#
# Test: Works with a real OCP-like object in the chain
#

{
    package FakeOCP;
    use Moo;
    sub config  { 'ocp.yaml' }
    sub verbose { 0 }
}

{
    package TestCmdWithFakeOCP;
    use Moo;
    with 'OCP::Role::Cmd';

    has command_chain => (
        is      => 'ro',
        default => sub { [FakeOCP->new] },
    );
}

{
    my $cmd = TestCmdWithFakeOCP->new;
    isa_ok($cmd->ocp, 'FakeOCP', 'ocp returns actual object from chain');
    is($cmd->ocp->config, 'ocp.yaml', 'Can call methods on ocp object');
    is($cmd->ocp->verbose, 0, 'verbose accessor works through chain');
}

#
# Test: Custom command_chain (multi-level)
#

{
    my $root = FakeOCP->new;
    my $cmd = TestCmd->new(command_chain => [$root, 'middle', 'leaf']);
    is($cmd->ocp, $root, 'ocp always returns first element (root)');
}

done_testing;

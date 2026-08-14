#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Cwd qw(getcwd);
use FindBin;

# Every command in this list must be reachable from the CLI. They are run in
# an empty directory, so each one is expected to stop at the missing config —
# what matters is that it gets that far instead of falling back to the root
# usage screen or a Perl error.

my $bin = "$FindBin::Bin/../bin/ocp";
my $dir = tempdir(CLEANUP => 1);
my $cwd = getcwd();

sub ocp {
    my (@args) = @_;
    chdir $dir or die "chdir: $!";
    my $output = `$^X $bin @args 2>&1`;
    my $rc = $? >> 8;
    chdir $cwd or die "chdir back: $!";
    return ($output, $rc);
}

my @COMMANDS = qw(
    init apply status destroy kubeconfig version update ssh
    node provider hetzner deployrobocop
);

for my $cmd (@COMMANDS) {
    my ($out) = ocp($cmd);
    unlike($out, qr/Usage: ocp <command>/,
        "'ocp $cmd' is a known command");
}

# Subcommand groups dispatch into their subcommands
{
    my ($out) = ocp('node');
    like($out, qr/subcommand required/, "'ocp node' asks for a subcommand");

    for my $sub (qw(ls add rm)) {
        my ($sub_out) = ocp('node', $sub);
        unlike($sub_out, qr/subcommand required/,
            "'ocp node $sub' reaches the subcommand");
    }
}

{
    my ($out) = ocp('provider');
    like($out, qr/subcommand required/, "'ocp provider' asks for a subcommand");

    for my $sub (qw(ls add rm)) {
        my ($sub_out) = ocp('provider', $sub);
        unlike($sub_out, qr/subcommand required/,
            "'ocp provider $sub' reaches the subcommand");
    }
}

# Hyphenated spellings are aliases for the class-derived names
{
    my ($out) = ocp('deploy-robocop');
    unlike($out, qr/Usage: ocp <command>/, "'ocp deploy-robocop' is accepted");
}

# A node name may be positional
{
    my ($out) = ocp('node', 'add');
    like($out, qr/Usage: ocp node add NAME/, 'node add without a name explains itself');

    my ($named) = ocp('node', 'add', 'worker-1');
    unlike($named, qr/Usage: ocp node add NAME/, 'positional node name is accepted');
}

# No stray warnings from the command wiring
{
    my ($out) = ocp('node');
    unlike($out, qr/redefined/, 'no redefinition warnings');
}

done_testing;

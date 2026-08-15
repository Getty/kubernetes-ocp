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
    node provider hetzner deployrobocop keys
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

{
    my ($out) = ocp('keys');
    like($out, qr/subcommand required/, "'ocp keys' asks for a subcommand");

    my ($sub_out) = ocp('keys', 'show');
    unlike($sub_out, qr/subcommand required/,
        "'ocp keys show' reaches the subcommand");
}

{
    my ($out) = ocp('hetzner');
    like($out, qr/subcommand required/, "'ocp hetzner' asks for a subcommand");

    my ($sub_out) = ocp('hetzner', 'list');
    unlike($sub_out, qr/subcommand required/,
        "'ocp hetzner list' reaches the subcommand");
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

# The flag that skips the Ready wait is spelled --nowait, like --nogit and
# --nopassword in `ocp init`. MooX::Options strips a literal "no-" as
# Getopt::Long's negation marker before it maps dashes to underscores, so a
# --no-wait spelling died with "Unknown option: wait". The older --no_wait is
# kept as an alias. Both must get past option parsing to the missing config.
{
    for my $spelling (qw(--nowait --no_wait)) {
        my ($out) = ocp('node', 'add', 'worker-1', $spelling);
        unlike($out, qr/Unknown option/,
            "'ocp node add worker-1 $spelling' is a known option");
        like($out, qr/Config file 'ocp\.yaml' not found/,
            "'ocp node add worker-1 $spelling' reaches the command body");
    }
}

# No stray warnings from the command wiring
{
    my ($out) = ocp('node');
    unlike($out, qr/redefined/, 'no redefinition warnings');
}

# An unknown command word is refused, not silently resolved to the enclosing
# command. MooX::Cmd used to fall back to the root: `ocp typo --help` printed
# the root usage and exited 0 (--help is handled while the object is built, so
# nothing ever looked at the typo), and `ocp typo apply` just ran apply.
{
    for my $argv (['quatschkommando'], ['quatschkommando', '--help'],
                  ['quatschkommando', 'apply'])
    {
        my ($out, $rc) = ocp(@$argv);
        isnt($rc, 0, "'ocp @$argv' exits non-zero");
        like($out, qr/Unknown command 'quatschkommando'/,
            "'ocp @$argv' names the word it did not understand");
        like($out, qr/\bapply\b.*\bstatus\b/s,
            "'ocp @$argv' lists the available commands");
    }

    for my $group (qw(node provider hetzner)) {
        my ($out, $rc) = ocp($group, 'quatsch', '--help');
        isnt($rc, 0, "'ocp $group quatsch --help' exits non-zero");
        like($out, qr/Unknown command 'quatsch' for 'ocp $group'/,
            "'ocp $group quatsch' names the group it belongs to");
    }
}

# ... and known input keeps behaving exactly as before
{
    my (undef, $help_rc) = ocp('--help');
    is($help_rc, 0, "'ocp --help' still exits 0");

    my ($out, $rc) = ocp();
    isnt($rc, 0, 'bare ocp is still a usage error');
    like($out, qr/Usage: ocp <command>/, 'bare ocp still prints the root usage');
}

# A root option and its value must not be mistaken for the command word
{
    my ($out) = ocp('--config', 'nope.yaml', 'status');
    like($out, qr/Config file 'nope\.yaml' not found/,
        'command after --config VALUE is still found');

    my ($aliased) = ocp('-v', 'deploy-image');
    unlike($aliased, qr/Unknown command/,
        'hyphenated alias is resolved even behind an option');
}

done_testing;

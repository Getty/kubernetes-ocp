#!/usr/bin/env perl
# karr k216 (lab 2026-10-18) -- `ocp keys operator add --name ... --ssh-pubkey
# ... --age ...` died "usage: ..." for every spelling, before anything else.
#
# MooX::Cmd hands a leaf command's execute the command line exactly as typed,
# options and their values included: MooX::Options parses a protected copy of
# @ARGV and leaves the vector alone. So `if @$args` is true whenever any option
# was given, and `$args->[0]` is the first OPTION when an option comes first.
# t/216-operator.t built the command with ->new and argv => [], and never saw it.
#
# The claims, each through the real command-line parsing (OCP->run_cli with
# @ARGV, the path bin/ocp takes), in a directory with no project:
#
#   * `keys operator add` with --name/--ssh-pubkey/--age, dashed and
#     underscored, --opt value and --opt=value, gets past the usage check to
#     the next step (no ocp.yaml); a genuinely stray word is still the usage
#     error
#   * `keys operator rm`, `keys recipients add|rm`, `provider rm` take their
#     positional argument behind an option (--pins-stdin NAME), and
#     `node add --role worker NAME` names the node NAME, not '--role'
#   * OCP::Role::Cmd::positional_args, the one place that tells options from
#     positional words: values of options that take one, --opt=value,
#     abbreviations, short options and everything after `--`

use strict;
use warnings;
use Test::More;

use Cwd qw( getcwd );
use Crypt::Age::Keys;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::Cmd::Keys::Operator::Add;
use OCP::Cmd::Node::Add;
use OCP::Cmd::Provider::Rm;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{OCP_OPERATOR_KEY};

my $dir  = tempdir(CLEANUP => 1);
my $orig = getcwd();
chdir $dir or die "chdir $dir: $!";
END { chdir $orig if defined $orig }

my $pub = path($dir, 'leitstand.pub');
$pub->spew("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJtVGsH8F4q91cnc+Q4tdQgQZce+oMFw2A9km8JcUGw9 leitstand\n");

my ($age) = Crypt::Age::Keys->generate_keypair;
like $age, qr/\Aage1/, 'a real age recipient for the fixtures';

# What run_cli makes of argv: (exit code, stderr).
sub cli {
    my (@argv) = @_;
    my $stderr = '';
    my $code;
    {
        local @ARGV = @argv;
        local *STDERR;
        open STDERR, '>', \$stderr or die "stderr: $!";
        local *STDOUT;
        my $stdout = '';
        open STDOUT, '>', \$stdout or die "stdout: $!";
        $code = OCP->run_cli;
    }
    return ($code, $stderr);
}

my $no_project = qr/Config file '[^']*ocp\.yaml' not found/;

# --- keys operator add ----------------------------------------------------

my @add_spellings = (
    [ 'dashed',      '--name', 'leitstand', '--ssh-pubkey', "$pub", '--age', $age ],
    [ 'underscored', '--name', 'leitstand', '--ssh_pubkey', "$pub", '--age', $age ],
    [ '--opt=value', '--name=leitstand', "--ssh-pubkey=$pub", "--age=$age" ],
    [ 'reordered, with --pins-stdin', '--pins-stdin', "--age", $age, '--ssh-pubkey', "$pub", '--name', 'leitstand' ],
);

for my $case (@add_spellings) {
    my ($label, @opts) = @$case;
    my ($code, $err) = cli(qw(keys operator add), @opts);
    is $code, 1, "operator add ($label): fails, as there is no project";
    unlike $err, qr/usage:/, "operator add ($label): not the usage error";
    like $err, $no_project, "operator add ($label): it got to the project";
}

{
    my ($code, $err) = cli(qw(keys operator add leitstand),
        '--name', 'leitstand', '--ssh-pubkey', "$pub", '--age', $age);
    is $code, 1, 'operator add with a stray word: exit 1';
    like $err, qr/usage: ocp keys operator add --name NAME/, '... the usage error';
}

{
    my ($code, $err) = cli(qw(keys operator add),
        '--name', 'leitstand', '--ssh-pubkey', "$pub", '--age', $age, '--', 'extra');
    like $err, qr/usage: ocp keys operator add/, 'a word after -- is positional too';
}

# --- keys operator rm -----------------------------------------------------

for my $argv ([qw(--pins-stdin leitstand)], [qw(leitstand --pins-stdin)], [qw(leitstand)]) {
    my ($code, $err) = cli(qw(keys operator rm), @$argv);
    unlike $err, qr/usage:/, "operator rm @$argv: not the usage error";
    like $err, $no_project, "operator rm @$argv: it got to the project";
}

{
    my ($code, $err) = cli(qw(keys operator rm --pins-stdin a b));
    like $err, qr/usage: ocp keys operator rm/, 'operator rm with two names: usage';
}

# --- keys recipients add|rm -----------------------------------------------

for my $verb (qw(add rm)) {
    my ($code, $err) = cli(qw(keys recipients), $verb, '--pins-stdin', $age);
    unlike $err, qr/Not an age recipient/, "recipients $verb --pins-stdin AGE: the recipient is AGE";
    unlike $err, qr/usage:/, "recipients $verb --pins-stdin AGE: not the usage error";
}

# --- node add, provider rm ------------------------------------------------

{
    no warnings 'redefine';
    local *OCP::Cmd::Node::Add::_k8s = sub { die "STOP node=" . $_[0]->name . "\n" };
    my ($code, $err) = cli(qw(node add --role worker w1));
    like $err, qr/STOP node=w1$/m, 'node add --role worker w1: the node is w1';
}

{
    no warnings 'redefine';
    local *OCP::Cmd::Provider::Rm::_k8s        = sub { bless {}, 'FakeApi' };
    local *OCP::Cmd::Provider::Rm::provider_cr = sub { die "STOP provider=$_[2]\n" };
    my ($code, $err) = cli(qw(provider rm --pins-stdin p1));
    like $err, qr/STOP provider=p1$/m, 'provider rm --pins-stdin p1: the provider is p1';
}

# --- positional_args ------------------------------------------------------

{
    my $cmd = do { local @ARGV = (); OCP::Cmd::Node::Add->new };
    my @cases = (
        [ [qw(--role worker w1)],              [qw(w1)],        'value of a valued option' ],
        [ [qw(w1 --role worker)],              [qw(w1)],        'positional first' ],
        [ [qw(--role=worker w1)],              [qw(w1)],        '--opt=value carries its own' ],
        [ [qw(--server-type cx22 w1)],         [qw(w1)],        'dashed valued option' ],
        [ [qw(--server_type cx22 w1)],         [qw(w1)],        'underscored valued option' ],
        [ [qw(--ro worker w1)],                [qw(w1)],        'an abbreviation, as Getopt reads it' ],
        [ [qw(--nowait --pins-stdin w1)],      [qw(w1)],        'booleans take no value' ],
        [ [qw(--label a=b --label c=d w1)],    [qw(w1)],        'a repeatable option' ],
        [ [qw(w1 -- --role x)],                [qw(w1 --role x)], 'everything after -- is positional' ],
        [ [qw(a b)],                           [qw(a b)],       'only positional words' ],
        [ [],                                  [],              'nothing' ],
    );
    for my $c (@cases) {
        my ($in, $want, $label) = @$c;
        is_deeply [ $cmd->positional_args($in) ], $want, "positional_args: $label";
    }
    is_deeply [ $cmd->positional_args(undef) ], [], 'positional_args: undef';
}

{
    local @ARGV = ();
    require OCP::Cmd::Kubeconfig;
    my $cmd = OCP::Cmd::Kubeconfig->new;
    is_deeply [ $cmd->positional_args([qw(-o out.yaml x)]) ], [qw(x)],
        'positional_args: a short option that takes a value';
    is_deeply [ $cmd->positional_args([qw(-e x)]) ], [qw(x)],
        'positional_args: a short boolean';
}

done_testing;

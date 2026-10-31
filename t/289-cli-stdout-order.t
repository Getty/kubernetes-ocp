#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use FindBin;

# k289: bin/ocp never set autoflush on STDOUT. On a terminal STDOUT is
# line-buffered and the order held, but into a pipe or a file it is
# block-buffered while STDERR is not, so `ocp apply > log 2>&1` -- CI, a
# container log, our own live runs -- had every [!!] line ahead of the
# progress it belongs to. The claim: with both channels in one pipe, a line
# appears where it was printed, whichever channel it went to.
#
# `ocp init --hetzner` without a token is the run: progress on STDOUT, the
# token prompt and "[!!] No token provided" on STDERR, then progress on STDOUT
# again -- offline, and with --pins-stdin the prompt reads an empty line from
# STDIN instead of the terminal.

my $BIN = "$FindBin::Bin/../bin/ocp";
my $LIB = "$FindBin::Bin/../lib";

plan skip_all => 'needs ssh-keygen' unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

# Run `ocp init` in a fresh directory with STDOUT on a pipe. $stderr is the
# shell redirection for STDERR: '2>&1' puts it into that same pipe.
sub run_init {
    my ($stderr) = @_;
    my $dir   = path(tempdir(CLEANUP => 1));
    my $input = $dir->child('stdin');
    $input->spew("\n");    # the token prompt: no token

    local $ENV{HETZNER_API_TOKEN} = '';
    my $out = `cd '$dir' && $^X -I'$LIB' '$BIN' init --nopassword --nogit --hetzner --pins-stdin --name order < '$input' $stderr`;
    return ($? >> 8, $out);
}

# Where a line starts in $text; -1 when it is not there.
sub at {
    my ($text, $line) = @_;
    return index $text, $line;
}

my @STDOUT_BEFORE = ('[ok] Generated SSH bootstrap key', 'Hetzner Cloud API Token required.');
my @STDERR_LINES  = ('Enter Hetzner API token: ', "[!!] No token provided. Run 'ocp init --hetzner' again.");
my @STDOUT_AFTER  = ('[..] Creating ocp.yaml', 'OCP project initialized: order');

subtest 'the lines this test orders are on the channels it says' => sub {
    my ($rc, $out) = run_init('2>/dev/null');
    is $rc, 0, 'init succeeded' or diag $out;
    cmp_ok at($out, $_), '>=', 0, "STDOUT has '$_'" for @STDOUT_BEFORE, @STDOUT_AFTER;
    is at($out, $_), -1, "STDOUT does not have '$_'" for @STDERR_LINES;
};

subtest 'STDOUT and STDERR in one pipe keep the order they were printed in' => sub {
    my ($rc, $out) = run_init('2>&1');
    is $rc, 0, 'init succeeded' or diag $out;

    my @order = (@STDOUT_BEFORE, @STDERR_LINES, @STDOUT_AFTER);
    for my $i (1 .. $#order) {
        my ($before, $after) = @order[$i - 1, $i];
        cmp_ok at($out, $before), '<', at($out, $after), "'$before' comes before '$after'"
            or diag $out;
    }
    cmp_ok at($out, $order[0]), '>=', 0, "'$order[0]' is there at all";
};

done_testing;

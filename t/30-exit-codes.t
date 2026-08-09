#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# OCP::run_cli turns whatever execute() returns into the process exit code.
# Perl returns the last evaluated expression, and print() evaluates to 1 — so a
# command ending in a print reported success as exit 1.
#
# `ocp apply` and `ocp destroy` both did. Nothing caught it because the runs
# were piped, and the shell reports the exit code of the last command in a
# pipeline, not of ocp.
#

my $lib = path(__FILE__)->parent->parent->child('lib', 'OCP', 'Cmd');
ok -d $lib, 'command directory exists' or done_testing, exit;

my @commands = sort { "$a" cmp "$b" } grep { !/Role/ } $lib->children(qr/\.pm$/);
push @commands, sort { "$a" cmp "$b" }
    map  { $_->children(qr/\.pm$/) }
    grep { $_->is_dir } $lib->children;

ok scalar(@commands), 'found command classes';

for my $file (@commands) {
    my $name = $file->relative($lib->parent->parent->parent)->stringify;
    my $src  = $file->slurp_utf8;

    my ($body) = $src =~ /^sub execute \{\n(.*?)\n\}$/ms;
    unless (defined $body) {
        pass "$name has no execute()";
        next;
    }

    # Strip comments and blank lines, then look at the final statement.
    my @lines = grep { /\S/ && !m{^\s*#} } split /\n/, $body;
    my $last  = $lines[-1] // '';
    $last =~ s/^\s+|\s+$//g;

    # Ending in die() is a deliberate failure path (e.g. "subcommand required").
    next if $last =~ /^die\b/;

    # A closing brace is fine — the statement before it decides, and an
    # if/else whose branches all return is correct (see Node/Add.pm).
    next if $last eq '}';

    # What must never end execute(): an expression whose value silently
    # becomes the exit code. print/printf/say all evaluate to 1.
    unlike $last, qr/^(?:print|printf|say)\b/,
        "$name does not end execute() with a print — that returns 1";

    like $last, qr/^return\b/,
        "$name ends execute() with an explicit return";
}

subtest 'every execute() has at least one return or die' => sub {
    for my $file (@commands) {
        my $name = $file->basename;
        my $src  = $file->slurp_utf8;
        my ($body) = $src =~ /^sub execute \{\n(.*?)\n\}$/ms;
        next unless defined $body;

        like $body, qr/^\s*(?:return\b|die\b)/m,
            "$name states its outcome somewhere in execute()";
    }
};

subtest 'a trailing print really would return 1' => sub {
    # The mechanism, pinned so the reason for the rule stays visible.
    my $value = do { open my $null, '>', '/dev/null' or die; print {$null} "x" };
    is $value, 1, 'print() evaluates to 1, which run_cli would use as exit code';
};

done_testing;

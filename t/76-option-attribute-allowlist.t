#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# karr #73 — `is_bool => 1` is not a MooX::Options attribute and was
# silently dropped by _filter_attributes. Three sites carried it
# (Provider::Add `default`, Node::Add `gpu`, Node::Add `nowait`) and
# they were harmless today only because they are positive-only flags
# without a default. The moment anyone copies the pattern or adds a
# `default => 1`, the typo-trap snaps shut: MooX::Options will keep
# ignoring the key and the documented `--no-...` will not exist.
#
# This test is the real value of the ticket. It does not rely on
# MooX::Options' own internals — it reads the source and asserts that
# every key inside `option(...)` blocks is one MooX::Options or Moo
# actually understands. A typo or an invented key fails here before it
# can fail in production.
#

# The allow-list, two sources and one place that explains where each came
# from. MooX::Options exposes @OPTIONS_ATTRIBUTES — the keys it strips from
# the option hash before forwarding the rest to `has`. Everything else is a
# standard Moo attribute key.
my @MOOX_OPTIONS = qw(
    format short repeatable negatable autosplit autorange
    doc long_doc order json hidden spacer_before spacer_after
);

# `negativable` is the Getopt::Long-spelled alias MooX::Options also
# strips — same role, different name. Not used in this repo today; listed
# so it does not fail the test the day someone copies it from a tutorial.
my @MOOX_OPTIONS_ALIASES = qw(negativable);

# Standard Moo attribute keys (see Moo::Attribute constructors). The repo
# uses is/default/format/doc/short/negatable/required in option blocks
# today; the wider set is listed so new keys land allowed, not silently.
my @MOO = qw(
    is default required lazy isa coerce predicate init_arg
    builder clearer trigger documentation
    reader writer accessor weak_ref handles does depends
);

my %ALLOWED = map { $_ => 1 } @MOOX_OPTIONS, @MOOX_OPTIONS_ALIASES, @MOO;

# Walk every option(...) block in the source and report its keys.
# The block starts at `option NAME => (` and ends at the matching `)`,
# skipping string content and `#` comments so a quoted `=>` inside a
# doc string does not become a key.
sub option_blocks {
    my ($source) = @_;
    my @blocks;

    my $pos = 0;
    while ($pos < length $source) {
        my $rest = substr $source, $pos;
        if ($rest =~ /\Goption\s+(\w+)\s*=>\s*\(/cg) {
            my $name = $1;
            my $local_end = pos($rest) // 0;     # end of `(...` open, relative to $rest
            my $open_abs  = $pos + $local_end - 1;
            my $b_end     = _find_matching_paren($source, $open_abs);
            last unless defined $b_end;

            my $b_start = $pos + (index($rest, 'option') // 0);
            my $block = substr($source, $b_start, $b_end - $b_start + 1);
            push @blocks, { name => $name, block => $block };

            $pos = $b_end + 1;
        }
        else {
            $pos++;
        }
    }

    return @blocks;
}

sub _find_matching_paren {
    my ($source, $open_pos) = @_;

    my $depth  = 0;
    my $in_str;
    my $p = $open_pos;
    while ($p < length $source) {
        my $c = substr $source, $p, 1;
        if ($in_str) {
            if    ($c eq '\\')   { $p += 2; next; }
            elsif ($c eq $in_str) { $in_str = undef; }
            $p++;
            next;
        }
        if ($c eq "'" || $c eq '"') { $in_str = $c; $p++; next; }
        if ($c eq '#') {
            while ($p < length $source && substr($source, $p, 1) ne "\n") {
                $p++;
            }
            next;
        }
        if    ($c eq '(') { $depth++; }
        elsif ($c eq ')') {
            $depth--;
            return $p if $depth == 0;
        }
        $p++;
    }
    return undef;
}

# Within one block, every top-level `key =>` line is an attribute key.
# Continuation lines like `    . 'more text'` do not start with `key =>`
# and are correctly skipped. String content was already excluded when
# the block was extracted.
sub keys_in_block {
    my ($block) = @_;
    my @keys;
    for my $line (split /\n/, $block) {
        next unless $line =~ /^\s*(\w+)\s*=>\s*\S/;
        push @keys, $1;
    }
    return @keys;
}

# ---------------------------------------------------------------------------
# 1. The allow-list itself stays in sync with MooX::Options' source.
# ---------------------------------------------------------------------------

subtest 'the allow-list tracks MooX::Options @OPTIONS_ATTRIBUTES' => sub {
    # Reading the source is the only way to be sure — VERSION numbers
    # drift, the array literal does not. Anything not in the array is
    # forwarded to Moo and quietly ignored (karr #73, what `is_bool`
    # proved).
    require MooX::Options;
    my $moox_file = $INC{'MooX/Options.pm'};
    ok -f $moox_file, 'MooX::Options is loaded and its source is readable';

    open my $fh, '<', $moox_file or die "open $moox_file: $!";
    my $src = do { local $/; <$fh> };
    close $fh;

    my ($lit) = $src =~ /my\s+\@OPTIONS_ATTRIBUTES\s*=\s*qw\/([^\/]*)\//s;
    ok $lit, '@OPTIONS_ATTRIBUTES is a qw/.../ literal in MooX::Options';
    my @moox = grep { length } split /\s+/, $lit;

    # Every MooX::Options key the repo allows must be in the source.
    # Anything in the source that is NOT in our allow-list is a real
    # gap to fix here.
    my %moox_set = map { $_ => 1 } @moox;
    my @missing_from_us = grep { !$ALLOWED{$_} } @moox;
    my @moox_missing    = grep { !$moox_set{$_} } @MOOX_OPTIONS;

    is_deeply \@missing_from_us, [],
        'every key MooX::Options lists is in our allow-list';
    is_deeply \@moox_missing, [],
        'and our MooX::Options keys are all real ones (no invented ones)';
};

# ---------------------------------------------------------------------------
# 2. Every option block in the repo uses only allowed keys.
# ---------------------------------------------------------------------------

subtest 'every option() key in lib/OCP/Cmd/ is one MooX::Options or Moo understands' => sub {
    my $state = { files => [] };
    path('lib/OCP/Cmd')->visit(sub {
        my ($p) = @_;
        push @{$state->{files}}, $p->stringify
            if $p->is_file && $p->stringify =~ /\.pm\z/;
    }, { recurse => 1 });
    my @files = sort @{$state->{files}};

    ok @files, 'found .pm files under lib/OCP/Cmd/';

    my @bad;   # [ file, option_name, key, line ]
    my @seen;  # (file, option) for the summary line below

    for my $file (@files) {
        my $src = path($file)->slurp_raw;
        for my $blk (option_blocks($src)) {
            my $name = $blk->{name};
            push @seen, "$file: option $name";

            my @block_lines = split /\n/, $blk->{block};
            for my $i (0 .. $#block_lines) {
                my $line = $block_lines[$i];
                next unless $line =~ /^\s*(\w+)\s*=>\s*\S/;
                my $key = $1;
                next if $ALLOWED{$key};
                push @bad, [$file, $name, $key, $i + 1];
            }
        }
    }

    is scalar(@bad), 0,
        'no option() block carries a key outside the allow-list'
        or do {
            diag '';
            diag "Offending blocks:";
            for my $row (@bad) {
                diag "  $row->[0]: option $row->[1] — '$row->[2]' at line $row->[3]";
            }
        };

    ok scalar(@seen), 'at least one option() block was inspected'
        or diag "no option() blocks found in:\n  " . join("\n  ", @files);
};

# ---------------------------------------------------------------------------
# 3. The known phantom keys from karr #73 are gone.
# ---------------------------------------------------------------------------

subtest 'the three phantom is_bool sites from karr #73 are gone' => sub {
    for my $file (
        'lib/OCP/Cmd/Provider/Add.pm',
        'lib/OCP/Cmd/Node/Add.pm',
    ) {
        my $src = path($file)->slurp_raw;

        # option() blocks: is_bool inside one of them is the trap.
        my $in_block_hit = 0;
        for my $blk (option_blocks($src)) {
            $in_block_hit++ if grep { $_ eq 'is_bool' } keys_in_block($blk->{block});
        }

        # The literal string may legitimately appear in POD or comments
        # (DeployImage.pm comments on what `is_bool` used to mean).
        ok !$in_block_hit,
            "$file: no option(...) block carries is_bool"
            or diag "Found $in_block_hit occurrence(s) in option() blocks";
    }
};

done_testing;
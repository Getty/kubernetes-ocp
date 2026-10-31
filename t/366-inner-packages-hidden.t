#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Module::Metadata ();
use Path::Tiny qw(path);

#
# k366: Dist::Zilla's MetaProvides::Package reads every lib/*.pm with
# Module::Metadata->packages_inside and puts each package it finds into the
# META provides map. A package that has no .pm of its own (an inner class a
# module defines for itself) then fails at install time: "1 provide map
# entries did not map to .pm files and may not be loadable". k317 kept
# OCP::SSH::HostKeyChanged and the JSON::PP::Boolean wrapper in OCP::BooleanEq
# out of the map by declaring them as `package` + comment + newline + name,
# which Module::Metadata does not read as a declaration. The claims:
#   1. the scanner flags a plainly declared inner package and passes the
#      hidden form (so the test below can fail at all);
#   2. every lib/**/*.pm yields exactly its own package, or only packages
#      on the allow-list below, each with a reason.
#

# file (relative to lib/) => { package => reason it may stay in the index }.
# Empty on purpose: a package on this list is indexed, and must have a .pm.
my %ALLOWED = ();

sub pm_files {
    my ($lib) = @_;
    my @pm;
    $lib->visit(sub { push @pm, $_ if $_->is_file && /\.pm\z/ }, { recurse => 1 });
    return sort { "$a" cmp "$b" } @pm;
}

# [ file, package ] for each package of a file that is neither the file's own
# (from its path under $lib) nor allowed.
sub stray_packages {
    my ($lib) = @_;
    my @stray;
    for my $file (pm_files($lib)) {
        my $rel = $file->relative($lib)->stringify;
        (my $own = $rel) =~ s{\.pm\z}{};
        $own =~ s{/}{::}g;
        for my $pkg (Module::Metadata->new_from_file("$file", collect_pod => 0)->packages_inside) {
            next if $pkg eq $own;
            next if $ALLOWED{$rel} && $ALLOWED{$rel}{$pkg};
            push @stray, [ $rel, $pkg ];
        }
    }
    return @stray;
}

# --- claim 1: the scanner can fail --------------------------------------

my $fix = path(tempdir(CLEANUP => 1));
$fix->child('Fx')->mkpath;
$fix->child('Fx', 'Plain.pm')->spew(
    "package Fx::Plain;\n1;\n\npackage Fx::Plain::Inner;\nsub x { 1 }\n1;\n");
$fix->child('Fx', 'Hidden.pm')->spew(
    "package Fx::Hidden;\n1;\n\n{\n    package    # inner, hidden from the indexer\n      Fx::Hidden::Inner;\n    sub x { 1 }\n}\n1;\n");
$fix->child('Fx', 'Own.pm')->spew("package Fx::Own;\n1;\n");

is_deeply(
    [ stray_packages($fix) ],
    [ [ 'Fx/Plain.pm', 'Fx::Plain::Inner' ] ],
    'scanner flags only the plainly declared inner package, not the hidden form or own packages',
);

# --- claim 2: the real lib/ ----------------------------------------------

my $lib = path('lib')->absolute;
cmp_ok(scalar(() = pm_files($lib)), '>', 50, 'found the modules under lib/');

my @stray = map { $_->[0].': '.$_->[1] } stray_packages($lib);
is_deeply(\@stray, [],
    'every package Module::Metadata finds in lib/ is its file\'s own, or allowed')
    or diag 'declare an inner package as "package # why hidden" + newline + name, '
        .'or add it to %ALLOWED with a reason';

done_testing;

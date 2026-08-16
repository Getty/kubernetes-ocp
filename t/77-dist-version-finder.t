#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# 4aa92cf claimed "drop per-module $VERSION, keep it single-sourced in OCP.pm"
# by removing the `our $VERSION = '0.001';` line from every .pm file under
# lib/. The claim was only true in the repo: PkgVersion's default finders
# include every file with a package statement, so dzil build re-inserted the
# $VERSION line into all 55 modules behind the user's back.
#
# The fix lives in dist.ini: `version_finder = :MainModule` + `:ExecFiles`
# restricts PkgVersion and RewriteVersion::Transitional to lib/OCP.pm and the
# bin/ scripts. bin/ocp and bin/robocop keep their $VERSION line because the
# lookup is anchored there (the line is otherwise unconsumed — bin/ocp reports
# $OCP::VERSION, not its own $VERSION), but no other .pm file gets one back.
#
# If anyone reverts the dist.ini setting, the next `dzil build` would silently
# re-insert $VERSION into the 55 modules and the single-source claim would be
# a lie again. The assertions here keep that from happening unnoticed.
#

my $root   = path(__FILE__)->parent->parent;
my $dist_ini = $root->child('dist.ini');

subtest 'dist.ini configures version_finder' => sub {
    ok -f $dist_ini, 'dist.ini exists';

    my $ini = $dist_ini->slurp_utf8;

    # The Author::GETTY bundle reads version_finder from its own payload
    # (lines 326-331 of PluginBundle/Author/GETTY) and forwards it to
    # PkgVersion, RewriteVersion::Transitional and BumpVersionAfterRelease.
    # There is no implicit :MainModule default — `no_cpan = 1` does not
    # change that. Without an explicit value, the rewriters fall back to
    # [':InstallModules', ':ExecFiles'] and silently re-insert $VERSION
    # into every .pm file at build time.
    my $bundle_marker = '[@Author::GETTY]';
    ok index($ini, $bundle_marker) >= 0,
        'the @Author::GETTY bundle is in use';

    my @finder_lines = $ini =~ /^\s*version_finder\s*=\s*(\S+)\s*$/mg;
    ok scalar @finder_lines, 'version_finder is set (no implicit default)';

    my %finder = map { $_ => 1 } @finder_lines;
    ok $finder{':MainModule'}, 'version_finder includes :MainModule (so PkgVersion only touches lib/OCP.pm)';
    ok $finder{':ExecFiles'},  'version_finder includes :ExecFiles (so RewriteVersion still stamps bin/ocp and bin/robocop)';
};

subtest 'lib/OCP.pm is the only source module that carries $VERSION' => sub {
    my $ocp = $root->child('lib/OCP.pm');
    ok -f $ocp, 'lib/OCP.pm exists';

    my $src = $ocp->slurp_utf8;
    like $src, qr/^\s*our\s+\$VERSION\s*=\s*['"]0\.001['"]\s*;/m,
        'lib/OCP.pm carries the single-sourced $VERSION';
};

subtest 'no other .pm file under lib/ carries $VERSION' => sub {
    my @pm_files;
    $root->child('lib')->visit(
        sub {
            push @pm_files, $_[0] if $_[0]->is_file && $_[0]->basename =~ /\.pm$/;
        },
        { recurse => 1 },
    );

    @pm_files = grep { $_->basename ne 'OCP.pm' }
                sort { $a->stringify cmp $b->stringify }
                @pm_files;

    my @with_version;
    for my $file (@pm_files) {
        my $src = $file->slurp_utf8;
        next unless $src =~ /^\s*our\s+\$VERSION\s*=\s*['"][^'"]+['"]\s*;/m;
        push @with_version, $file->relative($root)->stringify;
    }

    is_deeply \@with_version, [],
        'every .pm under lib/ other than OCP.pm is $VERSION-less in the source'
        or diag "Found \$VERSION in: @with_version";
};

subtest 'bin/ocp and bin/robocop keep their $VERSION anchor' => sub {
    # These are the only two files under bin/. RewriteVersion::Transitional
    # rewrites the matching line at build time, sourcing the version from
    # lib/OCP.pm. Removing the line would leave the rewriter with nothing to
    # match (PkgVersion would skip these files anyway — they have no package
    # statement) and the built bin/ocp would ship versionless.
    for my $bin (qw( bin/ocp bin/robocop )) {
        my $src = $root->child($bin)->slurp_utf8;
        like $src, qr/^\s*our\s+\$VERSION\s*=\s*['"][^'"]+['"]\s*;/m,
            "$bin still carries an anchor for the rewriter";
    }
};

done_testing;

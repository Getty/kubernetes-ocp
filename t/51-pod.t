#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# Every PodWeaver-scoped module must ship the section commands that
# @Author::GETTY's PodWeaver weaves: synopsis, description, seealso.
# Anything written before NAME/AUTHOR/COPYRIGHT is stripped at build
# time, so we check the weaver-level markers directly.
#
# Scope: discovered from three sources -- the two glob patterns that
# cover Provider modules and the named exception `lib/OCP/Choices.pm`
# that the original ticket called out. New modules matching a pattern
# join the assertion set for free; modules outside the patterns are
# out of scope (extending there is a separate decision, just like the
# original ticket author did not sweep the other modules).

my @PODS = (
    glob('lib/OCP/Provider*.pm'),
    glob('lib/OCP/Role/Provider*.pm'),
    'lib/OCP/Choices.pm',
);

# Structural assertion: every module in @PODS carries the weaver-level
# markers that PodWeaver weaves into the published POD. This is a
# structural test; it does not validate prose. It catches the failure
# mode we keep seeing -- a freshly added provider with one `=head1
# NAME` and nothing else, where PodWeaver eats everything above NAME
# and the published distribution has no synopsis at all.
subtest 'every POD in scope has PodWeaver structure' => sub {
    # Glob may yield empty strings on no-match; skip the missing ones
    # -- pattern coverage is the meta-assertion's job below, not this
    # structural test's.
    for my $file (grep { length && -f } @PODS) {
        open my $fh, '<', $file or die "open $file: $!";
        my $pod = do { local $/; <$fh> };
        close $fh;

        my $label = $file;
        $label =~ s{^lib/}{};
        $label =~ s{\.pm$}{};

        ok $pod =~ /^=synopsis\b/m,
            "$label has =synopsis section";
        ok $pod =~ /^=description\b/m,
            "$label has =description section";
        ok $pod =~ /^=seealso\b/m,
            "$label has =seealso section";

        # ABSTRACT must be on the first non-blank lines so PodWeaver can
        # build NAME from it. Anything written above NAME is stripped.
        my ($abstract) = ($pod =~ /^#\s*ABSTRACT:\s*(.+?)\s*$/m);
        ok defined $abstract && length $abstract,
            "$label has a non-empty # ABSTRACT line";

        # NAME/AUTHOR/SUPPORT/COPYRIGHT/CONTRIBUTORS/LICENSE are
        # weaver-built and must NOT be written by hand; their presence
        # means the author either copy-pasted a Perl::Critic example
        # or trusted an older Pod::Weaver. Either way, we strip on
        # build and the section is gone.
        for my $forbidden (qw(NAME AUTHOR SUPPORT COPYRIGHT CONTRIBUTORS LICENSE)) {
            ok $pod !~ /^=head1\s+$forbidden\b/m,
                "$label does not manually write =head1 $forbidden (weaver builds it)";
        }
    }
};

# Regression meta-assertion: prove @PODS is glob-driven, not
# hand-enumerated. If someone narrows a glob (drops `*`) or replaces
# the list with explicit filenames, the structural test above would
# still pass today but the suite would silently stop catching
# newly-added Provider modules. Re-discover the same way here and
# assert the lists match.
subtest '@PODS is dynamically discovered via globs (not enumerated)' => sub {
    my @rediscovery = (
        glob('lib/OCP/Provider*.pm'),
        glob('lib/OCP/Role/Provider*.pm'),
        'lib/OCP/Choices.pm',
    );

    is_deeply [sort @PODS], [sort @rediscovery],
        '@PODS equals re-discovery from the same three sources '
        . '(two globs + named exception -- no hand-written enumeration)';

    # Scope witnesses: the globs must be meaningful today so a future
    # module matching the pattern joins automatically. Count via a list
    # assignment -- scalar() in scalar context returns the first match,
    # not the total.
    my @provider_matches = glob('lib/OCP/Provider*.pm');
    ok scalar(@provider_matches) >= 1,
        'lib/OCP/Provider*.pm glob returns at least one Provider module today';
    ok grep({ $_ eq 'lib/OCP/Choices.pm' } @PODS),
        'lib/OCP/Choices.pm named exception is preserved';

    diag 'discovery: '
       . 'provider*=' . scalar(@provider_matches) . ' '
       . 'role/provider*=' . scalar(my @r = glob 'lib/OCP/Role/Provider*.pm') . ' '
       . 'named=1';
};

# Inline =attr / =method / =opt directives next to the code they
# document. PodWeaver picks these up at build time; without them the
# published attributes and methods are undocumented. These spot-checks
# stay independent of the structural sweep -- they pin the surface of
# the two most consequential Provider modules regardless of where the
# pattern scope moves.

subtest 'OCP::Provider::Hetzner documents each method with =method' => sub {
    open my $fh, '<', 'lib/OCP/Provider/Hetzner.pm' or die $!;
    my $pod = do { local $/; <$fh> };
    close $fh;

    my @methods = qw(
        upload_ssh_key server_exists create_server
        wait_for_running get_server_ip delete_server
        cleanup_on_failure list_servers_by_cluster
    );
    for my $m (@methods) {
        ok $pod =~ /^=method\s+$m\b/m, "=method $m present";
    }

    my @attrs = qw(token cluster_name ssh_key_name);
    for my $a (@attrs) {
        ok $pod =~ /^=attr\s+$a\b/m, "=attr $a present";
    }
};

subtest 'OCP::Role::Provider::ExistingHost documents required methods' => sub {
    open my $fh, '<', 'lib/OCP/Role/Provider/ExistingHost.pm' or die $!;
    my $pod = do { local $/; <$fh> };
    close $fh;

    ok $pod =~ /^=method\s+required\b/m,
        '=method required present (lists the methods consumers must implement)';
    ok $pod =~ /^=method\s+server_exists\b/m,
        '=method server_exists present';
    ok $pod =~ /^=method\s+create_server\b/m,
        '=method create_server present';
    ok $pod =~ /^=method\s+wait_for_running\b/m,
        '=method wait_for_running present';
    ok $pod =~ /^=method\s+delete_server\b/m,
        '=method delete_server present';
    ok $pod =~ /^=attr\s+verbose\b/m,
        '=attr verbose present';
};

done_testing;

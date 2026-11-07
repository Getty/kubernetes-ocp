#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use FindBin;
use Path::Tiny qw( path );
use YAML::XS ();

BEGIN { $ENV{ANSI_COLORS_DISABLED} = 1 }

use lib 'lib';
use OCP;
use OCP::Config;

#
# k394: registry: and ssl: took any key. validate() checked their shape only
# (k379), so a typo -- ssl: { emial: ... }, registry: { cahce: ... } -- passed,
# and its default stayed in force: no Let's Encrypt issuers, docker.io through
# the built-in ocp-cache. Every other section says such a key in a line of its
# own (system:, gpu:, kubernetes:, network:, cilium:, robocop:, ssh:).
#
# The claims here:
#   1. a key of registry: or ssl: that is none of the keys read there is one
#      line of validate(), naming the section and the key, in the words of the
#      other sections' unknown-key lines: the keys it must be, in the order the
#      shape line names them;
#   2. every key read there -- registry.cache, registry.upstream, registry.name
#      (OCP::Config registry_cache, registry_upstream, registry_name) and
#      ssl.email (ssl_email), the keys docs/configuration.md documents -- has
#      no such line, set one by one, all together, or as the documentation
#      writes them;
#   3. neither section has a nested mapping: a mapping at a key read there is
#      that key's own string line, and none for the keys inside it;
#   4. the line is at the section's key path: spec_errors('registry') and
#      spec_errors('ssl') return it, in validate()'s order, and no other path
#      does;
#   5. every accessor that reads the section refuses on it in that line and a
#      newline, as registry_config and ssl_config refuse on every other line
#      of theirs (k379): validate() and the readers cannot disagree;
#   6. ocp apply --dry-run refuses an ocp.yaml carrying one, with the line on
#      STDERR and exit 1.
#

local @ARGV = ();
my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);
my $bin    = "$FindBin::Bin/../bin/ocp";
my $lib    = "$FindBin::Bin/../lib";

# Through a file, as ocp reads it, around a spec that passes on its own.
sub config_for {
    my ($spec) = @_;
    my $f = path($tmpdir)->child('c' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8(YAML::XS::Dump({ name => 'k394', control_planes => { provider => 'local' }, %$spec }));
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

# The keys read under each section, in the order the shape line names them.
my %KEYS = (
    registry => [ qw( cache upstream name ) ],
    ssl      => [ qw( email ) ],
);
my %MUST_BE = (
    registry => 'cache, upstream, or name',
    ssl      => 'email',
);

# Every accessor that reads the section.
my %READERS = (
    registry => [ qw( registry_config registry_cache registry_upstream registry_name
                      has_external_cache has_external_upstream ) ],
    ssl      => [ qw( ssl_config ssl_email ) ],
);

# Keys no reader reads: typos, another section's key, a case that is not the
# key's.
my %UNKNOWN = (
    registry => [ qw( cahce mirror upstreams Name email ) ],
    ssl      => [ qw( emial mail issuer staging name ) ],
);

# Every path spec_errors answers for, but registry and ssl themselves.
my @OTHER_PATHS = (qw( name kubernetes control_planes control_planes[*] network network.pod_cidr
                       network.lb_pool network.l2 cilium gpu system ssh lbipam nocert robocop
                       robocop.security_level robocop.image workers workers[*] ));

sub unknown_line { my ($section, $key) = @_; return "$section.$key: unknown key (must be $MUST_BE{$section})" }

is_deeply [ config_for({})->validate ], [], 'the fixture: the bare config passes';

# --- 1. an unknown key: one line ----------------------------------------------

for my $section (sort keys %KEYS) {
    subtest "$section: a key nothing reads is one line, naming the section and the key" => sub {
        for my $key (@{ $UNKNOWN{$section} }) {
            my $c = config_for({ $section => { $key => 'x' } });
            is_deeply [ $c->validate ], [ unknown_line($section, $key) ], "$section.$key";
        }

        # Beside the keys read: those pass, the unknown one is the line.
        my %set = map { $_ => "$_.k394.test" } @{ $KEYS{$section} };
        my $c = config_for({ $section => { %set, $UNKNOWN{$section}[0] => 'x' } });
        is_deeply [ $c->validate ], [ unknown_line($section, $UNKNOWN{$section}[0]) ],
            "$section: beside every key read, still the one line";

        # Several: one line each, sorted by key, after a key read that is no
        # string -- as under system:.
        my @many = sort @{ $UNKNOWN{$section} };
        $c = config_for({ $section => { $KEYS{$section}[0] => [ 'a' ], map { $_ => 1 } @many } });
        my @lines = $c->validate;
        is scalar(@lines), 1 + @many, "$section: the string line and one line per unknown key";
        like $lines[0], qr/\A\Q$section.$KEYS{$section}[0]\E: must be a string /, "$section: the string line first";
        is_deeply [ @lines[1 .. $#lines] ], [ map { unknown_line($section, $_) } @many ],
            "$section: then the unknown keys, sorted";
    };
}

subtest 'registry: and ssl: each with an unknown key: registry first, as validate() reads them' => sub {
    my $c = config_for({ registry => { cahce => 'x' }, ssl => { emial => 'x' } });
    is_deeply [ $c->validate ], [ unknown_line(registry => 'cahce'), unknown_line(ssl => 'emial') ],
        'both lines, in order';
};

# --- 2. every key read: no line -------------------------------------------------

for my $section (sort keys %KEYS) {
    subtest "$section: every key read passes and reads as set" => sub {
        for my $key (@{ $KEYS{$section} }) {
            my $c = config_for({ $section => { $key => "$key.k394.test" } });
            is_deeply [ $c->validate ], [], "$section.$key alone";
        }
        my %set = map { $_ => "$_.k394.test" } @{ $KEYS{$section} };
        my $c = config_for({ $section => \%set });
        is_deeply [ $c->validate ], [], "$section: all of them";
        is_deeply $c->${\ "${section}_config" }, \%set, "${section}_config reads them";
        is_deeply [ $c->spec_errors($section) ], [], "spec_errors('$section'): none";
    };
}

# The sections as docs/configuration.md writes them, empty strings included.
subtest 'registry: and ssl: as the documentation writes them' => sub {
    my $c = config_for({ ssl      => { email => 'admin@example.com' },
                         registry => { name => 'ocp.internal', cache => '', upstream => '' } });
    is_deeply [ $c->validate ], [], 'validate(): no line';
    is $c->ssl_email,     'admin@example.com', 'ssl_email';
    is $c->registry_name, 'ocp.internal',      'registry_name';
    ok !$c->has_external_cache && !$c->has_external_upstream, 'nothing external';
};

# --- 3. no nested mapping -------------------------------------------------------

for my $section (sort keys %KEYS) {
    subtest "$section: a mapping at a key read is that key's line, none for the keys inside" => sub {
        for my $key (@{ $KEYS{$section} }) {
            my $c = config_for({ $section => { $key => { cahce => 'x', emial => 'y' } } });
            my @lines = $c->validate;
            is scalar(@lines), 1, "$section.$key: one line";
            like $lines[0], qr/\A\Q$section.$key\E: must be a string \(.*\), not a mapping\z/,
                "$section.$key: the string line";
            unlike $lines[0], qr/unknown key/, "$section.$key: no unknown-key line for what is inside";
        }
    };
}

# --- 4. at the section's key path -----------------------------------------------

subtest "the line is at the section's path, and at no other" => sub {
    my $c = config_for({ registry => { cahce => 'x', cache => [ 'a' ] }, ssl => { emial => 'x' } });
    my @all = $c->validate;
    is scalar(@all), 3, 'validate(): three lines';
    is_deeply [ $c->spec_errors('registry') ], [ @all[0, 1] ], "spec_errors('registry'): registry's two";
    is_deeply [ $c->spec_errors('ssl') ],      [ $all[2] ],    "spec_errors('ssl'): ssl's";
    is_deeply [ $c->spec_errors('ssl', 'registry') ], \@all,   "both, asked backwards: in validate()'s order";
    is_deeply [ $c->spec_errors(@OTHER_PATHS) ], [],           'no other path has them';
};

# --- 5. every reader refuses on it ----------------------------------------------

for my $section (sort keys %KEYS) {
    subtest "$section: every reader refuses an unknown key in validate()'s line" => sub {
        my $key  = $UNKNOWN{$section}[0];
        my $line = unknown_line($section, $key);
        my %set  = map { $_ => "$_.k394.test" } @{ $KEYS{$section} };
        my $c = config_for({ $section => { %set, $key => 'x' } });
        for my $m (@{ $READERS{$section} }) {
            ok !eval { $c->$m; 1 }, "$m refuses";
            is $@, "$line\n", "$m: validate()'s line and a newline";
        }
        # And the other section's readers read on.
        my ($other) = grep { $_ ne $section } sort keys %KEYS;
        for my $m (@{ $READERS{$other} }) {
            ok eval { $c->$m; 1 }, "$m reads on" or diag $@;
        }
    };
}

# --- 6. through ocp apply --dry-run ----------------------------------------------

# Nothing reads registry: or ssl: before validate(): ocp apply refuses them
# with the other lines. workers: none is one of those, so the run ends at
# validate() whatever it says about the other two.
subtest 'ocp apply --dry-run, an unknown key under registry: and ssl:: the lines on STDERR, exit 1' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({
        name => 'k394', control_planes => { provider => 'local' },
        registry => { cahce => 'http://cache.k394.test:5000' }, ssl => { emial => 'ops@k394.test' },
        workers => 'none',
    }));
    my ($out, $err) = map { $dir->parent->child("k394-$$-$_") } qw( out err );
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        open STDIN,  '<', '/dev/null' or die;
        open STDOUT, '>', "$out"      or die;
        open STDERR, '>', "$err"      or die;
        exec $^X, "-I$lib", $bin, 'apply', '--dry-run' or die "exec: $!";
    }
    waitpid $pid, 0;
    my $rc = $? >> 8;
    my ($o, $e) = ($out->slurp_utf8, $err->slurp_utf8);
    $_->remove for $out, $err;

    is $rc, 1, 'exit 1';
    is $o, '', 'nothing on STDOUT';
    like $e, qr/\AError: ocp\.yaml has 3 errors:\n/, 'the refusal, counted';
    like $e, qr/^  - registry\.cahce: unknown key \(must be cache, upstream, or name\)$/m, 'registry.cahce';
    like $e, qr/^  - ssl\.emial: unknown key \(must be email\)$/m, 'ssl.emial';
    like $e, qr/^  - workers: must be a list/m, 'workers';
};

done_testing;

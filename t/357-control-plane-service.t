#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Cwd qw( getcwd );
use File::Temp qw( tempdir );
use FindBin;
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';
use OCP;
use OCP::Choices;
use OCP::Config;
use OCP::Cmd::Apply::Validate;
use OCP::Cmd::Init;
use OCP::Cmd::Status;

#
# k357: a control plane's service: key goes. `ocp init --provider local
# --service systemd` wrote it, and nothing in lib/, bin/ or share/ read it;
# since k347 validate() took it as one of a control plane's keys all the same.
#
# The maintainer's decision (2026-11-06): ocp init no longer writes it,
# validate() refuses it with a hint that it is gone and can be deleted, and
# init's --service goes with it -- it did nothing but write that key.
#
# The claims:
#   1. service: on a control plane is a line, whatever it holds, in the
#      mapping form and in a list entry by its place, with the hint; the key
#      list it names has no service in it any more;
#   2. ocp apply refuses it before it touches a host; it is validate()'s
#      alone, as every unknown key of a control plane is: a command that
#      checks only the paths it reads (ocp status) runs on over it;
#   3. every other key of a control plane passes as before;
#   4. write_spec writes no service: for a local control plane, and what it
#      writes passes validate();
#   5. ocp init has no --service: it is refused as an option ocp init does not
#      know, and nothing is written.
#

local @ARGV = ();
my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);
my $BIN    = "$FindBin::Bin/../bin/ocp";
my $LIB    = "$FindBin::Bin/../lib";

# Through a file, as ocp reads it.
sub config_for {
    my ($spec) = @_;
    my $f = path($tmpdir)->child('c' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8(YAML::XS::Dump({ name => 'k357', %$spec }));
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

# A die comes back as a line of its own, so each claim fails on its own.
sub errors_for {
    my @e = eval { config_for(@_)->validate };
    return $@ ? ("validate() died: $@") : @e;
}

my @CP_KEYS  = qw( provider host public_ip private_ip node_ip server_type location image name );
my $KEYS     = OCP::Choices::or_list(@CP_KEYS);
my $MAP_KEYS = OCP::Choices::or_list(@CP_KEYS, 'nodes');
my $GONE     = 'service is gone (ocp init wrote it, nothing read it) -- delete it';

# --- 1. the line -------------------------------------------------------------------------------------

subtest "a control plane's service: is a line, with the hint" => sub {
    for my $value ('systemd', 'none', [ 'systemd' ]) {
        my $shown = ref $value ? 'a list' : $value;
        is_deeply [ errors_for({ control_planes => { provider => 'local', service => $value } }) ],
            [ "control_planes[1].service: unknown key (must be $MAP_KEYS); $GONE" ],
            "the mapping form, service: $shown";
    }
    is_deeply [ errors_for({ control_planes => [ { provider => 'ssh', host => 'cp1.k357.test' },
                                                 { provider => 'local', service => 'systemd' } ] }) ],
        [ "control_planes[2].service: unknown key (must be $KEYS); $GONE" ],
        'a list entry, by its place';
    is_deeply [ errors_for({ control_planes => { provider => 'local', nodes => 3, service => 'systemd' } }) ],
        [ "control_planes[1].service: unknown key (must be $MAP_KEYS); $GONE" ],
        'nodes: 3 -- said once, not once per control plane';
    is_deeply [ errors_for({ control_planes => { provider => 'local', service => 'systemd', count => 2 } }) ],
        [ "control_planes[1].count: unknown key (must be $MAP_KEYS); count is read by nothing -- "
          . 'how many control planes there are is nodes: N',
          "control_planes[1].service: unknown key (must be $MAP_KEYS); $GONE" ],
        'beside another key nothing reads: a line each, sorted';
    is_deeply [ errors_for({ control_planes => { provider => 'local', hots => 'x' } }) ],
        [ "control_planes[1].hots: unknown key (must be $MAP_KEYS)" ],
        'the key list a typo is told: no service in it';
};

# --- 2. who refuses it ---------------------------------------------------------------------------------

subtest "ocp apply refuses it; it is validate()'s alone" => sub {
    my $c    = config_for({ control_planes => { provider => 'local', service => 'systemd' } });
    my $line = "control_planes[1].service: unknown key (must be $MAP_KEYS); $GONE";
    my $file = $c->file;

    ok !eval { OCP::Cmd::Apply::Validate::refuse_invalid_config($c); 1 }, 'ocp apply refuses it';
    like $@, qr/\A\Q$file\E has 1 error:\n  - \Q$line\E\nNothing was done: ocp apply checks /,
        '... before it touches a host or the cluster';

    is_deeply [ $c->spec_errors('control_planes', 'control_planes[*]',
                                map { "control_planes[*].$_" } qw( provider host name )) ], [],
        'at no path of a control plane';
    is eval { OCP::Cmd::Status->new->refuse_spec_errors($c) }, 1, 'ocp status runs on over it' or diag $@;
    is_deeply $c->control_planes, [ { provider => 'local', service => 'systemd' } ],
        'control_planes reads the entry as it stands';
};

# --- 3. the other keys --------------------------------------------------------------------------------

subtest 'every other key of a control plane passes as before' => sub {
    is_deeply [ errors_for({ control_planes => { provider => 'hetzner', server_type => 'cx32', location => 'fsn1',
                                                 image => 'debian-13', public_ip => '10.9.0.5',
                                                 private_ip => '10.8.0.5', node_ip => '10.8.0.5',
                                                 name => 'police1', nodes => 1 } }) ],
        [], 'hetzner, the mapping form';
    is_deeply [ errors_for({ control_planes => [ { provider => 'ssh', host => 'cp1.k357.test', name => 'cp1' },
                                                 { provider => 'local' } ] }) ],
        [], 'a list, a local entry without service';
};

# --- 4. write_spec ----------------------------------------------------------------------------------------

subtest 'write_spec writes no service: for a local control plane' => sub {
    for my $service ('systemd', 'none', undef) {
        my $f = path($tmpdir)->child('init' . int(rand(1_000_000)) . '.yaml');
        OCP::Config->write_spec($f->stringify, name => 'k357', provider => 'local', service => $service);
        my $spec = YAML::XS::LoadFile($f->stringify);
        my $what = 'service ' . ($service // 'undef');
        is_deeply $spec->{control_planes}, { provider => 'local' }, "$what: provider local and nothing else";
        is_deeply [ OCP::Config->new(file => $f->stringify, ocp => $ocp)->validate ], [], "$what: passes";
    }
};

# --- 5. ocp init --service -----------------------------------------------------------------------------

subtest 'ocp init has no --service' => sub {
    ok !OCP::Cmd::Init->can('service'), 'no service accessor';
    my %declared = OCP::Cmd::Init->_options_data;
    ok !exists $declared{service}, 'no service option declared';

    my $dir = path(tempdir(CLEANUP => 1));
    my $cwd = getcwd();
    local $ENV{HETZNER_API_TOKEN} = '';    # never inherit a real token
    chdir $dir or die "chdir: $!";
    my $out = `$^X -I'$LIB' '$BIN' init --nopassword --nogit --provider local --service systemd </dev/null 2>&1`;
    my $rc  = $? >> 8;
    chdir $cwd or die "chdir back: $!";

    isnt $rc, 0, 'ocp init --provider local --service systemd: exit is not 0' or diag $out;
    like $out, qr/Unknown option: service/, '... an option ocp init does not know' or diag $out;
    ok !$dir->child('ocp.yaml')->exists, '... and no ocp.yaml was written';
};

done_testing;

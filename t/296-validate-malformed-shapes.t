#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use FindBin;
use JSON::PP ();
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';
use OCP;
use OCP::Config;
use OCP::Cmd::Apply::Validate;

#
# k296: since k255 `ocp apply` calls OCP::Config::validate() before anything,
# so whatever validate() says is the first thing a user sees. On some
# YAML-valid shapes it said a Perl error instead -- "Can't use string ("foo")
# as a HASH ref" -- and on a `gpu:` that is no mapping it said nothing, and
# every gpu_* reader died that way later.
#
# The claims here:
#   1. each of these shapes is an ordinary error line that names the key path
#      and what was expected: a control_planes entry that is no mapping, a
#      control_planes that is neither form, a nodes: that is no whole number
#      of 1 or more, a workers that is no list, a workers entry that is no
#      mapping, a gpu that is no mapping;
#   2. the gpu_* readers refuse a gpu that is no mapping in the same words,
#      instead of dying inside Perl -- validate() reports it first;
#   3. refuse_invalid_config (`ocp apply`) lists these lines like any other;
#   4. validate() never dies on any YAML-valid shape at any key it reads, nor
#      warns: a sweep puts a scalar, a boolean, null, a list and a mapping at
#      each. (A pool without a name warned "Use of uninitialized value".)
#

local @ARGV = ();
my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);
my $bin    = "$FindBin::Bin/../bin/ocp";
my $lib    = "$FindBin::Bin/../lib";

# Through a file, as ocp reads it: YAML booleans come back as JSON::PP::Boolean.
sub config_for {
    my ($spec) = @_;
    my $f = path($tmpdir)->child('c' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8(YAML::XS::Dump({ name => 'k296', %$spec }));
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

# A die comes back as a line of its own, so each claim fails on its own.
sub errors_for {
    my @e = eval { config_for(@_)->validate };
    return $@ ? ("validate() died: $@") : @e;
}

my $local = { provider => 'local' };

# --- 1. each shape is a line --------------------------------------------------

subtest 'a control_planes entry that is no mapping' => sub {
    is_deeply [ errors_for({ control_planes => [ $local, 'foo' ] }) ],
        [ "control_planes[2]: must be a mapping (one control plane), not 'foo'" ],
        'a string: named by its place, the rest still checked' ;

    is_deeply [ errors_for({ control_planes => [ [ 'a', 'b' ] ] }) ],
        [ 'control_planes[1]: must be a mapping (one control plane), not a list' ],
        'a list';

    is_deeply [ errors_for({ control_planes => [ $local, undef ] }) ],
        [ 'control_planes[2]: must be a mapping (one control plane), not null' ],
        'an empty entry is no hetzner control plane with nothing set';
};

subtest 'a control_planes that is neither form' => sub {
    is_deeply [ errors_for({ control_planes => 'foo' }) ],
        [ "control_planes: must be a mapping (one control plane, or nodes: N of them) "
          . "or a list of mappings, not 'foo'" ],
        'one line, not "server_type required for hetzner" for a control plane nobody wrote';
};

subtest 'control_planes.nodes is a whole number of 1 or more' => sub {
    for my $case ([ 'foo', "'foo'" ], [ [ 3 ], 'a list' ], [ { n => 3 }, 'a mapping' ],
                  [ 0, "'0'" ], [ -1, "'-1'" ], [ '2.5', "'2.5'" ], [ JSON::PP::true, 'true' ]) {
        my ($nodes, $shown) = @$case;
        my @w;
        local $SIG{__WARN__} = sub { push @w, @_ };
        is_deeply [ errors_for({ control_planes => { %$local, nodes => $nodes } }) ],
            [ "control_planes.nodes: must be a whole number of 1 or more, not $shown" ],
            "nodes: $shown";
        is_deeply \@w, [], "nodes: $shown -- and no Perl warning on the way";
    }

    is_deeply [ errors_for({ control_planes => { %$local, nodes => 3 } }) ], [], 'nodes: 3 passes';
};

# A list numifies to its address: as a repeat count it asked Perl for a list
# of some 10^14 control planes ("Out of memory during stack extend").
subtest 'control_planes() counts a nodes: that is no number as one control plane' => sub {
    is scalar @{ config_for({ control_planes => { %$local, nodes => [ 3 ] } })->control_planes }, 1, 'a list';
    is scalar @{ config_for({ control_planes => { %$local, nodes => 'foo' } })->control_planes }, 1, 'a string';
    is scalar @{ config_for({ control_planes => { %$local, nodes => 3 } })->control_planes }, 3, '3 is 3';
};

subtest 'a workers that is no list' => sub {
    is_deeply [ errors_for({ control_planes => $local, workers => 'foo' }) ],
        [ "workers: must be a list of worker pools, not 'foo'" ], 'a string';
    is_deeply [ errors_for({ control_planes => $local, workers => { name => 'w', provider => 'ssh' } }) ],
        [ 'workers: must be a list of worker pools, not a mapping' ], 'one pool, not in a list';
};

subtest 'a workers entry that is no mapping' => sub {
    is_deeply [ errors_for({ control_planes => $local,
                             workers => [ { name => 'w', provider => 'ssh' }, 'foo' ] }) ],
        [ "workers[2]: must be a mapping (a worker pool), not 'foo'" ], 'a string, by its place';
    is_deeply [ errors_for({ control_planes => $local, workers => [ [ 'w' ] ] }) ],
        [ 'workers[1]: must be a mapping (a worker pool), not a list' ], 'a list';
};

subtest 'a gpu that is no mapping' => sub {
    is_deeply [ errors_for({ control_planes => $local, gpu => 'foo' }) ],
        [ "gpu: must be a mapping, not 'foo'" ], 'a string';
    is_deeply [ errors_for({ control_planes => $local, gpu => [ 'host' ] }) ],
        [ 'gpu: must be a mapping, not a list' ], 'a list';

    # robocop: takes a boolean, so gpu: false is the likely slip -- and the
    # one place the line can say what was meant.
    is_deeply [ errors_for({ control_planes => $local, gpu => JSON::PP::false }) ],
        [ 'gpu: must be a mapping, not false; write gpu: { enabled: false }' ], 'false';
    is_deeply [ errors_for({ control_planes => $local, gpu => JSON::PP::true }) ],
        [ 'gpu: must be a mapping, not true; write gpu: { enabled: true }' ], 'true';

    is_deeply [ errors_for({ control_planes => $local, gpu => { enabled => JSON::PP::false } }) ], [],
        'a mapping passes';
    is_deeply [ errors_for({ control_planes => $local }) ], [], 'absent passes';
};

# --- 2. the gpu readers -------------------------------------------------------

subtest 'the gpu_* readers refuse a gpu that is no mapping in the same words' => sub {
    for my $gpu ('foo', [ 'host' ], JSON::PP::false) {
        my $c = config_for({ control_planes => $local, gpu => $gpu });
        my ($line) = $c->validate;
        (my $want = $line) =~ s/^gpu: /gpu /;
        for my $m (qw( gpu_enabled gpu_toolkit gpu_driver gpu_amd_config gpu_amd_allocation
                       gpu_amd_resource_naming gpu_amd_labeller gpu_amd_metrics gpu_amd_integrated )) {
            ok !eval { $c->$m; 1 }, "$m refuses " . $line;
            like $@, qr/^\Q$want\E at /, "$m: validate()'s line, not a Perl error";
        }
    }

    my $c = config_for({ control_planes => $local });
    is $c->gpu_enabled, 1, 'absent: the defaults as before (enabled)';
    is $c->gpu_driver, 'host', 'absent: driver host';
};

# --- 3. ocp apply lists them --------------------------------------------------

my %MALFORMED = (
    control_planes => [ { provider => 'ssh', host => 'cp.k296.test' }, 'foo' ],
    workers        => 'foo',
    gpu            => JSON::PP::false,
);

subtest 'refuse_invalid_config lists them like any other error' => sub {
    my $c = config_for(\%MALFORMED);
    my @want = $c->validate;
    is scalar(@want), 3, 'three lines' or diag explain \@want;

    ok !eval { OCP::Cmd::Apply::Validate::refuse_invalid_config($c); 1 }, 'refused';
    like $@, qr/ has 3 errors:\n/, 'counted';
    like $@, qr/^  - \Q$_\E$/m, "lists: $_" for @want;
    unlike $@, qr/Can't use|Not an? (?:HASH|ARRAY)|Out of memory|line \d+/, 'no Perl error in it';
};

subtest 'ocp apply --dry-run: the lines on STDERR, exit 1' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({ name => 'k296', %MALFORMED }));
    my ($out, $err) = map { $dir->parent->child("k296-$$-$_") } qw( out err );
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
    like $e, qr/^  - control_planes\[2\]: must be a mapping/m, 'the entry';
    like $e, qr/^  - workers: must be a list/m, 'workers';
    like $e, qr/^  - gpu: must be a mapping, not false/m, 'gpu';
    unlike $e, qr/Can't use|Not an? (?:HASH|ARRAY)|line \d+/, 'no Perl error';
};

# --- 4. the sweep -------------------------------------------------------------
#
# Every key validate() reads, top level and below, with every YAML shape in
# turn. Only "no die", and no Perl warning on STDERR above the refusal: what
# each line says is for the subtests above and the tests of each key.

my @SHAPES = (
    [ "'foo'" => 'foo' ], [ '7' => 7 ], [ 'true' => JSON::PP::true ], [ 'false' => JSON::PP::false ],
    [ 'null' => undef ], [ '[]' => [] ], [ "['foo']" => [ 'foo' ] ], [ '[{}]' => [ {} ] ],
    [ '{}' => {} ], [ '{foo: bar}' => { foo => 'bar' } ],
);

my $cp = sub { +{ provider => 'local', @_ } };
my $wp = sub { +{ name => 'w', provider => 'ssh', host => '10.9.0.1', @_ } };
my @AT = (
    [ 'name'                      => sub { +{ control_planes => $cp->(), name => $_[0] } } ],
    [ 'control_planes'            => sub { +{ control_planes => $_[0] } } ],
    [ 'control_planes[1]'         => sub { +{ control_planes => [ $_[0] ] } } ],
    [ 'control_planes[2]'         => sub { +{ control_planes => [ $cp->(), $_[0] ] } } ],
    [ 'control_planes.nodes'      => sub { +{ control_planes => $cp->(nodes => $_[0]) } } ],
    (map { my $k = $_;
        [ "control_planes.$k"     => sub { +{ control_planes => $cp->($k => $_[0]) } } ],
        [ "control_planes[1].$k"  => sub { +{ control_planes => [ $cp->($k => $_[0]) ] } } ],
     } qw( provider host public_ip private_ip node_ip server_type location )),
    [ 'workers'                   => sub { +{ control_planes => $cp->(), workers => $_[0] } } ],
    [ 'workers[1]'                => sub { +{ control_planes => $cp->(), workers => [ $_[0] ] } } ],
    (map { my $k = $_;
        [ "workers[1].$k"         => sub { +{ control_planes => $cp->(), workers => [ $wp->($k => $_[0]) ] } } ],
     } qw( name provider host nodes labels taints node_ip )),
    [ 'workers[1].nodes[1]'       => sub { +{ control_planes => $cp->(), workers => [ $wp->(nodes => [ $_[0] ]) ] } } ],
    [ 'network'                   => sub { +{ control_planes => $cp->(), network => $_[0] } } ],
    (map { my $k = $_;
        [ "network.$k"            => sub { +{ control_planes => $cp->(), network => { $k => $_[0] } } } ],
     } qw( pod_cidr lb_pool l2 )),
    (map { my $k = $_;
        [ "network.lb_pool.$k"    => sub { +{ control_planes => $cp->(), network => { lb_pool => { $k => $_[0] } } } } ],
     } qw( cidr start stop )),
    (map { my $k = $_;
        [ "network.l2.$k"         => sub { +{ control_planes => $cp->(), network => { l2 => { $k => $_[0] } } } } ],
     } qw( node_selector interfaces )),
    [ 'cilium'                    => sub { +{ control_planes => $cp->(), cilium => $_[0] } } ],
    (map { my $k = $_;
        [ "cilium.$k"             => sub { +{ control_planes => $cp->(), cilium => { $k => $_[0] } } } ],
     } qw( devices helm_values )),
    [ 'gpu'                       => sub { +{ control_planes => $cp->(), gpu => $_[0] } } ],
    (map { my $k = $_;
        [ "gpu.$k"                => sub { +{ control_planes => $cp->(), gpu => { $k => $_[0] } } } ],
     } qw( enabled driver toolkit amd )),
    (map { my $k = $_;
        [ "gpu.amd.$k"            => sub { +{ control_planes => $cp->(), gpu => { amd => { $k => $_[0] } } } } ],
     } qw( allocation resource_naming )),
    [ 'robocop'                   => sub { +{ control_planes => $cp->(), robocop => $_[0] } } ],
    (map { my $k = $_;
        [ "robocop.$k"            => sub { +{ control_planes => $cp->(), robocop => { $k => $_[0] } } } ],
     } qw( enabled security_level image )),
);

subtest 'validate() never dies on a YAML-valid shape' => sub {
    for my $at (@AT) {
        my ($path, $spec_with) = @$at;
        for my $shape (@SHAPES) {
            my ($shown, $value) = @$shape;
            my $c = config_for($spec_with->($value));
            my @w;
            local $SIG{__WARN__} = sub { push @w, @_ };
            my $ok = eval { my @e = $c->validate; 1 };
            ok $ok, "$path: $shown" or diag $@;
            is_deeply \@w, [], "$path: $shown -- no Perl warning" or diag explain \@w;
        }
    }
};

done_testing;

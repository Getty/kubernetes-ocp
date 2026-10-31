#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use FindBin;
use JSON::MaybeXS ();
use JSON::PP ();
use Path::Tiny qw( path );
use POSIX ();
use YAML::XS ();

use lib 'lib';
use OCP;
use OCP::Choices;
use OCP::Config;
use OCP::Cmd::Apply::Validate;
use OCP::Provider;

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
# k305, what k296 left: some shapes still passed, and some lines quoted Perl.
#   5. a name, a robocop (or robocop.enabled) and a pool name of the wrong
#      shape, and an empty control_planes list, are a line each instead of
#      passing;
#   6. control_planes.nodes is at most 7, the most etcd members etcd advises,
#      and control_planes() never takes a bigger one as a repeat count (10^12
#      ran out of memory);
#   7. no line quotes a value as Perl has it -- ARRAY(0x...), HASH(0x...),
#      "a array", a boolean as '1' or '0' -- at any key of the sweep.
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

# Since k305 the claim is 1 to 7, not 1 or more: see claim 6.
subtest 'control_planes.nodes is a whole number from 1 to 7' => sub {
    for my $case ([ 'foo', "'foo'" ], [ [ 3 ], 'a list' ], [ { n => 3 }, 'a mapping' ],
                  [ 0, "'0'" ], [ -1, "'-1'" ], [ '2.5', "'2.5'" ], [ JSON::PP::true, 'true' ]) {
        my ($nodes, $shown) = @$case;
        my @w;
        local $SIG{__WARN__} = sub { push @w, @_ };
        is_deeply [ errors_for({ control_planes => { %$local, nodes => $nodes } }) ],
            [ "control_planes.nodes: must be a whole number from 1 to 7, not $shown" ],
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
    # a host in the pod CIDR, so the pool is named in that line too (k305)
    [ 'workers[1].name, host 10.42.0.5' => sub { +{ control_planes => $cp->(),
                                     workers => [ $wp->(name => $_[0], host => '10.42.0.5') ] } } ],
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

# Claim 7 rides along: whatever a line says, it never quotes a value the way
# Perl holds it (k305). A boolean is no '1' or '0' either.
subtest 'validate() never dies, warns or quotes Perl on a YAML-valid shape' => sub {
    for my $at (@AT) {
        my ($path, $spec_with) = @$at;
        for my $shape (@SHAPES) {
            my ($shown, $value) = @$shape;
            my $c = config_for($spec_with->($value));
            my @w;
            local $SIG{__WARN__} = sub { push @w, @_ };
            my @e;
            my $ok = eval { @e = $c->validate; 1 };
            ok $ok, "$path: $shown" or diag $@;
            is_deeply \@w, [], "$path: $shown -- no Perl warning" or diag explain \@w;
            is_deeply [ grep { /\b(?:ARRAY|HASH|CODE|SCALAR|REF|GLOB)\(0x|\ba (?:array|hash)\b|json::pp/i } @e ],
                [], "$path: $shown -- no Perl value in a line";
            is_deeply [ grep { /'[01]'/ } @e ], [], "$path: $shown -- a boolean reads true or false"
                if JSON::MaybeXS::is_bool($value);
        }
    }
};

# --- 5. the shapes that passed ------------------------------------------------

subtest 'a name that is no string' => sub {
    for my $case ([ [ 'a' ], 'a list' ], [ { a => 1 }, 'a mapping' ],
                  [ JSON::PP::true, 'true' ], [ JSON::PP::false, 'false' ]) {
        my ($name, $shown) = @$case;
        is_deeply [ errors_for({ control_planes => $local, name => $name }) ],
            [ "name: must be a string (the cluster's name), not $shown" ], "name: $shown";
    }
    is_deeply [ errors_for({ control_planes => $local, name => 7 }) ], [], 'a number is a name';
    is_deeply [ errors_for({ control_planes => $local, name => ' ' }) ], [ 'name is required' ],
        'blank: the line it always had';
};

subtest 'a robocop that is no switch' => sub {
    is_deeply [ errors_for({ control_planes => $local, robocop => [ 'a' ] }) ],
        [ 'robocop: must be true, false or a mapping (enabled, security_level, image), not a list' ],
        'a list';
    is_deeply [ errors_for({ control_planes => $local, robocop => { enabled => [ 'a' ] } }) ],
        [ 'robocop.enabled: must be true or false, not a list' ], 'enabled: a list';
    is_deeply [ errors_for({ control_planes => $local, robocop => { enabled => {} } }) ],
        [ 'robocop.enabled: must be true or false, not a mapping' ], 'enabled: a mapping';

    for my $ok (JSON::PP::true, JSON::PP::false, 1, 0, {}, { enabled => JSON::PP::false }, { enabled => 1 }) {
        my $shown = ref $ok eq 'HASH' ? 'a mapping' : "$ok";
        is_deeply [ errors_for({ control_planes => $local, robocop => $ok }) ], [], "robocop: $shown passes";
    }
};

# A YAML true is a JSON::PP::Boolean, and the eq overload Cpanel::JSON::XS
# gives it makes `'hetzner' eq $true` true: provider: true was a known
# provider, security_level: true a level (k305).
subtest 'a YAML true is no choice' => sub {
    my $types = OCP::Choices::or_list(OCP::Provider->types);
    is_deeply [ errors_for({ control_planes => { provider => JSON::PP::true } }) ],
        [ "control_planes[1]: invalid provider true (must be $types)" ], 'control_planes.provider';
    is_deeply [ errors_for({ control_planes => $local,
                             workers => [ { name => 'w', provider => JSON::PP::true } ] }) ],
        [ "worker pool 'w': invalid provider true (must be $types)" ], 'a pool provider';
    is_deeply [ errors_for({ control_planes => $local, robocop => { security_level => JSON::PP::true } }) ],
        [ 'robocop.security_level: invalid value true (must be secret, secret_approved, or inject)' ],
        'robocop.security_level';
    my $c = config_for({ control_planes => $local, robocop => { security_level => JSON::PP::true } });
    ok !eval { $c->robocop_security_level; 1 }, 'the accessor refuses it too';
    like $@, qr/^robocop\.security_level must be .*, not true at /, 'in its words';
};

subtest 'an empty control_planes list' => sub {
    is_deeply [ errors_for({ control_planes => [] }) ],
        [ 'control_planes: must list at least one control plane, not an empty list' ], '[]';
    is_deeply [ errors_for({ control_planes => [ $local ] }) ], [], 'one passes';
};

# A pool is named by its name; one without a name that can be quoted is
# named by its place, as a control plane is -- not 'ARRAY(0x...)', not ''.
subtest 'a pool name that is no string' => sub {
    is_deeply [ errors_for({ control_planes => $local,
                             workers => [ { name => [ 'a' ], provider => 'aws' } ] }) ],
        [ "workers[1].name: must be a string (the pool's name), not a list",
          "workers[1]: invalid provider 'aws' (must be "
          . OCP::Choices::or_list(OCP::Provider->types) . ')' ],
        'a list: its own line, and the pool by its place';
    is_deeply [ errors_for({ control_planes => $local,
                             workers => [ { name => JSON::PP::true, provider => 'ssh' } ] }) ],
        [ "workers[1].name: must be a string (the pool's name), not true" ], 'true';
    is_deeply [ errors_for({ control_planes => $local, workers => [ {}, { name => 'w2' } ] }) ],
        [ 'worker pool: name required', 'workers[1]: provider required',
          "worker pool 'w2': provider required" ],
        "no name: by its place, not worker pool ''";
    is_deeply [ errors_for({ control_planes => $local, workers => [ { name => '' } ] }) ],
        [ 'worker pool: name required', 'workers[1]: provider required' ], "name: '' the same";
    is_deeply [ errors_for({ control_planes => $local,
                             workers => [ { name => [ 'a' ], provider => 'ssh', host => '10.42.0.5' } ] }) ],
        [ 'network.pod_cidr (default 10.42.0.0/16) overlaps workers[1] host 10.42.0.5 '
          . '-- set network.pod_cidr to a range nothing else uses',
          "workers[1].name: must be a string (the pool's name), not a list" ],
        'the pod CIDR line names it the same way';
};

# --- 6. the upper bound on nodes ----------------------------------------------

# In a child of its own: a repeat count taken as is asks Perl for some 10^12
# entries, and running out of memory is nothing an eval catches.
sub in_child {
    my ($code) = @_;
    pipe(my $r, my $w) or die "pipe: $!";
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        close $r;
        my @out = eval { $code->() };
        print {$w} $@ ? "died: $@" : join "\n", @out;
        close $w;
        POSIX::_exit(0);
    }
    close $w;
    my $out = do { local $/; <$r> };
    waitpid $pid, 0;
    return ($? >> 8, $out);
}

subtest 'control_planes.nodes is at most 7' => sub {
    is_deeply [ errors_for({ control_planes => { %$local, nodes => 7 } }) ], [], '7 passes';

    my $over = "control_planes.nodes: must be a whole number from 1 to 7, not '%s'; "
        . 'every control plane is an etcd member, and etcd advises no more than 7';
    is_deeply [ errors_for({ control_planes => { %$local, nodes => 8 } }) ],
        [ sprintf $over, 8 ], '8: the bound, and why';
    is scalar @{ config_for({ control_planes => { %$local, nodes => 8 } })->control_planes }, 1,
        'control_planes() counts it as one control plane';

    my $huge = '1000000000000';
    my ($rc, $out) = in_child(sub { config_for({ control_planes => { %$local, nodes => $huge } })->validate });
    is $rc, 0, '10^12: validate() returns';
    is $out, sprintf($over, $huge), '10^12: the same line';
    ($rc, $out) = in_child(sub {
        scalar @{ config_for({ control_planes => { %$local, nodes => $huge } })->control_planes } });
    is $rc, 0, '10^12: control_planes() returns';
    is $out, 1, '10^12: one control plane, not a repeat count';
};

# --- 7. the accessors -----------------------------------------------------------

subtest 'the accessors that croak quote no Perl value either' => sub {
    for my $case ([ robocop_security_level => { robocop => { security_level => [ 'a' ] } } ],
                  [ robocop_image          => { robocop => { image => [ 'a' ] } } ],
                  [ gpu_driver             => { gpu => { driver => [ 'a' ] } } ]) {
        my ($m, $spec) = @$case;
        ok !eval { config_for({ control_planes => $local, %$spec })->$m; 1 }, "$m refuses a list";
        like $@, qr/, not a list(?: at |;|\z)/, "$m: says a list";
        unlike $@, qr/ARRAY\(0x|a array/, "$m: not as Perl has it";
    }
};

done_testing;

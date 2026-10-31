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
# k315, what k305 left:
#   8. robocop and robocop.enabled are true or false (or 1 and 0) and nothing
#      else: a string -- no, off, "false" -- is one Perl calls true, and turned
#      robocop on. A string that spells a boolean gets a hint naming it, as
#      gpu: false does;
#   9. a key under robocop: other than enabled, security_level and image is a
#      line, as under network: and cilium: -- robocop: { enable: false } was a
#      mapping without enabled, so on;
#  10. robocop_enabled, which every reader of the switch asks (ocp apply, ocp
#      keys secure, the health gate), refuses what validate() refuses about
#      the switch, in its words, and reads what validate() passes the way it
#      always did -- swept over every shape at robocop and robocop.enabled;
#  11. a node_ip that is a boolean is called true or false, not "a reference";
#  12. the list form of control_planes holds at most 7, as nodes: does;
#  13. a control plane's host and server_type and a pool's host are strings;
#      an ssh pool's nodes is a list of hosts, each a string or a mapping with
#      host; any other pool's nodes is a count. A list counted was some 10^14
#      OCPNodes, and a boolean among the hosts died inside Perl.
#
# k320, the same gap at the other switches:
#  14. gpu.enabled, gpu.toolkit, gpu.amd.labeller, gpu.amd.metrics,
#      gpu.amd.integrated, lbipam, nocert and system.ntp are true or false (or 1
#      and 0), as robocop is: a string -- no, off, "false" -- is one Perl calls
#      true, and gpu: { enabled: no } turned the GPU stack on. A string that
#      spells a boolean gets the hint naming it;
#  15. each switch's accessor, which every reader of it asks (ocp apply, ocp
#      update, ocp node add, ocp status' drift check), refuses what validate()
#      refuses about the switch, in its words, and reads what validate() passes
#      as a plain 0 or 1, its default when absent -- swept over every shape at
#      each, and over every switch OCP::Config has.
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
    # the eighth of a list that holds one too many (k315)
    [ 'control_planes[8]'         => sub { +{ control_planes => [ (map { $cp->() } 1 .. 7), $_[0] ] } } ],
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
    # k315: an entry's host, and the nodes of a pool that counts its machines
    [ 'workers[1].nodes[1].host'  => sub { +{ control_planes => $cp->(), workers => [ $wp->(nodes => [ { host => $_[0] } ]) ] } } ],
    [ 'workers[1].nodes, hetzner' => sub { +{ control_planes => $cp->(), workers => [ {
                                     name => 'w', provider => 'hetzner', server_type => 'cx22', nodes => $_[0] } ] } } ],
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
     } qw( allocation resource_naming labeller metrics integrated )),
    [ 'robocop'                   => sub { +{ control_planes => $cp->(), robocop => $_[0] } } ],
    (map { my $k = $_;
        [ "robocop.$k"            => sub { +{ control_planes => $cp->(), robocop => { $k => $_[0] } } } ],
     } qw( enabled security_level image enable )),    # enable: no key of robocop's (k315)
    # the other switches (k320)
    (map { my $k = $_;
        [ $k                      => sub { +{ control_planes => $cp->(), $k => $_[0] } } ],
     } qw( lbipam nocert system )),
    [ 'system.ntp'                => sub { +{ control_planes => $cp->(), system => { ntp => $_[0] } } } ],
);

# Claim 7 rides along: whatever a line says, it never quotes a value the way
# Perl holds it (k305). A boolean is no '1' or '0' either, and no "reference"
# (claim 11, k315): no YAML value is one.
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
            is_deeply [ grep { /\b(?:ARRAY|HASH|CODE|SCALAR|REF|GLOB)\(0x|\ba (?:array|hash|reference)\b|json::pp/i } @e ],
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

# --- 8. robocop is true or false ------------------------------------------------

# ocp.yaml as typed, not as YAML::XS::Dump would write it: YAML::XS reads only
# a bare true and false as booleans, and every other spelling as a string.
sub config_from_text {
    my ($text) = @_;
    my $f = path($tmpdir)->child('t' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8("name: k315\ncontrol_planes:\n  provider: local\n$text");
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

my $ROBOCOP_IS = 'robocop: must be true, false or a mapping (enabled, security_level, image), not ';

subtest 'a robocop that is a string is no switch' => sub {
    for my $case ([ 'no', 'false' ], [ 'off', 'false' ], [ '"false"', 'false' ], [ 'FALSE', 'false' ],
                  [ 'n', 'false' ], [ 'yes', 'true' ], [ 'on', 'true' ], [ '"true"', 'true' ], [ 'True', 'true' ]) {
        my ($typed, $meant) = @$case;
        (my $word = $typed) =~ tr/"//d;
        is_deeply [ config_from_text("robocop: $typed\n")->validate ],
            [ "$ROBOCOP_IS'$word'; write robocop: $meant" ], "robocop: $typed -- the $meant it spells";
    }
    for my $typed ('foo', '7', '2', "''") {
        (my $word = $typed) =~ tr/'//d;
        is_deeply [ config_from_text("robocop: $typed\n")->validate ], [ "$ROBOCOP_IS'$word'" ],
            "robocop: $typed -- no hint where none would be true";
    }
    for my $typed ('true', 'false', '1', '0', '~') {
        is_deeply [ config_from_text("robocop: $typed\n")->validate ], [], "robocop: $typed passes";
    }
};

subtest 'a robocop.enabled that is a string is no switch' => sub {
    for my $case ([ 'no', 'false' ], [ 'off', 'false' ], [ '"false"', 'false' ], [ 'yes', 'true' ]) {
        my ($typed, $meant) = @$case;
        (my $word = $typed) =~ tr/"//d;
        is_deeply [ config_from_text("robocop:\n  enabled: $typed\n")->validate ],
            [ "robocop.enabled: must be true or false, not '$word'; write enabled: $meant" ],
            "enabled: $typed -- the $meant it spells";
    }
    is_deeply [ config_from_text("robocop:\n  enabled: foo\n")->validate ],
        [ "robocop.enabled: must be true or false, not 'foo'" ], 'enabled: foo -- no hint';
    for my $typed ('true', 'false', '1', '0') {
        is_deeply [ config_from_text("robocop:\n  enabled: $typed\n")->validate ], [], "enabled: $typed passes";
    }
};

# --- 9. robocop's keys ----------------------------------------------------------

subtest 'a key under robocop: that is none of its three' => sub {
    is_deeply [ config_from_text("robocop:\n  enable: false\n")->validate ],
        [ 'robocop.enable: unknown key (must be enabled, security_level, or image)' ],
        'enable: false -- a typo of enabled, and a mapping without enabled is on';
    is_deeply [ errors_for({ control_planes => $local,
                             robocop => { enabled => JSON::PP::true, level => 'inject', Image => 'x' } }) ],
        [ 'robocop.Image: unknown key (must be enabled, security_level, or image)',
          'robocop.level: unknown key (must be enabled, security_level, or image)' ],
        'one line each, sorted';
    is_deeply [ errors_for({ control_planes => $local, robocop => {
                    enabled => JSON::PP::true, security_level => 'inject', image => 'raudssus/ocp:1.2.3' } }) ],
        [], 'enabled, security_level and image pass';
};

# --- 10. robocop_enabled agrees with validate() ----------------------------------
#
# Every reader of the switch asks robocop_enabled -- ocp apply (after
# validate()), ocp keys secure (without it), the health gate. What validate()
# refuses, robocop_enabled refuses in the same words, so no reader turns a
# robocop: no on; what validate() passes, it reads as it always has.

subtest 'robocop_enabled reads the switch the way validate() does' => sub {
    my @extra = ([ "'no'" => 'no' ], [ "'off'" => 'off' ], [ "'false'" => 'false' ], [ '1' => 1 ], [ '0' => 0 ]);
    for my $at (grep { $_->[0] =~ /\Arobocop(?:\.enabled|\.enable)?\z/ } @AT) {
        my ($path, $spec_with) = @$at;
        for my $shape (@SHAPES, @extra) {
            my ($shown, $value) = @$shape;
            my $c = config_for($spec_with->($value));
            my @lines = $c->validate;
            my $on = eval { $c->robocop_enabled };
            if (@lines) {
                ok !defined $on, "$path: $shown -- refused by validate(), not read as on or off";
                like $@, qr/\A\Q${\ join '; ', @lines }\E at /, "$path: $shown -- in validate()'s words";
                next;
            }
            my $want = ref $value eq 'HASH'  ? 1           # robocop: {} -- a mapping opts in
                     : defined $value        ? ($value ? 1 : 0)
                     : $path eq 'robocop'    ? 0           # absent, and the control plane is local
                     :                         1;          # enabled: null -- a mapping without it
            is $on, $want, "$path: $shown -- passes, and reads $want";
        }
    }

    my $c = config_for({ control_planes => { provider => 'hetzner', location => 'fsn1', server_type => 'cx32' } });
    is $c->robocop_enabled, 1, 'absent: on with a hetzner provider, as before';
};

# --- 11. a boolean node_ip --------------------------------------------------------

subtest 'a node_ip that is a boolean is true or false, not a reference' => sub {
    my $is = 'must be one string like 10.0.0.1 or 10.0.0.1,fd00::1, not ';
    for my $b (JSON::PP::true, JSON::PP::false) {
        my $shown = $b ? 'true' : 'false';
        is_deeply [ errors_for({ control_planes => { %$local, node_ip => $b } }) ],
            [ "control_planes[1].node_ip: $is$shown" ], "control_planes.node_ip: $shown";
        is OCP::Choices::node_ip_error($b), "$is$shown",
            "node_ip_error: $shown -- the words ocp node add and spec.nodeIP are refused in";
    }
    is OCP::Choices::node_ip_error(JSON::MaybeXS->new->decode('[true]')->[0]), "${is}true",
        'a JSON true, as an OCPNode spec.nodeIP comes';
    is OCP::Choices::node_ip_error([ '10.0.0.1' ]), "${is}a list", 'a list: as before';
    is OCP::Choices::node_ip_error({ a => 1 }), "${is}a mapping", 'a mapping: as before';
};

# --- 12. the list form's bound -----------------------------------------------------

subtest 'the list form of control_planes holds at most 7' => sub {
    my $list = sub { [ map { +{ provider => 'ssh', host => "cp$_.k315.test" } } 1 .. $_[0] ] };
    my $over = 'control_planes: must list at most 7 control planes, not %d; '
        . 'every control plane is an etcd member, and etcd advises no more than 7';

    is_deeply [ errors_for({ control_planes => $list->(7) }) ], [], '7 pass';
    is_deeply [ errors_for({ control_planes => $list->($_) }) ], [ sprintf $over, $_ ], "$_: the bound, and why"
        for 8, 12;
    is_deeply [ errors_for({ control_planes => [ @{ $list->(7) }, 'foo' ] }) ],
        [ sprintf($over, 8), "control_planes[8]: must be a mapping (one control plane), not 'foo'" ],
        'its entries are still checked';
};

# --- 13. host, server_type and a pool's nodes ---------------------------------------

sub pool_errors { errors_for({ control_planes => $local, workers => [ @_ ] }) }

subtest 'a host or server_type that is no string' => sub {
    for my $case ([ [ 'a' ], 'a list' ], [ { a => 1 }, 'a mapping' ],
                  [ JSON::PP::true, 'true' ], [ JSON::PP::false, 'false' ]) {
        my ($v, $shown) = @$case;
        is_deeply [ errors_for({ control_planes => { provider => 'ssh', host => $v } }) ],
            [ "control_planes[1].host: must be a string (a host name or IP address), not $shown" ],
            "control plane host: $shown -- one line, no \"host required\" beside it";
        is_deeply [ errors_for({ control_planes => { provider => 'hetzner', location => 'fsn1', server_type => $v } }) ],
            [ "control_planes[1].server_type: must be a string (a Hetzner server type like cx32), not $shown" ],
            "control plane server_type: $shown";
        is_deeply [ pool_errors({ name => 'w', provider => 'ssh', host => $v }) ],
            [ "worker pool 'w': host must be a string (a host name or IP address), not $shown" ],
            "pool host: $shown";
    }
    is_deeply [ errors_for({ control_planes => [ { provider => 'ssh', host => 'cp.k315.test' },
                                                 { provider => 'hetzner', location => 'fsn1', server_type => 'cx32' } ],
                             workers => [ { name => 'w', provider => 'ssh', host => '10.9.0.1' } ] }) ],
        [], 'strings pass';
    is_deeply [ errors_for({ control_planes => { provider => 'ssh', host => '' } }) ],
        [ 'control_planes[1]: host required for ssh' ], "host: '' -- the line it always had";
};

subtest "a pool's nodes, as its provider reads them" => sub {
    my $ssh   = sub { +{ name => 'w', provider => 'ssh', @_ } };
    my $hz    = sub { +{ name => 'w', provider => 'hetzner', server_type => 'cx22', @_ } };
    my $hosts = 'nodes must be a list of hosts for an ssh pool (each a host name or IP address, '
        . 'or a mapping with host), not ';
    my $entry = 'must be a host name or IP address, or a mapping with host, not ';

    is_deeply [ pool_errors($ssh->(nodes => 2, host => '10.9.0.1')) ], [ "worker pool 'w': $hosts'2'" ],
        'ssh, a count: an ssh pool names its machines';
    is_deeply [ pool_errors($ssh->(nodes => { host => 'w1.k315.test' })) ], [ "worker pool 'w': ${hosts}a mapping" ],
        'ssh, one mapping not in a list';
    is_deeply [ pool_errors($ssh->(nodes => [ 'w1.k315.test', [ 'w2' ], JSON::PP::true, undef, '',
                                              { host => 'w3.k315.test' }, { name => 'x' },
                                              { host => [ 'a' ] }, { host => '' } ])) ],
        [ "worker pool 'w': nodes[2] ${entry}a list",
          "worker pool 'w': nodes[3] ${entry}true",
          "worker pool 'w': nodes[4] ${entry}null",
          "worker pool 'w': nodes[5] $entry''",
          "worker pool 'w': nodes[7] needs a host",
          "worker pool 'w': nodes[8].host must be a string (a host name or IP address), not a list",
          "worker pool 'w': nodes[9] needs a host" ],
        'ssh, each entry: a host, or a mapping with one';
    is_deeply [ pool_errors($ssh->(nodes => [ 'w1.k315.test', { host => '10.9.0.2' } ])) ], [], 'ssh: hosts pass';

    for my $case ([ [ 'a' ], 'a list' ], [ { n => 2 }, 'a mapping' ], [ JSON::PP::true, 'true' ],
                  [ 'two', "'two'" ], [ '2.5', "'2.5'" ], [ -1, "'-1'" ]) {
        my ($v, $shown) = @$case;
        is_deeply [ pool_errors($hz->(nodes => $v)) ],
            [ "worker pool 'w': nodes must be a whole number (how many machines the pool has), not $shown" ],
            "hetzner, nodes: $shown";
    }
    is_deeply [ pool_errors($hz->(nodes => $_)) ], [], "hetzner, nodes: $_ passes" for 0, 3;
    is_deeply [ pool_errors({ name => 'w', provider => 'aws', nodes => [ 'a' ] }) ],
        [ "worker pool 'w': invalid provider 'aws' (must be " . OCP::Choices::or_list(OCP::Provider->types) . ')' ],
        'an unknown provider: its line, and no guess at which nodes it would read';
};

# --- 14. the other switches are true or false --------------------------------------

# Each switch OCP::Config has besides robocop, the accessor every reader of it
# asks, and what that reads when the switch is absent.
my %SWITCH = (
    'gpu.enabled'        => [ gpu_enabled        => 1 ],
    'gpu.toolkit'        => [ gpu_toolkit        => 1 ],
    'gpu.amd.labeller'   => [ gpu_amd_labeller   => 1 ],
    'gpu.amd.metrics'    => [ gpu_amd_metrics    => 0 ],
    'gpu.amd.integrated' => [ gpu_amd_integrated => 0 ],
    'lbipam'             => [ lbipam             => 0 ],
    'nocert'             => [ no_cert            => 0 ],
    'system.ntp'         => [ ntp_enabled        => 1 ],
);

# The ocp.yaml lines that set $path to $typed: 'gpu.amd.labeller', 'off' is
# gpu:, amd: and labeller: off below it.
sub yaml_at {
    my ($path, $typed) = @_;
    my @keys = split /\./, $path;
    my $leaf = pop @keys;
    my $text = '';
    $text .= ('  ' x $_) . "$keys[$_]:\n" for 0 .. $#keys;
    return $text . ('  ' x @keys) . "$leaf: $typed\n";
}

# The spec that sets $path to $value, beside one local control plane.
sub spec_at {
    my ($path, $value) = @_;
    my $spec = { control_planes => { provider => 'local' } };
    my @keys = split /\./, $path;
    my $leaf = pop @keys;
    my $h = $spec;
    $h = $h->{$_} = {} for @keys;
    $h->{$leaf} = $value;
    return $spec;
}

subtest 'every switch is true or false' => sub {
    for my $path (sort keys %SWITCH) {
        my ($key) = $path =~ /([^.]+)\z/;
        my $is = "$path: must be true or false, not ";
        for my $case ([ 'no', 'false' ], [ 'off', 'false' ], [ '"false"', 'false' ], [ 'N', 'false' ],
                      [ 'yes', 'true' ], [ 'on', 'true' ], [ '"true"', 'true' ], [ 'True', 'true' ]) {
            my ($typed, $meant) = @$case;
            (my $word = $typed) =~ tr/"//d;
            is_deeply [ config_from_text(yaml_at($path, $typed))->validate ],
                [ "$is'$word'; write $key: $meant" ], "$path: $typed -- the $meant it spells";
        }
        for my $typed ('foo', '2', "''") {
            (my $word = $typed) =~ tr/'//d;
            is_deeply [ config_from_text(yaml_at($path, $typed))->validate ], [ "$is'$word'" ],
                "$path: $typed -- no hint where none would be true";
        }
        is_deeply [ config_from_text(yaml_at($path, '[ a ]'))->validate ], [ "${is}a list" ], "$path: a list";
        is_deeply [ config_from_text(yaml_at($path, '{ a: 1 }'))->validate ], [ "${is}a mapping" ],
            "$path: a mapping";
        for my $typed ('true', 'false', '1', '0', '~') {
            is_deeply [ config_from_text(yaml_at($path, $typed))->validate ], [], "$path: $typed passes";
        }
    }
};

# --- 15. the switch accessors agree with validate() -----------------------------------
#
# ocp apply reads the switches after validate(); ocp update, ocp node add and
# the drift check of ocp status read them without it. What validate() refuses,
# the accessor refuses in the same words, so no reader turns a gpu.enabled: no
# on; what validate() passes, it reads as 0 or 1, the default when absent.

subtest 'each switch accessor reads the switch the way validate() does' => sub {
    is_deeply [ sort keys %SWITCH ], [ sort keys %OCP::Config::SWITCH_DEFAULTS ],
        'every switch OCP::Config has is swept here, and none it does not have';

    my @extra = ([ "'no'" => 'no' ], [ "'off'" => 'off' ], [ "'false'" => 'false' ], [ "'yes'" => 'yes' ],
                 [ '1' => 1 ], [ '0' => 0 ]);
    for my $path (sort keys %SWITCH) {
        my ($m, $default) = @{ $SWITCH{$path} };
        for my $shape (@SHAPES, @extra) {
            my ($shown, $value) = @$shape;
            my $c = config_for(spec_at($path, $value));
            my @lines = $c->validate;
            my $got = eval { $c->$m };
            if (@lines) {
                ok !defined $got, "$m, $path: $shown -- refused by validate(), not read as on or off";
                like $@, qr/\A\Q${\ join '; ', @lines }\E at /, "$m, $path: $shown -- in validate()'s words";
                next;
            }
            my $want = defined $value ? ($value ? 1 : 0) : $default;
            is $got, $want, "$m, $path: $shown -- passes, and reads $want";
            ok defined $got && !ref $got, "$m, $path: $shown -- a plain 0 or 1, no boolean object";
        }
        is config_for({ control_planes => $local })->$m, $default, "$m: absent reads $default, as before";
    }
};

done_testing;

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
use lib 't/lib';
use OCP;
use OCP::Choices;
use OCP::Config;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Validate;
use OCP::Provider;
use OCPTest::Shapes qw( shapes at );

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
# k322, what k315 left in the pools and the names:
#  16. an ssh pool names its machines one way: host for one, or nodes for a
#      list. With neither it had no worker and nothing said so; with both, host
#      was not read. Each is a line; nodes: [] alone, a pool with none yet,
#      passes, as nodes: 0 does for a pool that counts its machines. A host
#      Perl calls false (0) names no machine, at the pool and in nodes, as
#      worker_ocpnodes reads it. Every ssh pool validate() passes is the
#      workers worker_ocpnodes makes of it. The one-way lines are validate()'s,
#      not those ocp destroy asks about the machines it reads (k323);
#  17. a control plane's location and image, and a pool's server_type,
#      location and image, are strings, as host and server_type are (claim 13):
#      a list reached the OCPNode spec and the Hetzner API;
#  18. the mapping form with nodes: N says a line about its one entry once, not
#      once for each control plane it stands for -- the per-entry lines and the
#      pod and service CIDR overlaps alike.
#
# k331, what k320 and k322 left:
#  19. a key under gpu: other than enabled, driver, toolkit and amd is a line,
#      as under gpu.amd: and robocop: -- gpu: { enable: false } was a mapping
#      without enabled, so the GPU stack stayed on; and so is a key under
#      system: other than timezone, locale and ntp;
#  20. a system: that is no mapping is a line; timezone, locale and
#      ntp_enabled died on it inside Perl, and validate() said nothing;
#  21. the accessors of gpu:, gpu.amd: and system: refuse what validate() says
#      about the mapping they read, in its words, and read what it passes as
#      before: no reader turns the GPU stack on for a gpu.enable: false;
#  22. a pool that is not ssh takes no host: worker_ocpnodes reads host for an
#      ssh pool only, so beside hetzner or local it named no machine, and
#      nothing said so. One line whatever the host's shape, and such a host is
#      held against no network, as it is no machine's address.
#
# k340, what k315 and k331 left:
#  23. a control plane's public_ip and private_ip are strings, as its host is:
#      a list there was the address workers joined at, ARRAY(0x...);
#  24. join_host and cluster_status, which the readers of the control plane's
#      address ask, refuse a public_ip (or the host cluster_status falls back
#      to) that is no string, in validate()'s words;
#  25. ssh: is a mapping, its private_key and public_key strings; a string
#      there died inside Perl when ocp destroy fetched the key. The key path
#      accessors refuse what validate() says about ssh:, in its words -- but
#      for a key nothing reads under it (claim 31);
#  26. system.timezone and system.locale are strings: a list reached the
#      Rexfile and the provider CR, whose CRD types both as strings. The
#      system accessors refuse it as validate() does (claim 21);
#  27. kubernetes: is a mapping, and kubernetes.dist rke2 or k3s: rke3 passed,
#      installed RKE2 and went out to robocop as OCP_DISTRIBUTION.
#      distribution, which every reader of it asks, refuses what validate()
#      says, in its words;
#  28. an ocp.yaml that is empty or no mapping is one line naming the file --
#      validate()'s only one, and what every other reader stops with, as a
#      message to the user rather than "This is an internal error".
#
# k347, what k331 left at the control planes and the pools:
#  29. a key of a worker pool that is none of those read -- name, provider,
#      nodes, host, server_type, location, image, labels, taints -- is a line:
#      count: has been read by nothing since a5a598d, and a typo passed in
#      silence. count: has a hint naming what the pool's provider reads
#      instead. node_ip keeps its own line, and is no unknown key beside it.
#      Every key the list names is one worker_ocpnodes reads;
#  30. so is a key of a control plane that is none of those read. nodes: is
#      one in a list entry, which control_planes does not read it from, and it
#      and count: have a hint. What `ocp init` writes passes.
#
# k355, what k340 and k347 left:
#  31. a key under kubernetes: other than dist and version is a line, and so
#      is one under ssh: other than private_key and public_key: kubernetes:
#      { distribution: k3s } was read by nothing, and the cluster was RKE2.
#      distribution: with a distribution OCP installs says to write dist:. The
#      accessors that read kubernetes: refuse it in validate()'s words; ssh:'s
#      read on, validate()'s alone as a pool's key is (k347): ocp destroy
#      reads ssh: in dev mode;
#  32. kubernetes.version is a string, a release or empty: a list went to the
#      installer as a list. version refuses what validate() says about
#      it, in its words, and reads what it passes as before;
#  33. a control plane's name is a string, as its host is: a list matched no
#      recorded control plane, and the drift of its pinned public_ip went
#      unsaid. cluster_status, which hands it on, refuses one that is none, in
#      validate()'s words;
#  34. a key of a mapping in an ssh pool's nodes: list other than host is a
#      line; node_ip keeps its own. validate()'s alone: what ocp destroy asks
#      about the machines it reads (_pool_nodes_errors) does not refuse it.
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
                             workers => [ { name => 'w', provider => 'ssh', host => 'w.k296.test' }, 'foo' ] }) ],
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
            is $@, "$want\n", "$m: validate()'s line, not a Perl error";
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

my @SHAPES = shapes();
my @AT     = at();

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
    like $@, qr/^robocop\.security_level must be .*, not true\n\z/, 'in its words';
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
                             workers => [ { name => JSON::PP::true, provider => 'ssh', host => 'w.k305.test' } ] }) ],
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

subtest 'the accessors that refuse quote no Perl value either' => sub {
    for my $case ([ robocop_security_level => { robocop => { security_level => [ 'a' ] } } ],
                  [ robocop_image          => { robocop => { image => [ 'a' ] } } ],
                  [ gpu_driver             => { gpu => { driver => [ 'a' ] } } ]) {
        my ($m, $spec) = @$case;
        ok !eval { config_for({ control_planes => $local, %$spec })->$m; 1 }, "$m refuses a list";
        like $@, qr/, not a list(?:;|\n\z)/, "$m: says a list";
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
# Every reader of the switch asks robocop_enabled -- ocp apply and ocp keys
# secure, each after all of validate() (keys secure since k321), and the
# health gate. What validate() refuses, robocop_enabled refuses in the same
# words, so no reader turns a robocop: no on; what validate() passes, it reads
# as it always has.

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
                is $@, join('; ', @lines) . "\n", "$path: $shown -- in validate()'s words";
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
          "worker pool 'w': nodes[9] needs a host",
          # and name: is no key of a machine's (k355, claim 34)
          'workers[1].nodes[7].name: unknown key (must be host)' ],
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
                is $@, join('; ', @lines) . "\n", "$m, $path: $shown -- in validate()'s words";
                next;
            }
            my $want = defined $value ? ($value ? 1 : 0) : $default;
            is $got, $want, "$m, $path: $shown -- passes, and reads $want";
            ok defined $got && !ref $got, "$m, $path: $shown -- a plain 0 or 1, no boolean object";
        }
        is config_for({ control_planes => $local })->$m, $default, "$m: absent reads $default, as before";
    }
};

# --- 16. an ssh pool names its machines one way ----------------------------------------

my $NONE = "an ssh pool needs host (one machine) or nodes (a list of machines); "
    . 'with neither it gets no worker -- nodes: [] says it has none yet';
my $BOTH = 'an ssh pool takes host (one machine) or nodes (a list of machines), not both; '
    . 'beside nodes, host is not read';

subtest 'an ssh pool names its machines one way' => sub {
    my $ssh = sub { +{ name => 'w', provider => 'ssh', @_ } };

    is_deeply [ pool_errors($ssh->()) ], [ "worker pool 'w': $NONE" ], 'neither: a line, not no worker in silence';
    is_deeply [ pool_errors($ssh->(host => '')) ], [ "worker pool 'w': $NONE" ], "host: '' is no host";
    is_deeply [ pool_errors($ssh->(nodes => undef)) ], [ "worker pool 'w': $NONE" ], 'nodes: null is no nodes';
    # worker_ocpnodes reads a host as Perl does: 0 names no machine.
    is_deeply [ pool_errors($ssh->(host => 0)) ], [ "worker pool 'w': $NONE" ], 'host: 0 is no host';
    is_deeply [ pool_errors($ssh->(nodes => [ 'w1.k322.test', '0' ])) ],
        [ "worker pool 'w': nodes[2] must be a host name or IP address, or a mapping with host, not '0'" ],
        'a nodes entry 0 names no machine';
    is_deeply [ pool_errors($ssh->(nodes => [ { host => 0 } ])) ], [ "worker pool 'w': nodes[1] needs a host" ],
        'a nodes entry with host: 0 names none either';
    is_deeply [ pool_errors({ provider => 'ssh' }) ], [ 'worker pool: name required', "workers[1]: $NONE" ],
        'a pool without a name: by its place';
    is_deeply [ pool_errors($ssh->(nodes => [])) ], [],
        'nodes: [] passes: a pool with none yet, as nodes: 0 is for a counted pool';

    is_deeply [ pool_errors($ssh->(host => 'w0.k322.test', nodes => [ 'w1.k322.test' ])) ],
        [ "worker pool 'w': $BOTH" ], 'both: a line, host is not read';
    is_deeply [ pool_errors($ssh->(host => 'w0.k322.test', nodes => [])) ], [ "worker pool 'w': $BOTH" ],
        'host beside nodes: [] -- not read either, so no worker';

    is_deeply [ pool_errors($ssh->(host => 'w0.k322.test')) ], [], 'host alone passes';
    is_deeply [ pool_errors($ssh->(nodes => [ 'w1.k322.test', { host => 'w2.k322.test' } ])) ], [],
        'nodes alone passes';

    # A host or nodes of the wrong shape has its own line (claim 13), and no
    # "needs host" beside it.
    is_deeply [ pool_errors($ssh->(host => [ 'a' ])) ],
        [ "worker pool 'w': host must be a string (a host name or IP address), not a list" ], 'host: a list';
    is_deeply [ pool_errors($ssh->(host => JSON::PP::false)) ],
        [ "worker pool 'w': host must be a string (a host name or IP address), not false" ], 'host: false';
    is_deeply [ pool_errors($ssh->(host => 'w0.k322.test', nodes => 2)) ],
        [ "worker pool 'w': nodes must be a list of hosts for an ssh pool (each a host name or IP "
          . "address, or a mapping with host), not '2'" ],
        'host beside a count: the count is the mistake';

    is_deeply [ pool_errors({ name => 'w', provider => 'hetzner', server_type => 'cx22' }) ], [],
        'a pool that counts its machines and sets no nodes: one machine, as before';

    # ocp destroy asks _pool_nodes_errors alone how it reads the machines
    # (k323), and reads a host beside nodes as apply does: not at all. The
    # one-way lines are validate()'s, and stand between no cluster and its
    # teardown.
    my $c = config_for({ control_planes => $local });
    is_deeply [ $c->_pool_nodes_errors($ssh->(host => 'w0.k322.test', nodes => [ 'w1.k322.test' ]), 'w') ], [],
        '_pool_nodes_errors, which ocp destroy asks: host beside nodes is no line there';
    is_deeply [ $c->_pool_nodes_errors($ssh->(nodes => [ '0' ]), 'w') ],
        [ "w: nodes[1] must be a host name or IP address, or a mapping with host, not '0'" ],
        '... an entry that names no machine is';
};

# The claim in worker_ocpnodes' terms: a pool that passes gets a worker for
# each machine it names, and no other -- none only when it says nodes: [].
subtest 'every ssh pool validate() passes is the workers worker_ocpnodes makes of it' => sub {
    my $json = JSON::MaybeXS->new(canonical => 1);
    for my $p ({}, { host => '' }, { host => 'w0.k322.test' }, { nodes => undef }, { nodes => [] },
               { host => 'w0.k322.test', nodes => undef }, { nodes => [ 'w1.k322.test' ] },
               { nodes => [ 'w1.k322.test', { host => 'w2.k322.test' } ] },
               { host => 'w0.k322.test', nodes => [ 'w1.k322.test' ] }, { host => 'w0.k322.test', nodes => [] },
               { host => '', nodes => [ 'w1.k322.test' ] }, { host => 0 }, { host => '0', nodes => [ 'w1.k322.test' ] },
               { nodes => [ '0' ] }, { nodes => [ { host => '0' } ] }) {
        my $pool  = { name => 'w', provider => 'ssh', %$p };
        my $shown = $json->encode($p);
        my $c     = config_for({ control_planes => $local, workers => [ $pool ] });
        if (my @lines = $c->validate) {
            pass "$shown: refused (@lines)";
            next;
        }
        # A host Perl calls false ('', 0) names no machine: worker_ocpnodes
        # reads it so.
        my @named = grep { $_ } $pool->{host}, map { ref $_ ? $_->{host} : $_ } @{ $pool->{nodes} // [] };
        my @got = map { $_->{spec}{host} } OCP::Cmd::Apply::CR::worker_ocpnodes($c);
        ok @got || (ref $pool->{nodes} eq 'ARRAY' && !@{ $pool->{nodes} }),
            "$shown: has a worker, unless it says it has none";
        is_deeply [ sort @got ], [ sort @named ], "$shown: a worker for every machine it names, and no other";
    }
};

# --- 17. location and image -------------------------------------------------------------

subtest 'a location or image that is no string' => sub {
    my %what = (server_type => 'a Hetzner server type like cx32', location => 'a Hetzner location like fsn1',
                image => 'an image name like debian-13');
    my $hz = { provider => 'hetzner', location => 'fsn1', server_type => 'cx32' };
    for my $case ([ [ 'a' ], 'a list' ], [ { a => 1 }, 'a mapping' ],
                  [ JSON::PP::true, 'true' ], [ JSON::PP::false, 'false' ]) {
        my ($v, $shown) = @$case;
        for my $key (qw( location image )) {
            is_deeply [ errors_for({ control_planes => { %$hz, $key => $v } }) ],
                [ "control_planes[1].$key: must be a string ($what{$key}), not $shown" ],
                "control plane $key: $shown -- one line, no \"required\" beside it";
        }
        is_deeply [ errors_for({ control_planes => [ $local, { provider => 'ssh', host => 'cp.k322.test', image => $v } ] }) ],
            [ "control_planes[2].image: must be a string ($what{image}), not $shown" ],
            "control plane image: $shown -- whatever the provider";
        for my $key (qw( server_type location image )) {
            is_deeply [ pool_errors({ name => 'w', provider => 'hetzner', server_type => 'cx22', $key => $v }) ],
                [ "worker pool 'w': $key must be a string ($what{$key}), not $shown" ], "pool $key: $shown";
        }
    }
    is_deeply [ errors_for({ control_planes => { %$hz, image => 'debian-13' },
                             workers => [ { name => 'w', provider => 'hetzner', server_type => 'cx22',
                                            location => 'nbg1', image => 'debian-13', nodes => 2 } ] }) ],
        [], 'strings pass';
};

# --- 18. nodes: N says each line once ---------------------------------------------------------

subtest 'the mapping form with nodes: N says a line about its entry once' => sub {
    is_deeply [ errors_for({ control_planes => { provider => 'hetzner', nodes => 3 } }) ],
        [ 'control_planes[1]: server_type required for hetzner', 'control_planes[1]: location required for hetzner' ],
        'server_type and location required: once, not for each of the three';
    is_deeply [ errors_for({ control_planes => { provider => 'ssh', host => [ 'a' ], nodes => 3 } }) ],
        [ 'control_planes[1].host: must be a string (a host name or IP address), not a list' ],
        'a host that is a list: once';
    is_deeply [ errors_for({ control_planes => { provider => 'ssh', host => '10.42.0.5', nodes => 3 } }) ],
        [ 'network.pod_cidr (default 10.42.0.0/16) overlaps control_planes[1].host 10.42.0.5 '
          . '-- set network.pod_cidr to a range nothing else uses' ],
        'a host in the pod CIDR: once';
    is_deeply [ errors_for({ control_planes => { provider => 'ssh', host => '10.43.0.5', nodes => 3 } }) ],
        [ 'the service network (default 10.43.0.0/16) overlaps control_planes[1].host 10.43.0.5 '
          . '-- ocp.yaml has no key to move it; use an address outside it' ],
        'a host in the service network: once';
    is_deeply [ errors_for({ control_planes => [ { provider => 'hetzner' }, { provider => 'hetzner' } ] }) ],
        [ 'control_planes[1]: server_type required for hetzner', 'control_planes[1]: location required for hetzner',
          'control_planes[2]: server_type required for hetzner', 'control_planes[2]: location required for hetzner' ],
        'the list form: each entry is its own, and named as such';
};

# --- 19. the keys of gpu: and system: -------------------------------------------------------

my $GPU_KEYS    = 'enabled, driver, toolkit, or amd';
my $AMD_KEYS    = 'allocation, resource_naming, labeller, metrics, or integrated';
my $SYSTEM_KEYS = 'timezone, locale, or ntp';

subtest 'a key under gpu: or system: that is none of its own' => sub {
    is_deeply [ config_from_text("gpu:\n  enable: false\n")->validate ],
        [ "gpu.enable: unknown key (must be $GPU_KEYS)" ],
        'gpu: { enable: false } -- a typo of enabled, and a gpu mapping without enabled is on';
    is_deeply [ errors_for({ control_planes => $local,
                             gpu => { enabled => JSON::PP::true, nvidia => {}, Driver => 'operator' } }) ],
        [ "gpu.Driver: unknown key (must be $GPU_KEYS)", "gpu.nvidia: unknown key (must be $GPU_KEYS)" ],
        'one line each, sorted';
    is_deeply [ errors_for({ control_planes => $local, gpu => { enabled => JSON::PP::true, driver => 'operator',
                                                                 toolkit => JSON::PP::false, amd => {} } }) ],
        [], 'enabled, driver, toolkit and amd pass';
    is_deeply [ errors_for({ control_planes => $local, gpu => { amd => { alocation => 'dra' } } }) ],
        [ "gpu.amd.alocation: unknown key (must be $AMD_KEYS)" ], "gpu.amd: the line it had (k250)";

    is_deeply [ config_from_text("system:\n  time_zone: Europe/Berlin\n")->validate ],
        [ "system.time_zone: unknown key (must be $SYSTEM_KEYS)" ],
        'system: { time_zone: ... } -- a typo of timezone, which stayed UTC';
    is_deeply [ errors_for({ control_planes => $local, system => { hostname => 'cp1', NTP => JSON::PP::false } }) ],
        [ "system.NTP: unknown key (must be $SYSTEM_KEYS)", "system.hostname: unknown key (must be $SYSTEM_KEYS)" ],
        'one line each, sorted';
    is_deeply [ errors_for({ control_planes => $local, system => { timezone => 'Europe/Berlin',
                                                                    locale => 'de_DE.UTF-8', ntp => JSON::PP::false } }) ],
        [], 'timezone, locale and ntp pass';
};

# --- 20. a system: that is no mapping --------------------------------------------------------

subtest 'a system that is no mapping' => sub {
    my $is = 'system: must be a mapping (timezone, locale, ntp), not ';
    for my $case ([ 'Europe/Berlin', "'Europe/Berlin'" ], [ [ 'a' ], 'a list' ], [ JSON::PP::false, 'false' ],
                  [ JSON::PP::true, 'true' ], [ 7, "'7'" ]) {
        my ($v, $shown) = @$case;
        is_deeply [ errors_for({ control_planes => $local, system => $v }) ], [ "$is$shown" ], "system: $shown";
    }
    is_deeply [ errors_for({ control_planes => $local, system => undef }) ], [], 'null: as absent';
    is_deeply [ errors_for({ control_planes => $local, system => {} }) ], [], '{}: the defaults';
};

# --- 21. the accessors of gpu:, gpu.amd: and system: agree with validate() --------------------
#
# ocp apply reads them after validate(); ocp update, ocp node add and the
# drift check of ocp status read them without it. What validate() says about
# the mapping an accessor reads, the accessor refuses in the same words; what
# it passes, the accessor reads as before. (A gpu: or gpu.amd: that is no
# mapping is claim 2's, in the words it has had since k296 and k250.)

my %READS = (
    gpu       => [ qw( gpu_config gpu_enabled gpu_toolkit gpu_driver ) ],
    'gpu.amd' => [ qw( gpu_amd_config gpu_amd_allocation gpu_amd_resource_naming gpu_amd_labeller
                       gpu_amd_metrics gpu_amd_integrated ) ],
    system    => [ qw( system_config timezone locale ntp_enabled ) ],
);
# gpu.amd: is read through gpu:, so what gpu: says the gpu.amd accessors say too.
my %REFUSED_WITH = (gpu => [ 'gpu', 'gpu.amd' ], 'gpu.amd' => [ 'gpu.amd' ], system => [ 'system' ]);

subtest 'the gpu, gpu.amd and system accessors read their mapping the way validate() does' => sub {
    my $clean = config_for({ control_planes => $local });
    my %default = map { my $m = $_; ($m => scalar $clean->$m) } map { @$_ } values %READS;

    my @cases = (
        [ gpu       => { gpu => { enable => JSON::PP::false } } ],
        [ gpu       => { gpu => { enable => JSON::PP::false, toolkt => JSON::PP::false } } ],
        [ gpu       => { gpu => { enabled => JSON::PP::false, nvidia => { driver => 'operator' } } } ],
        [ 'gpu.amd' => { gpu => { amd => { alocation => 'dra' } } } ],
        [ 'gpu.amd' => { gpu => { amd => { allocation => 'dra', metric => JSON::PP::true } } } ],
        [ system    => { system => { time_zone => 'Europe/Berlin' } } ],
        [ system    => { system => { timezone => 'Europe/Berlin', ntpd => JSON::PP::false } } ],
        (map { [ system => { system => $_->[1] } ] } @SHAPES),
    );
    for my $case (@cases) {
        my ($path, $spec) = @$case;
        my $c     = config_for({ control_planes => $local, %$spec });
        my @lines = $c->validate;
        my $shown = JSON::MaybeXS->new(canonical => 1, convert_blessed => 1, allow_nonref => 1)
            ->encode($spec->{$path =~ s/\..*//r});
        my %refused = map { $_ => 1 } map { @{ $READS{$_} } } @lines ? @{ $REFUSED_WITH{$path} } : ();
        for my $m (sort keys %default) {
            my $got = eval { $c->$m };
            if ($refused{$m}) {
                ok !defined $got, "$m, $path: $shown -- refused, as validate() refuses it";
                is $@, join('; ', @lines) . "\n", "$m, $path: $shown -- in validate()'s words";
                next;
            }
            is $@, '', "$m, $path: $shown -- reads on";
            next if ref $default{$m};    # the mappings themselves
            is $got, $default{$m}, "$m, $path: $shown -- reads $default{$m}, as when absent";
        }
    }

    my $c = config_for({ control_planes => $local,
                         gpu => { enabled => JSON::PP::false, driver => 'operator', toolkit => JSON::PP::false,
                                  amd => { allocation => 'dra', resource_naming => 'mixed', labeller => JSON::PP::false,
                                           metrics => JSON::PP::true, integrated => JSON::PP::true } },
                         system => { timezone => 'Europe/Berlin', locale => 'de_DE.UTF-8', ntp => JSON::PP::false } });
    is_deeply [ $c->validate ], [], 'every key of the three, set';
    is_deeply { map { $_ => scalar $c->$_ } grep { !ref $default{$_} } sort keys %default },
        { gpu_enabled => 0, gpu_driver => 'operator', gpu_toolkit => 0, gpu_amd_allocation => 'dra',
          gpu_amd_resource_naming => 'mixed', gpu_amd_labeller => 0, gpu_amd_metrics => 1,
          gpu_amd_integrated => 1, timezone => 'Europe/Berlin', locale => 'de_DE.UTF-8', ntp_enabled => 0 },
        '... and each read as set';
};

# --- 22. a pool that is not ssh takes no host ---------------------------------------------------

my $HOST_ONLY = 'host is read for an ssh pool only, and names no machine of ';
my $HZ_HOST   = "${HOST_ONLY}a hetzner pool, whose servers Hetzner creates at the addresses it "
    . 'hands out -- remove host';
my $LO_HOST   = "${HOST_ONLY}a local pool, which is the machine ocp runs on -- remove host, "
    . 'or name another machine in an ssh pool';

subtest 'a pool that is not ssh takes no host' => sub {
    my $hz = sub { +{ name => 'w', provider => 'hetzner', server_type => 'cx22', @_ } };
    my $lo = sub { +{ name => 'w', provider => 'local', @_ } };

    is_deeply [ pool_errors($hz->(host => 'w1.k331.test')) ], [ "worker pool 'w': $HZ_HOST" ],
        'hetzner: a line, not a host dropped in silence';
    is_deeply [ pool_errors($hz->(host => '10.9.0.1', nodes => 2)) ], [ "worker pool 'w': $HZ_HOST" ],
        'hetzner, beside a count';
    is_deeply [ pool_errors($lo->(host => '10.9.0.1')) ], [ "worker pool 'w': $LO_HOST" ], 'local';
    is_deeply [ pool_errors({ provider => 'hetzner', server_type => 'cx22', host => '10.9.0.1' }) ],
        [ 'worker pool: name required', "workers[1]: $HZ_HOST" ], 'a pool without a name: by its place';

    # Not read whatever it is, so its shape is no line of its own.
    for my $case ([ [ 'a' ], 'a list' ], [ { a => 1 }, 'a mapping' ], [ JSON::PP::true, 'true' ],
                  [ JSON::PP::false, 'false' ], [ '', "''" ], [ 0, '0' ]) {
        my ($v, $shown) = @$case;
        is_deeply [ pool_errors($hz->(host => $v)) ], [ "worker pool 'w': $HZ_HOST" ],
            "hetzner, host: $shown -- the one line";
        is_deeply [ pool_errors($lo->(host => $v)) ], [ "worker pool 'w': $LO_HOST" ], "local, host: $shown";
    }
    is_deeply [ pool_errors($hz->(host => undef)) ], [], 'hetzner, host: null -- as absent';
    is_deeply [ pool_errors($hz->(nodes => 2)) ], [], 'hetzner without host: as before';
    is_deeply [ pool_errors($lo->()) ], [], 'local without host: as before';

    # It is no machine's address, so no network has to stay clear of it.
    for my $addr ('10.42.0.5', '10.43.0.5') {
        is_deeply [ pool_errors($hz->(host => $addr)) ], [ "worker pool 'w': $HZ_HOST" ],
            "hetzner, host $addr: no overlap line beside it";
    }
    is_deeply [ pool_errors({ name => 'w', provider => 'ssh', host => '10.42.0.5' }) ],
        [ "network.pod_cidr (default 10.42.0.0/16) overlaps worker pool 'w' host 10.42.0.5 "
          . '-- set network.pod_cidr to a range nothing else uses' ],
        'an ssh pool host is a machine address, as before';

    is_deeply [ pool_errors({ name => 'w', provider => 'aws', host => '10.9.0.1' }) ],
        [ "worker pool 'w': invalid provider 'aws' (must be " . OCP::Choices::or_list(OCP::Provider->types) . ')' ],
        'an unknown provider: its line, and no guess at what it reads';

    # Why: worker_ocpnodes drops it. Should one of them come to read it, this
    # refusal has to go with that.
    for my $pool ($hz->(host => 'w1.k331.test'), $lo->(host => 'w1.k331.test')) {
        my $c = config_for({ control_planes => $local, workers => [ $pool ] });
        my @nodes = OCP::Cmd::Apply::CR::worker_ocpnodes($c);
        ok @nodes, "$pool->{provider}: worker_ocpnodes makes its worker";
        is_deeply [ grep { defined } map { $_->{spec}{host} } @nodes ], [],
            "$pool->{provider}: ... and no OCPNode carries the host";
    }
};

# --- 23. a control plane's public_ip and private_ip -----------------------------------------------

my @NO_STRING = ([ [ '10.9.0.1' ], 'a list' ], [ { a => 1 }, 'a mapping' ],
                 [ JSON::PP::true, 'true' ], [ JSON::PP::false, 'false' ]);

subtest "a control plane's public_ip or private_ip that is no string" => sub {
    my $ssh = { provider => 'ssh', host => 'cp.k340.test' };
    for my $case (@NO_STRING) {
        my ($v, $shown) = @$case;
        for my $key (qw( public_ip private_ip )) {
            my $line = "$key: must be a string (an IP address), not $shown";
            is_deeply [ errors_for({ control_planes => { %$ssh, $key => $v } }) ],
                [ "control_planes[1].$line" ], "$key: $shown";
            is_deeply [ errors_for({ control_planes => [ $local, { %$ssh, $key => $v } ] }) ],
                [ "control_planes[2].$line" ], "$key: $shown -- the list form, by its place";
            is_deeply [ errors_for({ control_planes => { %$ssh, $key => $v, nodes => 3 } }) ],
                [ "control_planes[1].$line" ], "$key: $shown -- with nodes: 3, once";
        }
    }
    is_deeply [ errors_for({ control_planes => { %$ssh, public_ip => '10.9.0.1', private_ip => '10.9.0.2' } }) ],
        [], 'strings pass';
    is_deeply [ errors_for({ control_planes => { %$ssh, public_ip => undef } }) ], [], 'null: as absent';
};

# --- 24. join_host and cluster_status agree with validate() ---------------------------------------
#
# The control plane's address is read through these two: join_host for the
# URL workers join at, cluster_status for every command that reaches the
# cluster (ocp node add, ocp update, the drift remedies). What validate() says
# about the key they read, they refuse in its words; what it passes, they
# read as before.

subtest "join_host and cluster_status read the control plane's address the way validate() does" => sub {
    for my $key (qw( public_ip host )) {
        for my $shape (@SHAPES) {
            my ($shown, $value) = @$shape;
            my $cp = { provider => 'ssh', host => 'cp.k340.test', $key => $value };
            my $c  = config_for({ control_planes => $cp });
            my ($line) = grep { /\Acontrol_planes\[1\]\.\Q$key\E: / } $c->validate;

            # cluster_status reads public_ip, else host; join_host public_ip alone.
            for my $m ('cluster_status', ($key eq 'public_ip' ? 'join_host' : ())) {
                my $got = eval { $m eq 'join_host' ? $c->join_host('adv.k340.test') : $c->cluster_status };
                if (defined $line) {
                    ok !defined $got, "$m, $key: $shown -- refused, as validate() refuses it";
                    is $@, "$line\n", "$m, $key: $shown -- in validate()'s words";
                    next;
                }
                is $@, '', "$m, $key: $shown -- reads on";
                my $ip = $key eq 'public_ip' ? $value : undef;
                my $want = $m eq 'join_host'
                    ? (defined $ip && length $ip ? $ip : 'adv.k340.test')
                    : do { my $a = $ip // $cp->{host}; defined $a && length $a ? { name => 'cp-1', public_ip => $a } : {} };
                is_deeply $got, $want, "$m, $key: $shown -- as before";
            }
        }
    }
};

# --- 25. ssh: --------------------------------------------------------------------------------------

my %SSH_WHAT = (private_key => 'a path like .ocp/id_ed25519', public_key => 'a path like .ocp/id_ed25519.pub');

subtest 'an ssh: that is no mapping, or a key path that is no string' => sub {
    my $is = 'ssh: must be a mapping (private_key, public_key), not ';
    for my $case ([ 'foo', "'foo'" ], [ [ 'a' ], 'a list' ], [ JSON::PP::true, 'true' ],
                  [ JSON::PP::false, 'false' ], [ 7, "'7'" ]) {
        my ($v, $shown) = @$case;
        is_deeply [ errors_for({ control_planes => $local, ssh => $v }) ], [ "$is$shown" ], "ssh: $shown";
    }
    for my $key (sort keys %SSH_WHAT) {
        for my $case (@NO_STRING) {
            my ($v, $shown) = @$case;
            is_deeply [ errors_for({ control_planes => $local, ssh => { $key => $v } }) ],
                [ "ssh.$key: must be a string ($SSH_WHAT{$key}), not $shown" ], "ssh.$key: $shown";
        }
    }
    is_deeply [ errors_for({ control_planes => $local, ssh => { private_key => [ 'a' ], public_key => {} } }) ],
        [ "ssh.private_key: must be a string ($SSH_WHAT{private_key}), not a list",
          "ssh.public_key: must be a string ($SSH_WHAT{public_key}), not a mapping" ], 'one line each';
    is_deeply [ errors_for({ control_planes => $local, ssh => undef }) ], [], 'null: as absent';
    is_deeply [ errors_for({ control_planes => $local, ssh => {} }) ], [], '{}: the defaults';
    is_deeply [ errors_for({ control_planes => $local,
                             ssh => { private_key => 'keys/id', public_key => 'keys/id.pub' } }) ], [], 'paths pass';
};

subtest 'the ssh key accessors read ssh: the way validate() does' => sub {
    for my $at (grep { $_->[0] =~ /\Assh(?:\.|\z)/ } @AT) {
        my ($path, $spec_with) = @$at;
        for my $shape (@SHAPES) {
            my ($shown, $value) = @$shape;
            my $c     = config_for($spec_with->($value));
            # but a key nothing reads under it: validate()'s alone (k355, claim 31)
            my @lines = grep { !/\Assh\.[^:]+: unknown key / } $c->validate;
            my $ssh   = $c->spec->{ssh};
            my %set   = ref $ssh eq 'HASH' ? %$ssh : ();
            my %want  = (
                ssh_private_key_path => $c->project_dir->child($set{private_key} // '.ocp/id_ed25519')->stringify,
                ssh_public_key_path  => $c->project_dir->child($set{public_key} // '.ocp/id_ed25519.pub')->stringify,
            );
            for my $m (qw( ssh_config ssh_private_key_path ssh_public_key_path )) {
                my $got = eval { $c->$m };
                if (@lines) {
                    ok !defined $got, "$m, $path: $shown -- refused, as validate() refuses it";
                    is $@, join('; ', @lines) . "\n", "$m, $path: $shown -- in validate()'s words";
                    next;
                }
                is $@, '', "$m, $path: $shown -- reads on";
                is $got, $want{$m}, "$m, $path: $shown -- as before" if $want{$m};
            }
        }
    }
};

# --- 26. system.timezone and system.locale ---------------------------------------------------------

subtest 'a system.timezone or system.locale that is no string' => sub {
    my %what = (timezone => 'a time zone like Europe/Berlin', locale => 'a locale like en_US.UTF-8');
    for my $key (sort keys %what) {
        for my $case (@NO_STRING) {
            my ($v, $shown) = @$case;
            my $line = "system.$key: must be a string ($what{$key}), not $shown";
            is_deeply [ errors_for({ control_planes => $local, system => { $key => $v } }) ], [ $line ],
                "system.$key: $shown";
            my $c = config_for({ control_planes => $local, system => { $key => $v } });
            for my $m (qw( system_config timezone locale ntp_enabled )) {
                ok !eval { $c->$m; 1 }, "$m refuses system.$key: $shown";
                is $@, "$line\n", "$m: in validate()'s words";
            }
        }
    }
    is_deeply [ errors_for({ control_planes => $local, system => { timezone => [ 'a' ], time_zone => 'UTC' } }) ],
        [ "system.timezone: must be a string ($what{timezone}), not a list",
          "system.time_zone: unknown key (must be $SYSTEM_KEYS)" ], 'beside an unknown key: a line each';
    my $c = config_for({ control_planes => $local, system => { timezone => 'Europe/Berlin', locale => 'de_DE.UTF-8' } });
    is_deeply [ $c->validate ], [], 'strings pass';
    is_deeply [ $c->timezone, $c->locale ], [ 'Europe/Berlin', 'de_DE.UTF-8' ], '... and read as set';
};

# --- 27. kubernetes: and kubernetes.dist -----------------------------------------------------------

subtest 'kubernetes: is a mapping, and kubernetes.dist rke2 or k3s' => sub {
    my $is = 'kubernetes: must be a mapping (dist, version), not ';
    for my $case ([ 'rke2', "'rke2'; write kubernetes: { dist: rke2 }" ], [ 'k3s', "'k3s'; write kubernetes: { dist: k3s }" ],
                  [ 'foo', "'foo'" ], [ [ 'rke2' ], 'a list' ], [ JSON::PP::true, 'true' ], [ JSON::PP::false, 'false' ]) {
        my ($v, $shown) = @$case;
        is_deeply [ errors_for({ control_planes => $local, kubernetes => $v }) ], [ "$is$shown" ],
            'kubernetes: ' . (ref $v eq 'ARRAY' ? 'a list' : "$v");
    }
    my $dist = 'kubernetes.dist: invalid value %s (must be rke2 or k3s)';
    for my $case ([ 'rke3', "'rke3'" ], [ 'RKE2', "'RKE2'" ], [ '', "''" ], [ [ 'rke2' ], 'a list' ],
                  [ { rke2 => 1 }, 'a mapping' ], [ JSON::PP::true, 'true' ], [ JSON::PP::false, 'false' ]) {
        my ($v, $shown) = @$case;
        is_deeply [ errors_for({ control_planes => $local, kubernetes => { dist => $v } }) ],
            [ sprintf $dist, $shown ], "dist: $shown";
    }
    is_deeply [ config_from_text("kubernetes:\n  dist: rke3\n  version: ''\n")->validate ],
        [ sprintf $dist, "'rke3'" ], 'dist: rke3 as typed -- installed RKE2, and robocop was told rke3';
    for my $ok ('rke2', 'k3s', undef) {
        is_deeply [ errors_for({ control_planes => $local, kubernetes => { dist => $ok, version => '' } }) ], [],
            'dist: ' . ($ok // 'null') . ' passes';
    }
    is_deeply [ errors_for({ control_planes => $local, kubernetes => undef }) ], [], 'kubernetes: null passes';
};

subtest 'distribution reads kubernetes.dist the way validate() does' => sub {
    my @extra = ([ "'rke2'" => 'rke2' ], [ "'k3s'" => 'k3s' ], [ "'rke3'" => 'rke3' ]);
    for my $at (grep { $_->[0] =~ /\Akubernetes(?:\.dist)?\z/ } @AT) {
        my ($path, $spec_with) = @$at;
        for my $shape (@SHAPES, @extra) {
            my ($shown, $value) = @$shape;
            my $c     = config_for($spec_with->($value));
            my @lines = $c->validate;
            my $k8s   = $c->spec->{kubernetes};
            my $set   = ref $k8s eq 'HASH' ? $k8s->{dist} : undef;
            # kubernetes and version read the mapping only; its dist is distribution's.
            my @refusing = (qw( distribution supervisor_port ), ($path eq 'kubernetes' ? qw( kubernetes version ) : ()));
            for my $m (qw( distribution supervisor_port kubernetes version )) {
                my $got = eval { $c->$m };
                if (@lines && grep { $_ eq $m } @refusing) {
                    ok !defined $got, "$m, $path: $shown -- refused, as validate() refuses it";
                    is $@, join('; ', @lines) . "\n", "$m, $path: $shown -- in validate()'s words";
                    next;
                }
                is $@, '', "$m, $path: $shown -- reads on";
                my $d = $set // 'rke2';
                is $got, $d, "$m, $path: $shown -- reads $d" if $m eq 'distribution';
                is $got, ($d eq 'k3s' ? 6443 : 9345), "$m, $path: $shown -- as before" if $m eq 'supervisor_port';
            }
        }
    }
    is config_for({ control_planes => $local })->distribution, 'rke2', 'absent: rke2, as before';
};

# --- 28. an ocp.yaml that is no mapping ------------------------------------------------------------

sub config_from_file_text {
    my ($text) = @_;
    my $f = path($tmpdir)->child('f' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8($text);
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

my $SETTINGS = 'a mapping (name, control_planes and the other settings)';

subtest 'an ocp.yaml that is empty or no mapping is one line naming the file' => sub {
    for my $case ([ '' => undef ], [ "---\n" => undef ], [ "# nothing yet\n" => undef ], [ "~\n" => undef ],
                  [ "- name: k340\n" => 'a list' ], [ "k340\n" => "'k340'" ], [ "true\n" => 'true' ]) {
        my ($text, $shown) = @$case;
        my $c    = config_from_file_text($text);
        my $file = $c->file;
        my $line = defined $shown ? "$file: must be $SETTINGS, not $shown" : "$file is empty: it must be $SETTINGS";
        (my $typed = $text) =~ s/\n/\\n/g;
        is_deeply [ $c->validate ], [ $line ], "\"$typed\": validate()'s one line";
        for my $m (qw( spec name control_planes workers robocop_enabled distribution )) {
            ok !eval { $c->$m; 1 }, "\"$typed\": $m stops";
            is $@, "$line\n", "\"$typed\": $m -- with that line";
            my ($msg, $internal) = OCP::_clean_message($@);
            is $internal, 0, "\"$typed\": $m -- a message to the user, not an internal error";
        }
    }

    my $c = OCP::Config->new(file => path($tmpdir)->child('none.yaml')->stringify, ocp => $ocp);
    is $c->name, 'mycluster', 'no file at all: the default spec, as before';
    my $ok = config_from_file_text("name: k340\ncontrol_planes:\n  provider: local\n");
    is_deeply [ $ok->validate ], [], 'a mapping: as before';
};

subtest 'ocp apply --dry-run on a list: the line on STDERR, exit 1' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8("- name: k340\n  control_planes:\n    provider: local\n");
    my ($out, $err) = map { $dir->parent->child("k340-$$-$_") } qw( out err );
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
    is $e, "Error: ocp.yaml has 1 error:\n  - ocp.yaml: must be $SETTINGS, not a list\n"
        . "Nothing was done: ocp apply checks ocp.yaml before it touches a host or the cluster. "
        . "Fix the lines above and run it again.\n", 'the line, and no internal error';
};


# --- 29. a worker pool's keys ------------------------------------------------------------------------

my $POOL_KEYS   = 'name, provider, nodes, host, server_type, location, image, labels, or taints';
# No service since k357 (t/357-control-plane-service.t): nothing read it.
my $CP_KEYS     = 'provider, host, public_ip, private_ip, node_ip, server_type, location, image, or name';
my $CP_MAP_KEYS = 'provider, host, public_ip, private_ip, node_ip, server_type, location, image, name, '
    . 'or nodes';

subtest 'a key of a worker pool that is none of those read' => sub {
    my $hz = sub { +{ name => 'w', provider => 'hetzner', server_type => 'cx22', @_ } };

    is_deeply [ pool_errors($hz->(count => 3)) ],
        [ "workers[1].count: unknown key (must be $POOL_KEYS); count is read by nothing -- write "
          . 'nodes: N, how many machines the pool has; without nodes it has one' ],
        'count: 3 -- a line with the hint, not one machine in silence';
    is_deeply [ pool_errors({ name => 'w', provider => 'ssh', host => 'w1.k347.test', count => 2 }) ],
        [ "workers[1].count: unknown key (must be $POOL_KEYS); count is read by nothing -- an ssh pool "
          . 'names its machines: host for one, or nodes, a list of hosts' ],
        'an ssh pool: the hint says how it names its machines';
    is_deeply [ pool_errors($hz->(nodes => 2, lables => { a => 'b' }, Image => 'debian-13')) ],
        [ "workers[1].Image: unknown key (must be $POOL_KEYS)",
          "workers[1].lables: unknown key (must be $POOL_KEYS)" ],
        'a typo: one line each, sorted';
    is_deeply [ pool_errors($hz->(), $hz->(name => 'v', count => 2)) ],
        [ "workers[2].count: unknown key (must be $POOL_KEYS); count is read by nothing -- write "
          . 'nodes: N, how many machines the pool has; without nodes it has one' ],
        'named by its place, as workers[2].name is';

    my @e = pool_errors($hz->(node_ip => '10.0.0.9'));
    is scalar(@e), 1, 'node_ip: one line' or diag explain \@e;
    like $e[0], qr/\Aworker pool 'w': node_ip cannot be set on a pool/, '... its own, not an unknown key';

    my %all = (name => 'w', provider => 'hetzner', nodes => 2, server_type => 'cx22', location => 'fsn1',
               image => 'debian-13', labels => { 'ai.citilan.de/node-class' => 'general' },
               taints => [ 'dedicated=ml:NoSchedule' ]);
    is_deeply [ pool_errors({ %all }) ], [], 'hetzner: every key the list names passes';
    is_deeply [ pool_errors({ name => 'w', provider => 'ssh', nodes => [ 'w1.k347.test', { host => 'w2.k347.test' } ] }) ],
        [], 'ssh with nodes';
    is_deeply [ pool_errors({ name => 'w', provider => 'ssh', host => 'w1.k347.test' }) ], [], 'ssh with host';
    is_deeply [ pool_errors({ name => 'w', provider => 'local' }) ], [], 'local';

    # Why: each key the list names reaches the pool's OCPNodes, and count
    # reaches none of them. Should worker_ocpnodes come to read another, the
    # list has to take it.
    my @nodes = OCP::Cmd::Apply::CR::worker_ocpnodes(config_for({ control_planes => $local,
                                                                  workers => [ { %all } ] }));
    is_deeply [ map { $_->{metadata}{name} } @nodes ], [ 'w-1', 'w-2' ], 'name and nodes: the OCPNodes';
    is_deeply [ map { $_->{spec}{providerRef} } @nodes ], [ ('hetzner-default') x 2 ], 'provider';
    for my $n (@nodes) {
        is_deeply [ @{ $n->{spec} }{qw( serverType location image )} ], [ 'cx22', 'fsn1', 'debian-13' ],
            "$n->{metadata}{name}: server_type, location and image";
        is_deeply $n->{spec}{labels}, { 'ai.citilan.de/node-class' => 'general' }, "$n->{metadata}{name}: labels";
        is scalar @{ $n->{spec}{taints} }, 1, "$n->{metadata}{name}: taints";
    }
    my @ssh = OCP::Cmd::Apply::CR::worker_ocpnodes(config_for({ control_planes => $local,
        workers => [ { name => 'w', provider => 'ssh', host => 'w1.k347.test' } ] }));
    is_deeply [ map { $_->{spec}{host} } @ssh ], [ 'w1.k347.test' ], 'host';
    my @counted = OCP::Cmd::Apply::CR::worker_ocpnodes(config_for({ control_planes => $local,
                                                                    workers => [ $hz->(count => 3) ] }));
    is scalar(@counted), 1, 'count: 3 -- one OCPNode, as without it';
};

# --- 30. a control plane's keys ---------------------------------------------------------------------

subtest 'a key of a control plane that is none of those read' => sub {
    is_deeply [ errors_for({ control_planes => { provider => 'local', count => 3 } }) ],
        [ "control_planes[1].count: unknown key (must be $CP_MAP_KEYS); count is read by nothing -- "
          . 'how many control planes there are is nodes: N' ],
        'the mapping form: count, and nodes among the keys';
    is_deeply [ errors_for({ control_planes => [ $local, { provider => 'local', count => 2 } ] }) ],
        [ "control_planes[2].count: unknown key (must be $CP_KEYS); count is read by nothing -- "
          . 'a list has one entry per control plane' ],
        'a list entry: count, by its place';
    is_deeply [ errors_for({ control_planes => [ { provider => 'local', nodes => 3 } ] }) ],
        [ "control_planes[1].nodes: unknown key (must be $CP_KEYS); nodes: N is read on a "
          . 'control_planes mapping only -- a list has one entry per control plane' ],
        'nodes: in a list entry';
    is scalar @{ config_for({ control_planes => [ { provider => 'local', nodes => 3 } ] })->control_planes }, 1,
        '... which stands for one control plane, as nothing reads it';
    is_deeply [ errors_for({ control_planes => { provider => 'local', nodes => 3 } }) ], [],
        'nodes: 3 on the mapping passes';
    is_deeply [ errors_for({ control_planes => { provider => 'local', nodes => 3, hots => 'cp.k347.test' } }) ],
        [ "control_planes[1].hots: unknown key (must be $CP_MAP_KEYS)" ],
        'nodes: 3 -- said once, not once per control plane';
    is_deeply [ errors_for({ control_planes => { provider => 'ssh', host => 'cp.k347.test', Host => 'x',
                                                 publicip => '10.9.0.5' } }) ],
        [ "control_planes[1].Host: unknown key (must be $CP_MAP_KEYS)",
          "control_planes[1].publicip: unknown key (must be $CP_MAP_KEYS)" ],
        'a typo: one line each, sorted';

    is_deeply [ errors_for({ control_planes => { provider => 'hetzner', server_type => 'cx32', location => 'fsn1',
                                                 image => 'debian-13', public_ip => '10.9.0.5',
                                                 private_ip => '10.8.0.5', node_ip => '10.8.0.5',
                                                 name => 'police1' } }) ],
        [], 'hetzner: every key the list names passes';
    is_deeply [ errors_for({ control_planes => [ { provider => 'ssh', host => 'cp1.k347.test', name => 'cp1' },
                                                 { provider => 'local' } ] }) ],
        [], 'a list of them';

    # What ocp init writes.
    for my $opts ([ provider => 'hetzner' ], [ provider => 'ssh', host => 'cp.k347.test' ],
                  [ provider => 'local' ]) {
        my $f = path($tmpdir)->child('init' . int(rand(1_000_000)) . '.yaml');
        OCP::Config->write_spec($f->stringify, name => 'k347', @$opts);
        is_deeply [ OCP::Config->new(file => $f->stringify, ocp => $ocp)->validate ], [],
            "ocp init --provider $opts->[1]: passes";
    }
};

# --- 31. the keys of kubernetes: and ssh: ------------------------------------------------------------

my $K8S_KEYS = 'dist or version';
my $SSH_KEYS = 'private_key or public_key';

subtest 'a key under kubernetes: or ssh: that is none of its own' => sub {
    is_deeply [ config_from_text("kubernetes:\n  distribution: k3s\n")->validate ],
        [ "kubernetes.distribution: unknown key (must be $K8S_KEYS); write kubernetes: { dist: k3s }" ],
        'kubernetes: { distribution: k3s } as typed -- read by nothing, and the cluster was RKE2';
    for my $case ([ 'rke3', "'rke3'" ], [ [ 'k3s' ], 'a list' ], [ undef, 'null' ]) {
        my ($v, $shown) = @$case;
        is_deeply [ errors_for({ control_planes => $local, kubernetes => { distribution => $v } }) ],
            [ "kubernetes.distribution: unknown key (must be $K8S_KEYS)" ],
            "distribution: $shown -- no distribution OCP installs, no hint";
    }
    is_deeply [ errors_for({ control_planes => $local, kubernetes => { dist => 'k3s', Version => 'v1', cni => 'cilium' } }) ],
        [ "kubernetes.Version: unknown key (must be $K8S_KEYS)", "kubernetes.cni: unknown key (must be $K8S_KEYS)" ],
        'one line each, sorted';
    is_deeply [ errors_for({ control_planes => $local, kubernetes => { dist => 'rke3', distribution => 'k3s' } }) ],
        [ "kubernetes.dist: invalid value 'rke3' (must be rke2 or k3s)",
          "kubernetes.distribution: unknown key (must be $K8S_KEYS); write kubernetes: { dist: k3s }" ],
        'beside a dist of its own: a line each';

    is_deeply [ errors_for({ control_planes => $local, ssh => { privat_key => 'keys/id' } }) ],
        [ "ssh.privat_key: unknown key (must be $SSH_KEYS)" ],
        'ssh: { privat_key: ... } -- the default key stayed in force';
    is_deeply [ errors_for({ control_planes => $local, ssh => { private_key => [ 'a' ], user => 'root' } }) ],
        [ "ssh.private_key: must be a string ($SSH_WHAT{private_key}), not a list",
          "ssh.user: unknown key (must be $SSH_KEYS)" ],
        'beside a path that is no string: a line each';

    # What ocp init writes.
    my $f = path($tmpdir)->child('init355.yaml');
    OCP::Config->write_spec($f->stringify, name => 'k355', provider => 'hetzner', dist => 'k3s',
                            version => 'v1.36.4+k3s1');
    is_deeply [ OCP::Config->new(file => $f->stringify, ocp => $ocp)->validate ], [], 'ocp init --dist k3s --version: passes';
};

# The mapping kubernetes hands on is read through it (k340); a key nothing
# reads under it is every reader's refusal, as gpu_config's is (claim 21).
subtest 'the kubernetes accessors read a key nothing reads the way validate() does' => sub {
    my $K8S_READERS = [ qw( kubernetes distribution supervisor_port version ) ];
    for my $k8s ({ distribution => 'k3s' }, { dist => 'k3s', cni => 'cilium' }, { distribution => undef }) {
        my $c     = config_for({ control_planes => $local, kubernetes => $k8s });
        my @lines = $c->validate;
        is scalar(@lines), 1, 'kubernetes: ' . join(', ', sort keys %$k8s) . ' -- one line' or diag explain \@lines;
        for my $m (@$K8S_READERS) {
            ok !eval { $c->$m; 1 }, "$m refuses kubernetes: { " . join(', ', sort keys %$k8s) . ' }';
            is $@, "$lines[0]\n", "$m: in validate()'s words";
        }
    }
    my $c = config_for({ control_planes => $local, kubernetes => { dist => 'k3s', version => 'v1.36.4+k3s1' } });
    is_deeply [ $c->validate ], [], 'dist and version pass';
    is_deeply [ map { $c->$_ } qw( distribution supervisor_port version ) ], [ 'k3s', 6443, 'v1.36.4+k3s1' ],
        '... and read as set';
};

# Not so under ssh:: ocp destroy reads it in dev mode (OCP::ClusterKey), and
# refused there it skips the uninstall on the ssh machines. A key nothing reads
# is validate()'s alone, as a pool's is (k347).
subtest 'the ssh key accessors read on over a key nothing reads' => sub {
    for my $ssh ({ privat_key => 'keys/id' }, { private_key => 'keys/id', user => 'root' }) {
        my $c    = config_for({ control_planes => $local, ssh => $ssh });
        my $keys = join ', ', sort keys %$ssh;
        my @lines = $c->validate;
        is scalar(@lines), 1, "ssh: { $keys } -- validate() has its line" or diag explain \@lines;
        my %want = (
            ssh_config           => $ssh,
            ssh_private_key_path => $c->project_dir->child($ssh->{private_key} // '.ocp/id_ed25519')->stringify,
            ssh_public_key_path  => $c->project_dir->child('.ocp/id_ed25519.pub')->stringify,
        );
        for my $m (sort keys %want) {
            my $got = eval { $c->$m };
            is $@, '', "$m, ssh: { $keys } -- reads on";
            is_deeply $got, $want{$m}, "$m, ssh: { $keys } -- as before";
        }
    }
};

# --- 32. kubernetes.version ------------------------------------------------------------------------

my $VERSION_WHAT = 'a release like v1.36.4+rke2r1 or v1.36.4+k3s1; empty for the one OCP pins';

subtest 'a kubernetes.version that is no string' => sub {
    for my $case (@NO_STRING) {
        my ($v, $shown) = @$case;
        is_deeply [ errors_for({ control_planes => $local, kubernetes => { dist => 'rke2', version => $v } }) ],
            [ "kubernetes.version: must be a string ($VERSION_WHAT), not $shown" ], "version: $shown";
    }
    is_deeply [ config_from_text("kubernetes:\n  version: [ v1.36.4+rke2r1 ]\n")->validate ],
        [ "kubernetes.version: must be a string ($VERSION_WHAT), not a list" ],
        'a list as typed -- went to the installer as a list';
    is_deeply [ errors_for({ control_planes => $local, kubernetes => { dist => 'rke3', version => {}, distro => 'k3s' } }) ],
        [ "kubernetes.dist: invalid value 'rke3' (must be rke2 or k3s)",
          "kubernetes.version: must be a string ($VERSION_WHAT), not a mapping",
          "kubernetes.distro: unknown key (must be $K8S_KEYS)" ],
        'beside a dist and a key nothing reads: a line each';
    # Under no dist, which is rke2: a k3s release is refused there since k376
    # (t/376-version-of-the-dist.t), a version without a suffix is not.
    for my $ok ('v1.36.4+rke2r1', 'v1.31.3', '', undef) {
        is_deeply [ errors_for({ control_planes => $local, kubernetes => { version => $ok } }) ], [],
            'version: ' . (defined $ok ? "'$ok'" : 'null') . ' passes';
    }
};

subtest 'version reads kubernetes.version the way validate() does' => sub {
    my @extra = ([ "'v1.36.4+k3s1'" => 'v1.36.4+k3s1' ], [ "''" => '' ]);
    for my $at (grep { $_->[0] eq 'kubernetes.version' } @AT) {
        my ($path, $spec_with) = @$at;
        for my $shape (@SHAPES, @extra) {
            my ($shown, $value) = @$shape;
            my $c     = config_for($spec_with->($value));
            my @lines = $c->validate;
            for my $m (qw( version kubernetes distribution supervisor_port )) {
                my $got = eval { $c->$m };
                # version's line is version's alone: the mapping and its dist read on.
                if (@lines && $m eq 'version') {
                    ok !defined $got, "$m, $path: $shown -- refused, as validate() refuses it";
                    is $@, join('; ', @lines) . "\n", "$m, $path: $shown -- in validate()'s words";
                    next;
                }
                is $@, '', "$m, $path: $shown -- reads on";
                is $got, $value // '', "$m, $path: $shown -- as before" if $m eq 'version';
                is $got, 'rke2', "$m, $path: $shown -- rke2" if $m eq 'distribution';
            }
        }
    }
};

# --- 33. a control plane's name --------------------------------------------------------------------

my $CP_NAME_WHAT = "the control plane's name, like police1";

subtest "a control plane's name that is no string" => sub {
    my $ssh = { provider => 'ssh', host => 'cp.k355.test' };
    for my $case (@NO_STRING) {
        my ($v, $shown) = @$case;
        my $line = "name: must be a string ($CP_NAME_WHAT), not $shown";
        is_deeply [ errors_for({ control_planes => { %$ssh, name => $v } }) ],
            [ "control_planes[1].$line" ], "name: $shown";
        is_deeply [ errors_for({ control_planes => [ $local, { %$ssh, name => $v } ] }) ],
            [ "control_planes[2].$line" ], "name: $shown -- the list form, by its place";
        is_deeply [ errors_for({ control_planes => { %$ssh, name => $v, nodes => 3 } }) ],
            [ "control_planes[1].$line" ], "name: $shown -- with nodes: 3, once";
    }
    is_deeply [ errors_for({ control_planes => { %$ssh, name => 'police1' } }) ], [], 'a string passes';
    is_deeply [ errors_for({ control_planes => { %$ssh, name => undef } }) ], [], 'null: as absent';
};

subtest "cluster_status reads the control plane's name the way validate() does" => sub {
    for my $shape (@SHAPES) {
        my ($shown, $value) = @$shape;
        my $c = config_for({ control_planes => { provider => 'ssh', host => 'cp.k355.test', name => $value } });
        my ($line) = grep { /\Acontrol_planes\[1\]\.name: / } $c->validate;
        my $got = eval { $c->cluster_status };
        if (defined $line) {
            ok !defined $got, "name: $shown -- refused, as validate() refuses it";
            is $@, "$line\n", "name: $shown -- in validate()'s words";
            next;
        }
        is $@, '', "name: $shown -- reads on";
        is_deeply $got, { name => $value // 'cp-1', public_ip => 'cp.k355.test' }, "name: $shown -- as before";
    }
};

# --- 34. the keys of an ssh pool's machine ---------------------------------------------------------

subtest "a key of an ssh pool's machine that is not host" => sub {
    my $ssh = sub { +{ name => 'w', provider => 'ssh', nodes => [ @_ ] } };

    is_deeply [ pool_errors($ssh->({ host => 'w1.k355.test', name => 'gpu1' })) ],
        [ 'workers[1].nodes[1].name: unknown key (must be host)' ],
        'name: -- the worker is named after its host';
    is_deeply [ pool_errors($ssh->('w0.k355.test', { host => 'w1.k355.test', labels => {}, Host => 'x' })) ],
        [ 'workers[1].nodes[2].Host: unknown key (must be host)',
          'workers[1].nodes[2].labels: unknown key (must be host)' ],
        'by its place, one line each, sorted';
    is_deeply [ pool_errors({ name => 'v', provider => 'local' }, $ssh->({ hots => 'w1.k355.test' })) ],
        [ "worker pool 'w': nodes[1] needs a host", 'workers[2].nodes[1].hots: unknown key (must be host)' ],
        'a typo of host: no host, and a key nothing reads';

    my @e = pool_errors($ssh->({ host => 'w1.k355.test', node_ip => '10.0.0.9' }));
    is scalar(@e), 1, 'node_ip: one line' or diag explain \@e;
    like $e[0], qr/\Aworker pool 'w': nodes\[1\]\.node_ip is not read from a pool's nodes/,
        '... its own, not an unknown key';

    is_deeply [ pool_errors({ name => 'w', provider => 'hetzner', server_type => 'cx22',
                              nodes => [ { host => 'w1.k355.test', name => 'gpu1' } ] }) ],
        [ "worker pool 'w': nodes must be a whole number (how many machines the pool has), not a list" ],
        'a pool that counts its machines: the list has its line, its entries none';
    is_deeply [ pool_errors($ssh->('w0.k355.test', { host => 'w1.k355.test' })) ], [], 'host passes';

    # validate()'s alone: ocp destroy asks _pool_nodes_errors how it reads the
    # machines, and a key nothing reads holds up no teardown (k323).
    my $pool = $ssh->({ host => 'w1.k355.test', name => 'gpu1' });
    my $c = config_for({ control_planes => $local, workers => [ $pool ] });
    is_deeply [ $c->_pool_nodes_errors($pool, "worker pool 'w'") ], [], 'not what ocp destroy asks';

    # Why: worker_ocpnodes reads host from the entry and nothing else.
    my @n = OCP::Cmd::Apply::CR::worker_ocpnodes($c);
    is_deeply [ map { $_->{metadata}{name} } @n ], [ 'w1' ], 'the worker is named after its host, not name:';
    is_deeply [ map { $_->{spec}{host} } @n ], [ 'w1.k355.test' ], '... and joined at it';
};

done_testing;

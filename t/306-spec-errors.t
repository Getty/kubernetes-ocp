#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use JSON::PP ();
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';
use OCP;
use OCP::Choices;
use OCP::Config;
use OCP::Provider;

#
# k306, step 1: spec_errors(@paths) answers what validate() says at the key
# paths a command reads, so that a command can refuse on what it reads
# without running all of validate(). Nothing refuses through it yet; the
# lines are validate()'s own, built once in the producers both read.
#
# The claims here:
#   1. spec_errors at every path it answers for is validate()'s lines in
#      validate()'s order, minus what validate() says alone -- told apart
#      here by an oracle of its own, so a line that moves into or out of a
#      path fails;
#   2. none of those is a key nothing reads, a "required" line, a bound,
#      node_ip, labels or taints: no path but gpu returns such a line;
#   3. a path names one place: an entry by its number from 1, or every entry
#      with *, which is each entry's answer in turn; nothing under a section
#      or an entry that has a line of its own shape, nothing past the last
#      entry, and the mapping form with nodes: N is one entry, said once;
#   4. gpu is every line validate() has under gpu:, its switches with them,
#      and no other switch;
#   5. lines come in validate()'s order and once, however the paths are
#      asked; a path spec_errors does not answer for croaks, as a caller's
#      mistake; an ocp.yaml that is no mapping stops it with the file's line,
#      as it stops every reader.
#

local @ARGV = ();
my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

# Through a file, as ocp reads it: YAML booleans come back as JSON::PP::Boolean.
sub config_for {
    my ($spec) = @_;
    my $f = path($tmpdir)->child('c' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8(YAML::XS::Dump({ name => 'k306', %$spec }));
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

my @CP_KEYS   = qw( provider host public_ip private_ip server_type location image name );
my @POOL_KEYS = qw( name provider nodes host server_type location image );

# Every path spec_errors answers for, each entry by *.
my @ALL = ('name', 'control_planes', 'control_planes[*]', (map { "control_planes[*].$_" } @CP_KEYS),
           'workers', 'workers[*]', (map { "workers[*].$_" } @POOL_KEYS), 'gpu');

# The oracle for claim 1: a line of validate()'s that is at some path, read
# off its words.
my $pool = qr/(?:worker pool '[^']*'|workers\[\d+\])/;
my $cp_key   = join '|', grep { $_ ne 'provider' } @CP_KEYS;
my $pool_key = join '|', qw( host server_type location image );
my @AT_A_PATH = (
    qr/\Aname: must be a string/,
    qr/\Acontrol_planes: must be a mapping/,
    qr/\Acontrol_planes\[\d+\]: must be a mapping/,
    qr/\Acontrol_planes\[\d+\]: invalid provider/,
    qr/\Acontrol_planes\[\d+\]\.(?:$cp_key): must be a string/,
    qr/\Aworkers: must be a list/,
    qr/\Aworkers\[\d+\]: must be a mapping/,
    qr/\Aworkers\[\d+\]\.name: must be a string/,
    qr/\A$pool: (?:provider required|invalid provider)/,
    qr/\A$pool: (?:$pool_key) must be a string/,
    qr/\A$pool: nodes(?: must |\[\d+\](?:\.host must | needs a host\z| must be ))/,
    qr/\Agpu[.:]/,
);
sub at_a_path { my ($line) = @_; return grep { $line =~ $_ } @AT_A_PATH }

my $local = { provider => 'local' };
my $ssh   = sub { +{ name => 'w', provider => 'ssh', host => '10.9.0.1', @_ } };
my $hz    = sub { +{ name => 'w', provider => 'hetzner', server_type => 'cx22', @_ } };

# Each shape validate() has a line for at a path, and one beside it of each
# kind it says alone.
my @CORPUS = (
    [ 'a name that is a list'   => { name => [ 'a' ] } ],
    [ 'a name that is a mapping' => { name => { a => 1 } } ],
    [ 'an empty name'           => { name => '' } ],
    [ 'control_planes neither form' => { control_planes => 'foo' } ],
    [ 'an empty control_planes list' => { control_planes => [] } ],
    [ 'an entry that is no mapping' => { control_planes => [ $local, 'foo', [ 'a' ], undef ] } ],
    [ 'nodes: 3 with a host list' => { control_planes => { provider => 'ssh', host => [ 'a' ], nodes => 3 } } ],
    [ 'nodes: 3 with node_ip' => { control_planes => { provider => 'local', node_ip => '10.0.0.1', nodes => 3 } } ],
    [ 'nodes: foo'            => { control_planes => { provider => 'local', nodes => 'foo' } } ],
    [ 'nodes: 9'              => { control_planes => { provider => 'local', nodes => 9 } } ],
    [ 'each key a list'       => { control_planes => [
          { provider => 'ssh', map { $_ => [ 'a' ] } qw( host public_ip private_ip server_type location image name ) } ] } ],
    [ 'each key a mapping, hetzner' => { control_planes => [
          { provider => 'hetzner', map { $_ => { a => 1 } } qw( server_type location image name ) } ] } ],
    [ 'an unknown provider'   => { control_planes => [ { provider => 'foo' }, { provider => JSON::PP::true } ] } ],
    [ 'hetzner without server_type, ssh without host'
                              => { control_planes => [ { provider => 'hetzner' }, { provider => 'ssh' } ] } ],
    [ 'unknown keys of a control plane' => { control_planes => [ { %$local, count => 3, hots => 'a' } ] } ],
    [ 'node_ip, bad and clashing' => { control_planes => [ { %$local, node_ip => 'x' },
          { %$local, node_ip => '10.0.0.1' }, { %$local, node_ip => '10.0.0.1' } ] } ],
    [ 'eight control planes'  => { control_planes => [ ($local) x 7, { provider => 'foo' } ] } ],
    [ 'workers that is no list' => { control_planes => $local, workers => 'foo' } ],
    [ 'workers a mapping'     => { control_planes => $local, workers => { a => 1 } } ],
    [ 'a pool that is no mapping' => { control_planes => $local, workers => [ 'just-a-string', $ssh->() ] } ],
    [ 'pool names'            => { control_planes => $local, workers => [
          $ssh->(name => [ 'a' ]), $ssh->(name => undef), $ssh->(name => '') ] } ],
    [ 'pool providers'        => { control_planes => $local, workers => [
          { name => 'a' }, { name => 'b', provider => 'foo' }, { name => 'c', provider => JSON::PP::false },
          { name => 'd', provider => [ 'ssh' ], host => [ 'h' ] } ] } ],
    [ 'pool keys nothing reads' => { control_planes => $local, workers => [
          $hz->(count => 2), $ssh->(count => 2, hots => 'x') ] } ],
    [ 'a host on a hetzner pool, an ssh pool, an unknown one' => { control_planes => $local, workers => [
          $hz->(host => [ 'a' ]), $ssh->(host => [ 'a' ]), { name => 'u', provider => 'aws', host => [ 'a' ] } ] } ],
    [ 'pool string keys'      => { control_planes => $local, workers => [
          $hz->(map { $_ => [ 'a' ] } qw( server_type location image )) ] } ],
    [ 'ssh nodes entries'     => { control_planes => $local, workers => [
          { name => 'w', provider => 'ssh', nodes => [ { host => [ 'a' ] }, 0, {}, 'ok', { host => 'h', name => 'x' },
                                                     { host => 'h', node_ip => '10.0.0.9' } ] } ] } ],
    [ 'ssh nodes a count, ssh neither, ssh both' => { control_planes => $local, workers => [
          { name => 'a', provider => 'ssh', nodes => 3 }, { name => 'b', provider => 'ssh' },
          { name => 'c', provider => 'ssh', host => 'h', nodes => [ 'x' ] } ] } ],
    [ 'hetzner nodes'         => { control_planes => $local, workers => [
          $hz->(name => 'a', nodes => [ 'a', 'b' ]), $hz->(name => 'b', nodes => 'abc'), $hz->(name => 'c', nodes => 2) ] } ],
    [ 'nodes under an unknown provider' => { control_planes => $local, workers => [
          { name => 'w', provider => 'aws', nodes => [ 'a' ] } ] } ],
    [ 'labels, taints, node_ip' => { control_planes => $local, workers => [
          $ssh->(labels => 'x', taints => 'y', node_ip => '10.0.0.5') ] } ],
    [ 'gpu false'             => { gpu => JSON::PP::false } ],
    [ 'gpu a string'          => { gpu => 'x' } ],
    [ 'gpu keys'              => { gpu => { enable => 1, driver => 'foo', enabled => 'yes', toolkit => 'no' } } ],
    [ 'gpu.amd a string'      => { gpu => { amd => 'x' } } ],
    [ 'gpu.amd keys'          => { gpu => { amd => { foo => 1, allocation => 'x', resource_naming => [ 'a' ],
                                                     metrics => 'no', labeller => 'off' } } } ],
    [ 'the switches beside gpu' => { nocert => 'no', lbipam => 'x', system => { ntp => 'yes' } } ],
    [ 'all of it at once'     => {
          name => [ 'a' ],
          control_planes => [ { provider => 'foo', host => [ 'a' ], count => 1 }, 'x' ],
          gpu => { driver => 'x', enabled => 'no' }, nocert => 'no',
          workers => [ 'x', { name => 'w', provider => 'ssh', nodes => [ {} ], host => 'h', count => 1 },
                       { provider => 'hetzner', server_type => [ 'a' ], nodes => 'x' } ] } ],
);

# Whether @$sub is @$all with lines left out, in order.
sub in_order {
    my ($sub, $all) = @_;
    my $i = 0;
    for my $line (@$sub) {
        $i++ while $i < @$all && $all->[$i] ne $line;
        return 0 if $i++ >= @$all;
    }
    return 1;
}

# --- 1. and 2. validate()'s lines at a path ---------------------------------

subtest "every path: validate()'s lines there, in its order" => sub {
    for my $case (@CORPUS) {
        my ($what, $spec) = @$case;
        my $c = config_for($spec);
        my @all  = $c->validate;
        my @here = $c->spec_errors(@ALL);
        ok scalar(@all), "$what: validate() has a line";
        ok in_order(\@here, \@all), "$what: in validate()'s order" or diag explain [ \@here, \@all ];
        is_deeply \@here, [ grep { at_a_path($_) } @all ], "$what: the lines at a path, no other"
            or diag explain \@all;
    }

    # Each path has a line in some shape above, and so does each word of
    # the oracle: none of them is left unasked.
    for my $path (@ALL) {
        ok scalar(grep { config_for($_->[1])->spec_errors($path) } @CORPUS), "$path: asked";
    }
    for my $re (@AT_A_PATH) {
        ok scalar(grep { my $c = $_; grep { $_ =~ $re } config_for($c->[1])->validate } @CORPUS), "$re: asked";
    }
};

subtest 'no path but gpu has a line validate() says alone' => sub {
    my $alone = qr/: unknown key | required for |\A(?:worker pool: name|name is) required\z|node_ip|: labels|: taints|must list at|\.nodes: |: an ssh pool |host is read for an ssh pool/;
    my @not_gpu = grep { $_ ne 'gpu' } @ALL;
    for my $case (@CORPUS) {
        my ($what, $spec) = @$case;
        my $c = config_for($spec);
        is_deeply [ grep { $_ =~ $alone } $c->spec_errors(@not_gpu) ], [], "$what: none";
    }
    my $c = config_for({ control_planes => [ { %$local, count => 3 } ],
                         workers => [ $ssh->(count => 2, labels => 'x') ] });
    ok scalar(grep { /: unknown key / } $c->validate), 'validate() has them';
    is_deeply [ $c->spec_errors(@ALL) ], [], 'spec_errors has none of them';
};

# --- 3. one place per path ----------------------------------------------------

subtest 'an entry by its number, or every entry by *' => sub {
    my $c = config_for({ control_planes => [ $local, 'foo', { provider => 'ssh', host => [ 'a' ] } ] });
    my $not_a_mapping = "control_planes[2]: must be a mapping (one control plane), not 'foo'";
    my $host = 'control_planes[3].host: must be a string (a host name or IP address), not a list';
    is_deeply [ $c->spec_errors('control_planes[2]') ], [ $not_a_mapping ], 'control_planes[2]';
    is_deeply [ $c->spec_errors('control_planes[*]') ], [ $not_a_mapping ], 'control_planes[*]';
    is_deeply [ $c->spec_errors('control_planes[1]') ], [], 'control_planes[1]: nothing wrong there';
    is_deeply [ $c->spec_errors('control_planes[3]') ], [], 'control_planes[3]: its host is not the entry';
    is_deeply [ $c->spec_errors('control_planes[3].host') ], [ $host ], 'control_planes[3].host';
    is_deeply [ $c->spec_errors('control_planes[*].host') ], [ $host ], 'control_planes[*].host';
    is_deeply [ $c->spec_errors('control_planes[2].host') ], [], 'under an entry that is no mapping: nothing';
    is_deeply [ $c->spec_errors('control_planes[4]', 'control_planes[4].host') ], [], 'past the last entry: nothing';
    is_deeply [ $c->spec_errors('control_planes') ], [], 'the section: nothing wrong with its shape';
    ok !grep({ /host required/ } $c->validate), 'and no "required" beside the host of the wrong shape';

    my $w = config_for({ control_planes => $local,
                         workers => [ $ssh->(name => 'a'), 'x', $ssh->(name => 'c', host => [ 'h' ]) ] });
    is_deeply [ $w->spec_errors('workers[2]') ], [ "workers[2]: must be a mapping (a worker pool), not 'x'" ],
        'workers[2]';
    is_deeply [ $w->spec_errors('workers[3].host') ],
        [ "worker pool 'c': host must be a string (a host name or IP address), not a list" ], 'workers[3].host';
    is_deeply [ $w->spec_errors('workers[1]', 'workers[1].host', 'workers[2].host', 'workers[4]') ], [],
        'a pool with nothing wrong, under a pool that is no mapping, past the last';
};

subtest '* is each entry in turn' => sub {
    for my $case (@CORPUS) {
        my ($what, $spec) = @$case;
        my $c = config_for($spec);
        for my $s ([ control_planes => '', @CP_KEYS ], [ workers => '', @POOL_KEYS ]) {
            my ($section, @keys) = @$s;
            for my $key (@keys) {
                my $tail = length $key ? ".$key" : '';
                is_deeply [ $c->spec_errors($section . "[*]$tail") ],
                    [ map { $c->spec_errors($section . "[$_]$tail") } 1 .. 9 ], "$what: $section\[*]$tail";
            }
        }
    }
};

subtest 'each key at its own path, at no other' => sub {
    my %cp = (provider => { provider => 'foo' },
              map { $_ => { provider => 'ssh', host => 'h', $_ => [ 'a' ] } } grep { $_ ne 'provider' } @CP_KEYS);
    my %pool = (name     => $ssh->(name => [ 'a' ]),
                provider => { name => 'w', provider => 'foo' },
                nodes    => $hz->(nodes => 'x'),
                host     => $ssh->(host => [ 'a' ]),
                map { $_ => $hz->($_ => [ 'a' ]) } qw( server_type location image ));
    for my $s ([ control_planes => \%cp, @CP_KEYS ], [ workers => \%pool, @POOL_KEYS ]) {
        my ($section, $entries, @keys) = @$s;
        for my $key (@keys) {
            my $c = config_for({ control_planes => $local, $section => [ $entries->{$key} ] });
            my @line = grep { at_a_path($_) } $c->validate;
            is scalar(@line), 1, "$section\[1].$key: validate() has one line at a path" or diag explain \@line;
            is_deeply [ $c->spec_errors($section . "[1].$_") ], [ $_ eq $key ? @line : () ],
                "$section\[1].$key: asked at .$_" for @keys;
        }
    }
};

subtest 'under a section of the wrong shape: nothing' => sub {
    my $c = config_for({ control_planes => 'foo', workers => 'foo' });
    is_deeply [ $c->spec_errors('control_planes') ],
        [ "control_planes: must be a mapping (one control plane, or nodes: N of them) or a list of mappings, not 'foo'" ],
        'control_planes';
    is_deeply [ $c->spec_errors('workers') ], [ "workers: must be a list of worker pools, not 'foo'" ], 'workers';
    is_deeply [ $c->spec_errors(grep { /\[/ } @ALL) ], [], 'no entry under either';
};

subtest 'nodes: N is one entry, said once' => sub {
    my $c = config_for({ control_planes => { provider => 'ssh', host => [ 'a' ], nodes => 3 } });
    my $line = 'control_planes[1].host: must be a string (a host name or IP address), not a list';
    is_deeply [ $c->spec_errors('control_planes[*].host') ], [ $line ], 'once by *';
    is_deeply [ $c->spec_errors('control_planes[1].host') ], [ $line ], 'at entry 1';
    is_deeply [ $c->spec_errors('control_planes[2].host', 'control_planes[3]') ], [], 'not at entry 2 or 3';
    is scalar(grep { $_ eq $line } $c->validate), 1, 'as validate() says it';
};

subtest 'a pool is asked for nodes as its provider reads them' => sub {
    my $c = config_for({ control_planes => $local, workers => [
        $hz->(name => 'a', nodes => 'abc'), { name => 'b', provider => 'aws', nodes => 'abc' } ] });
    is_deeply [ $c->spec_errors('workers[*].nodes') ],
        [ "worker pool 'a': nodes must be a whole number (how many machines the pool has), not 'abc'" ],
        'a known provider: its line; an unknown one: none, its provider has the line';
    is_deeply [ $c->spec_errors('workers[2].provider') ],
        [ "worker pool 'b': invalid provider 'aws' (must be " . OCP::Choices::or_list(OCP::Provider->types) . ')' ],
        'workers[2].provider';
};

subtest "a name: the shape is at the path, a name missing is validate()'s" => sub {
    is_deeply [ config_for({ name => [ 'a' ] })->spec_errors('name') ],
        [ "name: must be a string (the cluster's name), not a list" ], 'a list';
    my $c = config_for({ name => '' });
    is_deeply [ $c->spec_errors('name') ], [], "'': nothing at the path";
    is_deeply [ grep { /name/ } $c->validate ], [ 'name is required' ], "validate()'s line";
};

# --- 4. gpu -------------------------------------------------------------------

subtest "gpu: every line under gpu:, its switches with them" => sub {
    for my $case (@CORPUS) {
        my ($what, $spec) = @$case;
        my $c = config_for($spec);
        is_deeply [ $c->spec_errors('gpu') ], [ grep { /\Agpu[.:]/ } $c->validate ], $what;
    }
    my $c = config_for({ gpu => { enabled => 'yes' }, nocert => 'no' });
    is_deeply [ $c->spec_errors('gpu') ], [ "gpu.enabled: must be true or false, not 'yes'; write enabled: true" ]
        or diag explain [ $c->validate ];
};

# --- 5. order, once, what it does not answer for -----------------------------

subtest "validate()'s order and once, however the paths are asked" => sub {
    my $c = config_for({ name => [ 'a' ], control_planes => [ 'x' ], gpu => 'x', workers => [ 'x' ] });
    my @want = ("name: must be a string (the cluster's name), not a list",
                "control_planes[1]: must be a mapping (one control plane), not 'x'",
                "gpu: must be a mapping, not 'x'",
                "workers[1]: must be a mapping (a worker pool), not 'x'");
    is_deeply [ $c->spec_errors(reverse @ALL) ], \@want, 'asked backwards';
    is_deeply [ $c->spec_errors('workers[*]', 'gpu', 'control_planes[1]', 'name') ], \@want, 'asked in any order';
    is_deeply [ $c->spec_errors('control_planes[*]', 'control_planes[1]', 'control_planes[*]') ], [ $want[1] ],
        'asked three times: once';
    is_deeply [ $c->spec_errors ], [], 'asked for nothing: nothing';
};

subtest 'a path it does not answer for croaks' => sub {
    my $c = config_for({ control_planes => $local });
    for my $path ('foo', 'Name', 'name ', "name\n", 'control_planes[0]', 'control_planes[01]', 'control_planes[-1]',
                  'control_planes[1].count', 'control_planes[1].node_ip', 'control_planes[*].nodes',
                  'control_planes[1].host.x', 'control_planes.host', 'control_planes[]', 'workers[*].node_ip',
                  'workers[*].labels', 'workers[1].nodes[1]', 'gpu.driver', 'gpu.enabled', 'kubernetes', 'ssh') {
        ok !eval { $c->spec_errors('name', $path); 1 }, "'$path'";
        like $@, qr/\Aspec_errors: no key path '\Q$path\E' /, "'$path': its message names it";
    }
    ok !eval { $c->spec_errors(undef); 1 }, 'undef';
    like $@, qr/\Aspec_errors: no key path null /, 'undef: its message';
    ok !eval { $c->spec_errors([ 'name' ]); 1 }, 'a list';
    like $@, qr/\Aspec_errors: no key path a list /, 'a list: its message';
};

subtest 'an ocp.yaml that is no mapping stops it with the file line' => sub {
    my $f = path($tmpdir)->child('list.yaml');
    $f->spew_utf8("- name: k306\n");
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my $line = "$f: must be a mapping (name, control_planes and the other settings), not a list";
    for my $path (@ALL) {
        ok !eval { $c->spec_errors($path); 1 }, "$path stops";
        is $@, "$line\n", "$path: with validate()'s line";
    }
    is_deeply [ $c->validate ], [ $line ], 'as validate() says';
};

done_testing;

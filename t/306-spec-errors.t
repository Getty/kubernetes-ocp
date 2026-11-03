#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use JSON::PP ();
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';
use lib 't/lib';
use OCP;
use OCP::Choices;
use OCP::Config;
use OCP::Provider;
use OCPTest::Shapes qw( shapes at );

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
#   2. none of those is a line validate() says alone (@ALONE below): a key
#      nothing reads of an entry, a pool, a pool's machine or ssh:, a
#      "required" line, a bound, node_ip, an ssh pool's both-or-neither, a
#      host on a pool that takes none, the pod CIDR's and the service
#      network's overlaps;
#   3. a path names one place: an entry by its number from 1, or every entry
#      with *, which is each entry's answer in turn; nothing under a section
#      or an entry that has a line of its own shape, nothing past the last
#      entry, and the mapping form with nodes: N is one entry, said once;
#   4. gpu is every line validate() has under gpu:, its switches with them,
#      and no other switch: lbipam and nocert are at their own paths, and
#      system.ntp at system;
#   5. lines come in validate()'s order and once, however the paths are
#      asked; a path spec_errors does not answer for croaks, as a caller's
#      mistake; an ocp.yaml that is no mapping stops it with the file's line,
#      as it stops every reader.
#
# k400 (Part C, step C1): spec_errors answers every section validate()
# checks, and validate() and spec_errors read one ordered list of [ tag,
# line ]. Two claims change on purpose:
#   - claim 2 was "none of those is a key nothing reads, a 'required' line, a
#     bound, node_ip, labels or taints: no path but gpu returns such a line".
#     Labels, taints and the sections' own unknown keys (kubernetes:,
#     network:, cilium:, system:, robocop:) have paths now; what validate()
#     says alone is @ALONE, and no path returns one of those;
#   - claim 4 was "gpu is every line under gpu:, its switches with them, and
#     no other switch". gpu still has no other switch; lbipam and nocert
#     answer at their own paths now, system.ntp at system.
# And these are new:
#   6. over t/296's sweep (OCPTest::Shapes: every path validate() reads, every
#      YAML shape), spec_errors at every path is validate() but the lines it
#      says alone, and each line is at a path or alone, never both;
#   7. a path is the lines about its key, and no more: network is network:'s
#      shape and its unknown keys, not the lines under lb_pool:; robocop is
#      not its security_level or image;
#   8. an overlap of the pod CIDR or the service network is at no path (an
#      existing cluster's default pod CIDR overlapping a node address stops
#      no command that reads network:), nor is an unknown key of ssh:;
#   9. pod_cidr, pod_cidr_is_set, lb_pool_config, lb_pool_blocks, l2_config,
#      l2_node_selector and l2_interfaces refuse in the lines of their path
#      (network.pod_cidr, network.lb_pool, network.l2), joined as _refuse
#      joins them, and read on where it has none.
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
my @POOL_KEYS = qw( name provider nodes host server_type location image labels taints );

# The sections and keys that are one path each (k400).
my @SECTIONS = qw( kubernetes network network.pod_cidr network.lb_pool network.l2 cilium registry ssl
                   system ssh robocop robocop.security_level robocop.image lbipam nocert );

# Every path spec_errors answers for, each entry by *.
my @ALL = ('name', 'control_planes', 'control_planes[*]', (map { "control_planes[*].$_" } @CP_KEYS),
           'workers', 'workers[*]', (map { "workers[*].$_" } @POOL_KEYS), 'gpu', @SECTIONS);

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
    # k400
    qr/\A$pool: (?:labels[:.]|taints must be |taint )/,
    qr/\Akubernetes[.:]/,
    qr/\Anetwork(?::|\.\w+: unknown key )/,
    qr/\Anetwork\.(?:lb_pool|l2)\b/,
    qr/\Anetwork\.pod_cidr: .* (?:is not an IPv4 CIDR|has host bits set|is too small)/,
    qr/\A(?:cilium|registry|ssl|system)[.:]/,
    qr/\Assh(?::|\.\w+: must be a string)/,
    qr/\Arobocop[.:]/,
    qr/\A(?:lbipam|nocert): /,
);
sub at_a_path { my ($line) = @_; return grep { $line =~ $_ } @AT_A_PATH }

# The oracle for claim 2 (k400): a line validate() says alone, at no path.
my @ALONE = (
    qr/\A(?:name is|worker pool: name) required\z/,
    qr/\Acontrol_planes\[\d+\]: \w+ required for \w+\z/,
    qr/\Acontrol_planes: must list at /,
    qr/\Acontrol_planes\.nodes: /,
    qr/\Acontrol_planes\[\d+\]\.node_ip: /,
    qr/\Acontrol_planes: node_ip with nodes: /,
    qr/: node_ip cannot be set on a pool/,
    qr/: nodes\[\d+\]\.node_ip is not read from /,
    qr/\A(?:control_planes|workers)\[\d+\](?:\.nodes\[\d+\])?\.\w+: unknown key /,
    qr/\Assh\.\w+: unknown key /,
    qr/: an ssh pool (?:needs|takes) /,
    qr/: host is read for an ssh pool only/,
    qr/\A(?:network\.pod_cidr|the service network)\b.* overlaps /,
);
sub alone { my ($line) = @_; return grep { $line =~ $_ } @ALONE }

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
    # k400: the sections beside these
    [ 'kubernetes a string'   => { kubernetes => 'k3s' } ],
    [ 'kubernetes keys'       => { kubernetes => { dist => 'rke3', version => [ 'a' ], distribution => 'k3s' } } ],
    [ 'network a string'      => { network => 'foo' } ],
    [ 'network keys'          => { network => { pod_cidr => [ 'a' ], lb_pool => 'foo', l2 => 'bar', bar => 1 } } ],
    [ 'pod CIDR host bits'    => { network => { pod_cidr => '10.42.0.1/16' } } ],
    [ 'pod CIDR too small'    => { network => { pod_cidr => '10.42.0.0/25' } } ],
    [ 'pod CIDR and service network overlaps' => { control_planes => { provider => 'ssh', host => '10.42.0.5',
          public_ip => '10.43.0.5' }, network => { lb_pool => { cidr => '10.42.7.0/28' } } } ],
    [ 'lb_pool and l2 keys'   => { network => { lb_pool => { cidr => 'x', start => 'y', foo => 1 },
          l2 => { interfaces => 'x', node_selector => { a => [ 'b' ] }, foo => 1 } } } ],
    [ 'cilium a string'       => { cilium => 'foo' } ],
    [ 'cilium keys'           => { cilium => { devise => [ 'eth0' ], devices => 'x', helm_values => [ 'a' ] } } ],
    [ 'registry, ssl, ssh'    => { registry => { cache => [ 'a' ], foo => 1 }, ssl => 'x',
          ssh => { private_key => [ 'a' ], privat_key => 'x' } } ],
    [ 'system and ssh strings' => { system => { timezone => [ 'a' ], time_zone => 'x' }, ssh => 'x' } ],
    [ 'robocop a string'      => { robocop => 'no' } ],
    [ 'robocop keys'          => { robocop => { enabled => 'yes', enable => 1, security_level => 'foo',
          image => [ 'a' ] } } ],
    [ 'all of it at once'     => {
          name => [ 'a' ],
          control_planes => [ { provider => 'foo', host => [ 'a' ], count => 1 }, 'x' ],
          gpu => { driver => 'x', enabled => 'no' }, nocert => 'no',
          workers => [ 'x', { name => 'w', provider => 'ssh', nodes => [ {} ], host => 'h', count => 1 },
                       { provider => 'hetzner', server_type => [ 'a' ], nodes => 'x' } ],
          kubernetes => 'x', network => { pod_cidr => 'x', foo => 1 }, cilium => { foo => 1 }, ssl => 'x',
          system => 'x', ssh => { privat_key => 'x' }, robocop => { image => 'x', security_level => 'x' },
          lbipam => 'x' } ],
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
    for my $re (@AT_A_PATH, @ALONE) {
        ok scalar(grep { my $c = $_; grep { $_ =~ $re } config_for($c->[1])->validate } @CORPUS), "$re: asked";
    }
};

subtest 'no path has a line validate() says alone' => sub {
    for my $case (@CORPUS) {
        my ($what, $spec) = @$case;
        my $c = config_for($spec);
        is_deeply [ grep { alone($_) } $c->spec_errors(@ALL) ], [], "$what: none";
        is_deeply [ grep { alone($_) && at_a_path($_) } $c->validate ], [], "$what: no line is both";
    }
    my $c = config_for({ control_planes => [ { %$local, count => 3, host => '10.42.0.5' } ],
                         workers => [ $ssh->(count => 2) ], ssh => { privat_key => 'x' } });
    is scalar(grep { /: unknown key |overlaps/ } $c->validate), 4, 'validate() has them';
    is_deeply [ $c->spec_errors(@ALL) ], [], 'spec_errors has none of them';
};

# --- 6. over t/296's sweep ------------------------------------------------------

subtest "every path validate() reads, every shape: spec_errors is validate() but its own lines" => sub {
    for my $at (at()) {
        my ($path, $make) = @$at;
        my (@neither, @differ);
        for my $shape (shapes()) {
            my $c = config_for($make->($shape->[1]));
            my @all = $c->validate;
            push @neither, map { "$shape->[0]: $_" } grep { !alone($_) == !at_a_path($_) } @all;
            my @want = grep { !alone($_) } @all;
            my @got  = $c->spec_errors(@ALL);
            push @differ, { shape => $shape->[0], got => \@got, want => \@want }
                unless join("\0", @got) eq join("\0", @want);
        }
        is_deeply \@neither, [], "$path: each line at a path or alone, not both";
        is_deeply \@differ, [], "$path: spec_errors at every path is validate() but its own lines";
    }
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
                labels   => $ssh->(labels => 'x'),
                taints   => $ssh->(taints => 'y'),
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

    # k400: the switches beside gpu: are at their own paths.
    my $s = config_for({ gpu => { toolkit => 'no' }, nocert => 'no', lbipam => 'x', system => { ntp => 'yes' } });
    is_deeply [ $s->spec_errors('nocert') ], [ "nocert: must be true or false, not 'no'; write nocert: false" ],
        'nocert';
    is_deeply [ $s->spec_errors('lbipam') ], [ "lbipam: must be true or false, not 'x'" ], 'lbipam';
    is_deeply [ $s->spec_errors('system') ], [ "system.ntp: must be true or false, not 'yes'; write ntp: true" ],
        'system.ntp at system';
    is_deeply [ $s->spec_errors('gpu') ], [ "gpu.toolkit: must be true or false, not 'no'; write toolkit: false" ],
        'gpu: its own switch, no other';
};

# --- 7. and 8. a path is the lines about its key ------------------------------

subtest 'a path is the lines about its key, and no more' => sub {
    my $c = config_for({ network => { foo => 1, pod_cidr => 'x', lb_pool => 'y', l2 => 'z' },
                         robocop => { enable => 1, security_level => 'x', image => [ 'a' ] } });
    my $unknown = 'network.foo: unknown key (must be ' . OCP::Choices::or_list(qw( pod_cidr lb_pool l2 )) . ')';
    is_deeply [ $c->spec_errors('network') ], [ $unknown ], 'network: its unknown key, not the lines under it';
    is_deeply [ $c->spec_errors('network.pod_cidr') ],
        [ "network.pod_cidr: 'x' is not an IPv4 CIDR (e.g. 10.42.0.0/16)" ], 'network.pod_cidr';
    is_deeply [ $c->spec_errors('network.lb_pool') ], [ 'network.lb_pool: must be a mapping (cidr, or start+stop)' ],
        'network.lb_pool';
    is_deeply [ $c->spec_errors('network.l2') ], [ 'network.l2: must be a mapping' ], 'network.l2';
    is_deeply [ $c->spec_errors('robocop') ],
        [ 'robocop.enable: unknown key (must be ' . OCP::Choices::or_list(qw( enabled security_level image )) . ')' ],
        'robocop: not its security_level or image';
    is_deeply [ $c->spec_errors('robocop.security_level') ],
        [ "robocop.security_level: invalid value 'x' (must be "
          . OCP::Choices::or_list(@OCP::Config::ROBOCOP_SECURITY_LEVELS) . ')' ], 'robocop.security_level';
    is_deeply [ $c->spec_errors('robocop.image') ],
        [ 'robocop.image: must be an image reference like raudssus/ocp:1.2.3, not a list' ], 'robocop.image';

    my $n = config_for({ network => 'foo' });
    is_deeply [ $n->spec_errors('network') ], [ 'network: must be a mapping' ], 'network: its shape';
    is_deeply [ $n->spec_errors('network.pod_cidr', 'network.lb_pool', 'network.l2') ], [],
        'under it: nothing, network: has the line';
};

# Each example: spec_errors at the path is exactly validate()'s lines about it.
subtest 'examples: the lines about the key, as validate() says them' => sub {
    for my $ex (
        [ kubernetes          => { kubernetes => { dist => 'rke3' } },               qr/\Akubernetes\.dist: / ],
        [ 'network.pod_cidr'  => { network => { pod_cidr => [ 'a' ] } },             qr/\Anetwork\.pod_cidr: / ],
        [ 'network.lb_pool'   => { network => { lb_pool => 'foo' } },                qr/\Anetwork\.lb_pool: / ],
        [ cilium              => { cilium => { devise => [ 'eth0' ] } },             qr/\Acilium\.devise: / ],
        [ 'workers[1].taints' => { control_planes => $local, workers => [ $ssh->(taints => 'foo') ] },
                                                                                    qr/\Aworker pool 'w': taints / ],
        [ 'robocop.image'     => { robocop => { image => [ 'a' ] } },               qr/\Arobocop\.image: / ],
    ) {
        my ($path, $spec, $about) = @$ex;
        my $c = config_for($spec);
        my @about = grep { $_ =~ $about } $c->validate;
        is scalar(@about), 1, "$path: validate() has one line about it" or diag explain [ $c->validate ];
        is_deeply [ $c->spec_errors($path) ], \@about, "$path: spec_errors is that line";
    }
};

subtest "an overlap of the pod CIDR is at no path: a running cluster's default stops nothing" => sub {
    my $c = config_for({ control_planes => { provider => 'ssh', host => '10.42.0.5' } });
    is_deeply [ grep { /overlaps/ } $c->validate ],
        [ 'network.pod_cidr (default 10.42.0.0/16) overlaps control_planes[1].host 10.42.0.5'
          . ' -- set network.pod_cidr to a range nothing else uses' ], 'validate() has the overlap';
    is_deeply [ $c->spec_errors('network', 'network.pod_cidr') ], [], 'network and network.pod_cidr: nothing';
    is $c->pod_cidr, '10.42.0.0/16', 'pod_cidr reads it';
    ok !$c->pod_cidr_is_set, 'pod_cidr_is_set reads it';
};

subtest 'an unknown key of ssh: is at no path' => sub {
    my $c = config_for({ ssh => { privat_key => 'x' } });
    is_deeply [ grep { /\Assh/ } $c->validate ],
        [ 'ssh.privat_key: unknown key (must be ' . OCP::Choices::or_list(qw( private_key public_key )) . ')' ],
        'validate() has it';
    is_deeply [ $c->spec_errors('ssh') ], [], 'ssh: nothing';
};

# --- 9. the network accessors refuse in the lines of their path ----------------

subtest 'pod_cidr, lb_pool_blocks and l2_interfaces refuse in the lines of their path' => sub {
    my @accessors = (
        [ qr/\Anetwork\.pod_cidr\z/      => 'network.pod_cidr' => [ qw( pod_cidr pod_cidr_is_set ) ] ],
        [ qr/\Anetwork\.lb_pool(?:\.|\z)/ => 'network.lb_pool' => [ qw( lb_pool_config lb_pool_blocks ) ] ],
        [ qr/\Anetwork\.l2(?:\.|\z)/      => 'network.l2' => [ qw( l2_config l2_node_selector l2_interfaces ) ] ],
    );
    for my $acc (@accessors) {
        my ($at_re, $path, $methods) = @$acc;
        my @at = grep { $_->[0] =~ $at_re } at();
        ok scalar(@at), "$path: at() has its paths";
        my (%refused, %read);
        for my $at (@at) {
            my ($where, $make) = @$at;
            for my $shape (shapes()) {
                my $c = config_for($make->($shape->[1]));
                my @lines = $c->spec_errors($path);
                for my $m (@$methods) {
                    my $ok = eval { $c->$m; 1 };
                    if (@lines) {
                        $refused{$m}++;
                        is $@, join('; ', @lines) . "\n", "$where $shape->[0]: $m refuses in its path's lines";
                    }
                    else {
                        $read{$m}++;
                        ok $ok, "$where $shape->[0]: $m reads it" or diag $@;
                    }
                }
            }
        }
        for my $m (@$methods) {
            ok $refused{$m}, "$m: refuses in some shape";
            ok $read{$m},    "$m: reads in some shape";
        }
    }

    # What each reads where nothing is wrong, as it read before.
    my $c = config_for({ network => { pod_cidr => '10.50.0.0/16', lb_pool => { start => '10.9.9.1', stop => '10.9.9.9' },
                                      l2 => { interfaces => [ '^eth0$' ], node_selector => { a => 'b' } } } });
    is $c->pod_cidr, '10.50.0.0/16', 'pod_cidr';
    ok $c->pod_cidr_is_set, 'pod_cidr_is_set';
    is_deeply $c->lb_pool_blocks, [ { start => '10.9.9.1', stop => '10.9.9.9' } ], 'lb_pool_blocks';
    is_deeply $c->l2_interfaces, [ '^eth0$' ], 'l2_interfaces';
    is_deeply $c->l2_node_selector, { a => 'b' }, 'l2_node_selector';
    my $none = config_for({ network => { l2 => {} } });
    is $none->lb_pool_blocks, undef, 'no lb_pool: no blocks';
    is_deeply $none->l2_interfaces, $OCP::Config::DEFAULT_L2_INTERFACES, 'l2: {}: the default interfaces';
    is $none->pod_cidr, '10.42.0.0/16', 'no pod_cidr: the default';

    # Where each refuses, by one example each.
    my $bad = config_for({ network => { pod_cidr => '10.42.0.1/16', lb_pool => 'foo', l2 => { interfaces => 'x' } } });
    ok !eval { $bad->pod_cidr; 1 }, 'pod_cidr: host bits';
    is $@, "network.pod_cidr: '10.42.0.1/16' has host bits set; the network address is 10.42.0.0/16\n", 'in its line';
    ok !eval { $bad->lb_pool_blocks; 1 }, 'lb_pool_blocks: lb_pool: foo';
    is $@, "network.lb_pool: must be a mapping (cidr, or start+stop)\n", 'in its line';
    ok !eval { $bad->l2_interfaces; 1 }, 'l2_interfaces: interfaces: x';
    is $@, "network.l2.interfaces: must be a non-empty list of interface-name regexes\n", 'in its line';
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

    # k400: every section, asked backwards, in validate()'s order.
    my $all = config_for({ name => [ 'a' ], kubernetes => 'x', network => 'x', cilium => 'x', gpu => 'x',
                           registry => 'x', ssl => 'x', system => 'x', ssh => 'x', nocert => 'x', lbipam => 'x',
                           robocop => { enabled => 'x', security_level => 'x', image => 'x' },
                           control_planes => [ 'x' ], workers => [ $ssh->(labels => 'x', taints => 'y') ] });
    my @every = $all->validate;
    is scalar(@every), 17, 'validate() has a line in each';
    is_deeply [ $all->spec_errors(reverse @ALL) ], \@every, 'asked backwards: in its order';
};

subtest 'a path it does not answer for croaks' => sub {
    my $c = config_for({ control_planes => $local });
    for my $path ('foo', 'Name', 'name ', "name\n", 'control_planes[0]', 'control_planes[01]', 'control_planes[-1]',
                  'control_planes[1].count', 'control_planes[1].node_ip', 'control_planes[*].nodes',
                  'control_planes[1].host.x', 'control_planes.host', 'control_planes[]', 'workers[*].node_ip',
                  'workers[1].nodes[1]', 'gpu.driver', 'gpu.enabled',
                  # k400: kubernetes, ssh and workers[*].labels are paths now; these are not
                  'workers[*].labels.x', 'control_planes[1].labels', 'kubernetes.dist', 'ssh.private_key',
                  'network.foo', 'network.pod_cidr.x', 'network.lb_pool.cidr', 'network.l2.interfaces',
                  'cilium.devices', 'registry.cache', 'system.ntp', 'robocop.enabled', 'Network', 'network.') {
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

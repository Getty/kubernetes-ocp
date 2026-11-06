#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use JSON::MaybeXS qw( decode_json );
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Status;
use OCP::Config;
use OCP::Provider;

#
# k339: `ocp status` shows how many machines each worker pool has, and the
# number is the workers `ocp apply` makes of the pool -- the OCPNodes
# OCP::Cmd::Apply::CR::worker_ocpnodes builds. A hetzner or local pool
# without nodes: is one worker there (nodes // 1), and status showed it as 0;
# a count: beside it, which apply does not read, status showed instead. k332
# fixed the same for an ssh pool with host: only.
#
# The claim, for every pool shape validate() accepts: both forms of the spec
# summary say as many machines as worker_ocpnodes makes workers of the pool.
# The shapes are the product of the axes below; which of them validate()
# accepts is asked at run time, so the claim follows validate() (k331 refuses
# a host: on a pool that is not ssh, and those shapes leave the set). A shape
# validate() refuses is not asked of worker_ocpnodes: some of them it cannot
# build (a hetzner pool's nodes list counts to its address).
#
# Network-free: the projects are not deployed, so status reads ocp.yaml only.
#

#### harness

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }

my %BASE = (
    name           => 'k339',
    kubernetes     => { version => 'v1.32.1+rke2r1' },
    control_planes => { provider => 'hetzner', server_type => 'cx32', location => 'fsn1' },
);

my $tmp = tempdir(CLEANUP => 1);
my $n = 0;

# An undeployed project whose ocp.yaml has the one worker pool $pool, named w.
sub project {
    my ($pool) = @_;
    my $dir = path($tmp)->child('p' . ++$n);
    $dir->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({ %BASE, workers => [ { name => 'w', %$pool } ] }));
    return $dir->child('ocp.yaml')->stringify;
}

# (exit, STDOUT, STDERR) of one `ocp status`.
sub run_status {
    my ($cfg, %opt) = @_;
    my $cmd = OCP::Cmd::Status->new(
        ($opt{json} ? (json => 1) : ()),
        command_chain => [Local::FakeOCP->new(config => $cfg)],
    );
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my $rc;
    {
        local *STDOUT = $o;
        local *STDERR = $e;
        $rc = $cmd->execute([], []);
    }
    return ($rc, $out, $err);
}

# The machines both forms of the spec summary say pool w has: (text, json).
sub status_counts {
    my ($cfg) = @_;
    my (undef, $out)  = run_status($cfg);
    my (undef, $json) = run_status($cfg, json => 1);
    my ($text) = $out =~ /^Workers \(w\): (\S+) \(\w+\)$/m;
    my ($pool) = @{ (eval { decode_json($json) } // {})->{spec}{workers} // [] };
    return ($text, ref $pool eq 'HASH' ? $pool->{nodes} : undef);
}

my $json = JSON::MaybeXS->new(canonical => 1);

#### the shapes

# A key a shape leaves out, as against one it sets to ~.
my $ABSENT = \'absent';

my @NODES = (
    $ABSENT, undef, 0, 1, 3, [],
    [ '10.0.0.31' ],
    [ '10.0.0.31', { host => '10.0.0.32' } ],
    [ { host => 'w3.k339.test' } ],
);
my @HOST  = ( $ABSENT, '10.0.0.21', 'w1.k339.test', '0', '' );
# count: is read by nothing, and validate() refuses it since k347: the shapes
# with one leave the set, and a subtest of their own asks two of them.
my @COUNT = ( $ABSENT, 5 );

# A hetzner pool names its server type, which validate() requires since k308:
# without one, every hetzner shape would leave the set.
my %SERVER_TYPE = (hetzner => 'cpx22');

my @SHAPES;
for my $provider (OCP::Provider->types) {
    for my $nodes (@NODES) {
        for my $host (@HOST) {
            for my $count (@COUNT) {
                push @SHAPES, {
                    provider => $provider,
                    ($SERVER_TYPE{$provider} ? (server_type => $SERVER_TYPE{$provider}) : ()),
                    (ref $nodes && $nodes == $ABSENT ? () : (nodes => $nodes)),
                    (ref $host  && $host  == $ABSENT ? () : (host  => $host)),
                    (ref $count && $count == $ABSENT ? () : (count => $count)),
                };
            }
        }
    }
}

# Each shape validate() accepts, with its config, by how it is shown. Shown
# before it is written out: the YAML dump may make a number a string.
my (%accepted, $refused);
for my $pool (@SHAPES) {
    my $shown  = $json->encode($pool);
    my $config = OCP::Config->new(file => project($pool));
    if ($config->validate) { $refused++; next }
    $accepted{$shown} = $config;
}
note scalar(keys %accepted) . ' shapes accepted, ' . ($refused // 0) . ' refused';

#### the claim

# The shapes the card is about, and the ones around them, each with the
# workers ocp apply makes of it. validate() accepts all of them, with k331 and
# k347 and without them: were one to leave the set, the sweep would no longer
# ask it. The pools with a count:, which k347 refuses, are asked below.
my @NAMED = (
    [ { provider => 'hetzner', server_type => 'cpx22' }                 => 1, 'hetzner, no nodes: (k339)' ],
    [ { provider => 'local' }                                           => 1, 'local, no nodes: (k339)' ],
    [ { provider => 'hetzner', server_type => 'cpx22', nodes => undef } => 1, 'hetzner, nodes: ~' ],
    [ { provider => 'hetzner', server_type => 'cpx22', nodes => 0 }     => 0, 'hetzner, nodes: 0' ],
    [ { provider => 'hetzner', server_type => 'cpx22', nodes => 3 }     => 3, 'hetzner, nodes: 3' ],
    [ { provider => 'ssh', host => '10.0.0.21' }   => 1, 'ssh, host: only (k332)' ],
    [ { provider => 'ssh', nodes => [] }           => 0, 'ssh, nodes: []' ],
    [ { provider => 'ssh', nodes => [ '10.0.0.31', { host => '10.0.0.32' } ] } => 2, 'ssh, nodes: a list of two' ],
);

subtest 'the pools around k339 are workers, and status says as many' => sub {
    for my $case (@NAMED) {
        my ($pool, $want, $what) = @$case;
        my $config = $accepted{ $json->encode($pool) };
        ok $config, "$what: validate() accepts it" or next;
        is scalar(my @crs = OCP::Cmd::Apply::CR::worker_ocpnodes($config)), $want,
            "$what: ocp apply makes $want worker(s) of it";
        my ($text, $from_json) = status_counts($config->file);
        is $text,      $want, "$what: text says $want";
        is $from_json, $want, "$what: --json says $want";
    }
};

# A pool's count: is read by nothing, and validate() refuses it since k347,
# with the hint to write nodes:. ocp status reads ocp.yaml without validate(),
# though, and for such a pool it still counts the workers ocp apply makes, not
# the count: (k339) -- which the sweep can no longer ask, as validate() takes
# these shapes out of its set.
my @COUNTED = (
    [ { provider => 'hetzner', server_type => 'cpx22', count => 5 } => 1, 'hetzner, a count: and no nodes:' ],
    [ { provider => 'local', nodes => 3, count => 5 } => 3, 'local, nodes: 3 and a count:' ],
);

subtest 'a pool with a count: is refused, and status counts the workers apply makes of it' => sub {
    for my $case (@COUNTED) {
        my ($pool, $want, $what) = @$case;
        my $config = OCP::Config->new(file => project($pool));
        my @errors = $config->validate;
        is scalar(@errors), 1, "$what: validate() refuses it, with one line" or diag explain \@errors;
        like $errors[0] // '',
            qr/^workers\[1\]\.count: unknown key \(must be [^)]*\bnodes\b[^)]*\); count is read by nothing -- write nodes: N, how many machines the pool has; without nodes it has one$/,
            "$what: the line is the count:'s, with the hint to write nodes:";
        is scalar(my @crs = OCP::Cmd::Apply::CR::worker_ocpnodes($config)), $want,
            "$what: ocp apply makes $want worker(s) of it";
        my ($text, $from_json) = status_counts($config->file);
        is $text,      $want, "$what: text says $want, not the count:";
        is $from_json, $want, "$what: --json says $want, not the count:";
    }
};

subtest 'every pool validate() accepts: status counts the workers worker_ocpnodes makes of it' => sub {
    for my $shown (sort keys %accepted) {
        my $config = $accepted{$shown};
        my $want = () = OCP::Cmd::Apply::CR::worker_ocpnodes($config);
        my ($text, $from_json) = status_counts($config->file);
        is $text,      $want, "$shown: text says $want";
        is $from_json, $want, "$shown: --json says $want";
    }
};

done_testing;

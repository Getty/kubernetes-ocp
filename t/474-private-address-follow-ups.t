#!/usr/bin/env perl
# karr k474: follow-ups to k453's address: private.
#
#   1. OCP::Drift's host-side probes reach a control plane where every other
#      k453 reader does: under address: private at its private_ip (it was
#      public_ip // host, so a control plane with only private_ip pinned was
#      probed at its host or not at all); without it at its public_ip, as
#      before. Both through probe_targets and through the prober itself.
#   2. validate() refuses a hetzner worker pool without network: beside a
#      first control plane on address: private -- its workers join that
#      control plane at its address in the Hetzner network, which a server
#      outside the network cannot reach. A pool with network: passes, as does
#      one beside a control plane on the public address, and a non-hetzner
#      pool (whose machine is in the networks it is in).
#
# Network-free: OCP::Config and OCP::Drift on temp files, the prober a coderef.

use strict;
use warnings;
use Test::More;

use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Config;
use OCP::Drift;

my $tmp = tempdir(CLEANUP => 1);
my $n   = 0;

sub config_for {
    my ($spec) = @_;
    my $file = path($tmp)->child('c' . ++$n . '.yaml');
    $file->spew_utf8(YAML::XS::Dump({ name => 'hz', %$spec }));
    return OCP::Config->new(file => "$file");
}

# The hosts the rex probes were run on, in call order, each once.
sub probed {
    my ($config) = @_;
    my (@hosts, %seen);
    OCP::Drift->new(
        config     => $config,
        rex_prober => sub { my ($host) = @_; push @hosts, $host unless $seen{$host}++; return { stdout => '', exit => 0 } },
    )->rex_probe_drift;
    return \@hosts;
}

my %CP   = (provider => 'hetzner', server_type => 'cpx22', location => 'fsn1');
my %POOL = (name => 'w', provider => 'hetzner', server_type => 'cpx32', nodes => 1);

# ---------------------------------------------------------------- 1

subtest 'address: private -- the probes reach the private_ip' => sub {
    my $only_private = config_for({ control_planes => { %CP, network => 'cai-live', address => 'private',
        private_ip => '10.200.0.2' } });
    is_deeply [ $only_private->validate ], [], 'a valid ocp.yaml';
    is_deeply [ OCP::Drift->new(config => $only_private)->probe_targets ], [ '10.200.0.2' ],
        'only private_ip pinned: probe_targets names it';
    is_deeply probed($only_private), [ '10.200.0.2' ], 'and the probe runs there';

    my $both = config_for({ control_planes => { %CP, network => 'cai-live', address => 'private',
        public_ip => '203.0.113.10', private_ip => '10.200.0.2' } });
    is_deeply [ OCP::Drift->new(config => $both)->probe_targets ], [ '10.200.0.2' ],
        'both pinned: the private_ip, not the public_ip';
    is_deeply probed($both), [ '10.200.0.2' ], 'and the probe runs there';

    my $list = config_for({ control_planes => [
        { %CP, network => 'cai-live', address => 'private', private_ip => '10.200.0.2', public_ip => '203.0.113.10' },
        { %CP, network => 'cai-live', address => 'private', private_ip => '10.200.0.3', public_ip => '203.0.113.11' },
    ] });
    is_deeply [ OCP::Drift->new(config => $list)->probe_targets ], [ '10.200.0.2', '10.200.0.3' ],
        'every control plane at its private_ip';
};

subtest 'the public address, as before' => sub {
    my $public = config_for({ control_planes => { %CP, network => 'cai-live',
        public_ip => '203.0.113.10', private_ip => '10.200.0.2' } });
    is_deeply [ OCP::Drift->new(config => $public)->probe_targets ], [ '203.0.113.10' ],
        'no address: the public_ip, not the private_ip';
    is_deeply probed($public), [ '203.0.113.10' ], 'and the probe runs there';

    my $explicit = config_for({ control_planes => { %CP, network => 'cai-live', address => 'public',
        public_ip => '203.0.113.10', private_ip => '10.200.0.2' } });
    is_deeply [ OCP::Drift->new(config => $explicit)->probe_targets ], [ '203.0.113.10' ],
        'address: public: the public_ip';

    my $plain = config_for({ control_planes => { %CP, public_ip => '203.0.113.10' } });
    is_deeply [ OCP::Drift->new(config => $plain)->probe_targets ], [ '203.0.113.10' ],
        'no network keys at all: the public_ip';

    my $ssh = config_for({ control_planes => { provider => 'ssh', host => 'cp.hz.test' } });
    is_deeply [ OCP::Drift->new(config => $ssh)->probe_targets ], [ 'cp.hz.test' ],
        'nothing pinned: the host';
};

# ---------------------------------------------------------------- 2

my $NEEDS = "worker pool 'w': network required -- the first control plane is on address: private, "
    . "so its workers join it at its address in the Hetzner network 'cai-live', which a server "
    . "outside that network cannot reach; add network: to the pool";

subtest 'a hetzner pool beside a private control plane needs network:' => sub {
    my @lines = config_for({
        control_planes => { %CP, network => 'cai-live', address => 'private' },
        workers        => [ { %POOL } ],
    })->validate;
    is_deeply \@lines, [ $NEEDS ], 'refused, the pool and network: named';

    my @list = config_for({
        control_planes => [ { %CP, network => 'cai-live', address => 'private' } ],
        workers        => [ { %POOL }, { %POOL, name => 'n', network => 'cai-live' } ],
    })->validate;
    is_deeply \@list, [ $NEEDS ], 'the list form: only the pool without one';

    my @unnamed = config_for({
        control_planes => { %CP, network => 'cai-live', address => 'private' },
        workers        => [ { provider => 'hetzner', server_type => 'cpx32', nodes => 1 } ],
    })->validate;
    ok scalar(grep { /\Aworkers\[1\]: network required -- / } @unnamed), 'an unnamed pool by its place'
        or diag explain \@unnamed;

    my @private_pool = config_for({
        control_planes => { %CP, network => 'cai-live', address => 'private' },
        workers        => [ { %POOL, address => 'private' } ],
    })->validate;
    is_deeply \@private_pool, [ "worker pool 'w': address is private, which needs network: the Hetzner "
        . "network whose address OCP is to use" ], 'a pool on address: private has its own line, once';
};

subtest 'what still passes' => sub {
    is_deeply [ config_for({
        control_planes => { %CP, network => 'cai-live', address => 'private' },
        workers        => [ { %POOL, network => 'cai-live' } ],
    })->validate ], [], 'the pool names a network';

    is_deeply [ config_for({
        control_planes => { %CP, network => 'cai-live' },
        workers        => [ { %POOL } ],
    })->validate ], [], 'the control plane on the public address: no network needed';

    is_deeply [ config_for({
        control_planes => { %CP, network => 'cai-live', address => 'private' },
        workers        => [ { name => 's', provider => 'ssh', host => 'w1.hz.test' } ],
    })->validate ], [], 'an ssh pool: its machine is in the networks it is in';
};

done_testing;

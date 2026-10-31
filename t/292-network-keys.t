#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use FindBin;
use Path::Tiny qw( path );

use lib 'lib';
use OCP;
use OCP::Config;

#
# k292: validate() took any key under network:, so a typo -- pod_cdir,
# l2.interface, lb_pool.strat -- was silently ignored and the default stayed
# in force; and it never checked that network.lb_pool's start is not after
# its stop.
#
# The claims here:
#   1. an unknown key under network:, network.lb_pool and network.l2 is one
#      line, in the words cilium.* and gpu.amd.* are refused in, naming the
#      keys that would have worked;
#   2. every key OCP::Config reads there passes -- and the listing is the set
#      the accessors read, so a key a reader starts to read cannot be refused
#      as unknown;
#   3. start after stop is refused, compared as addresses (10.0.0.9 comes
#      before 10.0.0.10); start equal to stop is a pool of one and passes.
#

my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

sub config_for {
    my ($spec) = @_;
    my $f = path($tmpdir)->child('c' . int(rand(1_000_000)) . '.yaml');
    $ocp->dump_file($f->stringify, { name => 'k292', control_planes => { provider => 'local' }, %$spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

sub errors_for { config_for({ network => $_[0] })->validate }

# --- 1. unknown keys ----------------------------------------------------------

subtest 'a typo under network: is refused, not ignored' => sub {
    is_deeply [ errors_for({ pod_cdir => '172.20.0.0/16' }) ],
        [ 'network.pod_cdir: unknown key (must be pod_cidr, lb_pool, or l2)' ], 'pod_cdir';

    is_deeply [ errors_for({ l2 => { interface => [ '^eth0$' ] } }) ],
        [ 'network.l2.interface: unknown key (must be node_selector or interfaces)' ], 'l2.interface';

    is_deeply [ errors_for({ lb_pool => { cidr => '10.5.0.240/28', cdir => 'x' } }) ],
        [ 'network.lb_pool.cdir: unknown key (must be cidr, start, or stop)' ], 'lb_pool.cdir';

    is_deeply [ errors_for({ lb_pool => { strat => '10.5.0.240', stop => '10.5.0.249' } }) ],
        [ 'network.lb_pool.strat: unknown key (must be cidr, start, or stop)',
          'network.lb_pool: start and stop must both be set' ],
        'lb_pool.strat: named, and the missing start said too';

    is_deeply [ errors_for({ lbipam => 1, pod_cdir => 'x' }) ],
        [ 'network.lbipam: unknown key (must be pod_cidr, lb_pool, or l2)',
          'network.pod_cdir: unknown key (must be pod_cidr, lb_pool, or l2)' ],
        'one line per key, sorted';
};

# --- 2. nothing valid is refused ----------------------------------------------

subtest 'every key OCP::Config reads passes' => sub {
    my $net = {
        pod_cidr => '172.20.0.0/16',
        lb_pool  => { start => '10.5.10.64', stop => '10.5.10.79' },
        l2       => { node_selector => { 'cihq/l2-announce' => 'true' }, interfaces => [ '^eth[0-9]+$' ] },
    };
    my $c = config_for({ network => $net });
    is_deeply [ $c->validate ], [], 'no error';
    is $c->pod_cidr, '172.20.0.0/16', 'pod_cidr is read';
    is_deeply $c->lb_pool_blocks, [ { start => '10.5.10.64', stop => '10.5.10.79' } ], 'lb_pool start/stop';
    is_deeply $c->l2_node_selector, { 'cihq/l2-announce' => 'true' }, 'l2.node_selector';
    is_deeply $c->l2_interfaces, [ '^eth[0-9]+$' ], 'l2.interfaces';

    my $cidr = config_for({ network => { lb_pool => { cidr => '10.5.10.64/28' } } });
    is_deeply [ $cidr->validate ], [], 'lb_pool.cidr: no error';
    is_deeply $cidr->lb_pool_blocks, [ { cidr => '10.5.10.64/28' } ], 'lb_pool.cidr is read';
};

# The listing has to come from the same place as the readers, or the next
# key a reader starts to read is refused as unknown (k102, k110). Every key
# the network accessors read must be in the set validate() accepts.
subtest 'the known keys are the keys the accessors read' => sub {
    my $src = path("$FindBin::Bin/../lib/OCP/Config.pm")->slurp_utf8;

    my %read;
    $read{network}{$_} = 1 for $src =~ /network_config->\{(\w+)\}/g;
    $read{l2}{$_}      = 1 for $src =~ /l2_config->\{(\w+)\}/g;
    my ($blocks) = $src =~ /^sub lb_pool_blocks \{(.*?)^\}/ms;
    ok $blocks, 'lb_pool_blocks found' or return;
    $read{lb_pool}{$_} = 1 for $blocks =~ /\$p->\{(\w+)\}/g;

    my %known = (
        network => [ @OCP::Config::NETWORK_KEYS ],
        lb_pool => [ @OCP::Config::LB_POOL_KEYS ],
        l2      => [ @OCP::Config::L2_KEYS ],
    );
    for my $block (sort keys %read) {
        my %k = map { $_ => 1 } @{ $known{$block} };
        ok scalar(keys %{ $read{$block} }), "$block: the accessors read keys";
        for my $key (sort keys %{ $read{$block} }) {
            ok $k{$key}, "$block.$key is read and known";
        }
    }

    my $lib = path("$FindBin::Bin/../lib");
    my (@outside, $seen);
    my $it = $lib->iterator({ recurse => 1 });
    while (my $f = $it->()) {
        next unless $f->is_file && $f =~ /\.pm\z/;
        $seen++;
        next if $f->relative($lib) eq 'OCP/Config.pm';
        push @outside, $f->relative($lib) . '' if $f->slurp_utf8 =~ /\{network\}/;
    }
    ok $seen > 50, "the whole of lib/ looked at ($seen modules)";
    is_deeply \@outside, [], 'nothing outside OCP::Config reads network: on its own';
};

# --- 3. start after stop ------------------------------------------------------

subtest 'network.lb_pool start after stop' => sub {
    is_deeply [ errors_for({ lb_pool => { start => '10.230.30.249', stop => '10.230.30.240' } }) ],
        [ "network.lb_pool: start '10.230.30.249' is after stop '10.230.30.240' "
          . '(the pool runs from start up to stop)' ],
        'refused, both named';

    is_deeply [ errors_for({ lb_pool => { start => '10.0.1.0', stop => '10.0.0.255' } }) ],
        [ "network.lb_pool: start '10.0.1.0' is after stop '10.0.0.255' (the pool runs from start up to stop)" ],
        'across an octet';

    is_deeply [ errors_for({ lb_pool => { start => '10.0.0.9', stop => '10.0.0.10' } }) ], [],
        '10.0.0.9 to 10.0.0.10: compared as addresses, not as strings';
    is_deeply [ errors_for({ lb_pool => { start => '10.0.0.9', stop => '10.0.0.9' } }) ], [],
        'start equal to stop: a pool of one address';

    is_deeply [ errors_for({ lb_pool => { start => '10.0.0.300', stop => '10.0.0.1' } }) ],
        [ "network.lb_pool.start: '10.0.0.300' is not an IPv4 address" ],
        'an address that is none: its own line, no order to compare';
};

done_testing;

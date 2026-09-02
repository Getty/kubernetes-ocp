#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::Cmd::Apply::Network;

#
# k127: on a multi-node cluster with a separate high-speed fabric, the
# LB-IPAM path built two objects that were both wrong:
#
#   * CiliumLoadBalancerIPPool default-pool used "$node_ip/32" — the control
#     plane's own address. On >1 node the LoadBalancer gets an IP that already
#     belongs to a node.
#   * CiliumL2AnnouncementPolicy default-l2 matched interfaces by name
#     (^en[a-z0-9]+) — which matches the QSFP fabric enp1s0f0np0 and misses the
#     LAN interface enP7s7.30 (capital P). Names cannot make that distinction.
#
# Fix: the pool range is configurable (network.lb_pool), the node-IP /32 stays
# only as a single-node fallback; the L2 policy takes a nodeSelector
# (network.l2.node_selector) and configurable interfaces, and the built-in
# regexes are anchored.
#

local @ARGV = ();
my $ocp = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

sub config_for {
    my ($spec, $name) = @_;
    $name ||= 'c' . int(rand(1_000_000));
    my $f = path($tmpdir)->child("$name.yaml");
    $ocp->dump_file($f->stringify, { name => $name, %$spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

my $single = { control_planes => [{ provider => 'local' }] };
my $multi  = { control_planes => { provider => 'hetzner', server_type => 'cx32',
                                   location => 'fsn1', nodes => 2 } };

#
# Single-node, no network config: the old node-IP /32 trick is preserved.
#
{
    my $config = config_for($single, 'single');
    my $res = OCP::Cmd::Apply::Network::lb_ipam_resources('10.0.0.5', $config);

    is($res->[0]{kind}, 'CiliumLoadBalancerIPPool', 'first resource is the pool');
    is($res->[0]{metadata}{name}, 'default-pool', 'pool still named default-pool');
    is_deeply($res->[0]{spec}{blocks}, [{ cidr => '10.0.0.5/32' }],
        'single-node fallback: pool is the node IP as a /32');

    is($res->[1]{kind}, 'CiliumL2AnnouncementPolicy', 'second resource is the L2 policy');
    ok(!exists $res->[1]{spec}{nodeSelector},
        'no nodeSelector without config — every node announces (single-node)');
}

#
# Multi-node, no pool configured: refuse rather than hand out a node's own IP.
#
{
    my $config = config_for($multi, 'multi-nopool');
    my $err = do { local $@; eval {
        OCP::Cmd::Apply::Network::lb_ipam_resources('10.230.30.110', $config); 1
    }; $@ };
    like($err, qr/multi-node/i, 'multi-node without a pool dies');
    like($err, qr/network\.lb_pool/, 'the error names the key to set');
    unlike($err, qr{10\.230\.30\.110/32},
        'and does not quietly build a /32 of the control-plane IP');
}

#
# Configured start/stop range (the citiai shape).
#
{
    my $config = config_for({ %$multi,
        network => { lb_pool => { start => '10.230.30.240', stop => '10.230.30.249' } },
    }, 'multi-range');
    my $res = OCP::Cmd::Apply::Network::lb_ipam_resources('10.230.30.110', $config);
    is_deeply($res->[0]{spec}{blocks},
        [{ start => '10.230.30.240', stop => '10.230.30.249' }],
        'configured start/stop range is used verbatim');
    is($res->[0]{metadata}{name}, 'default-pool', 'still default-pool with a configured range');
}

#
# Configured CIDR block.
#
{
    my $config = config_for({ %$multi,
        network => { lb_pool => { cidr => '10.230.30.240/28' } },
    }, 'multi-cidr');
    my $res = OCP::Cmd::Apply::Network::lb_ipam_resources('10.230.30.110', $config);
    is_deeply($res->[0]{spec}{blocks}, [{ cidr => '10.230.30.240/28' }],
        'configured cidr block is used');
}

#
# L2 nodeSelector: brain/cortex are excluded by construction, not by regex.
#
{
    my $config = config_for({ %$multi,
        network => {
            lb_pool => { cidr => '10.230.30.240/28' },
            l2 => {
                node_selector => { 'ai.citilan.de/l2-announce' => 'true' },
                interfaces    => ['^eth[0-9]+$'],
            },
        },
    }, 'multi-l2');
    my $res = OCP::Cmd::Apply::Network::lb_ipam_resources('10.230.30.110', $config);
    my $l2 = $res->[1]{spec};
    is_deeply($l2->{nodeSelector},
        { matchLabels => { 'ai.citilan.de/l2-announce' => 'true' } },
        'nodeSelector.matchLabels comes from network.l2.node_selector');
    is_deeply($l2->{interfaces}, ['^eth[0-9]+$'],
        'configured interfaces replace the built-in list');
}

#
# The built-in interface regexes are anchored on both ends (k127 minimum).
#
{
    my $config = config_for($single, 'single-anchor');
    my $res = OCP::Cmd::Apply::Network::lb_ipam_resources('10.0.0.5', $config);
    for my $pat (@{ $res->[1]{spec}{interfaces} }) {
        like($pat, qr/\$$/, "default interface regex '$pat' is anchored with \$");
        like($pat, qr/^\^/, "default interface regex '$pat' is anchored with ^");
    }
}

#
# Config accessors and validation.
#
{
    my $config = config_for($single, 'accessors-default');
    is($config->lb_pool_blocks, undef, 'lb_pool_blocks is undef when unconfigured');
    is_deeply($config->l2_node_selector, {}, 'l2_node_selector defaults empty');
    is_deeply($config->l2_interfaces, ['^eth[0-9]+$', '^en[a-z0-9]+$'],
        'l2_interfaces default is the anchored built-in list');
}

{
    # start without stop
    my $config = config_for({ %$single,
        network => { lb_pool => { start => '10.0.0.1' } } }, 'bad-startonly');
    ok((grep { /network\.lb_pool.*start and stop/ } $config->validate),
        'start without stop is rejected');
}

{
    # cidr AND start/stop
    my $config = config_for({ %$single,
        network => { lb_pool => { cidr => '10.0.0.0/24', start => '10.0.0.1', stop => '10.0.0.9' } } },
        'bad-both');
    ok((grep { /either cidr or start/ } $config->validate),
        'cidr together with start/stop is rejected');
}

{
    # malformed IP
    my $config = config_for({ %$single,
        network => { lb_pool => { start => '10.0.0.999', stop => '10.0.0.9' } } }, 'bad-ip');
    ok((grep { /not an IPv4/ } $config->validate),
        'a malformed start address is rejected');
}

{
    # malformed cidr
    my $config = config_for({ %$single,
        network => { lb_pool => { cidr => '10.0.0.0/40' } } }, 'bad-cidr');
    ok((grep { /not an IPv4 CIDR/ } $config->validate),
        'a malformed cidr is rejected');
}

{
    # interfaces not a list
    my $config = config_for({ %$single,
        network => { l2 => { interfaces => 'eth0' } } }, 'bad-if');
    ok((grep { /network\.l2\.interfaces/ } $config->validate),
        'interfaces given as a scalar is rejected');
}

{
    # node_selector not a mapping
    my $config = config_for({ %$single,
        network => { l2 => { node_selector => ['a'] } } }, 'bad-ns');
    ok((grep { /network\.l2\.node_selector/ } $config->validate),
        'node_selector given as a list is rejected');
}

{
    # a fully valid network block produces no errors
    my $config = config_for({ %$multi,
        network => {
            lb_pool => { start => '10.230.30.240', stop => '10.230.30.249' },
            l2 => { node_selector => { 'x/y' => 'true' }, interfaces => ['^eth[0-9]+$'] },
        },
    }, 'good-net');
    is_deeply([grep { /network/ } $config->validate], [],
        'a well-formed network block validates clean')
        or diag(join "\n", $config->validate);
}

done_testing;

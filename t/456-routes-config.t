#!/usr/bin/env perl
# karr k456: a Hetzner control plane or pool takes static routes, routes:
# [{ to: CIDR, via: gateway | IPv4 }], which its nodes' OS gets. This file
# holds ocp.yaml's side and the OCPNode spec:
#
#   1. routes is a key validate() takes on a hetzner control plane and pool
#   2. validate() refuses, every line at once and in the place it is at: a
#      routes that is no list, an entry that is no mapping, a key of an entry
#      that is neither to nor via, a missing to or via, a to that is no IPv4
#      CIDR, has host bits set, is the default route or repeats another, a
#      via that is neither gateway nor an IPv4 address, via: gateway without
#      network:, and routes on an ssh or local entry (whose machine OCP did
#      not create)
#   3. worker_ocpnodes and ensure_control_plane_ocpnodes copy routes into the
#      OCPNode spec as written (via: gateway stays gateway; the provider
#      resolves it at install); an entry without routes gets no spec.routes
#   4. the OCPNode CRD declares spec.routes: a list of { to, via }, both
#      required, both held to a pattern that lets nothing but an IPv4 CIDR /
#      gateway or an IPv4 address through
#
# Network-free: OCP::Config on temp files only.

use strict;
use warnings;
use Test::More;

use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';

use OCP::Config;
use OCP::Cmd::Apply::CR;

my $tmp = tempdir(CLEANUP => 1);
my $n   = 0;

sub config_for {
    my ($spec) = @_;
    my $file = path($tmp)->child('c' . ++$n . '.yaml');
    $file->spew_utf8(YAML::XS::Dump({ name => 'hz', %$spec }));
    return OCP::Config->new(file => "$file");
}

my %CP   = (provider => 'hetzner', server_type => 'cpx22', location => 'fsn1', network => 'cai-live');
my %POOL = (name => 'w', provider => 'hetzner', server_type => 'cpx32', nodes => 2, network => 'cai-live');
my @LAB  = ({ to => '10.230.30.0/24', via => 'gateway' });

sub cp_errors   { config_for({ control_planes => { %CP, @_ } })->validate }
sub pool_errors { config_for({ control_planes => { %CP }, workers => [ { %POOL, @_ } ] })->validate }

# ---------------------------------------------------------------- 1

subtest 'routes is taken on a hetzner control plane and pool' => sub {
    is_deeply [ cp_errors(routes => \@LAB) ], [], 'a control plane: via gateway';
    is_deeply [ pool_errors(routes => \@LAB) ], [], 'a pool: via gateway';
    is_deeply [ cp_errors(routes => [ { to => '10.230.30.0/24', via => '10.200.0.1' },
                                      { to => '192.168.50.0/23', via => 'gateway' } ]) ],
        [], 'an address as via, and two routes';
    is_deeply [ config_for({ control_planes => { %CP, network => undef,
        routes => [ { to => '10.230.30.0/24', via => '10.200.0.1' } ] } })->validate ],
        [], 'an address as via needs no network:';
    is_deeply [ cp_errors(routes => []) ], [], 'an empty list: no routes';
};

# ---------------------------------------------------------------- 2

subtest 'what routes refuses, in place' => sub {
    is_deeply [ cp_errors(routes => '10.230.30.0/24') ],
        [ "control_planes[1]: routes must be a list like [ { to: 10.230.30.0/24, via: gateway } ], "
          . "not '10.230.30.0/24'" ], 'a string';
    is_deeply [ cp_errors(routes => { to => '10.230.30.0/24', via => 'gateway' }) ],
        [ "control_planes[1]: routes must be a list like [ { to: 10.230.30.0/24, via: gateway } ], "
          . 'not a mapping' ], 'one mapping, not a list of them';
    is_deeply [ cp_errors(routes => [ '10.230.30.0/24' ]) ],
        [ "control_planes[1]: routes[1] must be a mapping like { to: 10.230.30.0/24, via: gateway }, "
          . "not '10.230.30.0/24'" ], 'an entry that is a string';
    is_deeply [ cp_errors(routes => [ { %{ $LAB[0] }, dev => 'enp7s0', metric => 10 } ]) ],
        [ 'control_planes[1]: routes[1].dev is an unknown key (must be to or via)',
          'control_planes[1]: routes[1].metric is an unknown key (must be to or via)' ],
        'unknown keys: a line each, sorted';
    is_deeply [ cp_errors(routes => [ { via => 'gateway' } ]) ],
        [ 'control_planes[1]: routes[1] needs to: the IPv4 network the route leads to (e.g. 10.230.30.0/24)' ],
        'no to';
    is_deeply [ cp_errors(routes => [ { to => '10.230.30.0/24' } ]) ],
        [ 'control_planes[1]: routes[1] needs via: gateway (the Hetzner network gateway) or an IPv4 address' ],
        'no via -- there is no default next hop';
    is_deeply [ cp_errors(routes => [ { to => 'lab', via => 'gateway' },
                                      { to => '10.230.30.0/33', via => 'gateway' },
                                      { to => [ '10.0.0.0/8' ], via => 'gateway' } ]) ],
        [ "control_planes[1]: routes[1].to must be an IPv4 CIDR (e.g. 10.230.30.0/24), not 'lab'",
          "control_planes[1]: routes[2].to must be an IPv4 CIDR (e.g. 10.230.30.0/24), not '10.230.30.0/33'",
          'control_planes[1]: routes[3].to must be an IPv4 CIDR (e.g. 10.230.30.0/24), not a list' ],
        'a to that is no IPv4 CIDR';
    is_deeply [ cp_errors(routes => [ { to => '10.230.30.7/24', via => 'gateway' } ]) ],
        [ "control_planes[1]: routes[1].to '10.230.30.7/24' has host bits set; the network address is "
          . '10.230.30.0/24' ], 'host bits set: ip route would refuse it on the node';
    my @default = cp_errors(routes => [ { to => '0.0.0.0/0', via => 'gateway' } ]);
    is scalar(@default), 1, 'the default route: one line';
    like $default[0], qr/\Acontrol_planes\[1\]: routes\[1\]\.to is the default route: the server keeps its public default route/,
        '... saying the public default route stays';
    is_deeply [ cp_errors(routes => [ @LAB, { to => '10.230.30.0/24', via => '10.200.0.9' } ]) ],
        [ "control_planes[1]: routes[2].to '10.230.30.0/24' is routed by routes[1] already" ],
        'one network routed twice';
    is_deeply [ cp_errors(routes => [ { to => '10.230.30.0/24', via => 'gw' },
                                      { to => '10.230.31.0/24', via => '10.200.0.256' } ]) ],
        [ "control_planes[1]: routes[1].via must be gateway or an IPv4 address, not 'gw'",
          "control_planes[1]: routes[2].via must be gateway or an IPv4 address, not '10.200.0.256'" ],
        'a via that is neither';
    is_deeply [ config_for({ control_planes => { %CP, network => undef, routes => \@LAB } })->validate ],
        [ 'control_planes[1]: routes[1].via is gateway, which needs network: the Hetzner network whose '
          . 'gateway the route goes through' ], 'via: gateway without network:';

    is_deeply [ pool_errors(routes => [ { to => 'lab', via => 'gw' } ]) ],
        [ "worker pool 'w': routes[1].to must be an IPv4 CIDR (e.g. 10.230.30.0/24), not 'lab'",
          "worker pool 'w': routes[1].via must be gateway or an IPv4 address, not 'gw'" ],
        'a pool: the same lines, under its name';
};

subtest 'routes on an ssh or local entry' => sub {
    my @cp = config_for({ control_planes => { provider => 'ssh', host => 'cp.lab', routes => \@LAB } })->validate;
    is_deeply \@cp, [ 'control_planes[1]: routes is read for a hetzner control plane only: OCP leaves '
        . 'the routes of a machine it did not create to that machine -- set them there, and delete this' ],
        'an ssh control plane: one line, nothing about the shape';
    my @pool = config_for({ control_planes => { %CP },
        workers => [ { name => 'l', provider => 'ssh', host => 'w.lab', routes => 'x' } ] })->validate;
    is_deeply \@pool, [ "worker pool 'l': routes is read for a hetzner worker pool only: OCP leaves "
        . 'the routes of a machine it did not create to that machine -- set them there, and delete this' ],
        'an ssh pool: the same, even for a routes of the wrong shape';
};

# ---------------------------------------------------------------- 3

subtest 'the OCPNode spec carries routes as written' => sub {
    my $config = config_for({
        control_planes => [ map { { %CP, routes => \@LAB } } 1 .. 2 ],
        workers        => [ { %POOL, routes => [ @LAB, { to => '10.230.31.0/24', via => '10.200.0.9' } ] },
                            { %POOL, name => 'p' } ],
    });
    is_deeply [ $config->validate ], [], 'a valid ocp.yaml';

    my @crs = OCP::Cmd::Apply::CR::worker_ocpnodes($config);
    is scalar(@crs), 4, 'four workers';
    for my $cr (@crs[0, 1]) {
        is_deeply $cr->{spec}{routes},
            [ { to => '10.230.30.0/24', via => 'gateway' }, { to => '10.230.31.0/24', via => '10.200.0.9' } ],
            "$cr->{metadata}{name}: spec.routes, via: gateway unresolved";
    }
    ok !exists $_->{spec}{routes}, "$_->{metadata}{name}: no routes, no spec.routes" for @crs[2, 3];

    package EnsureApi { sub new { bless {}, shift } sub ensure { push @main::ENSURED, $_[1] } }
    our @ENSURED;
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $old = select $fh;
    OCP::Cmd::Apply::CR::ensure_control_plane_ocpnodes(undef, EnsureApi->new, $config);
    select $old;
    is scalar(@ENSURED), 1, 'police2';
    is_deeply $ENSURED[0]{spec}{routes}, \@LAB, 'police2: spec.routes';
};

# ---------------------------------------------------------------- 4

subtest 'the OCPNode CRD declares spec.routes' => sub {
    my ($crd) = YAML::XS::LoadFile('share/robocop/crds/ocpnode.yaml');
    my $routes = $crd->{spec}{versions}[0]{schema}{openAPIV3Schema}{properties}{spec}{properties}{routes};
    ok $routes, 'declared' or return;
    is $routes->{type}, 'array', 'a list';
    is $routes->{items}{type}, 'object', 'of objects';
    is_deeply [ sort @{ $routes->{items}{required} } ], [ qw( to via ) ], 'to and via required';
    is_deeply [ sort keys %{ $routes->{items}{properties} } ], [ sort @OCP::Config::ROUTE_KEYS ],
        "ocp.yaml's route keys, no other";
    ok !exists $routes->{default}, 'no default';

    my $to  = qr/$routes->{items}{properties}{to}{pattern}/;
    my $via = qr/$routes->{items}{properties}{via}{pattern}/;
    like   '10.230.30.0/24', $to,  'to: a CIDR passes';
    unlike $_, $to,  "to: '$_' does not" for ('10.230.30.0', '10.230.30.0/24; reboot', 'lab', '10x230x30x0/24');
    like   $_, $via, "via: '$_' passes" for ('gateway', '10.200.0.1');
    unlike $_, $via, "via: '$_' does not" for ('gateway2', '10.200.0.1 dev eth0', '$(reboot)');
};

done_testing;

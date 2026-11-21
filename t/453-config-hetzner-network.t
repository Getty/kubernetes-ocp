#!/usr/bin/env perl
# karr k453: a Hetzner control plane or pool joins an existing hcloud network,
# with existing firewalls, and OCP may use its private address. This file
# holds ocp.yaml's side:
#
#   1. network, firewalls and address on a hetzner control plane and pool, and
#      tls_san on a control plane, are keys validate() takes -- before k453
#      they were unknown keys
#   2. validate() refuses, every line at once: a network that is no name or
#      id, firewalls that are no list of them, an address that is neither
#      public nor private, address: private without a network, a tls_san that
#      is no list of names or addresses, and network/firewalls/address on an
#      ssh or local entry (which creates no server)
#   3. under address: private the first control plane's address is its
#      private_ip: join_host, cluster_status and cp_tls_sans read it instead
#      of public_ip; tls_san names go into the tls-san; address: public (or
#      none) reads public_ip as before
#   4. the address line is at spec_errors' path control_planes[1].address
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
use OCP::Cmd::Apply::Bootstrap;

my $tmp = tempdir(CLEANUP => 1);
my $n   = 0;

sub config_for {
    my ($spec) = @_;
    my $file = path($tmp)->child('c' . ++$n . '.yaml');
    $file->spew_utf8(YAML::XS::Dump({ name => 'hz', %$spec }));
    return OCP::Config->new(file => "$file");
}

my %CP = (provider => 'hetzner', server_type => 'cpx22', location => 'fsn1');
my %POOL = (name => 'w', provider => 'hetzner', server_type => 'cpx32', nodes => 1);

# ---------------------------------------------------------------- 1

subtest 'network, firewalls, address and tls_san are taken' => sub {
    my $config = config_for({
        control_planes => { %CP, network => 'cai-live', firewalls => [ 'cai-live-fw', 4711 ],
                            address => 'private', tls_san => [ 'api.hz.example', '10.200.0.2' ] },
        workers        => [ { %POOL, network => 4242, firewalls => [ 'cai-live-fw' ], address => 'private' } ],
    });
    is_deeply [ $config->validate ], [], 'no line';

    is_deeply [ config_for({ control_planes => { %CP, network => 'cai-live', address => 'public' } })->validate ],
        [], 'address: public with a network';
    is_deeply [ config_for({ control_planes => { %CP, network => 'cai-live' } })->validate ],
        [], 'a network alone (public address, as before)';
    is_deeply [ config_for({ control_planes => { provider => 'ssh', host => 'cp.hz.test',
                                                 tls_san => [ 'api.hz.example' ] } })->validate ],
        [], 'tls_san on an ssh control plane: the certificate is any provider\'s';
};

# ---------------------------------------------------------------- 2

subtest 'what validate() refuses, every line at once' => sub {
    my @lines = config_for({
        control_planes => { %CP, network => [ 'a' ], firewalls => 'cai-live-fw', address => 'internal',
                            tls_san => 'api.hz.example' },
        workers        => [ { %POOL, network => '', firewalls => [ 'ok', {} ], address => 'private' } ],
    })->validate;

    my @want = (
        "control_planes[1]: network must be the name or id of an existing Hetzner network, not a list",
        "control_planes[1]: firewalls must be a list of names or ids of existing Hetzner firewalls, not 'cai-live-fw'",
        "control_planes[1]: address must be public or private, not 'internal'",
        "control_planes[1]: tls_san must be a list of names or addresses the API server certificate also carries, not 'api.hz.example'",
        "worker pool 'w': network must be the name or id of an existing Hetzner network, not ''",
        "worker pool 'w': firewalls[2] must be the name or id of an existing Hetzner firewall, not a mapping",
        "worker pool 'w': address is private, which needs network: the Hetzner network whose address OCP is to use",
    );
    for my $line (@want) {
        is scalar(grep { $_ eq $line } @lines), 1, $line;
    }
    is scalar(@lines), scalar(@want), 'and nothing else'
        or diag explain \@lines;

    my @sans = config_for({ control_planes => { %CP, tls_san => [ 'api.hz.example', 'a b', '' ] } })->validate;
    is_deeply \@sans, [
        "control_planes[1]: tls_san[2] must be a host name or IP address, not 'a b'",
        "control_planes[1]: tls_san[3] must be a host name or IP address, not ''",
    ], 'a tls_san entry that is no name';

    my @private = config_for({ control_planes => { %CP, address => 'private' } })->validate;
    is_deeply \@private, [ "control_planes[1]: address is private, which needs network: the Hetzner "
        . "network whose address OCP is to use" ], 'address: private without a network, on a control plane';
};

subtest 'an ssh or local entry takes none of them' => sub {
    my @lines = config_for({
        control_planes => { provider => 'ssh', host => 'cp.hz.test', network => 'cai-live' },
        workers        => [ { name => 'l', provider => 'local', firewalls => [ 'fw' ], address => 'private' } ],
    })->validate;
    is_deeply \@lines, [
        "control_planes[1]: network is read for a hetzner control plane only: provider ssh creates no "
            . "server, its machine is in the networks it is in -- delete it",
        "worker pool 'l': firewalls is read for a hetzner worker pool only: provider local creates no "
            . "server, its machine is in the networks it is in -- delete it",
        "worker pool 'l': address is read for a hetzner worker pool only: provider local creates no "
            . "server, its machine is in the networks it is in -- delete it",
    ], 'one line per key, nothing about their shape';
};

subtest 'a key that is none of them is still unknown' => sub {
    my @lines = config_for({ control_planes => { %CP, networks => [ 'cai-live' ] } })->validate;
    is scalar(@lines), 1, 'one line';
    like $lines[0], qr/\Acontrol_planes\[1\]\.networks: unknown key \(must be .*network, firewalls, address, tls_san, routes, or nodes\)\z/,
        'networks: unknown, the choices name network';
};

# ---------------------------------------------------------------- 3

subtest 'address: private reads the private_ip' => sub {
    my $config = config_for({ control_planes => { %CP, network => 'cai-live', address => 'private',
        public_ip => '203.0.113.10', private_ip => '10.200.0.2', tls_san => [ 'api.hz.example' ] } });
    ok( OCP::Config->uses_private_address($config->control_planes->[0]), 'uses_private_address' );
    is $config->join_host('adv'), '10.200.0.2', 'join_host: the private_ip, not the public_ip';
    is $config->join_url($config->join_host('adv')), 'https://10.200.0.2:9345', 'the workers join there';
    is $config->cluster_status->{public_ip}, '10.200.0.2', 'cluster_status: the private_ip';
    is_deeply [ OCP::Cmd::Apply::Bootstrap::cp_tls_sans($config, '10.200.0.2') ],
        [ '10.200.0.2', 'api.hz.example' ], 'tls-san: the private address and the extra name, no public_ip';

    my $unpinned = config_for({ control_planes => { %CP, network => 'cai-live', address => 'private',
        public_ip => '203.0.113.10' } });
    is $unpinned->join_host('10.200.0.2'), '10.200.0.2',
        'no private_ip pinned: the advertised address, not the public_ip';

    my $public = config_for({ control_planes => { %CP, network => 'cai-live',
        public_ip => '203.0.113.10', private_ip => '10.200.0.2' } });
    ok( !OCP::Config->uses_private_address($public->control_planes->[0]), 'no address: public' );
    is $public->join_host('adv'), '203.0.113.10', 'join_host: the public_ip, as before';
    is $public->cluster_status->{public_ip}, '203.0.113.10', 'cluster_status: the public_ip, as before';
    is_deeply [ OCP::Cmd::Apply::Bootstrap::cp_tls_sans($public) ], [ '203.0.113.10' ],
        'tls-san: the public_ip, as before';
};

# ---------------------------------------------------------------- 4

subtest 'the address line is at control_planes[1].address' => sub {
    my $config = config_for({ control_planes => { %CP, network => 'n', address => [ 'private' ] } });
    is_deeply [ $config->spec_errors('control_planes[1].address') ],
        [ "control_planes[1]: address must be public or private, not a list" ], 'spec_errors finds it';
    is_deeply [ $config->spec_errors('control_planes[1].host') ], [], 'and not at another path';
};

done_testing;

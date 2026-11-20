#!/usr/bin/env perl
# karr k453: OCP::Provider::Hetzner joins an existing network and attaches
# existing firewalls, and reports the private address when asked to.
#
# The claims:
#
#   1. create_server sends networks => [ id ] and firewalls => [ ids ]: an id
#      as it is, a name looked up through list_all(name => ...), exact match
#      only; from the named options (bootstrap) or the OCPNode spec (robocop)
#   2. a network or firewall that does not exist dies before anything is
#      ordered -- OCP creates none -- and so does address: private without a
#      network; nothing is created, deleted or changed on a network or
#      firewall, ever
#   3. without network/firewalls the create body is what it was: neither key
#   4. wait_for_running reports the server's address in the network under
#      address: private (resolving a network given by name), the public IPv4
#      otherwise, and dies when a private address is asked for and there is
#      none; an existing server is reported the same way
#   5. OCP::Node hands spec.address and spec.network to wait_for_running
#
# Network-free: a fake WWW::Hetzner::Cloud records every call.

use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Provider::Hetzner;
use OCP::KnownHosts;

# known_hosts is not this test's business.
{ no warnings 'redefine'; *OCP::KnownHosts::forget = sub { 1 }; }

# --- a fake cloud -----------------------------------------------------------

package FakeEntity {
    sub new { my ($class, %a) = @_; return bless {%a}, $class }
    sub id          { $_[0]{id} }
    sub name        { $_[0]{name} }
    sub ipv4        { $_[0]{ipv4} }
    sub private_net { $_[0]{private_net} // [] }
}

package FakeCtl {
    sub new { my ($class, %a) = @_; return bless { items => [], calls => [], %a }, $class }
    sub calls { @{ $_[0]{calls} } }
    sub list_all {
        my ($self, %q) = @_;
        push @{ $self->{calls} }, [ list_all => %q ];
        return [ grep {
            (!defined $q{name} || $_->name eq $q{name})
            && (!defined $q{label_selector} || 1)
        } @{ $self->{items} } ];
    }
    sub get {
        my ($self, $id) = @_;
        push @{ $self->{calls} }, [ get => $id ];
        my ($hit) = grep { $_->id eq $id } @{ $self->{items} };
        die "Hetzner API error: not_found\n" unless $hit;
        return $hit;
    }
    sub create {
        my ($self, %a) = @_;
        push @{ $self->{calls} }, [ create => %a ];
        return FakeEntity->new(id => 99, name => $a{name});
    }
    sub wait_for_status {
        my ($self, $id) = @_;
        push @{ $self->{calls} }, [ wait_for_status => $id ];
        return $self->{running};
    }
}

package FakeCloud {
    sub new { my ($class, %a) = @_; return bless {%a}, $class }
    sub servers   { $_[0]{servers} }
    sub networks  { $_[0]{networks} }
    sub firewalls { $_[0]{firewalls} }
}

package main;

sub fixture {
    my (%o) = @_;
    my $cloud = FakeCloud->new(
        servers   => FakeCtl->new(items => $o{servers} // [], running => $o{running}),
        networks  => FakeCtl->new(items => [
            FakeEntity->new(id => 4242, name => 'cai-live'),
            FakeEntity->new(id => 4243, name => 'cai-live-2'),
        ]),
        firewalls => FakeCtl->new(items => [
            FakeEntity->new(id => 71, name => 'cai-live-fw'),
            FakeEntity->new(id => 72, name => 'ssh-only'),
        ]),
    );
    my $prov = OCP::Provider::Hetzner->new(token => 't0k3n', cluster_name => 'hz',
        ssh_key_name => 'ocp-hz-admin', cloud => $cloud);
    return ($prov, $cloud);
}

sub created {
    my ($cloud) = @_;
    my ($call) = grep { $_->[0] eq 'create' } $cloud->servers->calls;
    return $call ? { @$call[1 .. $#$call] } : undef;
}

sub writes_on_networks_or_firewalls {
    my ($cloud) = @_;
    return grep { $_->[0] !~ /\A(?:get|list_all)\z/ } $cloud->networks->calls, $cloud->firewalls->calls;
}

my %CREATE = (name => 'hz-police1', node => 'police1', role => 'control-plane', server_type => 'cpx22');

# ---------------------------------------------------------------- 1, 3

subtest 'names and ids become ids in the create body' => sub {
    my ($prov, $cloud) = fixture();
    my $info = $prov->create_server(%CREATE, network => 'cai-live', firewalls => [ 'cai-live-fw', 72 ],
                                    address => 'private');
    my $body = created($cloud);
    is_deeply $body->{networks},  [ 4242 ],     'networks: the id of cai-live';
    is_deeply $body->{firewalls}, [ 71, 72 ],   'firewalls: the id of the name, the id as it is';
    is $info->{address},    'private', 'the info carries the address';
    is $info->{network_id}, 4242,      'and the network id';
    is_deeply [ writes_on_networks_or_firewalls($cloud) ], [], 'nothing written on a network or firewall';

    my ($p2, $c2) = fixture();
    $p2->create_server(%CREATE, network => 4243);
    is_deeply created($c2)->{networks}, [ 4243 ], 'a network id as it is';
    is scalar(grep { $_->[0] eq 'list_all' } $c2->networks->calls), 0, 'and not looked up by name';
};

subtest 'from the OCPNode spec, as robocop calls it' => sub {
    my ($prov, $cloud) = fixture();
    $prov->create_server(name => 'w-1', node => 'w-1', role => 'worker',
        spec => { serverType => 'cpx32', network => 'cai-live', firewalls => [ 'cai-live-fw' ],
                  address => 'private' });
    my $body = created($cloud);
    is_deeply $body->{networks},  [ 4242 ], 'spec.network';
    is_deeply $body->{firewalls}, [ 71 ],   'spec.firewalls';

    my ($p2, $c2) = fixture();
    $p2->create_server(%CREATE, network => 'cai-live-2', spec => { network => 'cai-live' });
    is_deeply created($c2)->{networks}, [ 4243 ], 'the named option wins over the spec';
};

subtest 'without them the body has neither key' => sub {
    my ($prov, $cloud) = fixture();
    $prov->create_server(%CREATE);
    my $body = created($cloud);
    ok !exists $body->{networks},  'no networks';
    ok !exists $body->{firewalls}, 'no firewalls';
    is scalar($cloud->networks->calls) + scalar($cloud->firewalls->calls), 0, 'and no lookup';
};

# ---------------------------------------------------------------- 2

subtest 'what does not exist refuses the server before it is ordered' => sub {
    my ($prov, $cloud) = fixture();
    my $err = eval { $prov->create_server(%CREATE, network => 'cai-live-3'); 1 } ? '' : $@;
    is $err, "Hetzner server 'hz-police1': there is no Hetzner network 'cai-live-3' in this project. "
        . "OCP uses an existing network and creates none: create it, or name one that exists "
        . "(network: in ocp.yaml, spec.network on an OCPNode).\n", 'a network: one line';
    is created($cloud), undef, 'nothing ordered';

    ($prov, $cloud) = fixture();
    $err = eval { $prov->create_server(%CREATE, firewalls => [ 'cai-live-fw', 99 ]); 1 } ? '' : $@;
    like $err, qr/\AHetzner server 'hz-police1': there is no Hetzner firewall '99' in this project\. /,
        'a firewall id that does not exist';
    is created($cloud), undef, 'nothing ordered';

    ($prov, $cloud) = fixture();
    $err = eval { $prov->create_server(%CREATE, firewalls => [ 'cai-live' ]); 1 } ? '' : $@;
    like $err, qr/no Hetzner firewall 'cai-live'/, 'a network name is no firewall';

    ($prov, $cloud) = fixture();
    $err = eval { $prov->create_server(%CREATE, network => 'cai'); 1 } ? '' : $@;
    like $err, qr/no Hetzner network 'cai'/, 'a name matches exactly, not as a prefix';

    ($prov, $cloud) = fixture();
    $err = eval { $prov->create_server(%CREATE, address => 'private'); 1 } ? '' : $@;
    like $err, qr/\ARefusing to create Hetzner server 'hz-police1' with address private and no network/,
        'address: private without a network';
    is created($cloud), undef, 'nothing ordered';
};

# ---------------------------------------------------------------- 4

my $SERVER = FakeEntity->new(id => 99, ipv4 => '203.0.113.10',
    private_net => [ { network => 4243, ip => '10.201.0.5' }, { network => 4242, ip => '10.200.0.2' } ]);

subtest 'wait_for_running: which address' => sub {
    my ($prov) = fixture(running => $SERVER);
    my $info = $prov->create_server(%CREATE, network => 'cai-live', address => 'private');
    $prov->wait_for_running($info);
    is $info->{ip}, '10.200.0.2', 'private: the address in that network, not the first one';

    ($prov) = fixture(running => $SERVER);
    $info = $prov->create_server(%CREATE, network => 'cai-live');
    $prov->wait_for_running($info);
    is $info->{ip}, '203.0.113.10', 'a network, address public: the public IPv4';

    ($prov) = fixture(running => $SERVER);
    $info = { id => 99, address => 'private', network => 'cai-live' };
    $prov->wait_for_running($info);
    is $info->{ip}, '10.200.0.2', 'the network by name, as OCP::Node hands it';

    ($prov) = fixture(running => FakeEntity->new(id => 99, ipv4 => '203.0.113.10', private_net => []));
    my $err = eval { $prov->wait_for_running({ id => 99, address => 'private', network => 4242 }); 1 } ? '' : $@;
    like $err, qr/\AHetzner server 99 is running without an address in its network/,
        'private and none there: dies, no public address instead';
};

subtest 'an existing server' => sub {
    my $existing = FakeEntity->new(%$SERVER, name => 'hz-police1');
    my ($prov, $cloud) = fixture(servers => [ $existing ]);
    my $info = $prov->create_server(%CREATE, network => 'cai-live', address => 'private');
    is $info->{newly_created}, 0, 'found, not created';
    is $info->{ip}, '10.200.0.2', 'reported at its address in the network';
    is created($cloud), undef, 'nothing ordered';

    my $outside = FakeEntity->new(id => 98, name => 'hz-police1', ipv4 => '203.0.113.11', private_net => []);
    ($prov) = fixture(servers => [ $outside ]);
    my $err = eval { $prov->create_server(%CREATE, network => 'cai-live', address => 'private'); 1 } ? '' : $@;
    like $err, qr/\AHetzner server 'hz-police1' exists, but has no address in network 'cai-live': OCP does not move/,
        'one outside the network: said, not moved';
};

# ---------------------------------------------------------------- 5

subtest 'OCP::Node hands spec.address and spec.network on' => sub {
    require OCP::Node;
    our %GOT;
    package SeenProvider { sub new { bless {}, shift } sub wait_for_running { my ($s, $i) = @_;
        %main::GOT = %$i; $i->{ip} = '10.200.0.7'; $i } }
    my $node = bless {
        cr => { metadata => { name => 'w-1' },
                spec     => { role => 'worker', network => 'cai-live', address => 'private' },
                status   => { providerId => 99 } },
        provider => SeenProvider->new,
    }, 'OCP::Node';
    no warnings 'redefine';
    local *OCP::Node::_patch_status = sub { 1 };
    is $node->_resolve_host, '10.200.0.7', 'the address the provider reports';
    is_deeply \%main::GOT, { id => 99, address => 'private', network => 'cai-live' },
        'handed id, address and network';
};

done_testing;

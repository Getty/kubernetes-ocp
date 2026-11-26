#!/usr/bin/env perl
# karr k453: the private address is the one OCP uses, on ocp apply's
# bootstrap and on the worker path robocop drives.
#
# The claims:
#
#   1. bootstrap hands create_server the first control plane's network,
#      firewalls and address; under address: private the address
#      wait_for_running reports (the one in the network) is the SSH target,
#      the Rex transport, the advertised host (tls-san, kubeconfig server),
#      the node API host and the join address, and it is the node-ip the
#      install is handed -- police1 joins nothing, so without it RKE2 would
#      register and advertise the public address. tls_san names are in the
#      tls-san.
#   2. without address: private the bootstrap hands no node-ip (as before)
#      and no network keys when ocp.yaml names none
#   3. worker_ocpnodes copies a hetzner pool's network, firewalls and address
#      into every OCPNode spec (spec.network, spec.firewalls, spec.address),
#      and ensure_control_plane_ocpnodes a police2+'s; a pool without them
#      gets none of the three
#   4. the OCPNode CRD declares spec.network, spec.firewalls and spec.address,
#      whose enum is OCP::Config's address choices -- an older CRD would
#      prune them, and the worker would be created outside the network
#
# Network-free: the provider, SSH and Rex are stand-ins.

use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::CR;
use OCP::Config;
use OCP::Rex;
use OCP::Secrets;
use OCP::SSH;

no warnings 'once';

package FakeOcp { sub new { bless {}, shift } sub verbose { 0 } }

# A Hetzner stand-in that answers as OCP::Provider::Hetzner does: no ip from
# create_server, the address by address/network from wait_for_running.
package NetProv {
    sub new            { bless {}, shift }
    sub upload_ssh_key { }
    sub create_server  {
        my ($self, %o) = @_;
        $main::CREATE = { %o };
        return { id => 7, ip => undef, newly_created => 1, address => $o{address} // 'public',
                 network_id => defined $o{network} ? 4242 : undef };
    }
    sub wait_for_running {
        my ($self, $info) = @_;
        $info->{ip} = $info->{address} eq 'private' ? '10.200.0.2' : '203.0.113.10';
        return $info;
    }
    sub cleanup_on_failure { }
}

package main;

our ($CREATE, %REX, %INSTALL, $SSH_HOST);

sub project {
    my ($spec) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({ name => 'hz', %$spec }));
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# bootstrap_control_plane up to the install, which is recorded and stopped.
sub bootstrap {
    my ($config) = @_;
    ($CREATE, %REX, %INSTALL, $SSH_HOST) = (undef);
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $old = select $fh;
    eval {
        no warnings 'redefine';
        # The cleanup line a stopped install prints is not under test.
        open local *STDERR, '>', \my $stderr or die $!;
        local *OCP::Provider::for_spec      = sub { NetProv->new };
        local *OCP::Secrets::ensure_age_key = sub { 1 };
        local *OCP::SSH::new          = sub { my ($c, %a) = @_; $SSH_HOST = $a{host}; bless {%a}, $c };
        local *OCP::SSH::wait_for_ssh = sub { 1 };
        local *OCP::Rex::new          = sub { my ($c, %a) = @_; %REX = %a; bless {%a}, $c };
        local *OCP::Rex::install_server = sub { my ($s, %a) = @_; %INSTALL = %a; die "stop at the install\n" };
        OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
            $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
            admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
        );
    };
    my $died = $@;
    select $old;
    return $died;
}

my %CP = (provider => 'hetzner', server_type => 'cpx22', location => 'fsn1');

# ---------------------------------------------------------------- 1

subtest 'address: private -- the private address throughout' => sub {
    my $config = project({ control_planes => { %CP, network => 'cai-live', firewalls => [ 'cai-live-fw' ],
        address => 'private', tls_san => [ 'api.hz.example' ] } });
    is_deeply [ $config->validate ], [], 'a valid ocp.yaml';
    is bootstrap($config), "stop at the install\n", 'ran to the install';

    is $CREATE->{network}, 'cai-live', 'create_server: the network';
    is_deeply $CREATE->{firewalls}, [ 'cai-live-fw' ], 'the firewalls';
    is $CREATE->{address}, 'private', 'the address';

    is $SSH_HOST,              '10.200.0.2', 'SSH waits on the private address';
    is $REX{host},             '10.200.0.2', 'Rex connects there';
    is $REX{advertised_host},  '10.200.0.2', 'and advertises it (kubeconfig server)';
    is $REX{node_api_host},    '10.200.0.2', 'the nodes reach the API there';
    is $INSTALL{node_ip},      '10.200.0.2', 'the node-ip: the private address';
    is_deeply $INSTALL{tls_san}, [ '10.200.0.2', 'api.hz.example' ], 'tls-san: the private address and the name';
    ok !grep({ $_ eq '203.0.113.10' } @{ $INSTALL{tls_san} }), 'not the public address';

    my $pinned = project({ control_planes => { %CP, network => 'cai-live', address => 'private',
        node_ip => '10.200.0.9' } });
    bootstrap($pinned);
    is $INSTALL{node_ip}, '10.200.0.9', 'a node_ip ocp.yaml names wins';
};

# ---------------------------------------------------------------- 2

subtest 'without address: private, as before' => sub {
    my $config = project({ control_planes => { %CP } });
    bootstrap($config);
    ok !exists $CREATE->{$_}, "create_server gets no $_" for qw( network firewalls address );
    is $REX{host},        '203.0.113.10', 'the public address';
    ok !exists $INSTALL{node_ip}, 'no node-ip handed';

    my $net = project({ control_planes => { %CP, network => 'cai-live' } });
    bootstrap($net);
    is $CREATE->{network}, 'cai-live', 'a network alone: joined';
    is $REX{host}, '203.0.113.10', 'and still reached at the public address';
    ok !exists $INSTALL{node_ip}, 'no node-ip handed';
};

# ---------------------------------------------------------------- 3

subtest 'OCPNodes carry the pool\'s and police2+\'s network keys' => sub {
    my $config = project({
        control_planes => [ map { { %CP, network => 'cai-live', address => 'private' } } 1 .. 3 ],
        workers => [
            { name => 'w', provider => 'hetzner', server_type => 'cpx32', nodes => 2,
              network => 'cai-live', firewalls => [ 'cai-live-fw' ], address => 'private' },
            { name => 'p', provider => 'hetzner', server_type => 'cpx32', network => 'cai-live' },
        ],
    });
    is_deeply [ $config->validate ], [], 'a valid ocp.yaml';
    my @crs = OCP::Cmd::Apply::CR::worker_ocpnodes($config);
    is scalar(@crs), 3, 'three workers';
    for my $cr (@crs[0, 1]) {
        is $cr->{spec}{network}, 'cai-live', "$cr->{metadata}{name}: spec.network";
        is_deeply $cr->{spec}{firewalls}, [ 'cai-live-fw' ], "$cr->{metadata}{name}: spec.firewalls";
        is $cr->{spec}{address}, 'private', "$cr->{metadata}{name}: spec.address";
    }
    is $crs[2]{spec}{network}, 'cai-live', 'a pool with a network alone: spec.network';
    ok !exists $crs[2]{spec}{$_}, "and no spec.$_" for qw( firewalls address );

    # A pool without any of them -- beside a control plane on the public
    # address, as a pool beside a private one needs network: (k474).
    my $plain = project({
        control_planes => { %CP },
        workers        => [ { name => 'p', provider => 'hetzner', server_type => 'cpx32' } ],
    });
    is_deeply [ $plain->validate ], [], 'a valid ocp.yaml';
    my ($bare) = OCP::Cmd::Apply::CR::worker_ocpnodes($plain);
    ok !exists $bare->{spec}{$_}, "a pool without them: no spec.$_" for qw( network firewalls address );

    package EnsureApi { sub new { bless {}, shift } sub ensure { push @main::ENSURED, $_[1] } }
    our @ENSURED;
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $old = select $fh;
    OCP::Cmd::Apply::CR::ensure_control_plane_ocpnodes(undef, EnsureApi->new, $config);
    select $old;
    is scalar(@ENSURED), 2, 'police2 and police3';
    is $_->{spec}{network}, 'cai-live', "$_->{metadata}{name}: spec.network" for @ENSURED;
    is $_->{spec}{address}, 'private',  "$_->{metadata}{name}: spec.address" for @ENSURED;
};

# ---------------------------------------------------------------- 4

subtest 'the OCPNode CRD declares them' => sub {
    my ($crd) = YAML::XS::LoadFile('share/robocop/crds/ocpnode.yaml');
    my $props = $crd->{spec}{versions}[0]{schema}{openAPIV3Schema}{properties}{spec}{properties};
    is $props->{network}{type}, 'string', 'spec.network: a string';
    is $props->{firewalls}{type}, 'array', 'spec.firewalls: a list';
    is $props->{firewalls}{items}{type}, 'string', 'of strings';
    is_deeply [ sort @{ $props->{address}{enum} } ], [ sort @OCP::Config::ADDRESS_CHOICES ],
        'spec.address: the address choices of ocp.yaml';
    ok !exists $props->{address}{default}, 'no default: absent is the public address';
};

done_testing;

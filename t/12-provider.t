#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::Provider;
use OCP::Provider::Hetzner;
use OCP::Provider::SSH;
use OCP::Provider::Local;

#
# Test: Factory returns correct provider type
#

{
    my $hetzner = OCP::Provider->for_spec(
        { provider => 'hetzner' },
        token => 'fake-token',
        cluster_name => 'test',
    );
    isa_ok($hetzner, 'OCP::Provider::Hetzner', 'for_spec hetzner');
}

{
    my $ssh = OCP::Provider->for_spec(
        { provider => 'ssh' },
        ssh_key_path => '/tmp/fake.key',
    );
    isa_ok($ssh, 'OCP::Provider::SSH', 'for_spec ssh');
}

{
    my $local = OCP::Provider->for_spec(
        { provider => 'local' },
    );
    isa_ok($local, 'OCP::Provider::Local', 'for_spec local');
}

#
# Test: Default provider is hetzner
#

{
    my $default = OCP::Provider->for_spec(
        {},
        token => 'fake-token',
        cluster_name => 'test',
    );
    isa_ok($default, 'OCP::Provider::Hetzner', 'default provider is hetzner');
}

#
# Test: Invalid provider dies
#

{
    eval { OCP::Provider->for_spec({ provider => 'aws' }) };
    like($@, qr/Unsupported provider/, 'invalid provider dies');
}

#
# Test: SSH provider create_server
#

{
    my $ssh = OCP::Provider::SSH->new(ssh_key_path => '/tmp/fake.key');

    my $server = $ssh->create_server(host => '10.0.0.5');
    is($server->{ip}, '10.0.0.5', 'SSH create_server returns host IP');
    ok(!$server->{newly_created}, 'SSH server is never newly_created');

    # upload_ssh_key is no-op
    ok(!defined $ssh->upload_ssh_key('key', 'pubkey'), 'SSH upload_ssh_key is no-op');

    # cleanup_on_failure is no-op
    ok(!defined $ssh->cleanup_on_failure(undef), 'SSH cleanup is no-op');

    # list_servers_by_cluster returns empty
    is_deeply($ssh->list_servers_by_cluster('test'), [], 'SSH list returns empty');
}

#
# Test: SSH provider requires host
#

{
    my $ssh = OCP::Provider::SSH->new(ssh_key_path => '/tmp/fake.key');
    eval { $ssh->create_server() };
    like($@, qr/host/, 'SSH create_server dies without host');
}

#
# Test: Local provider
#

{
    my $local = OCP::Provider::Local->new;

    my $server = $local->create_server();
    is($server->{ip}, '127.0.0.1', 'Local server IP is localhost');
    ok(!$server->{newly_created}, 'Local server not newly_created');

    my $exists = $local->server_exists('any');
    ok($exists, 'Local server always exists');
    is($exists->{ip}, '127.0.0.1', 'Local server_exists returns localhost');

    is_deeply($local->list_servers_by_cluster('test'), [], 'Local list returns empty');
}

#
# Test: Hetzner provider attributes
#

{
    my $hz = OCP::Provider::Hetzner->new(
        token        => 'fake-token',
        cluster_name => 'mycluster',
    );
    is($hz->token, 'fake-token', 'Hetzner token');
    is($hz->cluster_name, 'mycluster', 'Hetzner cluster_name');
}

#
# Test: Hetzner upload_ssh_key validates input
#

{
    my $hz = OCP::Provider::Hetzner->new(
        token        => 'fake-token',
        cluster_name => 'test',
    );

    eval { $hz->upload_ssh_key('', 'pubkey') };
    like($@, qr/key name is required/, 'upload_ssh_key requires name');

    eval { $hz->upload_ssh_key('mykey', '') };
    like($@, qr/public key is empty/, 'upload_ssh_key requires pubkey');

    eval { $hz->upload_ssh_key('mykey', undef) };
    like($@, qr/public key is empty/, 'upload_ssh_key requires defined pubkey');
}

done_testing;

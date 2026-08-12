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

use MIME::Base64 qw(encode_base64);

#
# Test: from_cr dispatches hetzner with token from Secret
#

subtest 'from_cr dispatches hetzner with token from Secret' => sub {
    my $cr = {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
        metadata   => { name => 'hetzner-a', namespace => 'ocp-system' },
        spec       => {
            type => 'hetzner',
            hetzner => {
                tokenSecretRef => { name => 'ocp-provider-hetzner-a-token', key => 'token' },
                location   => 'fsn1',
                server_type => 'cx32',
            },
        },
    };

    my $mock_k8s = bless {
        secret => {
            data => {
                token => encode_base64('secret-token-xyz', ''),
            },
        },
    }, 'FakeK8sForProvider';

    sub FakeK8sForProvider::get {
        my ($self, $kind, %args) = @_;
        return $self->{secret};
    }

    my $prov = OCP::Provider->from_cr($cr, k8s => $mock_k8s);
    isa_ok $prov, 'OCP::Provider::Hetzner';
    is $prov->token, 'secret-token-xyz', 'token decoded from Secret data';
    is $prov->cluster_name, 'hetzner-a', 'cluster_name derived from CR metadata.name';
};

#
# Test: from_cr dispatches ssh
#

subtest 'from_cr dispatches ssh' => sub {
    my $cr = {
        metadata => { name => 'ssh-a', namespace => 'ocp-system' },
        spec     => { type => 'ssh' },
    };
    my $prov = OCP::Provider->from_cr($cr, k8s => undef);
    isa_ok $prov, 'OCP::Provider::SSH';
};

#
# Test: from_cr dispatches local
#

subtest 'from_cr dispatches local' => sub {
    my $cr = {
        metadata => { name => 'local-a', namespace => 'ocp-system' },
        spec     => { type => 'local' },
    };
    my $prov = OCP::Provider->from_cr($cr, k8s => undef);
    isa_ok $prov, 'OCP::Provider::Local';
};

#
# Test: from_cr dies on unknown type
#

subtest 'from_cr dies on unknown type' => sub {
    my $cr = {
        metadata => { name => 'x', namespace => 'ocp-system' },
        spec     => { type => 'unknown_garbage' },
    };
    eval { OCP::Provider->from_cr($cr, k8s => undef) };
    like $@, qr/Unsupported provider type/, 'dies on unknown';
};

subtest 'from_cr hetzner uses typed Kind args (not path=>)' => sub {
    use MIME::Base64 qw(encode_base64);
    my $cr = {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
        metadata   => { name => 'hz', namespace => 'ocp-system' },
        spec       => {
            type    => 'hetzner',
            hetzner => { tokenSecretRef => { name => 'mysecret', key => 'token' } },
        },
    };
    my $mock_k8s = bless {
        secret => { data => { token => encode_base64('tok', '') } },
        calls  => [],
    }, 'FakeK8sForProviderTyped';
    sub FakeK8sForProviderTyped::get {
        my ($self, $kind, %args) = @_;
        push @{ $self->{calls} }, [$kind, \%args];
        return $self->{secret};
    }
    OCP::Provider->from_cr($cr, k8s => $mock_k8s);
    my @bad = grep { exists $_->[1]{path} } @{ $mock_k8s->{calls} };
    is scalar(@bad), 0, 'no path=> in from_cr k8s call';
    is $mock_k8s->{calls}[0][0], 'Secret', 'typed Kind "Secret" used';
};

#
# Test: shared ExistingHost behaviour
#
# Exercised through a stand-in so no test ever runs an uninstall script.
#

package FakeExistingHost {
    use Moo;
    with 'OCP::Role::Provider::ExistingHost';

    has commands  => (is => 'ro', default => sub { [] });
    has reachable => (is => 'rw', default => 1);

    sub resolve_host {
        my ($self, %opts) = @_;
        my $host = $opts{host};
        die "host required\n" unless defined $host && length $host;
        return $host;
    }
    sub host_reachable { $_[0]->reachable }
    sub run_command {
        my ($self, $host, $command) = @_;
        push @{ $self->commands }, [$host, $command];
        return { stdout => '', stderr => '', exit => 0 };
    }
}

{
    my $p = FakeExistingHost->new;

    $p->delete_server('ignored-id', host => '10.0.0.9');
    is(scalar @{$p->commands}, 1, 'delete_server ran one command');
    is($p->commands->[0][0], '10.0.0.9', 'command went to the resolved host');
    like($p->commands->[0][1], qr/rke2-uninstall\.sh/, 'uninstall script invoked');
    like($p->commands->[0][1], qr/k3s-uninstall\.sh/, 'covers both distributions');
}

{
    my $p = FakeExistingHost->new;
    $p->delete_server(undef);
    is(scalar @{$p->commands}, 0, 'delete_server without a host does nothing');
}

{
    my $p = FakeExistingHost->new(reachable => 0);
    is($p->server_exists('n', host => '10.0.0.9'), undef, 'unreachable host reports missing');

    my $up = FakeExistingHost->new;
    is_deeply($up->server_exists('n', host => '10.0.0.9'), { ip => '10.0.0.9' },
        'reachable host reports its IP');
    is($up->server_exists('n'), undef, 'no host means no server');
}

{
    my $p = FakeExistingHost->new;
    my $info = { ip => '10.0.0.9' };
    is($p->wait_for_running($info, 120), $info, 'wait_for_running is a passthrough');
}

#
# Test: Local runs commands without SSH
#

{
    my $local = OCP::Provider::Local->new;

    my $result = $local->run_command('127.0.0.1', 'echo hello-from-local');
    is($result->{exit}, 0, 'local command exits 0');
    like($result->{stdout}, qr/hello-from-local/, 'local command output captured');

    my $failed = $local->run_command('127.0.0.1', 'exit 3');
    is($failed->{exit}, 3, 'exit code passed through');

    ok($local->host_reachable('127.0.0.1'), 'localhost is always reachable');
    is($local->resolve_host(host => '10.0.0.1'), '127.0.0.1', 'local provider stays local');
}

#
# Test: Hetzner ignores a missing server id instead of calling the API
#

{
    my $hz = OCP::Provider::Hetzner->new(token => 'fake', cluster_name => 'c');
    my $ok = eval { $hz->delete_server(undef); 1 };
    ok($ok, 'delete_server without id is a no-op (no API call)');
}

done_testing;

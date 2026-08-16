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
# Test: SSH provider finds the host inside spec
#
# OCP::Node::_provision never passes host => directly. It hands over the whole
# CR spec instead:
#
#     $self->provider->create_server(
#         name => ..., node => ..., role => ..., spec => $self->cr->{spec},
#     );
#
# A resolve_host that only reads $opts{host} dies there, so every ssh worker
# fails in provisioning before a single command runs. The host-only tests
# above cannot catch that: the bug lives in the gap between _provision's call
# shape and resolve_host's expectation, not in either one alone.
#

{
    my $ssh = OCP::Provider::SSH->new(ssh_key_path => '/tmp/fake.key');

    my $server = eval {
        $ssh->create_server(
            name => 'brain',
            node => 'brain',
            role => 'worker',
            spec => { host => 'brain.example.org', providerRef => 'ssh-default' },
        );
    };
    is($@, '', 'create_server survives the call shape _provision uses');
    is($server->{ip}, 'brain.example.org', 'host is read from spec when not passed directly');

    # An explicit host still wins, so callers that do pass one are unaffected.
    my $direct = $ssh->create_server(
        host => '10.0.0.9',
        spec => { host => 'ignored.example.org' },
    );
    is($direct->{ip}, '10.0.0.9', 'explicit host takes precedence over spec.host');

    # A spec without a host is still an error, not a silent undef.
    eval { $ssh->create_server(spec => { role => 'worker' }) };
    like($@, qr/host/, 'dies when neither host nor spec.host is present');
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
# Test: Hetzner create_server reads the OCPNode spec and always sets a key
#
# Same gap as the ssh case above, on the other provider. OCP::Node::_provision
# passes `spec => $cr->{spec}` and names no options at all, so create_server
# used to fall through to its own defaults on every field -- and to
# `ssh_keys => []`, which produces a Hetzner server with an empty
# authorized_keys: running, billed, and unreachable for OCP forever (karr #92).
#
# The cloud client is faked so nothing here talks to Hetzner. `cloud` is a
# lazy attribute, so passing it in replaces the builder outright.
#

package FakeHzServer {
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub id   { $_[0]{id} }
    sub ipv4 { $_[0]{ipv4} }
}

package FakeHzServers {
    sub new { my ($c, %a) = @_; bless { created => [], %a }, $c }
    sub list_by_label { $_[0]{existing} // [] }
    sub create {
        my ($self, %params) = @_;
        push @{ $self->{created} }, \%params;
        return FakeHzServer->new(id => 'SRV-' . scalar @{ $self->{created} });
    }
}

package FakeHzCloud {
    sub new     { my ($c, %a) = @_; bless { servers => FakeHzServers->new(%a) }, $c }
    sub servers { $_[0]{servers} }
}

package main;

sub hz_provider {
    my (%over) = @_;
    my $cloud = FakeHzCloud->new;
    my $prov  = OCP::Provider::Hetzner->new(
        token        => 'fake-token',
        cluster_name => 'cortex',
        cloud        => $cloud,
        %over,
    );
    return ($prov, $cloud->servers);
}

subtest 'create_server reads serverType/location/image out of the CR spec' => sub {
    my ($prov, $servers) = hz_provider(ssh_key_name => 'ocp-cortex-admin');

    # Exactly the call shape OCP::Node::_provision uses.
    $prov->create_server(
        name => 'w1',
        node => 'w1',
        role => 'worker',
        spec => {
            role        => 'worker',
            providerRef => 'hetzner-default',
            serverType  => 'cx42',
            location    => 'nbg1',
            image       => 'debian-12',
        },
    );

    my $sent = $servers->{created}[0];
    ok $sent, 'a server was created';
    is $sent->{server_type}, 'cx42',      'spec.serverType reaches server_type';
    is $sent->{location},    'nbg1',      'spec.location reaches location';
    is $sent->{image},       'debian-12', 'spec.image reaches image';
    is $sent->{labels}{'ocp-role'}, 'worker', 'role still labelled from the option';
};

subtest 'a spec-driven create still gets an SSH key' => sub {
    # THE assertion. Everything else on this path is comfort; a server without
    # a key cannot be joined, cannot be logged into, and cannot be fixed.
    my ($prov, $servers) = hz_provider(ssh_key_name => 'ocp-cortex-admin');

    $prov->create_server(
        name => 'w1', node => 'w1', role => 'worker',
        spec => { role => 'worker', providerRef => 'hetzner-default' },
    );

    my $keys = $servers->{created}[0]{ssh_keys};
    ok scalar @$keys, 'ssh_keys is not empty';
    is_deeply $keys, ['ocp-cortex-admin'], 'the cluster admin key is referenced';
};

subtest 'directly passed options beat the spec' => sub {
    # The bootstrap path names every option; it must keep winning, or `ocp
    # apply` would start taking a worker CR's overrides for its control plane.
    my ($prov, $servers) = hz_provider(ssh_key_name => 'ocp-cortex-admin');

    $prov->create_server(
        name        => 'cp1',
        node        => 'cp1',
        role        => 'control-plane',
        server_type => 'cx32',
        image       => 'debian-13',
        location    => 'fsn1',
        ssh_keys    => ['explicit-key'],
        spec        => {
            serverType => 'cx42',
            image      => 'ubuntu-24.04',
            location   => 'nbg1',
        },
    );

    my $sent = $servers->{created}[0];
    is $sent->{server_type}, 'cx32',      'explicit server_type wins over spec.serverType';
    is $sent->{image},       'debian-13', 'explicit image wins over spec.image';
    is $sent->{location},    'fsn1',      'explicit location wins over spec.location';
    is_deeply $sent->{ssh_keys}, ['explicit-key'],
        'explicit ssh_keys wins over ssh_key_name';
};

subtest 'defaults still apply when neither option nor spec says anything' => sub {
    my ($prov, $servers) = hz_provider(ssh_key_name => 'ocp-cortex-admin');

    $prov->create_server(name => 'w2', node => 'w2', role => 'worker');

    my $sent = $servers->{created}[0];
    is $sent->{server_type}, 'cx32',      'default server type';
    is $sent->{image},       'debian-13', 'default image';
    is $sent->{location},    'fsn1',      'default location';
};

subtest 'a create with no key at all fails before the server exists' => sub {
    my ($prov, $servers) = hz_provider();   # no ssh_key_name

    eval {
        $prov->create_server(
            name => 'w3', node => 'w3', role => 'worker',
            spec => { role => 'worker', providerRef => 'hetzner-default' },
        );
    };
    my $err = $@;

    ok $err, 'create_server dies rather than creating an unreachable machine';
    like $err, qr/without an SSH key/, 'the message names what is missing';
    like $err, qr/sshKeyName/,         'and where to set it';
    is scalar @{ $servers->{created} }, 0,
        'nothing was sent to Hetzner -- the refusal comes first, so no server is billed';

    # An ssh_keys list that only holds empty strings is the same nothing.
    my ($prov2, $servers2) = hz_provider();
    eval { $prov2->create_server(name => 'w4', ssh_keys => ['', undef]) };
    like $@, qr/without an SSH key/, 'an empty key list is not a key';
    is scalar @{ $servers2->{created} }, 0, 'and still creates nothing';
};

subtest 'an existing labelled server is returned without needing a key' => sub {
    # The idempotency branch must stay ahead of the refusal: a server that is
    # already there does not need a key decided for it.
    my $cloud = FakeHzCloud->new(
        existing => [ FakeHzServer->new(id => 'SRV-OLD', ipv4 => '1.2.3.4') ],
    );
    my $prov = OCP::Provider::Hetzner->new(
        token => 'fake-token', cluster_name => 'cortex', cloud => $cloud,
    );

    my $info = $prov->create_server(name => 'w1', node => 'w1', role => 'worker');
    is $info->{id}, 'SRV-OLD',      'existing server reported back';
    is $info->{newly_created}, 0,   'and not marked as newly created';
};

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
            type        => 'hetzner',
            clusterName => 'cortex',
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

    # This line used to assert the opposite -- 'hetzner-a', the CR's own name.
    # That claim was the bug written down: metadata.name is what
    # ensure_provider_cr writes as "<type>-default", so it labelled every
    # worker's server ocp-cluster=hetzner-default and `ocp destroy` never
    # found one again (karr #98).
    is $prov->cluster_name, 'cortex', 'cluster_name comes from spec.clusterName';
    isnt $prov->cluster_name, $cr->{metadata}{name},
        'and never from the provider CR name';
};

#
# Test: from_cr carries spec.hetzner.sshKeyName into the adapter
#
# This is the only route by which a worker learns which uploaded key to boot
# with: OCP::Node is trigger-neutral, and robocop -- the other caller of
# create_server -- never learns the cluster name the key is derived from.
#

subtest 'from_cr carries sshKeyName into the adapter' => sub {
    my $mock_k8s = bless {
        secret => { data => { token => encode_base64('t', '') } },
    }, 'FakeK8sForProvider';

    my $with = OCP::Provider->from_cr({
        metadata => { name => 'hetzner-default', namespace => 'ocp-system' },
        spec     => {
            type        => 'hetzner',
            clusterName => 'cortex',
            hetzner => {
                tokenSecretRef => { name => 'sec', key => 'token' },
                sshKeyName     => 'ocp-cortex-admin',
            },
        },
    }, k8s => $mock_k8s);
    is $with->ssh_key_name, 'ocp-cortex-admin', 'sshKeyName reaches the adapter';

    # A provider CR written before the field existed has none. That must stay
    # empty rather than become a guessed name -- create_server then refuses
    # with a message instead of creating an unreachable machine.
    my $without = OCP::Provider->from_cr({
        metadata => { name => 'hetzner-default', namespace => 'ocp-system' },
        spec     => {
            type        => 'hetzner',
            clusterName => 'cortex',
            hetzner     => { tokenSecretRef => { name => 'sec', key => 'token' } },
        },
    }, k8s => $mock_k8s);
    is $without->ssh_key_name, '', 'absent sshKeyName leaves the adapter empty';
};

#
# Test: from_cr refuses a provider CR with no spec.clusterName
#
# The other half of the same decision. A CR written before the field existed
# has none, and every remaining source of a cluster name would be wrong:
# metadata.name is "<type>-default", the namespace is ocp-system in every
# cluster there is, and an empty cluster_name makes create_server skip its
# idempotency check AND label the machine ocp-cluster= (matched by no
# selector at all). Refusing is the only answer that does not leave a running,
# billed, unfindable server behind.
#

subtest 'from_cr refuses a hetzner CR without spec.clusterName' => sub {
    my $mock_k8s = bless {
        secret => { data => { token => encode_base64('t', '') } },
    }, 'FakeK8sForProvider';

    my $prov = eval {
        OCP::Provider->from_cr({
            metadata => { name => 'hetzner-default', namespace => 'ocp-system' },
            spec     => {
                type    => 'hetzner',
                hetzner => { tokenSecretRef => { name => 'sec', key => 'token' } },
            },
        }, k8s => $mock_k8s);
    };
    my $err = $@;

    ok !$prov, 'no adapter is built';
    like $err, qr/spec\.clusterName/, 'the message names the missing field';
    like $err, qr/ocp apply/,         'and how to get it written';

    # An empty string is the same nothing: it would label the server
    # ocp-cluster= and pass nothing to the label selector.
    eval {
        OCP::Provider->from_cr({
            metadata => { name => 'hetzner-default', namespace => 'ocp-system' },
            spec     => {
                type        => 'hetzner',
                clusterName => '',
                hetzner     => { tokenSecretRef => { name => 'sec', key => 'token' } },
            },
        }, k8s => $mock_k8s);
    };
    like $@, qr/spec\.clusterName/, 'an empty clusterName is not a cluster name';

    # ssh and local carry no cluster label and must not grow the requirement.
    my $ssh = OCP::Provider->from_cr({
        metadata => { name => 'ssh-default', namespace => 'ocp-system' },
        spec     => { type => 'ssh' },
    }, k8s => undef);
    isa_ok $ssh, 'OCP::Provider::SSH', 'ssh provider still builds without clusterName';
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
    # Same message as for_spec: both entry points normalise through _build,
    # so there is one dispatch and one error string.
    my $cr = {
        metadata => { name => 'x', namespace => 'ocp-system' },
        spec     => { type => 'unknown_garbage' },
    };
    eval { OCP::Provider->from_cr($cr, k8s => undef) };
    like $@, qr/Unsupported provider/, 'dies on unknown';
};

subtest 'from_cr hetzner uses typed Kind args (not path=>)' => sub {
    use MIME::Base64 qw(encode_base64);
    my $cr = {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
        metadata   => { name => 'hz', namespace => 'ocp-system' },
        spec       => {
            type        => 'hetzner',
            clusterName => 'cortex',
            hetzner     => { tokenSecretRef => { name => 'mysecret', key => 'token' } },
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

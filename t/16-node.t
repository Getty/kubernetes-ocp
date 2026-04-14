use strict;
use warnings;
use Test::More;

package FakeK8s {
    sub new { my ($c, %a) = @_; bless { calls => [], %a }, $c }
    sub get    { my ($s, @a) = @_; push @{$s->{calls}}, [get    => \@a]; $s->{cr_cb}    ? $s->{cr_cb}->(@a)    : $s->{cr} }
    sub update { my ($s, $o) = @_; push @{$s->{calls}}, [update => $o];  $s->{update_cb} ? $s->{update_cb}->($o) : $o }
    sub patch  { my ($s, @a) = @_; push @{$s->{calls}}, [patch  => \@a]; $s->{patch_cb}  ? $s->{patch_cb}->(@a)  : {} }
    sub ensure { my ($s, $o) = @_; push @{$s->{calls}}, [ensure => $o];  $o }
    sub delete { my ($s, @a) = @_; push @{$s->{calls}}, [delete => \@a]; {} }
    sub list   { my ($s, @a) = @_; push @{$s->{calls}}, [list   => \@a]; $s->{list} // { items => [] } }
}

package FakeProvider {
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub create_server { my ($s, %a) = @_; $s->{create_cb} ? $s->{create_cb}->(%a) : { id => 'SRV1', ip => '1.2.3.4' } }
    sub delete_server { my ($s, @a) = @_; $s->{delete_cb} ? $s->{delete_cb}->(@a) : 1 }
}

package FakeSSH {
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub wait_for_ssh { my ($s, $n) = @_; $s->{ssh_cb} ? $s->{ssh_cb}->($n) : 1 }
}

package FakeRex {
    our @_instances;
    sub new { my ($c, %a) = @_; my $s = bless { %a, calls => [] }, $c; push @_instances, $s; $s }
    sub run_task { my ($s, $task, %p) = @_;
        push @{$s->{calls}}, [$task, \%p];
        $s->{run_cb} ? $s->{run_cb}->($task, %p) : 1;
    }
}

package main;

use OCP::Node;

my $cr = {
    apiVersion => 'ocp.internal/v1',
    kind       => 'OCPNode',
    metadata   => { name => 'worker-1', namespace => 'ocp-system' },
    spec       => { role => 'worker', providerRef => 'hetzner-a' },
    status     => { phase => 'Pending' },
};

my $fake_k8s  = FakeK8s->new;
my $fake_prov = FakeProvider->new;

subtest 'from_cr constructs with deps' => sub {
    my $node = OCP::Node->from_cr(
        $cr,
        k8s        => $fake_k8s,
        provider   => $fake_prov,
        ssh_key    => 'KEY',
        server_url => 'https://cp:9345',
        join_token => 'TOKEN',
    );

    is $node->name,  'worker-1', 'name accessor from metadata';
    is $node->role,  'worker',   'role accessor from spec';
    is $node->phase, 'Pending',  'phase accessor from status';
    is $node->reconciler_id, 'cli', 'reconciler_id defaults to cli';
    is $node->distribution,  'rke2', 'distribution defaults to rke2';
};

subtest 'reconciler_id override' => sub {
    my $node = OCP::Node->from_cr($cr, k8s => $fake_k8s, reconciler_id => 'robocop');
    is $node->reconciler_id, 'robocop', 'reconciler_id can be overridden';
};

subtest 'phase defaults to Pending when status missing' => sub {
    my $cr2 = { %$cr, status => {} };
    my $node = OCP::Node->from_cr($cr2, k8s => $fake_k8s);
    is $node->phase, 'Pending', 'missing status.phase defaults to Pending';
};

subtest 'lease acquisition stamps annotation and calls update with resourceVersion' => sub {
    my $cr = {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
        metadata   => { name => 'w1', namespace => 'ocp-system', resourceVersion => '100' },
        spec       => { role => 'worker', providerRef => 'p' },
        status     => { phase => 'Pending' },
    };
    my $k = FakeK8s->new(cr => $cr);
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    $node->_acquire_lease;

    my ($update) = grep { $_->[0] eq 'update' } @{$k->{calls}};
    ok $update, 'update was called';
    like $update->[1]{metadata}{annotations}{'ocp.internal/reconciler-lease'},
         qr/^cli\@.+\@300$/, 'lease annotation written with cli holder and 300s ttl';
    is $update->[1]{metadata}{resourceVersion}, '100', 'resourceVersion preserved on PUT';
};

subtest 'lease held by another reconciler dies' => sub {
    my $now = OCP::Node::_rfc3339_now();
    my $cr = {
        metadata => {
            name => 'w2', namespace => 'ocp-system',
            annotations => { 'ocp.internal/reconciler-lease' => "robocop\@$now\@300" },
        },
        spec => { role => 'worker', providerRef => 'p' },
        status => { phase => 'Pending' },
    };
    my $node = OCP::Node->from_cr($cr, k8s => FakeK8s->new(cr => $cr),
        provider => FakeProvider->new, ssh_key => 'K', server_url => 'U', join_token => 'T');

    eval { $node->_acquire_lease };
    like $@, qr/lease held/i, 'refuses to steal live lease held by another';
};

subtest 'lease expired is stealable' => sub {
    my $old = '2000-01-01T00:00:00Z';
    my $cr = {
        metadata => {
            name => 'w3', namespace => 'ocp-system',
            annotations => { 'ocp.internal/reconciler-lease' => "robocop\@$old\@300" },
        },
        spec => { role => 'worker', providerRef => 'p' },
        status => { phase => 'Pending' },
    };
    my $k = FakeK8s->new(cr => $cr);
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    eval { $node->_acquire_lease };
    is $@, '', 'expired lease is stealable';
    my ($update) = grep { $_->[0] eq 'update' } @{$k->{calls}};
    like $update->[1]{metadata}{annotations}{'ocp.internal/reconciler-lease'},
         qr/^cli\@/, 'new lease owned by cli';
};

subtest '_provision calls provider->create_server with node-name and transitions to Installing' => sub {
    my $create_args;
    my $prov = FakeProvider->new(create_cb => sub {
        $create_args = { @_ };
        return { id => 'SRV42', ip => '5.6.7.8' };
    });
    my $cr = {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
        metadata   => { name => 'w4', namespace => 'ocp-system', resourceVersion => '1' },
        spec       => { role => 'worker', providerRef => 'hetzner-a' },
        status     => { phase => 'Pending' },
    };
    my $k = FakeK8s->new(cr => $cr);
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    $node->_provision;

    ok $create_args, 'provider->create_server was called';
    is $create_args->{name}, 'w4', 'node name passed to create_server';
    is $create_args->{node}, 'w4', 'node param passed for label-based idempotency';
    my ($patch) = grep { $_->[0] eq 'patch' } @{$k->{calls}};
    ok $patch, 'status patched';
};

subtest '_release_lease removes the lease annotation' => sub {
    my $now = OCP::Node::_rfc3339_now();
    my $cr = {
        metadata => {
            name => 'w5', namespace => 'ocp-system',
            annotations => { 'ocp.internal/reconciler-lease' => "cli\@$now\@300" },
        },
        spec   => { role => 'worker', providerRef => 'p' },
        status => { phase => 'Installing' },
    };
    my $k = FakeK8s->new(cr => $cr);
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    $node->_release_lease;
    my ($update) = grep { $_->[0] eq 'update' } @{$k->{calls}};
    ok $update, 'update called to release';
    ok !exists $update->[1]{metadata}{annotations}{'ocp.internal/reconciler-lease'},
        'lease annotation removed';
};

subtest '_provision failure keeps lease (for TTL-based retry)' => sub {
    my $prov = FakeProvider->new(create_cb => sub { die "hetzner 5xx\n" });
    my $cr = {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
        metadata   => { name => 'w6', namespace => 'ocp-system', resourceVersion => '1' },
        spec       => { role => 'worker', providerRef => 'p' },
        status     => { phase => 'Pending' },
    };
    my $k = FakeK8s->new(cr => $cr);
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => $prov,
        ssh_key => 'K', server_url => 'U', join_token => 'T');

    eval { $node->_provision };
    ok $@, 'provision failure propagates';
    my @updates = grep { $_->[0] eq 'update' } @{$k->{calls}};
    is scalar @updates, 1, 'only the lease acquire update — no release-on-failure';
};

subtest '_install_kubernetes calls Rex with install_rke2_agent for workers' => sub {
    @FakeRex::_instances = ();
    my $cr = {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
        metadata   => { name => 'w1', namespace => 'ocp-system' },
        spec       => { role => 'worker', providerRef => 'p' },
        status     => { phase => 'Installing', publicIP => '1.2.3.4' },
    };
    my $k = FakeK8s->new(cr => $cr);
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'KEY', server_url => 'https://cp:9345', join_token => 'TOKEN',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
    );

    $node->_install_kubernetes;

    my $r = $FakeRex::_instances[0];
    ok $r, 'FakeRex instantiated';
    is $r->{host}, '1.2.3.4', 'rex constructed with publicIP';
    my ($call) = @{ $r->{calls} };
    is $call->[0], 'install_rke2_agent', 'rke2 task for worker';
    is $call->[1]{server}, 'https://cp:9345', 'server URL threaded';
    is $call->[1]{token},  'TOKEN',            'join token threaded';
    is $call->[1]{node_name}, 'w1',            'node_name set';

    my ($patch) = grep { $_->[0] eq 'patch' } @{$k->{calls}};
    ok $patch, 'status patched to Joining';
};

subtest '_install_kubernetes uses k3s task when distribution=k3s' => sub {
    @FakeRex::_instances = ();
    my $cr = {
        metadata => { name => 'w2', namespace => 'ocp-system' },
        spec => { role => 'worker', providerRef => 'p' },
        status => { phase => 'Installing', publicIP => '1.2.3.4' },
    };
    my $node = OCP::Node->from_cr($cr, k8s => FakeK8s->new(cr => $cr),
        provider => FakeProvider->new, ssh_key => 'K',
        server_url => 'U', join_token => 'T',
        distribution => 'k3s',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
    );
    $node->_install_kubernetes;
    my ($call) = @{ $FakeRex::_instances[0]{calls} };
    is $call->[0], 'install_k3s_agent', 'k3s task when distribution=k3s';
};

subtest '_wait_ready returns true when k8s Node is Ready' => sub {
    my $cr = {
        metadata => { name => 'w3', namespace => 'ocp-system' },
        spec => { role => 'worker', providerRef => 'p' },
        status => { phase => 'Joining', kubernetesNodeName => 'w3' },
    };
    my $k = FakeK8s->new(
        cr_cb => sub {
            return { status => { conditions => [{ type => 'Ready', status => 'True' }] } };
        },
    );
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    ok $node->_wait_ready, 'returns true on Ready';
    my ($patch) = grep { $_->[0] eq 'patch' } @{$k->{calls}};
    ok $patch, 'status patched on Ready';
};

subtest '_wait_ready returns false when Node not yet Ready' => sub {
    my $cr = {
        metadata => { name => 'w4', namespace => 'ocp-system' },
        spec => { role => 'worker', providerRef => 'p' },
        status => { phase => 'Joining', kubernetesNodeName => 'w4' },
    };
    my $k = FakeK8s->new(
        cr_cb => sub {
            return { status => { conditions => [{ type => 'Ready', status => 'False' }] } };
        },
    );
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    ok !$node->_wait_ready, 'returns false when not Ready';
};

subtest '_verify returns true when k8s Node is Ready' => sub {
    my $cr = {
        metadata => { name => 'w5', namespace => 'ocp-system' },
        spec => { role => 'worker', providerRef => 'p' },
        status => { phase => 'Ready', kubernetesNodeName => 'w5' },
    };
    my $k = FakeK8s->new(
        cr_cb => sub {
            return { status => { conditions => [{ type => 'Ready', status => 'True' }] } };
        },
    );
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    ok $node->_verify, '_verify returns true when Ready';
};

subtest '_verify returns false when k8s Node not Ready' => sub {
    my $cr = {
        metadata => { name => 'w6', namespace => 'ocp-system' },
        spec => { role => 'worker', providerRef => 'p' },
        status => { phase => 'Ready', kubernetesNodeName => 'w6' },
    };
    my $k = FakeK8s->new(
        cr_cb => sub {
            return { status => { conditions => [{ type => 'Ready', status => 'False' }] } };
        },
    );
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    ok !$node->_verify, '_verify returns false when not Ready';
};

done_testing;

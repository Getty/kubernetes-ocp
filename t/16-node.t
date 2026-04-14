use strict;
use warnings;
use Test::More;
use OCP::Node;

my $cr = {
    apiVersion => 'ocp.internal/v1',
    kind       => 'OCPNode',
    metadata   => { name => 'worker-1', namespace => 'ocp-system' },
    spec       => { role => 'worker', providerRef => 'hetzner-a' },
    status     => { phase => 'Pending' },
};

my $fake_k8s  = bless {}, 'FakeK8s';
my $fake_prov = bless {}, 'FakeProvider';

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

done_testing;

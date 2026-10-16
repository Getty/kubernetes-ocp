#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Node::Rm;

sub capture_stdout (&) {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die "open stdout capture: $!";
    local *STDOUT = $fh;
    $code->();
    return $out;
}

{
    package FakeIO;
    sub new              { bless {}, $_[0] }
    sub object_to_struct { $_[1] }
}

{
    package FakeK8sRm;

    my $_io = FakeIO->new;

    sub new {
        my ($class, %args) = @_;
        return bless {
            nodes     => $args{nodes}     // {},
            providers => $args{providers} // {},
            calls     => [],
        }, $class;
    }

    sub k8s { $_io }

    sub get {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['get', $kind, \%args];
        my $name = $args{name} // '';

        if ($kind eq 'OCPNode') {
            my $n = $self->{nodes}{$name};
            die "404: not found OCPNode/$name\n" unless $n;
            return $n;
        }

        if ($kind eq 'OCPNodeProvider') {
            my $p = $self->{providers}{$name};
            die "404: not found OCPNodeProvider/$name\n" unless $p;
            return $p;
        }

        return undef;
    }

    # Node::Rm lists the OCPNodes when a name does not resolve, so the
    # rejection can say which ones exist (k103). Without this the fake
    # would answer that question with a method error, and the empty-cluster
    # branch would be exercised for a cluster this fake says has nodes.
    sub list {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['list', $kind, \%args];
        my $from = $kind eq 'OCPNode' ? $self->{nodes} : $self->{providers};
        return FakeListRm->new([ map { $from->{$_} } sort keys %$from ]);
    }
}

{
    package FakeListRm;
    sub new   { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]->{items} }
}

{
    package FakeNode;
    sub teardown { $_[0]->{teardown_called}++ }
}

my $worker_cr = {
    metadata => { name => 'worker-1', namespace => 'ocp-system' },
    spec     => { role => 'worker', providerRef => 'hetzner-a' },
    status   => { phase => 'Ready' },
};

my $hetzner_provider_cr = {
    metadata => { name => 'hetzner-a', namespace => 'ocp-system' },
    spec     => { type => 'hetzner' },
};

subtest 'rm dies on missing node' => sub {
    my $k8s = FakeK8sRm->new(nodes => { 'worker-1' => $worker_cr });
    my $rm = OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'no-such-node');

    eval { $rm->execute([], []) };

    # Same claim this test always made — a name that resolves to no OCPNode
    # is refused and the message names it. k103 only added the second
    # half of the house shape (say what would have worked), so the assertion
    # got stronger rather than different; the wording moved from "not found"
    # to the form `ocp quatschkommando` has answered in since k67.
    like $@, qr/^Unknown node 'no-such-node'\./,
        'dies naming the node that does not exist';
    like $@, qr/^Available: worker-1$/m,
        'and naming the one that does';
};

subtest 'rm calls teardown on node' => sub {
    my $k8s = FakeK8sRm->new(
        nodes     => { 'worker-1' => $worker_cr },
        providers => { 'hetzner-a' => $hetzner_provider_cr },
    );

    my $teardown_called = 0;

    no warnings 'redefine';
    local *OCP::Node::teardown = sub { $teardown_called++ };
    local *OCP::Provider::from_cr = sub { bless {}, 'FakeProvider' };

    my $rm  = OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'worker-1');
    my $out = capture_stdout { $rm->execute([], []) };

    is $teardown_called, 1, 'teardown called exactly once';
    like $out, qr/worker-1.*removed/i, 'prints removed message';
};

subtest 'rm proceeds without provider when providerRef missing' => sub {
    my $no_prov_cr = {
        metadata => { name => 'orphan-1', namespace => 'ocp-system' },
        spec     => { role => 'worker' },
        status   => { phase => 'Pending' },
    };

    my $k8s = FakeK8sRm->new(nodes => { 'orphan-1' => $no_prov_cr });

    my $teardown_called = 0;

    no warnings 'redefine';
    local *OCP::Node::teardown = sub { $teardown_called++ };

    my $rm  = OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'orphan-1');
    my $out = capture_stdout { $rm->execute([], []) };

    is $teardown_called, 1, 'teardown called even without providerRef';
    like $out, qr/orphan-1.*removed/i, 'prints removed message';
};

#
# k175: `ocp node rm` on an ssh worker said "removed" while rke2-agent kept
# running. The ssh adapter was built from the CR alone, and the CR carries no
# key (ADR 0027): its ssh ran with no identity, the login was refused, and
# the refusal came back as an exit code nobody read.
#

{
    package FakeClusterKey;
    sub new  { bless { path => $_[1] }, $_[0] }
    sub path { $_[0]{path} }
}

my $ssh_worker_cr = {
    metadata => { name => 'ssh-w', namespace => 'ocp-system' },
    spec     => { role => 'worker', providerRef => 'ssh-default', host => 'w.vm' },
    status   => { phase => 'Ready', publicIP => 'w.vm' },
};
my $ssh_provider_cr = {
    metadata => { name => 'ssh-default', namespace => 'ocp-system' },
    spec     => { type => 'ssh', clusterName => 'c' },
};

sub rm_for {
    my (%args) = @_;
    my $k8s = FakeK8sRm->new(
        nodes     => { 'worker-1' => $worker_cr, 'ssh-w' => $ssh_worker_cr },
        providers => { 'hetzner-a' => $hetzner_provider_cr,
                       'ssh-default' => $ssh_provider_cr },
    );
    return OCP::Cmd::Node::Rm->new(k8s => $k8s, _config => bless({}, 'FakeConfig'), %args);
}

subtest 'an ssh worker is torn down with the cluster key' => sub {
    my (@key_asks, %from_cr_opts);
    no warnings 'redefine';
    local *OCP::Cmd::Node::Rm::cluster_ssh_key = sub {
        my ($self, $config, %opt) = @_;
        push @key_asks, \%opt;
        return FakeClusterKey->new('/tmp/cluster-key');
    };
    local *OCP::Provider::from_cr = sub {
        my ($class, $cr, %opts) = @_;
        %from_cr_opts = %opts;
        return bless {}, 'FakeProvider';
    };
    my $torn = 0;
    local *OCP::Node::teardown = sub { $torn++; 1 };

    my $out = capture_stdout { rm_for(name => 'ssh-w')->execute([], []) };

    is scalar @key_asks, 1, 'the cluster key is obtained';
    is $key_asks[0]{provider}, 'ssh', 'for the ssh provider';
    is $from_cr_opts{ssh_key_path}, '/tmp/cluster-key',
        'and its path is what the ssh adapter logs in with';
    is $torn, 1, 'teardown ran';
    like $out, qr/ssh-w.*removed/i, 'removed is reported after it succeeded';
};

subtest 'a hetzner worker asks for no SSH key' => sub {
    my $asked = 0;
    no warnings 'redefine';
    local *OCP::Cmd::Node::Rm::cluster_ssh_key = sub { $asked++; FakeClusterKey->new('/x') };
    local *OCP::Provider::from_cr = sub { bless {}, 'FakeProvider' };
    local *OCP::Node::teardown = sub { 1 };

    capture_stdout { rm_for(name => 'worker-1')->execute([], []) };
    is $asked, 0, 'no key, so no PIN2 prompt, for a node deleted through the API';
};

subtest 'no key for an ssh worker: nothing is torn down' => sub {
    my $torn = 0;
    no warnings 'redefine';
    local *OCP::Cmd::Node::Rm::cluster_ssh_key = sub { die "Wrong PIN2.\n" };
    local *OCP::Node::teardown = sub { $torn++; 1 };

    my $out = '';
    my $ok = eval { $out = capture_stdout { rm_for(name => 'ssh-w')->execute([], []) }; 1 };
    ok !$ok, 'rm fails';
    like $@, qr/Wrong PIN2/, 'with the reason';
    is $torn, 0, 'before anything was touched';
    unlike $out, qr/removed/i, 'and says nothing was removed';
};

subtest 'a failed teardown fails the command' => sub {
    no warnings 'redefine';
    local *OCP::Cmd::Node::Rm::cluster_ssh_key = sub { FakeClusterKey->new('/tmp/k') };
    local *OCP::Provider::from_cr = sub { bless {}, 'FakeProvider' };
    local *OCP::Node::teardown = sub {
        die "Teardown of node ssh-w failed: w.vm: Uninstall of RKE2/K3s failed (exit 255)\n";
    };

    my $out = '';
    my $ok = eval { $out = capture_stdout { rm_for(name => 'ssh-w')->execute([], []) }; 1 };
    ok !$ok, 'rm dies -- bin/ocp turns that into STDERR and exit 1';
    like $@, qr/exit 255/, 'carrying the diagnosis';
    unlike $out, qr/removed/i, '"removed" is not printed';
};

subtest 'a provider that cannot be built stops rm before teardown' => sub {
    my $torn = 0;
    no warnings 'redefine';
    local *OCP::Provider::from_cr = sub { die "from_cr: Secret 'hetzner-api-token' has no key 'token'\n" };
    local *OCP::Node::teardown = sub { $torn++; 1 };

    my $ok = eval { capture_stdout { rm_for(name => 'worker-1')->execute([], []) }; 1 };
    ok !$ok, 'rm fails';
    like $@, qr/hetzner-a/, 'naming the provider';
    like $@, qr/has no key 'token'/, 'and why it could not be built';
    is $torn, 0, 'without removing the node and leaving its server behind';
};

#
# k229: an ssh worker that never reached its host fails its teardown at the
# uninstall on every attempt, and the OCPNode stays (k175, and that stays so).
# --keep-machine is the way out, asked for by name; the failure says so.
#

my $crag_cr = {
    metadata => { name => 'crag', namespace => 'ocp-system' },
    spec     => { role => 'worker', providerRef => 'ssh-default', host => '10.0.0.9' },
    status   => { phase => 'Failed', message => 'SSH not ready: No route to host' },
};
my $hetzner_joined_cr = {
    metadata => { name => 'h1', namespace => 'ocp-system' },
    spec     => { role => 'worker', providerRef => 'hetzner-a' },
    status   => { phase => 'Ready', providerId => '4711', publicIP => '203.0.113.7',
                  kubernetesNodeName => 'h1', joinedAt => '2026-10-15T20:00:00Z' },
};

sub rm_k229 {
    my (%args) = @_;
    my $providers = delete $args{providers}
        // { 'hetzner-a' => $hetzner_provider_cr, 'ssh-default' => $ssh_provider_cr };
    my $k8s = FakeK8sRm->new(
        nodes     => { crag => $crag_cr, h1 => $hetzner_joined_cr },
        providers => $providers,
    );
    return OCP::Cmd::Node::Rm->new(k8s => $k8s, _config => bless({}, 'FakeConfig'), %args);
}

# What a --keep-machine run touched: the teardown's options and node, and
# whether a provider or a key was asked for.
sub keep_machine_run {
    my ($rm, @args) = @_;
    my %seen = (from_cr => 0, key => 0);
    no warnings 'redefine';
    local *OCP::Provider::from_cr = sub { $seen{from_cr}++; bless {}, 'FakeProvider' };
    local *OCP::Cmd::Node::Rm::cluster_ssh_key = sub { $seen{key}++; FakeClusterKey->new('/k') };
    local *OCP::Node::teardown = sub {
        my ($node, %opt) = @_;
        $seen{opt}      = \%opt;
        $seen{provider} = $node->provider;
        1;
    };
    $seen{out} = capture_stdout { $rm->execute([ @args ], []) };
    return \%seen;
}

subtest '--keep-machine: teardown without the machine, nothing asked for it' => sub {
    my $r = keep_machine_run(rm_k229(name => 'crag', keep_machine => 1));

    is_deeply $r->{opt}, { keep_machine => 1 }, 'teardown is asked to keep the machine';
    ok !$r->{provider}, 'the node gets no provider -- there is nothing to call it for';
    is $r->{from_cr}, 0, 'no provider is built';
    is $r->{key},     0, 'no cluster key, so no PIN2 for a machine nobody contacts';

    like $r->{out}, qr/^Node 'crag' removed\. Its machine was not touched:/m,
        'STDOUT says it is removed and that the machine was not touched';
    like $r->{out}, qr/10\.0\.0\.9/,            'names the host';
    like $r->{out}, qr/RKE2\/K3s/,              'what may still be on it';
    like $r->{out}, qr/registers its Node again/, 'and why that matters';
    like $r->{out}, qr/rke2-uninstall\.sh/,     'and how to get rid of it';
};

subtest '--keep-machine on a Hetzner node names the server that keeps billing' => sub {
    my $r = keep_machine_run(rm_k229(name => 'h1', keep_machine => 1));

    like $r->{out}, qr/Hetzner server 4711 \(203\.0\.113\.7\) keeps running and is billed/,
        'the server, by id and address, and that it costs';
};

subtest '--keep-machine needs no OCPNodeProvider' => sub {
    my $r = keep_machine_run(rm_k229(name => 'crag', keep_machine => 1, providers => {}));

    is_deeply $r->{opt}, { keep_machine => 1 }, 'the node is removed all the same';
    like $r->{out}, qr/10\.0\.0\.9/, 'the machine is described from the OCPNode alone';
};

subtest 'the name is the first word that is not an option' => sub {
    my $r = keep_machine_run(rm_k229(keep_machine => 1), '--keep-machine', 'crag');

    like $r->{out}, qr/^Node 'crag' removed/m,
        '`ocp node rm --keep-machine crag` removes crag, not a node called --keep-machine';
};

# A teardown that failed at the machine, the way OCP::Node reports it.
sub failing_at_machine {
    my ($err) = @_;
    return sub {
        my ($node) = @_;
        $node->_set_machine_cleanup_failed(1);
        die $err;
    };
}

subtest 'without --keep-machine a node that never joined stays, and the error names the way out' => sub {
    no warnings 'redefine';
    local *OCP::Cmd::Node::Rm::cluster_ssh_key = sub { FakeClusterKey->new('/tmp/k') };
    local *OCP::Provider::from_cr = sub { bless {}, 'FakeProvider' };
    local *OCP::Node::teardown = failing_at_machine(
        "Teardown of node crag failed: 10.0.0.9: ssh: connect to host 10.0.0.9 port 22: "
      . "No route to host\nThe node is kept (phase Failed); fix the cause and run "
      . "'ocp node rm crag' again.\n");

    my $out = '';
    my $ok = eval { $out = capture_stdout { rm_k229(name => 'crag')->execute([], []) }; 1 };
    my $err = $@;
    ok !$ok, 'rm still fails: the default is unchanged';
    unlike $out, qr/removed/i, 'and says nothing was removed';
    like $err, qr/No route to host/,                 'the reason comes first';
    like $err, qr/never joined the cluster/,         'it says this node never joined';
    like $err, qr/^  ocp node rm crag --keep-machine$/m, 'the way out, ready to run';
    like $err, qr/^Then check the machine by hand:\n  .*10\.0\.0\.9/m,
        'and what to check afterwards';
};

subtest 'a joined node that fails at the machine gets the way out, worded for it' => sub {
    no warnings 'redefine';
    local *OCP::Provider::from_cr = sub { bless {}, 'FakeProvider' };
    local *OCP::Node::teardown = failing_at_machine(
        "Teardown of node h1 failed: injected Hetzner API failure\n");

    ok !eval { capture_stdout { rm_k229(name => 'h1')->execute([], []) }; 1 }, 'rm fails';
    my $err = $@;
    unlike $err, qr/never joined/,                  'not called a node that never joined';
    like $err, qr/If the machine is gone/,          'offered for a machine that is gone';
    like $err, qr/ocp node rm h1 --keep-machine/,   'the way out';
    like $err, qr/Hetzner server 4711/,             'naming the server that would stay';
};

subtest 'a teardown that stopped before the machine offers no --keep-machine' => sub {
    no warnings 'redefine';
    local *OCP::Provider::from_cr = sub { bless {}, 'FakeProvider' };
    local *OCP::Node::teardown = sub {
        die "Teardown of node h1 failed: drain of Node/h1 timed out after 300s\n";
    };

    ok !eval { capture_stdout { rm_k229(name => 'h1')->execute([], []) }; 1 }, 'rm fails';
    like $@, qr/drain of Node\/h1/, 'with the reason';
    unlike $@, qr/--keep-machine/,
        'and no --keep-machine: the drain runs with it too, so it would not help';
};

subtest 'a providerRef that names no provider stops rm before teardown' => sub {
    my $torn = 0;
    no warnings 'redefine';
    local *OCP::Node::teardown = sub { $torn++; 1 };
    my $k8s = FakeK8sRm->new(nodes => { 'worker-1' => $worker_cr });   # no providers

    my $rm = OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'worker-1');
    my $ok = eval { capture_stdout { $rm->execute([], []) }; 1 };
    ok !$ok, 'rm fails';
    like $@, qr/OCPNodeProvider.*hetzner-a/, 'naming the missing provider';
    like $@, qr/^  ocp node rm worker-1 --keep-machine$/m,
        'and the way out that needs no provider (k229)';
    is $torn, 0, 'nothing is torn down';
};

done_testing;

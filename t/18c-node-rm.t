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
        die "Teardown of node ssh-w failed: Uninstall of RKE2/K3s on w.vm failed (exit 255)\n";
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

subtest 'a providerRef that names no provider stops rm before teardown' => sub {
    my $torn = 0;
    no warnings 'redefine';
    local *OCP::Node::teardown = sub { $torn++; 1 };
    my $k8s = FakeK8sRm->new(nodes => { 'worker-1' => $worker_cr });   # no providers

    my $rm = OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'worker-1');
    my $ok = eval { capture_stdout { $rm->execute([], []) }; 1 };
    ok !$ok, 'rm fails';
    like $@, qr/OCPNodeProvider.*hetzner-a/, 'naming the missing provider';
    is $torn, 0, 'nothing is torn down';
};

done_testing;

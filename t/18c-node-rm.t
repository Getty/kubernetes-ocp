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
    # rejection can say which ones exist (karr #103). Without this the fake
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
    # is refused and the message names it. karr #103 only added the second
    # half of the house shape (say what would have worked), so the assertion
    # got stronger rather than different; the wording moved from "not found"
    # to the form `ocp quatschkommando` has answered in since karr #67.
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

done_testing;

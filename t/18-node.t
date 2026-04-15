#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Node::Ls;

sub capture_stdout (&) {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die "open stdout capture: $!";
    local *STDOUT = $fh;
    $code->();
    return $out;
}

{
    package FakeList;
    sub new   { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]->{items} }
}

{
    package FakeIO;
    sub new              { bless {}, $_[0] }
    sub object_to_struct { $_[1] }
}

{
    package FakeK8sN;

    my $_io = FakeIO->new;

    sub new {
        my ($class, %args) = @_;
        return bless {
            nodes => $args{nodes} // [],
            calls => [],
        }, $class;
    }

    sub k8s { $_io }

    sub list {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['list', $kind, \%args];
        return FakeList->new($self->{nodes}) if $kind eq 'OCPNode';
        return FakeList->new([]);
    }
}

my $cr1 = {
    metadata => { name => 'worker-1', creationTimestamp => '2026-04-14T10:00:00Z' },
    spec     => { role => 'worker', providerRef => 'hetzner-a' },
    status   => { phase => 'Ready', publicIP => '1.2.3.4' },
};
my $cr2 = {
    metadata => { name => 'cp-1', creationTimestamp => '2026-04-13T10:00:00Z' },
    spec     => { role => 'control-plane', providerRef => 'hetzner-a' },
    status   => { phase => 'Ready', publicIP => '5.6.7.8' },
};

my $k8s = FakeK8sN->new(nodes => [$cr1, $cr2]);
my $ls  = OCP::Cmd::Node::Ls->new(k8s => $k8s);
my $stdout = capture_stdout { $ls->execute([], []) };

like $stdout, qr/NAME .* ROLE .* PHASE .* PROVIDER .* IP .* AGE/, 'header present';
like $stdout, qr/cp-1\s+control-plane\s+Ready\s+hetzner-a\s+5\.6\.7\.8/, 'cp-1 row';
like $stdout, qr/worker-1\s+worker\s+Ready\s+hetzner-a\s+1\.2\.3\.4/,    'worker-1 row';

subtest 'sorted by name' => sub {
    my @lines = grep { /\S/ } split /\n/, $stdout;
    shift @lines;
    my @names = map { (split /\s+/, $_)[0] } @lines;
    is $names[0], 'cp-1',     'cp-1 first (sorted)';
    is $names[1], 'worker-1', 'worker-1 second (sorted)';
};

subtest 'list call uses typed Kind' => sub {
    my @list_calls = grep { $_->[0] eq 'list' } @{$k8s->{calls}};
    is scalar @list_calls, 1, 'one list call';
    is $list_calls[0][1], 'OCPNode', 'Kind is OCPNode';
    is $list_calls[0][2]{namespace}, 'ocp-system', 'namespace is ocp-system';
};

subtest 'pending phase default' => sub {
    my $no_status = {
        metadata => { name => 'bare-1', creationTimestamp => '2026-04-14T00:00:00Z' },
        spec     => { role => 'worker', providerRef => 'hetzner-a' },
        status   => {},
    };
    my $k = FakeK8sN->new(nodes => [$no_status]);
    my $l = OCP::Cmd::Node::Ls->new(k8s => $k);
    my $out = capture_stdout { $l->execute([], []) };
    like $out, qr/bare-1\s+worker\s+Pending/, 'missing phase shown as Pending';
};

done_testing;

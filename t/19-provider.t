#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Provider::Ls;

sub capture_stdout (&) {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die "open stdout capture: $!";
    local *STDOUT = $fh;
    $code->();
    return $out;
}

{
    package FakeK8s;

    sub new {
        my ($class, %args) = @_;
        return bless {
            providers => $args{providers} // [],
            nodes     => $args{nodes}     // [],
        }, $class;
    }

    sub get {
        my ($self, %args) = @_;
        my $path = $args{path} // '';
        if ($path =~ /ocpnodeproviders$/) {
            return { items => $self->{providers} };
        }
        if ($path =~ /ocpnodes$/) {
            return { items => $self->{nodes} };
        }
        return { items => [] };
    }
}

my $fake = FakeK8s->new(
    providers => [
        {
            metadata => {
                name        => 'hetzner-a',
                annotations => { 'ocp.internal/default' => 'true' },
            },
            spec => {
                type    => 'hetzner',
                hetzner => { location => 'fsn1' },
            },
        },
        {
            metadata => { name => 'hetzner-b' },
            spec     => {
                type    => 'hetzner',
                hetzner => { location => 'nbg1' },
            },
        },
        {
            metadata => { name => 'ssh-local' },
            spec     => { type => 'ssh' },
        },
    ],
    nodes => [
        { spec => { providerRef => 'hetzner-a' } },
        { spec => { providerRef => 'hetzner-a' } },
        { spec => { providerRef => 'hetzner-a' } },
        { spec => { providerRef => 'ssh-local' } },
    ],
);

my $ls = OCP::Cmd::Provider::Ls->new(k8s => $fake);
my $stdout = capture_stdout { $ls->execute([], []) };

like $stdout, qr/^NAME/m, 'header present';
like $stdout, qr/hetzner-a\s+hetzner\s+fsn1\s+\*\s+3/, 'hetzner-a row: type, location, default, count';
like $stdout, qr/hetzner-b\s+hetzner\s+nbg1\s+\s*0/, 'hetzner-b row: no default, 0 nodes';
like $stdout, qr/ssh-local\s+ssh\s+\S*\s+\S*\s*1/,   'ssh-local row: 1 node';

done_testing;

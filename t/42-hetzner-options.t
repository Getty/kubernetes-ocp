#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::Hetzner;

# server_type_options used to hardcode architecture => 'x86', so Hetzner's
# ARM line (CAX*) could never appear in a picker. OCP runs on aarch64 — a
# k3s cluster on a GB10 box is the proof — so hiding half the catalogue by
# default is a bug waiting for its first caller. The method has none yet;
# this test is what keeps the default honest until it gets one.

{
    package FakeServerType;
    sub new { my ($class, %a) = @_; bless {%a}, $class }
    for my $field (qw(name cores memory disk cpu_type architecture deprecated)) {
        no strict 'refs';
        *{"FakeServerType::$field"} = sub { $_[0]{$field} };
    }
}

sub types {
    return [
        FakeServerType->new(name => 'cax11', cores => 2, memory => 4, disk => 40,
            cpu_type => 'shared', architecture => 'arm', deprecated => 0),
        FakeServerType->new(name => 'cax21', cores => 4, memory => 8, disk => 80,
            cpu_type => 'shared', architecture => 'arm', deprecated => 0),
        FakeServerType->new(name => 'cpx11', cores => 2, memory => 2, disk => 40,
            cpu_type => 'shared', architecture => 'x86', deprecated => 0),
        FakeServerType->new(name => 'cx11', cores => 1, memory => 2, disk => 20,
            cpu_type => 'shared', architecture => 'x86', deprecated => 1),
    ];
}

sub picker {
    OCP::Hetzner->new(token => 'fake', _server_types => types());
}

subtest 'both architectures show up by default' => sub {
    my $opts = picker()->server_type_options;

    is_deeply [map { $_->{value} } @$opts], [qw(cpx11 cax11 cax21)],
        'arm types are listed, deprecated ones are not';

    my ($cax11) = grep { $_->{value} eq 'cax11' } @$opts;
    like $cax11->{label}, qr/\barm\b/,
        'the label names the architecture, so a picker can tell CAX from CPX';

    my ($cpx11) = grep { $_->{value} eq 'cpx11' } @$opts;
    like $cpx11->{label}, qr/\bx86\b/, 'x86 is named too, not just implied';
};

subtest 'architecture is still a deliberate filter' => sub {
    is_deeply [map { $_->{value} } @{ picker()->server_type_options(architecture => 'arm') }],
        [qw(cax11 cax21)], 'arm only when asked for';

    is_deeply [map { $_->{value} } @{ picker()->server_type_options(architecture => 'x86') }],
        [qw(cpx11)], 'x86 only when asked for';
};

subtest 'ordering is deterministic' => sub {
    # cores, then memory, then name — without the name tiebreak two equally
    # sized machines from different lines could swap places between runs.
    my $a = [map { $_->{value} } @{ picker()->server_type_options }];
    my $b = [map { $_->{value} } @{ picker()->server_type_options }];
    is_deeply $a, $b, 'same input, same order';
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use lib 'lib';
use lib 't/lib';
use Test::More;
use JSON::MaybeXS ();

use OCP::Hetzner::Picker;
use OCPTest::HetznerIO;

# k246: the picker hid deprecated server types on the top-level `deprecated`
# flag, which Hetzner removes from GET /server_types on 2026-11-02 -- from
# then on the filter hides nothing. Whether a type can be ordered is a per-location
# fact: each entry of server_types[].locations[] carries `available` and
# `deprecation` (an object, or null when the type is not deprecated there;
# docs.hetzner.cloud/cloud.spec.json). server_type_options(location => L)
# offers a type only when its entry for L is available and undeprecated;
# without a location, when at least one entry is. The catalogue comes through
# a real WWW::Hetzner::Cloud on a fake IO, so the entries arrive exactly as
# WWW::Hetzner 0.102 hands them on: plain hashes, JSON booleans, undef for null.

my $true  = JSON::MaybeXS::true;
my $false = JSON::MaybeXS::false;
my $deprecation = {
    announced         => '2026-09-01T00:00:00Z',
    unavailable_after => '2026-12-01T00:00:00Z',
};

sub entry {
    my ($name, %a) = @_;
    return {
        id          => 1,
        name        => $name,
        available   => $a{available} // $true,
        deprecation => $a{deprecation},
        recommended => $false,
    };
}

sub type {
    my ($name, $cores, $memory, $arch, $locations, %extra) = @_;
    return {
        id => 1, name => $name, description => uc $name,
        cores => $cores, memory => $memory, disk => 40,
        cpu_type => 'shared', architecture => $arch,
        locations => $locations,
        %extra,
    };
}

sub offered {
    my ($types, %filter) = @_;
    my $io     = OCPTest::HetznerIO->new(collections => { server_types => $types });
    my $picker = OCP::Hetzner::Picker->new(token => 'fake-token', _cloud => $io->cloud);
    return [ map { $_->{value} } @{ $picker->server_type_options(%filter) } ];
}

# One type per case, asked for location fsn1 and for no location at all.
my @cases = (
    [ 'available and not deprecated in fsn1',
      type('cx22', 2, 4, 'x86', [ entry('fsn1') ]),
      1, 1 ],
    [ 'deprecated in fsn1 (deprecation object set)',
      type('cx11', 1, 2, 'x86', [ entry('fsn1', deprecation => $deprecation) ]),
      0, 0 ],
    [ 'unavailable in fsn1',
      type('cpx31', 4, 8, 'x86', [ entry('fsn1', available => $false) ]),
      0, 0 ],
    [ 'fsn1 missing from its locations, orderable in hel1',
      type('cax11', 2, 4, 'arm', [ entry('hel1') ]),
      0, 1 ],
    [ 'deprecated in fsn1, orderable in nbg1',
      type('cx32', 4, 8, 'x86', [ entry('fsn1', deprecation => $deprecation), entry('nbg1') ]),
      0, 1 ],
    [ 'unavailable in fsn1, deprecated in hel1: nowhere orderable',
      type('ccx13', 2, 8, 'x86', [ entry('fsn1', available => $false),
                                   entry('hel1', deprecation => $deprecation) ]),
      0, 0 ],
    [ 'top-level deprecated set, orderable in fsn1: the old flag is not read',
      type('cpx21', 3, 4, 'x86', [ entry('fsn1') ], deprecated => $true),
      1, 1 ],
    [ 'locations: null',
      type('cx42', 8, 16, 'x86', undef),
      0, 0 ],
    [ 'a locations entry that is not a hash',
      type('cx52', 16, 32, 'x86', [ 'fsn1' ]),
      0, 0 ],
);

for my $case (@cases) {
    my ($what, $type, $with, $without) = @$case;
    my $name = $type->{name};
    subtest $what => sub {
        my $fsn1 = eval { offered([ $type ], location => 'fsn1') };
        is $@, '', 'location => fsn1 does not die';
        is_deeply $fsn1, ($with ? [ $name ] : []),
            $with ? "$name is offered for fsn1" : "$name is not offered for fsn1";

        my $any = eval { offered([ $type ]) };
        is $@, '', 'no location does not die';
        is_deeply $any, ($without ? [ $name ] : []),
            $without ? "$name is offered without a location"
                     : "$name is not offered without a location";
    };
}

subtest 'the whole catalogue, across pages' => sub {
    # Nine types at two a page: five pages, each case on its own.
    my @types = map { $_->[1] } @cases;

    is_deeply offered(\@types), [qw( cax11 cx22 cpx21 cx32 )],
        'no location: every type orderable somewhere, sorted by cores, memory, name';
    is_deeply offered(\@types, location => 'fsn1'), [qw( cx22 cpx21 )],
        'fsn1: only the types orderable there';
    is_deeply offered(\@types, location => 'hel1'), [qw( cax11 )],
        'hel1: deprecated there is not orderable there';
    is_deeply offered(\@types, location => 'nbg1'), [qw( cx32 )],
        'nbg1: the type deprecated in fsn1 is still offered where it is not';
    is_deeply offered(\@types, location => 'ash'), [],
        'a location no type is offered in: nothing';
    is_deeply offered(\@types, location => 'fsn1', architecture => 'arm'), [],
        'location and architecture combine';
    is_deeply offered(\@types, location => 'hel1', architecture => 'arm'), [qw( cax11 )],
        'location and architecture combine to a match';
};

done_testing;

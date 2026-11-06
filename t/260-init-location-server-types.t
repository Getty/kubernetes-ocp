#!/usr/bin/env perl
use strict;
use warnings;
use lib 'lib';
use lib 't/lib';
use Test::More;
use JSON::MaybeXS ();

use OCP::Cmd::Init;
use OCP::Config;
use OCP::Hetzner::Picker;
use OCPTest::HetznerIO;

# k260: `ocp init --hetzner` read the server type list without a location and
# asked for it next to the location list, so it offered every type that could
# be ordered *somewhere* (k246) -- including one deprecated or unavailable in
# the location the user had just picked, and Enter kept the default type even
# where it could not be ordered. Now the location comes first and the type
# list is server_type_options(location => chosen); a default that is not on a
# list is not preselected, and a location nothing can be ordered in is not
# offered. The catalogue comes through a real WWW::Hetzner::Cloud on the fake
# IO, so the entries reach the picker exactly as WWW::Hetzner hands them on.

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
    my ($name, $cores, $memory, $arch, @locations) = @_;
    return {
        id => 1, name => $name, description => uc $name,
        cores => $cores, memory => $memory, disk => 40,
        cpu_type => 'shared', architecture => $arch,
        locations => \@locations,
    };
}

sub location {
    my ($name, $city, $country) = @_;
    return {
        id => 1, name => $name, description => $city,
        city => $city, country => $country, network_zone => 'eu-central',
    };
}

my @LOCATIONS = (
    location('fsn1', 'Falkenstein', 'DE'),
    location('hel1', 'Helsinki',    'FI'),
    location('nbg1', 'Nuremberg',   'DE'),
    location('ash',  'Ashburn',     'US'),
);

# The defaults are cpx22 in fsn1 (OCP::Config; cpx21 until k264). Orderable
# per location:
#   fsn1: cpx22 cax21 cx33   hel1: cpx22 cpx21   nbg1: cpx21 cx33   ash: none
my @TYPES = (
    type('cpx22', 2, 4, 'x86',
        entry('fsn1'), entry('hel1'),
        entry('nbg1', deprecation => $deprecation),
        entry('ash',  available => $false)),
    type('cx33', 4, 8, 'x86',
        entry('fsn1'),
        entry('hel1', deprecation => $deprecation),
        entry('nbg1')),
    type('cax21', 4, 8, 'arm',
        entry('fsn1'),
        entry('hel1', available => $false)),
    type('cpx21', 3, 4, 'x86',
        entry('hel1'), entry('nbg1'),
        entry('ash', deprecation => $deprecation)),
);

# Run the picker step of `ocp init` against a scripted STDIN and return the
# command object with what went to STDOUT and STDERR.
sub run_picker {
    my ($input, %collections) = @_;

    my $io = OCPTest::HetznerIO->new(collections => {
        locations    => \@LOCATIONS,
        server_types => \@TYPES,
        %collections,
    });
    my $init = OCP::Cmd::Init->new(
        _picker      => OCP::Hetzner::Picker->new(token => 'fake-token', _cloud => $io->cloud),
        _interactive => 1,
    );

    my ($out, $err) = ('', '');
    open my $in,     '<', \$input or die "stdin: $!";
    open my $out_fh, '>', \$out   or die "stdout: $!";
    open my $err_fh, '>', \$err   or die "stderr: $!";
    {
        local *STDIN  = $in;
        local *STDOUT = $out_fh;
        local *STDERR = $err_fh;
        $init->_prompt_hetzner_control_plane(undef);
    }

    return ($init, $out, $err);
}

# The values a prompt listed, in order: the "  N) value (...)" lines under it.
sub listed {
    my ($out, $prompt) = @_;
    my ($section) = $out =~ /^\Q$prompt\E\n(.*?)^(?:  No default|Choice)/ms
        or return;
    return [ $section =~ /^\s+\d+\) (\S+)/mg ];
}

subtest 'a type deprecated or unavailable only in the chosen location is not offered there' => sub {
    my ($hel1, $out, $err) = run_picker("hel1\n\n");

    is_deeply listed($out, 'Server type (orderable in hel1):'), [qw( cpx22 cpx21 )],
        'hel1 offers only what can be ordered there: not cx33 (deprecated in hel1),'
        . ' not cax21 (unavailable in hel1)';
    is $hel1->_location,    'hel1',  'the chosen location is kept';
    is $hel1->_server_type, 'cpx22', 'Enter keeps the default where it can be ordered';
    is $err, '', 'nothing went wrong';

    my ($fsn1, $fsn1_out) = run_picker("fsn1\n\n");
    is_deeply listed($fsn1_out, 'Server type (orderable in fsn1):'), [qw( cpx22 cax21 cx33 )],
        'the same cx33 and cax21 are still offered for fsn1, where they can be ordered';
};

subtest 'an answer naming a type the location cannot order is not taken' => sub {
    my ($by_name, $out) = run_picker("hel1\ncx33\n");
    is $by_name->_server_type, 'cpx22', 'cx33 by name is refused in hel1';
    like $out, qr/'cx33' is not on the list — keeping cpx22/, 'and the dialog says so';

    my ($by_number) = run_picker("hel1\n3\n");
    is $by_number->_server_type, 'cpx22',
        'number 3 is out of range for the two types hel1 offers';
};

subtest 'the default type is not preselected where it cannot be ordered' => sub {
    # cpx22 is deprecated in nbg1: Enter must not write it. Enter and a name
    # off the list ask again; the third answer is a choice from the list.
    my ($init, $out, $err) = run_picker("nbg1\n\ncpx22\n2\n");

    is_deeply listed($out, 'Server type (orderable in nbg1):'), [qw( cpx21 cx33 )],
        'nbg1 lists what it can order';
    unlike $out, qr/orderable in nbg1.*\[default\]/s, 'nothing on it is marked as default';
    like $out, qr/No default: cpx22 is not on this list/, 'and the dialog says why';
    is scalar(() = $out =~ /Choice: /g), 3, 'Enter and cpx22 each asked again';
    like $out, qr/'cpx22' is not on the list\n/, 'naming the default does not slip it through';

    is $init->_location,    'nbg1', 'location nbg1';
    is $init->_server_type, 'cx33', 'the type actually chosen from the list';
    is $err, '', 'nothing went wrong';
};

subtest 'input that ends before a type is chosen writes no half placement' => sub {
    my ($init, $out, $err) = run_picker("nbg1\n");

    is $init->_location,    undef, 'no location is kept';
    is $init->_server_type, undef, 'no server type is kept';
    like $err, qr/\[!!\] No server type chosen — keeping the defaults \(cpx22 in fsn1\)/,
        'STDERR says nothing was chosen and what ocp.yaml gets instead';
    unlike $out, qr/\[ok\] Control plane/, 'no placement is reported as chosen';
};

subtest 'a location nothing can be ordered in is not offered' => sub {
    my ($init, $out) = run_picker("ash\n\n");

    is_deeply listed($out, 'Location:'), [qw( fsn1 hel1 nbg1 )],
        'ash is left out: cpx22 is unavailable there, cpx21 deprecated';
    is $init->_location, 'fsn1', 'answering ash keeps the default location';

    # Same cut when it hits the default location: cpx21 alone is orderable,
    # and only in hel1, so fsn1 is not on the list and cannot be the default.
    my @hel1_only = (type('cpx21', 3, 4, 'x86', entry('fsn1', available => $false), entry('hel1')));

    my ($picked, $picked_out) = run_picker("\n1\n1\n", server_types => \@hel1_only);
    is_deeply listed($picked_out, 'Location:'), [qw( hel1 )], 'only hel1 is offered';
    like $picked_out, qr/No default: fsn1 is not on this list/, 'fsn1 is not preselected';
    is $picked->_location,    'hel1',  'Enter asked again, 1 took hel1';
    is $picked->_server_type, 'cpx21', 'and the one type hel1 offers was taken by number';

    my ($ended, undef, $err) = run_picker('', server_types => \@hel1_only);
    is $ended->_location, undef, 'closed input picks no location';
    like $err, qr/\[!!\] No location chosen — keeping the defaults \(cpx22 in fsn1\)/,
        'and STDERR says so';
};

subtest 'nothing is asked unless the type catalogue can be read' => sub {
    # The type list depends on the location, but it is read before the first
    # question: a type catalogue that fails must not be found out after the
    # user has already answered the location.
    my ($init, $out, $err) = run_picker("hel1\n\n", server_types => undef);
    unlike $out, qr/Location:/, 'no location was asked for';
    # The why is WWW::Hetzner's own line for the fake's 404 on /server_types,
    # taken from the error it raises -- its wording is its own (k406).
    my $why = eval { OCPTest::HetznerIO->new->cloud->server_types->list_all; 1 }
        ? die "the fake answered GET /server_types\n"
        : $@->message;
    like $err, qr/\[!!\] Could not read the Hetzner catalogue: \Q$why\E — keeping the defaults\n/,
        'STDERR says the catalogue could not be read, and why (k265)';
    is $init->_location, undef, 'the defaults stay';

    my ($none, $none_out, $none_err) = run_picker("\n\n",
        server_types => [ type('cpx21', 3, 4, 'x86', entry('fsn1', deprecation => $deprecation)) ]);
    unlike $none_out, qr/Location:/, 'a catalogue with nothing orderable asks nothing either';
    like $none_err, qr/\[!!\] No Hetzner location offers a server type that can be ordered/,
        'and STDERR names that, not a read failure';
    is $none->_location, undef, 'the defaults stay';
};

done_testing;

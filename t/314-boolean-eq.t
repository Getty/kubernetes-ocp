#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use FindBin;
use JSON::MaybeXS ();
use JSON::PP ();
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';
use OCP;
use OCP::Cmd::Apply::AMDGPU;
use OCP::Config;
use OCP::Node;
use OCP::Provider;

#
# k314: a true or false that ocp reads is a JSON::PP::Boolean -- from ocp.yaml
# because OCP.pm sets $YAML::XS::Boolean = 'JSON::PP', from a CR because
# Kubernetes::REST decodes with JSON::MaybeXS. Cpanel::JSON::XS, the backend
# JSON::MaybeXS loads in the image, overloads eq and ne on that class, and its
# handler swaps the operands when the boolean stands on the right: then the
# plain string is taken for the boolean and only its truth is compared. So
# `'hetzner' eq $true` was 1, and `grep { $_ eq $value } @choices` took a
# `true` for every choice. OCP::BooleanEq, which OCP.pm loads, now calls
# Cpanel's handler with the operands as they are (k316 moved the fix there
# from OCP.pm); the boolean stays a JSON::PP::Boolean.
#
# The claims here, with OCP loaded as bin/ocp and robocop load it:
#   1. a boolean from YAML and one from JSON compare the same under eq and ne
#      whichever side of the operator it stands on, and equal none of the
#      words ocp chooses among; what Cpanel's POD says a boolean equals, it
#      still equals, now on both sides;
#   2. provider: true is no provider type;
#   3. gpu.amd.allocation: true is no allocation, and an AMD node whose
#      allocation label is a boolean gets the default allocation, and the
#      warning that says so, like any other value outside the three;
#   4. an OCPNode spec.role of true is no role;
#   5. what reads the boolean as a boolean sees what it saw before: the class,
#      truth, is_bool, and true/false in JSON and in YAML;
#   6. loaded before anything else that loads JSON::MaybeXS, as bin/ocp loads
#      it, OCP still fixes the class, and says nothing about it under -w.
#

local @ARGV = ();
my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

note 'JSON::MaybeXS backend: ' . JSON::MaybeXS::JSON();

# The booleans as ocp gets them: from a file through OCP's YAML reader, and
# from a CR body through JSON::MaybeXS.
my $yaml_file = path($tmpdir)->child('bool.yaml');
$yaml_file->spew_utf8("t: true\nf: false\n");
my $from_yaml = $ocp->load_file($yaml_file);
my $from_json = JSON::MaybeXS->new(utf8 => 1)->decode('{"t":true,"f":false}');

my %bool = (
    'YAML true'  => $from_yaml->{t},
    'YAML false' => $from_yaml->{f},
    'JSON true'  => $from_json->{t},
    'JSON false' => $from_json->{f},
);

# A config read from a file, as ocp reads it.
sub config_for {
    my ($yaml) = @_;
    my $f = path($tmpdir)->child('c' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8($yaml);
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

# --- 1. both sides, both sources ----------------------------------------------

my @words = (
    OCP::Provider->types, OCP::Node->roles, @OCP::Config::GPU_AMD_ALLOCATIONS,
    @OCP::Config::ROBOCOP_SECURITY_LEVELS, @OCP::Config::GPU_DRIVERS,
    qw( Pending Ready yes no ),
);

subtest 'a boolean compares the same on either side of eq and ne' => sub {
    for my $what (sort keys %bool) {
        my $b = $bool{$what};
        is ref $b, 'JSON::PP::Boolean', "$what is a JSON::PP::Boolean";
        for my $s (@words, qw( true false 1 0 ), '') {
            is(($s eq $b ? 1 : 0), ($b eq $s ? 1 : 0), "$what: '$s' eq b is b eq '$s'");
            is(($s ne $b ? 1 : 0), ($b ne $s ? 1 : 0), "$what: '$s' ne b is b ne '$s'");
        }
    }
};

# What Cpanel's POD says eq means for a boolean, which `$flag eq 'true'` in
# code relies on: kept, and now true with the boolean on either side. Under
# JSON::PP alone a boolean is 1 or 0 and no word, so there is nothing to keep.
subtest "what Cpanel says a boolean equals, it equals on both sides" => sub {
    plan skip_all => 'JSON::MaybeXS runs on ' . JSON::MaybeXS::JSON() . ', not Cpanel::JSON::XS'
        unless JSON::MaybeXS::JSON() eq 'Cpanel::JSON::XS';
    my %equals = (true => [ 'true', '1' ], false => [ 'false', '0', '' ]);
    for my $src (qw( JSON YAML )) {
        for my $tf (qw( true false )) {
            my $b = $bool{"$src $tf"};
            for my $s (@{ $equals{$tf} }) {
                ok $b eq $s, "$src $tf eq '$s'";
                ok $s eq $b, "'$s' eq $src $tf";
            }
            my $other = $tf eq 'true' ? 'false' : 'true';
            ok !($other eq $b), "not '$other' eq $src $tf";
        }
    }
};

subtest 'a boolean equals none of the words ocp chooses among' => sub {
    for my $what (sort keys %bool) {
        my $b = $bool{$what};
        for my $s (@words) {
            ok !($s eq $b), "$what: not '$s' eq b";
            ok !($b eq $s), "$what: not b eq '$s'";
            ok($s ne $b, "$what: '$s' ne b");
        }
        is scalar(grep { $_ eq $b } @words), 0, "$what: grep { \$_ eq b } finds none";
    }
};

# --- 2. provider: true --------------------------------------------------------

subtest 'provider: true is no provider type' => sub {
    my $cp = config_for("name: k314\ncontrol_planes:\n  provider: true\n")->control_planes->[0];
    is ref $cp->{provider}, 'JSON::PP::Boolean', 'ocp.yaml hands it over as a boolean';
    ok(!OCP::Provider->known_type($cp->{provider}), 'known_type refuses it');
    ok(!OCP::Provider->known_type($bool{'JSON true'}), 'and a JSON true (an OCPNodeProvider spec.type)');
    ok(!OCP::Provider->known_type($bool{'YAML false'}), 'and false');
    ok(OCP::Provider->known_type($_), "'$_' is still one") for OCP::Provider->types;
};

# --- 3. an AMD allocation of true --------------------------------------------

subtest 'gpu.amd.allocation: true is no allocation' => sub {
    my $config = config_for("name: k314\ncontrol_planes:\n  provider: local\n"
        . "gpu:\n  enabled: true\n  amd:\n    allocation: true\n");
    my $got = eval { $config->gpu_amd_allocation };
    is $got, undef, 'gpu_amd_allocation returns nothing for it';
    like $@, qr/^gpu\.amd\.allocation must be .*, not true at /, 'it croaks, naming the value';
};

subtest 'an AMD node with a boolean allocation label gets the default, and is told' => sub {
    my $present = $OCP::Config::AMD_GPU_PRESENT_LABEL;
    my $label   = $OCP::Config::AMD_GPU_ALLOCATION_LABEL;
    my $default = 'device-plugin';

    for my $what ('JSON true', 'YAML true') {
        my %labels = ($present => 'true', $label => $bool{$what});
        my %on = map {
            $_ => OCP::Cmd::Apply::AMDGPU::selects(
                OCP::Cmd::Apply::AMDGPU::affinity($_, $default), \%labels) ? 1 : 0
        } qw( device_plugin dra );
        is_deeply \%on, { device_plugin => 1, dra => 0 },
            "$what: the default's component selects the node, the DRA driver does not";

        my $err = '';
        {
            local *STDERR;
            open STDERR, '>', \$err or die "STDERR: $!";
            OCP::Cmd::Apply::AMDGPU::warn_bad_allocation_labels($default,
                { name => 'amd1', labels => \%labels });
        }
        like $err, qr/\[WARN\] Node 'amd1': \Q$label\E=.* is not .*; the node gets gpu\.amd\.allocation \(device-plugin\)/,
            "$what: warn_bad_allocation_labels says the node gets the default";
    }

    my %dra = ($present => 'true', $label => 'dra');
    ok(OCP::Cmd::Apply::AMDGPU::selects(OCP::Cmd::Apply::AMDGPU::affinity('dra', $default), \%dra),
        "a label 'dra' still selects the DRA driver");
};

# --- 4. an OCPNode spec.role of true ------------------------------------------

subtest 'spec.role: true is no role' => sub {
    my $cr = JSON::MaybeXS->new(utf8 => 1)->decode(
        '{"metadata":{"name":"w1"},"spec":{"role":true,"providerRef":"local-default"}}');
    ok(!OCP::Node->known_role($cr->{spec}{role}), 'known_role refuses a JSON true');
    ok(!OCP::Node->known_role($bool{'YAML true'}), 'and a YAML true');
    ok(!OCP::Node->wants_finalizer($cr), 'and wants_finalizer takes it for no worker');
    ok(OCP::Node->known_role($_), "'$_' is still one") for OCP::Node->roles;
};

# --- 5. read as a boolean, nothing changed ------------------------------------

subtest 'a boolean read as a boolean is what it was' => sub {
    my ($t, $f) = @bool{'YAML true', 'YAML false'};
    ok  $t, 'true is true';
    ok !$f, 'false is false';
    ok(JSON::MaybeXS::is_bool($t) && JSON::MaybeXS::is_bool($f), 'JSON::MaybeXS::is_bool');
    ok(JSON::PP::is_bool($t) && JSON::PP::is_bool($f), 'JSON::PP::is_bool');
    is(JSON::MaybeXS->new(canonical => 1)->encode($from_yaml), '{"f":false,"t":true}',
        'JSON::MaybeXS writes true and false');
    is(JSON::PP->new->canonical->encode($from_yaml), '{"f":false,"t":true}',
        'JSON::PP writes true and false');
    is(YAML::XS::Dump({ f => $f, t => $t }), "---\nf: false\nt: true\n",
        'YAML::XS writes true and false');
    is "$t$f", '10', 'they stringify as 1 and 0';
};

# --- 6. loaded first ---------------------------------------------------------

# bin/ocp loads OCP before anything else that loads JSON::MaybeXS. Cpanel
# overloads the class when it first loads, so OCP has to load it before the
# fix, or Cpanel would come later and put its own handler back. The unimport
# ahead of the fix is what keeps -w from saying "redefined".
subtest 'loaded first, as bin/ocp loads it, OCP still fixes the class' => sub {
    my $script = path($tmpdir)->child('first.pl');
    $script->spew_utf8(join "\n",
        'use strict;',
        'use warnings;',
        'use OCP ();',
        'use JSON::MaybeXS ();',
        q{my $t = JSON::MaybeXS->new->decode('[true]')->[0];},
        q{print 'backend=', JSON::MaybeXS::JSON(), "\n";},
        q{print 'hetzner eq true=', ('hetzner' eq $t ? 1 : 0), "\n";},
        '');
    my $lib = "$FindBin::Bin/../lib";
    my $out = `$^X -w -I$lib $script 2>&1`;
    is $?, 0, 'the script ran' or diag $out;
    like $out, qr/^hetzner eq true=0$/m, "'hetzner' eq true is false";
    unlike $out, qr/redefined/, 'and -w says nothing about it';
    note $out;
};

done_testing;

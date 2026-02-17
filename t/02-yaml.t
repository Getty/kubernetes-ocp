#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;

# Create OCP instance for testing
local @ARGV = ();
my $ocp = OCP->new;
isa_ok($ocp, 'OCP');

#
# dump + load round-trip
#

{
    my $data = { name => 'test', count => 42 };
    my $yaml = $ocp->dump($data);
    ok($yaml, 'dump returns YAML string');
    like($yaml, qr/^---/, 'YAML starts with document marker');
    like($yaml, qr/name: test/, 'YAML contains expected key');

    my $loaded = $ocp->load($yaml);
    is_deeply($loaded, $data, 'load round-trips correctly');
}

#
# dump with multiple resources (multi-document YAML)
#

{
    my @resources = (
        { apiVersion => 'v1', kind => 'Namespace', metadata => { name => 'test-ns' } },
        { apiVersion => 'v1', kind => 'ConfigMap', metadata => { name => 'test-cm' } },
    );

    my $yaml = $ocp->dump(@resources);
    my @docs = split(/^---\n/m, $yaml);
    # First split element is empty (before first ---)
    shift @docs while @docs && $docs[0] eq '';
    is(scalar @docs, 2, 'Multi-document YAML has 2 documents');

    like($yaml, qr/kind: Namespace/, 'First resource present');
    like($yaml, qr/kind: ConfigMap/, 'Second resource present');
}

#
# dump_file + load_file round-trip
#

{
    my $tmpdir = tempdir(CLEANUP => 1);
    my $file = path($tmpdir)->child('test.yaml')->stringify;

    my $data = {
        name    => 'mycluster',
        workers => [
            { name => 'w1', provider => 'hetzner' },
            { name => 'w2', provider => 'ssh' },
        ],
    };

    $ocp->dump_file($file, $data);
    ok(-f $file, 'dump_file creates file');

    my $loaded = $ocp->load_file($file);
    is_deeply($loaded, $data, 'load_file round-trips correctly');
}

#
# Nested structures
#

{
    my $data = {
        spec => {
            containers => [{
                name  => 'app',
                image => 'nginx:latest',
                ports => [{ containerPort => 80 }],
            }],
        },
    };

    my $yaml = $ocp->dump($data);
    my $loaded = $ocp->load($yaml);
    is_deeply($loaded, $data, 'Nested structures round-trip');
}

#
# Booleans (JSON::PP booleans for proper YAML true/false)
#

{
    require JSON::PP;
    my $data = {
        enabled  => JSON::PP::true,
        disabled => JSON::PP::false,
    };

    my $yaml = $ocp->dump($data);
    like($yaml, qr/enabled: true/, 'Boolean true serialized');
    like($yaml, qr/disabled: false/, 'Boolean false serialized');

    my $loaded = $ocp->load($yaml);
    ok($loaded->{enabled}, 'Boolean true round-trips as true');
    ok(!$loaded->{disabled}, 'Boolean false round-trips as false');
}

#
# Empty data
#

{
    my $yaml = $ocp->dump({});
    ok($yaml, 'dump handles empty hash');
    my $loaded = $ocp->load($yaml);
    is_deeply($loaded, {}, 'Empty hash round-trips');
}

#
# Singleton access
#

{
    my $same = OCP->instance;
    is($same, $ocp, 'OCP->instance returns same object');
    is($same->dump({x => 1}), $ocp->dump({x => 1}), 'Singleton produces same output');
}

done_testing;

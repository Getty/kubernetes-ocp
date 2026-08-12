#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Config;

local @ARGV = ();
my $ocp = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

#
# Test: System config defaults
#

{
    my $f = path($tmpdir)->child('defaults.yaml');
    $ocp->dump_file($f->stringify, { name => 'defaults' });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    is_deeply($c->system_config, {}, 'system_config defaults to empty hash');
    is($c->timezone, 'UTC', 'timezone defaults to UTC');
    is($c->locale, 'en_US.UTF-8', 'locale defaults to en_US.UTF-8');
    is($c->ntp_enabled, 1, 'ntp defaults to enabled');
}

#
# Test: Custom system config
#

{
    my $f = path($tmpdir)->child('custom.yaml');
    $ocp->dump_file($f->stringify, {
        name   => 'custom',
        system => {
            timezone => 'Europe/Berlin',
            locale   => 'de_DE.UTF-8',
            ntp      => 0,
        },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    is($c->timezone, 'Europe/Berlin', 'custom timezone');
    is($c->locale, 'de_DE.UTF-8', 'custom locale');
    is($c->ntp_enabled, 0, 'ntp disabled');
}

#
# Test: Partial system config (only timezone set)
#

{
    my $f = path($tmpdir)->child('partial.yaml');
    $ocp->dump_file($f->stringify, {
        name   => 'partial',
        system => { timezone => 'Asia/Tokyo' },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    is($c->timezone, 'Asia/Tokyo', 'partial: custom timezone');
    is($c->locale, 'en_US.UTF-8', 'partial: locale falls back to default');
    is($c->ntp_enabled, 1, 'partial: ntp falls back to default');
}

#
# Test: write_spec with system config
#

{
    my $f = path($tmpdir)->child('written-system.yaml')->stringify;
    OCP::Config->write_spec($f,
        name     => 'systemtest',
        provider => 'ssh',
        host     => '10.0.0.1',
        system   => {
            timezone => 'America/New_York',
            locale   => 'en_US.UTF-8',
        },
    );

    ok(-f $f, 'write_spec with system creates file');
    my $c = OCP::Config->new(file => $f, ocp => $ocp);
    is($c->timezone, 'America/New_York', 'write_spec system: timezone');
    is($c->locale, 'en_US.UTF-8', 'write_spec system: locale');
}

#
# Test: write_spec without system config (no system key in YAML)
#

{
    my $f = path($tmpdir)->child('no-system.yaml')->stringify;
    OCP::Config->write_spec($f,
        name     => 'nosystem',
        provider => 'ssh',
        host     => '10.0.0.1',
    );

    my $c = OCP::Config->new(file => $f, ocp => $ocp);
    is($c->timezone, 'UTC', 'write_spec without system: timezone defaults');
    is($c->locale, 'en_US.UTF-8', 'write_spec without system: locale defaults');
}

#
# Test: SSH config with default key paths
#

{
    my $projdir = path($tmpdir)->child('sshdefault');
    $projdir->mkpath;
    my $f = $projdir->child('ocp.yaml');
    $ocp->dump_file($f->stringify, {
        name         => 'sshdefault',
        control_planes => { provider => 'ssh', host => 'test.example.com' },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    like($c->ssh_private_key_path, qr/\.ocp\/id_ed25519$/, 'default SSH private key path');
    like($c->ssh_public_key_path, qr/\.ocp\/id_ed25519\.pub$/, 'default SSH public key path');
}

#
# Test: Hostname derivation from SSH host (helper check)
#

{
    my $f = path($tmpdir)->child('hostname.yaml');
    $ocp->dump_file($f->stringify, {
        name         => 'avatar',
        control_planes => {
            provider => 'ssh',
            host     => 'avatar.conflict.industries',
        },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    my $cps = $c->control_planes;
    my $host = $cps->[0]{host};
    is($host, 'avatar.conflict.industries', 'SSH host preserved in config');

    # Verify hostname splitting logic (as used in Apply.pm)
    my ($hostname, $domain) = split(/\./, $host, 2);
    is($hostname, 'avatar', 'hostname derived from FQDN');
    is($domain, 'conflict.industries', 'domain derived from FQDN');
}

done_testing;

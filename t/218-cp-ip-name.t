#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Config;
use OCP::Secrets;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::SSH;

#
# k218: an ssh control plane is named after the first label of its host, the
# way a FQDN gives its short name. control_planes.host: 10.5.10.20 therefore
# gave a Kubernetes Node, an OCPNode and a machine hostname of "10" (ocpt,
# 2026-10-01) -- and every other 10.x control plane would have been "10" too.
# An IP address has no short name: it is named in full, the dots as dashes
# (10-5-10-20), which is a valid node name and hostname.
#

sub config_for {
    my ($host) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({ name => 'ocpt',
        control_planes => { provider => 'ssh', host => $host } }));
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    return ($config, OCP::Secrets->new(project_dir => $config->project_dir));
}

sub identity { OCP::Cmd::Apply::Bootstrap::cp_identity((config_for($_[0]))[0]) }

subtest 'an IPv4 host is named in full' => sub {
    my $id = identity('10.5.10.20');
    is $id->{name},     '10-5-10-20', 'name 10-5-10-20, not "10"';
    is $id->{hostname}, '10-5-10-20', 'the machine hostname too';
    is $id->{domain},   '',           'and an IP has no domain';
    is $id->{host},     '10.5.10.20', 'the host itself is untouched';
};

subtest 'an IPv6 host is named in full' => sub {
    my $id = identity('2a01:4f8::20');
    is $id->{name},   '2a01-4f8--20', 'colons as dashes';
    is $id->{domain}, '',             'no domain';
};

subtest 'names that are names keep the old rule' => sub {
    my $id = identity('cp1.lab.example');
    is $id->{name},   'cp1',         'FQDN: first label';
    is $id->{domain}, 'lab.example', 'the rest is the domain';
    is identity('cortex')->{name}, 'cortex', 'short name as is';
};

subtest 'ocp ssh --node finds the control plane by that name' => sub {
    my ($config, $secrets) = config_for('10.5.10.20');
    my $ssh = OCP::Cmd::SSH->new(node => '10-5-10-20');
    is $ssh->_resolve_target_host($config, $secrets, '10-5-10-20'), '10.5.10.20',
        'the dashed name resolves to the host';
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use YAML::XS ();
use OCP;
use OCP::Config;
use OCP::Secrets;
use OCP::Cmd::SSH;

#
# Regression test for karr #117.
#
# OCP::Cmd::SSH died with 'Not a HASH reference' when ocp.yaml's
# control_planes was a list (mixed hetzner+ssh is the canonical case).
# The dispatch read $spec->{control_planes}->{provider}, but the field
# may be an arrayref and never gets wrapped back into a hash.
#
# The fix is in OCP::Cmd::SSH::_resolve_target_host: it normalises the
# raw field into a list of CPs regardless of form, then walks that list
# matching the node arg against each CP's identity. Anything that does
# not match a CP falls through to the legacy police/cp regex and from
# there to the IP/hostname path the way it always did.
#

sub fresh_config {
    my (%spec) = @_;

    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({ name => 't', %spec }));

    my $config  = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    return ($config, $secrets);
}

subtest 'multi-CP ssh+hetzner: ocp ssh --node police1 no longer crashes' => sub {
    my ($config, $secrets) = fresh_config(
        control_planes => [
            { provider => 'ssh',     host => '10.0.0.10' },
            { provider => 'hetzner', server_type => 'cpx21', location => 'fsn1' },
        ],
    );

    my $ssh = OCP::Cmd::SSH->new(node => 'police1');

    # Before the fix this died with 'Not a HASH reference at
    # lib/OCP/Cmd/SSH.pm line 79.'. The minimal required behaviour now:
    # it returns, and the caller can hand the undef to _unknown_node_error.
    my $resolved = eval { $ssh->_resolve_target_host($config, $secrets, 'police1') };

    is $@, '', 'no crash on multi-CP control_planes (karr #117)';
    is $resolved, undef,
        'a CP-like name without a reachable kubeconfig is left undefined'
        . ' so _unknown_node_error can run';
};

subtest 'multi-CP ssh+hetzner: ocp ssh --node <ip> returns the IP' => sub {
    my ($config, $secrets) = fresh_config(
        control_planes => [
            { provider => 'ssh',     host => '10.0.0.10' },
            { provider => 'hetzner', server_type => 'cpx21', location => 'fsn1' },
        ],
    );

    my $ssh = OCP::Cmd::SSH->new(node => '10.0.0.10');

    is $ssh->_resolve_target_host($config, $secrets, '10.0.0.10'),
       '10.0.0.10',
       'an IP/hostname is returned as-is when no CP matches it';
};

subtest 'single-CP ssh (hash form): the dispatch reaches the host' => sub {
    my ($config, $secrets) = fresh_config(
        control_planes => {
            provider => 'ssh',
            host     => 'gpu-master.lan',
        },
    );

    my $ssh = OCP::Cmd::SSH->new(node => 'gpu-master.lan');

    is $ssh->_resolve_target_host($config, $secrets, 'gpu-master.lan'),
       'gpu-master.lan',
       'arg equal to the host passes through (was the only path that worked before)';
};

subtest 'multi-CP all-ssh: dispatch on the matching CP, not the first' => sub {
    my ($config, $secrets) = fresh_config(
        control_planes => [
            { provider => 'ssh', host => 'a.lan' },
            { provider => 'ssh', host => 'b.lan' },
        ],
    );

    my $ssh = OCP::Cmd::SSH->new(node => 'a');

    # First ssh CP's host label is 'a' (stripped of .lan). The match by
    # identity returns the host of that CP, not whichever CP happened to
    # be first.
    is $ssh->_resolve_target_host($config, $secrets, 'a'),
       'a.lan',
       'ocp ssh --node <ssh-host-label> returns the host of the matching CP';

    is $ssh->_resolve_target_host($config, $secrets, 'b'),
       'b.lan',
       'ocp ssh --node <second-ssh-host-label> reaches the second CP';

    is $ssh->_resolve_target_host($config, $secrets, '1.2.3.4'),
       '1.2.3.4',
       'a non-matching IP/hostname is returned as-is';
};

subtest 'empty control_planes entry: no crash' => sub {
    # The first entry has no provider -- the old `eq 'ssh'` would warn
    # under strict but the deref used to be the louder failure. Make sure
    # the normalisation survives an undef provider too.
    my ($config, $secrets) = fresh_config(
        control_planes => [ {}, { provider => 'ssh', host => 'b.lan' } ],
    );

    my $ssh = OCP::Cmd::SSH->new(node => 'police1');

    my $resolved = eval { $ssh->_resolve_target_host($config, $secrets, 'police1') };
    is $@, '', 'undef provider does not crash the dispatch';
    is $resolved, undef,
        'a CP-like name with no provider match falls through to the unknown path';
};

done_testing;
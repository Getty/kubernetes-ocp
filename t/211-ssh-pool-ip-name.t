#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Config;
use OCP::Cmd::Apply::CR;

#
# k211 (lab 2026-10-15): a worker of an ssh pool was named after the first label
# of its host. A pool listing hosts by IP (nodes: [10.230.30.52]) therefore
# wanted an OCPNode "10" for every 10.x worker -- it matched none of the existing
# OCPNodes, so the pool's labels and taints never reached them, and two such
# workers collided on one name. Workers follow the control-plane rule of k218:
# an IP is named in full with dashes, a FQDN by its first label.
#

sub names_for {
    my (@nodes) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({
        name           => 'lab',
        control_planes => { provider => 'ssh', host => 'cp.lab.example' },
        workers        => [ { name => 'lab', provider => 'ssh', nodes => \@nodes,
                              labels => { 'example.org/pool' => 'lab' } } ],
    }));
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    return [ map { $_->{metadata}{name} } OCP::Cmd::Apply::CR::worker_ocpnodes($config) ];
}

is_deeply names_for('10.230.30.52'), ['10-230-30-52'], 'an IPv4 host is named in full, not "10"';
is_deeply names_for('10.230.30.52', '10.230.30.250'), ['10-230-30-52', '10-230-30-250'],
    'two 10.x workers get two names';
is_deeply names_for('otho-lab.ai.citilan.de'), ['otho-lab'], 'a FQDN still gives its first label';
is_deeply names_for('crag'), ['crag'], 'a bare hostname stays as it is';
is_deeply names_for('2a01:4f8::20'), ['2a01-4f8--20'], 'an IPv6 host is named with dashes';
is_deeply names_for({ host => '10.230.30.52' }), ['10-230-30-52'], 'the hash form of a node too';

my ($cr) = do {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({ name => 'lab',
        control_planes => { provider => 'ssh', host => 'cp.lab.example' },
        workers => [ { name => 'lab', provider => 'ssh', nodes => ['10.230.30.52'] } ] }));
    OCP::Cmd::Apply::CR::worker_ocpnodes(OCP::Config->new(file => $dir->child('ocp.yaml')->stringify));
};
is $cr->{spec}{host}, '10.230.30.52', 'spec.host keeps the address as written';

done_testing;

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
# k211 (lab 2026-10-15): a pool listed otho-lab by its IP while the machine
# already ran as OCPNode/otho-lab (spec.host 10.230.30.52, added with
# `ocp node add`). missing_worker_ocpnodes matched by name only, so apply
# --dry-run planned "would create OCPNode/10-230-30-52 and bring the worker up":
# a second bootstrap of a running worker. The host is the machine; an OCPNode on
# the same host counts as present, with a warning naming the name to use.
#

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeK8s  { sub new { bless {}, shift } sub object_to_struct { $_[1] } }
package FakeApi  {
    sub new  { my ($c, @n) = @_; bless { nodes => \@n }, $c }
    sub k8s  { FakeK8s->new }
    sub list { FakeList->new($_[0]{nodes}) }
}
package main;

sub config_with {
    my (@nodes) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({ name => 'lab',
        control_planes => { provider => 'ssh', host => 'cp.lab.example' },
        workers => [ { name => 'lab', provider => 'ssh', nodes => \@nodes } ] }));
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub ocpnode { my ($name, $host) = @_; { metadata => { name => $name }, spec => { host => $host } } }

my $api = FakeApi->new(ocpnode('otho-lab', '10.230.30.52'), ocpnode('crag', '10.230.30.250'));

{
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, @_ };
    my @missing = OCP::Cmd::Apply::CR::missing_worker_ocpnodes(undef, $api, config_with('10.230.30.52'));
    is scalar @missing, 0, 'a pool host that already is an OCPNode under another name is not missing';
    like "@warn", qr{worker 10-230-30-52 \(host 10\.230\.30\.52\) is already OCPNode/otho-lab}, 'the warning names both';
    like "@warn", qr{list it as otho-lab}, 'and says which name to use';
}
{
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, @_ };
    my @missing = OCP::Cmd::Apply::CR::missing_worker_ocpnodes(undef, $api, config_with('10.230.30.99'));
    is_deeply [ map { $_->{metadata}{name} } @missing ], ['10-230-30-99'], 'a new host is still missing';
    is scalar @warn, 0, 'without a warning';
}
{
    my @missing = OCP::Cmd::Apply::CR::missing_worker_ocpnodes(undef, $api, config_with('crag.ai.citilan.de'));
    is scalar @missing, 0, 'a host listed by the OCPNode name is present as before';
}

done_testing;

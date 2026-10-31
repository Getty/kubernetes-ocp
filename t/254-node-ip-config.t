#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';
use OCP;
use OCP::Choices;
use OCP::Config;

#
# k254: ocp.yaml control_planes[].node_ip, the address a control plane
# registers as its InternalIP (RKE2/K3s node-ip). Live, 2026-10-31: synapse,
# joined by 10.230.30.50, registered 192.168.0.165 (its default route) and its
# control plane could not reach it -- Ready, with a broken Cilium tunnel.
#
# OCP::Config::validate takes the key and checks it with
# OCP::Choices::node_ip_error, prefixed control_planes[N].node_ip. It refuses
# it where one value would be several machines' address -- the mapping form
# with nodes: N > 1, a workers pool -- and in a pool's nodes list, which apply
# does not read it from: each rather than ignore it, since ignored the node
# joins on its default route's address without a word. Two control planes of
# the list form may not share an address: compared part by part (dual-stack)
# and as IPs, the line names both entries.
#

local @ARGV = ();
my $ocp = OCP->new;
my $dir = tempdir(CLEANUP => 1);
my $n   = 0;

sub errors_for {
    my ($spec) = @_;
    my $f = path($dir)->child('ocp-' . ++$n . '.yaml');
    $ocp->dump_file($f->stringify, { name => 'lab', %$spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp)->validate;
}

sub ssh_cp { +{ provider => 'ssh', host => $_[0], @_[1 .. $#_] } }

subtest 'list form: a valid node_ip passes, one per control plane' => sub {
    my @e = errors_for({ control_planes => [
        ssh_cp('otho.lab',  node_ip => '10.230.30.52'),
        ssh_cp('crag.lab',  node_ip => '10.230.30.54,fd00::54'),
        ssh_cp('pichu.lab'),
    ] });
    is_deeply \@e, [], 'IPv4, dual-stack and none: no errors' or diag explain \@e;
};

subtest 'list form: an invalid node_ip is refused in node_ip_error\'s words' => sub {
    my @bad = ('10.230.30.52/24', 'otho.lab', '127.0.0.1', '10.0.0.1, fd00::1', '');
    for my $v (@bad) {
        my @e = errors_for({ control_planes => [ ssh_cp('crag.lab'), ssh_cp('otho.lab', node_ip => $v) ] });
        my $want = 'control_planes[2].node_ip: ' . OCP::Choices::node_ip_error($v);
        is_deeply \@e, [ $want ], "'$v': one line, the second control plane named" or diag explain \@e;
    }
};

subtest 'list form: a YAML list is refused, not stringified' => sub {
    my @e = errors_for({ control_planes => [ ssh_cp('otho.lab', node_ip => [ '10.0.0.1' ]) ] });
    is scalar(@e), 1, 'one error' or diag explain \@e;
    like $e[0], qr/\Acontrol_planes\[1\]\.node_ip: must be one string/, 'the shape is named';
};

subtest 'mapping form, one control plane: node_ip is that one\'s' => sub {
    my @e = errors_for({ control_planes => ssh_cp('otho.lab', node_ip => '10.230.30.52') });
    is_deeply \@e, [], 'accepted' or diag explain \@e;

    @e = errors_for({ control_planes => ssh_cp('otho.lab', nodes => 1, node_ip => '10.230.30.52') });
    is_deeply \@e, [], 'nodes: 1 too' or diag explain \@e;

    @e = errors_for({ control_planes => ssh_cp('otho.lab', node_ip => 'otho.lab') });
    is_deeply \@e, [ 'control_planes[1].node_ip: ' . OCP::Choices::node_ip_error('otho.lab') ],
        'and checked like a list entry' or diag explain \@e;
};

subtest 'mapping form with nodes: N > 1: refused once, saying why' => sub {
    my @e = errors_for({ control_planes => {
        provider => 'hetzner', server_type => 'cx32', location => 'fsn1',
        nodes => 3, node_ip => '10.230.30.52',
    } });
    is scalar(@e), 1, 'one line, not one per copy' or diag explain \@e;
    like $e[0], qr/\Acontrol_planes: node_ip with nodes: 3\b/, 'names the key and the count';
    like $e[0], qr/all 3 control planes the same address/, 'says why';
    like $e[0], qr/one by one.*each with its own node_ip/, 'and what works instead';

    @e = errors_for({ control_planes => {
        provider => 'hetzner', server_type => 'cx32', location => 'fsn1',
        nodes => 2, node_ip => 'not-an-ip',
    } });
    is scalar(@e), 1, 'an invalid one too: the shared refusal only, no syntax line per copy'
        or diag explain \@e;

    @e = errors_for({ control_planes => {
        provider => 'hetzner', server_type => 'cx32', location => 'fsn1', nodes => 3,
    } });
    is_deeply \@e, [], 'nodes: 3 without node_ip is fine' or diag explain \@e;
};

subtest 'a workers pool takes no node_ip, nor its nodes list' => sub {
    my @e = errors_for({
        control_planes => ssh_cp('otho.lab'),
        workers => [ { name => 'gpu', provider => 'ssh', host => 'synapse.lab',
                       node_ip => '10.230.30.50' } ],
    });
    is scalar(@e), 1, 'one error' or diag explain \@e;
    like $e[0], qr/\Aworker pool 'gpu': node_ip cannot be set on a pool/, 'names pool and key';
    like $e[0], qr/one address cannot be every machine's/, 'says why';
    like $e[0], qr/ocp node add NAME --node_ip ADDRESS.*spec\.nodeIP/, 'and where it goes instead';

    @e = errors_for({
        control_planes => ssh_cp('otho.lab'),
        workers => [ { name => 'lab', provider => 'ssh',
                       nodes => [ { host => 'crag.lab' }, 'raichu.lab',
                                  { host => 'synapse.lab', node_ip => '10.230.30.50' } ] } ],
    });
    is scalar(@e), 1, 'one error for the one entry that has it' or diag explain \@e;
    like $e[0], qr/\Aworker pool 'lab': nodes\[3\]\.node_ip is not read from a pool's nodes/,
        'names the entry';
    like $e[0], qr/ocp node add NAME --node_ip ADDRESS/, 'and where it goes instead';

    @e = errors_for({
        control_planes => ssh_cp('otho.lab'),
        workers => [ { name => 'lab', provider => 'ssh', nodes => [ { host => 'crag.lab' } ] } ],
    });
    is_deeply \@e, [], 'a pool without it: no error' or diag explain \@e;
};

#### Two control planes at one address

my $CLASH = 'two control planes cannot register at one address';
sub clash { "control_planes[$_[0]].node_ip: $_[1] $_[2] control_planes[$_[3]].node_ip too; $CLASH" }

subtest 'list form: the same node_ip on two control planes is refused, naming both' => sub {
    my @e = errors_for({ control_planes => [
        ssh_cp('otho.lab', node_ip => '10.230.30.52'),
        ssh_cp('crag.lab', node_ip => '10.230.30.52'),
    ] });
    is_deeply \@e, [ clash(2, '10.230.30.52', is => 1) ], 'one line, the later entry, the earlier one named'
        or diag explain \@e;

    @e = errors_for({ control_planes => [
        ssh_cp('otho.lab',  node_ip => '10.230.30.52'),
        ssh_cp('crag.lab',  node_ip => '10.230.30.54'),
        ssh_cp('pichu.lab', node_ip => '10.230.30.52'),
    ] });
    is_deeply \@e, [ clash(3, '10.230.30.52', is => 1) ], 'not only neighbours' or diag explain \@e;

    @e = errors_for({ control_planes => [
        ssh_cp('otho.lab',  node_ip => '10.230.30.52'),
        ssh_cp('crag.lab',  node_ip => '10.230.30.53'),
        ssh_cp('pichu.lab', node_ip => '10.230.30.54,fd00::54'),
    ] });
    is_deeply \@e, [], 'distinct addresses, one subnet: no error' or diag explain \@e;
};

subtest 'dual-stack: addresses are compared one by one' => sub {
    my @e = errors_for({ control_planes => [
        ssh_cp('otho.lab', node_ip => '10.230.30.52,fd00::52'),
        ssh_cp('crag.lab', node_ip => '10.230.30.52'),
    ] });
    is_deeply \@e, [ clash(2, '10.230.30.52', is => 1) ], 'v4,v6 against v4' or diag explain \@e;

    @e = errors_for({ control_planes => [
        ssh_cp('otho.lab', node_ip => '10.230.30.52'),
        ssh_cp('crag.lab', node_ip => 'fd00::54,10.230.30.52'),
    ] });
    is_deeply \@e, [ clash(2, '10.230.30.52', is => 1) ], 'the shared part, wherever it stands'
        or diag explain \@e;

    @e = errors_for({ control_planes => [
        ssh_cp('otho.lab', node_ip => '10.230.30.52,fd00::52'),
        ssh_cp('crag.lab', node_ip => 'fd00::52,10.230.30.52'),
    ] });
    is_deeply \@e, [ clash(2, 'fd00::52 and 10.230.30.52', are => 1) ], 'both parts, in one line'
        or diag explain \@e;

    @e = errors_for({ control_planes => [
        ssh_cp('otho.lab',  node_ip => '10.230.30.52'),
        ssh_cp('crag.lab',  node_ip => 'fd00::54'),
        ssh_cp('pichu.lab', node_ip => '10.230.30.52,fd00::54'),
    ] });
    is_deeply \@e, [ clash(3, '10.230.30.52', is => 1), clash(3, 'fd00::54', is => 2) ],
        'one line per control plane it collides with, in list order' or diag explain \@e;
};

subtest 'compared as addresses, not as text' => sub {
    my @e = errors_for({ control_planes => [
        ssh_cp('otho.lab', node_ip => 'fd00::52'),
        ssh_cp('crag.lab', node_ip => 'FD00:0::52'),
    ] });
    is_deeply \@e, [ clash(2, 'FD00:0::52', is => 1) ], 'an IPv6 spelt otherwise, quoted as written'
        or diag explain \@e;

    @e = errors_for({ control_planes => [
        ssh_cp('otho.lab', node_ip => '10.230.30.5'),
        ssh_cp('crag.lab', node_ip => '10.230.30.52'),
    ] });
    is_deeply \@e, [], 'one address the prefix of another is no clash' or diag explain \@e;
};

subtest 'an invalid node_ip is refused for itself and counted for nothing' => sub {
    my $bad = '10.230.30.52, fd00::1';
    my @e = errors_for({ control_planes => [
        ssh_cp('otho.lab', node_ip => $bad),
        ssh_cp('crag.lab', node_ip => '10.230.30.52'),
    ] });
    is_deeply \@e, [ 'control_planes[1].node_ip: ' . OCP::Choices::node_ip_error($bad) ],
        'the first one invalid: its syntax line only' or diag explain \@e;

    @e = errors_for({ control_planes => [
        ssh_cp('otho.lab', node_ip => '10.230.30.52'),
        ssh_cp('crag.lab', node_ip => $bad),
    ] });
    is_deeply \@e, [ 'control_planes[2].node_ip: ' . OCP::Choices::node_ip_error($bad) ],
        'the second one invalid: the same' or diag explain \@e;
};

subtest 'control_planes reader: node_ip travels with its entry' => sub {
    my $f = path($dir)->child('reader.yaml');
    $ocp->dump_file($f->stringify, { name => 'lab',
        control_planes => [ ssh_cp('otho.lab', node_ip => '10.230.30.52'), ssh_cp('crag.lab') ] });
    my $cps = OCP::Config->new(file => $f->stringify, ocp => $ocp)->control_planes;
    is $cps->[0]{node_ip}, '10.230.30.52', 'police1 has its node_ip';
    ok !exists $cps->[1]{node_ip}, 'police2 has none';
};

done_testing;

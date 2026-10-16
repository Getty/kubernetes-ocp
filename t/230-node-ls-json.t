#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::MaybeXS qw( decode_json );

use lib 'lib';

use OCP::Cmd::Node::Ls;

# k230: `ocp node ls --json` -- the node inventory for scripts. Kubernetes API
# only, deterministic bytes, every key always present.

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeApi {
    sub new { my ($c, %a) = @_; bless { %a, kinds => [] }, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list { my ($s, $kind) = @_; push @{$s->{kinds}}, $kind; FakeList->new($kind eq 'Node' ? $s->{nodes} : $s->{ocpnodes}) }
}
package main;

sub run_ls {
    my ($api, %opt) = @_;
    my $cmd = OCP::Cmd::Node::Ls->new(json => 1, k8s => $api, %opt);
    my $out = '';
    my $err = '';
    open my $fh, '>', \$out or die $!;
    open my $eh, '>', \$err or die $!;
    my $rc;
    { local *STDOUT = $fh; local *STDERR = $eh; $rc = $cmd->execute([], []); }
    return ($rc, $out, $err);
}

my @KEYS = sort qw(name role pool host address publicIP phase kubernetesNodeName
                   labels gpu runtime kubelet os kernel);

my $api = FakeApi->new(
    ocpnodes => [
        { metadata => { name => 'zeta', creationTimestamp => '2026-01-01T00:00:00Z' },
          spec => { role => 'worker', providerRef => 'ssh-default' } },
        { metadata => { name => 'crag', annotations => { 'ocp.internal/pool' => 'gpu' } },
          spec => { role => 'worker', host => '10.0.0.20', labels => { tier => 'gpu' } },
          status => { phase => 'Ready', address => '10.0.0.20', publicIP => '1.2.3.4',
                      kubernetesNodeName => 'crag-k8s' } },
    ],
    nodes => [
        { metadata => { name => 'crag-k8s' },
          status => {
              allocatable => { 'nvidia.com/gpu' => '2' },
              nodeInfo => { containerRuntimeVersion => 'containerd://1.7.23',
                            kubeletVersion => 'v1.32.1', osImage => 'Debian 12',
                            kernelVersion => '6.1.0' } } },
    ],
);

my ($rc, $out, $err) = run_ls($api);
is($rc, 0, 'exit 0');
is($err, '', 'nothing on STDERR');
my $data = decode_json($out);
is(scalar @$data, 2, 'one object per node');
is_deeply([map { $_->{name} } @$data], [qw(crag zeta)], 'sorted by name');
is_deeply([sort keys %$_], \@KEYS, 'complete key set for ' . $_->{name}) for @$data;

my ($crag, $zeta) = @$data;
is($crag->{gpu}, 2, 'gpu from allocatable of the joined Node');
is($crag->{pool}, 'gpu', 'pool from annotation');
is($crag->{runtime}, 'containerd://1.7.23', 'runtime');
is($crag->{kubelet}, 'v1.32.1', 'kubelet');
is($crag->{os}, 'Debian 12', 'os');
is($crag->{kernel}, '6.1.0', 'kernel');
is_deeply($crag->{labels}, { tier => 'gpu' }, 'labels');
is($crag->{kubernetesNodeName}, 'crag-k8s', 'join key kept');

is($zeta->{gpu}, 0, 'no Node: gpu is 0');
ok(!ref(\$zeta->{gpu}) || $zeta->{gpu} =~ /\A\d+\z/, 'gpu is a number');
is($zeta->{phase}, 'Pending', 'phase defaults to Pending');
for my $k (qw(pool host address publicIP kubernetesNodeName labels runtime kubelet os kernel)) {
    ok(exists $zeta->{$k} && !defined $zeta->{$k}, "missing $k is null");
}
like($out, qr/"gpu"\s*:\s*0\b/, 'gpu rendered as number, not string');
like($out, qr/"gpu"\s*:\s*2\b/, 'gpu from a string allocatable rendered as number');

unlike($out, qr/\d{4}-\d\d-\d\dT|creationTimestamp/, 'no timestamp in the output');

my (undef, $again) = run_ls($api);
is($again, $out, 'second run is byte-identical');

# fallback join: no status.kubernetesNodeName -> metadata.name
my $fb = FakeApi->new(
    ocpnodes => [ { metadata => { name => 'n1' }, spec => { role => 'control-plane' } } ],
    nodes    => [ { metadata => { name => 'n1' }, status => { allocatable => { 'nvidia.com/gpu' => 1 },
                    nodeInfo => { kubeletVersion => 'v1' } } } ],
);
my $fbd = decode_json((run_ls($fb))[1]);
is($fbd->[0]{gpu}, 1, 'fallback join on metadata.name');
is($fbd->[0]{kubelet}, 'v1', 'fallback join carries nodeInfo');

# the text form is unchanged
{
    my $cmd = OCP::Cmd::Node::Ls->new(k8s => $api);
    my $text = '';
    open my $fh, '>', \$text or die;
    { local *STDOUT = $fh; $cmd->execute([], []); }
    like($text, qr/^NAME\s+ROLE\s+PHASE\s+PROVIDER\s+IP\s+AGE$/m, 'text header unchanged');
    is_deeply([grep { $_ eq 'Node' } @{ $api->{kinds} }], [('Node') x 2], 'text form did not list Nodes (only the two JSON runs did)');
}

done_testing;

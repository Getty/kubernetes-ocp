#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::MaybeXS qw( decode_json );

use lib 'lib';

use OCP::Cmd::Health;

# k230: `ocp health --json` -- a read-only, non-waiting scan with the severity
# split of the gate at the end of `ocp apply`.

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeApi {
    sub new { my ($c, %a) = @_; bless { %a, lists => 0 }, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list { my $s = shift; $s->{lists}++; die "connection refused\n" if $s->{down}; FakeList->new($s->{pods}) }
}
package main;

sub pod {
    my ($ns, $name, %o) = @_;
    return { metadata => { namespace => $ns, name => $name },
             status => { phase => 'Running', containerStatuses => [ $o{c} ] } };
}
sub waiting { +{ state => { waiting => { reason => $_[0] } }, restartCount => $_[1] // 0, ready => 0 } }
sub up      { +{ state => { running => {} }, ready => 1, restartCount => 0 } }

sub run_health {
    my ($api, %o) = @_;
    my $cmd = OCP::Cmd::Health->new(api => $api, %o);
    my ($out, $err) = ('', '');
    open my $oh, '>', \$out or die; open my $eh, '>', \$err or die;
    my $rc;
    { local *STDOUT = $oh; local *STDERR = $eh; $rc = $cmd->execute([], []); }
    return ($rc, $out, $err);
}

my $mixed = FakeApi->new(pods => [
    pod('kube-system', 'zz-ok',     c => up()),
    pod('kube-system', 'coredns',   c => waiting('ImagePullBackOff')),
    pod('gpu-operator', 'dcgm',     c => waiting('ErrImagePull')),
    pod('apps', 'booting',          c => waiting('ContainerCreating')),
    pod('apps', 'a-fine',           c => up()),
]);

my ($rc, $out, $err) = run_health($mixed, json => 1);
is($rc, 1, 'critical pod: exit 1');
is($err, '', 'nothing on STDERR');
my $d = decode_json($out);
is_deeply([sort keys %$d], [sort qw(healthy fatal pods)], 'key set');
ok(!$d->{healthy}, 'not healthy'); ok($d->{fatal}, 'fatal');
is_deeply([map { "$_->{namespace}/$_->{name}:$_->{state}" } @{ $d->{pods} }],
          ['apps/booting:starting', 'gpu-operator/dcgm:warning', 'kube-system/coredns:critical'],
          'sorted by namespace,name with state split');
is_deeply([sort keys %{ $d->{pods}[0] }], [sort qw(namespace name state reason)], 'pod keys');
is($d->{pods}[2]{reason}, 'ImagePullBackOff', 'reason carried');
is($mixed->{lists}, 1, 'one scan, no wait loop');
unlike($out, qr/\d{4}-\d\d-\d\dT/, 'no timestamps');
my (undef, $again) = run_health($mixed, json => 1);
is($again, $out, 'second run is byte-identical');

my $warn = FakeApi->new(pods => [ pod('gpu-operator', 'dcgm', c => waiting('ErrImagePull')) ]);
($rc, $out) = run_health($warn, json => 1);
is($rc, 0, 'warnings only: exit 0');
ok(!decode_json($out)->{healthy}, 'a warning is not healthy');
ok(!decode_json($out)->{fatal}, 'not fatal');

my $ok = FakeApi->new(pods => [ pod('kube-system', 'a', c => up()) ]);
($rc, $out) = run_health($ok, json => 1);
is($rc, 0, 'healthy: exit 0');
$d = decode_json($out);
ok($d->{healthy}, 'healthy'); is_deeply($d->{pods}, [], 'no pods listed');

# API failure
my $down = FakeApi->new(down => 1);
($rc, $out, $err) = run_health($down, json => 1);
is($rc, 1, 'API failure: exit 1');
like(decode_json($out)->{error}, qr/connection refused/, 'error field');
like($err, qr/connection refused/, 'diagnosis on STDERR');

# text form: same exit code, no JSON
($rc, $out, $err) = run_health($mixed);
is($rc, 1, 'text form exit 1');
like($err, qr/\[!!\] kube-system\/coredns/, 'text form prints the critical line, on STDERR (k231)');

done_testing;

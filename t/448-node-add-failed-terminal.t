#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Node::Add;

#
# k448: `ocp node add NAME` for a NAME whose OCPNode is Failed read it back
# (ensure keeps the stored status), repeated its old message and exited 1,
# installing nothing, whatever switches were given -- and nothing said that
# Failed is terminal and that `ocp node rm NAME --keep_machine` comes first.
# Now the add meets the Failed OCPNode before it writes, probes or asks for a
# PIN, and says so on STDERR: the old message, that Failed is terminal, and
# the rm, then the add again.
#

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeIO   { sub new { bless {}, $_[0] } sub object_to_struct { $_[1] } }
package FakeK8s {
    sub new { my ($c, %a) = @_; bless { nodes => $a{nodes} // {}, calls => [] }, $c }
    sub k8s { FakeIO->new }
    sub list {
        my ($s, $kind) = @_;
        push @{ $s->{calls} }, [ 'list', $kind ];
        return FakeList->new($kind eq 'OCPNodeProvider' ? [ {
            metadata => { name => 'ssh-default', namespace => 'ocp-system', annotations => {} },
            spec     => { type => 'ssh' } } ] : []);
    }
    sub get {
        my ($s, $kind, %a) = @_;
        push @{ $s->{calls} }, [ 'get', $kind, $a{name} ];
        if ($kind eq 'OCPNodeProvider') {
            return { metadata => { name => 'ssh-default', namespace => 'ocp-system' },
                     spec => { type => 'ssh' } } if $a{name} eq 'ssh-default';
            die "404: not found\n";
        }
        return $s->{nodes}{ $a{name} } if $kind eq 'OCPNode' && $s->{nodes}{ $a{name} };
        die "404: not found $kind/$a{name}\n";
    }
    sub ensure { my ($s, $o) = @_; push @{ $s->{calls} }, [ 'ensure', $o ]; $o }
    sub patch  { my ($s, $kind) = @_; push @{ $s->{calls} }, [ 'patch', $kind ]; {} }
}
package main;

my $MESSAGE = 'Rex task failed: Cilium state from an earlier cluster is on this machine';

sub ocpnode {
    my ($name, $role, $phase) = @_;
    return { apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
             metadata   => { name => $name, namespace => 'ocp-system' },
             spec       => { role => $role, providerRef => 'ssh-default', host => '10.0.0.9' },
             status     => { phase => $phase, message => $MESSAGE } };
}

sub add {
    my ($k8s, %flags) = @_;
    my $add = OCP::Cmd::Node::Add->new(k8s => $k8s, provider => 'ssh-default',
                                       host => '10.0.0.9', %flags);
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my $rc;
    {
        no warnings 'redefine';
        # Anything past the refusal would reach for the machine: recorded.
        local *OCP::Cmd::Node::Add::_preflight_host = sub { push @{ $k8s->{calls} }, [ 'preflight' ] };
        local *OCP::Cmd::Node::Add::_cli_reconcile  = sub { push @{ $k8s->{calls} }, [ 'reconcile' ]; 1 };
        local *STDOUT = $o;
        local *STDERR = $e;
        $rc = eval { $add->execute([], []) };
        $rc = "died: $@" unless defined $rc;
    }
    return { rc => $rc, out => $out, err => $err,
             reached => [ map { $_->[0] } grep { $_->[0] =~ /^(?:ensure|patch|preflight|reconcile)$/ } @{ $k8s->{calls} } ] };
}

for my $case ([ 'worker-9', 'worker', [] ],
              [ 'police4', 'control-plane', [ role => 'control-plane' ] ]) {
    my ($name, $role, $flags) = @$case;
    for my $switches ([], [ clean_cilium_residue => 1 ], [ nowait => 1 ]) {
        my $label = "$role $name" . (@$switches ? " --$switches->[0]" : '');
        subtest "$label: a Failed OCPNode is said to be terminal, with the rm first" => sub {
            my $k8s = FakeK8s->new(nodes => { $name => ocpnode($name, $role, 'Failed') });
            my $r = add($k8s, name => $name, @$flags, @$switches);
            is $r->{rc}, 1, 'exit 1';
            is_deeply $r->{reached}, [], 'nothing written, no probe, no install';
            like $r->{err}, qr/^  \[!!\] Failed: \Q$MESSAGE\E$/m, 'the old message, on STDERR';
            like $r->{err}, qr/OCPNode $name is Failed, and Failed is terminal/, 'says Failed is terminal';
            like $r->{err}, qr/^  ocp node rm $name --keep_machine$/m, 'names the rm, keeping the machine';
            my $again = "ocp node add $name" . ($role eq 'control-plane' ? ' --role control-plane' : '')
                      . ' --provider ssh-default --host 10.0.0.9';
            like $r->{err}, qr/^  \Q$again\E/m, 'then the add again, with its role, provider and host';
            like $r->{err}, qr/ocp node rm.*\n.*ocp node add/s, 'the rm first';
            is $r->{out}, '', 'nothing on STDOUT';
        };
    }
}

subtest 'control: an OCPNode not Failed is added as before' => sub {
    my $k8s = FakeK8s->new(nodes => { 'worker-9' => ocpnode('worker-9', 'worker', 'Installing') });
    my $r = add($k8s, name => 'worker-9', nowait => 1);
    is $r->{rc}, 0, 'exit 0';
    is_deeply $r->{reached}, [ 'preflight', 'ensure' ], 'the host preflight, then the OCPNode ensured';
    unlike $r->{err}, qr/terminal/, 'no terminal note';
};

subtest 'control: no OCPNode yet' => sub {
    my $k8s = FakeK8s->new;
    my $r = add($k8s, name => 'worker-9', nowait => 1);
    is $r->{rc}, 0, 'exit 0';
    is_deeply $r->{reached}, [ 'preflight', 'ensure' ], 'the host preflight, then the OCPNode ensured';
    unlike $r->{err}, qr/terminal/, 'no terminal note';
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Apply::CR;

#
# k447: on the reconcile path check_worker_phases covers workers only and
# warn_unlisted_failed_ocpnodes skips every other role, so a control plane
# whose join was refused (police2, for Cilium leftovers, k445) stayed Failed
# and every later `ocp apply` said nothing about it. check_control_plane_phases
# names each Failed control-plane OCPNode on STDERR with its message and the
# way back -- ocp node rm NAME --keep_machine, then ocp node add NAME --role
# control-plane -- and counts it the way a Failed worker is counted: in
# {_failed_components}, so the run ends incomplete and non-zero.
# The wiring into reconcile_components is held by t/445 (section 3).
#

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeK8s  { sub new { bless {}, shift } sub object_to_struct { $_[1] } }
package FakeApi  {
    sub new  { my ($c, @n) = @_; bless { nodes => \@n }, $c }
    sub k8s  { FakeK8s->new }
    sub list { die $_[0]{die} if $_[0]{die}; FakeList->new($_[0]{nodes}) }
}
package main;

sub capture_both {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    {
        local *STDOUT = $o;
        local *STDERR = $e;
        $code->();
    }
    return ($out, $err);
}

sub ocpnode {
    my ($name, $role, $phase, %more) = @_;
    return { metadata => { name => $name },
             spec     => { role => $role, providerRef => $more{provider} // 'ssh-default',
                           ($more{host} ? (host => $more{host}) : ()) },
             status   => { phase => $phase, (defined $more{message} ? (message => $more{message}) : ()) } };
}

my $MSG = 'Rex task failed: Cilium state from an earlier cluster is on this machine';

subtest 'a Failed control plane: named on STDERR with its message and the way back, counted' => sub {
    my $api = FakeApi->new(
        ocpnode('10-230-30-51', 'control-plane', 'Ready'),
        ocpnode('police2', 'control-plane', 'Failed', message => $MSG),
        ocpnode('police3', 'control-plane', 'Failed', provider => 'hetzner-default'),
        ocpnode('police4', 'control-plane', 'Installing'),
        ocpnode('w-1', 'worker', 'Failed', message => 'a worker'),
    );
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my @named;
    my ($out, $err) = capture_both(sub {
        @named = OCP::Cmd::Apply::CR::check_control_plane_phases($apply, $api);
    });
    is_deeply \@named, [ 'police2', 'police3' ], 'the Failed control planes, and only those';
    like $err, qr/^  \[!!\] control plane police2 is Failed: \Q$MSG\E$/m, 'police2 with its message';
    like $err, qr/^  \[!!\] control plane police3 is Failed$/m, 'police3, which has none';
    like $err, qr/^\s+the way back: ocp node rm police2 --keep_machine, then ocp node add police2 --role control-plane --provider ssh-default$/m,
        'the way back for police2: rm keeping the machine, then add as a control plane';
    like $err, qr/ocp node add police3 --role control-plane --provider hetzner-default$/m,
        'with the provider its OCPNode names';
    unlike $err, qr/w-1|police4|10-230-30-51/, 'a worker, a control plane on its way, a Ready one: not here';
    is $out, '', 'nothing on STDOUT';
    is_deeply $apply->{_failed_components}, [ 'control plane police2', 'control plane police3' ],
        'counted like a Failed worker: the run does not complete';
};

subtest 'an ssh control plane: the add names its host too' => sub {
    my $api = FakeApi->new(ocpnode('police5', 'control-plane', 'Failed', host => '10.0.0.5', message => $MSG));
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my (undef, $err) = capture_both(sub { OCP::Cmd::Apply::CR::check_control_plane_phases($apply, $api) });
    like $err, qr/then ocp node add police5 --role control-plane --provider ssh-default --host 10\.0\.0\.5$/m,
        '--host from its spec';
};

subtest 'no Failed control plane: nothing said, nothing counted' => sub {
    my $api = FakeApi->new(ocpnode('police1', 'control-plane', 'Ready'), ocpnode('w-1', 'worker', 'Failed'));
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my ($out, $err) = capture_both(sub { OCP::Cmd::Apply::CR::check_control_plane_phases($apply, $api) });
    is $out . $err, '', 'silent';
    ok !$apply->{_failed_components}, 'nothing counted';
};

subtest 'a list that fails dies, for the caller to report' => sub {
    my $api = FakeApi->new;
    $api->{die} = "connection refused\n";
    my $apply = bless {}, 'OCP::Cmd::Apply';
    eval { OCP::Cmd::Apply::CR::check_control_plane_phases($apply, $api) };
    is $@, "connection refused\n", 'dies with the cause';
};

done_testing;

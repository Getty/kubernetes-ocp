#!/usr/bin/env perl
# karr k176 -- every robocop reconcile says in the pod log what it did.
#
# Live finding: an OCPNode went Failed with "SSH not reachable on ocpt-w.vm
# after 120s" and robocop's log had no line about it -- the reason lived only in
# status.message. OCP::Node records such failures into the status without
# dying, so nothing reached the controller's catch, and the forked child
# (k159) logged nothing of its own.
#
# This file pins:
#   - the child logs the start (node, phase) and the result (new phase);
#   - a failure OCP::Node records without dying goes to STDERR with its reason;
#   - Failed is terminal, so the log and status.message say how to retry;
#   - all of it survives the fork and the child's POSIX::_exit.
#
# No cluster: a fake kube client, OCP::Node's install step stubbed to fail
# exactly the way the real SSH wait does.

use strict;
use warnings;
use Test::More;
use IO::Async::Loop;
use Path::Tiny ();

use lib 'lib';

use OCP::Node;
use OCP::Provider;
use OCP::Robocop::Controller;

sub ocpnode {
    my ($name, $phase, $message) = @_;
    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => $name, namespace => 'ocp-system', resourceVersion => '1' },
        spec       => { role => 'worker', providerRef => 'p' },
        status     => {
            defined $phase   ? (phase   => $phase)   : (),
            defined $message ? (message => $message) : (),
        },
    };
}

# Answers get() for the OCPNode and its provider, records every status patch
# (and, when given a file, appends it there -- a forked child's patches are
# otherwise invisible to the test).
package FakeKube {
    use JSON::MaybeXS ();
    sub new { my ($c, %a) = @_; bless { patches => [], %a }, $c }
    sub get {
        my ($self, $kind, %a) = @_;
        return $self->{node} if $kind eq 'OCPNode';
        return { apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
                 metadata => { name => 'p', namespace => 'ocp-system' },
                 spec => { type => 'ssh' } };
    }
    sub k8s { bless {}, 'FakeIOK8s' }
    # The teardown finalizer robocop adds to a worker that has none (k179).
    sub patch { 1 }
    sub patch_status {
        my ($self, $kind, %a) = @_;
        push @{ $self->{patches} }, $a{patch}{status};
        Path::Tiny::path($self->{patch_file})->append(
            JSON::MaybeXS->new(canonical => 1)->encode($a{patch}{status}) . "\n")
            if $self->{patch_file};
        return 1;
    }
}
package FakeIOK8s { sub object_to_struct { $_[1] } }

package main;

sub ctrl {
    my (%over) = @_;
    return OCP::Robocop::Controller->new(
        ssh_key    => 'K',
        server_url => 'U',
        join_token => 'T',
        %over,
    );
}

# The failure as the real _install_kubernetes records it: status Failed with
# the reason, and a normal return -- no exception for anyone to catch.
my $SSH_FAIL = sub {
    my ($self) = @_;
    $self->_patch_status(phase => 'Failed',
        message => "SSH not reachable: SSH not reachable on ocpt-w.vm after 120s\n");
    return;
};

sub capture_std {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    {
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $code->();
    }
    return ($out, $err);
}

subtest 'a failure OCP::Node records without dying is logged with its reason' => sub {
    no warnings 'redefine';
    local *OCP::Provider::from_cr            = sub { bless {}, 'FakeProvider' };
    local *OCP::Node::_install_kubernetes    = $SSH_FAIL;

    my $kube = FakeKube->new;
    my ($out, $err) = capture_std(sub {
        ctrl(kube => $kube)->_reconcile_cr(ocpnode('w1', 'Installing'));
    });

    like $out, qr/w1: reconciling \(phase Installing\)/, 'the start: node and phase';
    like $err, qr/w1: .*Installing -> Failed.*SSH not reachable on ocpt-w\.vm after 120s/,
        'the failure and its reason go to STDERR';
    like $err, qr/w1: .*terminal.*ocp node rm w1.*ocp node add w1/,
        'with a one-line hint how to retry';

    my $last = $kube->{patches}[-1];
    like $last->{message}, qr/SSH not reachable on ocpt-w\.vm after 120s/,
        'status.message keeps the reason';
    like $last->{message}, qr/ocp node rm w1.*ocp node add w1/,
        'and carries the same hint';
    ok !exists $last->{phase}, 'the hint patch leaves the phase alone';
};

subtest 'a successful step logs the phase it reached' => sub {
    no warnings 'redefine';
    local *OCP::Provider::from_cr         = sub { bless {}, 'FakeProvider' };
    local *OCP::Node::_install_kubernetes = sub {
        $_[0]->_patch_status(phase => 'Joining', message => 'RKE2 agent installed');
    };

    my $kube = FakeKube->new;
    my ($out, $err) = capture_std(sub {
        ctrl(kube => $kube)->_reconcile_cr(ocpnode('w1', 'Installing'));
    });
    like $out, qr/w1: .*Installing -> Joining/, 'the result on STDOUT';
    is $err, '', 'nothing on STDERR';
    is scalar @{ $kube->{patches} }, 1, 'no extra status patch';
};

subtest 'a node already Failed is skipped, and the hint is not added twice' => sub {
    my $kube = FakeKube->new;
    my $c = ctrl(kube => $kube);
    my $hint = $c->retry_hint('w1');
    my ($out, $err) = capture_std(sub {
        $c->_reconcile_cr(ocpnode('w1', 'Failed', "boom -- $hint"));
    });
    like $out, qr/w1: .*Failed.*terminal/, 'said so in one line';
    is scalar @{ $kube->{patches} }, 0, 'no status write';
};

subtest 'a controller-side failure (_mark_failed) also carries the hint, on STDERR' => sub {
    my $kube = FakeKube->new;
    my $cr = ocpnode('w1', 'Pending');
    delete $cr->{spec}{providerRef};
    my ($out, $err) = capture_std(sub { ctrl(kube => $kube)->_reconcile_cr($cr) });

    like $err, qr/marking w1 Failed: spec\.providerRef is missing/, 'reason on STDERR';
    like $err, qr/ocp node rm w1/, 'with the hint';
    like $kube->{patches}[-1]{message}, qr/providerRef is missing.*ocp node rm w1/s,
        'and the hint is in status.message';
};

subtest 'the log lines survive a real fork and the child _exit' => sub {
    my $dir = Path::Tiny->tempdir;
    my $out_file = $dir->child('stdout');
    my $err_file = $dir->child('stderr');

    no warnings 'redefine';
    local *OCP::Provider::from_cr         = sub { bless {}, 'FakeProvider' };
    local *OCP::Node::_install_kubernetes = $SSH_FAIL;

    my $loop = IO::Async::Loop->new;
    my $kube = FakeKube->new(node => ocpnode('w1', 'Installing'),
                             patch_file => $dir->child('patches')->stringify);
    my $c = ctrl(kube => $kube, loop => $loop);

    # The child inherits the descriptors; keep the parent's own buffered,
    # the way a pod's piped STDOUT is.
    open my $save_out, '>&', \*STDOUT or die $!;
    open my $save_err, '>&', \*STDERR or die $!;
    open STDOUT, '>', $out_file->stringify or die $!;
    open STDERR, '>', $err_file->stringify or die $!;
    STDOUT->autoflush(0);

    $c->enqueue(ocpnode('w1', 'Installing'));
    my $deadline = time + 20;
    $loop->loop_once(0.2) while $c->reconciling(ocpnode('w1')) && time < $deadline;

    open STDOUT, '>&', $save_out or die $!;
    open STDERR, '>&', $save_err or die $!;

    ok !$c->reconciling(ocpnode('w1')), 'the child finished';
    like $out_file->slurp, qr/w1: reconciling \(phase Installing\)/, 'start line from the child';
    my $err = $err_file->slurp;
    like $err, qr/Installing -> Failed.*SSH not reachable on ocpt-w\.vm after 120s/,
        'failure with its reason from the child, on STDERR';
    like $err, qr/ocp node rm w1/, 'and the retry hint';
    like $dir->child('patches')->slurp, qr/ocp node add w1/,
        'the child wrote the hint into status.message';
};

done_testing;

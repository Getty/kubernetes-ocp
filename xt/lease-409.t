#!/usr/bin/env perl
#
# The OCPNode lease against a REAL API server (k29).
#
# OCP::Node keeps two reconcilers off the same node with an annotation, and
# the annotation is only a lock because the API server refuses a write that
# carries a stale resourceVersion (409 Conflict). t/16-node.t proves the code
# that reacts to a 409, against a transport that answers 409 on command. It
# cannot prove that the API server answers one -- nothing in t/ has ever
# talked to one. This does.
#
# Needs a cluster `ocp apply` has bootstrapped (the OCPNode CRD must exist):
#
#   OCP_SMOKE_KUBECONFIG=/path/to/kubeconfig prove -l xt/lease-409.t
#
# xt/smoke.sh runs it in its own project dir. Without the variable the file
# skips, so a stray `prove -r xt` is harmless.
#
# What it does to the cluster: one OCPNode, named lease-409-<pid>, role
# control-plane, status.phase Failed -- which robocop leaves alone as terminal
# -- and no finalizer, so deleting it is the whole cleanup. It is deleted at
# the end whatever the checks said.
#
use strict;
use warnings;
use Test::More;
use Time::HiRes ();
use JSON::MaybeXS ();
use Kubernetes::REST::Kubeconfig;

use lib 'lib';
use OCP::K8s;
use OCP::Node;

my $kubeconfig = $ENV{OCP_SMOKE_KUBECONFIG};
plan skip_all => 'set OCP_SMOKE_KUBECONFIG to a cluster kubeconfig to run against a real API server'
    unless $kubeconfig && -r $kubeconfig;

my $ROUNDS = $ENV{OCP_SMOKE_LEASE_ROUNDS} || 8;
my $NAME   = "lease-409-$$";
my $NS     = 'ocp-system';

sub client {
    my $api = Kubernetes::REST::Kubeconfig->new(kubeconfig_path => $kubeconfig)->api;
    OCP::K8s->register($api);
    return $api;
}

sub node_for {
    my ($api, $id) = @_;
    my $cr = $api->k8s->object_to_struct($api->get('OCPNode', $NAME, namespace => $NS));
    return OCP::Node->new(cr => $cr, k8s => $api, reconciler_id => $id);
}

my $api = client();

$api->ensure({
    apiVersion => 'ocp.internal/v1',
    kind       => 'OCPNode',
    metadata   => { name => $NAME, namespace => $NS },
    spec       => { role => 'control-plane', providerRef => 'ssh-default' },
});
# Terminal, so robocop does not try to provision a machine for it. Status
# only goes through /status (OCP::K8s::patch_status says why).
OCP::K8s->patch_status($api, kind => 'OCPNode', name => $NAME, namespace => $NS,
    status => { phase => 'Failed', message => 'xt/lease-409.t test object' });

my $cleaned;
my $cleanup = sub {
    return if $cleaned++;
    eval { $api->delete('OCPNode', $NAME, namespace => $NS) };
};
END { $cleanup->() if $cleanup }

# --- 1: a write from a stale read is refused by the server -----------------

{
    my $na = node_for($api, 'smoke-a');
    my $nb = node_for($api, 'smoke-b');   # read at the same resourceVersion as $a

    my $a_lease = eval { $na->_acquire_lease; 1 };
    ok $a_lease, 'reconciler a takes the lease' or diag $@;

    # b writes the CR it read before a's write. The annotation says b holds
    # the lease; the resourceVersion says it read a world that is gone.
    my $stale = $nb->cr;
    $stale->{metadata}{annotations}{'ocp.internal/reconciler-lease'} = 'smoke-b@2000-01-01T00:00:00Z@300';
    eval { $nb->_put_cr($stale) };
    like $@, qr/\b409\b/, 'the API server answers 409 to a write from a stale resourceVersion';

    my $now = $api->k8s->object_to_struct($api->get('OCPNode', $NAME, namespace => $NS));
    like $now->{metadata}{annotations}{'ocp.internal/reconciler-lease'} // '', qr/^smoke-a\@/,
        'and the lease on the stored object is still a\'s';

    eval { $nb->_acquire_lease };
    like $@, qr/lease held by another reconciler/, 'b taking the lease meanwhile steps aside, it does not overwrite';

    $na->_release_lease;
    my $free = $api->k8s->object_to_struct($api->get('OCPNode', $NAME, namespace => $NS));
    ok !exists(($free->{metadata}{annotations} // {})->{'ocp.internal/reconciler-lease'}),
        'a releases it';
}

# --- 2: two reconcilers racing for it: exactly one wins ---------------------

my (%outcome, $rounds_ok);
for my $round (1 .. $ROUNDS) {
    my $start = Time::HiRes::time() + 1.5;   # both children fire together
    my @kids;
    for my $id (qw(smoke-a smoke-b)) {
        pipe(my $r, my $w) or die "pipe: $!";
        my $pid = fork // die "fork: $!";
        if (!$pid) {
            close $r;
            my $result = eval {
                my $child_api = client();          # its own connection, built after the fork
                my $node      = node_for($child_api, $id);
                my $wait      = $start - Time::HiRes::time();
                Time::HiRes::sleep($wait) if $wait > 0;
                $node->_acquire_lease;
                'won';
            } // do { my $e = $@; $e =~ s/\s+\z//; "lost: $e" };
            print {$w} JSON::MaybeXS->new->encode({ id => $id, result => $result });
            close $w;
            exit 0;
        }
        close $w;
        push @kids, [ $pid, $r ];
    }
    my @results;
    for my $k (@kids) {
        my ($pid, $r) = @$k;
        my $json = do { local $/; <$r> };
        waitpid $pid, 0;
        push @results, $json ? JSON::MaybeXS->new->decode($json) : { id => '?', result => 'lost: no answer' };
    }

    my @won  = grep { $_->{result} eq 'won' } @results;
    my @lost = grep { $_->{result} ne 'won' } @results;
    my $good = @won == 1 && @lost == 1 && $lost[0]{result} =~ /lease held by another reconciler/;
    $rounds_ok++ if $good;
    $outcome{ $lost[0]{result} =~ /\(409\)/ ? '409 on write' : 'lease seen live' }++ if @lost == 1;
    diag "round $round: " . join('; ', map { "$_->{id}: $_->{result}" } @results) unless $good;

    # Hand the lease back for the next round (whoever won).
    my $holder = ($won[0] // {})->{id};
    node_for($api, $holder // 'smoke-a')->_release_lease;
}
is $rounds_ok, $ROUNDS, "in all $ROUNDS races exactly one reconciler won, the other was told the lease is held";
diag 'losers: ' . join(', ', map { "$outcome{$_}x $_" } sort keys %outcome);

# --- cleanup ---------------------------------------------------------------

$cleanup->();
my $gone = eval { $api->get('OCPNode', $NAME, namespace => $NS); 1 };
ok !$gone && $@ =~ /\b404\b/, 'the test OCPNode is deleted';

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use MIME::Base64 qw( encode_base64 );

use lib 'lib';
use OCP::Node;
use OCP::KnownHosts;
use OCP::K8s;

#
# k239 (lab round 10, note 45): robocop's pinning of a Ready node without
# status.hostKeys (k235, _pin_unpinned) failed silently when the scan found
# nothing or the cluster could not resolve the name. Now:
#   - phase stays Ready, status.message becomes
#       'Node joined and Ready; host key not pinned: <reason>'
#     (an unresolvable name carries robocop's k240 wording as the reason),
#   - a warning (warn -> STDERR, robocop's log) says it,
#   - nothing lands in status.hostKeys,
#   - the next reconcile tries again; on success the pins are written and the
#     message is 'Node joined and Ready' again.
# A control plane is still neither pinned nor warned about, a node with pins
# costs no scan. ssh-keyscan is the seam OCP::Node::_scan_host_keys.
#

sub blob { my $c = shift; encode_base64(pack('N', 11) . 'ssh-ed25519' . pack('N', 32) . ($c x 32), '') }
my $ED = blob('a');

my @patches;
my @scans;
{
    no warnings 'redefine';
    *OCP::K8s::patch_status = sub { my ($c, $api, %a) = @_; push @patches, $a{status}; 1 };
    *OCP::KnownHosts::scan  = sub { () };
}
sub patched { my %m; for my $p (@patches) { $m{$_} = $p->{$_} for keys %$p } \%m }

{ package FakeIO; sub new { bless {}, shift } sub object_to_struct { $_[1] } }
{
    package FakeK8s;
    sub new { bless {}, shift }
    sub k8s { FakeIO->new }
    sub get {
        my ($s, $kind, @a) = @_;
        my $name = @a % 2 ? shift @a : { @a }->{name};
        die "404\n" unless $kind eq 'Node';
        return { metadata => { name => $name },
                 status   => { conditions => [ { type => 'Ready', status => 'True' } ] } };
    }
}

sub node {
    my (%o) = @_;
    @patches = (); @scans = ();
    return OCP::Node->from_cr({
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => ($o{role} // 'worker'), host => 'crag.lab' },
        status   => { phase => 'Ready', publicIP => 'crag.lab', message => 'Node joined and Ready',
                      %{ $o{status} // {} } },
    }, k8s => FakeK8s->new, reconciler_id => 'robocop@robocop-abc');
}

# $scan: coderef(host) returning the keys or dying. Returns the warnings.
sub reconcile_with {
    my ($n, $scan) = @_;
    my @warns;
    no warnings 'redefine';
    local *OCP::Node::_scan_host_keys = sub { push @scans, $_[1]; $scan->($_[1]) };
    local $SIG{__WARN__} = sub { push @warns, @_ };
    open my $efh, '>', \my $err or die;
    local *STDERR = $efh;
    is $n->reconcile, 1, 'reconcile goes through as Ready';
    return @warns;
}

my $RESOLVER = "Could not resolve hostname crag.lab: Name or service not known\n";

subtest 'scan dies with a resolver text: Ready kept, message + warning, no pins, retried' => sub {
    my $n = node();
    my @warns = reconcile_with($n, sub { die $RESOLVER });

    my $p = patched();
    isnt $p->{phase}, 'Failed', 'not Failed';
    is $n->phase, 'Ready', 'phase stays Ready';
    ok !exists $p->{hostKeys}, 'no hostKeys patched';
    like $p->{message}, qr/\ANode joined and Ready; host key not pinned: /, 'message carries the suffix';
    like $p->{message}, qr/Name 'crag\.lab' does not resolve/, 'with the unresolved-name wording';
    like $p->{message}, qr/CoreDNS|cluster DNS/, 'in its robocop form (k240)';
    unlike $p->{message}, qr/this machine|\/etc\/hosts/, 'not the CLI form';
    ok scalar(grep { /not pinned/ && /crag\.lab|w1/ } @warns), 'a warning names it'
        or diag explain \@warns;
    is_deeply \@scans, ['crag.lab'], 'one scan so far';

    # next resync: the cluster resolves now
    @patches = (); @scans = ();
    reconcile_with($n, sub { +{ type => 'ssh-ed25519', key => $ED } });
    is_deeply \@scans, ['crag.lab'], 'the next reconcile scans again';
    my $q = patched();
    is scalar(@{ $q->{hostKeys} // [] }), 1, 'pins written on success';
    is $q->{hostKeys}[0]{key}, $ED, 'the scanned key';
    is $q->{message}, 'Node joined and Ready', 'message back to plain, no suffix';
    is $n->phase, 'Ready', 'Ready';
};

subtest 'scan finds nothing (no error text): reason is ssh-keyscan found no host key' => sub {
    my $n = node();
    my @warns = reconcile_with($n, sub { () });
    my $p = patched();
    is $p->{message}, 'Node joined and Ready; host key not pinned: ssh-keyscan found no host key', 'exact message';
    ok !exists $p->{hostKeys}, 'no hostKeys';
    ok scalar(grep { /not pinned/ } @warns), 'warned';
    is $n->phase, 'Ready', 'Ready';
};

subtest 'scan dies with another text: that text is the reason' => sub {
    my $n = node();
    my @warns = reconcile_with($n, sub { die "connect to host crag.lab port 22: Connection refused\n" });
    like patched()->{message},
        qr/\ANode joined and Ready; host key not pinned: .*Connection refused/, 'reason in message';
    ok scalar(grep { /Connection refused/ } @warns), 'and in the warning';
};

subtest 'a control plane is neither pinned nor warned about' => sub {
    my $n = node(role => 'control-plane');
    my @warns = reconcile_with($n, sub { die $RESOLVER });
    is_deeply \@scans, [], 'no scan';
    ok !exists patched()->{hostKeys}, 'no pins';
    unlike patched()->{message} // '', qr/not pinned/, 'no message';
    ok !(grep { /not pinned/ } @warns), 'no warning';
};

subtest 'a node with pins costs no scan and says nothing' => sub {
    my $n = node(status => { hostKeys => [ { type => 'ssh-ed25519', key => $ED, fingerprint => 'SHA256:x' } ] });
    my @warns = reconcile_with($n, sub { die $RESOLVER });
    is_deeply \@scans, [], 'no scan';
    unlike patched()->{message} // '', qr/not pinned/, 'no message';
    ok !(grep { /not pinned/ } @warns), 'no warning';
};

# Lab finding on k239: robocop noted the unpinned key, then the CLI pinned it
# (TOFU via `ocp ssh --node crag`). _pin_unpinned returns early on pins, and
# only robocop's own successful pin cleared the note -- so status.message kept
# saying "host key not pinned" next to three pins. A node with pins clears that
# note (and only that note), once.
my $PINS = [ { type => 'ssh-ed25519', key => $ED, fingerprint => 'SHA256:x' } ];
my $NOTE = "Node joined and Ready; host key not pinned: Name 'crag.lab' does not resolve: the lookup failed inside the cluster";

subtest 'pinned elsewhere: a stale "not pinned" note clears, once, without a scan' => sub {
    my $n = node(status => { hostKeys => $PINS, message => $NOTE });
    my @warns = reconcile_with($n, sub { die $RESOLVER });
    is_deeply \@scans, [], 'no scan';
    my $p = patched();
    is $p->{message}, 'Node joined and Ready', 'note cleared';
    ok !exists $p->{hostKeys}, 'pins not rewritten';
    ok !(grep { /not pinned/ } @warns), 'no warning';
    is $n->phase, 'Ready', 'Ready';

    # next resync: nothing left to clear, nothing written
    my $m = node(status => { hostKeys => $PINS, message => 'Node joined and Ready' });
    reconcile_with($m, sub { die $RESOLVER });
    ok !exists patched()->{message}, 'plain message: no write per resync';
};

subtest 'pinned: any other message is left alone' => sub {
    my $n = node(status => { hostKeys => $PINS, message => 'Rex task failed: something earlier' });
    reconcile_with($n, sub { die $RESOLVER });
    ok !exists patched()->{message}, 'not touched';
};

subtest 'a control plane with pins and the note: untouched (k235 skip)' => sub {
    my $n = node(role => 'control-plane', status => { hostKeys => $PINS, message => $NOTE });
    reconcile_with($n, sub { die $RESOLVER });
    is_deeply \@scans, [], 'no scan';
    ok !exists patched()->{message}, 'message not touched';
};

done_testing;

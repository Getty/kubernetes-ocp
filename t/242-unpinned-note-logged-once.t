#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use MIME::Base64 qw( encode_base64 );

use lib 'lib';
use OCP::Node;
use OCP::KnownHosts;
use OCP::K8s;
use OCP::Provider;
use OCP::Robocop::Controller;

#
# k242: robocop re-warned "host key of NAME (HOST) not pinned: REASON" on every
# resync -- the same line, no timestamp -- because OCP::Node::_note_unpinned
# warned unconditionally. A robocop reconcile runs in a forked child, so an
# in-memory "already said" does not survive; the dedup rides on the message
# that is already patched only on change: status.message.
#   - OCP::Node takes an optional `logger` coderef, called ($level, $msg) with
#     level 'warn' or 'info'. Set: the line goes there. Unset: plain warn (CLI).
#   - The not-pinned warning is emitted only when status.message is not yet
#     exactly 'Node joined and Ready; host key not pinned: <reason>' (first
#     time, or the reason changed).
#   - Once pinned again (scan succeeded after a note, or pinned elsewhere and
#     the note cleared) one info line; without a prior note none.
#   - status.message behaves as before.
#   - OCP::Robocop::Controller hands OCP::Node->from_cr a logger that goes
#     through log / log_error, so the line carries the '[<ts>] ' prefix.
#

sub blob { my $c = shift; encode_base64(pack('N', 11) . 'ssh-ed25519' . pack('N', 32) . ($c x 32), '') }
my $ED = blob('a');

my @patches;
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

my @log;    # [level, msg] seen by the logger
sub node {
    my (%o) = @_;
    @patches = (); @log = ();
    return OCP::Node->from_cr({
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => 'crag.lab' },
        status   => { phase => 'Ready', publicIP => 'crag.lab', message => 'Node joined and Ready',
                      %{ $o{status} // {} } },
    }, k8s => FakeK8s->new, reconciler_id => 'robocop@robocop-abc',
       ($o{logger} ? (logger => sub { push @log, [ @_ ] }) : ()));
}

# Returns the plain warnings (the ones that did not go through a logger).
sub reconcile_with {
    my ($n, $scan) = @_;
    my @warns;
    no warnings 'redefine';
    local *OCP::Node::_scan_host_keys = sub { $scan->($_[1]) };
    local $SIG{__WARN__} = sub { push @warns, @_ };
    open my $efh, '>', \my $err or die;
    local *STDERR = $efh;
    is $n->reconcile, 1, 'reconcile goes through as Ready';
    return @warns;
}

sub lines { my $lvl = shift; grep { $_->[0] eq $lvl } @log }

my $RESOLVER = "Could not resolve hostname crag.lab: Name or service not known\n";
my $REFUSED  = "connect to host crag.lab port 22: Connection refused\n";
my $PREFIX   = 'Node joined and Ready; host key not pinned: ';
my $PINS     = [ { type => 'ssh-ed25519', key => $ED, fingerprint => 'SHA256:x' } ];

subtest 'with a logger the not-pinned line goes there, not to warn' => sub {
    my $n = node(logger => 1);
    my @warns = reconcile_with($n, sub { die $REFUSED });
    my @w = lines('warn');
    is scalar(@w), 1, 'one line at level warn' or diag explain \@log;
    like $w[0][1] // '', qr/host key of w1 \(crag\.lab\) not pinned: .*Connection refused/, 'the usual wording';
    unlike $w[0][1] // '', qr/\A\[/, 'no timestamp of its own (the controller adds it)';
    ok !(grep { /not pinned/ } @warns), 'nothing went to warn()';
    like patched()->{message}, qr/\Q$PREFIX\E.*Connection refused/, 'status.message unchanged in behavior';
};

subtest 'without a logger the line is a plain warn, as before (CLI)' => sub {
    my $n = node();
    my @warns = reconcile_with($n, sub { die $REFUSED });
    ok scalar(grep { /host key of w1 \(crag\.lab\) not pinned: .*Connection refused/ } @warns), 'warned'
        or diag explain \@warns;
};

subtest 'same failure on the next reconcile (message already patched): one warning in total' => sub {
    my $first = node(logger => 1);
    reconcile_with($first, sub { die $REFUSED });
    is scalar(lines('warn')), 1, 'first reconcile warns';
    my $msg = patched()->{message};
    like $msg, qr/\A\Q$PREFIX\E/, 'a note was patched';

    # robocop forks per reconcile: a fresh Node, seeing only the CR's status
    my @first_log = @log;
    my $second = node(logger => 1, status => { message => $msg });
    reconcile_with($second, sub { die $REFUSED });
    is scalar(lines('warn')), 0, 'second reconcile, same reason: no warning' or diag explain \@log;
    ok !exists patched()->{message}, 'and no write per resync (unchanged)';
    is scalar(@first_log) + scalar(@log), 1, 'one line across both';
};

subtest 'same dedup without a logger (warn path)' => sub {
    my $first = node();
    my @w1 = reconcile_with($first, sub { die $REFUSED });
    my $msg = patched()->{message};
    my $second = node(status => { message => $msg });
    my @w2 = reconcile_with($second, sub { die $REFUSED });
    is scalar(grep { /not pinned/ } @w1), 1, 'first warns';
    is scalar(grep { /not pinned/ } @w2), 0, 'second stays quiet';
};

subtest 'a changed reason warns again and patches' => sub {
    my $first = node(logger => 1);
    reconcile_with($first, sub { die $REFUSED });
    my $msg = patched()->{message};

    my $second = node(logger => 1, status => { message => $msg });
    reconcile_with($second, sub { die $RESOLVER });
    my @w = lines('warn');
    is scalar(@w), 1, 'new reason, new warning' or diag explain \@log;
    like patched()->{message}, qr/\A\Q$PREFIX\E.*(?:does not resolve|CoreDNS|cluster DNS)/, 'and the new message is written';
    isnt patched()->{message}, $msg, 'different from the old one';
};

subtest 'a message that merely starts like the note is not a match' => sub {
    my $n = node(logger => 1, status => { message => $PREFIX . 'something else entirely' });
    reconcile_with($n, sub { die $REFUSED });
    is scalar(lines('warn')), 1, 'different reason: warned';
};

subtest 'pinned after a note (scan succeeds): one info line, message cleared' => sub {
    my $msg = $PREFIX . 'ssh-keyscan found no host key';
    my $n = node(logger => 1, status => { message => $msg });
    reconcile_with($n, sub { +{ type => 'ssh-ed25519', key => $ED } });
    my @i = lines('info');
    is scalar(@i), 1, 'one info line' or diag explain \@log;
    like $i[0][1] // '', qr/host key of w1\b.*\bpinned/, 'says it is pinned now';
    unlike $i[0][1] // '', qr/not pinned/, 'not the warning';
    is scalar(lines('warn')), 0, 'no warning';
    is patched()->{message}, 'Node joined and Ready', 'message back to plain';
    is scalar(@{ patched()->{hostKeys} // [] }), 1, 'pins written';
};

subtest 'pinned without any earlier note: no info line' => sub {
    my $n = node(logger => 1);
    reconcile_with($n, sub { +{ type => 'ssh-ed25519', key => $ED } });
    is scalar(@log), 0, 'silent logger' or diag explain \@log;
    is scalar(@{ patched()->{hostKeys} // [] }), 1, 'pins still written';
};

subtest 'pinned elsewhere, note cleared: one info line; none without a note' => sub {
    my $n = node(logger => 1, status => { hostKeys => $PINS, message => $PREFIX . 'Name nope' });
    reconcile_with($n, sub { die $RESOLVER });
    my @i = lines('info');
    is scalar(@i), 1, 'one info line' or diag explain \@log;
    like $i[0][1] // '', qr/host key of w1\b.*\bpinned/, 'says it is pinned';
    is patched()->{message}, 'Node joined and Ready', 'note cleared';

    my $m = node(logger => 1, status => { hostKeys => $PINS });
    reconcile_with($m, sub { die $RESOLVER });
    is scalar(@log), 0, 'plain message and pins: no line at all';
};

#
# The controller: the logger it hands OCP::Node->from_cr goes through its own
# log / log_error, i.e. with the '[<ts>] ' prefix. Both from_cr sites.
#
{
    package FakeApi;
    sub new  { bless {}, shift }
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }
    sub patch_status { 1 }
    sub patch { 1 }
    sub get {
        my ($self, $kind, @rest) = @_;
        return { apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
                 metadata => { name => 'ssh-default', namespace => 'ocp-system' },
                 spec => { type => 'ssh' } } if $kind eq 'OCPNodeProvider';
        return undef;
    }
    package FakeNode;
    sub reconcile { 1 }
    sub teardown { 1 }
    sub phase { 'Ready' }
    sub name  { 'w1' }
    sub cr    { { status => {} } }
    sub lease_conflict { undef }
    sub host_key_mismatch { undef }
}

sub controller_logger {
    my ($run) = @_;
    my @deps;
    no warnings 'redefine';
    local *OCP::Node::from_cr     = sub { my ($c, $cr, %d) = @_; push @deps, \%d; bless {}, 'FakeNode' };
    local *OCP::Provider::from_cr = sub { bless {}, 'FakeProvider' };
    my ($out, $err) = ('', '');
    {
        open my $ofh, '>', \$out or die;
        open my $efh, '>', \$err or die;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $run->();
    }
    return $deps[0]{logger};
}

sub ctrl {
    OCP::Robocop::Controller->new(
        ssh_key => 'K', server_url => 'U', join_token => 'T',
        distribution => 'rke2', pod_cidr => '10.42.0.0/16', kube => FakeApi->new,
    );
}

sub emitted {
    my ($logger, $level, $msg) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $logger->($level, $msg);
    }
    return ($out, $err);
}

my @sites = (
    [ 'event path (_on_node_event)' => sub {
        ctrl()->_on_node_event({ apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => 'w1', namespace => 'ocp-system', resourceVersion => '1',
                          finalizers => [ OCP::Node::TEARDOWN_FINALIZER ] },
            spec => { role => 'worker', providerRef => 'ssh-default' },
            status => { phase => 'Ready' } });
    } ],
    [ 'teardown path (_on_node_deleted)' => sub {
        ctrl()->_on_node_deleted({ apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => 'w1', namespace => 'ocp-system', resourceVersion => '1',
                          deletionTimestamp => '2026-10-19T10:00:00Z',
                          finalizers => [ OCP::Node::TEARDOWN_FINALIZER ] },
            spec => { role => 'worker', providerRef => 'ssh-default' },
            status => { phase => 'Ready' } });
    } ],
);

for my $site (@sites) {
    my ($label, $run) = @$site;
    subtest "controller hands a timestamping logger to Node->from_cr: $label" => sub {
        my $logger = controller_logger($run);
        is ref($logger), 'CODE', 'a logger coderef is passed' or return;

        my ($out, $err) = emitted($logger, 'info', 'host key of w1 (crag.lab) pinned');
        like $out, qr/\A\[[^\]]+\] host key of w1 \(crag\.lab\) pinned\n\z/, 'info: STDOUT, [ts] prefix';
        is $err, '', 'info: nothing on STDERR';

        ($out, $err) = emitted($logger, 'warn', 'host key of w1 (crag.lab) not pinned: nope');
        like $err, qr/\A\[[^\]]+\] host key of w1 \(crag\.lab\) not pinned: nope\n\z/, 'warn: STDERR, [ts] prefix';
        is $out, '', 'warn: nothing on STDOUT';
    };
}

done_testing;

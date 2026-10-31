#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use MIME::Base64 qw( encode_base64 );
use Storable qw( dclone );

use lib 'lib';
use OCP::Choices;
use OCP::K8s;
use OCP::KnownHosts;
use OCP::Node;
use OCP::Versions;

#
# k254, the state machine's part. Live, 2026-10-31: synapse (192.168.0.165 on
# the default route, 10.230.30.50 on the cluster VLAN) joined amdlab by
# 10.230.30.50 and registered 192.168.0.165 as its InternalIP; its control
# plane could not reach that, Cilium's tunnel broke, and the node showed
# Ready while OCP reported success.
#
#   - OCPNode spec.nodeIP is checked with OCP::Choices::node_ip_error by
#     reconcile, ahead of the dispatch, for Pending/Provisioning/Installing:
#     invalid -> Failed 'spec.nodeIP: <why>', no server ordered, no lease, no
#     SSH, no Rex. A Joining or Ready node is not failed for it. Valid -> the
#     install task gets node_ip, and the Joining write records it as
#     status.nodeIP. Absent -> no node_ip at all (no default).
#   - OCP::Node->node_ip_mismatch($node_hash, $node_ip): pure, undef when every
#     part of the node-ip is an InternalIP of the Node, else one line.
#   - At the Ready transition a mismatch with status.nodeIP is warned about
#     once (logger or warn) and kept in status.message:
#     'Node joined and Ready; <diag>'.
#   - The host-key note (k239/k242) shares that message; noting or clearing
#     it keeps the node-ip note in front of it.
#

my @patches;
{
    no warnings 'redefine', 'once';
    *OCP::K8s::patch_status = sub { my ($c, $api, %a) = @_; push @patches, $a{status}; 1 };
    *OCP::KnownHosts::scan  = sub { () };
    *OCP::Versions::get_component_version = sub { 'v9.9.9' };
}
sub patched { my %m; for my $p (@patches) { $m{$_} = $p->{$_} for keys %$p } \%m }

{
    package FakeRex;
    our @calls;
    our $fail;
    sub new      { bless {}, shift }
    sub run_task { my ($s, $task, %p) = @_; push @calls, [ $task, \%p ]; die $fail if $fail; 1 }
}
{
    package FakeSSH;
    our $made = 0;
    sub new          { $made++; bless {}, shift }
    sub wait_for_ssh { 1 }
}
{ package FakeIO; sub new { bless {}, shift } sub object_to_struct { $_[1] } }
{
    package FakeK8s;
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub k8s { FakeIO->new }
    sub get {
        my ($s, $kind, @a) = @_;
        my $name = @a % 2 ? shift @a : { @a }->{name};
        die "404\n" unless $kind eq 'Node';
        return { metadata => { name => $name },
                 status   => { conditions => [ { type => 'Ready', status => 'True' } ],
                               addresses  => $s->{addresses} // [] } };
    }
}

#### Install: spec.nodeIP -> node_ip, status.nodeIP

sub install {
    my (%o) = @_;
    @patches = (); @FakeRex::calls = (); $FakeSSH::made = 0;
    local $FakeRex::fail = $o{fail};
    my $node = OCP::Node->from_cr({
            apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => 'synapse', namespace => 'ocp-system', resourceVersion => '1' },
            spec     => { role => $o{role} // 'worker', providerRef => 'ssh-default',
                          host => '10.230.30.50',
                          (exists $o{spec_ip} ? (nodeIP => $o{spec_ip}) : ()) },
            status   => { phase => 'Installing', publicIP => '10.230.30.50',
                          %{ $o{status} // {} } },
        },
        k8s => FakeK8s->new, ssh_key => 'KEY',
        server_url => 'https://otho:9345', join_token => 'TOKEN',
        distribution => $o{distribution} // 'rke2',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
    );
    $node->_install_kubernetes;
    return $FakeRex::calls[0];
}

subtest 'a valid spec.nodeIP goes to the install task and into status.nodeIP' => sub {
    my $call = install(spec_ip => '10.230.30.50');
    ok $call, 'the install ran' or return;
    is $call->[0], 'install_rke2_agent', 'as an agent';
    is $call->[1]{node_ip}, '10.230.30.50', 'node_ip handed over as written';
    is $patches[-1]{phase}, 'Joining', 'the node moves on to Joining';
    is $patches[-1]{nodeIP}, '10.230.30.50', 'status.nodeIP recorded with that write';
};

subtest 'dual-stack, a control plane and a k3s agent take it the same way' => sub {
    my $call = install(spec_ip => '10.230.30.50,fd00::50');
    is $call->[1]{node_ip}, '10.230.30.50,fd00::50', 'v4,v6 handed over as one string';
    is $patches[-1]{nodeIP}, '10.230.30.50,fd00::50', 'and recorded as such';

    $call = install(spec_ip => '10.230.30.51', role => 'control-plane');
    is $call->[0], 'install_rke2_server', 'a control plane joins as a server';
    is $call->[1]{node_ip}, '10.230.30.51', 'with its node_ip';

    $call = install(spec_ip => '10.230.30.52', distribution => 'k3s');
    is $call->[0], 'install_k3s_agent', 'a k3s agent';
    is $call->[1]{node_ip}, '10.230.30.52', 'with its node_ip';
};

{
    package FakeProvider;
    our @created;
    sub new           { bless {}, shift }
    sub create_server { my ($s, %a) = @_; push @created, \%a; +{ id => 'srv-1', ip => '10.230.30.50' } }
}

# Through reconcile, the way robocop and `ocp node add` drive a node: the check
# has to come before the first step that costs -- for a Pending node that is
# the server order, not the install.
my $leases;
sub reconcile_in {
    my ($phase, $spec_ip) = @_;
    @patches = (); @FakeRex::calls = (); @FakeProvider::created = (); $FakeSSH::made = 0;
    $leases = 0;
    no warnings 'redefine';
    local *OCP::Node::_acquire_lease = sub { $leases++; 1 };
    local *OCP::Node::_release_lease = sub { 1 };
    my $node = OCP::Node->from_cr({
            apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => 'synapse', namespace => 'ocp-system', resourceVersion => '1' },
            spec     => { role => 'worker', providerRef => 'hetzner-default',
                          (defined $spec_ip ? (nodeIP => $spec_ip) : ()) },
            status   => { phase => $phase,
                          ($phase eq 'Pending' ? () : (publicIP => '10.230.30.50')) },
        },
        k8s => FakeK8s->new, provider => FakeProvider->new, ssh_key => 'KEY',
        server_url => 'https://otho:9345', join_token => 'TOKEN', distribution => 'rke2',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
    );
    return $node->reconcile;
}

subtest 'through reconcile, a valid spec.nodeIP provisions and installs as before' => sub {
    is reconcile_in(Pending => '10.230.30.50'), 1, 'Pending: reconcile goes through';
    is scalar(@FakeProvider::created), 1, 'a server is ordered';
    is $patches[-1]{phase}, 'Installing', 'and the node moves on';

    is reconcile_in(Installing => '10.230.30.50'), 1, 'Installing: reconcile goes through';
    is $FakeRex::calls[0][1]{node_ip}, '10.230.30.50', 'the install is handed the node-ip';
    is $patches[-1]{phase}, 'Joining', 'Joining';
};

subtest 'an invalid spec.nodeIP fails the node before a server is ordered or anything is touched' => sub {
    for my $phase (qw( Pending Provisioning Installing )) {
        for my $bad ('10.230.30.50/24', 'synapse.lab', '127.0.0.1', '', '10.0.0.1, fd00::1') {
            my $at = "$phase, '$bad'";
            is reconcile_in($phase => $bad), 0, "$at: reconcile reports nothing done";
            is scalar(@FakeProvider::created), 0, "$at: no server ordered";
            is $leases, 0, "$at: no lease taken";
            is $FakeSSH::made, 0, "$at: no SSH contact set up";
            is scalar(@FakeRex::calls), 0, "$at: no install task";
            is scalar(@patches), 1, "$at: one status write" or diag explain \@patches;
            is $patches[0]{phase}, 'Failed', "$at: the node is Failed";
            is $patches[0]{message}, 'spec.nodeIP: ' . OCP::Choices::node_ip_error($bad),
                "$at: the validator's line, prefixed spec.nodeIP";
            ok !exists $patches[0]{nodeIP}, "$at: no status.nodeIP";
        }
    }
};

subtest 'no spec.nodeIP: no node_ip, no status.nodeIP -- nothing is guessed' => sub {
    my $call = install();
    ok $call, 'the install ran' or return;
    ok !exists $call->[1]{node_ip}, 'no node_ip parameter at all';
    is $patches[-1]{phase}, 'Joining', 'Joining';
    ok !exists $patches[-1]{nodeIP}, 'and status.nodeIP is not written';
};

subtest 'an install handed none removes a status.nodeIP an earlier one left' => sub {
    install(status => { nodeIP => '10.230.30.50' });
    is $patches[-1]{phase}, 'Joining', 'Joining';
    ok exists $patches[-1]{nodeIP} && !defined $patches[-1]{nodeIP},
        'nodeIP => undef (null in the merge patch: deleted)';

    install(spec_ip => '10.230.30.60', status => { nodeIP => '10.230.30.50' });
    is $patches[-1]{nodeIP}, '10.230.30.60', 'one handed a new value records that';
};

subtest 'a failed install records no status.nodeIP' => sub {
    my $call = install(spec_ip => '10.230.30.50', fail => "rex blew up\n");
    ok $call, 'the task was run';
    is $patches[-1]{phase}, 'Failed', 'Failed';
    ok !exists $patches[-1]{nodeIP}, 'nothing claims an install that did not finish';
};

#### node_ip_mismatch

sub k8s_node { +{ metadata => { name => 'synapse' }, status => { addresses => [ @_ ] } } }
sub addr     { +{ type => $_[0], address => $_[1] } }

# The way out every diagnosis ends with: rejoin with the node-ip, then restart
# the Cilium agent pod (CiliumNode keeps the old address until it does).
my $FIX = ' until it rejoins: re-run its install so config.yaml carries the node-ip '
        . 'and rke2/k3s restarts, then restart the Cilium agent pod on the node';

subtest 'node_ip_mismatch: nothing to compare is no mismatch' => sub {
    my $n = k8s_node(addr(InternalIP => '192.168.0.165'));
    is +OCP::Node->node_ip_mismatch($n, undef), undef, 'undef node-ip';
    is +OCP::Node->node_ip_mismatch($n, ''),    undef, 'empty node-ip';
};

subtest 'node_ip_mismatch: a match' => sub {
    my $n = k8s_node(addr(Hostname => 'synapse'), addr(InternalIP => '10.230.30.50'));
    is +OCP::Node->node_ip_mismatch($n, '10.230.30.50'), undef, 'IPv4';

    $n = k8s_node(addr(InternalIP => '10.230.30.50'), addr(InternalIP => 'fd00::50'));
    is +OCP::Node->node_ip_mismatch($n, '10.230.30.50,fd00::50'), undef, 'dual-stack, both there';
    is +OCP::Node->node_ip_mismatch($n, 'fd00::50,10.230.30.50'), undef, 'in either order';
    is +OCP::Node->node_ip_mismatch($n, 'FD00:0:0::50'), undef,
        'an IPv6 spelt otherwise is the same address';
};

subtest 'node_ip_mismatch: a mismatch, in one line without the node name' => sub {
    my $n = k8s_node(addr(Hostname => 'synapse'), addr(InternalIP => '192.168.0.165'));
    is +OCP::Node->node_ip_mismatch($n, '10.230.30.50'),
        'registered InternalIP 192.168.0.165, not the node-ip 10.230.30.50 it was installed with, and keeps that address' . $FIX,
        'synapse, as it happened';
    unlike +OCP::Node->node_ip_mismatch($n, '10.230.30.50'), qr/[;\n]/,
        'one line, and no ";" -- status.message separates its notes with "; "';

    $n = k8s_node(addr(InternalIP => '192.168.0.165'), addr(ExternalIP => '10.230.30.50'));
    is +OCP::Node->node_ip_mismatch($n, '10.230.30.50'),
        'registered InternalIP 192.168.0.165, not the node-ip 10.230.30.50 it was installed with, and keeps that address' . $FIX,
        'an ExternalIP of that address does not count';

    $n = k8s_node(addr(InternalIP => '192.168.0.165'), addr(InternalIP => 'fd00::1'));
    is +OCP::Node->node_ip_mismatch($n, '10.230.30.50'),
        'registered InternalIPs 192.168.0.165 and fd00::1, not the node-ip 10.230.30.50 it was installed with, and keeps those addresses' . $FIX,
        'several InternalIPs are all named';
};

subtest 'node_ip_mismatch: dual-stack, one part missing' => sub {
    my $n = k8s_node(addr(InternalIP => '10.230.30.50'));
    is +OCP::Node->node_ip_mismatch($n, '10.230.30.50,fd00::50'),
        'registered InternalIP 10.230.30.50, not the node-ip 10.230.30.50,fd00::50 it was installed with (fd00::50 missing), and keeps that address' . $FIX,
        'names the part that is missing';
};

subtest 'node_ip_mismatch: no InternalIP at all' => sub {
    my $want = 'registered no InternalIP, though it was installed with the node-ip 10.230.30.50, and has none' . $FIX;
    is +OCP::Node->node_ip_mismatch(k8s_node(addr(Hostname => 'synapse')), '10.230.30.50'), $want,
        'only a Hostname';
    is +OCP::Node->node_ip_mismatch({ metadata => {} }, '10.230.30.50'), $want, 'no status';
    is +OCP::Node->node_ip_mismatch(undef, '10.230.30.50'), $want, 'no Node hash';
    is +OCP::Node->node_ip_mismatch(k8s_node(addr(InternalIP => '')), '10.230.30.50'), $want,
        'an empty address is none';
};

subtest 'node_ip_mismatch is pure' => sub {
    my $n = k8s_node(addr(InternalIP => '192.168.0.165'));
    my $before = dclone($n);
    @patches = ();
    OCP::Node->node_ip_mismatch($n, '10.230.30.50') for 1 .. 2;
    is_deeply $n, $before, 'the Node hash is left as it was';
    is scalar(@patches), 0, 'nothing written';
};

#### The Ready transition

my @log;
sub joining_node {
    my (%o) = @_;
    @patches = (); @log = ();
    return OCP::Node->from_cr({
        metadata => { name => 'synapse', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => '10.230.30.50', %{ $o{spec} // {} } },
        status   => { phase => 'Joining', publicIP => '10.230.30.50',
                      message => 'RKE2 agent installed, waiting for node registration',
                      %{ $o{status} // {} } },
    }, k8s => FakeK8s->new(addresses => $o{addresses}),
       reconciler_id => 'robocop@robocop-abc',
       ($o{no_logger} ? () : (logger => sub { push @log, [ @_ ] })));
}
sub warns { grep { $_->[0] eq 'warn' } @log }

my $DIAG = 'registered InternalIP 192.168.0.165, not the node-ip 10.230.30.50 it was installed with, and keeps that address' . $FIX;
my @WRONG = (addr(Hostname => 'synapse'), addr(InternalIP => '192.168.0.165'));
my @RIGHT = (addr(Hostname => 'synapse'), addr(InternalIP => '10.230.30.50'));

subtest 'Ready at another address than status.nodeIP: warned, and kept in the message' => sub {
    my $n = joining_node(status => { nodeIP => '10.230.30.50' }, addresses => \@WRONG);
    ok $n->_wait_ready, 'the node is Ready all the same';
    is patched()->{phase}, 'Ready', 'phase Ready, not Failed: it did join';
    is patched()->{message}, "Node joined and Ready; $DIAG", 'the message carries the diagnosis';
    is_deeply [ warns() ], [ [ warn => "synapse: $DIAG" ] ], 'one warning, naming the node'
        or diag explain \@log;
};

subtest 'Ready where it was told to: plain message, no warning' => sub {
    my $n = joining_node(status => { nodeIP => '10.230.30.50' }, addresses => \@RIGHT);
    ok $n->_wait_ready, 'Ready';
    is patched()->{message}, 'Node joined and Ready', 'plain message';
    is scalar(@log), 0, 'nothing said';
};

subtest 'no status.nodeIP: no check, whatever it registered' => sub {
    my $n = joining_node(addresses => \@WRONG);
    ok $n->_wait_ready, 'Ready';
    is patched()->{message}, 'Node joined and Ready', 'plain message';
    is scalar(@log), 0, 'nothing said';
};

subtest 'said once: a message that already says it is not said again' => sub {
    my $n = joining_node(status => { nodeIP => '10.230.30.50',
                                     message => "Node joined and Ready; $DIAG" },
                         addresses => \@WRONG);
    ok $n->_wait_ready, 'Ready';
    is scalar(warns()), 0, 'no second warning' or diag explain \@log;
    is patched()->{message}, "Node joined and Ready; $DIAG", 'the message stays what it was';
};

subtest 'without a logger (the CLI) the warning is a plain warn' => sub {
    my $n = joining_node(status => { nodeIP => '10.230.30.50' }, addresses => \@WRONG,
                         no_logger => 1);
    my @w;
    local $SIG{__WARN__} = sub { push @w, @_ };
    ok $n->_wait_ready, 'Ready';
    is_deeply \@w, [ "[node] synapse: $DIAG\n" ], 'one line on STDERR, [node] prefixed';
};

#### Interplay with the host-key note (k239/k242)

sub blob { my $c = shift; encode_base64(pack('N', 11) . 'ssh-ed25519' . pack('N', 32) . ($c x 32), '') }
my $ED   = blob('a');
my $PINS = [ { type => 'ssh-ed25519', key => $ED, fingerprint => 'SHA256:x' } ];
my $IPNOTE  = "Node joined and Ready; $DIAG";
my $REFUSED = "connect to host 10.230.30.50 port 22: Connection refused\n";

sub ready_node {
    my (%o) = @_;
    @patches = (); @log = ();
    return OCP::Node->from_cr({
        metadata => { name => 'synapse', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => '10.230.30.50', %{ $o{spec} // {} } },
        status   => { phase => 'Ready', publicIP => '10.230.30.50', nodeIP => '10.230.30.50',
                      %{ $o{status} // {} } },
    }, k8s => FakeK8s->new(addresses => \@WRONG), reconciler_id => 'robocop@robocop-abc',
       logger => sub { push @log, [ @_ ] });
}

sub reconcile_with {
    my ($n, $scan) = @_;
    no warnings 'redefine';
    local *OCP::Node::_scan_host_keys = sub { $scan->($_[1]) };
    local $SIG{__WARN__} = sub { };
    open my $efh, '>', \my $err or die;
    local *STDERR = $efh;
    is $n->reconcile, 1, 'reconcile goes through as Ready';
}

subtest 'an unpinned host key is noted after the node-ip note, not instead of it' => sub {
    my $n = ready_node(status => { message => $IPNOTE });
    reconcile_with($n, sub { die $REFUSED });
    my $msg = patched()->{message} // '';
    like $msg, qr/\A\Q$IPNOTE\E; host key not pinned: .*Connection refused/,
        'both notes, the node-ip one first' or diag $msg;
    is scalar(warns()), 1, 'the host-key warning, once';
    unlike $log[0][1] // '', qr/node-ip/, 'and only that: the node-ip one was said at Ready';

    # robocop forks per reconcile: a fresh object from the stored message.
    my $again = ready_node(status => { message => $msg });
    reconcile_with($again, sub { die $REFUSED });
    ok !exists patched()->{message}, 'same failure again: no write' or diag explain \@patches;
    is scalar(@log), 0, 'and no warning';
};

subtest 'pinned after the note: the host-key part goes, the node-ip note stays' => sub {
    my $n = ready_node(status => { message => "$IPNOTE; host key not pinned: ssh-keyscan found no host key" });
    reconcile_with($n, sub { +{ type => 'ssh-ed25519', key => $ED } });
    is patched()->{message}, $IPNOTE, 'back to the node-ip note';
    is scalar(@{ patched()->{hostKeys} // [] }), 1, 'pins written';
    is scalar(grep { $_->[0] eq 'info' } @log), 1, 'one info line for the pin';
};

subtest 'pinned elsewhere after the note: the same' => sub {
    my $n = ready_node(status => { hostKeys => $PINS,
        message => "$IPNOTE; host key not pinned: ssh-keyscan found no host key" });
    reconcile_with($n, sub { die $REFUSED });
    is patched()->{message}, $IPNOTE, 'the host-key part cleared, the node-ip note kept';
};

subtest 'a node-ip note alone is not mistaken for a host-key note' => sub {
    my $n = ready_node(status => { hostKeys => $PINS, message => $IPNOTE });
    reconcile_with($n, sub { die $REFUSED });
    is scalar(@patches), 0, 'pinned node, node-ip note: nothing written' or diag explain \@patches;
    is scalar(@log), 0, 'nothing said';
};

subtest 'without a node-ip note the host-key note is as before' => sub {
    my $n = ready_node(status => { message => 'Node joined and Ready' });
    reconcile_with($n, sub { die $REFUSED });
    like patched()->{message} // '', qr/\ANode joined and Ready; host key not pinned: .*Connection refused/,
        'the k239 message';

    $n = ready_node(status => { message => 'something else entirely' });
    reconcile_with($n, sub { die $REFUSED });
    like patched()->{message} // '', qr/\ANode joined and Ready; host key not pinned: /,
        'a message that is no Ready line gives way, as it always did';
};

#### A node past its install is not failed for spec.nodeIP

subtest 'Joining or Ready: a spec.nodeIP edited since is not a reason to fail it' => sub {
    my $bad = { nodeIP => '10.230.30.50/24' };

    my $n = joining_node(spec => $bad, status => { nodeIP => '10.230.30.50' }, addresses => \@RIGHT);
    is $n->reconcile, 1, 'Joining: reconcile goes through';
    is patched()->{phase}, 'Ready', 'and the node is Ready, not Failed';

    $n = ready_node(spec => $bad, status => { hostKeys => $PINS, message => $IPNOTE });
    reconcile_with($n, sub { die $REFUSED });
    ok !grep({ ($_->{phase} // '') eq 'Failed' } @patches), 'Ready: not Failed either'
        or diag explain \@patches;
};

done_testing;

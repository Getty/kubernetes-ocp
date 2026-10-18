#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use MIME::Base64 qw( encode_base64 );
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';
use OCP::Node;
use OCP::KnownHosts;
use OCP::SSH;
use OCP::K8s;
use OCP::Config;
use OCP::Kubernetes;
use OCP::Secrets;
use OCP::Cmd::SSH;

#
# k235 (lab round 8, follow-up to k171): host-key pins for the nodes that
# already exist.
#
#   (a) a Ready worker without status.hostKeys is pinned on trust on first
#       use at the next reconcile -- never a node that has pins, never one
#       that is not Ready;
#   (b) `ocp ssh --node` verifies against the pins of the OCPNode, refuses a
#       changed key with the k171 message, and pins a worker that has none;
#   (c) `ocp node rm` (teardown) checks the host key before it takes the lease,
#       sets Terminating, cordons or drains: a changed key leaves the node as
#       it was.
#
# Network-free: ssh-keyscan is OCP::Node::_scan_host_keys, stubbed in every
# test; OCP::KnownHosts::scan is stubbed too, so that nothing can reach for
# a real scan whatever code path runs.
#

sub blob { my $c = shift; encode_base64(pack('N', 11) . 'ssh-ed25519' . pack('N', 32) . ($c x 32), '') }

my $fp  = OCP::KnownHosts->new(file => '/dev/null');
my $ED  = blob('a');
my $ED2 = blob('b');
my $ECDSA = encode_base64(pack('N', 19) . 'ecdsa-sha2-nistp256' . pack('N', 8) . 'zzzzzzzz', '');

my @patches;     # every status patch, in order
my @scans;       # hosts _scan_host_keys was asked about
{
    no warnings 'redefine';
    *OCP::K8s::patch_status = sub { my ($c, $api, %a) = @_; push @patches, $a{status}; 1 };
    *OCP::KnownHosts::scan  = sub { () };
}

# What the machine presents to a scan, per test.
my @MACHINE;
sub scan_stub { my $keys = shift; return sub { push @scans, $_[1]; @$keys } }

sub patched { my %m; for my $p (@patches) { $m{$_} = $p->{$_} for keys %$p } \%m }

sub pins { +[ { type => 'ssh-ed25519', key => $ED, fingerprint => $fp->fingerprint($ED) } ] }

{
    package FakeIO;
    sub new              { bless {}, shift }
    sub object_to_struct { $_[1] }
}

# The cluster as OCP::Node::_verify and _cordon use it.
{
    package FakeK8s;
    sub new { my ($c, %a) = @_; bless { calls => [], ready => 'True', %a }, $c }
    sub k8s { FakeIO->new }
    sub get {
        my ($s, $kind, @a) = @_;
        my $name = @a % 2 ? shift @a : { @a }->{name};     # get(Kind, name => ...) and get(Kind, $name, ...)
        push @{ $s->{calls} }, [ get => $kind, $name ];
        die "404 Not Found\n" if $s->{no_node} || $kind ne 'Node';
        return { metadata => { name => $name },
                 status   => { conditions => [ { type => 'Ready', status => $s->{ready} } ] } };
    }
}

{
    package FakeProvider;
    sub new { bless { calls => [], die_with => $_[1] }, $_[0] }
    sub delete_server {
        my ($s, @a) = @_;
        push @{ $s->{calls} }, [ delete_server => @a ];
        die $s->{die_with} if $s->{die_with};
        return 1;
    }
}

sub node {
    my (%o) = @_;
    @patches = (); @scans = ();
    my $cr = {
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => '10.0.0.9' },
        status   => { phase => 'Ready', publicIP => '10.0.0.9', %{ $o{status} // {} } },
    };
    return OCP::Node->from_cr($cr, k8s => ($o{k8s} // FakeK8s->new), ($o{provider} ? (provider => $o{provider}) : ()));
}

#
# (a) Bestandsnodes pinnen
#

subtest '(a) a Ready worker without pins is pinned on first use at the reconcile' => sub {
    my $n = node();
    my $spec_before = YAML::XS::Dump($n->cr->{spec});
    my $err = '';
    {
        no warnings 'redefine';
        local *OCP::Node::_scan_host_keys = scan_stub([
            { type => 'ssh-ed25519', key => $ED }, { type => 'ecdsa-sha2-nistp256', key => $ECDSA } ]);
        open my $efh, '>', \$err or die;
        local *STDERR = $efh;
        is $n->reconcile, 1, 'the reconcile of a Ready node goes through';
    }

    is_deeply \@scans, ['10.0.0.9'], 'one scan, of the node\'s address';
    my $keys = patched()->{hostKeys};
    is scalar(@{ $keys // [] }), 2, 'status.hostKeys patched with both offered types';
    is_deeply [ sort map { $_->{type} } @$keys ], [ 'ecdsa-sha2-nistp256', 'ssh-ed25519' ], 'by type';
    like $_->{fingerprint}, qr/\ASHA256:[A-Za-z0-9+\/]{43}\z/, 'SHA256 fingerprint' for @$keys;
    my ($ed) = grep { $_->{type} eq 'ssh-ed25519' } @$keys;
    is $ed->{key}, $ED, 'the key travels along (a known_hosts line is made of it)';
    is patched()->{phase}, undef, 'the phase is not touched';
    is YAML::XS::Dump($n->cr->{spec}), $spec_before, 'nothing lands in spec';
    like $err, qr/Trusted host key of 10\.0\.0\.9 \(w1\) on first contact/, 'said on STDERR';

    # The next reconcile of the same node: pins exist, so no traffic.
    @scans = ();
    {
        no warnings 'redefine';
        local *OCP::Node::_scan_host_keys = scan_stub([ { type => 'ssh-ed25519', key => $ED2 } ]);
        $n->reconcile;
    }
    is_deeply \@scans, [], 'a node that has pins now costs no scan';
};

subtest '(a) a Ready worker with pins is not scanned, not re-pinned' => sub {
    my $n = node(status => { hostKeys => pins() });
    {
        no warnings 'redefine';
        local *OCP::Node::_scan_host_keys = scan_stub([ { type => 'ssh-ed25519', key => $ED2 } ]);
        is $n->reconcile, 1, 'Ready';
    }
    is_deeply \@scans, [], 'no scan';
    ok !exists patched()->{hostKeys}, 'the pins are not overwritten';
    is $n->cr->{status}{hostKeys}[0]{key}, $ED, 'and still the first contact\'s';
};

subtest '(a) a node that is not Ready is not pinned' => sub {
    my $unready = node(k8s => FakeK8s->new(ready => 'False'));
    my $absent  = node(k8s => FakeK8s->new(no_node => 1));
    for my $case ([ 'Ready=False' => $unready ], [ 'no Kubernetes Node' => $absent ]) {
        my ($label, $n) = @$case;
        @patches = (); @scans = ();
        no warnings 'redefine';
        local *OCP::Node::_scan_host_keys = scan_stub([ { type => 'ssh-ed25519', key => $ED } ]);
        $n->reconcile;
        is_deeply \@scans, [], $label . ': no scan (a replaced machine\'s key is not one to learn)';
        ok !exists patched()->{hostKeys}, $label . ': nothing pinned';
    }
};

# k235 lab follow-up: the control plane stays unpinned, as k171 decided. The
# first robocop with k235 pinned the bootstrap CP's OCPNode (10-230-30-212)
# on its first reconcile; a worker beside it is still pinned.
subtest '(a) a Ready control plane without pins is not pinned; a worker still is' => sub {
    my $cp = node();
    $cp->cr->{metadata}{name} = 'cp1';
    $cp->cr->{spec}{role}     = 'control-plane';
    my $err = '';
    {
        no warnings 'redefine';
        local *OCP::Node::_scan_host_keys = scan_stub([ { type => 'ssh-ed25519', key => $ED } ]);
        open my $efh, '>', \$err or die;
        local *STDERR = $efh;
        is $cp->reconcile, 1, 'the control plane reconciles as Ready';
    }
    is_deeply \@scans, [], 'control plane: no scan';
    ok !exists patched()->{hostKeys}, 'control plane: no status.hostKeys patch';
    unlike $err, qr/Trusted host key/, 'control plane: nothing said about trusting a key';

    my $worker = node();
    {
        no warnings 'redefine';
        local *OCP::Node::_scan_host_keys = scan_stub([ { type => 'ssh-ed25519', key => $ED } ]);
        open my $efh, '>', \my $werr or die;
        local *STDERR = $efh;
        $worker->reconcile;
    }
    is_deeply \@scans, ['10.0.0.9'], 'worker: scanned';
    is scalar(@{ patched()->{hostKeys} // [] }), 1, 'worker: pinned';
};

subtest '(a) a scan that finds nothing pins nothing and does not fail the reconcile' => sub {
    my $n = node();
    {
        no warnings 'redefine';
        local *OCP::Node::_scan_host_keys = scan_stub([]);
        is $n->reconcile, 1, 'still Ready';
    }
    ok !exists patched()->{hostKeys}, 'no pins from nothing';
    isnt patched()->{phase}, 'Failed', 'not Failed';
};

#
# (b) ocp ssh --node
#

{
    package FakeList;
    sub new   { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]{items} }

    package FakeAPI;
    sub new { my ($c, %a) = @_; bless { ocpnodes => {}, %a }, $c }
    sub k8s          { FakeIO->new }
    sub resource_map { {} }
    sub get {
        my ($self, $kind, %args) = @_;
        return $self->{ocpnodes}{ $args{name} } // die "404 Not Found: $kind $args{name}\n"
            if $kind eq 'OCPNode';
        die "404 Not Found: $kind $args{name}\n";
    }
    sub list { FakeList->new([ values %{ $_[0]{ocpnodes} } ]) }
}

# OpenSSH's accept-new against the known_hosts file it is handed: records the
# machine's key when the file has none, refuses a different one.
{
    package FakeSSH;
    our @made;
    our $machine;           # the ed25519 key the machine presents
    our $reach = 1;         # whether the machine answers at all
    sub new { my ($c, %a) = @_; my $s = bless {%a, ran => []}, $c;
        # The file dies with the node object, so what it was seeded with is kept.
        $s->{seeded} = Path::Tiny::path($a{known_hosts})->slurp_utf8 if defined $a{known_hosts} && -f $a{known_hosts};
        push @made, $s; $s }
    sub run {
        my ($s, @cmd) = @_;
        push @{ $s->{ran} }, [@cmd];
        die "connection refused\n" unless $reach;
        my $kh = OCP::KnownHosts->new(file => $s->{known_hosts});
        my ($rec) = grep { $_->{type} eq 'ssh-ed25519' } $kh->entries($s->{host});
        unless ($rec) {
            $kh->ensure_dir;
            Path::Tiny::path($kh->file)->append_utf8("$s->{host} ssh-ed25519 $machine\n");
            return { exit => 0 };
        }
        die OCP::SSH::HostKeyChanged->new(host => $s->{host}, file => $kh->file, text => "changed\n")
            if $rec->{key} ne $machine;
        return { exit => 0 };
    }
    sub probe_rejected { OCP::SSH::probe_rejected(@_) }
    sub interactive  { my $s = shift; push @{ $s->{interactive} }, [@_]; 0 }
}

{
    package FakeKey;
    sub new            { bless {}, shift }
    sub path           { '/nonexistent/key' }
    sub describe       { 'fake key' }
    sub label          { 'the fake key' }
    sub origin         { 'bootstrap' }
    sub migration_hint { undef }
    package FakeOcp;
    sub new    { bless { config => $_[1] }, $_[0] }
    sub config { $_[0]{config} }
}

# Run `ocp ssh --node crag` as far as the connection, with the cluster API,
# the key and the SSH class faked. Returns { died, err, ssh }.
sub ocp_ssh {
    my ($cr, %o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('kubeconfig.yaml')->spew('x');
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({ name => 't', control_planes => { provider => 'hetzner' } }));

    @patches = (); @FakeSSH::made = ();
    $FakeSSH::machine = $o{machine} // $ED;
    $FakeSSH::reach   = $o{reach} // 1;
    my $api = FakeAPI->new(ocpnodes => { crag => $cr });

    my $err = '';
    my $died;
    {
        no warnings 'redefine';
        local *OCP::Cmd::SSH::_kubernetes = sub { OCP::Kubernetes->new(api => $api) };
        local *OCP::Cmd::SSH::cluster_ssh_key = sub { FakeKey->new };
        local *OCP::Secrets::ensure_age_key = sub { 1 };
        local *OCP::SSH::new = sub { shift; FakeSSH->new(@_) };
        local *OCP::Node::_scan_host_keys = scan_stub([ { type => 'ssh-ed25519', key => $ED } ]);
        open my $efh, '>', \$err or die;
        local *STDERR = $efh;
        my $cmd = OCP::Cmd::SSH->new(
            node => 'crag',
            command_chain => [ FakeOcp->new($dir->child('ocp.yaml')->stringify) ],
        );
        eval { $cmd->execute([ '--node', 'crag' ], []); 1 } or $died = $@;
    }
    return { died => $died, err => $err, ssh => $FakeSSH::made[0] };
}

sub crag_cr {
    my (%status) = @_;
    return { metadata => { name => 'crag', namespace => 'ocp-system' },
             spec     => { role => 'worker', host => 'crag.lab' },
             status   => { phase => 'Ready', publicIP => '10.230.30.54', %status } };
}

subtest '(b) ocp ssh --node verifies against the pins of the OCPNode' => sub {
    my $cr = crag_cr(hostKeys => [ { type => 'ssh-ed25519', key => $ED, fingerprint => $fp->fingerprint($ED) } ]);
    my $r = ocp_ssh($cr, machine => $ED);

    is $r->{died}, undef, 'the pinned key matches: no refusal' or diag $r->{died};
    my $ssh = $r->{ssh};
    ok $ssh, 'a connection was made';
    like $ssh->{known_hosts}, qr/ocp-node-known_hosts-/, 'to the node\'s own known_hosts, not the project\'s';
    like $ssh->{seeded}, qr/\A10\.230\.30\.54 ssh-ed25519 \Q$ED\E\n\z/,
        'which holds exactly the pins of the OCPNode';
    is_deeply $ssh->{ran}, [ ['true'] ], 'one batch-mode probe before the session';
    is_deeply $ssh->{interactive}, [ [] ], 'then the session is handed over';
    ok !exists patched()->{hostKeys}, 'the pins are left alone';
};

subtest '(b) a changed key aborts ocp ssh with the k171 message and the way out' => sub {
    my $cr = crag_cr(hostKeys => [ { type => 'ssh-ed25519', key => $ED, fingerprint => $fp->fingerprint($ED) } ]);
    my $r = ocp_ssh($cr, machine => $ED2);

    ok defined $r->{died}, 'ocp ssh dies';
    like $r->{died}, qr/\Ahost key of 10\.230\.30\.54 changed \(expected \Q@{[ $fp->fingerprint($ED) ]}\E \(ssh-ed25519\), got /,
        'with the changed-key message of k171, naming what was pinned';
    like $r->{died}, qr/refusing to touch the machine/, 'same words as every other refusal';
    like $r->{died}, qr/ocp node trust-host crag/, 'and the trust-host way out';
    ok !$r->{ssh}{interactive}, 'no session was handed over';
    ok !exists patched()->{hostKeys}, 'the pins are not overwritten by the contact';
};

subtest '(b) a worker without pins is pinned on the first ocp ssh' => sub {
    my $r = ocp_ssh(crag_cr(), machine => $ED);

    is $r->{died}, undef, 'goes through (trust on first use)' or diag $r->{died};
    my $keys = patched()->{hostKeys};
    is scalar(@{ $keys // [] }), 1, 'status.hostKeys patched';
    is $keys->[0]{type}, 'ssh-ed25519', 'the type the connection recorded';
    is $keys->[0]{key}, $ED, 'and its key';
    is $keys->[0]{fingerprint}, $fp->fingerprint($ED), 'with its fingerprint';
    is_deeply $r->{ssh}{interactive}, [ [] ], 'the session follows';
};

subtest '(b) a machine that does not answer is ssh\'s error, not a pin and not a verdict' => sub {
    my $r = ocp_ssh(crag_cr(), reach => 0);
    like $r->{died}, qr/connection refused/, 'the probe\'s own error is what dies';
    unlike $r->{died}, qr/host key/, 'not mistaken for a host-key problem';
    ok !exists patched()->{hostKeys}, 'nothing pinned';
};

#
# (c) node rm / teardown
#

subtest '(c) teardown with a changed key leaves the node exactly as it was' => sub {
    my $prov = FakeProvider->new;
    my $k8s  = FakeK8s->new;
    my $n    = node(status => { hostKeys => pins() }, provider => $prov, k8s => $k8s);
    my $status_before = YAML::XS::Dump($n->cr->{status});
    my %hit;

    {
        no warnings 'redefine';
        local *OCP::Node::_scan_host_keys = scan_stub([ { type => 'ssh-ed25519', key => $ED2 } ]);
        local *OCP::Node::_acquire_lease  = sub { $hit{lease}++; 1 };
        local *OCP::Node::_release_lease  = sub { $hit{release}++; 1 };
        local *OCP::Node::_cordon         = sub { $hit{cordon}++; 1 };
        local *OCP::Node::_drain          = sub { $hit{drain}++; 1 };
        ok !eval { $n->teardown; 1 }, 'teardown dies';
        my $want_old = $fp->fingerprint($ED);
        my $want_new = $fp->fingerprint($ED2);
        like $@, qr/\ATeardown of node w1 not done: host key of 10\.0\.0\.9 changed \(expected \Q$want_old\E \(ssh-ed25519\), got \Q$want_new\E/,
            'with the changed-key message';
        like $@, qr/ocp node trust-host w1/, 'and the way out';
    }

    is_deeply \@patches, [], 'not one status patch: no Terminating, no message, no Failed';
    is YAML::XS::Dump($n->cr->{status}), $status_before, 'the node\'s status is untouched, phase included';
    is $n->phase, 'Ready', 'phase stays Ready';
    is_deeply \%hit, {}, 'no lease, no cordon, no drain';
    is_deeply $prov->{calls}, [], 'the provider never touched the machine';
    is_deeply [ grep { $_->[0] ne 'get' } @{ $k8s->{calls} } ], [], 'nothing was done to the cluster';
    ok defined $n->host_key_mismatch, 'the caller can see why';
    ok !$n->machine_cleanup_failed, 'and --keep-machine is not the advice';
};

subtest '(c) a matching key lets the teardown proceed as before' => sub {
    my $prov = FakeProvider->new;
    my $n    = node(status => { hostKeys => pins() }, provider => $prov);
    my %hit;
    {
        no warnings 'redefine';
        local *OCP::Node::_scan_host_keys = scan_stub([ { type => 'ssh-ed25519', key => $ED } ]);
        local *OCP::Node::_acquire_lease  = sub { $hit{lease}++; 1 };
        local *OCP::Node::_release_lease  = sub { 1 };
        local *OCP::Node::_cordon         = sub { $hit{cordon}++; 0 };
        local *OCP::Node::_delete_object  = sub { 1 };
        local *OCP::Node::_put_cr         = sub { 1 };
        eval { $n->teardown };
    }
    ok $hit{lease}, 'the lease was taken';
    ok $hit{cordon}, 'the node was cordoned';
    is scalar(@{ $prov->{calls} }), 1, 'the provider was asked to delete';
    is patched()->{phase}, 'Terminating', 'phase went to Terminating';
};

subtest '(c) no pins and a keep_machine teardown are not checked' => sub {
    for my $case ([ 'no pins' => {}, 0 ], [ 'keep_machine' => { hostKeys => pins() }, 1 ]) {
        my ($label, $status, $keep) = @$case;
        my $prov = FakeProvider->new;
        my $n    = node(status => $status, provider => $prov);
        {
            no warnings 'redefine';
            local *OCP::Node::_scan_host_keys = scan_stub([ { type => 'ssh-ed25519', key => $ED2 } ]);
            local *OCP::Node::_acquire_lease  = sub { 1 };
            local *OCP::Node::_release_lease  = sub { 1 };
            local *OCP::Node::_cordon         = sub { 0 };
            local *OCP::Node::_delete_object  = sub { 1 };
            local *OCP::Node::_put_cr         = sub { 1 };
            eval { $n->teardown(keep_machine => $keep) };
        }
        is_deeply \@scans, [], $label . ': no pre-check scan';
        is patched()->{phase}, 'Terminating', $label . ': teardown went on';
    }
};

subtest '(c) fallback: a key that changes after the pre-check is still caught at the provider' => sub {
    # The scan sees nothing (no verdict), so the pre-check lets the teardown
    # start; the provider's own contact then meets the changed key.
    my $prov = FakeProvider->new(OCP::SSH::HostKeyChanged->new(host => '10.0.0.9', text => "changed\n"));
    my $n    = node(status => { hostKeys => pins() }, provider => $prov);
    my %hit;
    {
        no warnings 'redefine';
        local *OCP::Node::_scan_host_keys = scan_stub([]);
        local *OCP::Node::_acquire_lease  = sub { $hit{lease}++; 1 };
        local *OCP::Node::_release_lease  = sub { $hit{release}++; 1 };
        local *OCP::Node::_cordon         = sub { 0 };
        ok !eval { $n->teardown; 1 }, 'teardown dies';
        like $@, qr/\ATeardown of node w1 not done: host key of 10\.0\.0\.9 changed/, 'with the changed-key message';
        like $@, qr/ocp node trust-host w1/, 'and the way out';
    }
    is scalar(@{ $prov->{calls} }), 1, 'the provider was reached (the pre-check had no verdict)';
    ok $hit{lease} && $hit{release}, 'the lease was taken and given back';
    ok !(grep { ($_->{phase} // '') eq 'Failed' } @patches), 'phase is not Failed';
    like patched()->{message}, qr/host key of 10\.0\.0\.9 changed/, 'status.message names it (the k171 behaviour)';
    ok !$n->machine_cleanup_failed, 'and --keep-machine is not the advice';
};

done_testing;

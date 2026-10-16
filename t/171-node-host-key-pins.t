#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use MIME::Base64 qw( encode_base64 );
use Path::Tiny qw( path );

use lib 'lib';
use OCP::Node;
use OCP::KnownHosts;
use OCP::SSH;
use OCP::K8s;
use OCP::Cmd::Node::TrustHost;

#
# k171: the host keys of an OCPNode are pinned in status.hostKeys at the first
# contact and every later contact -- from the CLI or from any robocop pod --
# is verified against them (before, robocop trusted anew per pod, k168).
#
# Network-free. FakeSSH plays OpenSSH's accept-new against the known_hosts
# file OCP::Node hands it through OCP_KNOWN_HOSTS: it records the machine's
# key when the file holds none, and refuses a different one the way
# OCP::SSH does. ssh-keyscan is OCP::KnownHosts::scan, stubbed.
#

sub blob { my $c = shift; encode_base64(pack('N', 11) . 'ssh-ed25519' . pack('N', 32) . ($c x 32), '') }

my $fp = OCP::KnownHosts->new(file => '/dev/null');
my $ED   = blob('a');
my $ED2  = blob('b');
my $ECDSA = encode_base64(pack('N', 19) . 'ecdsa-sha2-nistp256' . pack('N', 8) . 'zzzzzzzz', '');

our $MACHINE_ED = $ED;                       # what the machine presents
our @REX;                                    # known_hosts content at Rex time

{
    package FakeSSH; use Path::Tiny qw( path );
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub wait_for_ssh {
        my $self = shift;
        my $kh = OCP::KnownHosts->new(file => $ENV{OCP_KNOWN_HOSTS});
        my ($rec) = grep { $_->{type} eq 'ssh-ed25519' } $kh->entries($self->{host});
        if (!$rec) {
            $kh->ensure_dir;
            path($kh->file)->append_utf8("$self->{host} ssh-ed25519 $main::MACHINE_ED\n");
            return 1;
        }
        die OCP::SSH::HostKeyChanged->new(host => $self->{host}, file => $kh->file, text => "changed\n")
            if $rec->{key} ne $main::MACHINE_ED;
        return 1;
    }
    sub run { +{ exit => 0 } }
}
{
    package FakeRex; use Path::Tiny qw( path );
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub run_task { push @main::REX, path($ENV{OCP_KNOWN_HOSTS})->slurp_utf8; 1 }
}

my @patches;
{
    no warnings 'redefine';
    *OCP::K8s::patch_status = sub { my ($c, $api, %a) = @_; push @patches, $a{status}; 1 };
    *OCP::KnownHosts::scan  = sub { ({ type => 'ssh-ed25519', key => $main::MACHINE_ED },
                                     { type => 'ecdsa-sha2-nistp256', key => $ECDSA }) };
}
sub patched { my %m; for my $p (@patches) { $m{$_} = $p->{$_} for keys %$p } \%m }

sub node {
    my (%status) = @_;
    @patches = (); @REX = ();
    return OCP::Node->from_cr({
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => '10.0.0.9' },
        status   => { phase => 'Installing', publicIP => '10.0.0.9', %status },
    }, k8s => 'x', ssh_key => 'K', server_url => 'https://cp:9345', join_token => 'T',
       ssh_class => 'FakeSSH', rex_class => 'FakeRex');
}

subtest 'first contact pins every offered key type' => sub {
    $MACHINE_ED = $ED;
    my $n = node();
    $n->_install_kubernetes;

    my $keys = patched()->{hostKeys};
    is scalar(@$keys), 2, 'two key types pinned';
    is_deeply [ sort map { $_->{type} } @$keys ], [ 'ecdsa-sha2-nistp256', 'ssh-ed25519' ];
    like $_->{fingerprint}, qr/\ASHA256:[A-Za-z0-9+\/]{43}\z/, 'SHA256 fingerprint' for @$keys;
    is $keys->[0]{key} ne '' ? 1 : 0, 1, 'the key travels along (a known_hosts line needs it)';
    like $REX[0], qr/ecdsa-sha2-nistp256/, 'Rex ran against the file with all pinned types';
    is patched()->{phase}, 'Joining', 'install went on';
};

subtest 'later contact verifies against the pins, in any pod' => sub {
    $MACHINE_ED = $ED;
    my $pins = [ { type => 'ssh-ed25519', key => $ED, fingerprint => $fp->fingerprint($ED) } ];
    my $n = node(hostKeys => $pins);
    $n->_install_kubernetes;

    ok !exists patched()->{hostKeys}, 'nothing re-pinned';
    like $REX[0], qr/\A10\.0\.0\.9 ssh-ed25519 \Q$ED\E\n\z/, 'known_hosts seeded from status only';
    is patched()->{phase}, 'Joining', 'install went on';
    ok !defined $n->host_key_mismatch, 'no mismatch';
};

subtest 'a changed key stops everything and names both fingerprints' => sub {
    $MACHINE_ED = $ED2;
    my $pins = [ { type => 'ssh-ed25519', key => $ED, fingerprint => $fp->fingerprint($ED) } ];
    my $n = node(hostKeys => $pins);
    $n->_install_kubernetes;

    my $p = patched();
    ok !exists $p->{phase}, 'phase untouched (no Failed)';
    ok !@REX, 'no install ran';
    my $want_old = $fp->fingerprint($ED);
    my $want_new = $fp->fingerprint($ED2);
    like $p->{message}, qr/\Ahost key of 10\.0\.0\.9 changed \(expected \Q$want_old\E \(ssh-ed25519\), got \Q$want_new\E/,
        'message names expected and got';
    like $p->{message}, qr/ocp node trust-host w1/, 'and the way out';
    is $n->host_key_mismatch, $p->{message}, 'caller can see it';
    ok !exists $p->{hostKeys}, 'the pins are not overwritten';

    # The CLI's wait does not spin on a verdict that waiting cannot change.
    @patches = (); @REX = ();
    my $m = node(hostKeys => $pins);
    {
        no warnings 'redefine';
        local *OCP::Node::_refresh       = sub { };
        local *OCP::Node::_acquire_lease = sub { 1 };
        local *OCP::Node::_release_lease = sub { 1 };
        ok !eval { $m->reconcile_until_ready(timeout => 30, interval => 0); 1 }, 'the CLI wait dies';
        like $@, qr/host key of 10\.0\.0\.9 changed/, 'with the message';
    }
};

subtest 'teardown with a changed key uninstalls nothing and keeps the phase' => sub {
    $MACHINE_ED = $ED2;
    my $pins = [ { type => 'ssh-ed25519', key => $ED, fingerprint => $fp->fingerprint($ED) } ];
    my $n = OCP::Node->from_cr({
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => '10.0.0.9' },
        status   => { phase => 'Ready', publicIP => '10.0.0.9', hostKeys => $pins },
    }, k8s => 'x', provider => FakeProvider->new);
    @patches = ();
    {
        no warnings 'redefine';
        local *OCP::Node::_acquire_lease = sub { 1 };
        local *OCP::Node::_release_lease = sub { 1 };
        local *OCP::Node::_cordon = sub { 0 };
        ok !eval { $n->teardown; 1 }, 'teardown dies';
        like $@, qr/host key of 10\.0\.0\.9 changed/, 'with the reason';
    }
    ok !(grep { ($_->{phase} // '') eq 'Failed' } @patches), 'phase is not Failed';
    ok !$n->machine_cleanup_failed, 'and --keep-machine is not the advice';
    is $FakeProvider::seen_file_content, "10.0.0.9 ssh-ed25519 $ED\n", 'the provider contacted the machine under the pins';
};
{
    package FakeProvider;
    use Path::Tiny qw( path );
    our $seen_file_content;
    sub new { bless {}, shift }
    sub delete_server {
        $seen_file_content = path($ENV{OCP_KNOWN_HOSTS})->slurp_utf8;
        die OCP::SSH::HostKeyChanged->new(host => '10.0.0.9', text => "changed\n");
    }
}

#
# ocp node trust-host
#
{
    package FakeIO; sub new { bless {}, shift } sub object_to_struct { $_[1] }
    package FakeApi;
    sub new { bless { cr => $_[1] }, $_[0] }
    sub k8s { FakeIO->new }
    sub get { $_[0]{cr} || die "404\n" }
}

subtest 'trust-host removes the pins, with --yes or confirmation' => sub {
    my $cr = { metadata => { name => 'w1' }, status => { message => 'host key of 10.0.0.9 changed (x)',
        hostKeys => [ { type => 'ssh-ed25519', fingerprint => 'SHA256:x', key => $ED } ] } };

    @patches = ();
    my $cmd = OCP::Cmd::Node::TrustHost->new(k8s => FakeApi->new($cr), yes => 1, name => 'w1');
    my $out = '';
    { open my $fh, '>', \$out; local *STDOUT = $fh; is $cmd->execute([], []), 0; }
    ok exists $patches[0]{hostKeys} && !defined $patches[0]{hostKeys}, 'hostKeys set to null (merge patch removes it)';
    ok exists $patches[0]{message} && !defined $patches[0]{message}, 'the changed-key message goes with it';
    like $out, qr/trusts on first use/, 'says what happens next';

    @patches = ();
    $cmd = OCP::Cmd::Node::TrustHost->new(k8s => FakeApi->new($cr), name => 'w1');
    { open my $in, '<', \"n\n"; local *STDIN = $in; open my $e, '>', \my $err; local *STDERR = $e;
      is $cmd->execute([], []), 1, 'declined: exit 1'; }
    is scalar(@patches), 0, 'nothing patched';

    @patches = ();
    $cmd = OCP::Cmd::Node::TrustHost->new(k8s => FakeApi->new($cr), name => 'w1');
    { open my $in, '<', \"y\n"; local *STDIN = $in; open my $e, '>', \my $err; local *STDERR = $e;
      is $cmd->execute([], []), 0, 'confirmed: ok'; }
    is scalar(@patches), 1, 'patched';

    @patches = ();
    $cmd = OCP::Cmd::Node::TrustHost->new(k8s => FakeApi->new({ metadata => { name => 'w1' }, status => {} }), yes => 1, name => 'w1');
    { open my $fh, '>', \my $o; local *STDOUT = $fh; is $cmd->execute([], []), 0; }
    is scalar(@patches), 0, 'no pins: nothing to do';
};

subtest 'the CRD carries status.hostKeys' => sub {
    require YAML::PP;
    my $crd = YAML::PP->new->load_file('share/robocop/crds/ocpnode.yaml');
    my $hk = $crd->{spec}{versions}[0]{schema}{openAPIV3Schema}{properties}{status}{properties}{hostKeys};
    is $hk->{type}, 'array', 'an array';
    is_deeply [ sort keys %{ $hk->{items}{properties} } ], [qw( fingerprint key type )], 'of type/fingerprint/key';
};

done_testing;

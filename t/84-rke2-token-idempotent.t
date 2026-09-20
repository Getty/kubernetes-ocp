use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';
use OCP::Rex;

#
# k150: `ocp apply` must not rotate the RKE2/K3s token of a cluster that
# already exists.
#
# RKE2/K3s seal the embedded-etcd datastore with the cluster token at bootstrap
# and only re-check it at the NEXT start. So a fresh token written into
# config.yaml on a re-apply is invisible while the server keeps running and
# then crash-loops it the next time it restarts:
#
#   failed to bootstrap cluster data: failed to reconcile with local datastore:
#   bootstrap data already found and encrypted with different token
#
# The single-node cluster is then unbootable without a datastore reset -- a
# latent, data-loss-adjacent landmine armed by every token-rotating apply.
#
# OCP::Rex::install_server is where the token is decided (it was
# `$opts{token} || $self->_generate_token()`, minting a new random token on
# every bootstrap that passes none -- which the control-plane deploy path does).
# The fix: reuse the machine's on-disk server/token when it already carries one,
# generating only for a genuinely fresh server.
#
# Network-free: run_task, the kubeconfig fetch and the on-disk token probe are
# all mocked. What only a real cluster can confirm -- that RKE2 accepts the
# reused token and the datastore reconciles -- is deliberately NOT claimed here.
#

delete local $ENV{OCP_REX_DEBUG};

my $tmp = path(tempdir(CLEANUP => 1));
my $key = $tmp->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub');

# Drive one install_server call and return the token it handed the install task.
# $existing is what the machine already carries on disk (undef = a fresh server).
sub token_install_passes {
    my (%opt) = @_;
    my $existing     = $opt{existing};
    my $distribution = $opt{distribution} || 'rke2';
    my $task_name    = $distribution eq 'k3s' ? 'install_k3s_server' : 'install_rke2_server';

    my $captured;
    no warnings 'redefine';
    # The seam under test stands in for "what the machine already carries".
    local *OCP::Rex::_existing_server_token = sub { $existing };
    local *OCP::Rex::fetch_kubeconfig_ssh   = sub { "apiVersion: v1\n" };
    local *OCP::Rex::run_task = sub {
        my ($s, $task, %p) = @_;
        $captured = $p{token} if $task eq $task_name;
        return 1;
    };

    OCP::Rex->new(host => '10.0.0.1', key_file => $key->stringify)
        ->install_server(distribution => $distribution);

    return $captured;
}

subtest 'a fresh server generates its own token' => sub {
    my $t = token_install_passes(existing => undef);
    ok defined $t && length $t,
        'install_server mints a token when the machine has none';
};

subtest 'a re-apply on an existing cluster reuses the on-disk token (no rotation)' => sub {
    # Apply 1: fresh machine -> a token is generated and sealed into the cluster.
    my $t1 = token_install_passes(existing => undef);
    ok length $t1, 'first apply sealed the cluster with a token';

    # Apply 2: the machine now carries that token on disk. The second apply MUST
    # hand the SAME token to the install task -- writing a different one into
    # config.yaml is exactly the k150 landmine.
    my $t2 = token_install_passes(existing => $t1);
    is $t2, $t1,
        'second apply reuses the existing token instead of generating a new one';
};

subtest 'an explicit token still wins over the on-disk one' => sub {
    # $opts{token} is the caller's override and takes precedence over both the
    # on-disk read and generation -- the documented, pre-existing contract.
    my $captured;
    no warnings 'redefine';
    local *OCP::Rex::_existing_server_token = sub { 'ON-DISK' };
    local *OCP::Rex::fetch_kubeconfig_ssh   = sub { "apiVersion: v1\n" };
    local *OCP::Rex::run_task = sub {
        my ($s, $task, %p) = @_;
        $captured = $p{token} if $task eq 'install_rke2_server';
        return 1;
    };

    OCP::Rex->new(host => '10.0.0.1', key_file => $key->stringify)
        ->install_server(distribution => 'rke2', token => 'EXPLICIT');

    is $captured, 'EXPLICIT', 'a passed token is used verbatim';
};

subtest 'k3s server-token is reused too' => sub {
    my $t1 = token_install_passes(existing => undef, distribution => 'k3s');
    my $t2 = token_install_passes(existing => $t1,   distribution => 'k3s');
    is $t2, $t1, 'k3s install_server reuses the on-disk token as well';
};

#
# The real _existing_server_token, with OCP::SSH mocked: it reads the right file
# per distribution, trims it, and yields undef for a fresh server or an
# unreachable host so the caller falls back to minting a token.
#

subtest '_existing_server_token reads the distribution token file and trims it' => sub {
    my @cat_cmds;
    no warnings 'redefine';
    local *OCP::SSH::new = sub { my ($c, %a) = @_; bless { %a }, $c };
    local *OCP::SSH::run = sub {
        my ($self, $cmd) = @_;
        push @cat_cmds, $cmd;
        return { stdout => "sealed-token-value\n", stderr => '', exit => 0 };
    };

    my $rex = OCP::Rex->new(host => '10.0.0.1', key_file => $key->stringify);

    is $rex->_existing_server_token('rke2'), 'sealed-token-value',
        'returns the on-disk token with its trailing newline trimmed';
    like $cat_cmds[-1], qr{/var/lib/rancher/rke2/server/token},
        'reads the RKE2 server token file';

    is $rex->_existing_server_token('k3s'), 'sealed-token-value',
        'k3s returns its on-disk token too';
    like $cat_cmds[-1], qr{/var/lib/rancher/k3s/server/token},
        'reads the K3s server token file for a k3s cluster';
};

subtest '_existing_server_token yields undef for a fresh server' => sub {
    no warnings 'redefine';
    local *OCP::SSH::new = sub { my ($c, %a) = @_; bless { %a }, $c };
    # `cat` of a missing file exits non-zero -- the fresh-server signal.
    local *OCP::SSH::run = sub { { stdout => '', stderr => 'No such file', exit => 1 } };

    my $rex = OCP::Rex->new(host => '10.0.0.1', key_file => $key->stringify);
    is $rex->_existing_server_token('rke2'), undef,
        'no server/token on disk -> undef, so install_server mints a fresh one';
};

subtest '_existing_server_token degrades to undef when the read dies' => sub {
    no warnings 'redefine';
    local *OCP::SSH::new = sub { my ($c, %a) = @_; bless { %a }, $c };
    local *OCP::SSH::run = sub { die "ssh unreachable\n" };

    my $rex = OCP::Rex->new(host => '10.0.0.1', key_file => $key->stringify);
    is $rex->_existing_server_token('rke2'), undef,
        'an unreachable host falls back to no-existing-token, never aborts the install';
};

done_testing;

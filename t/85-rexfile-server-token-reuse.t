#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# k154: a bare hand-run of the Rexfile server-install tasks must not rotate the
# token of a cluster that already exists.
#
# This is the defense-in-depth twin of k150. k150 fixed the controller side
# (OCP::Rex::install_server reuses the on-disk token), so the `ocp apply` path is
# already safe -- it always passes a token= param down to the task. But the
# Rexfile tasks themselves still minted a fresh token whenever none was passed:
#
#   my $token = $params->{token} || _generate_token();
#
# So a human running `rex -f share/Rexfile install_rke2_server` WITHOUT token= on
# a machine that already carries a cluster would write a new token into
# config.yaml while the embedded-etcd datastore stays sealed with the original,
# arming the same fatal reconcile crash on the next server restart:
#
#   bootstrap data already found and encrypted with different token
#
# The fix mirrors k150: read the machine's on-disk server/token first, generate
# only when there is none. The task runs ON the node, so the read is a LOCAL read
# (is_file/cat over the Rex connection), not SSH-from-the-controller.
#
# Network-free and Rex-session-free, following the t/68 convention: the pure
# decision helpers are lifted out of the Rexfile and run with is_file/cat/run
# stubbed; the wiring inside the task bodies (which needs a real Rex session to
# run) is asserted against the Rexfile source, as t/64 does for the pins.
#
# What only a real cluster can confirm -- that RKE2/k3s accept the reused token
# and the datastore reconciles -- is deliberately NOT claimed here.
#

my $root    = path(__FILE__)->parent->parent;
my $rexfile = $root->child('share/Rexfile');

plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

my $src = $rexfile->slurp_utf8;

# --- lift the decision helpers out of the Rexfile --------------------------

my @wanted = qw( _existing_server_token _generate_token );

my @subs;
for my $name (@wanted) {
    my ($body) = $src =~ /^(sub \Q$name\E \{.*?^\})/ms;
    ok defined $body, "share/Rexfile defines $name"
        or BAIL_OUT("k154 fix absent: $name is not in the Rexfile");
    push @subs, $body;
}

# is_file / cat / run are Rex::Commands::Fs / ::Run in the real Rexfile; here
# they stand in for the target filesystem. Stubs come FIRST in the eval'd string
# so `cat $path` (paren-less) parses as a call inside the extracted subs.
my $stubs = <<'PERL';
package RexfileServerToken;
our %FILES;                       # path => on-disk content (present == is_file true)
our $CAT_DIES  = 0;               # simulate an unreadable file
our @GENERATED;                   # records every _generate_token() minting
our $GEN_VALUE = 'FRESH-GENERATED-TOKEN';
sub is_file { exists $FILES{ $_[0] } }
sub cat     { die "unreadable\n" if $CAT_DIES; return $FILES{ $_[0] } }
sub run     { push @GENERATED, $_[0]; return $GEN_VALUE }
PERL

ok eval("$stubs\n" . join("\n", @subs) . "\n1;"),
    'the lifted helpers compile against plain is_file/cat/run stubs'
    or BAIL_OUT("cannot compile the lifted helpers: $@");

my $existing = RexfileServerToken->can('_existing_server_token');

my $RKE2_TOKEN_PATH = '/var/lib/rancher/rke2/server/token';
my $K3S_TOKEN_PATH  = '/var/lib/rancher/k3s/server/token';

# Reset the stub filesystem to a known state before each case.
sub set_fs {
    my (%files) = @_;
    no warnings 'once';   # the package globals live in the eval'd stub string
    %RexfileServerToken::FILES = %files;
    $RexfileServerToken::CAT_DIES = 0;
    @RexfileServerToken::GENERATED = ();
}

# --- _existing_server_token: the read + decide logic -----------------------

subtest 'an existing cluster token is read back, per distribution' => sub {
    set_fs($RKE2_TOKEN_PATH => "sealed-rke2-token\n");
    is $existing->('rke2'), 'sealed-rke2-token',
        'rke2 returns the on-disk server/token (trailing newline trimmed)';

    set_fs($K3S_TOKEN_PATH => "sealed-k3s-token\n");
    is $existing->('k3s'), 'sealed-k3s-token',
        'k3s reads its OWN server/token path, not the rke2 one';

    # Cross-check the path selection: an rke2 token on disk is invisible to a
    # k3s read and vice versa, so a wrong path can never silently "work".
    set_fs($RKE2_TOKEN_PATH => "only-rke2\n");
    is $existing->('k3s'), undef,
        'k3s does not read the rke2 token file';
};

subtest 'a fresh server has no token file -> undef (caller will generate)' => sub {
    set_fs();   # empty filesystem: is_file is false everywhere
    is $existing->('rke2'), undef,
        'no server/token on disk -> undef, so the || chain falls to _generate_token';
    is $existing->('k3s'), undef,
        'same for k3s';
};

subtest 'the read is tolerant: an unreadable file degrades to undef' => sub {
    set_fs($RKE2_TOKEN_PATH => "does-not-matter\n");
    $RexfileServerToken::CAT_DIES = 1;
    is $existing->('rke2'), undef,
        'a cat that dies is caught -> undef, the install is never aborted mid-decision';
};

subtest 'an empty token file is treated as no token' => sub {
    set_fs($RKE2_TOKEN_PATH => "\n");
    is $existing->('rke2'), undef,
        'a whitespace-only file trims to empty -> undef, so a fresh token is minted';
};

# --- the || chain: existing wins, and no fresh token is minted -------------
#
# The task body decides with:  $params->{token} || _existing_server_token(...) || _generate_token()
# The source subtest below binds the real tasks to exactly that chain; here we
# run the chain to prove its consequence -- a truthy on-disk token short-circuits
# generation, which is the whole point of the fix.

my $generate = RexfileServerToken->can('_generate_token');

sub decide {
    my ($explicit, $dist) = @_;
    return $explicit || $existing->($dist) || $generate->();
}

subtest 'an existing token is reused and NO fresh token is generated' => sub {
    set_fs($RKE2_TOKEN_PATH => "sealed-rke2-token\n");
    my $chosen = decide(undef, 'rke2');
    is $chosen, 'sealed-rke2-token', 'the chain hands back the on-disk token';
    is scalar(@RexfileServerToken::GENERATED), 0,
        '_generate_token was never called -- config.yaml keeps the sealed token';
};

subtest 'a genuinely fresh server still generates a token, as before' => sub {
    set_fs();   # nothing on disk
    my $chosen = decide(undef, 'rke2');
    is $chosen, 'FRESH-GENERATED-TOKEN', 'with no on-disk token, one is minted';
    is scalar(@RexfileServerToken::GENERATED), 1,
        '_generate_token ran exactly once for the fresh server';
};

subtest 'an explicit token= param still wins (the ocp-apply path is unchanged)' => sub {
    set_fs($RKE2_TOKEN_PATH => "sealed-rke2-token\n");
    my $chosen = decide('PASSED-BY-OCP-APPLY', 'rke2');
    is $chosen, 'PASSED-BY-OCP-APPLY',
        'a passed token beats both the on-disk read and generation';
    is scalar(@RexfileServerToken::GENERATED), 0,
        'and nothing is generated';
};

# --- the tasks actually wire the helper, in the right order ----------------
#
# Running the full task needs a Rex session; assert the wiring against source,
# the way t/64 asserts the Cilium pins. Order matters: token param first (apply),
# on-disk second (bare hand-run), generation last (fresh server).

subtest 'both server-install tasks reuse the on-disk token before generating' => sub {
    my ($rke2_task) = $src =~ /^task "install_rke2_server", sub \{\n(.*?)\n\};$/ms;
    my ($k3s_task)  = $src =~ /^task "install_k3s_server", sub \{\n(.*?)\n\};$/ms;

    ok defined $rke2_task, 'install_rke2_server task found' or return;
    ok defined $k3s_task,  'install_k3s_server task found'  or return;

    like $rke2_task,
        qr/\$params->\{token\}\s*\|\|\s*_existing_server_token\(\s*'rke2'\s*\)\s*\|\|\s*_generate_token\(\)/,
        'rke2: $params->{token} || _existing_server_token(rke2) || _generate_token()';

    like $k3s_task,
        qr/\$params->\{token\}\s*\|\|\s*_existing_server_token\(\s*'k3s'\s*\)\s*\|\|\s*_generate_token\(\)/,
        'k3s: $params->{token} || _existing_server_token(k3s) || _generate_token()';
};

subtest 'the helper reads server/token (the sealing key), not node-token' => sub {
    my ($body) = $src =~ /^(sub _existing_server_token \{.*?^\})/ms;
    ok defined $body, 'helper body available' or return;

    like $body, qr{/var/lib/rancher/rke2/server/token},
        'rke2 path is the datastore-sealing server/token';
    like $body, qr{/var/lib/rancher/k3s/server/token},
        'k3s path is the datastore-sealing server/token';
    unlike $body, qr{node-token},
        'not node-token -- that is the join credential, not the sealing key';

    # Tolerant by construction: guarded by is_file, read wrapped in eval.
    like $body, qr/is_file\(/,   'guards the read with is_file (missing file -> undef)';
    like $body, qr/eval\s*\{\s*cat/, 'wraps the read in eval (unreadable file -> undef)';
};

done_testing;

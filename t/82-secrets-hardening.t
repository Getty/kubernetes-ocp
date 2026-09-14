#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Secrets;
use OCP::Keys;
use OCP::Password;

# Security-hardening regressions from the 2026-09-14 audit. Three separate
# claims, one file because they share the same lane (the crypto boundary):
#
#   Fix 1  generate_ssh_key must not build a shell command by string
#          interpolation — a project path with a quote or metacharacter used
#          to break out of the quotes. This one is a true red/green: the old
#          string form produces no keypair at the requested path.
#
#   Fix 2  the private age key and the decrypted kubeconfig must be created
#          0600, not spewed at the umask default and chmod'd a statement later.
#          A final-mode assertion is all that is asserted here: the race window
#          is a matter of timing, and a test that tried to catch it would be
#          flaky. So these pass before AND after the fix — they are the guard
#          that keeps the mode where it belongs, not the reproduction.
#
#   Fix 3  the /dev/urandom reads must check they got the bytes they asked for.
#          The short-read branch itself is not cleanly mockable (read() is a
#          builtin against a device file), so what is asserted is the happy
#          path: the CSPRNG helpers return exactly the requested length.

# Establish the OCP singleton for load/dump (kubeconfig round-trip needs it).
local @ARGV = ();
my $ocp = OCP->new;

#
# Fix 1 — generate_ssh_key survives a hostile project path
#

SKIP: {
    skip 'needs ssh-keygen', 6 unless _have('ssh-keygen');

    # A single quote plus spaces: the canonical break-out from -f '$key_path'.
    my $base = tempdir(CLEANUP => 1);
    my $proj = path($base)->child(q{weird 'quote' dir});
    $proj->mkpath;

    my $secrets = OCP::Secrets->new(project_dir => $proj);

    my $result = eval { $secrets->generate_ssh_key };
    ok($result, 'generate_ssh_key returns a result for a quoted project path')
        or diag "died: $@";

    my $priv = $proj->child('.ocp', 'id_ed25519');
    my $pub  = $proj->child('.ocp', 'id_ed25519.pub');

    ok(-f $priv, 'private key written to the exact requested path (no break-out)');
    ok(-f $pub,  'public key written beside it');

    my $priv_content = -f $priv ? $priv->slurp : '';
    my $pub_content  = -f $pub  ? $pub->slurp  : '';

    like($priv_content, qr/-----BEGIN OPENSSH PRIVATE KEY-----/,
        'private key file is a real OpenSSH key');
    like($pub_content, qr/^ssh-ed25519 /,
        'public key file is a real ed25519 public key');

    my $mode = -f $priv ? ((stat($priv->stringify))[2] & 07777) : undef;
    is($mode, 0600, 'private SSH key is mode 0600');
}

#
# Fix 2a — generate_age_key writes .ocp/age.key as 0600
#

{
    my $dir = path(tempdir(CLEANUP => 1));
    my $secrets = OCP::Secrets->new(project_dir => $dir);
    $secrets->generate_age_key;

    my $mode = (stat($secrets->age_key_file->stringify))[2] & 07777;
    is($mode, 0600, 'generate_age_key: .ocp/age.key is 0600');
}

#
# Fix 2b — decrypt_age_key_with_password re-creates .ocp/age.key as 0600
#

{
    my $dir = path(tempdir(CLEANUP => 1));
    my $secrets = OCP::Secrets->new(project_dir => $dir);
    $secrets->generate_age_key;
    $secrets->encrypt_age_key_with_password('pin1-secret');

    # Drop the cached plaintext key so decrypt has to write it afresh.
    $secrets->age_key_file->remove;
    ok(!$secrets->has_age_key, 'cached age.key removed for the test');

    $secrets->decrypt_age_key_with_password('pin1-secret');
    ok($secrets->has_age_key, 'decrypt_age_key_with_password re-created age.key');

    my $mode = (stat($secrets->age_key_file->stringify))[2] & 07777;
    is($mode, 0600, 'decrypt_age_key_with_password: .ocp/age.key is 0600');
}

#
# Fix 2c — decrypt_kubeconfig_to_file writes the target as 0600
#

{
    my $dir = path(tempdir(CLEANUP => 1));
    my $secrets = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $secrets->generate_age_key;

    my $kubeconfig = "apiVersion: v1\nkind: Config\nclusters: []\n";
    $secrets->save_kubeconfig($kubeconfig);

    # A nested target also exercises the mkpath before the secure write.
    my $target = $dir->child('out', 'kubeconfig.yaml');
    my $written = $secrets->decrypt_kubeconfig_to_file("$target");

    ok(-f $target, 'decrypt_kubeconfig_to_file wrote the target');
    like($target->slurp, qr/kind: Config/, 'decrypted kubeconfig round-trips');

    my $mode = (stat($target->stringify))[2] & 07777;
    is($mode, 0600, 'decrypt_kubeconfig_to_file: target is 0600');
}

#
# Fix 3 — CSPRNG helpers return exactly the requested number of bytes
#

{
    is(length(OCP::Keys::_random_bytes(16)), 16,
        'OCP::Keys::_random_bytes(16) returns 16 bytes');
    is(length(OCP::Keys::_random_bytes(12)), 12,
        'OCP::Keys::_random_bytes(12) returns 12 bytes');
    is(length(OCP::Password::_random_bytes(16)), 16,
        'OCP::Password::_random_bytes(16) returns 16 bytes');
    is(length(OCP::Password::_random_bytes(12)), 12,
        'OCP::Password::_random_bytes(12) returns 12 bytes');
}

done_testing;

sub _have {
    my ($cmd) = @_;
    return system("command -v $cmd >/dev/null 2>&1") == 0;
}

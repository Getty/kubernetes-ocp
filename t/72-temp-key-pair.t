#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP::TempKeyPair;

#
# The pair of files a Rex run needs on disk, and the fact that neither of them
# outlives the object that wrote it.
#
# Why there is a public half at all: OCP::Rex does
#
#     $ENV{REX_PUBLIC_KEY} = $self->key_file . '.pub';
#
# unconditionally, so anything handing Rex a private key in a temp file owes a
# .pub beside it. OCP::Cmd::Apply::Bootstrap got that wrong (karr #87) and
# OCP::Node got it wrong the same way on the worker path (karr #93). This is
# the one place that dance lives now.
#
# The claims split in two:
#
#   * OWNERSHIP — both files exist while the object does, both are gone when
#     it goes, including when it goes because something died. That is the part
#     that has actually failed in production, twice.
#   * DERIVATION — the .pub holds the real public half of the private key even
#     when nobody handed one over. That is what lets OCP::Node stay
#     trigger-neutral: robocop is given private key material and nothing else,
#     no key store and no project directory, so a public half only the CLI
#     could supply would leave the controller exactly as broken as before.
#
# ssh-keygen is used to MAKE the fixtures, never to do the work: the point of
# public_from_private is that it needs no external binary, and the strongest
# available statement of "it is correct" is byte equality with what ssh-keygen
# itself writes.
#

sub have_ssh_keygen { system('command -v ssh-keygen >/dev/null 2>&1') == 0 }

# Returns ($private_material, $public_line) for a fresh throwaway ed25519 key.
# `passphrase` encrypts the private half, which is the interesting case: the
# public key sits OUTSIDE the encrypted section, so it is still readable —
# where `ssh-keygen -y` would stop and ask for the password.
sub keypair {
    my (%opt) = @_;
    my $dir  = path(tempdir(CLEANUP => 1));
    my $file = $dir->child('k');
    my $pass = $opt{passphrase} // '';
    my $cmt  = $opt{comment}    // 'ocp-cluster-key';
    system("ssh-keygen -q -t ed25519 -N '$pass' -C '$cmt' -f '$file' >/dev/null 2>&1") == 0
        or die "ssh-keygen failed";
    return ($file->slurp, $dir->child('k.pub')->slurp);
}

# The two fields that authenticate. ssh-keygen writes a third, the comment,
# which lives in the section a passphrase encrypts and authenticates nothing.
sub key_fields { my @f = split ' ', $_[0]; return "$f[0] $f[1]" }

# ------------------------------------------------------------- the two files

subtest 'both halves are written, at the names OCP::Rex derives' => sub {
    my $pair = OCP::TempKeyPair->for_private_key("PRIVATE\n", public => "ssh-ed25519 AAAApub x\n");

    ok -f $pair->path, 'the private key is on disk';
    is path($pair->path)->slurp, "PRIVATE\n", 'holding the material it was given';

    is $pair->public_path, $pair->path . '.pub',
        'the public half is at key_file . ".pub" — the name OCP::Rex builds';
    ok -f $pair->public_path, 'and it actually exists, which is the whole ticket';
    is path($pair->public_path)->slurp, "ssh-ed25519 AAAApub x\n",
        'holding the public half it was given';
};

subtest 'the private half is not world-readable' => sub {
    my $pair = OCP::TempKeyPair->for_private_key("PRIVATE\n");
    my $mode = (stat $pair->path)[2] & 07777;
    is $mode, 0600, 'ssh refuses a key file anyone else can read';
};

subtest 'both files go away when the object does' => sub {
    my ($priv, $pub);
    {
        my $pair = OCP::TempKeyPair->for_private_key("PRIVATE\n");
        ($priv, $pub) = ($pair->path, $pair->public_path);
        ok -f $priv, 'private exists while the object is alive';
        ok -f $pub,  'so does the public half';
    }
    ok !-e $priv, 'private is gone once the object leaves scope';
    ok !-e $pub,  'and so is the public half';
};

subtest 'a die on the way through still cleans up both' => sub {
    # The case that matters: an unreachable host, a Rex task blowing up. What
    # must not be left behind in /tmp is a readable private key.
    my ($priv, $pub);
    my $err = do {
        local $@;
        eval {
            my $pair = OCP::TempKeyPair->for_private_key("PRIVATE\n");
            ($priv, $pub) = ($pair->path, $pair->public_path);
            die "the step that used the key failed\n";
        };
        $@;
    };

    like $err, qr/the step that used the key failed/, 'the failure propagated';
    ok $priv && !-e $priv, 'and the private key did not survive it';
    ok $pub  && !-e $pub,  'nor the public half';
};

subtest 'cleanup is explicit as well as automatic, and idempotent' => sub {
    my $pair = OCP::TempKeyPair->for_private_key("PRIVATE\n");
    my ($priv, $pub) = ($pair->path, $pair->public_path);

    # No warnings on the way out: the private half belongs to File::Temp, and
    # unlinking it behind its back says "unlink0: ... is gone already". That
    # warning is exactly why cleanup drops the reference instead.
    my @warnings;
    {
        local $SIG{__WARN__} = sub { push @warnings, $_[0] };
        $pair->cleanup;
        ok eval { $pair->cleanup; 1 }, 'calling it twice is not an error';
        undef $pair;
    }

    ok !-e $priv, 'cleanup removed the private half';
    ok !-e $pub,  'and the public one';
    is_deeply \@warnings, [], 'and said nothing on the way out'
        or diag "unexpected warnings:\n@warnings";
};

subtest 'no material is not an error here' => sub {
    # OCP::Node's ssh_key is optional, and a node reconciled without one has
    # to fail at the SSH connection with a diagnosable message — not while
    # building a lazy attribute, where nothing can report it.
    my $pair = eval { OCP::TempKeyPair->for_private_key(undef) };
    is $@, '', 'undef material does not die';
    ok $pair && -f $pair->path,       'the private file is still created';
    ok $pair && -f $pair->public_path, 'and so is the .pub, so the path resolves';
};

# ------------------------------------------------------- where .pub comes from

subtest 'the public half is derived when nobody hands one over' => sub {
    plan skip_all => 'needs ssh-keygen to make a fixture' unless have_ssh_keygen();

    my ($private, $public) = keypair();
    my $pair = OCP::TempKeyPair->for_private_key($private);

    is key_fields(path($pair->public_path)->slurp), key_fields($public),
        'the derived .pub is byte-for-byte the public key ssh-keygen wrote';

    like path($pair->public_path)->slurp, qr/^ssh-ed25519 AAAA/,
        'in authorized_keys form';
};

subtest 'a passphrase on the private half does not hide the public one' => sub {
    plan skip_all => 'needs ssh-keygen to make a fixture' unless have_ssh_keygen();

    # This is the reason for parsing the container rather than shelling out to
    # `ssh-keygen -y`: the public key lives ahead of the encrypted section, so
    # it reads out without the passphrase that ssh-keygen would demand.
    my ($private, $public) = keypair(passphrase => 'secretpass', comment => 'enc@ocp');
    like $private, qr/BEGIN OPENSSH PRIVATE KEY/, 'still the openssh container';

    is key_fields(OCP::TempKeyPair::public_from_private($private) // ''),
       key_fields($public),
        'the public half comes out anyway';
};

subtest 'a handed-in public half wins over the derived one' => sub {
    plan skip_all => 'needs ssh-keygen to make a fixture' unless have_ssh_keygen();

    # OCP::ClusterKey has the stored public key from keys.yaml and should use
    # it: it carries the comment, and it is what was uploaded to the provider.
    my ($private) = keypair();
    my $pair = OCP::TempKeyPair->for_private_key($private,
        public => "ssh-ed25519 AAAAgiven admin\@ocp\n");

    is path($pair->public_path)->slurp, "ssh-ed25519 AAAAgiven admin\@ocp\n",
        'what the caller passed is what is written';
};

subtest 'material that is not a key produces an empty .pub, not a wrong one' => sub {
    # Rex's requirement is that the PATH resolves; the private key is what
    # authenticates. Guessing at content nobody can derive would be worse than
    # writing none.
    for my $junk (
        ['bare string',          'K'],
        ['empty',                ''],
        ['PEM RSA',              "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"],
        ['openssh-shaped junk',  "-----BEGIN OPENSSH PRIVATE KEY-----\nADMINKEYMATERIAL\n-----END OPENSSH PRIVATE KEY-----\n"],
        ['truncated container',  "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n"],
    ) {
        my ($label, $material) = @$junk;
        is OCP::TempKeyPair::public_from_private($material), undef,
            "$label: derivation declines instead of guessing";

        my $pair = OCP::TempKeyPair->for_private_key($material);
        ok -f $pair->public_path, "$label: the .pub is still created";
        is path($pair->public_path)->slurp, '', "$label: and is empty";
    }
};

done_testing;

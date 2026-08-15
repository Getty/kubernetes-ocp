#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Cwd qw(getcwd);

use OCP;
use OCP::Cmd::Init;
use OCP::Keys;
use OCP::Secrets;

# karr #86 — `ocp init` on a fresh clone used to destroy the project.
#
# .ocp/ is gitignored (ADR 0004), the encrypted files are not: a colleague who
# clones the repo has keys.yaml, secrets.yaml and age.key.enc, but no
# .ocp/age.key. Step 4 of OCP::Cmd::Init asked `has_age_key` — "is there one on
# this machine?" — got "no", and generated a FRESH keypair over .ocp/age.pub.
# From that moment keys.yaml was encrypted to a recipient whose private half
# nobody had, and step 5b died with
#
#     Could not decrypt data key with any of the provided identities
#
# The question at that point is not "is there one here" but "does this PROJECT
# already have one that I simply do not hold". age.key.enc and the plaintext
# `sops: age: - recipient:` block of the committed SOPS files answer it without
# needing any key at all.
#
# The dev-mode branch in OCP::Cmd::Apply (~line 129) runs the same has_age_key
# check and is deliberately correct: it states that it does not touch
# age.key.enc, so nothing committed can be devalued there. That boundary is
# what was missing on the secure path.

plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

my $PIN = 'test-pin-1234';

# ---------------------------------------------------------------- helpers

# Run OCP::Cmd::Init::execute in a project dir with the PIN prompts answered.
# Secure mode is the default and is the whole point here.
sub run_init {
    my (%args) = @_;

    my $dir     = delete $args{dir} || tempdir(CLEANUP => 1);
    my $pin     = delete $args{pin} // $PIN;
    my $prompts = 0;

    my $init = OCP::Cmd::Init->new(
        command_chain => [OCP->new],
        nogit         => 1,
        name          => 'clonetest',
        _interactive  => 0,
        %args,
    );

    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";

    my $out = '';
    my $err = eval {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub { $prompts++; $pin };
        open my $fh, '>', \$out or die "capture: $!";
        my $old = select $fh;
        eval { $init->execute([], []) };
        my $e = $@;
        select $old;
        close $fh;
        $e;
    };
    $err = $@ if $@ && !$err;

    chdir $cwd or die "chdir back: $!";

    return {
        dir     => path($dir),
        out     => $out,
        err     => $err // '',
        prompts => $prompts,
    };
}

# What `git clone` of an OCP project gives you: everything except .ocp/, which
# .gitignore excludes. This is the scenario, reproduced without git.
sub clone_project {
    my ($src) = @_;

    my $dst = path(tempdir(CLEANUP => 1));
    for my $entry ($src->children) {
        next if $entry->basename eq '.ocp';
        if ($entry->is_dir) {
            $entry->visit(sub {
                my ($p) = @_;
                return if $p->is_dir;
                my $rel = $p->relative($src);
                $dst->child($rel)->parent->mkpath;
                $p->copy($dst->child($rel));
            }, { recurse => 1 });
        }
        else {
            $entry->copy($dst->child($entry->basename));
        }
    }

    ok !-d $dst->child('.ocp'), 'the clone has no .ocp/ — that is the premise';
    return $dst;
}

# The age recipient a SOPS file is bound to. SOPS records it in plaintext, so
# this needs no key — which is exactly why init can consult it before deciding
# to generate anything.
sub recipient_of {
    my ($file) = @_;
    my $data = OCP->new->load_file("$file");
    return $data->{sops}{age}[0]{recipient};
}

# ------------------------------------------------------------- the core case

subtest 'init on a fresh clone keeps keys.yaml decryptable' => sub {
    my $origin = run_init()->{dir};
    ok -f $origin->child('keys.yaml'),   'origin project has keys.yaml';
    ok -f $origin->child('age.key.enc'), 'and age.key.enc';

    my $recipient = recipient_of($origin->child('keys.yaml'));
    like $recipient, qr/\Aage1/, 'keys.yaml names an age recipient';
    is $recipient, $origin->child('.ocp', 'age.pub')->slurp =~ s/\s+\z//r,
        'and it is the origin .ocp/age.pub';

    my ($admin_before) =
        grep { ($_->{purpose} // '') eq 'admin' }
        @{ OCP::Keys->new(project_dir => $origin)->list_keys };
    ok $admin_before, 'origin has an admin key in keys.yaml';

    my $clone     = clone_project($origin);
    my $keys_yaml = $clone->child('keys.yaml')->slurp;
    my $key_enc   = $clone->child('age.key.enc')->slurp;

    my $r = run_init(dir => $clone->stringify);
    is $r->{err}, '', 'init on the clone completed' or diag $r->{out};

    # THE assertion. Everything else here is diagnosis for when it fails.
    my $admin_after = eval {
        my ($k) = grep { ($_->{purpose} // '') eq 'admin' }
            @{ OCP::Keys->new(project_dir => $clone)->list_keys };
        $k;
    };
    my $decrypt_error = $@;
    ok $admin_after, 'keys.yaml is STILL decryptable after init on the clone'
        or diag "decrypt failed: $decrypt_error";
    is $admin_after && $admin_after->{public}, $admin_before->{public},
        'and it is the same admin key, not a replacement';

    is $clone->child('.ocp', 'age.pub')->slurp =~ s/\s+\z//r, $recipient,
        '.ocp/age.pub holds the project recipient, not a freshly minted one';
    is $clone->child('keys.yaml')->slurp, $keys_yaml,
        'keys.yaml was not rewritten';
    is $clone->child('age.key.enc')->slurp, $key_enc,
        'age.key.enc was not rewritten either';

    is $r->{prompts}, 1,
        'exactly one prompt: PIN1 to unlock what is already there — no new PIN was set';
};

subtest 'the unlocked clone can encrypt again, not just decrypt' => sub {
    # Unlocking has to restore .ocp/age.pub as well. Without it the project
    # reads but cannot write: every encrypt path (save_kubeconfig, add_key,
    # set_hetzner_token) goes through age_recipient.
    my $origin = run_init()->{dir};
    my $clone  = clone_project($origin);

    my $r = run_init(dir => $clone->stringify);
    is $r->{err}, '', 'init completed' or diag $r->{out};

    my $secrets = OCP::Secrets->new(project_dir => $clone);
    ok $secrets->age_recipient, 'the clone has an age recipient again';

    $secrets->set_hetzner_token('tok-from-the-clone');
    is $secrets->hetzner_token, 'tok-from-the-clone',
        'and writing new encrypted material round-trips';

    # The origin must still be able to read what the clone wrote — same key.
    $clone->child('secrets.yaml')->copy($origin->child('secrets.yaml'));
    my $origin_secrets = OCP::Secrets->new(project_dir => $origin);
    is $origin_secrets->hetzner_token, 'tok-from-the-clone',
        'the origin can read it too: both sides share one project key';
};

# ------------------------------------------------------- must not regress

subtest 'a first run in an empty directory still just generates a key' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    my $r = run_init(dir => $dir->stringify);

    is $r->{err}, '', 'init completed' or diag $r->{out};
    ok -f $dir->child('.ocp', 'age.key'), '.ocp/age.key generated';
    ok -f $dir->child('.ocp', 'age.pub'), '.ocp/age.pub generated';
    ok -f $dir->child('age.key.enc'),     'age.key.enc created from it';
    like $r->{out}, qr/Generated age key/, 'and init says so';

    is recipient_of($dir->child('keys.yaml')),
        $dir->child('.ocp', 'age.pub')->slurp =~ s/\s+\z//r,
        'keys.yaml is bound to the key that was just generated';
};

subtest 'a re-run with the full local state changes nothing' => sub {
    my $dir = run_init()->{dir};

    my %before = map { $_ => $dir->child($_)->slurp }
        ('keys.yaml', 'age.key.enc', '.ocp/age.key', '.ocp/age.pub');

    my $r = run_init(dir => $dir->stringify);
    is $r->{err}, '', 're-run completed' or diag $r->{out};

    is $dir->child($_)->slurp, $before{$_}, "$_ is byte-identical after a re-run"
        for sort keys %before;

    is $r->{prompts}, 0, 'and nothing was asked — everything was already there';
    like $r->{out}, qr/Age encryption key exists/, 'init reports the existing key';
};

# --------------------------------------------------- loud failure, not damage

subtest 'a wrong PIN1 aborts instead of minting a new key' => sub {
    my $origin = run_init()->{dir};
    my $clone  = clone_project($origin);

    my $r = run_init(dir => $clone->stringify, pin => 'not-the-pin');

    ok $r->{err}, 'init failed rather than carrying on';
    like $r->{err}, qr/PIN1|age\.key\.enc/,
        'and the message names PIN1 / age.key.enc';

    ok !-f $clone->child('.ocp', 'age.pub'),
        'no recipient file was written — nothing was devalued';
    ok !-f $clone->child('.ocp', 'age.key'),
        'and no private key either';

    # The project is untouched, so the right PIN still works afterwards.
    my $retry = run_init(dir => $clone->stringify);
    is $retry->{err}, '', 'a retry with the correct PIN1 succeeds';
    my $reopened = OCP::Keys->new(project_dir => $clone);
    ok $reopened->list_keys->[0], 'and keys.yaml opens';
};

subtest 'encrypted material with no way in aborts and says what is missing' => sub {
    # A dev-mode project (--nopassword) has no age.key.enc, but `--hetzner`
    # still leaves a secrets.yaml bound to the project recipient. Cloned, that
    # is unopenable — and the one thing init must not do is paper over it by
    # generating a new key.
    my $origin = path(tempdir(CLEANUP => 1));
    my $r0 = run_init(dir => $origin->stringify, nopassword => 1);
    is $r0->{err}, '', 'dev-mode init completed' or diag $r0->{out};
    OCP::Secrets->new(project_dir => $origin)->set_hetzner_token('dev-token');

    my $clone = clone_project($origin);
    ok -f $clone->child('secrets.yaml'), 'the clone has the encrypted secrets';
    ok !-f $clone->child('age.key.enc'), 'but no age.key.enc to unlock with';
    my $before = $clone->child('secrets.yaml')->slurp;

    my $r = run_init(dir => $clone->stringify, nopassword => 1);

    ok $r->{err}, 'init refused to continue';
    like $r->{err}, qr/secrets\.yaml/, 'the message names the file that is bound';
    like $r->{err}, qr/age\.key/,      'and the key material that is missing';
    like $r->{err}, qr/\.ocp\//,
        'and points at .ocp/, which git never carried';

    is $r->{prompts}, 0, 'dev mode still never prompts for a PIN';
    ok !-f $clone->child('.ocp', 'age.pub'),
        'no new recipient was minted over the project one';
    is $clone->child('secrets.yaml')->slurp, $before,
        'secrets.yaml is exactly as it was — recoverable by whoever has the key';
};

subtest '--nopassword cannot be applied to a secure project' => sub {
    my $origin = run_init()->{dir};
    my $clone  = clone_project($origin);

    my $r = run_init(dir => $clone->stringify, nopassword => 1);

    ok $r->{err}, 'the contradiction is surfaced, not averaged out';
    like $r->{err}, qr/age\.key\.enc/, 'naming the secure-mode material';
    like $r->{err}, qr/--nopassword/,  'and the flag that conflicts with it';
    is $r->{prompts}, 0, 'without prompting — dev mode does not ask for PINs';
    ok !-f $clone->child('.ocp', 'age.pub'), 'and nothing was overwritten';
};

subtest 'a project already damaged by the old init is diagnosed, and recovers' => sub {
    # Somebody ran the broken `ocp init` before this fix: their clone now
    # holds a minted key that opens nothing. What was committed is intact —
    # the old run died at step 5b, before anything could be rewritten — so
    # this is recoverable, and the tool should say how.
    my $origin = run_init()->{dir};
    my $clone  = clone_project($origin);
    my $keys_yaml = $clone->child('keys.yaml')->slurp;

    # Reproduce the damage: a fresh keypair in .ocp/, exactly what the old
    # step 4 wrote. Made in a scratch dir, because generate_age_key now
    # refuses to do this in a project that is bound.
    my $scratch = path(tempdir(CLEANUP => 1));
    OCP::Secrets->new(project_dir => $scratch)->generate_age_key;
    $clone->child('.ocp')->mkpath;
    $scratch->child('.ocp', $_)->copy($clone->child('.ocp', $_))
        for qw(age.key age.pub);

    my $r = run_init(dir => $clone->stringify);
    ok $r->{err}, 'init refuses to pretend this key works';
    like $r->{err}, qr/does not open this project/, 'and names the problem';
    like $r->{err}, qr/keys\.yaml needs:\s+age1/,
        'showing which recipient keys.yaml actually needs';
    like $r->{err}, qr/age\.key\.enc/, 'and where the real key still is';
    is $r->{prompts}, 0, 'no PIN was asked for on a key that cannot be used';

    # The recipe the message gives has to work.
    $clone->child('.ocp', $_)->remove for qw(age.key age.pub);
    my $recovered = run_init(dir => $clone->stringify);
    is $recovered->{err}, '', 'after removing them, init recovers the project'
        or diag $recovered->{out};

    my ($admin) = grep { ($_->{purpose} // '') eq 'admin' }
        @{ OCP::Keys->new(project_dir => $clone)->list_keys };
    ok $admin, 'keys.yaml opens again';
    is $clone->child('keys.yaml')->slurp, $keys_yaml,
        'and it was never rewritten in the first place — that is why this works';
};

# ------------------------------------------------- the guard itself, directly

subtest 'generate_age_key refuses to overwrite a project recipient' => sub {
    # Requirement from the ticket: the safety net has to hold even if some
    # other path to generation is found later. It lives in OCP::Secrets, below
    # every command, so this is asserted without going through init at all.
    my $origin = run_init()->{dir};
    my $clone  = clone_project($origin);

    my $secrets = OCP::Secrets->new(project_dir => $clone);
    ok !$secrets->has_age_key, 'no local age key in the clone';
    ok $secrets->project_has_age_key,
        'but the PROJECT has one — the question init was not asking';

    my $err = do { local $@; eval { $secrets->generate_age_key }; $@ };
    ok $err, 'generate_age_key croaks instead of minting over it';
    like $err, qr/keys\.yaml|age\.key\.enc/, 'naming what stands in the way';

    ok !-f $clone->child('.ocp', 'age.pub'), 'age.pub was not written';
    ok !-f $clone->child('.ocp', 'age.key'), 'nor age.key';

    # And it stays true once the local key is back: regenerating over a live
    # recipient is wrong no matter who holds the private half.
    run_init(dir => $clone->stringify);
    my $pub = $clone->child('.ocp', 'age.pub')->slurp;
    my $err2 = do { local $@; eval { $secrets->generate_age_key }; $@ };
    ok $err2, 'still refused with the key present';
    is $clone->child('.ocp', 'age.pub')->slurp, $pub, 'age.pub untouched';
};

subtest 'project_has_age_key answers for the project, not for this machine' => sub {
    my $empty = OCP::Secrets->new(project_dir => path(tempdir(CLEANUP => 1)));
    ok !$empty->project_has_age_key, 'an empty directory has no project key';

    my $origin = run_init()->{dir};
    my $origin_secrets = OCP::Secrets->new(project_dir => $origin);
    ok $origin_secrets->project_has_age_key, 'an initialized project has one';

    my $clone = clone_project($origin);
    my $clone_secrets = OCP::Secrets->new(project_dir => $clone);
    ok $clone_secrets->project_has_age_key,
        'and so does its clone, with .ocp/ absent';

    # age.key.enc alone is enough — the SOPS files need not be there.
    my $bare = path(tempdir(CLEANUP => 1));
    $origin->child('age.key.enc')->copy($bare->child('age.key.enc'));
    my $bare_secrets = OCP::Secrets->new(project_dir => $bare);
    ok $bare_secrets->project_has_age_key,
        'age.key.enc on its own already answers yes';

    # So is a SOPS file on its own.
    my $sops = path(tempdir(CLEANUP => 1));
    $origin->child('keys.yaml')->copy($sops->child('keys.yaml'));
    my $s = OCP::Secrets->new(project_dir => $sops);
    ok $s->project_has_age_key, 'so does a committed SOPS file';
    is $s->project_age_recipients->[0], recipient_of($origin->child('keys.yaml')),
        'and it reports which recipient it is bound to';
};

sub _have {
    my ($cmd) = @_;
    return system("command -v $cmd >/dev/null 2>&1") == 0;
}

done_testing;

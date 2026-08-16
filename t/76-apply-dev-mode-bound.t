#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Cwd qw(getcwd);

use OCP;
use OCP::Cmd::Apply;

# karr #90 — the dev-mode apply branch hit the same age-key trap #86
# closed for `ocp init`. The dev-mode branch in OCP::Cmd::Apply checks
# `has_age_key` ("is there one on this machine"), sees no, and asks
# OCP::Secrets::generate_age_key to mint a fresh pair. Once #86 put
# the safety net inside generate_age_key, that call croaks for any
# project that is already bound to an age recipient — and a --nopassword
# project can absolutely be bound, if it carries an encrypted
# secrets.yaml or kubeconfig.yaml. The croak's text tells the user to
# "Unlock the existing key with PIN1 (age.key.enc)" — advice that
# does not apply on this branch, where there is no PIN to ask for.

plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

# --------------------------------------------------------------- helpers

# Run OCP::Cmd::Apply::execute in a project dir, capturing the croak
# (via $@) and the printed output. The branch sits in execute() early,
# so we hit the croak before any of the deploy / bootstrap machinery.
sub run_apply {
    my (%args) = @_;

    my $dir = delete $args{dir};

    my $apply = OCP::Cmd::Apply->new(
        command_chain => [OCP->new],
        %args,
    );

    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";

    my $out = '';
    my $err;
    eval {
        no warnings 'redefine';
        open my $fh, '>', \$out or die "capture: $!";
        my $old = select $fh;
        eval { $apply->execute([], []) };
        $err = $@;
        select $old;
        close $fh;
        1;
    } or do {
        # capture died too; fall through to $@ below
    };

    chdir $cwd or die "chdir back: $!";

    return {
        err => $err // '',
        out => $out,
    };
}

# A minimal ocp.yaml. The exec branch reads name/cluster_exists/shh key
# path — nothing else reaches here before the age-key check.
sub write_minimal_ocp_yaml {
    my ($dir) = @_;
    $dir->child('ocp.yaml')->spew_utf8(<<'YAML');
name: devmode-clone
control_planes:
  - provider: ssh
    host: 1.2.3.4
YAML
}

# A committed secrets.yaml with the plaintext SOPS recipient block that
# project_has_age_key reads without holding any key. The body never has
# to decrypt: the whole point is that the block is honest by itself.
sub write_sops_secrets {
    my ($dir) = @_;
    $dir->child('secrets.yaml')->spew_utf8(<<'YAML');
hetzner_token: ENC[AES256_GCM,data:abc,tag:xyz,iv:aaa]
sops:
    age:
        - recipient: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          enc: |
              -----BEGIN AGE ENCRYPTED FILE-----
YAML
}

# --------------------------------------------------------- the test cases

subtest 'dev-mode apply refuses when the project is bound to an age recipient' => sub {
    # Setup: a --nopassword project whose SOPS-bound secrets.yaml was
    # committed and whose .ocp/ is missing — i.e. exactly the state a
    # colleague in a fresh clone is in. No keys.yaml (dev mode), no
    # kubeconfig.yaml (first apply, not a reconcile), no .ocp/age.key,
    # no age.key.enc (dev mode writes neither).
    my $dir = path(tempdir(CLEANUP => 1));
    write_minimal_ocp_yaml($dir);
    write_sops_secrets($dir);

    my $r = run_apply(dir => $dir->stringify);

    ok $r->{err}, 'apply died rather than generating over the binding'
        or diag $r->{out};

    like $r->{err}, qr/Project is bound.*age recipient/is,
        'the message names the binding diagnosis';
    like $r->{err}, qr/secrets\.yaml.*kubeconfig\.yaml.*age\.key\.enc/is,
        'and lists the files that are bound';
    like $r->{err}, qr/\.ocp\/age\.key/,
        'and points at the missing key file (.ocp/ is gitignored)';
    like $r->{err}, qr/PIN-protected unlock is disabled in dev mode/i,
        'and names why PIN-based unlock is not an answer here';
    like $r->{err}, qr/Restore\s+\.ocp\/age\.key/,
        'and tells the user what to do — restore .ocp/age.key';

    # The advice #86's generic croak gave — "unlock with PIN1" — does
    # not exist on this branch. If it slips back in, a dev-mode user
    # would be told to type a PIN that has nowhere to go.
    unlike $r->{err}, qr/\bRun\s+['"]?ocp init\b/,
        'and does NOT suggest ocp init (dev mode has no PIN to ask for)';
    unlike $r->{err}, qr/Unlock the existing key with PIN1/,
        'and does NOT promise PIN-based unlock — the wrong answer for dev mode';

    # The execute() return value is whatever the die escalated to. A
    # non-zero exit code is what surfaces here for a CLI invoker; the
    # `ok $err` above already proves the croak fired, and the absence
    # of those generic phrases proves it is the dev-mode message and
    # not the generic one from OCP::Secrets.
    ok $r->{err} =~ /\S/, 'a non-empty error is reported (exit non-zero)';

    # The committed material is untouched — that is the whole point of
    # failing fast.
    ok -f $dir->child('secrets.yaml'), 'secrets.yaml still exists';
    ok !-d $dir->child('.ocp'),
        'and no .ocp/ was created — nothing was devalued by this run';
};

subtest 'dev-mode apply still generates a key when the project is genuinely unbound' => sub {
    # Empty-ish project: no secrets.yaml, no keys.yaml (so dev mode),
    # no age.key.enc, no .ocp/. Only ocp.yaml and a bootstrap SSH key.
    # The original branch behaviour was correct for this case, and is
    # the one the new guard has to leave alone.
    my $dir = path(tempdir(CLEANUP => 1));
    write_minimal_ocp_yaml($dir);
    $dir->child('.ocp')->mkpath;
    $dir->child('.ocp', 'id_ed25519')->spew("FAKE\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew("FAKEPUB\n");

    my $secrets = OCP::Secrets->new(project_dir => $dir);
    ok !$secrets->has_age_key, 'precondition: no local age key';
    ok !$secrets->project_has_age_key,
        'precondition: project is not bound to a recipient either';

    # Direct test of the guard's two branches without spinning up the
    # rest of execute() — the guard reads project_has_age_key BEFORE
    # it ever touches the network or starts provisioning.
    my $generated = eval { $secrets->generate_age_key };
    ok $generated, 'an unbound project still gets a fresh keypair'
        or diag $@;

    ok -f $dir->child('.ocp', 'age.key'),
        '.ocp/age.key was written';
    ok -f $dir->child('.ocp', 'age.pub'),
        '.ocp/age.pub was written';
};

sub _have {
    my ($cmd) = @_;
    return system("command -v $cmd >/dev/null 2>&1") == 0;
}

done_testing;

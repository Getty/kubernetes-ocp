#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Cwd qw(getcwd);

use OCP;
use OCP::Cmd::Init;
use OCP::Cmd::Keys::Show;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Config;
use OCP::Keys;

# Two holes in the same seam — secure mode + the ssh provider + the two-tier
# key system — found while bringing up a real cluster:
#
#   karr #85: OCP::Cmd::Apply::Bootstrap picks .ocp/id_ed25519 unconditionally
#   for `provider: ssh`, but `ocp init` created that file only under
#   --nopassword. A secure-mode ssh project therefore had no key at all, and
#   `ocp apply` reported "SSH not reachable" — a network message for what was
#   really "nothing to authenticate with". --ssh-key was read on the same
#   dead branch, so in secure mode it was accepted and silently dropped.
#
#   karr #84: the only code that could surface a public key was
#   OCP::Keys::decrypt_all_to_disk, which had no caller and would have written
#   every PRIVATE key to .ocp/keys/ in plaintext as a side effect. There was
#   no way to answer "what do I put in authorized_keys?".
#
# The dangerous half of the fix is idempotency. A bootstrap key that already
# exists is already distributed to running machines; regenerating it locks the
# operator out of their own cluster. OCP::Secrets::generate_ssh_key unlinks
# before it generates, so "don't touch an existing key" has to be asserted,
# not assumed.

plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

my $PIN = 'test-pin-1234';

# Run OCP::Cmd::Init::execute in a fresh temp dir with both PIN prompts
# answered. Secure mode is the default — the point of these tests is the path
# every other init test skips with --nopassword.
sub run_init {
    my (%args) = @_;

    my $dir     = delete $args{dir} || tempdir(CLEANUP => 1);
    my $prompts = 0;

    my $init = OCP::Cmd::Init->new(
        command_chain => [OCP->new],
        nogit         => 1,
        name          => 'securetest',
        _interactive  => 0,
        %args,
    );

    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";

    my $out = '';
    my $err = eval {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub { $prompts++; $PIN };
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
        err     => $err,
        prompts => $prompts,
    };
}

# ---------------------------------------------------------------- karr #85

subtest 'secure mode creates the bootstrap key the deploy path requires' => sub {
    my $r = run_init(provider => 'ssh', host => 'cp.example.test');
    is $r->{err}, '', 'secure init completed' or diag $r->{out};

    my $priv = $r->{dir}->child('.ocp', 'id_ed25519');
    my $pub  = $r->{dir}->child('.ocp', 'id_ed25519.pub');

    ok -f $priv, '.ocp/id_ed25519 exists after a secure-mode init'
        or diag $r->{out};
    ok -f $pub,  '.ocp/id_ed25519.pub exists too — init prints it for authorized_keys';
    like $pub->slurp, qr/\Assh-ed25519 /, 'and it really is an ed25519 public key';

    # The two-tier system is additional, not replaced.
    ok -f $r->{dir}->child('keys.yaml'), 'keys.yaml is still written';
    is $r->{prompts}, 4, 'PIN1 + PIN2, each confirmed — no extra prompt was added';

    my $keys = OCP::Keys->new(project_dir => $r->{dir});
    my %purpose = map { ($_->{purpose} // '') => 1 } @{ $keys->list_keys };
    ok $purpose{admin},      'admin key still generated';
    ok $purpose{automation}, 'robo key still generated';
};

subtest 'the bootstrap key is created only where something reads it' => sub {
    # The gate is the same condition OCP::ClusterKey answers with, dev mode
    # || ssh. A secure Hetzner control plane gets the admin key uploaded via
    # the API and never sees this file, so creating one there would be inert.
    #
    # It would also be actively misleading now: since karr #87, Update,
    # Node::Add and the reconcile path's Rex remedy all go through
    # OCP::ClusterKey and take the admin key on this combination. A bootstrap
    # key sitting here would be a file that looks like the answer and is not
    # — t/71 asserts that even when one exists, the admin key still wins.
    my $hetzner = run_init(provider => 'hetzner');
    is $hetzner->{err}, '', 'secure hetzner init completed' or diag $hetzner->{out};
    ok !-f $hetzner->{dir}->child('.ocp', 'id_ed25519'),
        'no bootstrap key for secure + hetzner';
    ok -f $hetzner->{dir}->child('keys.yaml'),
        'the two-tier keys that path DOES use are there';

    my $ssh = run_init(provider => 'ssh', host => 'cp.example.test');
    ok -f $ssh->{dir}->child('.ocp', 'id_ed25519'),
        'but secure + ssh gets one';

    # Dev mode needs it for EVERY provider: OCP::Cmd::Apply's --nopassword
    # path dies outright when .ocp/id_ed25519 is missing, whatever the
    # provider. Gating on ssh alone would have broken that.
    my $dev = run_init(provider => 'hetzner', nopassword => 1);
    is $dev->{err}, '', 'dev-mode hetzner init completed' or diag $dev->{out};
    ok -f $dev->{dir}->child('.ocp', 'id_ed25519'),
        '--nopassword still gets a key on hetzner — the dev path requires it';
};

subtest 'switching ocp.yaml to provider ssh and re-running init picks it up' => sub {
    # _provider answers "what should a NEW ocp.yaml say" and defaults to
    # hetzner, so a bare re-run must not be the thing that decides this.
    my $r = run_init(provider => 'hetzner');
    ok !-f $r->{dir}->child('.ocp', 'id_ed25519'), 'no key yet';

    my $file = $r->{dir}->child('ocp.yaml');
    my $spec = $file->slurp;
    $spec =~ s/provider: hetzner/provider: ssh/;
    $file->spew($spec);

    # No --provider: exactly what someone re-running `ocp init` would type.
    my $again = run_init(dir => $r->{dir}->stringify);
    is $again->{err}, '', 're-run completed' or diag $again->{out};
    ok -f $r->{dir}->child('.ocp', 'id_ed25519'),
        'the key appears without having to repeat --provider ssh';
};

subtest 'the bootstrap key is NOT encrypted — apply must read it unprompted' => sub {
    my $r = run_init(provider => 'ssh', host => 'cp.example.test');
    my $priv = $r->{dir}->child('.ocp', 'id_ed25519');

    like $priv->slurp, qr/-----BEGIN OPENSSH PRIVATE KEY-----/,
        'usable as-is: no age envelope, no PIN2 layer';
    unlike $priv->slurp, qr/BEGIN AGE ENCRYPTED FILE/,
        'specifically not age-encrypted — that would re-block the bootstrap';
};

subtest 'an existing bootstrap key is never regenerated, whatever the provider' => sub {
    # This is the cp-lab situation: a key made by hand, its public half
    # already in authorized_keys on six machines. Re-running init must leave
    # it exactly as it is. The idempotency guard sits in FRONT of the provider
    # gate on purpose — a hetzner project that has a bootstrap key has it for
    # a reason, and must not become fair game just because nothing would
    # create one there today.
    for my $case (
        { provider => 'ssh', host => 'cp.example.test' },
        { provider => 'hetzner' },
        { provider => 'hetzner', nopassword => 1 },
    ) {
        my $label = join ' + ', $case->{provider},
            ($case->{nopassword} ? 'dev' : 'secure');

        my $dir = tempdir(CLEANUP => 1);
        path($dir)->child('.ocp')->mkpath;

        my $priv = path($dir)->child('.ocp', 'id_ed25519');
        my $pub  = path($dir)->child('.ocp', 'id_ed25519.pub');
        $priv->spew("HANDMADE PRIVATE KEY - DO NOT TOUCH\n");
        $pub->spew("ssh-ed25519 AAAAhandmade handmade\n");

        my $r = run_init(dir => $dir, %$case);
        is $r->{err}, '', "$label: init completed over an existing key"
            or diag $r->{out};

        is $priv->slurp, "HANDMADE PRIVATE KEY - DO NOT TOUCH\n",
            "$label: the existing private key is byte-identical afterwards";
        is $pub->slurp, "ssh-ed25519 AAAAhandmade handmade\n",
            "$label: and so is its public half";
        like $r->{out}, qr/SSH bootstrap key exists/,
            "$label: init says it kept the key rather than staying silent";
    }
};

subtest '--ssh-key is honoured in secure mode instead of being swallowed' => sub {
    # Silently ignored options are a repeat offender in this repo (karr #67,
    # #37). --ssh-key was declared, documented, and read only on the
    # --nopassword branch.
    my $ext = path(tempdir(CLEANUP => 1));
    $ext->child('mykey')->spew("EXTERNAL PRIVATE KEY\n");
    $ext->child('mykey.pub')->spew("ssh-ed25519 AAAAexternal external\n");

    my $r = run_init(
        provider => 'ssh',
        host     => 'cp.example.test',
        ssh_key  => $ext->child('mykey')->stringify,
    );
    is $r->{err}, '', 'init completed' or diag $r->{out};

    is $r->{dir}->child('.ocp', 'id_ed25519')->slurp, "EXTERNAL PRIVATE KEY\n",
        'the supplied key became the bootstrap key';
    is $r->{dir}->child('.ocp', 'id_ed25519.pub')->slurp,
        "ssh-ed25519 AAAAexternal external\n",
        'its public half came along';
};

subtest '--ssh-key on a provider that has no bootstrap key is refused out loud' => sub {
    # Same rule as everywhere else in this repo: evaluate the option or say
    # it does not apply. Never accept it and do nothing.
    my $ext = path(tempdir(CLEANUP => 1));
    $ext->child('mykey')->spew("EXTERNAL PRIVATE KEY\n");

    my $r = run_init(
        provider => 'hetzner',
        ssh_key  => $ext->child('mykey')->stringify,
    );
    is $r->{err}, '', 'init still completes' or diag $r->{out};

    ok !-f $r->{dir}->child('.ocp', 'id_ed25519'),
        'nothing was written where nothing would read it';
    like $r->{out}, qr/--ssh-key is not used with provider 'hetzner'/,
        'and the operator is told the flag did not apply';
    like $r->{out}, qr/admin key/,
        'with the key that provider actually uses named';
};

subtest '--ssh-key against an existing key is refused loudly, not obeyed' => sub {
    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('.ocp')->mkpath;
    path($dir)->child('.ocp', 'id_ed25519')->spew("IN SERVICE\n");

    my $ext = path(tempdir(CLEANUP => 1));
    $ext->child('other')->spew("REPLACEMENT\n");

    my $r = run_init(
        dir      => $dir,
        provider => 'ssh',
        host     => 'cp.example.test',
        ssh_key  => $ext->child('other')->stringify,
    );

    is path($dir)->child('.ocp', 'id_ed25519')->slurp, "IN SERVICE\n",
        'the key in service wins over the flag — no silent lockout';
    like $r->{out}, qr/was NOT used/,
        'and the operator is told the flag was not applied';
    like $r->{out}, qr/--force/, 'with the way to override named';

    # --force is the escape hatch, and it must actually work.
    my $forced = run_init(
        dir      => $dir,
        provider => 'ssh',
        host     => 'cp.example.test',
        force    => 1,
        ssh_key  => $ext->child('other')->stringify,
    );
    is path($dir)->child('.ocp', 'id_ed25519')->slurp, "REPLACEMENT\n",
        '--force replaces it';
    diag $forced->{out} if $forced->{err};
};

subtest 'what init writes is what Bootstrap reaches for (provider: ssh)' => sub {
    # The two halves of #85 in one assertion: Bootstrap::setup_ssh_key picks
    # ssh_private_key_path for provider ssh regardless of mode, so that file
    # has to exist after a secure init.
    my $r = run_init(provider => 'ssh', host => 'cp.example.test');
    is $r->{err}, '', 'secure init with provider ssh completed' or diag $r->{out};

    my $config = OCP::Config->new(
        file => $r->{dir}->child('ocp.yaml')->stringify,
    );
    is $config->control_planes->[0]{provider}, 'ssh',
        'ocp.yaml really names the ssh provider';

    my $apply = FakeApply->new;
    OCP::Cmd::Apply::Bootstrap::setup_ssh_key($apply, $config);

    is $apply->_ssh_key_path, $config->ssh_private_key_path,
        'Bootstrap picks the bootstrap key for provider ssh';
    ok -f $apply->_ssh_key_path,
        'and the file it picked exists — this is what "SSH not reachable" really was';

    like $r->{out}, qr/Add this public key to your server/,
        'secure-mode init names a key to distribute (it used to print nothing)';
    like $r->{out}, qr/ocp keys show --purpose admin/,
        'and points at the admin key that ocp ssh will need';
};

# ---------------------------------------------------------------- karr #84

subtest 'ocp keys show prints the admin public key' => sub {
    my $r = run_init();
    is $r->{err}, '', 'init completed' or diag $r->{out};

    my ($out, $err, $prompts, $diag) = run_keys_show($r->{dir});

    my $keys = OCP::Keys->new(project_dir => $r->{dir});
    my ($admin) = grep { ($_->{purpose} // '') eq 'admin' } @{ $keys->list_keys };
    ok $admin, 'there is an admin key to show';

    is $err, '', 'the command succeeded';
    like $out, qr/\Assh-ed25519 /, 'stdout is a public key and starts with one';
    is $out, $admin->{public} . "\n",
        'stdout is exactly the admin public key — pipeable into authorized_keys';
    like $diag, qr/\Q$admin->{name}\E/,
        'the key name goes to stderr, where a redirect cannot pick it up';
};

subtest 'ocp keys show never asks for PIN2, and never emits a private key' => sub {
    my $r = run_init();

    my ($out, $err, $prompts) = run_keys_show($r->{dir});

    is $prompts, 0,
        'no password prompt at all: public keys sit behind the age layer only';

    # The load-bearing assertion. A command that prints key material must be
    # provably unable to print the secret half.
    unlike $out, qr/PRIVATE KEY/,
        'no private key marker on stdout';
    unlike $out, qr/BEGIN AGE ENCRYPTED FILE/,
        'not even the encrypted private blob leaks out';

    my $keys = OCP::Keys->new(project_dir => $r->{dir});
    for my $key (@{ $keys->list_keys }) {
        my $private = $keys->decrypt_key(
            $key->{name},
            ($key->{purpose} // '') eq 'automation' ? () : $PIN,
        )->{private};
        unlike $out, qr/\Q$private\E/,
            "the decrypted private half of $key->{name} is nowhere in the output";
        unlike $out, qr/\Q$key->{private}\E/,
            "nor is its stored ciphertext";
    }
};

subtest 'ocp keys show works before any cluster exists' => sub {
    # `ocp ssh` refuses without a kubeconfig, which is right for a command
    # that connects to a node. This one answers a question that only matters
    # BEFORE the first apply.
    my $r = run_init();
    ok !-f $r->{dir}->child('kubeconfig.yaml'), 'no cluster deployed';

    my ($out, $err) = run_keys_show($r->{dir});
    is $err, '', 'it does not demand a cluster';
    like $out, qr/\Assh-ed25519 /, 'and still prints the key';
};

subtest 'ocp keys show selects by purpose and by name' => sub {
    my $r = run_init();
    my $keys = OCP::Keys->new(project_dir => $r->{dir});
    my ($robo) = grep { ($_->{purpose} // '') eq 'automation' } @{ $keys->list_keys };

    my ($by_purpose) = run_keys_show($r->{dir}, purpose => 'automation');
    is $by_purpose, $robo->{public} . "\n", '--purpose automation picks the robo key';

    my ($by_name) = run_keys_show($r->{dir}, name => $robo->{name});
    is $by_name, $robo->{public} . "\n", '--name picks the same key';

    my (undef, $missing) = run_keys_show($r->{dir}, purpose => 'nonesuch');
    like $missing, qr/No key with purpose 'nonesuch'/,
        'an unknown purpose is an error, not empty output';

    my (undef, $unnamed) = run_keys_show($r->{dir}, name => 'no-such-key');
    like $unnamed, qr/No key named 'no-such-key'/, 'so is an unknown name';
};

subtest 'ocp keys show explains itself in a --nopassword project' => sub {
    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('.ocp')->mkpath;

    my (undef, $err) = run_keys_show(path($dir));
    like $err, qr/No keys\.yaml found/, 'says what is missing';
    like $err, qr/\.ocp\/id_ed25519\.pub/,
        'and where a dev-mode project keeps its key instead';
};

subtest 'decrypt_all_to_disk is gone, POD and all' => sub {
    ok !OCP::Keys->can('decrypt_all_to_disk'),
        'the uncalled method that would have spilled private keys to disk is removed';
    ok !OCP::Keys->can('keys_dir'),
        'and the .ocp/keys/ attribute that only it used';

    # The claim is about the documentation, not about the file: a tombstone
    # comment in the code saying why the method went is worth keeping.
    my $source = path('lib/OCP/Keys.pm')->slurp;
    my ($pod) = $source =~ /^__END__$(.*)/ms;
    ok $pod, 'found the POD section';

    unlike $pod, qr/decrypt_all_to_disk/,
        'no POD left promising a .ocp/keys/ layout nothing produces';
    unlike $pod, qr/^\s*public: ssh-ed25519 AAAA\.\.\.$/m,
        'the FILE FORMAT example no longer shows public: as plaintext on disk';
    like $pod, qr/ENCRYPTION LAYERS/,
        'and it now states which field the PIN2 layer actually covers';
};

# --------------------------------------------------------------- helpers

# Run OCP::Cmd::Keys::Show against a project dir. Returns (stdout, error,
# prompt count, stderr) — prompts are counted so "needs no PIN2" is
# measurable, and the streams are kept apart because the split is the feature:
# key material on stdout, everything else on stderr.
sub run_keys_show {
    my ($dir, %args) = @_;

    my $prompts = 0;
    my $show = OCP::Cmd::Keys::Show->new(
        command_chain => [OCP->new],
        %args,
    );

    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";

    my ($out, $diag) = ('', '');
    {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub { $prompts++; $PIN };

        open my $fh,  '>', \$out  or die "capture stdout: $!";
        open my $efh, '>', \$diag or die "capture stderr: $!";
        my $old = select $fh;
        local *STDERR = $efh;
        eval { $show->execute([], []) };
        select $old;
        close $fh;
        close $efh;
    }
    my $err = $@ // '';

    chdir $cwd or die "chdir back: $!";

    return ($out, $err, $prompts, $diag);
}

{
    # Stand-in for OCP::Cmd::Apply: setup_ssh_key only ever touches the
    # _ssh_key_path accessor.
    package FakeApply;
    sub new { bless {}, shift }
    sub _ssh_key_path {
        my $self = shift;
        $self->{path} = shift if @_;
        return $self->{path};
    }
}

sub _have {
    my ($cmd) = @_;
    return system("command -v $cmd >/dev/null 2>&1") == 0;
}

done_testing;

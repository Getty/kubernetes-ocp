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

# What `ocp init` writes, and what it tells the operator to distribute.
#
# THE DECISION THIS FILE NOW ENCODES: secure mode has two key tiers and only
# two — robo (automation, no PIN2) and admin (age + PIN2). The bootstrap key
# .ocp/id_ed25519 is dev mode's single credential and exists nowhere else. It
# used to be created for `provider: ssh` in both modes (karr #85), on the
# theory that a pre-existing machine can only trust what a human put there by
# hand. That theory was wrong about which key the human puts there: the admin
# public key is printable (`ocp keys show --purpose admin`), so a human can
# distribute exactly the key OCP uploads through the Hetzner API. The provider
# decides who distributes, not what.
#
# So the claims here are mirror images of what they were:
#
#   * secure + ssh writes NO bootstrap key, and the report at the end names
#     the ADMIN public key — prominently, as the thing to paste. A new
#     secure-mode project that were told to distribute .ocp/id_ed25519.pub
#     would be born locked out.
#   * --ssh-key does not apply in secure mode and says so.
#   * dev mode is untouched in every respect.
#
# Unchanged and load-bearing: an EXISTING bootstrap key is never regenerated
# and never removed, in either mode. Machines out there have its public half
# in authorized_keys; migrating means adding the admin key, never deleting
# anything locally. OCP::Secrets::generate_ssh_key unlinks before it
# generates, so "don't touch an existing key" has to be asserted, not assumed.
#
# The other half of the file is karr #84: `ocp keys show`, the command that
# makes the admin public key printable at all. Before it, the only code that
# could surface a public key was OCP::Keys::decrypt_all_to_disk, which had no
# caller and would have written every PRIVATE key to .ocp/keys/ in plaintext
# as a side effect.

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

# ------------------------------------------- secure mode has two tiers only

subtest 'secure + ssh writes no bootstrap key and hands out the admin key' => sub {
    my $r = run_init(provider => 'ssh', host => 'cp.example.test');
    is $r->{err}, '', 'secure init completed' or diag $r->{out};

    ok !-f $r->{dir}->child('.ocp', 'id_ed25519'),
        'no bootstrap key — secure mode does not have that tier'
        or diag $r->{out};
    ok !-f $r->{dir}->child('.ocp', 'id_ed25519.pub'),
        'not even a public half lying around to be pasted by mistake';

    ok -f $r->{dir}->child('keys.yaml'), 'keys.yaml is written';
    is $r->{prompts}, 4, 'PIN1 + PIN2, each confirmed — no extra prompt was added';

    my $keys = OCP::Keys->new(project_dir => $r->{dir});
    my %purpose = map { ($_->{purpose} // '') => 1 } @{ $keys->list_keys };
    ok $purpose{admin},      'admin key generated';
    ok $purpose{automation}, 'robo key generated';

    # The load-bearing part for a NEW project: what does init tell the
    # operator to put in authorized_keys? If that is anything other than the
    # admin key, the cluster is born locked out — OCP will only ever offer
    # the admin key afterwards.
    my ($admin) = grep { ($_->{purpose} // '') eq 'admin' } @{ $keys->list_keys };
    like $r->{out}, qr/Add the admin public key to your server/,
        'the report names the admin key as the one to distribute';
    like $r->{out}, qr/\Q$admin->{public}\E/,
        'and prints that exact key, ready to paste';
    like $r->{out}, qr/ocp keys show --purpose admin/,
        'plus the command that prints it again';

    unlike $r->{out}, qr/id_ed25519/,
        'the bootstrap key is not mentioned at all — it does not exist here';
};

subtest 'the bootstrap key is created only under --nopassword' => sub {
    # The gate is now the mode alone, matching OCP::ClusterKey: dev mode
    # reaches for this file on every provider, secure mode never does.
    for my $provider (qw(hetzner ssh local)) {
        my %addr = $provider eq 'ssh' ? (host => 'cp.example.test') : ();

        my $secure = run_init(provider => $provider, %addr);
        is $secure->{err}, '', "secure + $provider: init completed"
            or diag $secure->{out};
        ok !-f $secure->{dir}->child('.ocp', 'id_ed25519'),
            "secure + $provider: no bootstrap key";
        ok -f $secure->{dir}->child('keys.yaml'),
            "secure + $provider: the two keys that ARE used are there";

        # Dev mode needs it for EVERY provider: OCP::Cmd::Apply's
        # --nopassword path dies outright when .ocp/id_ed25519 is missing.
        my $dev = run_init(provider => $provider, %addr, nopassword => 1);
        is $dev->{err}, '', "dev + $provider: init completed" or diag $dev->{out};
        ok -f $dev->{dir}->child('.ocp', 'id_ed25519'),
            "dev + $provider: --nopassword still gets its one key";
    }
};

subtest 're-running init in an ssh project reports the admin key, not a new one' => sub {
    # _provider answers "what should a NEW ocp.yaml say" and defaults to
    # hetzner, so a bare re-run must not be the thing that decides this —
    # _effective_provider reads the ocp.yaml that will survive the run. That
    # used to matter because a key got created; it now matters because this
    # re-run is how an operator asks "what do I have to do?" mid-migration.
    my $r = run_init(provider => 'hetzner');

    my $file = $r->{dir}->child('ocp.yaml');
    my $spec = $file->slurp;
    $spec =~ s/provider: hetzner/provider: ssh/;
    $file->spew($spec);

    # No --provider: exactly what someone re-running `ocp init` would type.
    my $again = run_init(dir => $r->{dir}->stringify);
    is $again->{err}, '', 're-run completed' or diag $again->{out};

    ok !-f $r->{dir}->child('.ocp', 'id_ed25519'),
        'still no bootstrap key — nothing would read one';
    like $again->{out}, qr/Add the admin public key to your server/,
        'but the ssh setup instructions appear without repeating --provider ssh';
};

subtest 'the dev-mode key is NOT encrypted — apply must read it unprompted' => sub {
    my $r = run_init(provider => 'ssh', host => 'cp.example.test', nopassword => 1);
    my $priv = $r->{dir}->child('.ocp', 'id_ed25519');

    like $priv->slurp, qr/-----BEGIN OPENSSH PRIVATE KEY-----/,
        'usable as-is: no age envelope, no PIN2 layer';
    unlike $priv->slurp, qr/BEGIN AGE ENCRYPTED FILE/,
        'specifically not age-encrypted — that would re-block the bootstrap';

    like $r->{out}, qr/Add the bootstrap public key to your server/,
        'and dev mode still names it as the key to distribute';

    my $pub = $r->{dir}->child('.ocp', 'id_ed25519.pub')->slurp;
    chomp $pub;
    like $r->{out}, qr/\Q$pub\E/, 'printing the key itself, as before';
};

subtest 'an existing bootstrap key is never regenerated and never removed' => sub {
    # This is the cp-lab situation: a key whose public half is already in
    # authorized_keys on six machines. Re-running init must leave it exactly
    # as it is. The idempotency guard sits in FRONT of the mode gate on
    # purpose — a secure-mode project that has a bootstrap key has it because
    # its machines were set up before the tier was dropped, and taking it away
    # is the one thing that could make the migration unrecoverable.
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

        # In secure mode the file is kept but unused, and an operator has to
        # hear that — otherwise the key that used to open every machine goes
        # quiet with no explanation anywhere.
        next if $case->{nopassword};
        like $r->{out}, qr/LEGACY/,
            "$label: and reports it as legacy, not as a working credential";
        like $r->{out}, qr/ocp keys show --purpose admin/,
            "$label: naming what to distribute instead";
    }
};

subtest '--ssh-key is honoured in dev mode, where the key it names is used' => sub {
    my $ext = path(tempdir(CLEANUP => 1));
    $ext->child('mykey')->spew("EXTERNAL PRIVATE KEY\n");
    $ext->child('mykey.pub')->spew("ssh-ed25519 AAAAexternal external\n");

    my $r = run_init(
        provider   => 'ssh',
        host       => 'cp.example.test',
        nopassword => 1,
        ssh_key    => $ext->child('mykey')->stringify,
    );
    is $r->{err}, '', 'init completed' or diag $r->{out};

    is $r->{dir}->child('.ocp', 'id_ed25519')->slurp, "EXTERNAL PRIVATE KEY\n",
        'the supplied key became the bootstrap key';
    is $r->{dir}->child('.ocp', 'id_ed25519.pub')->slurp,
        "ssh-ed25519 AAAAexternal external\n",
        'its public half came along';
};

subtest '--ssh-key in secure mode is refused out loud, on every provider' => sub {
    # Silently ignored options are a repeat offender in this repo (karr #67,
    # #37). The flag was once honoured for secure + ssh, because that
    # combination had a bootstrap key; now nothing in secure mode reads one,
    # so the rule is the other rule this repo keeps: evaluate the option or
    # say it does not apply. Never accept it and do nothing.
    for my $provider (qw(hetzner ssh)) {
        my %addr = $provider eq 'ssh' ? (host => 'cp.example.test') : ();

        my $ext = path(tempdir(CLEANUP => 1));
        $ext->child('mykey')->spew("EXTERNAL PRIVATE KEY\n");

        my $r = run_init(
            provider => $provider,
            %addr,
            ssh_key  => $ext->child('mykey')->stringify,
        );
        is $r->{err}, '', "$provider: init still completes" or diag $r->{out};

        ok !-f $r->{dir}->child('.ocp', 'id_ed25519'),
            "$provider: nothing was written where nothing would read it";
        like $r->{out}, qr/--ssh-key is not used in secure mode/,
            "$provider: the operator is told the flag did not apply";
        like $r->{out}, qr/ocp keys show --purpose admin/,
            "$provider: with the key that IS used named, and how to print it";
    }
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

subtest 'what init tells the operator to install is what Bootstrap presents' => sub {
    # End to end over real key material: the public key `ocp init` prints for
    # authorized_keys must be the public half of the private key
    # Bootstrap::setup_ssh_key hands to Rex and ssh. If those two ever drift
    # apart, `ocp apply` fails as "SSH not reachable" — a network message for
    # what is really "the machine was given a different key".
    my $r = run_init(provider => 'ssh', host => 'cp.example.test');
    is $r->{err}, '', 'secure init with provider ssh completed' or diag $r->{out};

    my $config = OCP::Config->new(
        file => $r->{dir}->child('ocp.yaml')->stringify,
    );
    is $config->control_planes->[0]{provider}, 'ssh',
        'ocp.yaml really names the ssh provider';

    my $keys = OCP::Keys->new(project_dir => $r->{dir});
    my ($admin) = grep { ($_->{purpose} // '') eq 'admin' } @{ $keys->list_keys };

    my $cwd = getcwd();
    chdir $r->{dir} or die "chdir: $!";
    my $apply = FakeApply->new;
    # pin2 in hand: no terminal under prove, and the prompt itself is t/71's
    # subject. Everything else here is real — real keys.yaml, real age key.
    my $key = eval {
        OCP::Cmd::Apply::Bootstrap::setup_ssh_key($apply, $config, pin2 => $PIN)
    };
    my $err = $@;
    chdir $cwd or die "chdir back: $!";

    is $err, '', 'setup_ssh_key succeeded' or diag $err;
    is $key->origin, 'admin',
        'Bootstrap presents the admin key on provider ssh too';
    isnt $apply->_ssh_key_path, $config->ssh_private_key_path,
        'not .ocp/id_ed25519 — which this project does not even have';
    ok -f $apply->_ssh_key_path, 'the file it picked exists';

    is $key->content, $keys->decrypt_key($admin->{name}, $PIN)->{private},
        'and holds the private half of the admin key';
    like $r->{out}, qr/\Q$admin->{public}\E/,
        'whose public half is exactly what init told the operator to install';
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

    # Both claims are the ones this test always made — an unknown purpose and
    # an unknown name are errors, not empty output. karr #103 kept them and
    # added the second half of the house shape: the rejection now also says
    # what would have worked. Against a REAL keys.yaml here, so the listing
    # is the project's actual keys rather than a fixture's.
    my (undef, $missing) = run_keys_show($r->{dir}, purpose => 'nonesuch');
    like $missing, qr/^Unknown key purpose 'nonesuch'\./,
        'an unknown purpose is an error, not empty output';
    like $missing, qr/^Available: .*\badmin\b/m,
        'and names the purposes this project has keys for';

    my (undef, $unnamed) = run_keys_show($r->{dir}, name => 'no-such-key');
    like $unnamed, qr/^Unknown key 'no-such-key'\./, 'so is an unknown name';
    like $unnamed, qr/^Available: .*\Q$robo->{name}\E \(purpose automation\)/m,
        'and names the keys that exist, with their purpose';

    # The listing must never carry key material: this command's contract is
    # that STDOUT is the key and nothing else (karr #84), and a rejection is
    # not the place to break it.
    unlike $unnamed, qr/\Q$robo->{public}\E/, 'no public half in the listing';
    unlike $unnamed, qr/ssh-ed25519|ssh-rsa|BEGIN [A-Z ]*PRIVATE KEY/,
        'no key material of any kind';
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

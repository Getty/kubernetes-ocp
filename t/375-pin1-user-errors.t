#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

#
# k375: a wrong PIN1 was reported as an internal error. OCP::Password croaked
# "Decryption failed. Wrong password?", the croak carried " at FILE line N.",
# and the dispatcher (OCP.pm _clean_message) labels that internal and sends
# the user to --verbose for a stack trace -- for the commonest mistake there
# is. The same was true of the other ways the PIN1 path fails for the user.
# The claims:
#   1. a wrong PIN1 dies as a user error -- "message\n", no Perl location --
#      that says PIN1 does not open age.key.enc, to retype it, and that a
#      forgotten one cannot be recovered; nothing is written. The same for an
#      empty PIN1 and an empty age.key.enc, each with its own message, and for
#      a key the project's files are not bound to;
#   2. no key at all: a clone of a dev-mode project gets the refusal that says
#      where its key is (k370), not "Run 'ocp init'"; a project with nothing
#      encrypted yet is told to run ocp init -- both as user errors;
#   3. through bin/ocp --pins-stdin: STDERR has "Error: <that message>", no
#      "This is an internal error", no Perl location; STDOUT has nothing;
#   4. a command that needs the cluster API, on a project with no
#      kubeconfig.yaml, says so -- not "Cannot decrypt kubeconfig.yaml. Make
#      sure .ocp/age.key exists.", which named neither the cause nor the fix.
#

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{HETZNER_API_TOKEN};

my $PIN1   = 'pin1-k375';
my $PIN2   = 'pin2-k375';
my $PROMPT = 'Enter PIN1 (cluster access): ';

my $KUBECONFIG = join "\n",
    'apiVersion: v1', 'kind: Config', 'current-context: k375',
    'clusters:', '- name: k375', '  cluster:', '    server: https://127.0.0.1:9',
    '    insecure-skip-tls-verify: true',
    'users:', '- name: k375', '  user:', '    token: t',
    'contexts:', '- name: k375', '  context:', '    cluster: k375', '    user: k375', '';

# A project as the machine that made it has it. secure => 1: the project key
# behind PIN1 in age.key.enc and an admin key behind PIN2; without it, dev
# mode: the key in .ocp/ alone. kubeconfig => 0 leaves kubeconfig.yaml out,
# as before the first apply. Nothing here may reach a network: the API is
# 127.0.0.1:9, the machine a .invalid name.
sub origin {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($o{pin1} // $PIN1) if $o{secure};

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k375', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k375\n", public => 'ssh-ed25519 AAAAadmin k375', pin2 => $PIN2)
        if $o{secure};
    $keys->add_key(name => 'robo-ssh-k375', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO PRIVATE k375\n", public => 'ssh-ed25519 AAAArobo k375');

    $s->create_secrets(registry_password => 'pw-k375');
    $s->save_kubeconfig($KUBECONFIG) unless defined $o{kubeconfig} && !$o{kubeconfig};
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k375',
        control_planes => { provider => 'ssh', host => 'cp.k375.invalid' },
        robocop        => { enabled => 1, security_level => 'inject' },
    });
    return $dir;
}

# What a clone gets: every committed file, no .ocp/.
sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

# Run $code with every PIN prompt answered by $pin; the prompts asked, and
# what $code died with ('' when it did not).
sub prompted {
    my ($pin, $code) = @_;
    my @asked;
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { push @asked, $_[0]; $pin };
    my $died = eval { $code->(); 1 } ? '' : "$@";
    return (\@asked, $died);
}

# A message for the user: ends in a newline, carries no Perl location -- what
# the dispatcher does not call an internal error.
sub user_error_ok {
    my ($err, $what) = @_;
    like $err, qr/\n\z/, "$what: a message that ends in a newline";
    unlike $err, qr/ at \S+ line \d+/, "$what: no Perl location";
}

my $secure    = origin(secure => 1);
my $other     = origin(secure => 1, pin1 => 'pin1-other-k375');
my $dev       = origin();
my $dev_no_kc = origin(kubeconfig => 0);

# The three ways into the PIN1 prompt: the cached unlock, the in-memory one
# (k349), and a read that unlocks first (k370).
my @unlocks = (
    [ ensure_age_key  => sub { $_[0]->ensure_age_key } ],
    [ unlock_age_key  => sub { $_[0]->unlock_age_key } ],
    [ read_kubeconfig => sub { $_[0]->read_kubeconfig } ],
);

for my $u (@unlocks) {
    my ($name, $call) = @$u;

    subtest "$name: a wrong PIN1 is a user error, and nothing is written" => sub {
        my $clone = clone_of($secure);
        my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
        my ($asked, $err) = prompted('not-the-pin', sub { $call->($s) });
        is_deeply $asked, [$PROMPT], 'PIN1 asked';
        like $err, qr/\APIN1 does not open age\.key\.enc\. Nothing was unlocked, nothing written\.\n/,
            'what failed';
        like $err, qr/Run the command again and retype PIN1/, 'what to do';
        like $err, qr/--pins-stdin/, 'and where, when it came from STDIN';
        like $err, qr/forgotten PIN1 cannot be\s+recovered/, 'what a forgotten one means';
        like $err, qr{docs/security\.md}, 'with where that is written down';
        user_error_ok($err, $name);
        ok !-e $clone->child('.ocp'), 'no .ocp/';
        ok !defined $s->age_key, 'no key in memory';
    };
}

subtest 'an empty PIN1 says it was empty, not that it was wrong' => sub {
    for my $pin ('', undef) {
        my $label = defined $pin ? "''" : 'undef';
        my $clone = clone_of($secure);
        my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
        my (undef, $err) = prompted($pin, sub { $s->ensure_age_key });
        like $err, qr/\ANo PIN1 given, so age\.key\.enc stays locked\./, "$label: said";
        like $err, qr/enter PIN1/, "$label: what to do";
        user_error_ok($err, $label);
        ok !-e $clone->child('.ocp'), "$label: no .ocp/";
    }
};

subtest 'an empty age.key.enc says so, and where to get it back' => sub {
    my $clone = clone_of($secure);
    $clone->child('age.key.enc')->spew('');
    my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    my (undef, $err) = prompted($PIN1, sub { $s->ensure_age_key });
    like $err, qr/\Aage\.key\.enc is empty: there is no key in it for PIN1 to open\./, 'said';
    like $err, qr/git checkout -- age\.key\.enc/, 'restore it from git';
    unlike $err, qr/PIN1 does not open/, 'not blamed on PIN1';
    user_error_ok($err, 'empty age.key.enc');
    ok !-e $clone->child('.ocp'), 'no .ocp/';
};

subtest "another project's age.key.enc, opened with its PIN1: a user error naming both keys" => sub {
    my $clone = clone_of($secure);
    $other->child('age.key.enc')->copy($clone->child('age.key.enc'));
    my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    my (undef, $err) = prompted('pin1-other-k375', sub { $s->ensure_age_key });
    like $err, qr/\AThis age key does not belong to this project\./, 'said';
    like $err, qr/The key opens:.*\n.*needs:/s, 'both recipients named';
    like $err, qr/Nothing was done\. Use the key those files name\.\n\z/, 'and what to do';
    user_error_ok($err, 'foreign key');
    ok !-e $clone->child('.ocp'), 'no .ocp/';
};

subtest 'no key at all: a dev-mode clone is told where its key is, not to run ocp init' => sub {
    my $clone = clone_of($dev);
    ok !-e $clone->child('age.key.enc'), 'precondition: no age.key.enc (dev mode)';
    my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    my ($asked, $err) = prompted($PIN1, sub { $s->ensure_age_key });
    is_deeply $asked, [], 'no PIN1 asked: there is nothing to unlock';
    like $err, qr/\AERROR: \S+\.yaml is encrypted, and this checkout has no age key to open it/,
        'the refusal that names a committed file';
    like $err, qr/copy \.ocp\/age\.key from whoever set the project up/, 'and where the key is';
    unlike $err, qr/Run 'ocp init'/, "not 'Run ocp init': a new key opens none of them";
    user_error_ok($err, 'dev-mode clone');
    ok !-e $clone->child('.ocp'), 'no .ocp/';
};

subtest 'no key at all, nothing encrypted yet: run ocp init' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, { name => 'k375' });
    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    my (undef, $err) = prompted($PIN1, sub { $s->ensure_age_key });
    like $err, qr/\AERROR: This project has no age key: no \.ocp\/age\.key, no age\.key\.enc,/,
        'said';
    like $err, qr/Run 'ocp init' to set it up\.\n\z/, 'and what to do';
    user_error_ok($err, 'uninitialised project');
};

#
# Through bin/ocp, as the user meets it.
#

my $bin = path('bin/ocp')->absolute;
my $lib = path('lib')->absolute;

sub run_ocp {
    my ($dir, $stdin, @argv) = @_;
    my ($in, $out, $err) = map { Path::Tiny->tempfile } 1 .. 3;
    $in->spew($stdin);
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        delete $ENV{KUBECONFIG};
        open STDIN,  '<', "$in"  or die;
        open STDOUT, '>', "$out" or die;
        open STDERR, '>', "$err" or die;
        alarm 120;
        exec $^X, "-I$lib", "$bin", @argv, '--pins-stdin' or die "exec: $!";
    }
    waitpid $pid, 0;
    return ($?, $out->slurp_utf8, $err->slurp_utf8);
}

# A refusal as the dispatcher prints it: on STDERR, after "Error:", with
# neither the internal-error line nor a Perl location, and not on STDOUT --
# which may hold a command's progress report up to there, nothing more.
sub refused_ok {
    my ($what, $st, $out, $err, $re) = @_;
    isnt $st >> 8, 0, "$what: exit non-zero";
    like $err, $re, "$what: the message on STDERR";
    unlike $err, qr/internal error/, "$what: not called an internal error";
    unlike $err, qr/ at \S+ line \d+/, "$what: no Perl location";
    unlike $out, qr/Error:|PIN1|kubeconfig\.yaml/, "$what: none of it on STDOUT";
}

for my $argv (['keys', 'show'], ['kubeconfig'], ['node', 'ls']) {
    subtest "ocp @$argv --pins-stdin, a wrong PIN1" => sub {
        my $clone = clone_of($secure);
        my ($st, $out, $err) = run_ocp($clone, "not-the-pin\n", @$argv);
        refused_ok("ocp @$argv", $st, $out, $err,
            qr/^Error: PIN1 does not open age\.key\.enc\. Nothing was unlocked, nothing written\.$/m);
        is $out, '', 'nothing on STDOUT: the refusal comes before any output';
        ok !-e $clone->child('.ocp'), 'no .ocp/';
    };
}

subtest 'ocp keys show --pins-stdin, an empty PIN1' => sub {
    my $clone = clone_of($secure);
    my ($st, $out, $err) = run_ocp($clone, "\n", 'keys', 'show');
    refused_ok('ocp keys show', $st, $out, $err, qr/^Error: No PIN1 given, so age\.key\.enc stays locked\./m);
};

subtest 'ocp keys show on a dev-mode clone: where the key is' => sub {
    my $clone = clone_of($dev);
    my ($st, $out, $err) = run_ocp($clone, '', 'keys', 'show');
    refused_ok('ocp keys show', $st, $out, $err,
        qr/^Error: \S+\.yaml is encrypted, and this checkout has no age key to open it/m);
    unlike $err, qr/Run 'ocp init'/, "not 'Run ocp init'";
};

# Every command that reads kubeconfig.yaml for the API first, as far as one
# reaches that read from bin/ocp with a name and nothing else.
for my $argv (['node', 'ls'], ['provider', 'ls'], ['deploy-robocop'],
              ['node', 'rm', 'w-k375'], ['node', 'trust-host', 'w-k375'],
              ['node', 'add', 'w-k375'], ['provider', 'rm', 'p-k375'],
              ['provider', 'add', '--name', 'p-k375', '--type', 'ssh'],
              ['deploy-image', '--image', 'ghcr.io/k375/robocop:1']) {
    subtest "ocp @$argv with no kubeconfig.yaml: says there is none" => sub {
        my $dir = $dev_no_kc;
        ok !-e $dir->child('kubeconfig.yaml'), 'precondition: no kubeconfig.yaml';
        my ($st, $out, $err) = run_ocp($dir, '', @$argv);
        refused_ok("ocp @$argv", $st, $out, $err,
            qr/^Error: This project has no kubeconfig\.yaml, so there is no cluster API to reach\.$/m);
        like $err, qr/'ocp apply' writes it/, 'and what writes it';
        unlike $err, qr/Cannot decrypt|Make sure \.ocp\/age\.key exists/, 'not the old hint';
    };
}

done_testing;

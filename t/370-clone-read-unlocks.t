#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Crypt::Age::Keys ();

use lib 'lib';

use OCP;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

#
# k370: the read side of k360. A clone of a secure-mode project has the
# committed files -- keys.yaml, secrets.yaml, kubeconfig.yaml, age.key.enc --
# and no .ocp/, which is gitignored. The commands a teammate runs first on it
# (ocp status, ocp kubeconfig, ocp node ls, ocp health, ocp provider ls,
# ocp deploy-robocop, ocp hetzner list, ...) read kubeconfig.yaml or
# secrets.yaml without unlocking the project key first, and died before PIN1
# was asked: "Error open (<) on '.ocp/age.key': No such file or directory".
# The claims:
#   1. the reads -- read_kubeconfig, read_secret, hetzner_token,
#      read_all_secrets, decrypt_file, decrypt_kubeconfig_to_file -- unlock
#      the project key as ensure_age_key does: PIN1, asked once, and the key
#      cached 0600 in .ocp/age.key with .ocp/age.pub back, so a later run asks
#      nothing;
#   2. a key already in hand (unlock_age_key, k349) or SOPS_AGE_KEY_FILE
#      (k216) is read as before: no PIN1, nothing written;
#   3. the probes that try the key under eval because it never prompts
#      (repair_sops_lastmodified, OCP::Keys for _robo_probe_key,
#      check_local_age_key) still never prompt and write nothing;
#   4. a wrong PIN1 is refused by name, and nothing is written;
#   5. no .ocp/age.key and no age.key.enc to unlock it from (a clone of a
#      dev-mode project): a refusal that names the file and where the key
#      comes from -- a user error, not Path::Tiny's text -- and nothing written;
#   6. from bin/ocp, PIN1 on STDIN: every command group above unlocks and
#      gets past the read; with no key at all, the refusal is one Error: line
#      on STDERR, not an internal error.
#

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{HETZNER_API_TOKEN};

my $PIN1   = 'pin1-k370';
my $PIN2   = 'pin2-k370';
my $PROMPT = 'Enter PIN1 (cluster access): ';

# A deployed secure-mode project as the machine that made it has it: the
# project key in .ocp/ and behind PIN1 in age.key.enc, an admin (PIN2) and a
# robo key in keys.yaml, secrets.yaml, a kubeconfig for an API that refuses
# every connection (nothing here may reach a network), an ocp.yaml for ssh
# machines. token => 1 puts a Hetzner token into secrets.yaml; without it
# there is none, so `ocp hetzner list` stops at the token, before any call.
sub origin {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k370', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k370\n", public => 'ssh-ed25519 AAAAadmin k370', pin2 => $PIN2);
    $keys->add_key(name => 'robo-ssh-k370', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO PRIVATE k370\n", public => 'ssh-ed25519 AAAArobo k370');

    $s->create_secrets(registry_password => 'pw-k370',
        ($o{token} ? (hetzner_token => 'token-k370') : ()));
    $s->save_kubeconfig(join "\n",
        'apiVersion: v1', 'kind: Config', 'current-context: k370',
        'clusters:', '- name: k370', '  cluster:', '    server: https://127.0.0.1:9',
        '    insecure-skip-tls-verify: true',
        'users:', '- name: k370', '  user:', '    token: t',
        'contexts:', '- name: k370', '  context:', '    cluster: k370', '    user: k370', '');
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k370',
        control_planes => { provider => 'ssh', host => 'cp.k370.invalid' },
        robocop        => { enabled => 1, security_level => 'inject' },
    });
    return $dir;
}

# What a clone gets: every committed file, no .ocp/. %skip leaves files out.
sub clone_of {
    my ($src, @skip) = @_;
    my %skip = map { $_ => 1 } @skip;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename))
        for grep { $_->is_file && !$skip{ $_->basename } } $src->children;
    return $dst;
}

sub mode_of { (stat $_[0])[2] & 07777 }

# Run $code with every PIN prompt answered by $pin; returns the prompts asked.
sub prompted {
    my ($pin, $code) = @_;
    my @asked;
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { push @asked, $_[0]; $pin };
    $code->();
    return \@asked;
}

my $origin    = origin(token => 1);
my $no_token  = origin();
my $recipient = $origin->child('.ocp', 'age.pub')->slurp =~ s/\s+\z//r;

# The project key, cached in the clone's .ocp/ as ensure_age_key leaves it.
sub cached_ok {
    my ($clone, $what, $recipient_of) = @_;
    $recipient_of //= $recipient;
    my $key = $clone->child('.ocp', 'age.key');
    ok -f $key, "$what: .ocp/age.key cached";
    return unless -f $key;
    is sprintf('%04o', mode_of($key)), '0600', "$what: and it is 0600";
    is eval { Crypt::Age::Keys->public_key_from_secret($key->slurp =~ s/\s+\z//r) },
        $recipient_of, "$what: and it is the project key";
    my $pub = $clone->child('.ocp', 'age.pub');
    is -f $pub ? $pub->slurp =~ s/\s+\z//r : undef, $recipient_of, "$what: .ocp/age.pub is back";
}

# The reads, each on a fresh clone: what it returns when it unlocked.
my @reads = (
    [ read_kubeconfig  => sub { $_[0]->read_kubeconfig },
      sub { like $_[0] // '', qr{server: https://127\.0\.0\.1:9}, 'the kubeconfig' } ],
    [ read_secret      => sub { $_[0]->read_secret('registry_password') },
      sub { is $_[0], 'pw-k370', 'the secret' } ],
    [ hetzner_token    => sub { $_[0]->hetzner_token },
      sub { is $_[0], 'token-k370', 'the token from secrets.yaml' } ],
    [ read_all_secrets => sub { $_[0]->read_all_secrets },
      sub { is_deeply $_[0], { registry_password => 'pw-k370', hetzner_token => 'token-k370' },
                'every secret' } ],
    [ decrypt_file     => sub { $_[0]->decrypt_file('kubeconfig.yaml') },
      sub { like $_[0] // '', qr{server: https://127\.0\.0\.1:9}, 'the decrypted file' } ],
    [ decrypt_kubeconfig_to_file => sub {
          my $dir = Path::Tiny->tempdir;
          my $out = $dir->child('kc.yaml');
          $_[0]->decrypt_kubeconfig_to_file($out);
          return -f $out ? $out->slurp : undef },
      sub { like $_[0] // '', qr{server: https://127\.0\.0\.1:9}, 'the kubeconfig, written out' } ],
);

for my $read (@reads) {
    my ($name, $call, $check) = @$read;
    subtest "a clone: $name unlocks the project key with PIN1" => sub {
        my $clone = clone_of($origin);
        ok !-e $clone->child('.ocp'), 'precondition: the clone has no .ocp/';

        my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
        my ($got, $err);
        my $asked = prompted($PIN1, sub { $got = eval { $call->($s) }; $err = $@ });
        is $err, '', "$name reads" or diag $err;
        $check->($got);
        is_deeply $asked, [$PROMPT], 'PIN1 asked, once';
        cached_ok($clone, $name);

        my $again = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
        $asked = prompted($PIN1, sub { $got = eval { $call->($again) } });
        $check->($got);
        is_deeply $asked, [], 'a later run asks nothing';
    };
}

subtest 'a key in hand or SOPS_AGE_KEY_FILE: no PIN1, nothing written' => sub {
    my $clone = clone_of($origin);
    my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    my $asked = prompted($PIN1, sub { $s->unlock_age_key });
    is_deeply $asked, [$PROMPT], 'unlock_age_key (k349) asks PIN1';
    $asked = prompted($PIN1, sub {
        like eval { $s->read_kubeconfig } // '', qr/kind: Config/, 'then read_kubeconfig reads';
        is eval { $s->read_secret('registry_password') }, 'pw-k370', 'and read_secret';
    });
    is_deeply $asked, [], 'and asks nothing more';
    ok !-e $clone->child('.ocp'), 'nothing written: no .ocp/';

    # The key given to new (as OCP::Keys does), and no age.key.enc to unlock.
    my $project_key = $origin->child('.ocp', 'age.key')->slurp =~ s/\s+\z//r;
    my $held = clone_of($origin, 'age.key.enc');
    my $h = OCP::Secrets->new(project_dir => $held, ocp => $ocp, age_key => $project_key);
    $asked = prompted($PIN1, sub {
        like eval { $h->read_kubeconfig } // '', qr/kind: Config/,
            'a key given to new, no age.key.enc: read_kubeconfig reads';
    });
    is_deeply $asked, [], 'and asks nothing';
    ok !-e $held->child('.ocp'), 'nothing written: no .ocp/';

    my $idfile = Path::Tiny->tempfile;
    $idfile->spew("$project_key\n");
    local $ENV{SOPS_AGE_KEY_FILE} = "$idfile";
    for my $skip ([], ['age.key.enc']) {
        my $sops = clone_of($origin, @$skip);
        my $what = @$skip ? 'SOPS_AGE_KEY_FILE, no age.key.enc' : 'SOPS_AGE_KEY_FILE';
        my $t = OCP::Secrets->new(project_dir => $sops, ocp => $ocp);
        $asked = prompted($PIN1, sub {
            like eval { $t->read_kubeconfig } // '', qr/kind: Config/, "$what: read_kubeconfig reads";
            is eval { $t->hetzner_token }, 'token-k370', "$what: and hetzner_token";
        });
        is_deeply $asked, [], "$what: asks nothing";
        ok !-e $sops->child('.ocp'), "$what: nothing written: no .ocp/";
    }
};

subtest 'the probes that must never prompt still do not' => sub {
    my $clone = clone_of($origin);
    # A bare sops lastmodified, so repair_sops_lastmodified gets as far as the key.
    my $kc = $clone->child('kubeconfig.yaml');
    $kc->spew($kc->slurp =~ s/^(\s+lastmodified:\s+)(["'])([^"']+)\2/$1$3/mr);
    my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    ok $s->_sops_lastmodified_bare($kc->slurp_raw), 'precondition: kubeconfig.yaml is bare';

    my @repaired;
    my $asked = prompted($PIN1, sub {
        @repaired = eval { $s->repair_sops_lastmodified };
        eval { OCP::Keys->new(project_dir => $clone, ocp => $ocp)->get_automation_key };
        eval { $s->check_local_age_key };
    });
    is_deeply \@repaired, [], 'repair_sops_lastmodified repairs nothing without the key';
    is_deeply $asked, [], 'and nothing asked PIN1: repair, OCP::Keys, check_local_age_key';
    ok !-e $clone->child('.ocp'), 'nothing written: no .ocp/';
};

subtest 'a wrong PIN1 on a read is refused, and nothing is written' => sub {
    my $clone = clone_of($origin);
    my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    my ($refused, $err);
    my $asked = prompted('not-the-pin', sub { $refused = !eval { $s->read_kubeconfig; 1 }; $err = $@ });
    is_deeply $asked, [$PROMPT], 'PIN1 asked';
    ok $refused, 'read_kubeconfig refuses';
    like $err, qr/\ADecryption failed\. Wrong password\?/, 'naming why';
    ok !-e $clone->child('.ocp'), 'no .ocp/';
};

subtest 'no age.key and no age.key.enc: a refusal that says where the key is' => sub {
    for my $read ([ 'kubeconfig.yaml', sub { $_[0]->read_kubeconfig } ],
                  [ 'secrets.yaml',    sub { $_[0]->hetzner_token } ],
                  [ 'kubeconfig.yaml', sub { $_[0]->decrypt_file('kubeconfig.yaml') } ]) {
        my ($file, $call) = @$read;
        my $clone = clone_of($origin, 'age.key.enc');
        my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
        my ($refused, $err);
        my $asked = prompted($PIN1, sub { $refused = !eval { $call->($s); 1 }; $err = $@ });
        ok $refused, "$file: refused";
        is_deeply $asked, [], "$file: nothing to ask PIN1 for";
        like $err, qr/\AERROR: \Q$file\E is encrypted, and this checkout has no age key/,
            "$file: names the file";
        like $err, qr/\.ocp\/age\.key/,     "$file: names .ocp/age.key";
        like $err, qr/age\.key\.enc/,        "$file: and age.key.enc";
        like $err, qr/SOPS_AGE_KEY_FILE/,    "$file: and SOPS_AGE_KEY_FILE";
        like $err, qr/\n\z/,                 "$file: a user error, ends in a newline";
        unlike $err, qr/Error open| line \d+/, "$file: no Perl error text";
        ok !-e $clone->child('.ocp'), "$file: nothing written: no .ocp/";
    }
};

#
# From bin/ocp
#

my $bin = path('bin/ocp')->absolute;
my $lib = path('lib')->absolute;

# PINs on STDIN: with --pins-stdin where the command has it; `ocp hetzner
# list` does not, and its prompt reads the line off a STDIN that is no
# terminal all the same.
sub run_ocp {
    my ($dir, $stdin, @argv) = @_;
    my ($in, $out, $err) = map { Path::Tiny->tempfile } 1 .. 3;
    $in->spew($stdin);
    my @pins = $argv[0] eq 'hetzner' ? () : ('--pins-stdin');
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        delete $ENV{KUBECONFIG};
        open STDIN,  '<', "$in"  or die;
        open STDOUT, '>', "$out" or die;
        open STDERR, '>', "$err" or die;
        alarm 120;
        exec $^X, "-I$lib", "$bin", @argv, @pins or die "exec: $!";
    }
    waitpid $pid, 0;
    return ($?, $out->slurp_utf8, $err->slurp_utf8);
}

# Every command group whose first decrypt is one of the reads, on a clone of
# a deployed project. Each must ask PIN1, cache the key and get past the read
# to its next step; how that step ends -- the API refuses every connection,
# PIN2 is not given, there is no token -- is the command's own business.
my @commands = (
    [ ['kubeconfig'],      sub { my ($st, $o, $e) = @_;
          is $st >> 8, 0, 'exit 0' or diag $e;
          like $o, qr{server: https://127\.0\.0\.1:9}, 'the kubeconfig on STDOUT';
          unlike $o, qr/PIN1/, 'and nothing else there' } ],
    [ ['status'],          sub { like $_[2], qr/Cannot connect to cluster API/, 'on to the API' } ],
    [ ['node', 'ls'],      sub { like $_[2], qr{127\.0\.0\.1:9}, 'on to the API' } ],
    [ ['health'],          sub { like $_[2], qr{127\.0\.0\.1:9}, 'on to the API' } ],
    [ ['provider', 'ls'],  sub { like $_[2], qr{127\.0\.0\.1:9}, 'on to the API' } ],
    [ ['deploy-robocop'],  sub { like $_[2], qr/Enter PIN2/, 'on to the admin key (PIN2)' } ],
    [ ['hetzner', 'list'], sub { my ($st, $o, $e) = @_;
          isnt $st >> 8, 0, 'exit non-zero';
          like $e, qr/Hetzner API token required/, 'on to the token: secrets.yaml holds none' } ],
);

for my $c (@commands) {
    my ($argv, $check) = @$c;
    subtest "bin/ocp @$argv on a clone, PIN1 on STDIN" => sub {
        my $clone = clone_of($no_token);
        my $rec   = $no_token->child('.ocp', 'age.pub')->slurp =~ s/\s+\z//r;
        my ($st, $o, $e) = run_ocp($clone, "$PIN1\n", @$argv);
        is $st & 127, 0, 'no signal (alarm)';
        like $e, qr/\Q$PROMPT\E/, 'PIN1 asked, on STDERR'
            or diag "ocp @$argv: exit=" . ($st >> 8) . "\n--- STDERR:\n$e";
        unlike $e, qr/Error open|age\.key': No such file|Cannot decrypt/,
            'no error reading the file';
        $check->($st, $o, $e) or diag $e;
        cached_ok($clone, "@$argv", $rec);
    };
}

subtest 'bin/ocp on a clone without any key: one Error: line, no Perl text' => sub {
    for my $argv (['kubeconfig'], ['status']) {
        my $clone = clone_of($no_token, 'age.key.enc');
        my ($st, $o, $e) = run_ocp($clone, "$PIN1\n", @$argv);
        isnt $st >> 8, 0, "ocp @$argv: exit non-zero";
        is $st & 127, 0, "ocp @$argv: no signal";
        like $e, qr/^Error: kubeconfig\.yaml is encrypted, and this checkout has no age key/m,
            "ocp @$argv: the refusal on STDERR";
        unlike $e, qr/\Q$PROMPT\E/, "ocp @$argv: no PIN1 asked";
        unlike $e, qr/internal error|Error open| line \d+\./, "ocp @$argv: no Perl error text";
        is $o, '', "ocp @$argv: nothing on STDOUT" if $argv->[0] eq 'kubeconfig';
        ok !-e $clone->child('.ocp'), "ocp @$argv: nothing written: no .ocp/";
    }
};

done_testing;

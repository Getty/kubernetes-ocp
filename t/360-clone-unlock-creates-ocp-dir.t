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
# k360: a clone of a secure-mode project has the committed files --
# keys.yaml, secrets.yaml, kubeconfig.yaml, age.key.enc -- and no .ocp/,
# which is gitignored. The first PIN1 unlock caches the project key at
# .ocp/age.key, and the write opened the file O_CREAT|O_EXCL without making
# its directory: every command whose first use of the key is ensure_age_key
# died after PIN1 was typed, "Cannot create .ocp/age.key securely: No such
# file or directory". The claims:
#   1. ensure_age_key with PIN1 on a clone without .ocp/ caches the key:
#      .ocp/age.key is 0600 and is the project key, .ocp/age.pub is back, and
#      a fresh object reads every file with it and asks nothing;
#   2. the .ocp/ it makes has the mode every other writer of .ocp/ gives it
#      (Path::Tiny's mkpath: 0777 less the umask) -- 0755 under umask 022,
#      the same as the origin's, made by generate_age_key;
#   3. a .ocp/ the clone has already keeps its mode;
#   4. a wrong PIN1 is refused as before, and writes nothing: no .ocp/;
#   5. from bin/ocp: `ocp keys show --pins-stdin`, PIN1 on STDIN, prints the
#      admin public key on STDOUT and exits 0.
#

# Every mode below is for this umask, the common one.
umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};

my $PIN1   = 'pin1-k360';
my $PIN2   = 'pin2-k360';
my $ADMIN  = 'ssh-ed25519 AAAAadmin k360';

# A secure-mode project as the machine that made it has it: the project key
# in .ocp/ and behind PIN1 in age.key.enc, an admin key (PIN2) in keys.yaml,
# a token in secrets.yaml, a kubeconfig, an ocp.yaml.
sub origin {
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k360', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k360\n", public => $ADMIN, pin2 => $PIN2);

    $s->create_secrets(hetzner_token => 'token-k360');
    $s->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k360',
        control_planes => { provider => 'ssh', host => 'cp.k360.test' },
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

my $origin    = origin();
my $recipient = $origin->child('.ocp', 'age.pub')->slurp;
chomp $recipient;

subtest 'a clone: PIN1 makes .ocp/ and caches the project key there' => sub {
    my $clone = clone_of($origin);
    ok !-e $clone->child('.ocp'), 'precondition: the clone has no .ocp/';

    my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    my $err;
    my $asked = prompted($PIN1, sub { eval { $s->ensure_age_key; 1 } or $err = $@ });
    is $err, undef, 'ensure_age_key unlocks';
    is_deeply $asked, ['Enter PIN1 (cluster access): '], 'PIN1 asked, once';

    my $key = $clone->child('.ocp', 'age.key');
    ok -f $key, '.ocp/age.key written';
    is sprintf('%04o', mode_of($key)), '0600', 'and it is 0600';
    my $cached = -f $key ? $key->slurp =~ s/\s+\z//r : '';
    is eval { Crypt::Age::Keys->public_key_from_secret($cached) }, $recipient,
        'and it is the project key';
    is -f $clone->child('.ocp', 'age.pub') ? $clone->child('.ocp', 'age.pub')->slurp =~ s/\s+\z//r : undef,
        $recipient, '.ocp/age.pub is back';

    my $again = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    $asked = prompted($PIN1, sub { ok eval { $again->ensure_age_key; 1 }, 'a later run: ensure_age_key' });
    is_deeply $asked, [], 'asks nothing';
    is eval { $again->read_secret('hetzner_token') }, 'token-k360', 'secrets.yaml reads';
    like eval { $again->read_kubeconfig } // '', qr/kind: Config/, 'kubeconfig.yaml reads';
    my $keys = OCP::Keys->new(project_dir => $clone, ocp => $ocp);
    is eval { $keys->get_admin_key($PIN2)->{private} }, "ADMIN PRIVATE k360\n",
        'keys.yaml reads, and the admin key opens with PIN2';
};

subtest '.ocp/ gets the mode every other writer of it gives it' => sub {
    my $clone = clone_of($origin);
    prompted($PIN1, sub { eval { OCP::Secrets->new(project_dir => $clone, ocp => $ocp)->ensure_age_key } });

    my $dir = $clone->child('.ocp');
    ok -d $dir, '.ocp/ made';
    is sprintf('%04o', mode_of($dir)), sprintf('%04o', 0777 & ~umask), '0777 less the umask';
    is sprintf('%04o', mode_of($dir)), '0755', 'which is 0755 under umask 022';
    is sprintf('%04o', mode_of($dir)), sprintf('%04o', mode_of($origin->child('.ocp'))),
        'the mode generate_age_key gave the origin its .ocp/';
};

subtest 'a .ocp/ the clone has already keeps its mode' => sub {
    my $clone = clone_of($origin);
    my $dir   = $clone->child('.ocp');
    $dir->mkpath;
    $dir->chmod(0700);
    $dir->child('id_ed25519')->spew('BOOTSTRAP k360');

    my $err;
    prompted($PIN1, sub { eval { OCP::Secrets->new(project_dir => $clone, ocp => $ocp)->ensure_age_key; 1 } or $err = $@ });
    is $err, undef, 'ensure_age_key unlocks';
    ok -f $dir->child('age.key'), '.ocp/age.key written';
    is sprintf('%04o', mode_of($dir)), '0700', '.ocp/ is 0700 still';
    is $dir->child('id_ed25519')->slurp, 'BOOTSTRAP k360', 'and what was in it is there';
};

subtest 'a wrong PIN1 is refused, and nothing is written' => sub {
    my $clone = clone_of($origin);
    my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    my ($refused, $err);
    prompted('not-the-pin', sub { $refused = !eval { $s->ensure_age_key; 1 }; $err = $@ });
    ok $refused, 'ensure_age_key refuses';
    like $err, qr/\ADecryption failed\. Wrong password\?/, 'naming why';
    ok !-e $clone->child('.ocp'), 'no .ocp/';
};

subtest 'from bin/ocp: ocp keys show --pins-stdin on a clone' => sub {
    my $clone = clone_of($origin);
    my $bin   = path('bin/ocp')->absolute;
    my $lib   = path('lib')->absolute;
    my ($in, $out, $err) = map { Path::Tiny->tempfile } 1 .. 3;
    $in->spew("$PIN1\n");

    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $clone or die "chdir: $!";
        local $ENV{HOME} = $clone->stringify;
        open STDIN,  '<', "$in"  or die;
        open STDOUT, '>', "$out" or die;
        open STDERR, '>', "$err" or die;
        exec $^X, "-I$lib", "$bin", 'keys', 'show', '--pins-stdin' or die "exec: $!";
    }
    waitpid $pid, 0;
    my $rc = $? >> 8;
    my ($o, $e) = ($out->slurp_utf8, $err->slurp_utf8);

    is $rc, 0, 'exit 0' or diag $e;
    is $o, "$ADMIN\n", 'the admin public key on STDOUT';
    unlike $e, qr/Cannot create|No such file/, 'no write error on STDERR';
    my $key = $clone->child('.ocp', 'age.key');
    ok -f $key, '.ocp/age.key written';
    is sprintf('%04o', mode_of($key)), '0600', 'and it is 0600' if -f $key;
};

done_testing;

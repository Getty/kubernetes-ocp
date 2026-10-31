#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Digest::MD5 ();
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Crypt::Age::Keys ();

use OCP;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

#
# k349: on a clone of a secure-mode project -- keys.yaml, secrets.yaml,
# kubeconfig.yaml and age.key.enc, no .ocp/ (gitignored) -- the only way to
# the project key was ensure_age_key, which caches it: PIN1, then
# .ocp/age.key and .ocp/age.pub written. `ocp apply --dry-run` went that way
# and left both behind. The claims, for the in-memory unlock a dry run takes:
#   1. unlock_age_key opens age.key.enc with PIN1 into the object (age_key),
#      and every read works with it: secrets.yaml, kubeconfig.yaml, and
#      keys.yaml with the admin (PIN2) and robo keys through an OCP::Keys
#      handed that key;
#   2. nothing under the project directory is created or changed -- no .ocp/
#      at all -- and ensure_age_key on the same object afterwards neither
#      asks again nor writes;
#   3. a wrong PIN1 is refused as before, and so is a key the project's files
#      are not bound to: nothing held, nothing written;
#   4. a key that is there already (.ocp/age.key, SOPS_AGE_KEY_FILE) is used
#      as it is, without a prompt -- and without restoring .ocp/age.pub, which
#      ensure_age_key does.
#

local @ARGV = ();
my $ocp = OCP->new;    # load/dump for the kubeconfig

my $PIN1 = 'pin1-k349';
my $PIN2 = 'pin2-k349';

# A secure-mode project as the machine that made it has it: the project key
# in .ocp/ and behind PIN1 in age.key.enc, an admin key (PIN2) and a robo key
# in keys.yaml, a token in secrets.yaml, a kubeconfig.
sub origin {
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k349', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k349\n", public => 'ssh-ed25519 AAAAadmin k349', pin2 => $PIN2);
    $keys->add_key(name => 'robo-ssh-k349', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO PRIVATE k349\n", public => 'ssh-ed25519 AAAArobo k349');

    $s->create_secrets(hetzner_token => 'token-k349');
    $s->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");
    return $dir;
}

# What a clone gets: every committed file, no .ocp/.
sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

# Every path under $dir, directories too, with each file's digest.
sub listing {
    my ($dir) = @_;
    my %seen;
    $dir->visit(sub {
        my ($p) = @_;
        $seen{ $p->relative($dir)->stringify } = -d $p ? 'dir' : Digest::MD5::md5_hex($p->slurp_raw);
    }, { recurse => 1 });
    return \%seen;
}

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

subtest 'a clone: PIN1 opens the project key in memory, and every read works with it' => sub {
    my $clone  = clone_of($origin);
    my $before = listing($clone);
    ok !-e $clone->child('.ocp'), 'precondition: the clone has no .ocp/';

    my $s = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    my $asked = prompted($PIN1, sub { ok $s->unlock_age_key, 'unlock_age_key' });

    is_deeply $asked, ['Enter PIN1 (cluster access): '], 'PIN1 asked, once';
    ok defined $s->age_key, 'the key is held';
    my $held = Crypt::Age::Keys->public_key_from_secret($s->age_key =~ s/\s+\z//r);
    is $held, $recipient, 'and it is the project key';

    is $s->read_secret('hetzner_token'), 'token-k349', 'secrets.yaml reads';
    like $s->read_kubeconfig, qr/kind: Config/, 'kubeconfig.yaml reads';
    like $s->decrypt_file('secrets.yaml'), qr/token-k349/, 'decrypt_file reads';

    my $keys = OCP::Keys->new(project_dir => $clone, ocp => $ocp, age_key => $s->age_key);
    is scalar @{ $keys->list_keys }, 2, 'keys.yaml reads through OCP::Keys';
    is $keys->get_admin_key($PIN2)->{private}, "ADMIN PRIVATE k349\n", 'the admin key opens with PIN2';
    is $keys->get_automation_key->{private}, "ROBO PRIVATE k349\n", 'the robo key opens';

    $asked = prompted($PIN1, sub { ok $s->ensure_age_key, 'ensure_age_key afterwards' });
    is_deeply $asked, [], 'asks nothing more';

    is_deeply listing($clone), $before, 'the project directory as it was'
        or diag explain listing($clone);
    ok !-e $clone->child('.ocp'), 'no .ocp/ created';
};

subtest 'without the key in hand, OCP::Keys reads .ocp/age.key as ever' => sub {
    my $clone = clone_of($origin);
    my $keys  = OCP::Keys->new(project_dir => $clone, ocp => $ocp);
    ok !eval { $keys->list_keys; 1 }, 'the clone has none: keys.yaml does not read';

    my $own = OCP::Keys->new(project_dir => $origin, ocp => $ocp);
    is scalar @{ $own->list_keys }, 2, 'the origin has it: keys.yaml reads';
};

subtest 'a wrong PIN1 is refused: nothing held, nothing written' => sub {
    my $clone  = clone_of($origin);
    my $before = listing($clone);
    my $s      = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);

    my $err;
    my $asked = prompted('not-the-pin', sub { $err = eval { $s->unlock_age_key; 1 } ? '' : $@ });
    like $err, qr/\APIN1 does not open age\.key\.enc\./, 'prompted: refused, as ensure_age_key refuses it';
    is scalar @$asked, 1, 'after one PIN1 prompt';

    ok !eval { $s->unlock_age_key('not-the-pin'); 1 }, 'given: refused';
    like $@, qr/\APIN1 does not open age\.key\.enc\./, 'with the same words';

    ok !defined $s->age_key, 'no key held';
    ok !eval { $s->read_secret('hetzner_token'); 1 }, 'and nothing reads';
    is_deeply listing($clone), $before, 'the project directory as it was';

    ok $s->unlock_age_key($PIN1), 'the right PIN1 afterwards unlocks';
    is $s->read_secret('hetzner_token'), 'token-k349', 'and reads';
    is_deeply listing($clone), $before, 'still writing nothing';
};

subtest 'a key the project is not bound to is refused: nothing held, nothing written' => sub {
    my $clone = clone_of($origin);

    my $other = path(tempdir(CLEANUP => 1));
    my $o     = OCP::Secrets->new(project_dir => $other, ocp => $ocp);
    $o->generate_age_key;
    $o->encrypt_age_key_with_password($PIN1);
    $other->child('age.key.enc')->copy($clone->child('age.key.enc'));

    my $before = listing($clone);
    my $s      = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);

    ok !eval { $s->unlock_age_key($PIN1); 1 }, 'refused';
    like $@, qr/\AThis age key does not belong to this project\./, 'naming why';
    ok !defined $s->age_key, 'no key held';
    is_deeply listing($clone), $before, 'the project directory as it was';
};

subtest '.ocp/age.key there, .ocp/age.pub not: used as it is, age.pub not restored' => sub {
    my $dir = clone_of($origin);
    $dir->child('.ocp')->mkpath;
    $origin->child('.ocp', 'age.key')->copy($dir->child('.ocp', 'age.key'));
    my $before = listing($dir);

    my $s     = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    my $asked = prompted($PIN1, sub { ok $s->unlock_age_key, 'unlock_age_key' });
    is_deeply $asked, [], 'no PIN1 asked';
    ok !defined $s->age_key, 'nothing held: the file is the key';
    is $s->read_secret('hetzner_token'), 'token-k349', 'secrets.yaml reads';
    is_deeply listing($dir), $before, 'no .ocp/age.pub written';

    ok $s->ensure_age_key, 'ensure_age_key, for contrast';
    ok -f $dir->child('.ocp', 'age.pub'), 'restores it';
};

subtest 'SOPS_AGE_KEY_FILE: no PIN1, nothing held, nothing written' => sub {
    my $clone   = clone_of($origin);
    my $keyfile = path(tempdir(CLEANUP => 1))->child('project.key');
    $origin->child('.ocp', 'age.key')->copy($keyfile);
    my $before = listing($clone);

    local $ENV{SOPS_AGE_KEY_FILE} = $keyfile->stringify;
    my $s     = OCP::Secrets->new(project_dir => $clone, ocp => $ocp);
    my $asked = prompted($PIN1, sub { ok $s->unlock_age_key, 'unlock_age_key' });
    is_deeply $asked, [], 'no PIN1 asked';
    ok !defined $s->age_key, 'nothing held: the variable names the key';
    is $s->read_secret('hetzner_token'), 'token-k349', 'secrets.yaml reads';
    is_deeply listing($clone), $before, 'the project directory as it was';
};

subtest 'no key anywhere: refused as ensure_age_key refuses it' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    ok !eval { $s->unlock_age_key($PIN1); 1 }, 'refused';
    like $@, qr/\AERROR: This project has no age key: .*Run 'ocp init' to set it up\.\n\z/s,
        'with the same words';
    is_deeply listing($dir), {}, 'nothing written';
};

done_testing;

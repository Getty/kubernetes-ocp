#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::Keys;
use OCP::Secrets;

#
# k428: OCP::Secrets trusted a .ocp/age.key that was there without checking
# it against the project. One that does not belong -- left from another
# project, or from before a re-key -- went through ensure_age_key and died at
# the first SOPS read: "Could not decrypt data key with any of the provided
# identities at lib/OCP/... line N.", which the dispatcher calls an internal
# error.
#
# The claims:
#   * ensure_age_key and unlock_age_key refuse a .ocp/age.key the committed
#     files are not encrypted to, before any SOPS read, as a user error: no
#     Perl location, both recipients named
#   * the advice fits the project: with age.key.enc, move the cache aside
#     (age.key and age.pub) and let PIN1 unlock the project key; without
#     one (dev mode), the cache is the only copy of a key -- never told to
#     delete it, told to put the project's key there
#   * nothing is written or removed by the refusal
#   * the project's own key still passes, and a project with nothing
#     encrypted yet takes any key
#   * from bin/ocp: the refusal on STDERR, not called an internal error
#

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};

my $PIN1 = 'pin1-k428';
my $KUBE = "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n";

# A project with kubeconfig.yaml and secrets.yaml encrypted to its key;
# with secure => 1 also age.key.enc under $PIN1.
sub project {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1) if $o{secure};
    $s->create_secrets(registry_password => 'pw-k428');
    $s->save_kubeconfig($KUBE);
    OCP::Keys->new(project_dir => $dir, ocp => $ocp)->add_key(
        name => 'robo-k428', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO k428\n", public => 'ssh-ed25519 AAAArobo k428');
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k428',
        control_planes => { provider => 'ssh', host => 'cp.k428.invalid' },
    });
    return $dir;
}

# Another project's key cached in $dir's .ocp/ (age.key and age.pub).
sub stale_cache {
    my ($dir) = @_;
    my $other = path(tempdir(CLEANUP => 1));
    OCP::Secrets->new(project_dir => $other, ocp => $ocp)->generate_age_key;
    $other->child('.ocp', $_)->copy($dir->child('.ocp', $_)) for qw( age.key age.pub );
    return $other->child('.ocp', 'age.pub')->slurp =~ s/\s+\z//r;
}

sub snapshot {
    my ($dir) = @_;
    return { map { $_->relative($dir)->stringify => $_->slurp_raw }
             grep { $_->is_file } $dir->child('.ocp')->children };
}

for my $case ([ 'secure mode (age.key.enc)' => 1 ], [ 'dev mode (no age.key.enc)' => 0 ]) {
    my ($label, $secure) = @$case;

    for my $how (qw( ensure_age_key unlock_age_key )) {
        subtest "$label: $how refuses a stale .ocp/age.key" => sub {
            my $dir   = project(secure => $secure);
            my $own   = $dir->child('.ocp', 'age.pub')->slurp =~ s/\s+\z//r;
            my $stale = stale_cache($dir);
            my $before = snapshot($dir);

            my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
            no warnings 'redefine';
            local *OCP::Password::prompt_password = sub { die "PIN prompted\n" };
            ok !eval { $s->$how; 1 }, 'refused';
            my $err = $@;

            like $err, qr/\A.*\.ocp\/age\.key does not belong to this project/,
                'says the cached key is not the project\'s';
            like $err, qr/\Q$stale\E/, 'names what the cached key opens';
            like $err, qr/kubeconfig\.yaml needs:\s+\Q$own\E/, 'and what the files need';
            unlike $err, qr/ at \S+ line \d+/, 'no Perl location';
            unlike $err, qr/Could not decrypt data key/, 'not the SOPS internals';
            unlike $err, qr/PIN prompted/, 'no PIN asked';
            if ($secure) {
                like $err, qr/age\.key\.enc/, 'points at age.key.enc';
                like $err, qr/PIN1/, 'and PIN1';
                like $err, qr/mv \.ocp\/age\.key /, 'move the cache aside';
                like $err, qr/mv \.ocp\/age\.pub /, 'its recipient half too';
            } else {
                unlike $err, qr/\b(?:rm|mv)\b/, 'the only key there is: never told to (re)move it';
                like $err, qr/project's key/, 'told to put the project\'s key there';
            }
            is_deeply snapshot($dir), $before, '.ocp/ untouched';
        };
    }
}

subtest 'OCP::Keys refuses a stale .ocp/age.key before reading keys.yaml' => sub {
    my $dir = project(secure => 1);
    stale_cache($dir);
    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    ok !eval { $keys->list_keys; 1 }, 'refused';
    like $@, qr/\AERROR: The cached \.ocp\/age\.key does not belong to this project/,
        'as a stale cache';
    unlike $@, qr/Could not decrypt data key| at \S+ line \d+/, 'not as the SOPS internals';
};

subtest 'read_kubeconfig refuses a stale .ocp/age.key as a stale cache' => sub {
    my $dir = project(secure => 1);
    stale_cache($dir);
    ok !eval { OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->read_kubeconfig; 1 }, 'refused';
    like $@, qr/\AERROR: The cached \.ocp\/age\.key does not belong to this project/,
        'with the advice for a cache';
};

subtest 'secure mode: moved aside as told, PIN1 unlocks the project key' => sub {
    my $dir = project(secure => 1);
    stale_cache($dir);
    $dir->child('.ocp', $_)->move($dir->child('.ocp', "$_.stale")) for qw( age.key age.pub );
    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    ok eval { $s->ensure_age_key($PIN1); 1 }, 'unlocked' or diag $@;
    is $s->read_kubeconfig, $ocp->dump($ocp->load($KUBE)), 'and the kubeconfig reads';
};

subtest 'the project\'s own cached key passes' => sub {
    for my $secure (1, 0) {
        my $dir = project(secure => $secure);
        my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
        ok eval { $s->ensure_age_key; 1 }, "ensure_age_key (secure=$secure)" or diag $@;
        ok eval { $s->unlock_age_key; 1 }, "unlock_age_key (secure=$secure)" or diag $@;
    }
};

subtest 'nothing encrypted yet: any key passes' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->generate_age_key;
    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    ok eval { $s->ensure_age_key; 1 }, 'ensure_age_key' or diag $@;
};

subtest 'bin/ocp: a user error, not an internal one' => sub {
    my $dir = project(secure => 1);
    stale_cache($dir);
    my ($bin, $lib) = (path('bin/ocp')->absolute, path('lib')->absolute);
    my $err = path(tempdir(CLEANUP => 1))->child('err');
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        open STDIN,  '<', '/dev/null' or die;
        open STDOUT, '>', '/dev/null' or die;
        open STDERR, '>', "$err"      or die;
        exec $^X, "-I$lib", "$bin", 'kubeconfig' or die "exec: $!";
    }
    waitpid $pid, 0;
    my $st  = $?;
    my $out = $err->slurp_utf8;
    isnt $st >> 8, 0, 'exit non-zero';
    like $out, qr/^Error: .*\.ocp\/age\.key does not belong to this project/m, 'the refusal';
    unlike $out, qr/internal error/i, 'not called an internal error';
    unlike $out, qr/ at \S+ line \d+/, 'no Perl location';
};

done_testing;

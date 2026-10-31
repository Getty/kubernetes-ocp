#!/usr/bin/env perl
# karr k349 -- `ocp apply --dry-run` against a cluster that exists, on a clone.
#
# A clone of a secure-mode project has keys.yaml, secrets.yaml,
# kubeconfig.yaml and age.key.enc, and no .ocp/ (gitignored). The reconcile
# branch read kubeconfig.yaml straight off .ocp/age.key, so on a clone the
# dry run died before PIN1 was asked; and its robocop check went through
# ensure_age_key, which caches the key in .ocp/ and restores .ocp/age.pub.
# The claims, for the dry run of a cluster that exists:
#
#   * on a clone: PIN1 asked once, the kubeconfig decrypted with the project
#     key in memory, the robo key read with the same key for the robocop
#     check (a current Secret is current, a stale one is outdated), the run
#     at its end -- and the project directory as it was: no .ocp/ at all;
#   * on a checkout with .ocp/age.key and no .ocp/age.pub: no PIN1 asked,
#     and age.pub not restored;
#   * a wrong PIN1 is refused before the kubeconfig is read: nothing
#     decrypted, nothing written.
#
# The bootstrap path's dry run is t/297 (a subprocess, PINs over
# --pins-stdin); the in-memory unlock itself is t/349-unlock-age-key-in-memory.
#
# Network-free and cluster-free: the K8s API is a fake that serves the
# robocop Secret and Deployment; the detector's findings and the host probes
# are stubbed out (t/38, t/234 have them); the PIN prompt is stubbed on
# OCP::Password. The age key, keys.yaml and kubeconfig.yaml are real.

use strict;
use warnings;
use Test::More;

use Digest::MD5 ();
use File::Temp qw( tempdir );
use Kubernetes::REST::APIError;
use MIME::Base64 ();
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Drift;
use OCP::Config;
use OCP::Drift;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

local @ARGV = ();
my $ocp = OCP->new;

my $PIN1       = 'pin1-k349';
my $PIN2       = 'pin2-k349';
my $ROBO_PRIV  = "-----BEGIN OPENSSH PRIVATE KEY-----\nROBO k349\n-----END OPENSSH PRIVATE KEY-----\n";
my $TOKEN      = 'K10k349::server:k349';
my $KUBECONFIG = "apiVersion: v1\nkind: Config\nclusters: []\n";
my $SECRET     = 'Secret/ocp-system/robocop-credentials';
my $DEPLOYMENT = 'Deployment/ocp-system/robocop';

# --- Fakes ----------------------------------------------------------------

package FakeList {
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}

# Serves what it holds under kind/namespace/name; anything else is a 404.
# Records every write -- there must be none.
package FakeApi {
    sub new { my ($c, %a) = @_; bless { objects => {}, writes => [], %a }, $c }

    sub get {
        my ($self, $kind, $name, %opt) = @_;
        my $key = join '/', $kind, $opt{namespace} // '-', $name;
        return $self->{objects}{$key} // die Kubernetes::REST::APIError->new(
            code => 404, context => 'get',
            body => '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}',
        );
    }

    sub list             { FakeList->new([]) }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }

    for my $write (qw( ensure create update patch delete apply )) {
        no strict 'refs';
        *{"FakeApi::$write"} = sub { push @{ $_[0]{writes} }, $write; $_[1] };
    }
}

package FakeOCP {
    sub new     { bless {}, shift }
    sub verbose { 0 }
}

package main;

# --- Fixture --------------------------------------------------------------

# A secure-mode project with a cluster, as the machine that made it has it:
# the project key in .ocp/ and behind PIN1 in age.key.enc, an admin (PIN2)
# and a robo key in keys.yaml, kubeconfig.yaml, robocop on at level secret.
sub origin {
    my $dir = path(tempdir(CLEANUP => 1));
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k349',
        kubernetes     => { dist => 'k3s' },
        control_planes => { provider => 'ssh', host => 'cp.k349.test' },
        robocop        => { enabled => 1, security_level => 'secret' },
    });

    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k349', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k349\n", public => 'ssh-ed25519 AAAAadmin k349', pin2 => $PIN2);
    $keys->add_key(name => 'robo-ssh-k349', type => 'ssh_ed25519', purpose => 'automation',
        private => $ROBO_PRIV, public => 'ssh-ed25519 AAAArobo k349');

    $s->create_secrets(hetzner_token => 'token-k349');
    $s->save_kubeconfig($KUBECONFIG);
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

sub config_for {
    OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify, ocp => $ocp);
}

# The robocop-credentials Secret as the API server hands it back, with
# $robo as its robo key: the one a write for $config would leave by default.
sub credentials_secret {
    my ($config, $robo) = @_;
    my %plain = (
        'robo-ssh-key' => $robo // $ROBO_PRIV,
        'server-url'   => $config->join_url('cp.k349.test'),
        'rke2-token'   => $TOKEN,
    );
    return { kind => 'Secret',
             metadata => { name => 'robocop-credentials', namespace => 'ocp-system' },
             data => { map { $_ => MIME::Base64::encode_base64($plain{$_}, '') } keys %plain } };
}

# One `ocp apply --dry-run` reconcile in $dir, every PIN prompt answered by
# $pin: { rv, died, out, err, prompts, kubeconfigs, writes }. kubeconfigs is
# what the API was built from -- the kubeconfig the run decrypted.
sub dry_run_in {
    my ($dir, %o) = @_;
    my $config = config_for($dir);
    my $api    = FakeApi->new(objects => {
        $SECRET     => credentials_secret($config, $o{robo}),
        $DEPLOYMENT => { kind => 'Deployment', metadata => { name => 'robocop' } },
    });
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ], dry_run => 1);

    my (@prompts, @kubeconfigs);
    my ($out, $err) = ('', '');
    my ($rv, $died);
    {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub { push @prompts, $_[0]; $o{pin} // $PIN1 };
        local *OCP::Cmd::Apply::_k8s_api = sub {
            my ($self, $kubeconfig) = @_;
            push @kubeconfigs, $kubeconfig if defined $kubeconfig;
            return $api;
        };
        local *OCP::Cmd::Apply::rex_prober = sub { undef };
        local *OCP::Drift::detect          = sub { [] };
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $apply->_reconcile_components($config) };
        $died = $@;
    }
    return { rv => $rv, died => $died, out => $out, err => $err, prompts => \@prompts,
             kubeconfigs => \@kubeconfigs, writes => $api->{writes} };
}

my $ORIGIN = origin();

subtest 'a clone: PIN1 once, everything read with the key in memory, no .ocp/ after' => sub {
    my $dir    = clone_of($ORIGIN);
    my $before = listing($dir);
    ok !-e $dir->child('.ocp'), 'precondition: the clone has no .ocp/';

    my $r = dry_run_in($dir);

    is $r->{died}, '', 'no death' or diag $r->{died};
    is_deeply $r->{prompts}, [ 'Enter PIN1 (cluster access): ' ], 'PIN1 asked, once';
    is scalar @{ $r->{kubeconfigs} }, 1, 'the API built from the kubeconfig';
    like $r->{kubeconfigs}[0] // '', qr/^kind: Config$/m, 'decrypted with the key in memory';
    unlike $r->{out}, qr/robocop-credentials/,
        'the robocop Secret is current: the robo key was read with the same key';
    like $r->{out}, qr/^  0 difference\(s\) a real run would act on\.$/m, 'nothing to act on';
    like $r->{out}, qr/\[Dry run - no changes made\]\n\z/, 'to its end';
    is $r->{err}, '', 'nothing on STDERR';
    is_deeply $r->{writes}, [], 'nothing written to the cluster';
    is_deeply listing($dir), $before, 'the project directory as it was: no .ocp/'
        or diag explain listing($dir);
};

subtest 'control: a stale robocop Secret is outdated, so the comparison is made' => sub {
    my $dir    = clone_of($ORIGIN);
    my $before = listing($dir);

    my $r = dry_run_in($dir, robo => "-----BEGIN OPENSSH PRIVATE KEY-----\nOLD\n-----END OPENSSH PRIVATE KEY-----\n");

    is $r->{died}, '', 'no death' or diag $r->{died};
    like $r->{out}, qr{^  \[robocop\] Secret/robocop-credentials is outdated\n\s+would rewrite it \(secret\)$}m,
        'outdated, would rewrite it';
    like $r->{out}, qr/^  1 difference\(s\) a real run would act on\.$/m, 'one difference';
    is_deeply $r->{prompts}, [ 'Enter PIN1 (cluster access): ' ], 'PIN1 asked, once';
    is_deeply listing($dir), $before, 'the project directory as it was';
};

subtest 'a checkout with .ocp/age.key and no .ocp/age.pub: no PIN1, age.pub not restored' => sub {
    my $dir = clone_of($ORIGIN);
    $dir->child('.ocp')->mkpath;
    $ORIGIN->child('.ocp', 'age.key')->copy($dir->child('.ocp', 'age.key'));
    my $before = listing($dir);
    ok !-e $dir->child('.ocp', 'age.pub'), 'precondition: no .ocp/age.pub';

    my $r = dry_run_in($dir);

    is $r->{died}, '', 'no death' or diag $r->{died};
    is_deeply $r->{prompts}, [], 'no PIN1: the key is on disk';
    unlike $r->{out}, qr/robocop-credentials/, 'the robocop Secret is current';
    like $r->{out}, qr/\[Dry run - no changes made\]\n\z/, 'to its end';
    ok !-e $dir->child('.ocp', 'age.pub'), 'no .ocp/age.pub';
    is_deeply listing($dir), $before, 'the project directory as it was'
        or diag explain listing($dir);
};

subtest 'a wrong PIN1 is refused before the kubeconfig is read' => sub {
    my $dir    = clone_of($ORIGIN);
    my $before = listing($dir);

    my $r = dry_run_in($dir, pin => 'wrong-k349');

    like $r->{died}, qr/\ADecryption failed\. Wrong password\?/, 'refused';
    is_deeply $r->{prompts}, [ 'Enter PIN1 (cluster access): ' ], 'on PIN1';
    is_deeply $r->{kubeconfigs}, [], 'no kubeconfig decrypted, no API built';
    unlike $r->{out}, qr/Checking for drift/, 'the run went no further';
    is_deeply listing($dir), $before, 'the project directory as it was: no .ocp/'
        or diag explain listing($dir);
};

done_testing;

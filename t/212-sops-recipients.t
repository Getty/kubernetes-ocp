#!/usr/bin/env perl
# karr k212 -- the project's SOPS files for more than one age recipient.
#
# Decisions (2026-10-01):
#   F1  the recipient list lives in .sops.yaml (sops-native creation_rules)
#   F2  `ocp keys recipients ls|add|rm`, re-encryption through File::SOPS rotate
#   F3  rm = recipient out + re-encrypt + a loud hint to rotate what it could read
#
# The project key (age.key / age.key.enc, PIN1) is always a recipient; the
# others come from the .sops.yaml that governs the files. Every write path has
# to honour the list, or the next `ocp apply` silently drops the extra
# recipient again. The private halves inside keys.yaml keep their own age
# layer for the project key alone -- a second recipient reads the file, not
# the project's SSH keys.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Cwd qw(getcwd);
use FindBin;
use YAML::XS ();

use Crypt::Age;
use File::SOPS;
use OCP;
use OCP::Secrets;
use OCP::Keys;

local @ARGV = ();
my $ocp = OCP->new;

my $BIN = "$FindBin::Bin/../bin/ocp";
my $LIB = "$FindBin::Bin/../lib";

my ($LEIT_PUB, $LEIT_SEC) = Crypt::Age->generate_keypair;
my ($OTHER_PUB)           = Crypt::Age->generate_keypair;

sub project {
    my (%o) = @_;
    my $root = path(tempdir(CLEANUP => 1));
    my $dir  = $o{subdir} ? $root->child($o{subdir}) : $root;
    $dir->mkpath;
    my $secrets = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    my $k = $secrets->generate_age_key;
    $dir->child('ocp.yaml')->spew("name: t\ncontrol_planes:\n  provider: local\n");
    return ($dir, $secrets, $k->{public_key}, $root);
}

sub bound { # file => [ recipients ], from the plaintext sops metadata
    my ($secrets) = @_;
    my %b;
    push @{ $b{ $_->{file} } }, $_->{recipient} for @{ $secrets->age_key_bindings };
    return { map { $_ => [ sort @{ $b{$_} } ] } keys %b };
}

sub opens {
    my ($file, $identity) = @_;
    return eval {
        File::SOPS->decrypt(encrypted => path($file)->slurp, identities => [$identity],
            format => 'yaml');
        1;
    } ? 1 : 0;
}

sub fill {
    my ($dir, $secrets) = @_;
    $secrets->create_secrets(hetzner_token => 'tok');
    $secrets->save_kubeconfig("apiVersion: v1\nkind: Config\n");
    OCP::Keys->new(project_dir => $dir, ocp => $ocp)->add_key(
        name => 'admin-ssh', type => 'ssh_ed25519', purpose => 'admin',
        private => "PRIVATE\n", public => 'ssh-ed25519 AAAA admin', pin2 => '1234');
}

# --- the list ----------------------------------------------------------------

subtest 'without a .sops.yaml the project key is the only recipient' => sub {
    my ($dir, $secrets, $proj) = project();
    is_deeply $secrets->recipients_for($dir->child('secrets.yaml')), [ $proj ], 'just the project key';
    fill($dir, $secrets);
    is_deeply bound($secrets)->{'secrets.yaml'}, [ $proj ], 'and the files say so';
};

subtest 'set_sops_recipients writes a project .sops.yaml the files follow' => sub {
    my ($dir, $secrets, $proj) = project();
    $secrets->set_sops_recipients([ $LEIT_PUB ]);

    my $conf = YAML::XS::LoadFile($dir->child('.sops.yaml')->stringify);
    my ($rule) = @{ $conf->{creation_rules} };
    is_deeply [ split /,/, $rule->{age} ], [ $proj, $LEIT_PUB ],
        'one rule, project key first, then the extra recipient';
    my %args = File::SOPS->creation_rules_for(file => $dir->child('keys.yaml')->stringify);
    is_deeply $args{recipients}, [ $proj, $LEIT_PUB ], 'and sops (File::SOPS) reads it the same way';

    is_deeply $secrets->recipients_for($dir->child($_)), [ $proj, $LEIT_PUB ], "recipients for $_"
        for qw(keys.yaml secrets.yaml kubeconfig.yaml);
};

subtest 'every write path encrypts for the whole list' => sub {
    my ($dir, $secrets, $proj) = project();
    $secrets->set_sops_recipients([ $LEIT_PUB ]);
    fill($dir, $secrets);

    my $b = bound($secrets);
    is_deeply $b->{$_}, [ sort $proj, $LEIT_PUB ], "$_: both recipients"
        for qw(keys.yaml secrets.yaml kubeconfig.yaml);
    # for my: File::SOPS->decrypt clobbers $_ (Crypt::Age underneath)
    for my $f (qw(secrets.yaml kubeconfig.yaml keys.yaml)) {
        ok opens($dir->child($f), $LEIT_SEC), "the second recipient opens $f";
    }

    $secrets->encrypt_file("a: b\n", 'secrets.yaml');
    ok opens($dir->child('secrets.yaml'), $LEIT_SEC), 'encrypt_file follows the list too';

    # The inner layer of keys.yaml stays the project's (and PIN2's).
    my $keys = File::SOPS->decrypt(encrypted => $dir->child('keys.yaml')->slurp,
        identities => [ $LEIT_SEC ], format => 'yaml');
    my $blob = $keys->{keys}[0]{private};
    ok !eval { Crypt::Age->decrypt(ciphertext => $blob, identities => [ $LEIT_SEC ]); 1 },
        'a private key inside keys.yaml is not readable for the second recipient';
};

subtest 'an existing project .sops.yaml keeps its other rules' => sub {
    my ($dir, $secrets, $proj) = project();
    $dir->child('.sops.yaml')->spew(<<"YAML");
creation_rules:
  - path_regex: ^other/
    age: $OTHER_PUB
  - path_regex: ^(keys|secrets|kubeconfig)\\.yaml\$
    age: $proj
YAML
    $secrets->set_sops_recipients([ $LEIT_PUB ]);
    my $rules = YAML::XS::LoadFile($dir->child('.sops.yaml')->stringify)->{creation_rules};
    is scalar @$rules, 2, 'still two rules';
    is $rules->[0]{age}, $OTHER_PUB, 'the foreign rule untouched';
    is $rules->[1]{age}, "$proj,$LEIT_PUB", 'the OCP rule extended';

    $secrets->set_sops_recipients([]);
    is YAML::XS::LoadFile($dir->child('.sops.yaml')->stringify)->{creation_rules}[1]{age}, $proj,
        'back to the project key alone';
};

subtest 'a .sops.yaml above the project governs it like sops says' => sub {
    my ($dir, $secrets, $proj, $root) = project(subdir => 'cluster');
    $root->child('.sops.yaml')->spew(<<"YAML");
creation_rules:
  - path_regex: ^cluster/
    age: $LEIT_PUB
YAML
    is_deeply $secrets->recipients_for($dir->child('secrets.yaml')), [ $proj, $LEIT_PUB ],
        'project key plus the parent rule';
    is $secrets->governing_sops_config, $root->child('.sops.yaml')->stringify, 'found';
    ok !$secrets->sops_config_is_ours, 'and it is not the project\'s own';

    $root->child('.sops.yaml')->spew(<<"YAML");
creation_rules:
  - path_regex: ^elsewhere/
    age: $OTHER_PUB
YAML
    is_deeply $secrets->recipients_for($dir->child('secrets.yaml')), [ $proj ],
        'a parent config without a rule for the project changes nothing (and does not die)';
};

# --- re-encryption -------------------------------------------------------------

subtest 'rotate_sops_files brings existing files to the list, and back' => sub {
    my ($dir, $secrets, $proj) = project();
    fill($dir, $secrets);
    ok !opens($dir->child('secrets.yaml'), $LEIT_SEC), 'before: the second recipient cannot read';

    $secrets->set_sops_recipients([ $LEIT_PUB ]);
    my @done = $secrets->rotate_sops_files;
    is_deeply [ sort @done ], [ qw(keys.yaml kubeconfig.yaml secrets.yaml) ], 'all three re-encrypted';
    for my $f (@done) { ok opens($dir->child($f), $LEIT_SEC), "after add: $f opens for it" }
    is $secrets->read_secret('hetzner_token'), 'tok', 'the content is unchanged';
    like $dir->child('secrets.yaml')->slurp, qr/lastmodified: "/, 'lastmodified quoted as OCP writes it';

    $secrets->set_sops_recipients([]);
    $secrets->rotate_sops_files;
    my $proj_sec = $secrets->age_key_file->slurp =~ s/\s+\z//r;
    for my $f (@done) {
        ok !opens($dir->child($f), $LEIT_SEC), "after rm: $f no longer opens for it";
        ok opens($dir->child($f), $proj_sec), "the project key still opens $f";
    }
    is_deeply [ $secrets->rotate_sops_files ], [], 'in step: nothing to do';
};

# --- the commands --------------------------------------------------------------

sub ocp_in {
    my ($dir, @args) = @_;
    my $cwd = getcwd();
    chdir $dir or die $!;
    my $err = path(tempdir(CLEANUP => 1))->child('err');
    my $out = `$^X -I'$LIB' '$BIN' @args 2>'$err' </dev/null`;
    my $rc  = $? >> 8;
    chdir $cwd or die $!;
    return ($rc, $out, $err->slurp);
}

subtest 'ocp keys recipients add / ls / rm' => sub {
    my ($dir, $secrets, $proj) = project();
    fill($dir, $secrets);

    my ($rc, $out, $err) = ocp_in($dir, qw(keys recipients add), 'age1nonsense');
    isnt $rc, 0, 'a malformed recipient is refused';
    like $err, qr/age1nonsense/, 'named';
    ok !-f $dir->child('.sops.yaml'), 'and nothing written';

    ($rc, $out, $err) = ocp_in($dir, qw(keys recipients add), $LEIT_PUB);
    is $rc, 0, 'add' or diag $err;
    ok opens($dir->child('secrets.yaml'), $LEIT_SEC), 'secrets.yaml re-encrypted for it';
    ok opens($dir->child('kubeconfig.yaml'), $LEIT_SEC), 'kubeconfig.yaml too';
    like $out, qr/keys\.yaml.*\n.*|secrets\.yaml/, 'the re-encrypted files are named';

    ($rc, $out, $err) = ocp_in($dir, qw(keys recipients add), $LEIT_PUB);
    is $rc, 0, 'adding it again is fine';
    like $out . $err, qr/already/, 'and says so';

    ($rc, $out, $err) = ocp_in($dir, qw(keys recipients ls));
    is $rc, 0, 'ls';
    is $out, "$proj\n$LEIT_PUB\n", 'STDOUT: the recipients and nothing else';
    like $err, qr/project key/, 'which one is the project key: on STDERR';

    ($rc, $out, $err) = ocp_in($dir, qw(keys recipients rm), $proj);
    isnt $rc, 0, 'the project key cannot be removed';
    like $err, qr/PIN1|project key/, 'with the reason';

    ($rc, $out, $err) = ocp_in($dir, qw(keys recipients rm), $OTHER_PUB);
    isnt $rc, 0, 'an unknown recipient';
    like $err, qr/Unknown recipient .*\n.*Available:.*\Q$LEIT_PUB\E/s, 'lists what can be removed';

    ($rc, $out, $err) = ocp_in($dir, qw(keys recipients rm), $LEIT_PUB);
    is $rc, 0, 'rm' or diag $err;
    for my $f (qw(secrets.yaml kubeconfig.yaml keys.yaml)) { ok !opens($dir->child($f), $LEIT_SEC), "$f closed to it" }
    like $err, qr/rotate/i, 'the rotation hint, on STDERR';
    like $err, qr/secrets\.yaml/, 'naming secrets.yaml';
    like $err, qr/kubeconfig\.yaml/, 'and kubeconfig.yaml';
    like $err, qr/git history/i, 'and why: the old versions stay readable';

    ($rc, $out) = ocp_in($dir, qw(keys recipients ls));
    is $out, "$proj\n", 'only the project key left';
};

subtest 'a parent .sops.yaml is read, not rewritten' => sub {
    my ($dir, $secrets, $proj, $root) = project(subdir => 'cluster');
    fill($dir, $secrets);
    $root->child('.sops.yaml')->spew(<<"YAML");
creation_rules:
  - path_regex: ^cluster/
    age: $proj
YAML
    my $before = $root->child('.sops.yaml')->slurp;

    my ($rc, $out, $err) = ocp_in($dir, qw(keys recipients add), $LEIT_PUB);
    isnt $rc, 0, 'add refuses to edit a .sops.yaml outside the project';
    like $err, qr/\Q@{[ $root->child('.sops.yaml') ]}\E/, 'names the file to edit';
    is $root->child('.sops.yaml')->slurp, $before, 'which is untouched';
    ok !-f $dir->child('.sops.yaml'), 'and no shadowing project .sops.yaml appears';

    $root->child('.sops.yaml')->spew($before =~ s/age: \Q$proj\E/age: $proj,$LEIT_PUB/r);
    ($rc, $out, $err) = ocp_in($dir, qw(keys recipients add), $LEIT_PUB);
    is $rc, 0, 'once it is listed there, add re-encrypts' or diag $err;
    ok opens($dir->child('secrets.yaml'), $LEIT_SEC), 'and the files follow';
};

done_testing;

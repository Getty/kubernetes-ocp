#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Crypt::Age;
use File::SOPS;
use JSON::MaybeXS ();
use YAML::XS ();

# The `sops:` block's `lastmodified` has to be a QUOTED scalar: gopkg.in/yaml.v3
# resolves a bare RFC3339 scalar to a Go time.Time where sops's decoder wants a
# string, so `sops -d` refuses such a document at exit 1, and File::SOPS warns
# about it on every read.
#
# File::SOPS 0.001 and 0.002 wrote it bare; from 0.003 on every YAML write
# quotes it, rotate included. k153 quoted OCP's own output on top while the
# image still carried 0.002 (until 2026-09-23); k247 dropped that, as the
# cpanfile pins 0.005. Files committed before then can still be bare, so this
# pins what OCP owes them as well as what it writes now:
#
#   1. every OCP write path produces a quoted document that round-trips;
#   2. a project File::SOPS 0.002 really wrote still opens through OCP's read
#      paths, the PIN2 layer of an admin key included;
#   3. the first rewrite through OCP repairs it;
#   4. repair_sops_lastmodified repairs it before anything else is written
#      (k259), and leaves a quoted file byte for byte alone.

use_ok('OCP');
use_ok('OCP::Secrets');
use_ok('OCP::Keys');

delete $ENV{SOPS_AGE_KEY_FILE};

my $ocp     = OCP->new;
my $ts_qr   = qr/^\s+lastmodified: "\d{4}-\d\d-\d\dT[\d:]+Z"\s*$/m;
my $bare_qr = qr/^\s+lastmodified: \d{4}-\d\d-\d\dT[\d:]+Z\s*$/m;
my $warn_qr = qr/time\.Time|PLAIN scalar/;

# Exit code of `sops -d` on $file with the project key of $dir; only called
# inside the image, where the sops binary is.
sub sops_exit {
    my ($dir, $file) = @_;
    local $ENV{SOPS_AGE_KEY_FILE} = $dir->child('.ocp/age.key')->stringify;
    system('sops -d ' . $dir->child($file) . ' >/dev/null 2>&1');
    return $? >> 8;
}

#
# 1. The four write paths OCP owns all produce quoted, round-tripping files.
#

my $dir = path(tempdir(CLEANUP => 1));
my $secrets = OCP::Secrets->new(project_dir => $dir);
$secrets->generate_age_key;

# secrets.yaml
$secrets->create_secrets(hetzner_token => 'tok-123');
like( $dir->child('secrets.yaml')->slurp, $ts_qr,
      'create_secrets quotes lastmodified' );
is( $secrets->read_all_secrets->{hetzner_token}, 'tok-123',
    'secrets round-trip (MAC verified)' );

# kubeconfig.yaml
my $kc = "apiVersion: v1\nkind: Config\nclusters: []\n";
$secrets->save_kubeconfig($kc);
like( $dir->child('kubeconfig.yaml')->slurp, $ts_qr,
      'save_kubeconfig quotes lastmodified' );
# read_kubeconfig re-serializes via YAML, so compare the parsed structure.
is_deeply( $ocp->load($secrets->read_kubeconfig), $ocp->load($kc),
    'kubeconfig round-trip (MAC verified)' );

# generic encrypt_file / decrypt_file
$secrets->encrypt_file("foo: bar\n", 'extra.yaml');
like( $dir->child('extra.yaml')->slurp, $ts_qr,
      'encrypt_file quotes lastmodified' );
is_deeply( $ocp->load($secrets->decrypt_file('extra.yaml')), { foo => 'bar' },
    'encrypt_file round-trip (MAC verified)' );

# keys.yaml (OCP::Keys)
my $keys = OCP::Keys->new(project_dir => $dir);
$keys->add_key(
    name    => 'robo-ssh',
    type    => 'ed25519',
    private => "PRIVATE-KEY-MATERIAL",
    public  => "ssh-ed25519 AAAA robo",
    purpose => 'automation',
);
like( $dir->child('keys.yaml')->slurp, $ts_qr,
      'OCP::Keys quotes lastmodified' );
my $got = $keys->get_key('robo-ssh');
is( $got && $got->{name}, 'robo-ssh',
    'keys round-trip (MAC verified)' );

subtest 'sops reads what OCP writes' => sub {
    plan skip_all => 'not inside the OCP image' unless -x '/usr/local/bin/sops';
    is( sops_exit($dir, $_), 0, "sops -d $_" )
        for qw(secrets.yaml kubeconfig.yaml extra.yaml keys.yaml);
};

#
# 2. A project as File::SOPS 0.002 wrote it -- the documents at the end of
#    this file, made by that release, bare timestamp and all -- still opens.
#

my %fx = legacy_fixture();
my $old = path(tempdir(CLEANUP => 1));
$old->child('.ocp')->mkpath;
$old->child('.ocp/age.key')->spew("$fx{key}\n");
$old->child('.ocp/age.key')->chmod(0600);
$old->child('.ocp/age.pub')->spew("$fx{pub}\n");
$old->child('secrets.yaml')->spew_raw($fx{secrets});
$old->child('keys.yaml')->spew_raw($fx{keys});

like( $old->child($_)->slurp, $bare_qr, "the 0.002 $_ carries a bare lastmodified" )
    for qw(secrets.yaml keys.yaml);

my $old_secrets = OCP::Secrets->new(project_dir => $old);
my $old_keys    = OCP::Keys->new(project_dir => $old);

sub legacy_reads_ok {
    my ($label) = @_;
    is( eval { $old_secrets->read_secret('hetzner_token') }, 'tok-legacy-0.002',
        "$label: read_secret (MAC verified)" );
    my $robo = eval { $old_keys->decrypt_key('robo-ssh') };
    is( $robo && $robo->{private}, "ROBO-PRIVATE\n",
        "$label: automation key, age layer" );
    my $admin = eval { $old_keys->decrypt_key('admin-ssh', 'pin-two') };
    is( $admin && $admin->{private}, "ADMIN-PRIVATE\n",
        "$label: admin key, PIN2 layer under age" );
}

# File::SOPS flags the bare timestamp on every read of a 0.002 file, and the
# rewrites below read before they write; anything else still gets through.
local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ $warn_qr };

legacy_reads_ok('0.002 project');

#
# 3. The first rewrite through OCP quotes the timestamp; nothing is lost.
#

$old_secrets->update_secret(other => 'x');
like( $old->child('secrets.yaml')->slurp, $ts_qr, 'update_secret repairs secrets.yaml' );

$old_keys->add_key(
    name    => 'third',
    type    => 'ed25519',
    private => "THIRD-PRIVATE\n",
    public  => 'ssh-ed25519 AAAA third',
    purpose => 'automation',
);
like( $old->child('keys.yaml')->slurp, $ts_qr, 'add_key repairs keys.yaml' );

my $warned = '';
{
    local $SIG{__WARN__} = sub { $warned .= $_[0] };
    legacy_reads_ok('repaired project');
}
unlike( $warned, $warn_qr, 'no lastmodified warning once repaired' );

subtest 'sops refuses the 0.002 documents and reads them repaired' => sub {
    plan skip_all => 'not inside the OCP image' unless -x '/usr/local/bin/sops';
    my $raw = path(tempdir(CLEANUP => 1));
    $raw->child('.ocp')->mkpath;
    $raw->child('.ocp/age.key')->spew("$fx{key}\n");
    $raw->child('secrets.yaml')->spew_raw($fx{secrets});
    $raw->child('keys.yaml')->spew_raw($fx{keys});
    for my $f (qw(secrets.yaml keys.yaml)) {
        isnt( sops_exit($raw, $f), 0, "sops -d refuses the 0.002 $f" );
        is( sops_exit($old, $f), 0, "sops -d reads the repaired $f" );
    }
};

#
# 4. Repaired at rest (k259). Nothing in 3. happens to a project nobody
#    changes, so repair_sops_lastmodified rewrites the bare files of the run
#    that holds the key -- same plaintext, same recipients -- and leaves a
#    quoted file byte for byte as it is.
#

my @owned = OCP::Secrets->sops_file_names;
is_deeply( \@owned, [qw(keys.yaml secrets.yaml kubeconfig.yaml)],
    'the files OCP owns, all three in the 0.002 fixture' );

# A fresh copy of the 0.002 project, all three files.
sub legacy_project {
    my $d = path(tempdir(CLEANUP => 1));
    $d->child('.ocp')->mkpath;
    $d->child('.ocp/age.key')->spew("$fx{key}\n");
    $d->child('.ocp/age.key')->chmod(0600);
    $d->child('.ocp/age.pub')->spew("$fx{pub}\n");
    $d->child("$_.yaml")->spew_raw($fx{$_}) for qw(keys secrets kubeconfig);
    return $d;
}

# What each file holds: its bytes, its recipients, and its plaintext as
# File::SOPS returns it, encoded canonically so the types count too (an int
# encodes as 0, a string as "0").
my $json = JSON::MaybeXS->new(canonical => 1, convert_blessed => 1);
sub snapshot {
    my ($d, $key) = @_;
    my %s;
    for my $f (@owned) {
        my $raw  = $d->child($f)->slurp_raw;
        my $data = do {
            local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ $warn_qr };
            File::SOPS->decrypt(encrypted => $raw, identities => [$key], format => 'yaml');
        };
        $s{$f} = {
            raw        => $raw,
            plaintext  => $json->encode($data),
            recipients => [ $raw =~ /^\s+recipient: (age1\S+)/mg ],
        };
    }
    return \%s;
}

# repair_sops_lastmodified with STDOUT, STDERR and warnings each caught.
sub repair {
    my ($d) = @_;
    my ($out, $err, $warned) = ('', '', '');
    open my $ofh, '>', \$out or die "capture stdout: $!";
    open my $efh, '>', \$err or die "capture stderr: $!";
    my @done = do {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        local $SIG{__WARN__} = sub { $warned .= $_[0] };
        OCP::Secrets->new(project_dir => $d)->repair_sops_lastmodified;
    };
    close $ofh;
    close $efh;
    return { done => \@done, out => $out, err => $err, warned => $warned };
}

sub bytes_of { my ($d) = @_; return { map { $_ => $d->child($_)->slurp_raw } @owned } }

my $repaired = legacy_project();

subtest 'a 0.002 project: every file OCP owns is repaired, nothing lost' => sub {
    my $d = $repaired;
    like( $d->child($_)->slurp_raw, $bare_qr, "precondition: the 0.002 $_ is bare" ) for @owned;
    my $before = snapshot($d, $fx{key});

    my $r = repair($d);
    is_deeply( $r->{done}, \@owned, 'returns the files it repaired, in file order' );
    my @lines = split /\n/, $r->{out};
    is( scalar @lines, scalar @owned, 'one STDOUT line per repaired file' );
    like( $lines[$_] // '', qr/\A\[ok\] Repaired \Q$owned[$_]\E: sops lastmodified quoted/,
          "the STDOUT line names $owned[$_]" ) for 0 .. $#owned;
    is( $r->{err},    '', 'nothing on STDERR' );
    is( $r->{warned}, '', 'no warning gets out, File::SOPS\'s own about the bare scalar included' );

    my $after = snapshot($d, $fx{key});
    for my $f (@owned) {
        like(   $after->{$f}{raw}, $ts_qr,   "$f: lastmodified quoted" );
        unlike( $after->{$f}{raw}, $bare_qr, "$f: no bare lastmodified left" );
        is(     $after->{$f}{plaintext}, $before->{$f}{plaintext}, "$f: same plaintext, types included" );
        is_deeply( $after->{$f}{recipients}, $before->{$f}{recipients}, "$f: same recipients" );
    }

    # The layers below SOPS: keys.yaml's private halves carry their own age
    # layer, the admin key PIN2 on top.
    my $keys  = OCP::Keys->new(project_dir => $d);
    my $robo  = eval { $keys->decrypt_key('robo-ssh') };
    is( $robo && $robo->{private}, "ROBO-PRIVATE\n", 'automation key, age layer' );
    my $admin = eval { $keys->decrypt_key('admin-ssh', 'pin-two') };
    is( $admin && $admin->{private}, "ADMIN-PRIVATE\n", 'admin key, PIN2 layer under age' );

    my $warned = '';
    {
        local $SIG{__WARN__} = sub { $warned .= $_[0] };
        my $s = OCP::Secrets->new(project_dir => $d);
        $s->read_all_secrets;
        $s->read_kubeconfig;
        $keys->list_keys;
    }
    unlike( $warned, $warn_qr, 'File::SOPS reads all three without the warning' );

    my $again = repair($d);
    is_deeply( $again->{done}, [], 'a second run repairs nothing' );
    is( $again->{out}.$again->{err}.$again->{warned}, '', 'and says nothing' );
    is_deeply( bytes_of($d), { map { $_ => $after->{$_}{raw} } @owned },
        'every file byte-identical after the second run' );
};

subtest 'a recipient beyond the project key stays one' => sub {
    # An operator's recipient (k216) in a bare file, and no .sops.yaml that
    # would name it: the document's own list is the one to keep. Built by
    # unquoting what File::SOPS writes now -- the MAC's AAD is the timestamp
    # string, so the document stays valid and is 0.002's shape where it counts.
    my $d = legacy_project();
    my ($op_pub, $op_key) = Crypt::Age->generate_keypair;
    my $raw = File::SOPS->encrypt(
        data       => { hetzner_token => 'tok-operator' },
        recipients => [ $fx{pub}, $op_pub ],
        format     => 'yaml',
    );
    $raw =~ s/^(\s+lastmodified: )"([^"]+)"$/$1$2/m or die 'no quoted lastmodified';
    $d->child('secrets.yaml')->spew_raw($raw);
    like( $raw, $bare_qr, 'precondition: bare' );

    my $r = repair($d);
    ok( grep( { $_ eq 'secrets.yaml' } @{ $r->{done} } ), 'secrets.yaml repaired' );
    my $after = $d->child('secrets.yaml')->slurp_raw;
    like( $after, $ts_qr, 'quoted' );
    is_deeply( [ $after =~ /^\s+recipient: (age1\S+)/mg ], [ $fx{pub}, $op_pub ],
        'both recipients, in their order' );
    my $data = eval {
        File::SOPS->decrypt(encrypted => $after, identities => [$op_key], format => 'yaml');
    };
    is( $data && $data->{hetzner_token}, 'tok-operator', 'the operator alone still opens it' );
};

subtest 'a quoted project is left byte for byte' => sub {
    # $dir from 1.: every file written by OCP as it is now.
    like( $dir->child($_)->slurp_raw, $ts_qr, "precondition: $_ quoted" ) for @owned;
    my $before = bytes_of($dir);
    my $r = repair($dir);
    is_deeply( $r->{done}, [], 'nothing repaired' );
    is( $r->{out}.$r->{err}.$r->{warned}, '', 'nothing said' );
    is_deeply( bytes_of($dir), $before, 'every file byte-identical' );
};

subtest 'only the sops lastmodified counts, and only bare' => sub {
    my $d = path(tempdir(CLEANUP => 1));
    my $s = OCP::Secrets->new(project_dir => $d);
    my $pub = $s->generate_age_key->{public_key};

    # A plain timestamp under a user's own `lastmodified`, at the sops
    # section's indentation, before and after it: never the one to repair.
    my $ts = '2026-01-01T00:00:00Z';
    $d->child('kubeconfig.yaml')->spew_raw( File::SOPS->encrypt(
        data              => { meta => { lastmodified => $ts }, zone => { lastmodified => $ts } },
        recipients        => [$pub],
        unencrypted_regex => '^lastmodified$',
        format            => 'yaml',
    ) );
    my $kc = $d->child('kubeconfig.yaml')->slurp_raw;
    like( $kc, qr/^meta:\n  lastmodified: \Q$ts\E$/m, 'precondition: plain data timestamp before sops:' );
    like( $kc, qr/^zone:\n  lastmodified: \Q$ts\E$/m, 'precondition: plain data timestamp after sops:' );

    # The sops one quoted the other way, and tagged: sops reads both.
    $s->create_secrets(hetzner_token => 'tok');
    $s->encrypt_file("foo: bar\n", 'keys.yaml');
    for my $c ([ 'secrets.yaml', q{'%s'} ], [ 'keys.yaml', '!!str %s' ]) {
        my ($f, $fmt) = @$c;
        my $raw = $d->child($f)->slurp_raw;
        $raw =~ s/^(\s+lastmodified: )"([^"]+)"$/$1.sprintf($fmt, $2)/me
            or die "no quoted lastmodified in $f";
        $d->child($f)->spew_raw($raw);
    }
    like( $d->child('secrets.yaml')->slurp_raw, qr/^\s+lastmodified: '/m, 'precondition: single-quoted' );
    like( $d->child('keys.yaml')->slurp_raw,    qr/^\s+lastmodified: !!str /m, 'precondition: tagged' );
    ok( eval { $s->read_all_secrets->{hetzner_token} eq 'tok' }, 'precondition: the single-quoted one still opens' );
    ok( eval { $s->decrypt_file('keys.yaml') }, 'precondition: the tagged one still opens' );

    my $before = bytes_of($d);
    my $r = repair($d);
    is_deeply( $r->{done}, [], 'nothing repaired' );
    is( $r->{out}.$r->{err}, '', 'nothing said' );
    is_deeply( bytes_of($d), $before, 'every file byte-identical' );
};

subtest 'a file that cannot be rewritten: STDERR, unchanged, the rest goes on' => sub {
    my $d = legacy_project();
    # One flipped ciphertext bit: File::SOPS refuses the value, so rotate
    # cannot decrypt the file and writes nothing.
    my $file = $d->child('secrets.yaml');
    my $tampered = $file->slurp_raw =~ s/data:P4DLlRKVeWBcJSqMwbzfwQ==/data:P4DLlRKVeWBcJSqMwbzfwA==/r;
    isnt( $tampered, $file->slurp_raw, 'precondition: secrets.yaml tampered' );
    $file->spew_raw($tampered);

    my $r = eval { repair($d) };
    ok( $r, 'does not die' ) or diag $@;
    is_deeply( $r->{done}, [qw(keys.yaml kubeconfig.yaml)], 'the other two are repaired' );
    like( $r->{err}, qr/\A\[!!\] Could not repair secrets\.yaml: \S/, 'STDERR names the file' );
    like( $r->{err}, qr/sops -d refuses/, 'and says what is wrong with it' );
    like( $r->{err}, qr/The file is\s+unchanged/, 'and that nothing was written' );
    unlike( $r->{out}, qr/secrets\.yaml/, 'no [ok] line for it' );
    is( $file->slurp_raw, $tampered, 'secrets.yaml byte-identical' );
};

subtest 'no key at hand: no repair, and no PIN1 for it' => sub {
    my $d = legacy_project();
    $d->child('.ocp/age.key')->remove;
    $d->child('age.key.enc')->spew("behind PIN1\n");
    no warnings qw(once redefine);
    local *OCP::Password::prompt_password = sub { die "asked for a PIN\n" };

    my $before = bytes_of($d);
    my $r = eval { repair($d) };
    ok( $r, 'does not die' ) or diag $@;
    is_deeply( $r->{done}, [], 'nothing repaired' );
    is( $r->{out}.$r->{err}, '', 'nothing said: the run\'s own reads say what is missing' );
    is_deeply( bytes_of($d), $before, 'every file byte-identical' );
};

subtest 'a foreign key: no repair, and no word about it' => sub {
    # The run's own decrypt names that key and the project's (k118); a line
    # about a cosmetic repair ahead of it would only bury that.
    my $d = legacy_project();
    my (undef, $foreign) = Crypt::Age->generate_keypair;
    $d->child('.ocp/age.key')->spew("$foreign\n");

    my $before = bytes_of($d);
    my $r = eval { repair($d) };
    ok( $r, 'does not die' ) or diag $@;
    is_deeply( $r->{done}, [], 'nothing repaired' );
    is( $r->{out}.$r->{err}, '', 'nothing said' );
    is_deeply( bytes_of($d), $before, 'every file byte-identical' );
    ok( !eval { OCP::Secrets->new(project_dir => $d)->read_kubeconfig; 1 }
        && $@ =~ /does not belong to this project/,
        'the run\'s own read says it, by name' );
};

subtest 'SOPS_AGE_KEY_FILE is a key at hand as well' => sub {
    my $d = legacy_project();
    $d->child('.ocp/age.key')->remove;
    my $id = path(tempdir(CLEANUP => 1))->child('identity.txt');
    $id->spew("# test-only\n$fx{key}\n");
    local $ENV{SOPS_AGE_KEY_FILE} = $id->stringify;

    my $r = repair($d);
    is_deeply( $r->{done}, \@owned, 'all three repaired' );
    like( $d->child($_)->slurp_raw, $ts_qr, "$_ quoted" ) for @owned;
};

subtest 'sops -d reads the repaired files, to the same plaintext' => sub {
    plan skip_all => 'not inside the OCP image' unless -x '/usr/local/bin/sops';
    my $fresh = legacy_project();
    my $plain = snapshot($repaired, $fx{key});
    for my $f (@owned) {
        isnt( sops_exit($fresh, $f), 0, "sops -d refuses the 0.002 $f" );
        is( sops_exit($repaired, $f), 0, "sops -d reads the repaired $f" );
        local $ENV{SOPS_AGE_KEY_FILE} = $repaired->child('.ocp/age.key')->stringify;
        # sops prints UTF-8; File::SOPS hands back characters (keys.yaml's
        # private halves are age ciphertext, code points up to 0xFF).
        my $out = `sops -d --output-type json $repaired/$f`;
        is_deeply( JSON::MaybeXS->new(utf8 => 1)->decode($out), $json->decode($plain->{$f}{plaintext}),
            "sops -d of the repaired $f is the plaintext File::SOPS reads" );
    }
};

done_testing;

# Written by File::SOPS 0.002 (git tag 0.002 of p5-file-sops) for the test-only
# age key below: secrets.yaml with hetzner_token, keys.yaml with the entries
# OCP::Keys->add_key made for an automation key and an admin key (PIN2
# 'pin-two'), re-encrypted unchanged by that release; kubeconfig.yaml as
# OCP::Secrets->save_kubeconfig wrote an RKE2-shaped kubeconfig under it
# (k259), its sops section between two root keys.
sub legacy_fixture {
    return (
        key => 'AGE-SECRET-KEY-19R7KDAQCNK09ARC3SNHA7UMU0XHN33MDV8QQC82CF4SUU4YX7XDSDKDTHH',
        pub => 'age1c6cvesac45gqrrp04x22gqcwse6kagvr5erpgzda98xkvaqtffsqj4nthk',
        secrets => <<'YAML',
---
hetzner_token: ENC[AES256_GCM,data:P4DLlRKVeWBcJSqMwbzfwQ==,iv:XLo1+34YlPgBLWPbCKZJn5GphHMBEXdZzrx/YlgnyEs=,tag:gut3zNSZCFhAmr1sfLZr6w==,type:str]
sops:
  age:
  - enc: |
      -----BEGIN AGE ENCRYPTED FILE-----
      YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBFNnRxam93bkFwWXRPTmtr
      TlFPdWhuS0syRkN5OGVKdUhkaXNIWklscVJRCmRkaFFIZFdrcmkxbmY4VklENVk1
      d3ZwSlFYVlFJMTR6MDJ6TjlGYm55a1UKLS0tIGMzbC83UTd2YWE2TmpabllXQ0FC
      SjVMcUR2QWI3YzR2bys0UFNwd1hhQkEKCbxhkXcgZAIlneWWpWywcXkcyQ8MywBd
      f+Xmjv4wP++h7fg8P0NAzvuC2TpVw52E410UQfG6H9rrEiwpeXioGw==
      -----END AGE ENCRYPTED FILE-----
    recipient: age1c6cvesac45gqrrp04x22gqcwse6kagvr5erpgzda98xkvaqtffsqj4nthk
  azure_kv: []
  gcp_kms: []
  hc_vault: []
  kms: []
  lastmodified: 2026-10-31T01:39:38Z
  mac: ENC[AES256_GCM,data:6fNuEmGwTtYzDJ1xYYQ3u9QWEMOKxSgpAeqrQf5NpdeK3bI6zx05/hDxwBTyn5sRNVpBgNIqdBiXeFe1sdddWYH4iv4WjLl4ij+RCKb8BLb820IfFrO0Mz2mq5K6P4ujn9u7mDgmP8QoVNmJeqc5cfALgDi/7mjk7KUfDeOQx58=,iv:HeuE+LHLIbaT+c/b0ktCE+pTU7TqwPtWEZbshs8eahc=,tag:EOZMx80/28sUhcMmmrFuFQ==,type:str]
  pgp: []
  unencrypted_suffix: _unencrypted
  version: 3.7.3
YAML
        keys => <<'YAML',
---
keys:
- created: ENC[AES256_GCM,data:DP9xS+2sRpqkOwm7qk5R7QY/jTY=,iv:gFE7r0oORR8IsFPS+YTVfz5SVXkUgn2rVnkjh3qAljU=,tag:dyEdQgHQLUEnoRCkFoCB8A==,type:str]
  deprecated: ENC[AES256_GCM,data:NA==,iv:dOmE7Ck2Zmmpr/Tsxhv6KPsoC4/M5ARF/+9bULssaAI=,tag:G76hspr+2QLvIH50aFJOrg==,type:int]
  name: ENC[AES256_GCM,data:j2DZQcOCN88=,iv:Rx5D1S74wp6Yfu5txXngXEVbgghPqGY9Ww9tgD1529I=,tag:T2lbnklsVH3MmHFX0GU7UQ==,type:str]
  private: ENC[AES256_GCM,data:rbe16befiQY4DlDzRIVEkuGK3hNBC/x9yCRhSGSoJjutEQSsFzPYCnRfd08GGZ8nUy+ErDN3i0O9Mog0eF+Y7vDxOLW8siyrvhnGIur5Vif3MTJvbwAy+W9K3c/Lq/htiriw4DcRe3+8w+q27R4RxJ5zB2wHjMUbRDSJcLTSbdSYApDM8RqOnSYGTHqKAAXaQJXeLwDan/Cby5kYiC9k5pTBWz6PDD+bPN3rpel82hBj8oM5x5nflLDEH6mtL8D21mj+3Ts/WWDwLqhFsdDTOBIdzcXtif7YC/rRPjEluQo76aWzycVbj0Yxeua0Mw==,iv:dmbSBSpWjp2HSh4NH0hmWpswhY3jLzF/KlHcgWlv2DA=,tag:9MfrO393gof9tWvNW55hdg==,type:str]
  public: ENC[AES256_GCM,data:ZL+QGEQ9VwQf3QADo2ov0eogtxcj,iv:e2Oh1hHJeMMd3wn7EYtrhgj6l+S5B1FX2dL7t8E6zrQ=,tag:BMlok1j2IuRbuOUc4+A4xQ==,type:str]
  purpose: ENC[AES256_GCM,data:ddECaLYpkYgbDg==,iv:tuEJqt+tgp+7ILOZh46QH2u3U+A54IE59GCC2XSLeP4=,tag:jXKyuNv393soQN6s17qfSQ==,type:str]
  type: ENC[AES256_GCM,data:XkP5uWPjZA==,iv:VVoGSI1PWQ0R86EY5Y+vfrXArIFGRsmYhQyHPy6s6Og=,tag:iTifB0KNT+TaHWFXIZfhug==,type:str]
- created: ENC[AES256_GCM,data:YKyikDUEcnLCDxJFDK+yOZorJHM=,iv:+hRWGAKnr2cUBn/56iCqnGpTEN/CFGJKum3QCAZo5Zw=,tag:Bj3iRD38CqP6BML7BEbJzw==,type:str]
  deprecated: ENC[AES256_GCM,data:mQ==,iv:8Cn56ZkanJdVRtdoc8MWY/6BPAmNYHL8SRBOM4h2I5c=,tag:SGW4Xp/pOnDJ/GHq6/254w==,type:int]
  name: ENC[AES256_GCM,data:V7yx1Lt9BT2M,iv:7fi51n2aocIPg8JqORfbl0coEaKxGWyAXio7Z0MsnFQ=,tag:OlfCJQWXtzQsMKQMoE3yrQ==,type:str]
  private: ENC[AES256_GCM,data:sGPm7zbz1BMqctwZYtsufl0HsipKNSGGnxjSuQEQMJyNWsgBC6h3KhN1bZye8EgH1Lvy4zhszFVOKeU/LvVnPGggYntrxyVeYCGH2SOmn1TPpP1lhSGA23vOy1d6DZKEGKGfpiUHIsbWcz5VycSnWR0Cu/EO1/QbAJMPkLoZFdCT6p0VtMpXfpL75t2p64m8Z7FZ0T+eNSjETFpUDs2MmovHPl4B0M2U3+L3XE1MDAGe41G4DC+IoPUjsb8VGxKq/R8jJn/0i1JoZ24ChW2CuqDtZhO4jgecuBudlzZmhqRjsFUZj/paAXBrpcgTsDCAMJyJL4mGExxI8+xy4tn6hfek8VeI2dEJsZE7VG0zwW3jT+aUH54WFhwI75RTZham9mgXem3G3KzUG3h/MRIU0Tk2OGUYeIVb/X83uKMDixMsXVBRU7DDyUtWQUkqMu+lWM6CGPVm,iv:mF/YVQKV3IQ5VC/kSJpMGN3BKBY9T4NBSXQNnfdy4pA=,tag:RLzHoJHRUAPvEdv3My9b3A==,type:str]
  public: ENC[AES256_GCM,data:3Av2JHfFzoQLX6r64k4dBzN78l/3Cw==,iv:VOKTJBg4r2mwNYVHAOWBBD35zPcuZ77f08e1Q7Z2izI=,tag:SdBFwGjr2wfgIY2PiaxJ7Q==,type:str]
  purpose: ENC[AES256_GCM,data:HfzYb/I=,iv:4V5VwFgPmWwtcQjEy8rMorIs2boO/m/vd6NPFWrPuyI=,tag:5dWK/M2IODuSQBqC+M2hjQ==,type:str]
  type: ENC[AES256_GCM,data:w/zBW1nEwA==,iv:1Cys5MqL6+7o2fzjgk0/LJtpsHOVXZRk8cu5C9X3y74=,tag:qXwXvp+WHiabGGE5dDLcmw==,type:str]
sops:
  age:
  - enc: |
      -----BEGIN AGE ENCRYPTED FILE-----
      YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBqZXI2dHB4SmwrS2ZvQ1NQ
      RmExdmNwZHRmRVQ4WEpNdHo5anl5RlRTUlNFCi9jaU1pNlE0Y0FBbnZHb3pkOWJu
      SlFoVlB2RER1TFdxN3BUSkVRNmg3MFEKLS0tIDYrQUhzYWxPOXpycDhKNHFRZmRl
      SGJzeXRvTTF5RGhpU2JyR044MUJCY1kKsCyEH/pvHzb/Gz26/zono1xNl/Zum74V
      W03aXkPKu44n3bZpCws73TyzdU9IBQcLuoxyjHGnHVF53ET0MUh3aA==
      -----END AGE ENCRYPTED FILE-----
    recipient: age1c6cvesac45gqrrp04x22gqcwse6kagvr5erpgzda98xkvaqtffsqj4nthk
  azure_kv: []
  gcp_kms: []
  hc_vault: []
  kms: []
  lastmodified: 2026-10-31T01:39:38Z
  mac: ENC[AES256_GCM,data:AeEan+nPB4GG9bToR1hDaq0CMFQGbmaPDtoSbn/oi+6x4C5+ZztG+O01NiOdVrdSpKgEZACCB4PzCDVguY7rBVr56CKU7yJVGk69F8l4t1r8mY7thdnOT3iKfOalUoXaJRgzkd++ED0U++zAdwEkYYx2UeULqP7NVO4dVE/Sp+g=,iv:sG19Sftgg+P6Id10SPpJRwLPDy4mrm/x3Jm6mKXx7Dc=,tag:ui9itHjn07YcSikshAQcOg==,type:str]
  pgp: []
  unencrypted_suffix: _unencrypted
  version: 3.7.3
version: ENC[AES256_GCM,data:qw==,iv:hXcx6MBeYcxNA3X67G43VC2ZDuCX5xIhariL+kPil/4=,tag:ctk+Fpe0546f6kpYM7B38g==,type:int]
YAML
        kubeconfig => <<'YAML',
---
apiVersion: ENC[AES256_GCM,data:T/U=,iv:XoWiCx63eoKfuHQuXZOSlSFwZGpIRlCLOjn28TmEydc=,tag:4JlenJLYjceUUGbrUveO+g==,type:str]
clusters:
- cluster:
    certificate-authority-data: ENC[AES256_GCM,data:g7pQCkuLNRpSglQB,iv:qwHfzpZ1+tjw4KZTI2/yNhP0jKhgo78EQXQIZWyBMnU=,tag:sG41aTaxh4IVx0cjTtO1JQ==,type:str]
    server: ENC[AES256_GCM,data:dRnzSPRxM58Y/qV/IDU9rtqgh5OOww==,iv:zZlZnxMpxTDlw4ttqmkAA6UHh3c5kvRKJDPVs/dVe2Y=,tag:1Z0ufhije/KKTRDpkkPupg==,type:str]
  name: ENC[AES256_GCM,data:izp0fAE/rA==,iv:7fF9Y1bJrNT43+pz0D+N8VwjF4Cxek1skkAz5kmg/HY=,tag:rmnzJf9tqRcqidbnDST6Ow==,type:str]
contexts:
- context:
    cluster: ENC[AES256_GCM,data:JgMxvJbNzg==,iv:0jERXanxZb3PQi12YxofdQ7PVExBnpeASzB2VhcKLS0=,tag:vLd1D6vm3oRnP1gMhWQ6DA==,type:str]
    user: ENC[AES256_GCM,data:mHySPuFCIw==,iv:bXqgpRp6UpZJnuzd1dtqnXhLuo6io1edszw76dv0v3A=,tag:/t/aqH2HGJDdAfCJvkmcRg==,type:str]
  name: ENC[AES256_GCM,data:oJYzFuU1HQ==,iv:kBzJD1WBFLBIUKzHK+SWHvyB7/0P19HXtToJlfdUegE=,tag:F3cxYVArES/3kkfkP8IXwA==,type:str]
current-context: ENC[AES256_GCM,data:QcAHGkAfTg==,iv:5SqW2IYgQ1abVWBKCFApZbJxGLe523FBRoToYrR4LPc=,tag:L1l4iU6m3fyDCbUqekU/QA==,type:str]
kind: ENC[AES256_GCM,data:CyPYvrAu,iv:SOTzPP6xo+YCesushOINomlR8K02yHheDWMwSH54Ejg=,tag:65k/A3KLNxYm3TDGI92H3w==,type:str]
preferences: {}
sops:
  age:
  - enc: |
      -----BEGIN AGE ENCRYPTED FILE-----
      YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA1V1lIcm5ZVXZsdTN1UzFr
      SlBIZGxzbVIxSElsZUJEZEJrREhOS2duVTJJCnNhMUg3UHV0TmVWQXRpMVd4eFox
      MUUxVk83eGlZRkcvYUt2KzNxcWhZMVkKLS0tIHAza0RFcTNhQmkvVHRXa3hCamVV
      d0JuK1lQTXZYeEpzUEUwTGZHa2o0UUkK7kyqDgCYmGKoDGQ4Nd431U6y/YBWnHYz
      R3lZhjcKf/5zVIjJaIybpdVw+hXbVE9cMZY/0J5bx7A+QGDBX+cDpw==
      -----END AGE ENCRYPTED FILE-----
    recipient: age1c6cvesac45gqrrp04x22gqcwse6kagvr5erpgzda98xkvaqtffsqj4nthk
  azure_kv: []
  gcp_kms: []
  hc_vault: []
  kms: []
  lastmodified: 2026-10-31T02:01:19Z
  mac: ENC[AES256_GCM,data:pcT3LYdKhjCzT8TqT86xlwqX0QEGu8RcmGP6fPZyQRn95iLH1KZgKlVCB53GoIx3ZtBDHDH4pjAL88r4gKJTTpO58TsmqJm4RksSrlIMCX0ua/AchTqAV9CGtY2Qby9qo2mOF07oPjbXuRqfW24H/GMCzvK0eOg8K250faY//DU=,iv:715H2cKXhwKVrmwAMWJhwSVv9nO8ZAwiFJknts05ePw=,tag:jzUG9emCODHaSNxsC6wkHQ==,type:str]
  pgp: []
  unencrypted_suffix: _unencrypted
  version: 3.7.3
users:
- name: ENC[AES256_GCM,data:ljUg9AmzxA==,iv:U+K1XCsuPLHy5q/mRUOx+8o5xKhbiLr1mzwjHVV5sQ8=,tag:GscjBt2KpmZvPUe8zj0ooA==,type:str]
  user:
    client-certificate-data: ENC[AES256_GCM,data:l9jJktb4QaEBqjGkiqs=,iv:9UZoFZN0dkbhGS2raNkYDZ4UQR0A9AvuFuwV1ru45r4=,tag:zx/UASVBTeKWBwAq9Tx6vA==,type:str]
    client-key-data: ENC[AES256_GCM,data:V76E0p2M6F08xgL7HA==,iv:wC4j8w3U1SQxLzbT6eiojvmo4uKvzR2tw9IMv+xr75c=,tag:nu8j58BRJP9ufhJIqNj/kQ==,type:str]
YAML
    );
}

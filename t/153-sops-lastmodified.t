#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

# k153: File::SOPS before 0.004 emits the `sops:` block's `lastmodified` as a
# bare YAML scalar. gopkg.in/yaml.v3 resolves a bare RFC3339 scalar to a Go
# time.Time where sops's decoder wants a string, so `sops` refuses such a
# document and File::SOPS carps once on every decrypt -- noise on every ocp
# command that reads an encrypted file. OCP normalizes its own SOPS output so
# the committed material always quotes the timestamp and stays sops-compatible
# whatever File::SOPS version produced it.

use_ok('OCP');
use_ok('OCP::Secrets');
use_ok('OCP::Keys');

#
# The value normalizer itself -- version-independent, deterministic.
#

my $ocp = OCP->new;

my $bare = <<'YAML';
data: ENC[AES256_GCM,data:xx,type:str]
sops:
    age: []
    lastmodified: 2026-09-20T15:03:35Z
    mac: ENC[AES256_GCM,data:yy,type:str]
    version: 3.11.0
YAML

my $fixed = $ocp->quote_sops_lastmodified($bare);
like(
    $fixed,
    qr/^\s+lastmodified: "2026-09-20T15:03:35Z"\s*$/m,
    'a bare RFC3339 lastmodified is emitted as a quoted string',
);
is(
    $ocp->quote_sops_lastmodified($fixed), $fixed,
    'already-quoted lastmodified is left untouched (idempotent)',
);

# Only the metadata line moves: an ENC value that merely spells "lastmodified"
# is never a bare RFC3339 scalar, so nothing else is rewritten.
my @in  = split /\n/, $bare;
my @out = split /\n/, $fixed;
is( scalar(grep { $in[$_] ne $out[$_] } 0 .. $#in), 1,
    'exactly one line changes' );

#
# The four write paths OCP owns all produce quoted, round-tripping files.
#

my $dir = path(tempdir(CLEANUP => 1));
my $secrets = OCP::Secrets->new(project_dir => $dir);
$secrets->generate_age_key;

my $ts_qr = qr/^\s+lastmodified: "\d{4}-\d\d-\d\dT[\d:]+Z"\s*$/m;

# secrets.yaml
$secrets->create_secrets(hetzner_token => 'tok-123');
like( $dir->child('secrets.yaml')->slurp, $ts_qr,
      'create_secrets quotes lastmodified' );
is( $secrets->read_all_secrets->{hetzner_token}, 'tok-123',
    'secrets round-trip after quoting (MAC verified)' );

# kubeconfig.yaml
my $kc = "apiVersion: v1\nkind: Config\nclusters: []\n";
$secrets->save_kubeconfig($kc);
like( $dir->child('kubeconfig.yaml')->slurp, $ts_qr,
      'save_kubeconfig quotes lastmodified' );
# read_kubeconfig re-serializes via YAML, so compare the parsed structure.
is_deeply( $ocp->load($secrets->read_kubeconfig), $ocp->load($kc),
    'kubeconfig round-trip after quoting (MAC verified)' );

# generic encrypt_file / decrypt_file
$secrets->encrypt_file("foo: bar\n", 'extra.yaml');
like( $dir->child('extra.yaml')->slurp, $ts_qr,
      'encrypt_file quotes lastmodified' );
is_deeply( $ocp->load($secrets->decrypt_file('extra.yaml')), { foo => 'bar' },
    'encrypt_file round-trip after quoting (MAC verified)' );

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
    'keys round-trip after quoting (MAC verified)' );

#
# A legacy file (bare timestamp, as an old File::SOPS wrote it) is repaired
# in place, MAC-safe and without the decrypt-path warning. This is the exact
# bug -> fix path, on whatever File::SOPS version is installed.
#

my $kcfile = $dir->child('kubeconfig.yaml');
(my $legacy = $kcfile->slurp) =~ s/lastmodified: "([^"]+)"/lastmodified: $1/;
$kcfile->spew($legacy);
unlike( $kcfile->slurp, $ts_qr, 'legacy file has a bare timestamp' );

$kcfile->spew( $ocp->quote_sops_lastmodified($kcfile->slurp) );
like( $kcfile->slurp, $ts_qr, 'legacy file is re-quoted in place' );

my $warned = '';
{
    local $SIG{__WARN__} = sub { $warned .= $_[0] };
    is_deeply( $ocp->load($secrets->read_kubeconfig), $ocp->load($kc),
        'repaired legacy file still decrypts (MAC verified)' );
}
unlike( $warned, qr/time\.Time|PLAIN scalar/,
        'no lastmodified advisory warning after repair' );

done_testing;

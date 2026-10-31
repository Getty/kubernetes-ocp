#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

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
#   3. the first rewrite through OCP repairs it.

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

done_testing;

# Written by File::SOPS 0.002 (git tag 0.002 of p5-file-sops) for the test-only
# age key below: secrets.yaml with hetzner_token, keys.yaml with the entries
# OCP::Keys->add_key made for an automation key and an admin key (PIN2
# 'pin-two'), re-encrypted unchanged by that release.
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
    );
}

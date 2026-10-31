#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Cmd::Apply;
use OCP::Keys;
use OCP::Secrets;

# k259 at the level of `ocp apply`: a project whose SOPS files File::SOPS
# 0.002 wrote (bare `lastmodified`, which `sops -d` refuses) is re-quoted by
# the run, through OCP::Secrets->repair_sops_lastmodified. t/153 pins what
# that method does to a file; this pins where apply calls it:
#
#   - before the fork into bootstrap / reconcile, so both paths repair, and
#     before either path's first decrypt;
#   - after the banner, its [ok] lines set off by a blank line;
#   - never under --dry-run, which writes nothing;
#   - a project OCP writes today goes through byte for byte.
#
# Neither path gets further than its first step: the reconcile and the
# bootstrap are stubbed, each recording the files as it found them, so no
# cluster, SSH host or provider is touched.

delete $ENV{SOPS_AGE_KEY_FILE};

package FakeOCP {
    sub new     { bless { config => $_[1] }, $_[0] }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

package main;

my %fx      = legacy_fixture();
my @owned   = OCP::Secrets->sops_file_names;
my $ts_qr   = qr/^\s+lastmodified: "\d{4}-\d\d-\d\dT[\d:]+Z"\s*$/m;
my $bare_qr = qr/^\s+lastmodified: \d{4}-\d\d-\d\dT[\d:]+Z\s*$/m;
my $warn_qr = qr/time\.Time|PLAIN scalar/;

# A project on the fixture's age key, holding the named fixture files.
sub project {
    my (@files) = @_;
    my $d = path(tempdir(CLEANUP => 1));
    $d->child('ocp.yaml')->spew_utf8(<<'YAML');
name: k259
control_planes:
  - provider: ssh
    host: 1.2.3.4
YAML
    $d->child('.ocp')->mkpath;
    $d->child('.ocp/age.key')->spew("$fx{key}\n");
    $d->child('.ocp/age.key')->chmod(0600);
    $d->child('.ocp/age.pub')->spew("$fx{pub}\n");
    $d->child("$_.yaml")->spew_raw($fx{$_}) for @files;
    return $d;
}

sub bytes_of {
    my ($d) = @_;
    return { map { $_ => $d->child($_)->slurp_raw } grep { -f $d->child($_) } @owned };
}

# `ocp apply [--dry-run]` in $d, STDOUT, STDERR and warnings each caught.
# PIN2 is the fixture's admin PIN; the bootstrap path stops where it would
# provision, the reconcile path where it would read the kubeconfig.
sub apply {
    my ($d, %opt) = @_;
    my %seen;
    my ($out, $err, $warned) = ('', '', '');

    no warnings 'redefine';
    local *OCP::Cmd::Apply::_reconcile_components = sub {
        $seen{reconcile} = bytes_of($d);
        return;
    };
    local *OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane = sub {
        $seen{bootstrap} = bytes_of($d);
        die "test stops at bootstrap\n";
    };
    local *OCP::Password::prompt_password = sub { 'pin-two' };

    my $apply = OCP::Cmd::Apply->new(
        command_chain => [ FakeOCP->new($d->child('ocp.yaml')->stringify) ],
        $opt{dry_run} ? ( dry_run => 1 ) : (),
    );

    open my $ofh, '>', \$out or die "capture stdout: $!";
    open my $efh, '>', \$err or die "capture stderr: $!";
    my $ok = eval {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        local $SIG{__WARN__} = sub { $warned .= $_[0] };
        $apply->execute([], []);
        1;
    };
    my $died = $ok ? '' : $@;
    close $ofh;
    close $efh;

    return { out => $out, err => $err, warned => $warned, died => $died, seen => \%seen };
}

# The warnings a read of a still-bare file raises, and nothing else.
sub only_bare_warnings {
    my ($warned) = @_;
    return !grep { !/$warn_qr/ } grep { length } split /\n/, $warned;
}

subtest 'reconcile path: repaired before the reconcile reads, after the banner' => sub {
    my $d = project(qw(keys secrets kubeconfig));
    like( $d->child($_)->slurp_raw, $bare_qr, "precondition: the 0.002 $_ is bare" ) for @owned;

    my $r = apply($d);
    is( $r->{died}, '', 'apply returns' ) or diag $r->{died};

    for my $f (@owned) {
        like(   $d->child($f)->slurp_raw, $ts_qr,   "$f: lastmodified quoted" );
        unlike( $d->child($f)->slurp_raw, $bare_qr, "$f: no bare lastmodified left" );
        like( $r->{seen}{reconcile}{$f} // '', $ts_qr,
              "$f: already quoted when the reconcile starts" );
    }

    my @repaired = $r->{out} =~ /^\[ok\] Repaired (\S+):/mg;
    is_deeply( \@repaired, \@owned, 'one [ok] line per file on STDOUT, naming it' );
    like( $r->{out},
          qr/CONTROL PLANE DEPLOYMENT.*^Cluster: k259\n\n\[ok\] Repaired keys\.yaml:/ms,
          'the first [ok] line comes after the banner' );
    like( $r->{out},
          qr/^\[ok\] Repaired kubeconfig\.yaml:[^\n]*\n\n\[ok\] Cluster already exists/m,
          'a blank line, then the reconcile path' );
    is( $r->{err},    '', 'nothing on STDERR' );
    is( $r->{warned}, '', 'no warning' );

    my $s = OCP::Secrets->new(project_dir => $d);
    is( $s->read_secret('hetzner_token'), 'tok-legacy-0.002', 'secrets.yaml: same value' );
    my $was = project(qw(kubeconfig));
    my $kc_was = do {
        local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ $warn_qr };
        OCP::Secrets->new(project_dir => $was)->read_kubeconfig;
    };
    is_deeply( OCP->new->load($s->read_kubeconfig), OCP->new->load($kc_was),
        'kubeconfig.yaml: same content' );

    my $before = bytes_of($d);
    my $again  = apply($d);
    unlike( $again->{out}, qr/Repaired/, 'a second apply repairs nothing' );
    is_deeply( bytes_of($d), $before, 'and leaves every file byte for byte' );
};

subtest 'reconcile path under --dry-run: nothing is rewritten' => sub {
    my $d = project(qw(keys secrets kubeconfig));
    my $before = bytes_of($d);

    my $r = apply($d, dry_run => 1);
    is( $r->{died}, '', 'apply returns' ) or diag $r->{died};
    ok( $r->{seen}{reconcile}, 'the dry run reaches the reconcile' );
    is_deeply( $r->{seen}{reconcile}, $before, 'which finds the files as they were' );
    is_deeply( bytes_of($d), $before, 'every file byte-identical' );
    like( $d->child($_)->slurp_raw, $bare_qr, "$_ still bare" ) for @owned;
    unlike( $r->{out}, qr/Repaired/, 'no [ok] Repaired line' );
    is( $r->{err}, '', 'nothing on STDERR' );
};

subtest 'bootstrap path: repaired before Step 1' => sub {
    my $d = project(qw(keys secrets));
    my @files = qw(keys.yaml secrets.yaml);
    like( $d->child($_)->slurp_raw, $bare_qr, "precondition: the 0.002 $_ is bare" ) for @files;

    my $r = apply($d);
    is( $r->{died}, "test stops at bootstrap\n", 'apply goes as far as the bootstrap' );

    for my $f (@files) {
        like( $d->child($f)->slurp_raw, $ts_qr, "$f: lastmodified quoted" );
        like( $r->{seen}{bootstrap}{$f} // '', $ts_qr, "$f: already quoted when the bootstrap starts" );
    }
    my @repaired = $r->{out} =~ /^\[ok\] Repaired (\S+):/mg;
    is_deeply( \@repaired, \@files, 'one [ok] line per file on STDOUT, naming it' );
    like( $r->{out},
          qr/^Cluster: k259\n\n\[ok\] Repaired keys\.yaml:[^\n]*\n\[ok\] Repaired secrets\.yaml:[^\n]*\n\nStep 1: /m,
          'after the banner, before Step 1, a blank line between' );
    like( $r->{out}, qr/^\[ok\] admin-key decrypted: admin-ssh$/m,
          'PIN2 still opens the admin key in the repaired keys.yaml' );
    is( $r->{err},    '', 'nothing on STDERR' );
    is( $r->{warned}, '', 'no warning, the admin key read included' );
};

subtest 'bootstrap path under --dry-run: nothing is rewritten' => sub {
    my $d = project(qw(keys secrets));
    my $before = bytes_of($d);

    my $r = apply($d, dry_run => 1);
    is( $r->{died}, '', 'apply returns' ) or diag $r->{died};
    like( $r->{out}, qr/^\[Dry run - no changes made\]$/m, 'the dry run runs to its end' );
    is_deeply( bytes_of($d), $before, 'every file byte-identical' );
    unlike( $r->{out}, qr/Repaired/, 'no [ok] Repaired line' );
    is( $r->{err}, '', 'nothing on STDERR' );
    ok( only_bare_warnings($r->{warned}), 'warnings only about the bare timestamp it left' )
        or diag $r->{warned};
};

subtest 'a project OCP writes today goes through byte for byte' => sub {
    my $d = project();
    my $s = OCP::Secrets->new(project_dir => $d);
    $s->create_secrets(hetzner_token => 'tok-today');
    $s->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");
    OCP::Keys->new(project_dir => $d)->add_key(
        name    => 'robo-ssh',
        type    => 'ed25519',
        private => "ROBO-PRIVATE\n",
        public  => 'ssh-ed25519 AAAA robo',
        purpose => 'automation',
    );
    like( $d->child($_)->slurp_raw, $ts_qr, "precondition: $_ quoted" ) for @owned;
    my $before = bytes_of($d);

    my $r = apply($d);
    is( $r->{died}, '', 'apply returns' ) or diag $r->{died};
    is_deeply( $r->{seen}{reconcile}, $before, 'the reconcile finds the files as they were' );
    is_deeply( bytes_of($d), $before, 'every file byte-identical' );
    like( $r->{out}, qr/^Cluster: k259\n\n\[ok\] Cluster already exists/m,
          'no [ok] Repaired line, and no blank line of its own' );
    is( $r->{err}.$r->{warned}, '', 'nothing on STDERR, no warning' );
};

done_testing;

# A verbatim copy of t/153's legacy_fixture -- the genuine File::SOPS 0.002
# documents k259 is about.
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

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::PP ();
use Path::Tiny qw(path);
use Storable qw(dclone);
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Status;
use OCP::Config;
use OCP::Drift;
use OCP::Kubernetes;

no warnings 'once';

#
# k291, found live on amdlab 2026-10-31 (k290): the cluster's
# ocpnodes.ocp.internal CRD came from an OCP before k254 and had no
# spec.nodeIP. `ocp apply --dry-run` and the real run's drift check both said
# "No drift detected"; only the later "Checking node CRs" step re-applied the
# CRD, silently. Meanwhile the API server dropped spec.nodeIP from every
# OCPNode written against the old schema, without an error.
#
# The claims here:
#   1. OCP::Drift compares the live schemas of OCP's own CRDs
#      (share/robocop/crds) with the image's, by property path under spec and
#      status. What the image declares and the cluster does not is drift that
#      ocp apply closes (self_healing): the node CR step re-applies the CRD.
#   2. What the cluster declares and the image does not is a CRD newer than
#      this ocp: reported, with a manual step, and not "fixed" -- ensure_crds
#      leaves it as it is instead of taking the newer schema back.
#   3. An absent CRD (a 404, and only a 404) is a 'missing' entry: ocp apply
#      installs it. Any other failed read is an 'error' entry with its cause,
#      carped once (k269) -- never "absent", never "same".
#   4. `ocp status` (text and --json) and `ocp apply --dry-run` show the
#      entries.
#   5. ensure_crds dies with the path when share/robocop/crds is missing.
#

my $CRD_BASE = '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/';
my $NODE_CRD = 'ocpnodes.ocp.internal';
my $PROV_CRD = 'ocpnodeproviders.ocp.internal';

my %SHIPPED = map { $_->{metadata}{name} => $_ }
    grep { ref $_ eq 'HASH' && ($_->{kind} // '') eq 'CustomResourceDefinition' }
    map { YAML::XS::LoadFile("$_") } sort(path('share/robocop/crds')->children(qr/\.ya?ml\z/));

sub v1_props {
    my ($crd, $part) = @_;
    my ($v1) = grep { $_->{name} eq 'v1' } @{ $crd->{spec}{versions} };
    return $v1->{schema}{openAPIV3Schema}{properties}{$part}{properties};
}

# As the apiserver hands a CRD back: JSON, with what it adds on its own.
sub stored {
    my ($crd) = @_;
    my $copy = JSON::PP::decode_json(JSON::PP::encode_json($crd));
    $copy->{spec}{conversion} = { strategy => 'None' };
    $copy->{metadata}{resourceVersion} = '4711';
    $copy->{status} = { acceptedNames => { kind => $crd->{spec}{names}{kind} }, storedVersions => ['v1'] };
    return $copy;
}

# The OCPNode CRD of an OCP from before k254: no nodeIP in spec or status.
my $OLD_NODE = dclone($SHIPPED{$NODE_CRD});
delete v1_props($OLD_NODE, $_)->{nodeIP} for qw(spec status);

# One from an OCP newer than this one: a spec and a status field more.
my $NEWER_NODE = dclone($SHIPPED{$NODE_CRD});
v1_props($NEWER_NODE, 'spec')->{zone}         = { type => 'string' };
v1_props($NEWER_NODE, 'status')->{drainedAt}  = { type => 'string', format => 'date-time' };

package FakeResponse {
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }

# A cluster's CRDs by name, served over _request the way the apiserver answers
# a raw GET; a CRD it does not have is a 404. raw_fail answers a name with
# [ status, body ], or dies with a string (no response at all). Every typed
# get is a 404 and every list empty: the other probes find nothing to read.
# Writes (_request PATCH, server-side apply) are recorded.
package FakeApi {
    sub new { my ($c, %a) = @_; bless { crds => {}, raw_fail => {}, reads => [], writes => [], %a }, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub expand_class { undef }
    sub get  { die "Kubernetes API error (get $_[1]): 404 NotFound\n" }
    sub list { FakeList->new([]) }
    sub _request {
        my ($self, $method, $path, $body) = @_;
        if ($method ne 'GET') {
            push @{ $self->{writes} }, "$method $body->{kind}/$body->{metadata}{name}";
            return FakeResponse->new(200, '{}');
        }
        push @{ $self->{reads} }, $path;
        my ($name) = $path =~ m{/customresourcedefinitions/([^/]+)\z}
            or return FakeResponse->new(404, '{"kind":"Status","code":404}');
        if (my $fail = $self->{raw_fail}{$name}) {
            die $fail unless ref $fail;
            return FakeResponse->new(@$fail);
        }
        my $crd = $self->{crds}{$name}
            or return FakeResponse->new(404, '{"kind":"Status","reason":"NotFound","code":404}');
        return FakeResponse->new(200, JSON::PP->new->canonical->utf8->encode($crd));
    }
}

package main;

my $tmp = tempdir(CLEANUP => 1);
my $n = 0;

# A cluster that already exists: an ssh control plane and its status.
sub project {
    my $dir = path($tmp)->child('p' . ++$n);
    $dir->mkpath;
    $dir->child('ocp.yaml')->spew(<<'YAML');
name: amdlab
kubernetes:
  dist: rke2
control_planes:
  provider: ssh
  host: otho.ocp.invalid
YAML
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n");
    return $dir;
}

sub config { OCP::Config->new(file => project()->child('ocp.yaml')->stringify) }

# The cluster's CRDs: the shipped ones, then what %crds says (undef: absent).
sub cluster {
    my (%crds) = @_;
    my %have = map { $_ => stored($SHIPPED{$_}) } keys %SHIPPED;
    for my $name (keys %crds) {
        defined $crds{$name} ? ($have{$name} = stored($crds{$name})) : delete $have{$name};
    }
    return \%have;
}

sub ocp_crd_entries {
    my ($api) = @_;
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, @_ };
    my @e = OCP::Drift->new(config => config(), api => $api)->ocp_crd_drift;
    return (\@warn, @e);
}

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $o;
        local *STDERR = $e;
        local $SIG{__WARN__} = sub { print STDERR @_ };
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, out => $out, err => $err, died => $died };
}

#### the premise

subtest 'premise: the shipped OCPNode CRD declares nodeIP, the pre-k254 one does not' => sub {
    ok exists $SHIPPED{$_}, "$_ is shipped" for $NODE_CRD, $PROV_CRD;
    ok v1_props($SHIPPED{$NODE_CRD}, $_)->{nodeIP}, "shipped: $_.nodeIP" for qw(spec status);
    ok !v1_props($OLD_NODE, $_)->{nodeIP}, "old: no $_.nodeIP" for qw(spec status);
};

#### 1. the cluster's CRD lacks what the image declares

subtest 'k291 reproduced: an OCPNode CRD without spec.nodeIP is drift' => sub {
    my $api = FakeApi->new(crds => cluster($NODE_CRD => $OLD_NODE));
    my @warn;
    my $drift = do {
        local $SIG{__WARN__} = sub { push @warn, @_ };
        OCP::Drift->new(config => config(), api => $api)->detect;
    };
    my @e = grep { ($_->{message} // '') =~ /\Q$NODE_CRD\E/ } @$drift;
    is scalar @e, 1, 'detect names the OCPNode CRD, once';
    my ($e) = @e;
    is $e->{kind}, 'version', 'a version entry';
    is $e->{component}, 'ocp_crd', 'component ocp_crd';
    is $e->{label}, 'OCPNode CRD', 'labelled by the kind it defines';
    like $e->{message}, qr/lacks spec\.nodeIP, status\.nodeIP, which this ocp declares/,
        'the message names both fields the cluster lacks';
    like $e->{message}, qr/drops what it does not declare/, 'and why that matters';
    like $e->{message}, qr/ocp apply updates it\z/, 'and that ocp apply closes it';
    ok $e->{self_healing}, 'self_healing: the node CR step re-applies the CRD';
    ok !$e->{remedy}, 'no Rex or API remedy of its own';
    ok !$e->{manual_step}, 'no manual step';
    is_deeply [ grep { /\Q$NODE_CRD\E|\Q$PROV_CRD\E/ } @warn ], [], 'nothing carped about the CRDs';
};

subtest 'the same CRDs, as the apiserver stores them: no entry' => sub {
    my ($warn, @e) = ocp_crd_entries(FakeApi->new(crds => cluster()));
    is_deeply \@e, [], 'no ocp_crd entry';
    is_deeply $warn, [], 'nothing carped';
};

subtest 'a nested property: the topmost missing path stands for what is under it' => sub {
    my $prov = dclone($SHIPPED{$PROV_CRD});
    ok delete v1_props($prov, 'spec')->{hetzner}, 'premise: the provider CRD has spec.hetzner';
    my $node = dclone($SHIPPED{$NODE_CRD});
    my $hk = v1_props($node, 'status')->{hostKeys}{items}{properties};
    ok delete $hk->{fingerprint}, 'premise: status.hostKeys items have a fingerprint';

    my ($warn, @e) = ocp_crd_entries(FakeApi->new(crds => cluster($PROV_CRD => $prov, $NODE_CRD => $node)));
    my %by = map { $_->{label} => $_ } @e;
    like $by{'OCPNodeProvider CRD'}{message}, qr/lacks spec\.hetzner, which this ocp declares/,
        'spec.hetzner, not every field under it';
    unlike $by{'OCPNodeProvider CRD'}{message}, qr/spec\.hetzner\./, 'its children are not listed';
    like $by{'OCPNode CRD'}{message}, qr/lacks status\.hostKeys\[\]\.fingerprint,/,
        'a property of an array\'s items is named through []';
};

#### 2. the cluster's CRD is newer than this ocp

subtest 'downgrade: the cluster declares fields this ocp does not know' => sub {
    my ($warn, @e) = ocp_crd_entries(FakeApi->new(crds => cluster($NODE_CRD => $NEWER_NODE)));
    is scalar @e, 1, 'one entry';
    my ($e) = @e;
    is $e->{kind}, 'version', 'a version entry';
    like $e->{message}, qr/declares spec\.zone, status\.drainedAt, which this ocp does not know/,
        'names the fields only the cluster has';
    like $e->{message}, qr/newer than this ocp, which leaves it as it is\z/,
        'says it is newer and that this ocp leaves it';
    unlike $e->{message}, qr/ocp apply updates it/, 'never "ocp apply updates it"';
    ok !$e->{remedy}, 'no remedy';
    ok !$e->{self_healing}, 'and not self-healing: report only';
    like $e->{manual_step}, qr/ocp that installed it/, 'the manual step names the way out';
    like $e->{manual_step}, qr/would drop those fields from every OCPNode/,
        'and what writing this ocp\'s CRD over it would cost';
};

subtest 'both at once: a newer CRD that lacks a field of this ocp is still newer' => sub {
    my $mixed = dclone($NEWER_NODE);
    delete v1_props($mixed, 'spec')->{nodeIP};
    my ($warn, @e) = ocp_crd_entries(FakeApi->new(crds => cluster($NODE_CRD => $mixed)));
    is scalar @e, 1, 'one entry';
    like $e[0]{message}, qr/declares spec\.zone, status\.drainedAt, which this ocp does not know, and lacks spec\.nodeIP, which it declares/,
        'names both sides';
    ok !$e[0]{self_healing}, 'not self-healing: ensure_crds leaves it';
    ok $e[0]{manual_step}, 'a manual step';
};

#### 3. absent and unreadable

subtest 'absent (a 404): a missing entry, ocp apply installs it' => sub {
    my ($warn, @e) = ocp_crd_entries(FakeApi->new(crds => cluster($NODE_CRD => undef)));
    is scalar @e, 1, 'one entry';
    my ($e) = @e;
    is $e->{kind}, 'missing', 'kind missing';
    is $e->{message}, "OCPNode CRD ($NODE_CRD) is not installed; ocp apply installs it", 'message';
    ok $e->{self_healing}, 'self-healing';
    ok !$e->{remedy}, 'no remedy of its own';
    is_deeply $warn, [], 'a 404 is an answer: nothing carped';

    my ($w2, @none) = ocp_crd_entries(FakeApi->new);
    is scalar(grep { $_->{kind} eq 'missing' } @none), 2, 'a cluster without either: two missing entries';
};

for my $case (
    [ '403', [ 403, '{"kind":"Status","reason":"Forbidden","code":403}' ], qr/403/ ],
    [ '500', [ 500, '{"kind":"Status","reason":"InternalError","code":500}' ], qr/500/ ],
    [ 'a transport failure', "connect: Connection refused\n", qr/Connection refused/ ],
    [ 'an undecodable body', [ 200, 'not json' ], qr/undecodable response body/ ],
) {
    my ($what, $fail, $cause) = @$case;
    subtest "unreadable ($what): an error entry with its cause, never absent" => sub {
        my $api = FakeApi->new(crds => cluster(), raw_fail => { $NODE_CRD => $fail });
        my ($warn, @e) = ocp_crd_entries($api);
        is scalar @e, 1, 'one entry, for the CRD that could not be read';
        my ($e) = @e;
        is $e->{kind}, 'error', 'kind error: drift unknown';
        is $e->{component}, 'ocp_crd', 'component';
        like $e->{message}, qr/\AOCPNode CRD: could not read CustomResourceDefinition \Q$NODE_CRD\E, drift unknown: /,
            'names what it could not read';
        like $e->{message}, $cause, 'and the cause';
        ok !$e->{remedy} && !$e->{self_healing}, 'nothing to run';
        is scalar @$warn, 1, 'carped once';
        like $warn->[0], qr/^OCP::Drift::ocp_crd_drift: get CustomResourceDefinition \Q$NODE_CRD\E failed: /,
            'naming the probe and the read';
    };
}

subtest 'the CRDs this ocp ships cannot be read: one error entry, not a clean cluster' => sub {
    my $share = tempdir(CLEANUP => 1);     # a share dir without robocop/crds
    local $ENV{OCP_SHARE_DIR} = $share;
    my ($warn, @e) = ocp_crd_entries(FakeApi->new(crds => cluster()));
    is scalar @e, 1, 'one entry';
    my ($e) = @e;
    is $e->{kind}, 'error', 'kind error: drift unknown';
    is $e->{component}, 'ocp_crd', 'component';
    is $e->{message}, "OCP CRDs: could not read the ones this ocp ships, drift unknown:"
        . " OCP's CRDs not found: $share/robocop/crds is not a directory", 'names the missing directory';
    ok !$e->{remedy} && !$e->{self_healing}, 'nothing to run';
    is scalar @$warn, 1, 'carped once';
    like $warn->[0], qr{^OCP::Drift::ocp_crd_drift: OCP's CRDs not found: \Q$share\E/robocop/crds }, 'with the path';
};

subtest 'detect asks only with an API' => sub {
    my $drift = OCP::Drift->new(config => config())->detect;
    is_deeply [ grep { ($_->{component} // '') eq 'ocp_crd' } @$drift ], [], 'no API, no CRD entry';
};

subtest 'the GPU CRD probe reads through the same reader: a 404 is no drift there' => sub {
    my ($warn, @e) = do {
        my @w;
        local $SIG{__WARN__} = sub { push @w, @_ };
        my @x = OCP::Drift->new(config => config(), api => FakeApi->new)->gpu_crd_drift;
        (\@w, @x);
    };
    is_deeply \@e, [], 'the GPU operator is optional: absent CRDs are no entry';
    is_deeply $warn, [], 'and nothing carped';
};

#### 4. what the user sees

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }
{ package Local::FakeSecrets; sub new { bless {}, $_[0] } sub has_kubeconfig { 1 } sub read_kubeconfig { "apiVersion: v1\n" } }
{
    package Local::FakeK8s;
    our $API;
    sub new { bless {}, $_[0] }
    sub list_nodes { [ { metadata => { name => 'otho' } } ] }
    sub api { $API }
    sub gpu_nodes { [] }
    sub node_name { $_[1]{metadata}{name} }
    sub node_ready { 1 }
    sub node_roles { 'control-plane' }
    sub node_version { 'v1.32.1+rke2r1' }
    sub node_internal_ip { '10.230.30.52' }
    sub node_gpu_count { 0 }
    sub node_gpu_capacity { undef }
}

# `ocp status` against $api, the drift section limited to the CRD probe.
sub run_status {
    my ($api, %opt) = @_;
    my $dir = project();
    my $cmd = OCP::Cmd::Status->new(
        ($opt{json} ? (json => 1) : ()),
        command_chain => [ Local::FakeOCP->new(config => $dir->child('ocp.yaml')->stringify) ],
    );
    local $Local::FakeK8s::API = $api;
    no warnings 'redefine';
    local *OCP::Secrets::new            = sub { Local::FakeSecrets->new };
    local *OCP::Cmd::Status::reach_cluster_api = sub { $_[1] };
    local *OCP::Kubernetes::new         = sub { Local::FakeK8s->new };
    local *OCP::Drift::detect           = sub { [ $_[0]->ocp_crd_drift ] };
    local *OCP::Cmd::Status::rex_prober = sub { undef };
    return capture { $cmd->execute([], []) };
}

my $UPGRADE_LINE = "  [drift] OCPNode CRD ($NODE_CRD) in the cluster lacks spec.nodeIP, status.nodeIP,"
    . " which this ocp declares, and the API server drops what it does not declare; ocp apply updates it";
my $NEWER_LINE = "  [drift] OCPNode CRD ($NODE_CRD) in the cluster declares spec.zone, status.drainedAt,"
    . " which this ocp does not know: newer than this ocp, which leaves it as it is";

subtest 'ocp status shows both directions' => sub {
    my $r = run_status(FakeApi->new(crds => cluster($NODE_CRD => $OLD_NODE)));
    is $r->{died}, '', 'status ran';
    like $r->{out}, qr/\n=== Drift ===\n\Q$UPGRADE_LINE\E\n/, 'the older CRD, as a drift line';
    is $r->{rv}, 0, 'exit 0: a finding, not a failure';

    $r = run_status(FakeApi->new(crds => cluster($NODE_CRD => $NEWER_NODE)));
    like $r->{out}, qr/\Q$NEWER_LINE\E\n {10}Run ocp apply with the ocp that installed it\./,
        'the newer CRD, with its manual step under it';

    $r = run_status(FakeApi->new(crds => cluster($NODE_CRD => $OLD_NODE)), json => 1);
    my $d = JSON::PP::decode_json($r->{out});
    my ($e) = grep { $_->{component} eq 'ocp_crd' } @{ $d->{drift} };
    is $e->{kind}, 'version', 'json: the entry';
    like $e->{message}, qr/lacks spec\.nodeIP, status\.nodeIP/, 'json: its message';
};

# `ocp apply --dry-run` against an existing cluster, drift limited to the CRD
# probe, nothing else in ocp.yaml that a dry run would read.
sub run_dry {
    my ($api) = @_;
    my $config = config();
    my $apply = OCP::Cmd::Apply->new(command_chain => [ Local::FakeOCP->new(config => 'x') ], dry_run => 1);
    $apply->{_k8s_api} = $api;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_k8s_api       = sub { $_[0]{_k8s_api} };
    local *OCP::Secrets::read_kubeconfig   = sub { "apiVersion: v1\n" };
    local *OCP::Drift::detect              = sub { [ $_[0]->ocp_crd_drift ] };
    local *OCP::Cmd::Apply::rex_prober     = sub { undef };
    return capture { $apply->_reconcile_components($config) };
}

subtest 'ocp apply --dry-run shows both directions' => sub {
    my $r = run_dry(FakeApi->new(crds => cluster($NODE_CRD => $OLD_NODE)));
    is $r->{died}, '', 'the dry run ran';
    unlike $r->{out}, qr/No drift detected/, 'no "No drift detected" over an older CRD';
    like $r->{out}, qr/^\Q$UPGRADE_LINE\E\n/m, 'the older CRD, as a drift line';
    like $r->{out}, qr/^  1 difference\(s\) a real run would act on\.$/m, 'counted as an action';
    is_deeply $r->{rv} ? [1] : [], [], 'and the dry run stops short of the health gate';

    $r = run_dry(FakeApi->new(crds => cluster($NODE_CRD => $NEWER_NODE)));
    like $r->{out}, qr/^\Q$NEWER_LINE\E\n {10}report only, a real run leaves it as it is\n/m,
        'the newer CRD: report only';
    like $r->{out}, qr/^  0 difference\(s\) a real run would act on\.$/m, 'not an action';
    like $r->{out}, qr/^  1 more reported only/m, 'counted as reported only';

    $r = run_dry(FakeApi->new(crds => cluster(), raw_fail => { $NODE_CRD => [ 403, 'forbidden' ] }));
    like $r->{out}, qr/^  \[drift\] could not be checked: OCPNode CRD: could not read CustomResourceDefinition \Q$NODE_CRD\E, drift unknown: 403 forbidden$/m,
        'an unreadable CRD: could not be checked';
    like $r->{out}, qr/^  1 more could not be checked/m, 'counted as unknown';
    like $r->{err}, qr/OCP::Drift::ocp_crd_drift: get CustomResourceDefinition \Q$NODE_CRD\E failed: 403 forbidden/,
        'the cause on STDERR';
};

#### ensure_crds

my $SHARE = path('share');
my $apply = OCP::Cmd::Apply->new(command_chain => [ Local::FakeOCP->new(config => 'x') ]);

sub ensure_crds {
    my ($api, $share) = @_;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_find_share_dir = sub { $share // $SHARE };
    return capture { OCP::Cmd::Apply::CR::ensure_crds($apply, $api) };
}

subtest 'ensure_crds: an older or absent CRD is applied' => sub {
    my $api = FakeApi->new(crds => cluster($NODE_CRD => $OLD_NODE, $PROV_CRD => undef));
    my $r = ensure_crds($api);
    is $r->{died}, '', 'no death';
    is_deeply [ sort @{ $api->{writes} } ],
        [ "PATCH CustomResourceDefinition/$PROV_CRD", "PATCH CustomResourceDefinition/$NODE_CRD" ],
        'both CRDs applied';
    like $r->{out}, qr/\[ok\] ensured CustomResourceDefinition\/\Q$NODE_CRD\E/, 'said';
    is_deeply [ sort @{ $api->{reads} } ], [ sort map { $CRD_BASE . $_ } $NODE_CRD, $PROV_CRD ],
        'each read once before its apply';
};

subtest 'ensure_crds: a newer CRD is left as it is, not "fixed"' => sub {
    my $api = FakeApi->new(crds => cluster($NODE_CRD => $NEWER_NODE));
    my $r = ensure_crds($api);
    is $r->{died}, '', 'no death';
    is_deeply $api->{writes}, [ "PATCH CustomResourceDefinition/$PROV_CRD" ],
        'only the provider CRD is applied; the newer OCPNode CRD is not written over';
    like $r->{out}, qr/^  \[skip\] CustomResourceDefinition\/\Q$NODE_CRD\E is newer than this ocp \(it declares spec\.zone, status\.drainedAt\); left as it is$/m,
        'said on STDOUT, with the fields';
};

subtest 'ensure_crds: a CRD that cannot be read is not written over blind' => sub {
    my $api = FakeApi->new(crds => cluster(), raw_fail => { $NODE_CRD => [ 403, 'forbidden' ] });
    my $r = ensure_crds($api);
    like $r->{died}, qr/\AGET \Q$CRD_BASE$NODE_CRD\E failed: HTTP 403 forbidden/, 'dies with the cause';
    is_deeply [ grep { /\Q$NODE_CRD\E/ } @{ $api->{writes} } ], [], 'nothing written for it';
};

#### 5. a broken package

subtest 'ensure_crds: no share/robocop/crds dies with the path' => sub {
    my $empty = path(tempdir(CLEANUP => 1));
    my $api = FakeApi->new;
    my $r = ensure_crds($api, $empty);
    my $want = $empty->child('robocop', 'crds');
    like $r->{died}, qr/\Q$want\E/, 'the death names the missing directory';
    is_deeply $api->{writes}, [], 'nothing applied';
};

done_testing;

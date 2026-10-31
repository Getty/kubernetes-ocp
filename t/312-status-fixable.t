#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS qw( decode_json );
use Path::Tiny qw(path);
use Storable qw(dclone);

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Status;
use OCP::Drift;
use OCP::Kubernetes;

#
# k312: `ocp status` counted "N of M can be reconciled automatically: run
# 'ocp apply'" from the drift entries with a remedy, and --json set an
# entry's fixable by the same test. An entry ocp apply closes without a
# remedy task was left out of both: a self_healing one (a manifest the run
# re-applies anyway -- NFD, the GPU stack, the GPU Operator CRDs, OCP's own
# CRDs since k291) and a missing one the run deploys (registry.local in
# CoreDNS). Status undercounted what `ocp apply` fixes, and an entry whose
# message said "ocp apply updates it" was fixable: false.
#
# The claims here:
#   1. An entry is fixable when ocp apply closes it: a remedy, self_healing,
#      or kind missing. The text count and --json's fixable say the same.
#   2. A report-only entry is not: no remedy, not self_healing, not missing --
#      a kubelet version, the pod CIDR, a CRD newer than this ocp (a version
#      entry with a manual_step and no self_healing). Nor is a check that
#      could not be made.
#   3. Both draw the line where `ocp apply --dry-run` does (k188): its "N
#      difference(s) a real run would act on" counts the same entries, its
#      "reported only" the rest.
#
# The entries are shaped as OCP::Drift builds them.
#

my %ENTRY = (
    cilium => {
        kind => 'version', component => 'cilium', label => 'Cilium',
        expected => '1.20.0', actual => 'v1.17.0',
        message => 'Cilium runs v1.17.0, expected 1.20.0',
        remedy => { type => 'rex', task => 'upgrade_cilium', params => {} },
    },
    nfd => {
        kind => 'version', component => 'nfd', label => 'NFD',
        expected => 'v0.18.3', actual => 'v0.17.0',
        message => 'NFD runs v0.17.0, expected v0.18.3',
        remedy => undef, self_healing => 1,
    },
    ocp_crd => {
        kind => 'version', component => 'ocp_crd', label => 'OCPNode CRD',
        expected => undef, actual => undef,
        message => 'OCPNode CRD (ocpnodes.ocp.internal) in the cluster lacks spec.nodeIP, which this ocp'
            . ' declares, and the API server drops what it does not declare; ocp apply updates it',
        remedy => undef, self_healing => 1,
    },
    gpu_crd => {
        kind => 'version', component => 'gpu_operator_crd', label => 'CRD clusterpolicies.nvidia.com',
        message => 'GPU Operator CRD clusterpolicies.nvidia.com in the cluster differs from the one OCP'
            . ' ships; ocp apply re-applies it',
        remedy => undef, self_healing => 1,
    },
    registry_dns => {
        kind => 'missing', component => 'registry_dns', label => 'registry.local DNS',
        expected => '10.0.0.10', actual => undef,
        message => 'registry.local is missing from the CoreDNS Corefile (expected 10.0.0.10); ocp apply restores it',
        remedy => undef,
    },
    newer_crd => {
        kind => 'version', component => 'ocp_crd', label => 'OCPNode CRD',
        expected => undef, actual => undef,
        message => 'OCPNode CRD (ocpnodes.ocp.internal) in the cluster declares spec.zone, which this ocp'
            . ' does not know: newer than this ocp, which leaves it as it is',
        manual_step => 'Run ocp apply with the ocp that installed it. This one does not write its own'
            . ' CRD over it: the API server would drop that field from every OCPNode.',
        remedy => undef,
    },
    kubelet => {
        kind => 'version', component => 'rke2', label => 'rke2 on police1',
        expected => 'v1.32.1+rke2r1', actual => 'v1.31.4+rke2r1',
        message => 'police1 runs v1.31.4+rke2r1, expected v1.32.1+rke2r1',
        remedy => undef,
    },
    pod_cidr => {
        kind => 'spec', component => 'pod_cidr', label => 'Pod CIDR',
        expected => '10.42.0.0/16', actual => '10.0.0.0/8',
        message => 'Pod CIDR: Cilium pod pool is 10.0.0.0/8, ocp.yaml expects 10.42.0.0/16 (default);'
            . ' the pod network of a running cluster is not changed automatically',
        manual_step => 'Keep the running pool: set network.pod_cidr: 10.0.0.0/8 in ocp.yaml.',
        remedy => undef,
    },
    unknown => {
        kind => 'error', component => 'worker_host_probes', label => 'Worker host probes',
        expected => undef, actual => undef,
        message => 'Worker host probes: could not list OCPNode in ocp-system, drift unknown: 403 Forbidden',
        remedy => undef,
    },
);

my @FIXABLE     = qw( cilium nfd ocp_crd gpu_crd registry_dns );
my @REPORT_ONLY = qw( newer_crd kubelet pod_cidr );
my @UNKNOWN     = qw( unknown );

#### harness

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }
{ package Local::FakeSecrets; sub new { bless {}, $_[0] } sub read_kubeconfig { "apiVersion: v1\n" } }
{
    package Local::FakeK8s;
    sub new { bless {}, $_[0] }
    sub list_nodes { [ { metadata => { name => 'police1' } } ] }
    sub api { undef }
    sub gpu_nodes { [] }
    sub node_name { $_[1]{metadata}{name} }
    sub node_ready { 1 }
    sub node_roles { 'control-plane' }
    sub node_version { 'v1.32.1+rke2r1' }
    sub node_internal_ip { '10.0.0.10' }
    sub node_gpu_count { 0 }
    sub node_gpu_capacity { undef }
}
# The dry run's api. detect is faked; the GPU step's read finds no operator,
# the AMD GPU step's (k261) no node with the marker.
{
    package Local::FakeApi;
    sub new { bless {}, $_[0] }
    sub get { die "Kubernetes API error (get $_[1]): 404 NotFound\n" }
    sub list { bless { items => [] }, 'Local::FakeList' }
}
{ package Local::FakeList; sub items { $_[0]{items} } }

my $tmp = tempdir(CLEANUP => 1);
my $n = 0;

# A deployed cluster on an ssh control plane: no robocop, no workers, no GPU,
# so a dry run counts the drift entries and nothing else.
sub project {
    my $dir = path($tmp)->child('p' . ++$n);
    $dir->mkpath;
    $dir->child('ocp.yaml')->spew(<<'YAML');
name: k312
kubernetes:
  dist: rke2
control_planes:
  provider: ssh
  host: police1.ocp.invalid
YAML
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n");
    return $dir->child('ocp.yaml')->stringify;
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

sub entries { [ map { dclone($ENTRY{$_}) } @_ ] }

# `ocp status` (text, or --json) with detect answering @names.
sub run_status {
    my ($names, %opt) = @_;
    my $cmd = OCP::Cmd::Status->new(
        ($opt{json} ? (json => 1) : ()),
        command_chain => [ Local::FakeOCP->new(config => project()) ],
    );
    no warnings 'redefine';
    local *OCP::Secrets::new            = sub { Local::FakeSecrets->new };
    local *OCP::Kubernetes::new         = sub { Local::FakeK8s->new };
    local *OCP::Drift::detect           = sub { entries(@$names) };
    local *OCP::Cmd::Status::rex_prober = sub { undef };
    return capture { $cmd->execute([], []) };
}

# fixable per entry name, out of `ocp status --json`.
sub json_fixable {
    my ($names) = @_;
    my $r = run_status($names, json => 1);
    my %by_message = map { $ENTRY{$_}{message} => $_ } @$names;
    my $d = decode_json($r->{out});
    return { map { $by_message{ $_->{message} } => ($_->{fixable} ? 1 : 0) } @{ $d->{drift} } };
}

# The count line of the text form, or '' when it prints none.
sub count_line {
    my ($names) = @_;
    my $r = run_status($names);
    my ($line) = $r->{out} =~ /^(\d+ of \d+ can be reconciled automatically: run 'ocp apply'\.)$/m;
    return $line // '';
}

# `ocp apply --dry-run` against the same entries.
sub run_dry {
    my ($names) = @_;
    my $config = OCP::Config->new(file => project());
    my $apply = OCP::Cmd::Apply->new(command_chain => [ Local::FakeOCP->new(config => 'x') ], dry_run => 1);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_k8s_api     = sub { Local::FakeApi->new };
    local *OCP::Secrets::read_kubeconfig = sub { "apiVersion: v1\n" };
    local *OCP::Drift::detect            = sub { entries(@$names) };
    local *OCP::Cmd::Apply::rex_prober   = sub { undef };
    return capture { $apply->_reconcile_components($config) };
}

#### 1 + 2: every entry on its own

for my $name (@FIXABLE) {
    subtest "$name: fixable, in the text count and in --json" => sub {
        is count_line([ $name ]), "1 of 1 can be reconciled automatically: run 'ocp apply'.",
            'text: counted';
        is_deeply json_fixable([ $name ]), { $name => 1 }, 'json: fixable true';
    };
}

for my $name (@REPORT_ONLY) {
    subtest "$name: report only, counted nowhere" => sub {
        my $r = run_status([ $name ]);
        like $r->{out}, qr/\n=== Drift ===\n  \[drift\] \Q$ENTRY{$name}{message}\E\n/, 'text: listed';
        is count_line([ $name ]), '', 'text: no count line';
        is_deeply json_fixable([ $name ]), { $name => 0 }, 'json: fixable false';
    };
}

subtest 'a check that could not be made: neither a finding nor fixable' => sub {
    is count_line([ @UNKNOWN ]), '', 'text: no count line';
    is_deeply json_fixable([ @UNKNOWN ]), { unknown => 0 }, 'json: fixable false';
};

#### 1: all of them at once, and the two forms agree

my @ALL = (@FIXABLE, @REPORT_ONLY, @UNKNOWN);

subtest 'the mixed report: text count and --json fixable agree' => sub {
    my $r = run_status(\@ALL);
    is $r->{died}, '', 'status ran';
    is $r->{rv}, 0, 'exit 0';
    is $r->{err}, '', 'STDERR empty';
    is count_line(\@ALL), "5 of 8 can be reconciled automatically: run 'ocp apply'.",
        'text: the five ocp apply closes, of the eight found';

    my $fixable = json_fixable(\@ALL);
    is_deeply $fixable, { (map { $_ => 1 } @FIXABLE), (map { $_ => 0 } @REPORT_ONLY, @UNKNOWN) },
        'json: fixable per entry';
    my ($n, $m) = count_line(\@ALL) =~ /^(\d+) of (\d+)/;
    is scalar(grep { $_ } values %$fixable), $n, 'json: as many fixable as the text counts';
    is scalar(@ALL) - @UNKNOWN, $m, 'text: of the entries that are findings';
};

#### 3: the same line as ocp apply --dry-run

subtest 'ocp apply --dry-run acts on exactly the entries status calls fixable' => sub {
    my $r = run_dry(\@ALL);
    is $r->{died}, '', 'the dry run ran';
    my $fixable = scalar @FIXABLE;
    like $r->{out}, qr/^  \Q$fixable\E difference\(s\) a real run would act on\.$/m,
        'its action count is the status count';
    like $r->{out}, qr/^  3 more reported only -- a real run leaves them as they are\.$/m,
        'its report-only entries are the ones status does not count';
    like $r->{out}, qr/^  1 more could not be checked/m, 'and the unknown one stays apart';

    for my $name (@REPORT_ONLY) {
        like $r->{out}, qr/^  \[drift\] \Q$ENTRY{$name}{message}\E\n {10}report only, a real run leaves it as it is$/m,
            "$name: report only there too";
    }
};

done_testing;

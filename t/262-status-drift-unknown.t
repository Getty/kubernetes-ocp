#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use JSON::MaybeXS qw( decode_json );

use lib 'lib';

use OCP;
use OCP::Cmd::Status;
use OCP::Drift;
use OCP::Kubernetes;

#
# k262: both forms of `ocp status` ran drift detection as
# `eval { OCP::Drift->new(...)->detect } // []`. When OCP::Drift itself died,
# drift read as an empty list -- "no drift" in the text form, "drift": [] in
# --json, exit 0 -- and nothing reached STDERR: a wrong verdict, told as a
# clean one.
#
# Now the cause goes to STDERR, the drift section says drift could not be
# determined, the JSON drift list holds one entry of kind error (the shape
# OCP::Drift gives a probe it could not read since k256/k268) with the cause
# in error beside it, and the exit is 1.
#
# And those per-probe error entries: the text form printed them as plain
# "[drift]" findings and counted them into "N of M can be reconciled". They
# read as `ocp apply` words them (k267) -- "could not be checked" with the
# cause -- and are no finding to count.
#

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }
{ package Local::FakeSecrets; sub new { bless {}, $_[0] } sub has_kubeconfig { 1 } sub read_kubeconfig { "apiVersion: v1\n" } }
{
    package Local::FakeK8s;
    sub new { bless {}, $_[0] }
    sub list_nodes { [ { metadata => { name => 'police1' } } ] }
    sub api { bless {}, 'Local::NoServer' }    # cluster_api asks it for a server (k399)
    sub gpu_nodes { [] }
    sub node_name { $_[1]{metadata}{name} }
    sub node_ready { 1 }
    sub node_roles { 'control-plane' }
    sub node_version { 'v1.32.1+rke2r1' }
    sub node_internal_ip { '10.0.0.10' }
    sub node_gpu_count { 0 }
    sub node_gpu_capacity { undef }
}

our $DETECT;
my $ocp = OCP->new;
my $tmp = tempdir(CLEANUP => 1);

sub project {
    my ($name) = @_;
    my $dir = path($tmp)->child($name);
    $dir->mkpath;
    my $cfg = $dir->child('ocp.yaml');
    $ocp->dump_file($cfg->stringify, {
        name           => $name,
        version        => 'v1.32.1+rke2r1',
        control_planes => [{ provider => 'hetzner', server_type => 'cx32' }],
    });
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n");
    return $cfg->stringify;
}

# (exit, STDOUT, STDERR) of one run, detect answering through $DETECT.
sub run_status {
    my ($cfg, %opt) = @_;
    my $cmd = OCP::Cmd::Status->new(
        ($opt{json} ? (json => 1) : ()),
        command_chain => [Local::FakeOCP->new(config => $cfg)],
    );
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my $rc;
    {
        no warnings 'redefine';
        local *OCP::Secrets::new            = sub { Local::FakeSecrets->new };
        local *OCP::Cmd::Status::reach_cluster_api = sub { $_[1] };
        local *OCP::Kubernetes::new         = sub { Local::FakeK8s->new };
        local *OCP::Drift::detect           = sub { $DETECT->(@_) };
        local *OCP::Cmd::Status::rex_prober = sub { undef };
        local *STDOUT = $o;
        local *STDERR = $e;
        $rc = $cmd->execute([], []);
    }
    return ($rc, $out, $err);
}

my $DIES = sub { die "drift exploded\n" };

my $UNKNOWN_LINE = '  [drift] could not be checked: Drift detection: could not complete, drift unknown: drift exploded';

#### drift detection dies: text

{
    local $DETECT = $DIES;
    my ($rc, $out, $err) = run_status(project('text-dies'));

    is $rc, 1, 'detection died: exit 1';
    is $err, "WARNING: Cannot detect drift: drift exploded\n",
        'STDERR: the failure with its cause, and only that';

    like $out, qr/^police1\s+Ready\s+control-plane\s/m, 'STDOUT: the node table, as before';
    like $out, qr/\n=== Drift ===\n\Q$UNKNOWN_LINE\E\n/,
        'STDOUT: the drift section says drift could not be determined';
    unlike $out, qr/can be reconciled/, 'STDOUT: no count of drift that was not found';
    like $out, qr/\nKubeconfig: ocp kubeconfig -e\n\z/, 'STDOUT: the report ends as a good run does';
    unlike $out, qr/WARNING/, 'STDOUT: no warning';
}

{
    local $DETECT = sub { undef };
    my ($rc, $out, $err) = run_status(project('text-nolist'));
    is $rc, 1, 'detection handing back no list: exit 1 as well';
    like $err, qr/^WARNING: Cannot detect drift: /, '... and said on STDERR';
}

#### drift detection dies: --json

{
    local $DETECT = $DIES;
    my ($rc, $out, $err) = run_status(project('json-dies'), json => 1);

    is $rc, 1, 'json, detection died: exit 1';
    is $err, "WARNING: Cannot detect drift: drift exploded\n", 'json: the cause on STDERR';

    my $d = decode_json($out);
    is_deeply [ map { $_->{name} } @{ $d->{nodes} } ], ['police1'], 'json: the nodes, as before';
    is $d->{error}, 'Cannot detect drift: drift exploded', 'json: error says what is missing';
    is scalar @{ $d->{drift} }, 1, 'json: drift is not an empty list';
    my ($e) = @{ $d->{drift} };
    is $e->{kind}, 'error', 'json: one entry of kind error, drift unknown';
    is $e->{component}, 'drift', 'json: for drift detection as a whole';
    is $e->{message}, 'Drift detection: could not complete, drift unknown: drift exploded',
        'json: the message carries the cause';
    ok !$e->{fixable}, 'json: nothing for ocp apply to run';
    is_deeply [ sort keys %$e ], [ sort qw(kind component expected actual message manual_step fixable) ],
        'json: the keys of every drift entry';
}

#### the per-probe error entries (k256, k268) and the drift beside them

my @MIXED = (
    { kind => 'version', component => 'cilium', label => 'Cilium',
      message => 'Cilium runs v1.17.0, expected 1.20.0', remedy => { task => 'upgrade_cilium' } },
    { kind => 'error', component => 'worker_host_probes', label => 'Worker host probes',
      message => 'Worker host probes: could not list OCPNode in ocp-system, drift unknown: 403 Forbidden',
      remedy => undef },
    { kind => 'version', component => 'nfd', label => 'NFD',
      message => 'NFD runs v0.17.0, expected v0.18.3', remedy => undef },
);

{
    local $DETECT = sub { [ @MIXED ] };
    my ($rc, $out, $err) = run_status(project('text-mixed'));

    is $rc, 0, 'a probe that could not be read leaves the exit alone';
    is $err, '', 'STDERR: empty here (OCP::Drift carps the cause itself)';
    my ($section) = $out =~ /\n=== Drift ===\n(.*?)\n\n/s;
    is $section, join("\n",
        '  [drift] Cilium runs v1.17.0, expected 1.20.0',
        '  [drift] could not be checked: Worker host probes: could not list OCPNode in ocp-system, drift unknown: 403 Forbidden',
        '  [drift] NFD runs v0.17.0, expected v0.18.3',
    ), 'the error entry reads "could not be checked" with its cause, the drift as before';
    like $out, qr/^1 of 2 can be reconciled automatically: run 'ocp apply'\.$/m,
        'the count is of the drift found, not of the checks that could not be made';
}

{
    local $DETECT = sub { [ @MIXED ] };
    my ($rc, $out, $err) = run_status(project('json-mixed'), json => 1);
    my $d = decode_json($out);

    is $rc, 0, 'json: a probe that could not be read leaves the exit alone';
    ok !exists $d->{error}, 'json: and sets no error';
    my ($e) = grep { $_->{component} eq 'worker_host_probes' } @{ $d->{drift} };
    is $e->{kind}, 'error', 'json: the entry keeps kind error';
    like $e->{message}, qr/drift unknown: 403 Forbidden\z/, 'json: with its cause';
    ok !$e->{fixable}, 'json: not fixable';
}

#### the control: no drift is still no drift

{
    local $DETECT = sub { [] };
    my ($rc, $out, $err) = run_status(project('text-clean'));
    is $rc, 0, 'no drift: exit 0';
    is $err, '', 'no drift: STDERR empty';
    unlike $out, qr/=== Drift ===/, 'no drift: no drift section';

    ($rc, $out, $err) = run_status(project('json-clean'), json => 1);
    my $d = decode_json($out);
    is $rc, 0, 'json, no drift: exit 0';
    is_deeply $d->{drift}, [], 'json, no drift: an empty list';
    ok !exists $d->{error}, 'json, no drift: no error';
}

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP;
use OCP::Cmd::Status;
use OCP::Drift;
use OCP::Kubernetes;

#
# k257: the text form of `ocp status` printed a failed decrypt of
# kubeconfig.yaml and a failed connect to the cluster API on STDOUT. The rule
# in .claude/rules/ocp-rules.md: STDOUT is the report, STDERR is what went
# wrong together with its diagnosis, and the exit code says which it was.
# The --json form (t/230-status-json.t) already kept to it.
#

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }
{ package Local::FakeSecrets; sub new { bless {}, $_[0] } sub read_kubeconfig { $main::KC } }
{
    package Local::FakeK8s;
    sub new { bless {}, $_[0] }
    sub list_nodes {
        die "connection refused\n" if $main::API_DOWN;
        return [ { metadata => { name => 'police1' } } ];
    }
    sub api { undef }
    sub gpu_nodes { [] }
    sub node_name { $_[1]{metadata}{name} }
    sub node_ready { 1 }
    sub node_roles { 'control-plane' }
    sub node_version { 'v1.32.1+rke2r1' }
    sub node_internal_ip { '10.0.0.10' }
    sub node_gpu_count { 0 }
}

our ($KC, $API_DOWN);
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

sub run_status {
    my ($cfg) = @_;
    my $cmd = OCP::Cmd::Status->new(command_chain => [Local::FakeOCP->new(config => $cfg)]);
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my $rc;
    {
        no warnings 'redefine';
        local *OCP::Secrets::new            = sub { Local::FakeSecrets->new };
        local *OCP::Kubernetes::new         = sub { Local::FakeK8s->new };
        local *OCP::Drift::detect           = sub { [] };
        local *OCP::Cmd::Status::rex_prober = sub { undef };
        local *STDOUT = $o;
        local *STDERR = $e;
        $rc = $cmd->execute([], []);
    }
    return ($rc, $out, $err);
}

#### kubeconfig.yaml cannot be decrypted

{
    my $cfg = project('nokc');
    local $KC = undef;
    my ($rc, $out, $err) = run_status($cfg);

    is $rc, 1, 'undecryptable kubeconfig: exit 1';

    # STDOUT: the report, as far as it got.
    like $out, qr/^Cluster: nokc$/m, 'STDOUT: the spec summary is the report';
    like $out, qr/^=== Status ===\nCluster exists \(kubeconfig\.yaml found\)\n/m,
        'STDOUT: the status section says what it found';
    unlike $out, qr/decrypt|age\.key|ERROR/i, 'STDOUT: neither the error nor its diagnosis';

    # STDERR: the error and its diagnosis, nothing else.
    is $err, "ERROR: Cannot decrypt kubeconfig.yaml\nMake sure .ocp/age.key exists.\n",
        'STDERR: the error with its diagnosis, and only that';
}

#### cluster API cannot be reached

{
    my $cfg = project('down');
    local $KC       = "apiVersion: v1\n";
    local $API_DOWN = 1;
    my ($rc, $out, $err) = run_status($cfg);

    is $rc, 1, 'API failure: exit 1';

    # STDOUT: the report, ending on the kubeconfig hint as a good run does.
    like $out, qr/^Cluster: down$/m, 'STDOUT: the spec summary is the report';
    like $out, qr/^Cluster exists \(kubeconfig\.yaml found\)$/m, 'STDOUT: the status section';
    like $out, qr/\nKubeconfig available\. Export with: ocp kubeconfig -e\n\z/,
        'STDOUT: the kubeconfig hint closes the report';
    unlike $out, qr/connection refused|Cannot connect|WARNING|Error:/,
        'STDOUT: neither the error nor its cause';

    # STDERR: the error and the API's answer, one line each.
    is $err, "WARNING: Cannot connect to cluster API\nError: connection refused\n",
        'STDERR: the error with its cause, and only that';
}

#### a cluster that answers: STDERR stays empty

{
    my $cfg = project('live');
    local $KC = "apiVersion: v1\n";
    my ($rc, $out, $err) = run_status($cfg);

    is $rc, 0, 'success: exit 0';
    like $out, qr/^police1\s+Ready\s+control-plane\s/m, 'STDOUT: the node table';
    like $out, qr/^Kubeconfig: ocp kubeconfig -e$/m, 'STDOUT: the kubeconfig hint';
    is $err, '', 'STDERR: empty';
}

done_testing;

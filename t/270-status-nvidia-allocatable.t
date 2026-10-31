#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use JSON::MaybeXS qw( decode_json );

use lib 'lib';

use IO::K8s;
use OCP;
use OCP::Cmd::Status;
use OCP::Drift;
use OCP::Kubernetes;

#
# k270: `ocp status` counts NVIDIA GPUs by status.allocatable, as the AMD
# block does since k252. The kubelet keeps capacity standing after the device
# plugin unregisters, so a node whose plugin is gone still has capacity 1 --
# and nothing the scheduler can hand out. Text shows allocatable, capacity
# beside it where the two differ; --json nodes[].gpu is allocatable and
# nodes[].gpu_capacity the capacity. The real OCP::Kubernetes runs over a fake
# api handing out real IO::K8s nodes, as in t/252-status-amd-gpu.t.
#

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }
{ package Local::FakeSecrets; sub new { bless {}, $_[0] } sub read_kubeconfig { "apiVersion: v1\nkind: Config\n" } }
{ package Local::FakeList; sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
{
    package Local::FakeApi;
    sub new { my ($class, %arg) = @_; bless { %arg }, $class }
    sub list {
        my ($self, $kind) = @_;
        die "unexpected list $kind\n" unless $kind eq 'Node';
        return Local::FakeList->new($self->{nodes});
    }
    sub get { die "unexpected get $_[1]\n" }
}

my $IO = IO::K8s->new;

sub node {
    my ($name, %arg) = @_;
    return $IO->struct_to_object('Node', {
        metadata => { name => $name },
        status   => {
            conditions => [ { type => 'Ready', status => 'True' } ],
            addresses  => [ { type => 'InternalIP', address => '10.230.30.52' } ],
            nodeInfo   => {
                kubeletVersion => 'v1.36.4+rke2r1', kubeProxyVersion => 'v1.36.4+rke2r1',
                architecture => 'amd64', bootID => 'b', containerRuntimeVersion => 'containerd://2.3.4',
                kernelVersion => '6.8.0', machineID => 'm', operatingSystem => 'linux',
                osImage => 'Ubuntu 24.04.5 LTS', systemUUID => 'u',
            },
            (defined $arg{allocatable} ? (allocatable => { 'nvidia.com/gpu' => $arg{allocatable} }) : ()),
            (defined $arg{capacity}    ? (capacity    => { 'nvidia.com/gpu' => $arg{capacity} })    : ()),
        },
    });
}

my $ocp = OCP->new;
my $tmp = tempdir(CLEANUP => 1);
my $ENC = JSON::MaybeXS->new(canonical => 1, pretty => 1);

sub project {
    my ($name) = @_;
    my $dir = path($tmp)->child($name);
    $dir->mkpath;
    my $cfg = $dir->child('ocp.yaml');
    $ocp->dump_file($cfg->stringify, {
        name           => $name,
        kubernetes     => { version => 'v1.36.4+rke2r1' },
        control_planes => [{ provider => 'ssh', host => '10.230.30.52' }],
    });
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n");
    return $cfg->stringify;
}

# Runs `ocp status` (--json when $json) over the nodes; returns rc, STDOUT, STDERR.
sub run_status {
    my ($cfg, $json, @nodes) = @_;
    my $k8s = OCP::Kubernetes->new(api => Local::FakeApi->new(nodes => \@nodes));
    my $cmd = OCP::Cmd::Status->new(($json ? (json => 1) : ()),
        command_chain => [Local::FakeOCP->new(config => $cfg)]);
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my $rc;
    {
        no warnings 'redefine';
        local *OCP::Secrets::new            = sub { Local::FakeSecrets->new };
        local *OCP::Kubernetes::new         = sub { $k8s };
        local *OCP::Drift::detect           = sub { [] };
        local *OCP::Cmd::Status::rex_prober = sub { undef };
        local *STDOUT = $o;
        local *STDERR = $e;
        $rc = $cmd->execute([], []);
    }
    return ($rc, $out, $err);
}

# The GPU section only: from its header to the blank line before the hint.
sub gpu_section {
    my ($out) = @_;
    return $out =~ /^(=== GPU Status ===\n.*?)\n(?:=== |Kubeconfig: )/ms ? $1 : undef;
}

# The gpu and gpu_capacity of every node, re-encoded from STDOUT with exactly
# those values: equal to STDOUT only when they are there as numbers (or null),
# not as strings.
sub gpu_fields_exact {
    my ($out, %want) = @_;
    my $d = decode_json($out);
    for my $n (@{ $d->{nodes} }) {
        @$n{qw( gpu gpu_capacity )} = @{ $want{ $n->{name} } };
    }
    return $out eq $ENC->encode($d);
}

my $STALE = ': stale after a device plugin unregisters, or unhealthy devices; only allocatable schedules)';

#### capacity 1 / allocatable 0: the device plugin is gone

{
    my $cfg = project('gone');
    my @nodes = (node('otho', capacity => '1', allocatable => '0'));

    my ($rc, $out, $err) = run_status($cfg, 0, @nodes);
    is $rc, 0, 'plugin gone, text: exit 0';
    is $err, '', 'plugin gone, text: nothing on STDERR';
    is gpu_section($out), "=== GPU Status ===\n"
        . "  otho: 0x NVIDIA GPU allocatable (capacity 1$STALE\n",
        'plugin gone, text: the node stays listed, 0 allocatable, capacity beside it';
    unlike $out, qr/1x NVIDIA GPU/, 'plugin gone, text: capacity is never taken for the count';

    ($rc, $out, $err) = run_status($cfg, 1, @nodes);
    is $rc, 0, 'plugin gone, JSON: exit 0';
    is $err, '', 'plugin gone, JSON: nothing on STDERR';
    my $otho = decode_json($out)->{nodes}[0];
    is $otho->{gpu}, 0, 'plugin gone, JSON: gpu is allocatable, 0';
    is $otho->{gpu_capacity}, 1, 'plugin gone, JSON: gpu_capacity is 1';
    ok gpu_fields_exact($out, otho => [ 0, 1 ]), 'plugin gone, JSON: both are numbers';
}

#### capacity 1 / allocatable 1: the device plugin runs

{
    my $cfg = project('up');
    my @nodes = (node('otho', capacity => '1', allocatable => '1'));

    my ($rc, $out, $err) = run_status($cfg, 0, @nodes);
    is $err, '', 'plugin up, text: nothing on STDERR';
    is gpu_section($out), "=== GPU Status ===\n  otho: 1x NVIDIA GPU\n",
        'plugin up, text: the line of before, no capacity beside it';

    ($rc, $out, $err) = run_status($cfg, 1, @nodes);
    my $otho = decode_json($out)->{nodes}[0];
    is $otho->{gpu}, 1, 'plugin up, JSON: gpu 1';
    is $otho->{gpu_capacity}, 1, 'plugin up, JSON: gpu_capacity 1';
    ok gpu_fields_exact($out, otho => [ 1, 1 ]), 'plugin up, JSON: both are numbers';
}

#### capacity 2 / allocatable 1: one device unhealthy

{
    my $cfg = project('half');
    my @nodes = (node('otho', capacity => '2', allocatable => '1'));

    my ($rc, $out, $err) = run_status($cfg, 0, @nodes);
    is gpu_section($out), "=== GPU Status ===\n"
        . "  otho: 1x NVIDIA GPU allocatable (capacity 2$STALE\n",
        'one device unhealthy, text: 1 allocatable, capacity 2 beside it';

    ($rc, $out, $err) = run_status($cfg, 1, @nodes);
    ok gpu_fields_exact($out, otho => [ 1, 2 ]), 'one device unhealthy, JSON: gpu 1, gpu_capacity 2';
}

#### No NVIDIA GPU: gpu 0, gpu_capacity null, no GPU section

{
    my $cfg = project('none');
    my @nodes = (node('police1'));

    my ($rc, $out, $err) = run_status($cfg, 0, @nodes);
    unlike $out, qr/GPU Status/, 'no GPU, text: no GPU section';

    ($rc, $out, $err) = run_status($cfg, 1, @nodes);
    my $p1 = decode_json($out)->{nodes}[0];
    ok exists $p1->{gpu_capacity} && !defined $p1->{gpu_capacity}, 'no GPU, JSON: gpu_capacity is null';
    ok gpu_fields_exact($out, police1 => [ 0, undef ]), 'no GPU, JSON: gpu 0, gpu_capacity null';
}

done_testing;

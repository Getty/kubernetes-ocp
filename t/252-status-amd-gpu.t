#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use IO::K8s;
use Kubernetes::REST::APIError;
use OCP;
use OCP::Cmd::Status;
use OCP::Drift;
use OCP::Kubernetes;

#
# k252: AMD GPU nodes in the GPU section of `ocp status` (design spec
# 2026-10-31-amd-gpu-worker-design.md, section 6). The real OCP::Kubernetes
# runs over a fake api, and the nodes, DaemonSets and ResourceSlices are real
# IO::K8s objects, so the fields are read the way a live cluster hands them
# over. Drift is stubbed: it has its own tests, and this one compares output.
#

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }
{ package Local::FakeSecrets; sub new { bless {}, $_[0] } sub has_kubeconfig { 1 } sub read_kubeconfig { "apiVersion: v1\nkind: Config\n" } }
{ package Local::FakeList; sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
{
    package Local::FakeApi;
    sub new { my ($class, %arg) = @_; bless { %arg, calls => [] }, $class }
    sub calls { $_[0]{calls} }
    sub list {
        my ($self, $kind) = @_;
        push @{ $self->{calls} }, "list $kind";
        return Local::FakeList->new($self->{nodes}) if $kind eq 'Node';
        die "unexpected list $kind\n" unless $kind eq 'ResourceSlice';
        my $slices = $self->{slices} // [];
        die $slices unless ref $slices eq 'ARRAY';
        return Local::FakeList->new($slices);
    }
    sub get {
        my ($self, $kind, %arg) = @_;
        push @{ $self->{calls} }, "get $kind $arg{namespace}/$arg{name}";
        die "unexpected get $kind\n" unless $kind eq 'DaemonSet';
        my $ds = $self->{daemonsets}{ $arg{name} } // main::api_error(404, "get $kind");
        die $ds if $ds->isa('Kubernetes::REST::APIError');
        return $ds;
    }
}

my $IO = IO::K8s->new;

sub api_error {
    my ($code, $context) = @_;
    my $reason = $code == 404 ? 'NotFound' : 'Forbidden';
    return Kubernetes::REST::APIError->new(
        code    => $code,
        context => $context,
        body    => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}),
    );
}

sub node {
    my ($name, %arg) = @_;
    return $IO->struct_to_object('Node', {
        metadata => { name => $name, labels => $arg{labels} // {} },
        status   => {
            conditions => [ { type => 'Ready', status => 'True' } ],
            addresses  => [ { type => 'InternalIP', address => $arg{ip} // '10.0.0.1' } ],
            nodeInfo   => {
                kubeletVersion => 'v1.36.4+rke2r1', kubeProxyVersion => 'v1.36.4+rke2r1',
                architecture => 'amd64', bootID => 'b', containerRuntimeVersion => 'containerd://2.3.4',
                kernelVersion => '7.0.0', machineID => 'm', operatingSystem => 'linux',
                osImage => 'Ubuntu 24.04.5 LTS', systemUUID => 'u',
            },
            ($arg{allocatable} ? (allocatable => $arg{allocatable}) : ()),
            ($arg{capacity}    ? (capacity    => $arg{capacity})    : ()),
        },
    });
}

sub daemonset {
    my ($name, $ready, $desired) = @_;
    return $IO->struct_to_object('DaemonSet', {
        metadata => { name => $name, namespace => 'kube-system' },
        spec     => {
            selector => { matchLabels => { app => $name } },
            template => {
                metadata => { labels => { app => $name } },
                spec     => { containers => [ { name => 'c', image => 'rocm/k8s-device-plugin:1.31.0.11' } ] },
            },
        },
        status => {
            numberReady => $ready, desiredNumberScheduled => $desired,
            currentNumberScheduled => $desired, numberMisscheduled => 0,
        },
    });
}

# The shape the DRA driver published on synapse (2026-10-31): pool named after
# the node, one device gpu-0-128.
sub slice {
    my ($name, %arg) = @_;
    my $node = $arg{node} // 'synapse';
    return $IO->struct_to_object('ResourceSlice', {
        metadata => { name => $name },
        spec     => {
            driver   => $arg{driver} // 'gpu.amd.com',
            nodeName => $node,
            pool     => { name => $node, generation => $arg{generation} // 1, resourceSliceCount => 1 },
            devices  => [ map {
                +{
                    name       => "gpu-$_-128",
                    attributes => {
                        deviceID     => { string => '0x1586' },
                        computeUnits => { int => 40 },
                        simdUnits    => { int => 80 },
                        pciBusID     => { string => '0000:95:00.0' },
                        type         => { string => 'amdgpu' },
                    },
                    capacity => { memory => { value => '128Gi' } },
                }
            } 0 .. ($arg{devices} // 1) - 1 ],
        },
    });
}

my %AMD = ('ocp.internal/amd-gpu.present' => 'true');
my $DP  = 'amdgpu-device-plugin-daemonset';
my $LB  = 'amdgpu-labeller-daemonset';
my $DRA = 'k8s-gpu-dra-driver-kubeletplugin';
my $MX  = 'amdgpu-metrics-exporter';

my $ocp = OCP->new;
my $tmp = tempdir(CLEANUP => 1);

sub project {
    my ($name, %gpu) = @_;
    my $dir = path($tmp)->child($name);
    $dir->mkpath;
    my $cfg = $dir->child('ocp.yaml');
    $ocp->dump_file($cfg->stringify, {
        name           => $name,
        kubernetes     => { version => 'v1.36.4+rke2r1' },
        control_planes => [{ provider => 'ssh', host => '10.230.30.52' }],
        (%gpu ? (gpu => \%gpu) : ()),
    });
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n");
    return $cfg->stringify;
}

# Runs `ocp status` (text) against $api; returns rc, STDOUT, STDERR.
sub run_status {
    my ($cfg, $api) = @_;
    my $k8s = OCP::Kubernetes->new(api => $api);
    my $cmd = OCP::Cmd::Status->new(command_chain => [Local::FakeOCP->new(config => $cfg)]);
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my $rc;
    {
        no warnings 'redefine';
        local *OCP::Secrets::new          = sub { Local::FakeSecrets->new };
        local *OCP::Cmd::Status::reach_cluster_api = sub { $_[1] };
        local *OCP::Kubernetes::new       = sub { $k8s };
        local *OCP::Drift::detect         = sub { [] };
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

#### NVIDIA-only cluster: byte for byte what it printed before k252

{
    my $cfg = project('nvlab');
    my $api = Local::FakeApi->new(nodes => [
        node('otho', ip => '10.230.30.52',
             allocatable => { 'nvidia.com/gpu' => '1' }, capacity => { 'nvidia.com/gpu' => '1' },
             labels => { 'node-role.kubernetes.io/control-plane' => 'true' }),
        node('crag', ip => '10.230.30.54'),
    ]);
    my ($rc, $out, $err) = run_status($cfg, $api);

    my $row = "%-20s %-10s %-20s %-16s %s\n";
    my $expected = "Cluster: nvlab\n"
        . "Config:  $cfg\n"
        . "\n"
        . "=== Spec ===\n"
        . "Distribution: rke2 v1.36.4+rke2r1\n"
        . "Control Planes: 1 (ssh)\n"
        # k359: the GPU settings set at a node's install (t/359).
        . "GPU, set at install: toolkit true, amd.integrated false\n"
        . "  a joined worker takes a change only when joined again, a control plane never\n"
        . "\n"
        . "=== Status ===\n"
        . "Cluster exists (kubeconfig.yaml found)\n"
        . "\n"
        . sprintf($row, 'NAME', 'STATUS', 'ROLES', 'VERSION', 'INTERNAL-IP')
        . ('-' x 80) . "\n"
        . sprintf($row, 'otho', 'Ready', 'control-plane', 'v1.36.4+rke2r1', '10.230.30.52')
        . sprintf($row, 'crag', 'Ready', '<none>', 'v1.36.4+rke2r1', '10.230.30.54')
        . "\n"
        . "=== GPU Status ===\n"
        . "  otho: 1x NVIDIA GPU\n"
        . "\n"
        . "Kubeconfig: ocp kubeconfig -e\n";

    is $rc, 0, 'NVIDIA-only: exit 0';
    is $out, $expected, 'NVIDIA-only: the report is byte-identical to the pre-AMD one (plus k359\'s Spec line)';
    is $err, '', 'NVIDIA-only: nothing on STDERR';
    is_deeply [ grep { !/^list Node$/ } @{ $api->calls } ], [],
        'NVIDIA-only: no DaemonSet or ResourceSlice is read';
}

#### No GPU at all: still no GPU section

{
    my $cfg = project('nogpu');
    my $api = Local::FakeApi->new(nodes => [ node('police1') ]);
    my ($rc, $out, $err) = run_status($cfg, $api);
    unlike $out, qr/GPU Status/, 'no GPU node: no GPU section';
    unlike $out, qr/AMD/, 'and no AMD line';
}

#### AMD node, device plugin ready, single gfx target, cluster default

{
    my $cfg = project('amdlab', enabled => 1);
    my $api = Local::FakeApi->new(
        nodes => [
            node('otho', allocatable => { 'nvidia.com/gpu' => '1' },
                 capacity    => { 'nvidia.com/gpu' => '1' }),
            node('synapse', labels => { %AMD, 'ocp.internal/amd-gpu.gfx-target' => 'gfx1151' },
                 allocatable => { 'amd.com/gpu' => '1' }, capacity => { 'amd.com/gpu' => '1' }),
        ],
        daemonsets => { $DP => daemonset($DP, 1, 1), $LB => daemonset($LB, 1, 1) },
        slices     => [],
    );
    my ($rc, $out, $err) = run_status($cfg, $api);

    is $rc, 0, 'AMD: exit 0';
    is $err, '', 'AMD: a cluster that answers everything leaves STDERR empty';
    is gpu_section($out), "=== GPU Status ===\n"
        . "  otho: 1x NVIDIA GPU\n"
        . "  synapse: AMD GPU\n"
        . "    amd.com/gpu: 1 allocatable (capacity 1)\n"
        . "    gfx target:  gfx1151\n"
        . "    allocation:  device-plugin (cluster default gpu.amd.allocation)\n"
        . "  AMD DRA ResourceSlices (driver gpu.amd.com) [experimental]: none published\n"
        . "  AMD DaemonSets:\n"
        . "    kube-system/$DP: 1/1 ready\n"
        . "    kube-system/$DRA [experimental]: not deployed\n"
        . "    kube-system/$LB: 1/1 ready\n"
        . "    kube-system/$MX: not deployed\n",
        'AMD: NVIDIA line unchanged, then the AMD node, the slices and the DaemonSets';
    is_deeply [ sort grep { /^get / } @{ $api->calls } ],
        [ sort map { "get DaemonSet kube-system/$_" } $DP, $DRA, $LB, $MX ],
        'AMD: the four DaemonSets of %OCP::Drift::AMD_GPU_DAEMONSETS are read';
}

#### Stale capacity: the plugin left, the kubelet kept capacity

{
    my $cfg = project('stale');
    my $api = Local::FakeApi->new(
        nodes => [ node('synapse', labels => { %AMD },
                        allocatable => { 'amd.com/gpu' => '0' }, capacity => { 'amd.com/gpu' => '1' }) ],
        daemonsets => { $DP => daemonset($DP, 0, 0) },
    );
    my ($rc, $out, $err) = run_status($cfg, $api);
    like $out, qr/^    amd\.com\/gpu: 0 allocatable \(capacity 1: stale after a device plugin unregisters, or unhealthy devices; only allocatable schedules\)$/m,
        'stale capacity: allocatable is the count, capacity is named as not schedulable';
    unlike $out, qr/amd\.com\/gpu: 1 allocatable/, 'stale capacity: capacity is never taken for allocatable';
    like $out, qr/^    kube-system\/$DP: 0\/0 ready$/m, 'a DaemonSet no node selects is 0/0, not missing';
    like $out, qr/^    gfx target:  not labelled$/m, 'no gfx label: said so';
}

#### A node whose amd.com/gpu is all there is (no marker label)

{
    my $cfg = project('nomarker');
    my $api = Local::FakeApi->new(
        nodes => [ node('rocky', allocatable => { 'amd.com/gpu' => '2' }, capacity => { 'amd.com/gpu' => '2' }),
                   node('plain', labels => { 'ocp.internal/amd-gpu.present' => 'false' }) ],
    );
    my ($rc, $out, $err) = run_status($cfg, $api);
    like $out, qr/^  rocky: AMD GPU$/m, 'amd.com/gpu without the marker still makes an AMD node';
    unlike $out, qr/plain: AMD/, 'a marker other than true does not';
}

#### Several gfx targets, override label vs. cluster default

{
    my $cfg = project('mixed', amd => { allocation => 'dra' });
    my $api = Local::FakeApi->new(
        nodes => [
            node('multi', labels => {
                %AMD,
                'ocp.internal/amd-gpu.gfx-target.gfx1151' => '1',
                'ocp.internal/amd-gpu.gfx-target.gfx1100' => '2',
                'ocp.internal/amd-gpu.allocation'         => 'device-plugin',
            }, allocatable => { 'amd.com/gpu' => '3' }, capacity => { 'amd.com/gpu' => '3' }),
            node('synapse', labels => { %AMD, 'ocp.internal/amd-gpu.gfx-target' => 'gfx1151' }),
            node('typo', labels => { %AMD, 'ocp.internal/amd-gpu.allocation' => 'dra-please' }),
        ],
    );
    my ($rc, $out, $err) = run_status($cfg, $api);
    like $out, qr/^  multi: AMD GPU\n    amd\.com\/gpu: 3 allocatable \(capacity 3\)\n    gfx target:  2x gfx1100, 1x gfx1151\n    allocation:  device-plugin \(node label ocp\.internal\/amd-gpu\.allocation\)$/m,
        'several gfx targets: one per label with its count; the node label wins over gpu.amd.allocation';
    like $out, qr/^  synapse: AMD GPU\n    amd\.com\/gpu: 0 allocatable\n    gfx target:  gfx1151\n    allocation:  dra \[experimental\] \(cluster default gpu\.amd\.allocation\)$/m,
        'no node label: the cluster default applies, DRA marked experimental';
    like $out, qr/^    allocation:  dra-please \(node label ocp\.internal\/amd-gpu\.allocation; not one of device-plugin, dra, or none\)$/m,
        'an unknown node label value is shown as it is, and named as unknown';
    is $err, '', 'a typo in a node label is a finding in the report, not a read error';
}

#### Invalid gpu.amd.allocation in ocp.yaml: said on STDERR, the report goes on

{
    my $cfg = project('badcfg', amd => { allocation => 'plugin' });
    my $api = Local::FakeApi->new(nodes => [
        node('synapse', labels => { %AMD }),
        node('override', labels => { %AMD, 'ocp.internal/amd-gpu.allocation' => 'none' }),
    ]);
    my ($rc, $out, $err) = run_status($cfg, $api);
    is $rc, 0, 'invalid gpu.amd.allocation: status still completes';
    like $err, qr/^WARNING: gpu\.amd\.allocation must be device-plugin, dra, or none, not 'plugin'; /m,
        'invalid gpu.amd.allocation: the reason on STDERR';
    unlike $err, qr/ at \S+ line \d+/, 'and without the croak location';
    like $out, qr/^  synapse: AMD GPU\n.*\n.*\n    allocation:  unknown \(gpu\.amd\.allocation is invalid, see STDERR\)$/m,
        'a node without the label: allocation unknown';
    like $out, qr/^    allocation:  none \(node label ocp\.internal\/amd-gpu\.allocation\)$/m,
        'a node with the label does not need the default';
}

#### ResourceSlices: counted per node, other drivers left out

{
    my $cfg = project('slices');
    my $api = Local::FakeApi->new(
        nodes  => [ node('synapse', labels => { %AMD, 'ocp.internal/amd-gpu.allocation' => 'dra' }) ],
        slices => [
            slice('synapse-gpu.amd.com-a'),
            slice('rocky-gpu.amd.com-a', node => 'rocky', devices => 2),
            slice('otho-gpu.nvidia.com-a', node => 'otho', driver => 'gpu.nvidia.com'),
            # A pool mid-republish: the old generation is no longer counted.
            slice('rocky-gpu.amd.com-old', node => 'rocky', devices => 2, generation => 0),
        ],
        daemonsets => { $DRA => daemonset($DRA, 1, 1) },
    );
    my ($rc, $out, $err) = run_status($cfg, $api);
    like $out, qr/^  AMD DRA ResourceSlices \(driver gpu\.amd\.com\) \[experimental\]:\n    rocky: 2 devices\n    synapse: 1 device\n  AMD DaemonSets:$/m,
        'slices: devices per node, sorted, only driver gpu.amd.com, only the newest generation of a pool';
    unlike $out, qr/otho: \d+ device/, 'another driver\'s slice is not counted';
    like $out, qr/^    kube-system\/$DRA \[experimental\]: 1\/1 ready$/m, 'the DRA DaemonSet is marked experimental';
    is $err, '', 'slices: nothing on STDERR';
}

#### ResourceSlices: API not served, read failure

{
    my $cfg = project('noslices');
    my $api = Local::FakeApi->new(
        nodes  => [ node('synapse', labels => { %AMD }) ],
        slices => api_error(404, 'list ResourceSlice'),
    );
    my ($rc, $out, $err) = run_status($cfg, $api);
    like $out, qr/^  AMD DRA ResourceSlices \(driver gpu\.amd\.com\) \[experimental\]: not served \(this cluster's API has no resource\.k8s\.io\/v1\)$/m,
        'slices 404: the API is not served, said plainly';
    is $err, '', 'slices 404: not an error';

    $api = Local::FakeApi->new(
        nodes  => [ node('synapse', labels => { %AMD }) ],
        slices => api_error(403, 'list ResourceSlice'),
    );
    ($rc, $out, $err) = run_status($cfg, $api);
    like $out, qr/^  AMD DRA ResourceSlices \(driver gpu\.amd\.com\) \[experimental\]: unknown \(read failed, see STDERR\)$/m,
        'slices 403: the report says the count is unknown';
    like $err, qr/^WARNING: Cannot read ResourceSlices: Kubernetes API error \(list ResourceSlice\): 403 .*Forbidden/m,
        'slices 403: the API error on STDERR';
    is $rc, 0, 'slices 403: a part of the GPU section, not the exit code';
}

#### DaemonSets: missing, partial, ready, unreadable

{
    my $cfg = project('ds');
    my $api = Local::FakeApi->new(
        nodes      => [ node('synapse', labels => { %AMD }) ],
        daemonsets => {
            $DP => daemonset($DP, 0, 1),
            $LB => daemonset($LB, 1, 1),
            $MX => api_error(403, 'get DaemonSet'),
        },
    );
    my ($rc, $out, $err) = run_status($cfg, $api);
    like $out, qr/^    kube-system\/$DP: 0\/1 ready$/m, 'partial: ready of desired';
    like $out, qr/^    kube-system\/$LB: 1\/1 ready$/m, 'ready';
    like $out, qr/^    kube-system\/$DRA \[experimental\]: not deployed$/m, 'missing: not deployed';
    like $out, qr/^    kube-system\/$MX: unknown \(read failed, see STDERR\)$/m, 'unreadable: unknown in the report';
    like $err, qr/^WARNING: Cannot read DaemonSet kube-system\/$MX: Kubernetes API error \(get DaemonSet\): 403 /m,
        'unreadable: the API error on STDERR';
    unlike $err, qr/$DRA/, 'a missing DaemonSet is not an error';
}

done_testing;

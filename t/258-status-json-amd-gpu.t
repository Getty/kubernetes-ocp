#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use JSON::MaybeXS qw( decode_json );

use lib 'lib';

use IO::K8s;
use Kubernetes::REST::APIError;
use OCP;
use OCP::Cmd::Status;
use OCP::Drift;
use OCP::Kubernetes;

#
# k258: `ocp status --json` carries what the text form's AMD block shows
# (k252): the AMD nodes, the devices in the ResourceSlices of driver
# gpu.amd.com, and the DaemonSets of %OCP::Drift::AMD_GPU_DAEMONSETS. A
# cluster without an AMD node prints the object it printed before, byte for
# byte. The fixtures are t/252-status-amd-gpu.t's: the real OCP::Kubernetes
# over a fake api handing out real IO::K8s objects.
#

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }
{ package Local::FakeSecrets; sub new { bless {}, $_[0] } sub read_kubeconfig { "apiVersion: v1\nkind: Config\n" } }
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
                    attributes => { type => { string => 'amdgpu' } },
                    capacity   => { memory => { value => '128Gi' } },
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
my $ENC = JSON::MaybeXS->new(canonical => 1, pretty => 1);

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

# Runs `ocp status --json` against $api; returns rc, STDOUT, STDERR.
sub run_status {
    my ($cfg, $api) = @_;
    my $k8s = OCP::Kubernetes->new(api => $api);
    my $cmd = OCP::Cmd::Status->new(json => 1, command_chain => [Local::FakeOCP->new(config => $cfg)]);
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

# STDOUT with its amd_gpu part swapped for $amd and encoded again: equal to
# STDOUT only when amd_gpu is $amd to the byte -- a count printed as a string
# or a key too many fails it.
sub with_amd_gpu {
    my ($out, $amd) = @_;
    my $d = decode_json($out);
    $d->{amd_gpu} = $amd;
    return $ENC->encode($d);
}

sub ds {
    my ($name, $state, $ready, $desired) = @_;
    return { namespace => 'kube-system', name => $name, state => $state, ready => $ready, desired => $desired };
}

#### No AMD node: the object of before k258, byte for byte, and nothing more read

{
    my $cfg = project('nvlab');
    my $api = Local::FakeApi->new(nodes => [
        node('otho', ip => '10.230.30.52',
             allocatable => { 'nvidia.com/gpu' => '1' }, capacity => { 'nvidia.com/gpu' => '1' },
             labels => { 'node-role.kubernetes.io/control-plane' => 'true' }),
        node('crag', ip => '10.230.30.54', labels => { 'ocp.internal/amd-gpu.present' => 'false' }),
    ]);
    my ($rc, $out, $err) = run_status($cfg, $api);

    my $true = JSON::MaybeXS::true();
    is $out, $ENC->encode({
        cluster  => 'nvlab',
        config   => $cfg,
        deployed => $true,
        drift    => [],
        nodes    => [
            { gpu => 0, gpu_capacity => undef, internal_ip => '10.230.30.54', name => 'crag',
              ready => $true, roles => '<none>', version => 'v1.36.4+rke2r1' },
            { gpu => 1, gpu_capacity => 1, internal_ip => '10.230.30.52', name => 'otho',
              ready => $true, roles => 'control-plane', version => 'v1.36.4+rke2r1' },
        ],
        spec => {
            control_planes => { count => 1, provider => 'ssh', server_type => undef },
            distribution   => 'rke2',
            version        => 'v1.36.4+rke2r1',
            workers        => [],
        },
    }), 'no AMD node: the pre-k258 object (plus k270\'s gpu_capacity) to the byte, no amd_gpu key';
    is $rc, 0, 'no AMD node: exit 0';
    is $err, '', 'no AMD node: nothing on STDERR';
    is_deeply [ grep { !/^list Node$/ } @{ $api->calls } ], [],
        'no AMD node: no DaemonSet or ResourceSlice is read';
}

#### AMD node, device plugin ready, cluster default

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
    my $amd = {
        nodes => [ {
            name => 'synapse', allocatable => 1, capacity => 1, gfx_targets => [ 'gfx1151' ],
            allocation => 'device-plugin', allocation_source => 'config',
        } ],
        resource_slices => { state => 'served', devices => {} },
        daemonsets      => {
            device_plugin => ds($DP,  'ready', 1, 1),
            dra           => ds($DRA, 'not-deployed', undef, undef),
            labeller      => ds($LB,  'ready', 1, 1),
            metrics       => ds($MX,  'not-deployed', undef, undef),
        },
    };
    is $out, with_amd_gpu($out, $amd), 'AMD: the amd_gpu object, counts as numbers';
    is_deeply decode_json($out)->{amd_gpu}, $amd, 'AMD: amd_gpu as expected';

    my $d = decode_json($out);
    is_deeply [ map { "$_->{name}=$_->{gpu}" } @{ $d->{nodes} } ], [ 'otho=1', 'synapse=0' ],
        'nodes[].gpu stays the NVIDIA count';
    is_deeply [ sort grep { /^get / } @{ $api->calls } ],
        [ sort map { "get DaemonSet kube-system/$_" } $DP, $DRA, $LB, $MX ],
        'AMD: the four DaemonSets of %OCP::Drift::AMD_GPU_DAEMONSETS are read';

    my (undef, $again) = run_status($cfg, $api);
    is $again, $out, 'AMD: a second run is byte-identical';
}

#### Several gfx targets, node label vs. config, slices counted, DaemonSet states

{
    my $cfg = project('mixed', amd => { allocation => 'dra' });
    my $api = Local::FakeApi->new(
        nodes => [
            node('typo', labels => { %AMD, 'ocp.internal/amd-gpu.allocation' => 'dra-please' }),
            node('multi', labels => {
                %AMD,
                'ocp.internal/amd-gpu.gfx-target.gfx1151' => '1',
                'ocp.internal/amd-gpu.gfx-target.gfx1100' => '2',
                'ocp.internal/amd-gpu.allocation'         => 'device-plugin',
            }, allocatable => { 'amd.com/gpu' => '3' }, capacity => { 'amd.com/gpu' => '3' }),
            node('synapse', labels => { %AMD, 'ocp.internal/amd-gpu.gfx-target' => 'gfx1151' }),
            # A second card came in: the host step wrote one label per target,
            # the one-target label of before is still there. gfx1151 is one
            # target, not two, and the list is sorted, not in label order.
            node('relabelled', labels => {
                %AMD,
                'ocp.internal/amd-gpu.gfx-target'         => 'gfx1151',
                'ocp.internal/amd-gpu.gfx-target.gfx1151' => '1',
                'ocp.internal/amd-gpu.gfx-target.gfx1100' => '1',
            }, allocatable => { 'amd.com/gpu' => '0' }, capacity => { 'amd.com/gpu' => '1' }),
        ],
        slices => [
            slice('synapse-gpu.amd.com-a'),
            slice('rocky-gpu.amd.com-a', node => 'rocky', devices => 2),
            slice('otho-gpu.nvidia.com-a', node => 'otho', driver => 'gpu.nvidia.com'),
            slice('rocky-gpu.amd.com-old', node => 'rocky', devices => 2, generation => 0),
        ],
        daemonsets => {
            $DRA => daemonset($DRA, 0, 1),
            $DP  => daemonset($DP, 0, 0),
            $LB  => api_error(403, 'get DaemonSet'),
        },
    );
    my ($rc, $out, $err) = run_status($cfg, $api);

    my $amd = {
        nodes => [
            { name => 'multi', allocatable => 3, capacity => 3, gfx_targets => [ 'gfx1100', 'gfx1151' ],
              allocation => 'device-plugin', allocation_source => 'node-label' },
            { name => 'relabelled', allocatable => 0, capacity => 1, gfx_targets => [ 'gfx1100', 'gfx1151' ],
              allocation => 'dra', allocation_source => 'config' },
            { name => 'synapse', allocatable => 0, capacity => undef, gfx_targets => [ 'gfx1151' ],
              allocation => 'dra', allocation_source => 'config' },
            { name => 'typo', allocatable => 0, capacity => undef, gfx_targets => [],
              allocation => 'dra-please', allocation_source => 'node-label' },
        ],
        resource_slices => { state => 'served', devices => { rocky => 2, synapse => 1 } },
        daemonsets      => {
            device_plugin => ds($DP,  'ready', 0, 0),
            dra           => ds($DRA, 'partial', 0, 1),
            labeller      => ds($LB,  'unknown', undef, undef),
            metrics       => ds($MX,  'not-deployed', undef, undef),
        },
    };
    is_deeply decode_json($out)->{amd_gpu}, $amd,
        'mixed: nodes sorted, label wins over config, slices per node, every DaemonSet state';
    is $out, with_amd_gpu($out, $amd), 'mixed: to the byte, null where nothing was read';
    is $rc, 0, 'an unreadable DaemonSet is part of the GPU section, not the exit code';
    like $err, qr/\AWARNING: Cannot read DaemonSet kube-system\/$LB: Kubernetes API error \(get DaemonSet\): 403 [^\n]*Forbidden[^\n]*\n\z/,
        'the unreadable DaemonSet: its API error on STDERR, one line and nothing else there';
}

#### gpu.amd.allocation invalid: allocation null, the reason on STDERR

{
    my $cfg = project('badcfg', amd => { allocation => 'plugin' });
    my $api = Local::FakeApi->new(nodes => [
        node('synapse', labels => { %AMD }),
        node('override', labels => { %AMD, 'ocp.internal/amd-gpu.allocation' => 'none' }),
    ]);
    my ($rc, $out, $err) = run_status($cfg, $api);

    is $rc, 0, 'invalid gpu.amd.allocation: exit 0';
    my $nodes = decode_json($out)->{amd_gpu}{nodes};
    is_deeply [ map { [ $_->{name}, $_->{allocation}, $_->{allocation_source} ] } @$nodes ],
        [ [ 'override', 'none', 'node-label' ], [ 'synapse', undef, 'config' ] ],
        'a node without its own label: allocation null, from config';
    like $err, qr/^WARNING: gpu\.amd\.allocation must be device-plugin, dra, or none, not 'plugin'; /m,
        'the reason on STDERR';
}

#### ResourceSlices: not served, unreadable

{
    my $cfg = project('noslices');
    my $api = Local::FakeApi->new(
        nodes  => [ node('synapse', labels => { %AMD }) ],
        slices => api_error(404, 'list ResourceSlice'),
    );
    my ($rc, $out, $err) = run_status($cfg, $api);
    is_deeply decode_json($out)->{amd_gpu}{resource_slices}, { state => 'not-served', devices => {} },
        'slices 404: not served, so none';
    is $err, '', 'slices 404: not an error';

    $api = Local::FakeApi->new(
        nodes  => [ node('synapse', labels => { %AMD }) ],
        slices => api_error(403, 'list ResourceSlice'),
    );
    ($rc, $out, $err) = run_status($cfg, $api);
    my $slices = decode_json($out)->{amd_gpu}{resource_slices};
    is_deeply $slices, { state => 'unknown', devices => undef }, 'slices 403: unknown, devices null';
    like $out, qr/"devices" : null/, 'slices 403: null on STDOUT, not an empty object';
    like $err, qr/^WARNING: Cannot read ResourceSlices: Kubernetes API error \(list ResourceSlice\): 403 /m,
        'slices 403: the API error on STDERR';
    is $rc, 0, 'slices 403: exit 0';
}

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp ();
use JSON::PP ();
use Kubernetes::REST::APIError;
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::AMDGPU;
use OCP::Cmd::Apply::DeployedHash;
use OCP::Config;
use OCP::Versions;

# Loaded before any glob below is set, so its own subs cannot replace them.
require Rex::Rancher::K8s;

#
# k251: `ocp apply` puts the AMD GPU stack on nodes the host step marked
# (ocp.internal/amd-gpu.present=true, k249): ROCm's device plugin or DRA
# driver by the node's allocation, AMD's node labeller, and with
# gpu.amd.metrics the device-metrics-exporter -- through Rex::Rancher::K8s,
# which is mocked here (the image's Rex::Rancher has none of the functions).
# The fake library acts on a fake cluster the way the real one acts on a real
# cluster that schedules by the affinity it was given, so readiness,
# idempotency and removal are judged on what the cluster then says.
#

my $MARKER = 'ocp.internal/amd-gpu.present';
my $ALLOC  = 'ocp.internal/amd-gpu.allocation';

my %DS = (
    device_plugin => 'amdgpu-device-plugin-daemonset',
    labeller      => 'amdgpu-labeller-daemonset',
    dra           => 'k8s-gpu-dra-driver-kubeletplugin',
    metrics       => 'amdgpu-metrics-exporter',
);
my %FN_DS = (
    deploy_amd_device_plugin    => 'device_plugin',
    deploy_amd_node_labeller    => 'labeller',
    deploy_amd_dra_driver       => 'dra',
    deploy_amd_metrics_exporter => 'metrics',
    remove_amd_device_plugin    => 'device_plugin',
    remove_amd_node_labeller    => 'labeller',
    remove_amd_dra_driver       => 'dra',
    remove_amd_metrics_exporter => 'metrics',
);
my @LIB_FNS = sort keys %FN_DS;

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my $rv;
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = $code->();
    }
    return ($rv, $out, $err);
}

# The scheduler's reading of the affinity, written here independently of
# OCP::Cmd::Apply::AMDGPU::selects so the two can be held against each other.
sub scheduler_selects {
    my ($affinity, $labels) = @_;
    my $terms = $affinity->{nodeAffinity}{requiredDuringSchedulingIgnoredDuringExecution}{nodeSelectorTerms};
    for my $t (@$terms) {
        my $all = 1;
        for my $e (@{ $t->{matchExpressions} }) {
            my $v = $labels->{ $e->{key} };
            my $member = defined $v && scalar grep { $_ eq $v } @{ $e->{values} };
            $all = 0 if $e->{operator} eq 'In'    && !$member;
            $all = 0 if $e->{operator} eq 'NotIn' &&  $member;
        }
        return 1 if $all;
    }
    return 0;
}

{
    package FakeList;
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}
{
    package FakeResponse;
    sub new     { my ($c, %a) = @_; bless { %a }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}
{
    # A cluster: Nodes (labels, allocatable), DaemonSets and ResourceSlices.
    package AmdApi;
    sub new {
        my ($c, %a) = @_;
        return bless { nodes => {}, ds => {}, slices => [], selectors => [], calls => [], %a }, $c;
    }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub node {
        my ($self, $name, %labels) = @_;
        $self->{nodes}{$name} = { metadata => { name => $name, labels => { %labels } },
                                  status   => { allocatable => {}, capacity => {} } };
        return $self;
    }
    # Every Node, whatever the selector: the step must check the value itself.
    sub list {
        my ($self, $kind, %a) = @_;
        die $self->{list_dies} if $self->{list_dies};
        push @{ $self->{selectors} }, $a{labelSelector};
        return FakeList->new([ map { $self->{nodes}{$_} } sort keys %{ $self->{nodes} } ]);
    }
    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : undef;
        my %a = @rest;
        $name //= $a{name};
        # A read that fails the way the test says: { "Kind/name" => error }.
        if (my $fail = $self->{get_fails}{"$kind/$name"}) { die $fail }
        if ($kind eq 'DaemonSet') { return $self->{ds}{$name} // die "404 DaemonSet/$name\n" }
        if ($kind eq 'Node')      { return $self->{nodes}{$name} // die "404 Node/$name\n" }
        if ($kind eq 'OCPNode') {
            return { status => { kubernetesNodeName => $self->{k8s_name}{$name} // $name } };
        }
        die "404 $kind/$name\n";
    }
    sub _request {
        my ($self, $method, $path) = @_;
        return FakeResponse->new(status => 404, content => '') unless $path =~ m{/resourceslices\z};
        return FakeResponse->new(status => $self->{slices_status}, content => 'slices refused')
            if $self->{slices_status};
        return FakeResponse->new(status => 200,
            content => JSON::PP::encode_json({ items => $self->{slices} }));
    }
}
{
    package FakeOcp;
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub load_file { YAML::XS::LoadFile("$_[1]") }
    sub dump_file { YAML::XS::DumpFile("$_[1]", $_[2]) }
}

# The library's effect on AmdApi: a deploy puts the DaemonSet there, rolled
# out on the nodes its affinity selects, and the plugin's GPUs in their
# allocatable (the DRA driver's as ResourceSlices); a remove takes it away.
sub fake_lib {
    my ($api) = @_;
    my %impl;
    for my $fn (@LIB_FNS) {
        my $c = $FN_DS{$fn};
        $impl{$fn} = sub {
            my (%o) = @_;
            push @{ $api->{calls} }, [ $fn, { %o } ];
            die "kubeconfig required\n" unless $o{kubeconfig};
            if ($fn =~ /^remove_/) {
                delete $api->{ds}{ $DS{$c} };
                $api->{slices} = [] if $c eq 'dra';
                return;
            }
            die "The cluster does not serve DeviceClass in resource.k8s.io/v1:"
              . " the AMD GPU DRA driver needs Kubernetes 1.34 or later; nothing deployed\n"
                if $c eq 'dra' && $api->{no_dra_v1};
            my @on = grep { main::scheduler_selects($o{affinity}, $_->{metadata}{labels}) }
                     values %{ $api->{nodes} };
            my $gen = ($api->{ds}{ $DS{$c} }{metadata}{generation} // 0) + 1;
            my $ready = $api->{pods_unready}{$c} ? 0 : scalar @on;
            # The DaemonSet that cannot be read once it is there.
            $api->{get_fails}{"DaemonSet/$DS{$c}"} = $api->{fail_after_deploy}{$c}
                if $api->{fail_after_deploy}{$c};
            $api->{ds}{ $DS{$c} } = {
                metadata => { name => $DS{$c}, generation => $gen },
                spec     => { affinity => $o{affinity} },
                status   => { observedGeneration => $gen, desiredNumberScheduled => scalar @on,
                              numberReady => $ready, updatedNumberScheduled => scalar @on },
            };
            for my $n (@on) {
                if ($c eq 'device_plugin') {
                    $n->{status}{capacity}{'amd.com/gpu'} = '1';
                    my $res = ($o{resource_naming} // 'single') eq 'mixed' ? 'amd.com/cpx_nps4' : 'amd.com/gpu';
                    $n->{status}{allocatable}{$res} = '1' unless $api->{no_allocatable};
                }
                if ($c eq 'dra' && !$api->{no_slices}) {
                    push @{ $api->{slices} }, { spec => { driver => 'gpu.amd.com', nodeName => $n->{metadata}{name} } };
                }
            }
            return;
        };
    }
    return %impl;
}

sub project {
    my ($gpu_yaml) = @_;
    my $dir = path(File::Temp::tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew(<<"YAML" . ($gpu_yaml // ''));
name: amdlab
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: otho.ocp.invalid
YAML
    $dir->child('.ocp')->mkpath;
    return $dir;
}

sub config_for {
    my ($dir, $gpu_yaml) = @_;
    $dir->child('ocp.yaml')->spew(<<"YAML" . ($gpu_yaml // ''));
name: amdlab
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: otho.ocp.invalid
YAML
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my $KC = File::Temp->new(SUFFIX => '.yaml');

sub new_apply {
    my ($api) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    $apply->{_k8s_api} = $api;
    $apply->{_kc_temp} = $KC;
    return $apply;
}

# One AMD GPU stack step against $api with the fake library; %o: gpu (the
# gpu: block of ocp.yaml), dir (the project, kept across runs), missing (lib
# functions this Rex::Rancher lacks), impl (functions replaced), apply.
sub run_step {
    my ($api, %o) = @_;
    my $dir    = $o{dir} // project();
    my $config = config_for($dir, $o{gpu});
    my $apply  = $o{apply} // new_apply($api);
    my %impl   = (fake_lib($api), %{ $o{impl} // {} });
    my $waited = 0;
    my ($r, $out, $err);
    {
        no strict 'refs';
        no warnings qw( redefine once );
        local (*Rex::Rancher::K8s::deploy_amd_device_plugin, *Rex::Rancher::K8s::deploy_amd_node_labeller,
               *Rex::Rancher::K8s::deploy_amd_dra_driver,    *Rex::Rancher::K8s::deploy_amd_metrics_exporter,
               *Rex::Rancher::K8s::remove_amd_device_plugin, *Rex::Rancher::K8s::remove_amd_node_labeller,
               *Rex::Rancher::K8s::remove_amd_dra_driver,    *Rex::Rancher::K8s::remove_amd_metrics_exporter);
        for my $fn (@LIB_FNS) {
            next if grep { $_ eq $fn } @{ $o{missing} // [] };
            *{"Rex::Rancher::K8s::$fn"} = $impl{$fn};
        }
        local *OCP::Cmd::Apply::wait_seconds = sub { $waited += $_[1] };
        ($r, $out, $err) = capture {
            $o{after_join}
                ? [ OCP::Cmd::Apply::AMDGPU::after_join($apply, $config, $o{after_join}) ]
                : OCP::Cmd::Apply::AMDGPU::step($apply, $config)
        };
    }
    my @calls = @{ $api->{calls} };
    $api->{calls} = [];
    return { r => $r, out => $out, err => $err, dir => $dir, apply => $apply, waited => $waited,
             calls => \@calls, fns => [ map { $_->[0] } @calls ],
             hashes => (-f $dir->child('.ocp/deployed.yaml')
                        ? YAML::XS::LoadFile($dir->child('.ocp/deployed.yaml')) : {}) };
}

sub call_opts { my ($res, $fn) = @_; my ($c) = grep { $_->[0] eq $fn } @{ $res->{calls} }; $c && $c->[1] }

sub exprs {
    my ($c, $default) = @_;
    return OCP::Cmd::Apply::AMDGPU::affinity($c, $default)
        ->{nodeAffinity}{requiredDuringSchedulingIgnoredDuringExecution}{nodeSelectorTerms}[0]{matchExpressions};
}

my $M = { key => $MARKER, operator => 'In', values => ['true'] };

subtest 'affinity: the marker, then the allocation term of the default' => sub {
    is_deeply exprs('device_plugin', 'device-plugin'),
        [ $M, { key => $ALLOC, operator => 'NotIn', values => [qw(dra none)] } ],
        'default device-plugin: the plugin NotIn [dra, none]';
    is_deeply exprs('dra', 'device-plugin'),
        [ $M, { key => $ALLOC, operator => 'In', values => ['dra'] } ],
        'default device-plugin: DRA In [dra]';
    is_deeply exprs('dra', 'dra'),
        [ $M, { key => $ALLOC, operator => 'NotIn', values => [qw(device-plugin none)] } ],
        'default dra: DRA NotIn [device-plugin, none]';
    is_deeply exprs('device_plugin', 'dra'),
        [ $M, { key => $ALLOC, operator => 'In', values => ['device-plugin'] } ],
        'default dra: the plugin In [device-plugin]';
    is_deeply exprs('device_plugin', 'none'),
        [ $M, { key => $ALLOC, operator => 'In', values => ['device-plugin'] } ],
        'default none: the plugin only on an explicit device-plugin';
    is_deeply exprs('dra', 'none'),
        [ $M, { key => $ALLOC, operator => 'In', values => ['dra'] } ],
        'default none: DRA only on an explicit dra';
    for my $default (qw(device-plugin dra none)) {
        is_deeply exprs($_, $default), [ $M ], "$_ with default $default: the marker only"
            for qw(labeller metrics);
    }
};

subtest 'affinity matrix: every default against every override label' => sub {
    # default => { label value (undef: no label) => component, '' for neither }
    my %want = (
        'device-plugin' => { none_label => 'device_plugin', 'device-plugin' => 'device_plugin',
                             dra => 'dra', none => '', bogus => 'device_plugin' },
        'dra'           => { none_label => 'dra', 'device-plugin' => 'device_plugin',
                             dra => 'dra', none => '', bogus => 'dra' },
        'none'          => { none_label => '', 'device-plugin' => 'device_plugin',
                             dra => 'dra', none => '', bogus => '' },
    );
    for my $default (sort keys %want) {
        for my $value (sort keys %{ $want{$default} }) {
            my %labels = ($MARKER => 'true', ($value eq 'none_label' ? () : ($ALLOC => $value)));
            my @got = grep {
                my $aff = OCP::Cmd::Apply::AMDGPU::affinity($_, $default);
                my $mine = OCP::Cmd::Apply::AMDGPU::selects($aff, \%labels);
                is $mine, scheduler_selects($aff, \%labels),
                    "selects() reads $_ like the scheduler (default $default, label $value)";
                $mine;
            } qw(device_plugin dra);
            is join(',', @got), $want{$default}{$value},
                "default $default, label " . ($value eq 'none_label' ? '(none)' : $value)
                . ": " . ($want{$default}{$value} || 'neither');
        }
    }
    ok !OCP::Cmd::Apply::AMDGPU::selects(OCP::Cmd::Apply::AMDGPU::affinity('labeller', 'device-plugin'), {}),
        'no marker, no labeller';
};

subtest 'trigger: no marker node -- nothing deployed, said as skipped' => sub {
    my $api = AmdApi->new;
    $api->node('cpu1');
    $api->node('nfd-only', 'feature.node.kubernetes.io/pci-0300_1002.present' => 'true');
    $api->node('off', $MARKER => 'false');
    my $res = run_step($api);
    is_deeply $res->{fns}, [], 'no library call';
    is_deeply $api->{selectors}, ["$MARKER=true"], 'the cluster was asked for the marker';
    like $res->{out}, qr/No AMD GPU nodes \(no node carries \Q$MARKER\E=true\)/, 'the reason';
    like $res->{out}, qr/\[ok\] AMD GPU stack skipped/, 'the verdict';
    is_deeply $res->{r}{failed}, [], 'nothing failed';
    is $res->{r}{changed}, 0, 'nothing changed';
    is $res->{err}, '', 'nothing on STDERR';
};

subtest 'trigger: a marker node gets the plugin and the labeller, with the pins' => sub {
    my $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    $api->node('cpu1');
    my $res = run_step($api);
    is_deeply $res->{fns}, [qw(deploy_amd_device_plugin deploy_amd_node_labeller)],
        'the default allocation (device-plugin) and the labeller, nothing else';
    my $dp = call_opts($res, 'deploy_amd_device_plugin');
    is $dp->{kubeconfig}, $KC->filename, 'the kubeconfig file apply decrypted';
    is $dp->{version}, OCP::Versions->get_component_version('amd_device_plugin'), 'the plugin pin';
    is $dp->{resource_naming}, 'single', 'gpu.amd.resource_naming';
    is $dp->{wait}, 0, 'wait => 0: OCP waits by its own check';
    is $dp->{node_labeller}, 0, 'the labeller is its own component';
    is_deeply $dp->{affinity}, OCP::Cmd::Apply::AMDGPU::affinity('device_plugin', 'device-plugin'),
        'the affinity';
    is call_opts($res, 'deploy_amd_node_labeller')->{version},
        OCP::Versions->get_component_version('amd_device_plugin'), 'the labeller: the plugin release';
    like $res->{out}, qr/AMD GPU node\(s\): synapse \(device-plugin\)/, 'the node and its allocation';
    like $res->{out}, qr/\[ok\] AMD GPU device plugin deployed/, 'plugin reported';
    like $res->{out}, qr/\[ok\] AMD GPU node labeller deployed/, 'labeller reported';
    is $res->{r}{changed}, 2, 'two changes';
    ok $res->{hashes}{'amd-gpu-device-plugin'} && $res->{hashes}{'amd-gpu-node-labeller'},
        'both recorded in deployed.yaml';
    ok !exists $res->{hashes}{'amd-gpu-dra-driver'}, 'no DRA record';
    is $res->{err}, '', 'nothing on STDERR';
};

subtest 'gpu.enabled false: no node is asked for, nothing deployed' => sub {
    my $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    my $res = run_step($api, gpu => "gpu:\n  enabled: false\n");
    is_deeply $res->{fns}, [], 'no library call';
    is_deeply $api->{selectors}, [], 'no Node listed';
    like $res->{out}, qr/gpu\.enabled is false/, 'the reason';
};

subtest 're-apply with nothing changed does nothing; a vanished DaemonSet comes back' => sub {
    my $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    my $first = run_step($api);
    my $again = run_step($api, dir => $first->{dir});
    is_deeply $again->{fns}, [], 'no library call';
    like $again->{out}, qr/\[ok\] AMD GPU device plugin up to date/, 'plugin up to date';
    like $again->{out}, qr/\[ok\] AMD GPU node labeller up to date/, 'labeller up to date';
    is $again->{r}{changed}, 0, 'no change counted';
    is $again->{waited}, 0, 'no wait';

    delete $api->{ds}{ $DS{device_plugin} };
    my $back = run_step($api, dir => $first->{dir});
    is_deeply $back->{fns}, ['deploy_amd_device_plugin'], 'only the missing one is deployed';
    like $back->{out}, qr/\[ok\] AMD GPU device plugin redeployed \(was gone from the cluster\)/, 'restored';
};

subtest 'switches remove or redeploy exactly the affected component' => sub {
    my $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    my $base = run_step($api);
    my $dir  = $base->{dir};

    my $res = run_step($api, dir => $dir, gpu => "gpu:\n  amd:\n    labeller: false\n");
    is_deeply $res->{fns}, ['remove_amd_node_labeller'], 'labeller off: only the labeller is removed';
    like $res->{out}, qr/Removing AMD GPU node labeller \(gpu\.amd\.labeller is false\)/, 'with the reason';
    like $res->{out}, qr/\[ok\] AMD GPU node labeller removed/, 'reported';
    ok !exists $res->{hashes}{'amd-gpu-node-labeller'}, 'and its record dropped';
    ok !$api->{ds}{ $DS{labeller} }, 'gone from the cluster';
    is $res->{r}{changed}, 1, 'a removal is a change';

    $res = run_step($api, dir => $dir, gpu => "gpu:\n  amd:\n    labeller: false\n");
    is_deeply $res->{fns}, [], 'and stays removed without another call';

    $res = run_step($api, dir => $dir, gpu => "gpu:\n  amd:\n    labeller: false\n    resource_naming: mixed\n");
    is_deeply $res->{fns}, ['deploy_amd_device_plugin'], 'resource_naming: the plugin is redeployed';
    like $res->{out}, qr/\[ok\] AMD GPU device plugin updated/, 'as updated';
    is call_opts($res, 'deploy_amd_device_plugin')->{resource_naming}, 'mixed', 'with mixed';

    $res = run_step($api, dir => $dir, gpu => "gpu:\n  amd:\n    labeller: false\n    resource_naming: mixed\n    metrics: true\n");
    is_deeply $res->{fns}, ['deploy_amd_metrics_exporter'], 'metrics on: the exporter, nothing else';
    my $m = call_opts($res, 'deploy_amd_metrics_exporter');
    is $m->{version}, OCP::Versions->get_component_version('amd_metrics_exporter'), 'its pin';
    is_deeply $m->{affinity}, { nodeAffinity => { requiredDuringSchedulingIgnoredDuringExecution => {
        nodeSelectorTerms => [ { matchExpressions => [ $M ] } ] } } }, 'the marker only';
    ok !exists $m->{wait}, 'no wait option: the exporter has none';
    like $res->{out}, qr/\[ok\] AMD device metrics exporter deployed/, 'reported';

    $res = run_step($api, dir => $dir, gpu => "gpu:\n  amd:\n    labeller: false\n    resource_naming: mixed\n");
    is_deeply $res->{fns}, ['remove_amd_metrics_exporter'], 'metrics off again: removed';
    like $res->{out}, qr/gpu\.amd\.metrics is false/, 'with the reason';

    $res = run_step($api, dir => $dir, gpu => "gpu:\n  amd:\n    labeller: false\n    resource_naming: mixed\n    allocation: dra\n");
    is_deeply $res->{fns}, [qw(remove_amd_device_plugin deploy_amd_dra_driver)],
        'allocation dra: the plugin goes before the DRA driver comes';
    like $res->{out}, qr/no AMD GPU node has allocation device-plugin/, 'the plugin\'s reason';
    is_deeply call_opts($res, 'deploy_amd_dra_driver')->{affinity},
        OCP::Cmd::Apply::AMDGPU::affinity('dra', 'dra'), 'DRA with the dra default\'s NotIn';
    is call_opts($res, 'deploy_amd_dra_driver')->{version},
        OCP::Versions->get_component_version('amd_dra_driver'), 'the DRA pin';
    like $res->{out}, qr/\[ok\] AMD GPU DRA driver deployed/, 'reported';

    delete $api->{nodes}{synapse};
    $res = run_step($api, dir => $dir, gpu => "gpu:\n  amd:\n    allocation: dra\n");
    is_deeply $res->{fns}, ['remove_amd_dra_driver'], 'the last AMD node gone: the DRA driver goes';
    like $res->{out}, qr/no AMD GPU node left/, 'with the reason';
    is_deeply [ grep { /^amd-gpu-/ } keys %{ $res->{hashes} } ], [], 'no AMD record left';
};

subtest 'a node override next to the default: both, the narrow one first' => sub {
    my $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    $api->node('instinct', $MARKER => 'true', $ALLOC => 'dra');
    my $res = run_step($api, gpu => "gpu:\n  amd:\n    labeller: false\n");
    is_deeply $res->{fns}, [qw(deploy_amd_dra_driver deploy_amd_device_plugin)],
        'the In [dra] driver before the NotIn plugin';
    like $res->{out}, qr/instinct \(dra\), synapse \(device-plugin\)/, 'each node with its allocation';
    is $api->{ds}{ $DS{dra} }{status}{desiredNumberScheduled}, 1, 'DRA on one node';
    is $api->{ds}{ $DS{device_plugin} }{status}{desiredNumberScheduled}, 1, 'the plugin on the other';
};

subtest 'a DaemonSet OCP did not record is removed when nothing selects it' => sub {
    my $api = AmdApi->new;
    $api->{ds}{ $DS{labeller} } = { metadata => { name => $DS{labeller} } };
    my $res = run_step($api);
    is_deeply $res->{fns}, ['remove_amd_node_labeller'], 'present in the cluster: removed';
};

subtest 'allocation none and the labeller off: nothing to do' => sub {
    my $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    my $res = run_step($api, gpu => "gpu:\n  amd:\n    allocation: none\n    labeller: false\n");
    is_deeply $res->{fns}, [], 'no call';
    like $res->{out}, qr/synapse \(none\)/, 'the node is named with allocation none';
    like $res->{out}, qr/No AMD GPU node selects a component/, 'the reason';
};

subtest 'an allocation label that is no allocation: warned, the default applies' => sub {
    my $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true', $ALLOC => 'plugin');
    my $res = run_step($api, gpu => "gpu:\n  amd:\n    labeller: false\n");
    like $res->{err}, qr/\[WARN\] Node 'synapse': \Q$ALLOC\E=plugin is not device-plugin, dra, or none; the node gets gpu\.amd\.allocation \(device-plugin\)/,
        'said on STDERR';
    is_deeply $res->{fns}, ['deploy_amd_device_plugin'], 'and it gets the default\'s component';
};

subtest 'a Rex::Rancher without the functions: one WARN, no call, no failure' => sub {
    my $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    my $res = run_step($api, missing => ['deploy_amd_node_labeller']);
    is_deeply $res->{fns}, [], 'not even the functions it has: no half stack';
    my @warn = $res->{err} =~ /^.*\[WARN\].*$/mg;
    is scalar @warn, 1, 'one line';
    like $warn[0], qr/needs a newer Rex::Rancher: Rex::Rancher::K8s \S+ has no deploy_amd_node_labeller; nothing deployed or removed/,
        'that names the missing function';
    is_deeply $res->{r}{failed}, [], 'no failure';
    ok $res->{r}{warned}, 'but warned';
    like $res->{out}, qr/\[ok\] AMD GPU stack skipped/, 'the block closes';

    $res = run_step($api, missing => [ @LIB_FNS ]);
    like $res->{err}, qr/has no deploy_amd_device_plugin, deploy_amd_node_labeller;/,
        'none at all: every function this run needs is named';
};

subtest 'DRA on a cluster without resource.k8s.io/v1: a diagnosis on STDERR, a failure' => sub {
    my $api = AmdApi->new(no_dra_v1 => 1);
    $api->node('synapse', $MARKER => 'true');
    my $res = run_step($api, gpu => "gpu:\n  amd:\n    allocation: dra\n");
    like $res->{err}, qr/\[!!\] AMD GPU DRA driver setup failed: The cluster does not serve DeviceClass in resource\.k8s\.io\/v1/,
        'the library\'s reason';
    like $res->{err}, qr/allocation dra get no GPU until the cluster runs Kubernetes 1\.34 or later/,
        'what it means for the nodes';
    like $res->{err}, qr/device-plugin meanwhile/, 'and the way out';
    is_deeply $res->{r}{failed}, ['AMD GPU DRA driver'], 'counted as failed';
    ok !exists $res->{hashes}{'amd-gpu-dra-driver'}, 'not recorded';
    like $res->{out}, qr/\[ok\] AMD GPU node labeller deployed/, 'the labeller still went ahead';
    unlike $res->{out}, qr/\[ok\] AMD GPU DRA driver/, 'no [ok] for the driver';
};

subtest 'readiness: allocatable, not capacity; a ResourceSlice per DRA node' => sub {
    my $api = AmdApi->new(no_allocatable => 1);
    $api->node('synapse', $MARKER => 'true');
    my $res = run_step($api, gpu => "gpu:\n  amd:\n    labeller: false\n");
    is $res->{waited}, OCP::Cmd::Apply::AMDGPU::ready_timeout(), 'waited the whole budget';
    like $res->{err}, qr/AMD GPU device plugin setup failed: AMD GPU device plugin not ready after 300s: node 'synapse' shows no amd\.com\/gpu in status\.allocatable/,
        'capacity alone is not a GPU a pod can get';
    ok !exists $res->{hashes}{'amd-gpu-device-plugin'}, 'not recorded, so the next apply tries again';
    is_deeply $res->{r}{failed}, ['AMD GPU device plugin'], 'failed';

    $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    $res = run_step($api, gpu => "gpu:\n  amd:\n    labeller: false\n    resource_naming: mixed\n");
    is_deeply $res->{r}{failed}, [], 'mixed: a partitioned amd.com/ resource counts';

    $api = AmdApi->new(no_slices => 1);
    $api->node('synapse', $MARKER => 'true');
    $res = run_step($api, gpu => "gpu:\n  amd:\n    labeller: false\n    allocation: dra\n");
    like $res->{err}, qr/no ResourceSlice of driver gpu\.amd\.com for node 'synapse'/, 'DRA: no slice, not ready';

    $api = AmdApi->new(pods_unready => { labeller => 1 });
    $api->node('synapse', $MARKER => 'true');
    $res = run_step($api);
    like $res->{err}, qr/AMD GPU node labeller not ready after 300s: DaemonSet kube-system\/amdgpu-labeller-daemonset has 0 of 1 pod\(s\) ready/,
        'the DaemonSet\'s own ready count';
    like $res->{out}, qr/\[ok\] AMD GPU device plugin deployed/, 'the plugin is not held by it';
};

subtest 'a Node list that fails removes nothing' => sub {
    my $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    my $first = run_step($api);
    $api->{list_dies} = "503 apiserver unavailable\n";
    my $res = run_step($api, dir => $first->{dir});
    is_deeply $res->{fns}, [], 'no removal on a list nobody could read';
    like $res->{err}, qr/\[!!\] AMD GPU stack setup failed: 503 apiserver unavailable/, 'said';
    is_deeply $res->{r}{failed}, ['AMD GPU stack'], 'failed';
};

subtest 'after the worker join: once more for a joined AMD node, and only then' => sub {
    my $api = AmdApi->new;
    $api->node('cpu1');
    my $dir   = project();
    my $first = run_step($api, dir => $dir);
    is_deeply $first->{fns}, [], 'first check: no AMD node yet';

    $api->node('10-230-30-50', $MARKER => 'true');
    $api->{k8s_name} = { synapse => '10-230-30-50' };
    my $res = run_step($api, dir => $dir, apply => $first->{apply},
        after_join => [ { name => 'synapse', phase => 'Ready' }, { name => 'cpu2', phase => 'Failed' } ]);
    like $res->{out}, qr/Checking AMD GPU stack again, after the worker join \(10-230-30-50\)/, 'said, by Node name';
    is_deeply $res->{fns}, [qw(deploy_amd_device_plugin deploy_amd_node_labeller)], 'deployed for it';
    is_deeply $res->{r}, [], 'nothing failed';

    $res = run_step($api, dir => $dir, apply => $first->{apply},
        after_join => [ { name => 'cpu1', phase => 'Ready' } ]);
    is $res->{out}, '', 'a joined node without the marker: nothing';

    my $failed = new_apply($api);
    $failed->{_amd_gpu_step} = { failed => ['AMD GPU stack'], warned => 0 };
    $res = run_step($api, dir => $dir, apply => $failed,
        after_join => [ { name => 'synapse', phase => 'Ready' } ]);
    is $res->{out}, '', 'the first check failed: said there, not retried';

    $res = run_step($api, dir => $dir, apply => new_apply($api),
        after_join => [ { name => 'synapse', phase => 'Ready' } ]);
    is $res->{out}, '', 'the first check did not run: nothing';
};

#
# k269: only a 404 says a DaemonSet is not there. An RBAC denial or an
# apiserver 5xx says nothing about it, and used to read as absent all the
# same: a recorded component was redeployed as "restored", one the cluster
# might hold was never removed, and the readiness wait said "not found".
#

# What Kubernetes::REST dies with for an HTTP error status (as in t/25).
sub api_error {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(
        code    => $code,
        context => 'get',
        body    => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}),
    );
}
my @REFUSALS = ([403, 'Forbidden'], [500, 'InternalError']);

subtest 'k269: an unreadable DaemonSet of a component to remove: it fails, the others carry on' => sub {
    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        my $api = AmdApi->new;
        $api->node('synapse', $MARKER => 'true');
        # The DRA driver: no node selects it, no record -- the cluster decides.
        $api->{ds}{ $DS{dra} } = { metadata => { name => $DS{dra} } };
        $api->{get_fails}{"DaemonSet/$DS{dra}"} = api_error($code, $reason);
        my $res = run_step($api);
        is_deeply $res->{fns}, [qw(deploy_amd_device_plugin deploy_amd_node_labeller)],
            "$code: no removal, and the plugin and the labeller still deployed";
        like $res->{err}, qr{\[!!\] AMD GPU DRA driver setup failed: could not read DaemonSet kube-system/\Q$DS{dra}\E: Kubernetes API error \(get\): $code .*"reason":"$reason"},
            "$code: the failure, with its cause, on STDERR";
        is_deeply $res->{r}{failed}, ['AMD GPU DRA driver'], "$code: counted as failed";
        ok $api->{ds}{ $DS{dra} }, "$code: the DaemonSet is left in the cluster";
    }

    my $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    $api->{get_fails}{"DaemonSet/$DS{dra}"} = api_error(404, 'NotFound');
    my $res = run_step($api);
    is_deeply $res->{fns}, [qw(deploy_amd_device_plugin deploy_amd_node_labeller)], '404: nothing to remove';
    is_deeply $res->{r}{failed}, [], '404: no failure';
    is $res->{err}, '', '404: nothing on STDERR';

    $api = AmdApi->new;
    $api->{get_fails}{"DaemonSet/$DS{metrics}"} = api_error(403, 'Forbidden');
    $res = run_step($api);
    is_deeply $res->{fns}, [], 'no AMD node at all: no call';
    is_deeply $res->{r}{failed}, ['AMD device metrics exporter'], 'and the one it could not read failed';
    unlike $res->{out}, qr/AMD GPU stack skipped/, 'not called skipped: whether it is to remove is unknown';

    $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    $api->{get_fails}{"DaemonSet/$DS{dra}"} = api_error(403, 'Forbidden');
    $res = run_step($api, missing => ['deploy_amd_node_labeller']);
    is_deeply $res->{fns}, [], 'a Rex::Rancher without the functions: no call';
    ok $res->{r}{warned}, 'warned';
    is_deeply $res->{r}{failed}, ['AMD GPU DRA driver'], 'and the unreadable one failed all the same';
};

subtest 'k269: a recorded component whose DaemonSet cannot be read is not redeployed' => sub {
    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        my $api = AmdApi->new;
        $api->node('synapse', $MARKER => 'true');
        my $first = run_step($api);
        $api->{get_fails}{"DaemonSet/$DS{device_plugin}"} = api_error($code, $reason);
        my $res = run_step($api, dir => $first->{dir});
        is_deeply $res->{fns}, [], "$code: no deploy for a DaemonSet nobody could see";
        unlike $res->{out}, qr/device plugin (?:redeployed|updated)/, "$code: neither restored nor updated";
        like $res->{err}, qr{\[!!\] AMD GPU device plugin setup failed: could not read DaemonSet kube-system/\Q$DS{device_plugin}\E: Kubernetes API error \(get\): $code },
            "$code: the failure, with its cause";
        is_deeply $res->{r}{failed}, ['AMD GPU device plugin'], "$code: counted as failed";
        like $res->{out}, qr/\[ok\] AMD GPU node labeller up to date/, "$code: the labeller carries on";
        ok defined $res->{hashes}{'amd-gpu-device-plugin'}, "$code: the record stays";
    }
};

subtest 'k269: the readiness wait names a read it could not make, not "not found"' => sub {
    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        my $api = AmdApi->new(fail_after_deploy => { labeller => api_error($code, $reason) });
        $api->node('synapse', $MARKER => 'true');
        my $res = run_step($api);
        like $res->{err}, qr{AMD GPU node labeller not ready after 300s: could not read DaemonSet kube-system/\Q$DS{labeller}\E: Kubernetes API error \(get\): $code },
            "$code: DaemonSet -- what could not be read, and why";
        unlike $res->{err}, qr/not found/, "$code: DaemonSet -- not called not found";
        is $res->{waited}, OCP::Cmd::Apply::AMDGPU::ready_timeout(), "$code: read again for the whole budget";
        like $res->{out}, qr/\[ok\] AMD GPU device plugin deployed/, "$code: the plugin is not held by it";

        $api = AmdApi->new;
        $api->node('synapse', $MARKER => 'true');
        $api->{get_fails}{'Node/synapse'} = api_error($code, $reason);
        $res = run_step($api, gpu => "gpu:\n  amd:\n    labeller: false\n");
        like $res->{err}, qr{AMD GPU device plugin not ready after 300s: could not read Node 'synapse': Kubernetes API error \(get\): $code },
            "$code: Node -- not called a node without the GPU";

        $api = AmdApi->new(slices_status => $code);
        $api->node('synapse', $MARKER => 'true');
        $res = run_step($api, gpu => "gpu:\n  amd:\n    labeller: false\n    allocation: dra\n");
        like $res->{err}, qr{AMD GPU DRA driver not ready after 300s: could not read ResourceSlices: GET /apis/resource\.k8s\.io/v1/resourceslices failed: HTTP $code slices refused},
            "$code: ResourceSlices -- not called a node without a slice";
    }

    my $api = AmdApi->new(fail_after_deploy => { labeller => api_error(404, 'NotFound') });
    $api->node('synapse', $MARKER => 'true');
    my $res = run_step($api);
    like $res->{err}, qr{AMD GPU node labeller not ready after 300s: DaemonSet kube-system/\Q$DS{labeller}\E not found\n},
        '404: DaemonSet not found';

    $api = AmdApi->new;
    $api->node('synapse', $MARKER => 'true');
    $api->{get_fails}{'Node/synapse'} = api_error(404, 'NotFound');
    $res = run_step($api, gpu => "gpu:\n  amd:\n    labeller: false\n");
    like $res->{err}, qr{AMD GPU device plugin not ready after 300s: Node 'synapse' not found\n}, '404: Node not found';

    $api = AmdApi->new(slices_status => 404);
    $api->node('synapse', $MARKER => 'true');
    $res = run_step($api, gpu => "gpu:\n  amd:\n    labeller: false\n    allocation: dra\n");
    like $res->{err}, qr{AMD GPU DRA driver not ready after 300s: no ResourceSlice of driver gpu\.amd\.com for node 'synapse'},
        '404: no ResourceSlice';
};

subtest 'DeployedHash: forget drops a record, removed is a change' => sub {
    my $dir    = project();
    my $config = config_for($dir);
    my $apply  = new_apply(AmdApi->new);
    OCP::Cmd::Apply::DeployedHash::save($apply, $config, $_, 'h') for qw(a b);
    OCP::Cmd::Apply::DeployedHash::forget($apply, $config, 'a');
    is_deeply OCP::Cmd::Apply::DeployedHash::load($apply, $config), { b => 'h' }, 'only that one';
    my ($changed, $out) = capture { OCP::Cmd::Apply::DeployedHash::report_component($apply, 'X', 'removed') };
    is $changed, 1, 'counts';
    is $out, "  [ok] X removed (no longer selected)\n", 'its line';
};

subtest 'kubeconfig_path: the file api() wrote, or a clear death' => sub {
    is OCP::Cmd::Apply::K8s::kubeconfig_path({ _kc_temp => $KC }), $KC->filename, 'the temp file';
    eval { OCP::Cmd::Apply::K8s::kubeconfig_path({}) };
    like $@, qr/No kubeconfig file at hand/, 'without one';
};

subtest 'both apply paths run the step and the after-join check' => sub {
    for my $file ('lib/OCP/Cmd/Apply/Deploy.pm', 'lib/OCP/Cmd/Apply/Drift.pm') {
        my $src = path($file)->slurp;
        like $src, qr/Checking AMD GPU stack\.\.\.\\n";\s*\n\s*(?:my \$amd = |push \@\{ \$self->\{_failed_components\} \},\s*\@\{ )OCP::Cmd::Apply::AMDGPU::step\(\$self, \$config\)/,
            "$file: the step";
        like $src, qr/OCP::Cmd::Apply::AMDGPU::after_join\(\$self, \$config, \\\@results\)/,
            "$file: after the worker step";
    }
};

done_testing;

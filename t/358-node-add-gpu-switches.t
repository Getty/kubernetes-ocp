#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();

use lib 'lib';

#
# k358: `ocp node add` read only gpu.toolkit (k223) and gpu.amd.integrated
# (k253) off the OCPNodeProvider CR. robocop and `ocp apply`'s CLI path hand
# OCP::Node the whole set OCP::Provider->gpu_flags_from_cr returns (k31), so
# on a node node add joined without robocop
#   - gpu.enabled: false, the cluster kill switch, did not hold: detection ran;
#   - gpu.driver: operator did not hold: the host driver went on;
#   - gpu.amd.integrated: true opened the iGPU gate under gpu.enabled: false.
# k31 wired the robocop and apply paths and left node add out; k223 noted the
# gap and kept to its own field. Nothing in the history makes it a choice.
#
# This file holds node add's join to robocop's for the same OCPNode CR (as
# node add writes it) and the same provider CR: the same gpu flags handed to
# OCP::Node, the same GPU parameters in the install task. `ocp apply`'s CLI
# path is held to the same. And it pins what --gpu does on its own: spec.gpu
# true on the OCPNode, which has the install task detect the GPU and set up
# the node's integrated AMD GPU under an enabled cluster -- and gives way to
# gpu.enabled: false, as it does when robocop joins the node (k31: the kill
# switch wins over a per-node spec.gpu).
#

use OCP;
use OCP::Provider;
use OCP::Node;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Node::Add;
use OCP::Robocop::Controller;
use OCP::Config;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);

# The provider CR's spec.gpu, as `ocp apply` writes it (ensure_provider_cr),
# or none: a CR an older ocp wrote.
my %GPU = (
    'kill switch'        => { enabled => JSON::PP::false, driver => 'host', toolkit => JSON::PP::true,
                              amd => { integrated => JSON::PP::true } },
    'operator driver'    => { enabled => JSON::PP::true, driver => 'operator', toolkit => JSON::PP::false,
                              amd => { integrated => JSON::PP::false } },
    'integrated'         => { enabled => JSON::PP::true, driver => 'host', toolkit => JSON::PP::true,
                              amd => { integrated => JSON::PP::true } },
    'from before spec.gpu' => undef,
);

our $GPU_SPEC;
our $OCPNODE;

sub provider {
    return {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
        metadata   => { name => 'ssh-default', namespace => 'ocp-system' },
        spec       => { type => 'ssh', ($GPU_SPEC ? (gpu => $GPU_SPEC) : ()) },
    };
}

{
    package FakeApi;
    sub new  { bless {}, shift }
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }
    sub patch_status { 1 }
    sub patch { 1 }
    sub get {
        my ($self, $kind) = @_;
        return $main::OCPNODE   if $kind eq 'OCPNode';
        return main::provider() if $kind eq 'OCPNodeProvider';
        return undef;
    }
}
{
    package FakeNode;
    sub reconcile_until_ready { 1 }
    sub reconcile { 1 }
    sub phase { 'Ready' }
    sub name  { 'worker-9' }
    sub cr    { { status => {} } }
    sub lease_conflict { undef }
    sub host_key_mismatch { undef }
}
{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}
{
    package FakeSecrets;
    sub new             { bless {}, shift }
    sub read_kubeconfig { undef }
}
{
    package FakeAddConfig;
    sub new            { bless {}, shift }
    sub cluster_status { {} }
    sub distribution   { 'rke2' }
    sub pod_cidr       { '10.42.0.0/16' }
}
{
    package FakeProvider;
    sub new              { bless {}, shift }
    sub create_server    { { id => 'S1', ip => '1.2.3.4' } }
    sub wait_for_running { $_[1] }
}

sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: k358\ncontrol_planes:\n  provider: ssh\n  host: cp.example\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# The OCPNode CR a caller handed to OCP::Node->from_cr, and its deps.
sub from_cr_call (&) {
    my ($run) = @_;
    my @calls;
    no warnings 'redefine';
    local *OCP::Node::from_cr     = sub { my ($c, $cr, %d) = @_; push @calls, [ $cr, \%d ]; bless {}, 'FakeNode' };
    local *OCP::Provider::from_cr = sub { FakeProvider->new };
    local *OCP::SSH::new = sub { bless {}, $_[0] };
    local *OCP::SSH::run = sub { { stdout => "K10::token\n", stderr => '', exit => 0 } };
    my ($out, $err) = ('', '');
    {
        open my $ofh, '>', \$out or die;
        open my $efh, '>', \$err or die;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $run->();
    }
    return $calls[0];
}

my @GPU_DEPS = qw( gpu_enabled gpu_driver gpu_toolkit gpu_amd_integrated );

# The GPU parameters OCP::Node's install task gets for that CR and those deps,
# run through the real OCP::Node with the machine layers faked (as t/253).
{
    package FakeRex;
    our @calls;
    sub new      { bless {}, shift }
    sub run_task { my ($s, $task, %p) = @_; push @calls, [ $task, \%p ]; 1 }
}
{
    package FakeSSH;
    sub new          { bless {}, shift }
    sub wait_for_ssh { 1 }
}
{
    package Anything;
    sub new { bless {}, shift }
}

sub install_gpu_params {
    my ($call) = @_;
    my ($cr, $deps) = @$call;
    no warnings 'redefine', 'once';
    local *OCP::Versions::get_component_version = sub { 'v9.9.9' };
    local *OCP::K8s::patch_status = sub { return };
    @FakeRex::calls = ();
    my $node = OCP::Node->from_cr({
            %$cr,
            metadata => { %{ $cr->{metadata} }, resourceVersion => '1' },
            status   => { phase => 'Installing', publicIP => '1.2.3.4' },
        },
        k8s => Anything->new, provider => FakeProvider->new,
        ssh_key => 'KEY', server_url => 'https://cp:9345', join_token => 'TOKEN',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
        map { exists $deps->{$_} ? ($_ => $deps->{$_}) : () } @GPU_DEPS,
    );
    $node->_install_kubernetes;
    my $params = $FakeRex::calls[0][1] or return undef;
    return { map { exists $params->{$_} ? ($_ => $params->{$_}) : () }
             qw( gpu gpu_driver gpu_toolkit gpu_amd_integrated ) };
}

sub gpu_deps {
    my ($deps) = @_;
    return { map { exists $deps->{$_} ? ($_ => $deps->{$_}) : () } @GPU_DEPS };
}

# The three joins of one OCPNode, under the provider CR $GPU_SPEC names.
sub joins {
    my ($with_gpu) = @_;
    my $add = OCP::Cmd::Node::Add->new(k8s => FakeApi->new, name => 'worker-9',
                                       ($with_gpu ? (gpu => 1) : ()));
    my $cr = $add->_build_cr('ssh-default');
    local $OCPNODE = { %$cr, status => { phase => 'Pending' } };

    my %call;
    $call{'node add'} = from_cr_call {
        $add->_cli_reconcile($cr, FakeApi->new, FakeAddConfig->new, FakeSecrets->new);
    };
    $call{robocop} = from_cr_call {
        OCP::Robocop::Controller->new(
            ssh_key => 'K', server_url => 'U', join_token => 'T',
            distribution => 'rke2', pod_cidr => '10.42.0.0/16', kube => FakeApi->new,
        )->_on_node_event({ %$cr, metadata => { %{ $cr->{metadata} }, resourceVersion => '1' },
                            status => { phase => 'Pending' } });
    };
    $call{'ocp apply'} = from_cr_call {
        OCP::Cmd::Apply::CR::cli_reconcile_workers(
            OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]), FakeApi->new, project(),
            [ 'worker-9' ],
            { ssh_key_path => '/nonexistent', cp_ip => '1.2.3.4', secrets => FakeSecrets->new });
    };
    return \%call;
}

#
# 1. node add hands OCP::Node what robocop does, and the install task gets the
#    same GPU parameters -- with and without --gpu, for every provider CR.
#
for my $what (sort keys %GPU) {
    for my $with_gpu (0, 1) {
        my $label = "$what, " . ($with_gpu ? '--gpu' : 'no --gpu');
        subtest "same join as robocop: $label" => sub {
            local $GPU_SPEC = $GPU{$what};
            my $call = joins($with_gpu);
            ok $call->{$_}, "$_: a node was built" or return for sort keys %$call;

            my %want = OCP::Provider->gpu_flags_from_cr(provider());
            is_deeply gpu_deps($call->{'node add'}[1]), \%want,
                'node add hands OCP::Node every flag gpu_flags_from_cr reads off the provider CR';
            is_deeply gpu_deps($call->{'node add'}[1]), gpu_deps($call->{$_}[1]),
                "the same gpu flags as $_" for 'robocop', 'ocp apply';

            my $node_add = install_gpu_params($call->{'node add'});
            ok $node_add, 'node add: the install task ran' or return;
            is_deeply $node_add, install_gpu_params($call->{robocop}),
                'the install task\'s GPU parameters are robocop\'s for the same CRs';
        };
    }
}

#
# 2. What that means on the machine, and what --gpu does on its own.
#
my %EXPECT = (
    # gpu.enabled: false wins over everything: no detection, no iGPU --
    # --gpu included, as on a node robocop joins (k31).
    'kill switch, no --gpu'   => { gpu => 0, gpu_driver => 'host', gpu_toolkit => 1 },
    'kill switch, --gpu'      => { gpu => 0, gpu_driver => 'host', gpu_toolkit => 1 },
    # gpu.driver: operator reaches the host step; --gpu opts the node in,
    # its integrated AMD GPU with it.
    'operator driver, no --gpu' => { gpu_driver => 'operator', gpu_toolkit => 0 },
    'operator driver, --gpu'    => { gpu => 1, gpu_driver => 'operator', gpu_toolkit => 0,
                                     gpu_amd_integrated => 1 },
    'integrated, no --gpu'    => { gpu_driver => 'host', gpu_toolkit => 1, gpu_amd_integrated => 1 },
    'integrated, --gpu'       => { gpu => 1, gpu_driver => 'host', gpu_toolkit => 1, gpu_amd_integrated => 1 },
    # A provider CR from before spec.gpu: only --gpu speaks, the Rexfile's
    # defaults decide the rest.
    'from before spec.gpu, no --gpu' => {},
    'from before spec.gpu, --gpu'    => { gpu => 1, gpu_amd_integrated => 1 },
);

for my $what (sort keys %GPU) {
    for my $with_gpu (0, 1) {
        my $label = "$what, " . ($with_gpu ? '--gpu' : 'no --gpu');
        subtest "node add's install task: $label" => sub {
            local $GPU_SPEC = $GPU{$what};
            my $call = joins($with_gpu)->{'node add'};
            ok $call, 'a node was built' or return;
            my $spec_gpu = $call->[0]{spec}{gpu};
            if ($with_gpu) {
                ok JSON::PP::is_bool($spec_gpu) && $spec_gpu, '--gpu: spec.gpu true on the OCPNode, a JSON boolean';
            } else {
                ok !exists $call->[0]{spec}{gpu}, 'no --gpu: no spec.gpu on the OCPNode';
            }
            is_deeply install_gpu_params($call), $EXPECT{$label}, 'the GPU parameters of the install task';
        };
    }
}

done_testing;

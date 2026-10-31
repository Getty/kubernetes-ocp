#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();

use lib 'lib';

#
# k250: integrated AMD GPUs are opt-in. Rex::GPU marks the iGPU of a Ryzen CPU
# or APU `integrated => 1`, and detection runs on every node -- control planes
# included, and a Hetzner AX42 control plane has a Phoenix iGPU (gfx1103) no
# one asked OCP to drive or offer as amd.com/gpu. So the Rexfile hands an
# integrated AMD GPU on only when its gpu_amd_integrated parameter is true.
#
# OCP::Node decides that parameter for a join. A node joined as a GPU node on
# purpose (`ocp node add --gpu`, spec.gpu true) is consent for its iGPU; so is
# gpu.amd.integrated for every node, as the gpu_amd_integrated attribute (read
# off the OCPNodeProvider CR since k253, t/253). The two are OR-ed.
# Neither, or a node with no GPU detection at all, passes nothing: the
# Rexfile's default (0) decides. What the Rexfile does with it is k249's.
#

use OCP::Node;

{
    package FakeRex;
    our @calls;
    sub new      { bless {}, shift }
    sub run_task { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 }
}
{
    package FakeSSH;
    sub new          { bless {}, shift }
    sub wait_for_ssh { 1 }
}
{
    package FakeProvider;
    sub new              { bless {}, shift }
    sub create_server    { { id => 'S1', ip => '1.2.3.4' } }
    sub wait_for_running { $_[1] }
}
{
    package Anything;
    sub new { bless {}, shift }
}

# The install task's params for a worker whose OCPNode spec carries
# $spec_gpu (undef: no spec.gpu at all), built with the attributes in %attr.
sub install_params {
    my ($spec_gpu, %attr) = @_;
    no warnings 'redefine', 'once';
    local *OCP::Versions::get_component_version = sub { 'v9.9.9' };
    local *OCP::K8s::patch_status = sub { return };
    @FakeRex::calls = ();
    my $node = OCP::Node->from_cr({
            apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => 'w1', namespace => 'ocp-system', resourceVersion => '1' },
            spec     => { role => 'worker', providerRef => 'ssh-default',
                          (defined $spec_gpu ? (gpu => $spec_gpu) : ()) },
            status   => { phase => 'Installing', publicIP => '1.2.3.4' },
        },
        k8s => Anything->new, provider => FakeProvider->new,
        ssh_key => 'KEY', server_url => 'https://cp:9345', join_token => 'TOKEN',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
        %attr,
    );
    $node->_install_kubernetes;
    return $FakeRex::calls[0][1];
}

subtest 'ocp node add --gpu opens the integrated gate for that node' => sub {
    my $p = install_params(JSON::PP::true);
    ok $p, 'the install task ran' or return;
    is $p->{gpu}, 1, 'the node is a GPU node';
    is $p->{gpu_amd_integrated}, 1, 'and its iGPU may be set up: --gpu is consent';
};

subtest 'nobody asked: nothing passed, the Rexfile default (0) decides' => sub {
    my $p = install_params(undef);
    ok $p, 'the install task ran' or return;
    ok !exists $p->{gpu_amd_integrated}, 'no spec.gpu, no cluster switch: not passed';

    $p = install_params(undef, gpu_amd_integrated => 0);
    ok !exists $p->{gpu_amd_integrated}, 'the cluster switch off: not passed either';

    $p = install_params(JSON::PP::false);
    ok !exists $p->{gpu_amd_integrated}, 'spec.gpu false: not passed';
    is $p->{gpu}, 0, '(that node runs no GPU detection at all)';
};

subtest 'gpu.amd.integrated opens it for every node' => sub {
    my $p = install_params(undef, gpu_amd_integrated => 1);
    ok $p, 'the install task ran' or return;
    is $p->{gpu_amd_integrated}, 1, 'a node without --gpu gets it from the cluster switch';
    ok !exists $p->{gpu}, 'and the gpu flag is left to its default as before';

    $p = install_params(JSON::PP::true, gpu_amd_integrated => 1);
    is $p->{gpu_amd_integrated}, 1, 'both saying yes is still 1';

    $p = install_params(JSON::PP::true, gpu_amd_integrated => 0);
    is $p->{gpu_amd_integrated}, 1, 'the cluster switch off does not take back a node\'s --gpu';
};

subtest 'no detection at all wins' => sub {
    my $p = install_params(JSON::PP::true, gpu_enabled => 0);
    ok $p, 'the install task ran' or return;
    is $p->{gpu}, 0, 'gpu.enabled: false is the kill switch, --gpu or not';
    ok !exists $p->{gpu_amd_integrated}, 'and the integrated gate is not passed under it';

    $p = install_params(undef, gpu_enabled => 0, gpu_amd_integrated => 1);
    ok !exists $p->{gpu_amd_integrated}, 'nor from the cluster switch';

    $p = install_params(JSON::PP::false, gpu_amd_integrated => 1);
    ok !exists $p->{gpu_amd_integrated}, 'nor on a node that opted out with spec.gpu false';
};

done_testing;

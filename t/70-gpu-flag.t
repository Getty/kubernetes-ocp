#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();

use lib 'lib';

#
# spec.gpu was set on the OCPNode CR by `ocp node add --gpu` (a JSON boolean
# after karr #50) and never read anywhere. OCP::Rex has had a `gpu` parameter
# since gpu_enabled was wired through (#13): install_agent / install_server
# read it, _maybe_detect_gpu in the Rexfile honours it, and Apply/Bootstrap
# passes it from OCP::Config. OCP::Node->_install_kubernetes is the seam that
# nobody closed -- it builds its own little %params for run_task and omits the
# field, so the flag written on the CR was, and is, decoration.
#
# These tests assert exactly that seam. FakeRex records every run_task call
# with its arguments, so the test asks what was passed to install_rke2_agent
# (or install_k3s_agent) for the worker spec.gpu=true case.
#
# The behaviour the ticket asks for is "spec.gpu wird gelesen": if the CR sets
# the flag, the Rex call carries gpu => 1; if the CR clears it, the Rex call
# carries gpu => 0. Both are new -- today neither key is in the params at all,
# because OCP::Node never puts it there.
#
# gpu_driver is intentionally NOT threaded here. The CRD declares spec.gpu as
# a bare boolean (no spec.gpu.driver field), and the only knob for gpu_driver
# today is ocp.yaml gpu.driver, which OCP::Node has no view of. The per-node
# driver question is what karr #31 will answer for the robocop side; here we
# keep the seam narrow and leave OCP::Rex's default ('host') in charge.
#

package FakeProvider {
    sub new            { my ($c, %a) = @_; bless {%a}, $c }
    sub create_server  { { id => 'S1', ip => '1.2.3.4' } }
    sub delete_server  { 1 }
    sub wait_for_running { $_[1]{ip} = '9.9.9.9'; return $_[1] }
}

package FakeSSH {
    sub new          { my ($c, %a) = @_; bless { %a }, $c }
    sub wait_for_ssh { 1 }
}

package FakeRex {
    our @_instances;
    sub new { my ($c, %a) = @_; my $s = bless { %a, calls => [] }, $c; push @_instances, $s; $s }
    sub run_task {
        my ($s, $task, %p) = @_;
        push @{$s->{calls}}, [$task, \%p];
        return 1;
    }
}

# Just enough of a k8s object to satisfy `k8s => required`; _install_kubernetes
# never reaches the API in this test (OCP::K8s->patch_status is stubbed).
package _Anything { sub new { bless {}, shift } }

sub ocpnode {
    my (%over) = @_;
    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => 'gpu-w1', namespace => 'ocp-system',
                        resourceVersion => '100' },
        spec       => { role => 'worker', providerRef => 'ssh-default' },
        status     => { phase => 'Installing', publicIP => '1.2.3.4' },
        %over,
    };
}

# All assertions go through one entry point, so the OCP::Node load happens
# once. The binding run is `make test` in the Docker image; here on the host
# we are not testing OCP::Versions or OCP.pm, so we stub them out. The chain
# OCP::Node -> OCP::K8s/Rex/SSH/TempKeyPair/Versions does not load OCP.pm at
# compile time -- only OCP::Versions->_ocp_version does, lazily, when
# get_component_version is called from _install_kubernetes. Stub that and
# _patch_status, and the install path reaches run_task on the host without
# MooX::Singleton ever being asked for.
sub load_ocp_node {
    return 1 if $OCP::Node::LOADED;
    eval {
        require OCP::Versions;
        require OCP::Node;
        require OCP::Rex;
        require OCP::SSH;
        require OCP::TempKeyPair;
        1;
    } or do {
        plan skip_all => "load chain incomplete on this host: $@";
        return 0;
    };
    no warnings 'redefine', 'once';
    *OCP::Versions::get_component_version = sub { 'v9.9.9' };
    *OCP::K8s::patch_status               = sub { return; };
    $OCP::Node::LOADED = 1;
    return 1;
}

sub installing_node_call {
    my (%over) = @_;
    load_ocp_node() or return;
    @FakeRex::_instances = ();
    my $cr = ocpnode(%over);

    my $node = OCP::Node->from_cr($cr,
        k8s        => _Anything->new,
        provider   => FakeProvider->new,
        ssh_key    => 'KEY',
        server_url => 'https://cp:9345',
        join_token => 'TOKEN',
        ssh_class  => 'FakeSSH',
        rex_class  => 'FakeRex',
        ($over{distribution} ? (distribution => $over{distribution}) : ()),
    );
    $node->_install_kubernetes;
    return $FakeRex::_instances[0]{calls}[0];
}

subtest 'spec.gpu=true is forwarded as gpu=1 to install_rke2_agent' => sub {
    # The point of the ticket: `ocp node add --gpu` writes spec.gpu as a JSON
    # boolean into the CR (karr #50), and OCP::Node never reads it. Today this
    # test asserts the seam is closed.
    my $call = installing_node_call(spec => { gpu => JSON::PP->new->true });
    return unless $call;

    is $call->[0],     'install_rke2_agent', 'the agent install task is rke2';
    is $call->[1]{gpu}, 1,
        'spec.gpu=true reaches Rex as gpu=1, instead of being decoration';
};

subtest 'spec.gpu=false is forwarded as gpu=0' => sub {
    # The other half of the same seam: a CR that explicitly clears the flag.
    # Today the field is never read, so this case is currently indistinguishable
    # from spec.gpu=true or absent; the test pins the new behaviour.
    my $call = installing_node_call(spec => { gpu => JSON::PP->new->false });
    return unless $call;

    is $call->[0],     'install_rke2_agent', 'still the rke2 agent task';
    is $call->[1]{gpu}, 0,
        'spec.gpu=false reaches Rex as gpu=0 -- GPU work is skipped on the worker';
};

subtest 'absent spec.gpu is left out of the params (OCP::Rex default wins)' => sub {
    # `ocp node add` without --gpu produces no spec.gpu key on the CR. The
    # absent case keeps OCP::Rex's default ('do the GPU work' = // 1) -- which
    # is what every worker does today, the documented baseline. Threading the
    # flag through is what fixes the disconnected case; flipping the default
    # is a separate, wider decision (karr #31, robocop side).
    my $call = installing_node_call();
    return unless $call;

    ok !exists $call->[1]{gpu},
        'absent spec.gpu is left out, so OCP::Rex keeps its // 1 default';
};

subtest 'spec.gpu is also forwarded on the k3s path' => sub {
    # Same source of truth, different task name. The test would catch a future
    # fix that wired the flag into one task name and forgot the other.
    my $call = installing_node_call(
        spec         => { gpu => JSON::PP->new->true },
        distribution => 'k3s',
    );
    return unless $call;

    is $call->[0],     'install_k3s_agent', 'the agent install task is k3s';
    is $call->[1]{gpu}, 1, 'spec.gpu=true forwarded under k3s as well';
};

subtest 'gpu_driver is not pulled out of thin air' => sub {
    # The CRD declares spec.gpu as a bare boolean; gpu_driver lives only in
    # ocp.yaml. OCP::Node has no view of ocp.yaml, and inventing a default
    # here would silently change the behaviour of every worker. The right
    # place to plumb the project-wide driver through is the same %params list
    # we're touching here, once karr #31 lands the provider-CR shape that
    # robocop also needs.
    my $call = installing_node_call(spec => { gpu => JSON::PP->new->true });
    return unless $call;

    ok !exists $call->[1]{gpu_driver},
        'no gpu_driver in the params -- OCP::Rex keeps its host default for now';
};

done_testing;

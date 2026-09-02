#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();

use lib 'lib';

#
# k31 -- robocop-joined workers must honour the cluster-wide GPU switches.
#
# The per-node spec.gpu flag on the OCPNode CR is already threaded through
# (k70, t/70-gpu-flag.t): `ocp node add --gpu` writes it and
# OCP::Node::_install_kubernetes forwards it as gpu => 1/0. What k70 left open
# is everything robocop cannot see: robocop only watches the OCPNode /
# OCPNodeProvider CRs, never ocp.yaml, so the cluster-wide gpu.enabled /
# gpu.driver from ocp.yaml never reached a worker it joined -- and neither did
# gpu_driver at all, because the OCPNode CRD carries no spec.gpu.driver field.
#
# The channel is the OCPNodeProvider CR. `ocp apply` copies ocp.yaml's
# gpu.enabled / gpu.driver onto it (OCP::Cmd::Apply::CR::ensure_provider_cr),
# from_cr's two callers (OCP::Robocop::Controller and the CLI reconcile path)
# read them back with OCP::Provider->gpu_flags_from_cr, and hand them to
# OCP::Node as gpu_enabled / gpu_driver. This test pins both halves:
#
#   1. gpu_flags_from_cr normalises the provider-CR gpu block the way
#      OCP::Config normalises the same two ocp.yaml keys.
#   2. OCP::Node::_install_kubernetes turns those cluster-wide flags into the
#      gpu / gpu_driver params the Rexfile reads -- with gpu.enabled: false as
#      a cluster kill switch that overrides a per-node spec.gpu that says yes.
#
# FakeRex records every run_task call so the test can ask exactly what reached
# the worker install.
#

package FakeProvider {
    sub new              { my ($c, %a) = @_; bless {%a}, $c }
    sub create_server    { { id => 'S1', ip => '1.2.3.4' } }
    sub delete_server    { 1 }
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
# never reaches the API here (OCP::K8s->patch_status is stubbed).
package _Anything { sub new { bless {}, shift } }

sub ocpnode {
    my (%over) = @_;
    my $spec   = delete $over{spec}   || {};
    my $status = delete $over{status} || {};
    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => 'gpu-w1', namespace => 'ocp-system',
                        resourceVersion => '100' },
        spec       => { role => 'worker', providerRef => 'hetzner-default', %$spec },
        status     => { phase => 'Installing', publicIP => '1.2.3.4', %$status },
        %over,
    };
}

# Same host-run stubbing as t/70: the OCP::Node -> Versions/K8s/Rex/SSH chain
# does not need a cluster, only OCP::Versions->get_component_version (which
# lazily loads OCP.pm / MooX::Singleton) and OCP::K8s->patch_status. Stub both.
sub load_ocp_node {
    return 1 if $OCP::Node::LOADED;
    eval {
        require OCP::Versions;
        require OCP::Node;
        require OCP::Provider;
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

# Build an OCPNode, run its install, and hand back the first run_task call.
# gpu_enabled / gpu_driver are OCP::Node constructor attributes (the
# cluster-wide flags the caller passes), not CR fields -- pull them out of
# %over before building the CR, exactly as distribution is handled.
sub installing_node_call {
    my (%over) = @_;
    load_ocp_node() or return;
    @FakeRex::_instances = ();

    my $distribution = delete $over{distribution};
    my $gpu_enabled  = exists $over{gpu_enabled} ? delete $over{gpu_enabled} : undef;
    my $gpu_driver   = exists $over{gpu_driver}  ? delete $over{gpu_driver}  : undef;
    my $has_enabled  = exists $over{_has_enabled} ? delete $over{_has_enabled} : defined $gpu_enabled;
    my $has_driver   = exists $over{_has_driver}  ? delete $over{_has_driver}  : defined $gpu_driver;

    my $cr = ocpnode(%over);

    my $node = OCP::Node->from_cr($cr,
        k8s        => _Anything->new,
        provider   => FakeProvider->new,
        ssh_key    => 'KEY',
        server_url => 'https://cp:9345',
        join_token => 'TOKEN',
        ssh_class  => 'FakeSSH',
        rex_class  => 'FakeRex',
        ($distribution ? (distribution => $distribution) : ()),
        ($has_enabled  ? (gpu_enabled  => $gpu_enabled)  : ()),
        ($has_driver   ? (gpu_driver   => $gpu_driver)   : ()),
    );
    $node->_install_kubernetes;
    return $FakeRex::_instances[0]{calls}[0];
}

#
# 1. OCP::Provider->gpu_flags_from_cr -- the parse.
#
subtest 'gpu_flags_from_cr normalises the provider-CR gpu block' => sub {
    load_ocp_node() or return;

    my %off = OCP::Provider->gpu_flags_from_cr(
        { spec => { type => 'hetzner', gpu => { enabled => JSON::PP::false, driver => 'host' } } });
    is $off{gpu_enabled}, 0, 'enabled:false -> gpu_enabled 0';
    is $off{gpu_driver}, 'host', 'driver:host passes through';

    my %on = OCP::Provider->gpu_flags_from_cr(
        { spec => { gpu => { enabled => JSON::PP::true, driver => 'operator' } } });
    is $on{gpu_enabled}, 1, 'enabled:true -> gpu_enabled 1';
    is $on{gpu_driver}, 'operator', 'driver:operator passes through';

    my %none = OCP::Provider->gpu_flags_from_cr({ spec => { type => 'ssh' } });
    ok !exists $none{gpu_enabled}, 'absent gpu block -> no gpu_enabled key';
    ok !exists $none{gpu_driver},  'absent gpu block -> no gpu_driver key';
};

#
# 2. OCP::Node turns the cluster-wide flags into Rex params.
#
subtest 'cluster gpu.enabled:false forces gpu=0 even when spec.gpu=true' => sub {
    # The whole point of the ticket: a worker robocop joins on a cluster
    # configured gpu.enabled: false must NOT run GPU detection, even if its own
    # OCPNode carries spec.gpu=true. The cluster kill switch wins.
    my $call = installing_node_call(
        spec        => { gpu => JSON::PP::true },
        gpu_enabled => 0,
    );
    return unless $call;
    is $call->[1]{gpu}, 0,
        'cluster gpu.enabled:false overrides a per-node spec.gpu=true';
};

subtest 'gpu_driver reaches the worker install' => sub {
    # gpu_driver lives only in ocp.yaml (there is no spec.gpu.driver on the
    # OCPNode CRD); it now reaches robocop-joined workers via the provider CR.
    my $call = installing_node_call(
        spec        => { gpu => JSON::PP::true },
        gpu_enabled => 1,
        gpu_driver  => 'operator',
    );
    return unless $call;
    is $call->[1]{gpu}, 1, 'gpu.enabled:true keeps the node doing GPU work';
    is $call->[1]{gpu_driver}, 'operator',
        'cluster gpu.driver:operator reaches Rex -- host driver install skipped';
};

subtest 'per-node spec.gpu=false still opts a node out under an enabled cluster' => sub {
    my $call = installing_node_call(
        spec        => { gpu => JSON::PP::false },
        gpu_enabled => 1,
    );
    return unless $call;
    is $call->[1]{gpu}, 0,
        'spec.gpu=false wins for this node while the cluster stays gpu-enabled';
};

subtest 'no cluster flags -> nothing added, OCP::Rex defaults win (baseline)' => sub {
    # A provider CR that predates the field passes neither flag. OCP::Node must
    # then behave exactly as before k31: spec.gpu still forwarded (k70), but no
    # gpu_driver invented and no cluster kill switch applied.
    my $call = installing_node_call(spec => { gpu => JSON::PP::true });
    return unless $call;
    is $call->[1]{gpu}, 1, 'per-node spec.gpu still forwarded (k70 untouched)';
    ok !exists $call->[1]{gpu_driver},
        'no gpu_driver without a cluster flag -- OCP::Rex keeps its host default';
};

subtest 'full chain: gpu_flags_from_cr feeds OCP::Node' => sub {
    load_ocp_node() or return;
    my $provider_cr = {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNodeProvider',
        metadata   => { name => 'hetzner-default', namespace => 'ocp-system' },
        spec       => {
            type => 'hetzner',
            gpu  => { enabled => JSON::PP::false, driver => 'host' },
        },
    };
    my %flags = OCP::Provider->gpu_flags_from_cr($provider_cr);
    my $call = installing_node_call(
        spec        => { gpu => JSON::PP::true },
        _has_enabled => 1,
        _has_driver  => 1,
        gpu_enabled => $flags{gpu_enabled},
        gpu_driver  => $flags{gpu_driver},
    );
    return unless $call;
    is $call->[1]{gpu}, 0,
        'enabled:false read off the provider CR reaches the worker as gpu=0';
    is $call->[1]{gpu_driver}, 'host',
        'driver read off the provider CR reaches the worker as gpu_driver';
};

done_testing;

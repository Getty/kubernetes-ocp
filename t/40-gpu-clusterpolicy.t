#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use YAML::XS ();

use OCP::Cmd::Apply;
use OCP::Versions;

#
# Every image in the ClusterPolicy is pinned by hand, and the GPU Operator
# resolves each one from repository/image/version in the CR — it has no
# catalogue to fall back on (imagePath() in clusterpolicy_types.go errors out
# when the CR carries no path and the operator Deployment sets no *_IMAGE env,
# which OCP's hand-rolled Deployment does not). A pin that does not exist is
# therefore not a warning, it is a DaemonSet that never starts.
#
# That is how v26.3.3 of the retired nvcr.io/nvidia/cloud-native/
# gpu-operator-validator shipped: five DaemonSets in Init:ImagePullBackOff on
# a real cluster, because the validator is the init container of all of them.
# The image moved into the operator image itself in v25.10.
#

{
    package FakeOCP;
    sub new  { bless {}, shift }
    sub dump { my ($self, @r) = @_; return join '', map { YAML::XS::Dump($_) } @r }
}

{
    package FakeConfig;
    sub new {
        my ($class, %arg) = @_;
        $arg{gpu_driver}  //= 'host';
        $arg{gpu_toolkit} //= 1;
        bless {%arg}, $class;
    }
    sub distribution { $_[0]->{distribution} }
    sub gpu_driver   { $_[0]->{gpu_driver} }
    sub gpu_toolkit  { $_[0]->{gpu_toolkit} }
}

{
    package FakeApply;
    sub new { bless { ocp => FakeOCP->new }, shift }
    sub ocp { $_[0]->{ocp} }
}

sub cluster_policy_for {
    my ($distribution, %gpu) = @_;

    my $yaml = OCP::Cmd::Apply::_generate_gpu_operator_manifest(
        FakeApply->new,
        FakeConfig->new(distribution => $distribution, %gpu),
    );

    my @docs = YAML::XS::Load($yaml);
    my ($policy) = grep { ($_->{kind} // '') eq 'ClusterPolicy' } @docs;

    return ($policy, $yaml);
}

my $gpu_version = OCP::Versions->get_component_version('gpu_operator');

subtest 'the manifest survives the round trip it is applied through' => sub {
    my ($policy, $yaml) = cluster_policy_for('k3s');

    ok $policy, 'a ClusterPolicy comes out of YAML::XS::Load';
    is $policy->{apiVersion}, 'nvidia.com/v1', 'the CRD group the operator watches';
};

subtest 'the validator runs the operator image' => sub {
    my ($policy) = cluster_policy_for('k3s');
    my $validator = $policy->{spec}{validator};

    is $validator->{repository}, 'nvcr.io/nvidia',
        'not cloud-native, where the validator repo stops at v25.3.4';
    is $validator->{image}, 'gpu-operator',
        'the operator image carries /usr/bin/nvidia-validator since v25.10';
    is $validator->{version}, $gpu_version,
        'tagged with the operator version, as upstream values.yaml has it';
};

subtest 'the retired validator repo is gone from the whole manifest' => sub {
    for my $distribution (qw(k3s rke2)) {
        my (undef, $yaml) = cluster_policy_for($distribution);
        unlike $yaml, qr/gpu-operator-validator/,
            "$distribution: nothing pulls nvcr.io/nvidia/cloud-native/gpu-operator-validator";
    }
};

#
# An enabled component with an incomplete image path is the same failure in a
# different costume: the operator cannot build a reference and the operand
# never comes up.
#

subtest 'every enabled component names a full image' => sub {
    my ($policy) = cluster_policy_for('rke2');
    my $spec = $policy->{spec};

    for my $component (sort keys %$spec) {
        my $c = $spec->{$component};
        next unless ref $c eq 'HASH';
        next unless exists $c->{repository} || exists $c->{image};
        next unless $c->{enabled};

        ok $c->{repository}, "$component has a repository";
        ok $c->{image},      "$component has an image";
        ok $c->{version},    "$component has a version";
    }
};

subtest 'the pins come from the version manifest' => sub {
    my ($policy) = cluster_policy_for('k3s');
    my $spec = $policy->{spec};

    is $spec->{toolkit}{version},
        OCP::Versions->get_component_version('nvidia_toolkit'), 'toolkit';
    is $spec->{devicePlugin}{version},
        OCP::Versions->get_component_version('nvidia_device_plugin'), 'device plugin';
    is $spec->{dcgmExporter}{version},
        OCP::Versions->get_component_version('dcgm_exporter'), 'dcgm exporter';
    is $spec->{dcgm}{version},
        OCP::Versions->get_component_version('nvidia_dcgm'), 'dcgm';

    is(OCP::Versions->get_component_version('nvidia_validator'), undef,
        'no separate validator pin to drift away from the operator version');
};

#
# gpu.driver and gpu.toolkit used to be config keys nothing read: the
# ClusterPolicy hardcoded driver.enabled=false and toolkit.enabled=true, so a
# spec asking for the operator-managed driver got the host one anyway, and a
# DGX — where the vendor image already carries toolkit and runtime — got the
# toolkit DaemonSet rewriting a containerd config that already worked.
#

subtest 'gpu.driver decides which side installs the driver' => sub {
    my ($host) = cluster_policy_for('k3s', gpu_driver => 'host');
    ok !$host->{spec}{driver}{enabled},
        "host mode leaves the operator's driver DaemonSet off — Rex owns the host driver";

    my ($operator) = cluster_policy_for('k3s', gpu_driver => 'operator');
    ok $operator->{spec}{driver}{enabled},
        'operator mode turns it on';

    # The lesson from the validator pin: an enabled component with no image
    # path is a DaemonSet that never starts, because OCPs hand-rolled operator
    # Deployment sets none of the *_IMAGE env the Helm chart does.
    is $operator->{spec}{driver}{repository}, 'nvcr.io/nvidia', 'and names a repository';
    is $operator->{spec}{driver}{image},      'driver',         'and an image';
    is $operator->{spec}{driver}{version},
        OCP::Versions->get_component_version('nvidia_driver'),
        'pinned from the version manifest, not inline';
};

subtest 'gpu.toolkit can be turned off for hosts that already have one' => sub {
    my ($on) = cluster_policy_for('k3s');
    ok $on->{spec}{toolkit}{enabled}, 'on by default — a plain host has no NVIDIA runtime';

    my ($off) = cluster_policy_for('k3s', gpu_toolkit => 0);
    ok !$off->{spec}{toolkit}{enabled},
        'off when the spec says so — NVIDIA guidance for DGX hosts is '
      . 'toolkit.enabled=false next to driver.enabled=false';
};

subtest 'the driver is never installed twice' => sub {
    for my $driver (qw(host operator)) {
        my ($policy) = cluster_policy_for('rke2', gpu_driver => $driver);
        my $by_operator = $policy->{spec}{driver}{enabled} ? 1 : 0;
        is $by_operator, ($driver eq 'operator' ? 1 : 0),
            "$driver: exactly one side of the driver install is active";
    }
};

#
# The toolkit env carries node paths, and the operator mounts the *directory*
# of each into the DaemonSet. A wrong directory that happens to exist is the
# worst case: the mount succeeds and the failure surfaces much later, when the
# toolkit tries to reach containerd through it.
#
# That is what /var/lib/rancher/rke2/agent/containerd/containerd.sock was — the
# containerd --root with a socket name appended. Measured on a live RKE2 node
# (v1.36.3+rke2r1): containerd runs with -a /run/k3s/containerd/containerd.sock
# and --root /var/lib/rancher/rke2/agent/containerd. RKE2 runs k3s' agent code,
# so the socket lives under /run/k3s on both distributions; only the config
# path is distribution-specific.
#

sub toolkit_env_for {
    my ($distribution) = @_;
    my ($policy) = cluster_policy_for($distribution);
    return { map { $_->{name} => $_->{value} } @{ $policy->{spec}{toolkit}{env} } };
}

subtest 'the containerd socket is the k3s one on both distributions' => sub {
    for my $distribution (qw(k3s rke2)) {
        my $env = toolkit_env_for($distribution);
        is $env->{CONTAINERD_SOCKET}, '/run/k3s/containerd/containerd.sock',
            "$distribution: RKE2 inherits k3s' agent, and its containerd socket with it";
    }

    my $rke2 = toolkit_env_for('rke2');
    unlike $rke2->{CONTAINERD_SOCKET}, qr{/var/lib/rancher/rke2/agent/containerd/},
        'not the containerd --root, which exists and so mounts before it fails';
    unlike $rke2->{CONTAINERD_SOCKET}, qr{^/var/run/},
        '/run, not the /var/run compatibility symlink onto it';
};

subtest 'the containerd config follows the distribution' => sub {
    is toolkit_env_for('k3s')->{CONTAINERD_CONFIG},
        '/var/lib/rancher/k3s/agent/etc/containerd/config.toml',
        'k3s keeps its agent state under its own name';

    is toolkit_env_for('rke2')->{CONTAINERD_CONFIG},
        '/var/lib/rancher/rke2/agent/etc/containerd/config.toml',
        'rke2 under its own — measured from the containerd -c argument on a node';

    is toolkit_env_for('nonsense-distribution')->{CONTAINERD_CONFIG},
        '/var/lib/rancher/rke2/agent/etc/containerd/config.toml',
        'an unrecognised dist falls back to rke2 instead of landing in the path';
};

#
# The absence of CONTAINERD_SET_AS_DEFAULT is an assertion, not an accident
# (karr #30). #23 decided that OCP does not make the nvidia runtime the node's
# default runtime, not even sideways — management pods reach it through
# RuntimeClass, every other container keeps runc. Setting the variable to 1 is
# exactly that sideways route.
#
# It is not merely obsolete upstream: nvidia-container-toolkit v1.19.1 still
# accepts it as a source for --set-as-default, behind NVIDIA_RUNTIME_SET_AS_DEFAULT
# in the same lookup chain (first source that is set wins). The operator sets
# that one to false as long as cdi.enabled is true, which is what made the value
# inert on cortex — crictl reported defaultRuntimeName runc while OCP was
# sending 1. So the variable is not dead, only outvoted, and what stands in the
# ClusterPolicy is what OCP is asking for: put it back and OCP asks for the
# opposite of the #23 decision, and gets it the day the operator stops shadowing
# it. That is why the assertion names the variable instead of only listing what
# is allowed.
#
# CONTAINERD_RUNTIME_CLASS goes with it for a duller reason: the operator
# overwrites it with operator.runtimeClass ("nvidia") before the DaemonSet is
# rendered, so it never said anything.
#

subtest 'the toolkit env is the operator input and nothing else' => sub {
    for my $distribution (qw(k3s rke2)) {
        my $env = toolkit_env_for($distribution);

        ok exists $env->{CONTAINERD_SOCKET},
            "$distribution: the socket stays — the operator derives RUNTIME_SOCKET "
          . 'and the sock-dir hostPath mount from it';
        ok exists $env->{CONTAINERD_CONFIG},
            "$distribution: the config stays — same for RUNTIME_CONFIG and config-dir";

        ok !exists $env->{CONTAINERD_SET_AS_DEFAULT},
            "$distribution: nvidia is never made the node's default runtime through "
          . 'the toolkit env (karr #30, decision from #23) — the toolkit still reads '
          . 'this variable, it is only outvoted while cdi.enabled is true';
        ok !exists $env->{CONTAINERD_RUNTIME_CLASS},
            "$distribution: the operator sets the runtime class itself";

        is_deeply [sort keys %$env], [qw(CONTAINERD_CONFIG CONTAINERD_SOCKET)],
            "$distribution: nothing else rides along — a new variable here is a "
          . 'decision about the node, so it has to be made in this test too';
    }
};

subtest 'the retired half of the 22.9 recipe is gone from the whole manifest' => sub {
    for my $distribution (qw(k3s rke2)) {
        my (undef, $yaml) = cluster_policy_for($distribution);
        unlike $yaml, qr/CONTAINERD_SET_AS_DEFAULT/,
            "$distribution: not smuggled back in through another component's env";
        unlike $yaml, qr/CONTAINERD_RUNTIME_CLASS/,
            "$distribution: likewise the runtime class";
    }
};

#
# cdi.enabled is the field the #23 decision rides on. The toolkit defaults
# --set-as-default to true, and the operator only writes
# NVIDIA_RUNTIME_SET_AS_DEFAULT=false ahead of it when config.CDI.IsEnabled()
# returns true. The CRD's kubebuilder default makes that true for nil, which is
# what kept runc as defaultRuntimeName on cortex — but OCP had no pin and no
# test for it. An operator release that flips the CRD default silently undoes
# #23 and makes nvidia the node's default runtime (karr #76). The field has to
# be present in the spec so OCP stops leaning on a default it does not own.
#

subtest 'cdi.enabled is set explicitly in the ClusterPolicy spec' => sub {
    for my $distribution (qw(k3s rke2)) {
        my ($policy) = cluster_policy_for($distribution);
        my $cdi = $policy->{spec}{cdi};
        ok ref $cdi eq 'HASH',
            "$distribution: cdi is a top-level spec section, not a stray field";
        ok exists $cdi->{enabled},
            "$distribution: cdi.enabled is present — the field the decision rides on";
        ok $cdi->{enabled},
            "$distribution: cdi.enabled is true — the operator only writes "
          . 'NVIDIA_RUNTIME_SET_AS_DEFAULT=false when IsEnabled() is true, and '
          . 'that is what keeps runc as defaultRuntimeName (karr #76, decision #23)';
    }
};

subtest 'the cdi decision does not ride on the CRD default in the rendered YAML' => sub {
    for my $distribution (qw(k3s rke2)) {
        my (undef, $yaml) = cluster_policy_for($distribution);
        like $yaml, qr/^\s+cdi:\s*\n\s+enabled:\s*true\s*$/m,
            "$distribution: cdi.enabled appears as a literal 'enabled: true' "
          . 'block in the rendered YAML, not omitted and not left to a CRD default';
    }
};

done_testing;

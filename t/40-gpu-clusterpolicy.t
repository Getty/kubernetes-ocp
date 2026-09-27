#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS ();
use JSON::PP ();
use Path::Tiny qw(path);
use Scalar::Util qw(looks_like_number);
use YAML::XS ();

use OCP::Cmd::Apply;
use OCP::Share;
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
    sub new       { bless {}, shift }
    sub dump      { my ($self, @r) = @_; return join '', map { YAML::XS::Dump($_) } @r }
    sub load_file { my ($self, $f) = @_; YAML::XS::LoadFile("$f") }
    sub dump_file { my ($self, $f, $d) = @_; YAML::XS::DumpFile("$f", $d) }
}

{
    package FakeConfig;
    sub new {
        my ($class, %arg) = @_;
        $arg{gpu_driver}  //= 'host';
        $arg{gpu_toolkit} //= 1;
        bless {%arg}, $class;
    }
    sub distribution  { $_[0]->{distribution} }
    sub gpu_driver    { $_[0]->{gpu_driver} }
    sub gpu_toolkit   { $_[0]->{gpu_toolkit} }
    # What setup_gpu_operator asks on top of the manifest generator.
    sub gpu_enabled   { 1 }
    sub deployed_file { $_[0]->{dir}->child('.ocp', 'deployed.yaml')->stringify }
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
        # A component without an enabled switch always runs: the validator
        # has none in NVIDIA's CRD, and it is the init container of the rest.
        next if exists $c->{enabled} && !$c->{enabled};

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
# (k30). k23 decided that OCP does not make the nvidia runtime the node's
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
# opposite of the k23 decision, and gets it the day the operator stops shadowing
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
          . 'the toolkit env (k30, decision from k23) — the toolkit still reads '
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
# cdi.enabled is the field the k23 decision rides on. The toolkit defaults
# --set-as-default to true, and the operator only writes
# NVIDIA_RUNTIME_SET_AS_DEFAULT=false ahead of it when config.CDI.IsEnabled()
# returns true. The CRD's kubebuilder default makes that true for nil, which is
# what kept runc as defaultRuntimeName on cortex — but OCP had no pin and no
# test for it. An operator release that flips the CRD default silently undoes
# k23 and makes nvidia the node's default runtime (k76). The field has to
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
          . 'that is what keeps runc as defaultRuntimeName (k76, decision k23)';
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

#
# The ClusterPolicy is only half of what setup_gpu_operator sends. The CRD the
# API server checks it against goes out right before it, from
# share/gpu-operator/crds — and for as long as that directory existed, the
# ClusterPolicy CRD in it was not NVIDIA's at all but a hand-written stub
# (ccb9e2f): one object per component, each with
# x-kubernetes-preserve-unknown-fields, and nothing else. Once OCP set
# cdi.enabled (k76), the stub did not name cdi, and the live test on
# 2026-09-27 (fresh RKE2, RTX 3090) ended in
#
#   [WARN] GPU Operator setup failed: apply ClusterPolicy/gpu-cluster-policy
#   failed: HTTP 500 ... failed to create typed patch object
#   (/gpu-cluster-policy; nvidia.com/v1, Kind=ClusterPolicy):
#   .spec.cdi: field not declared in schema
#
# with every test above green, because they read the ClusterPolicy and never
# the CRD. So the pair is checked here the way setup_gpu_operator sends it:
# the share directory resolved as the code resolves it, the files the code
# picks, parsed as apply_yaml_file parses them, encoded as Kubernetes::REST
# puts them on the wire.
#
# "Declared" means named in `properties`, or covered by a map's
# `additionalProperties`. x-kubernetes-preserve-unknown-fields does not count,
# although the API server stores such a field: stored is not read. The operator
# drops whatever its Go types do not have, so a misspelt `enable:` under a
# preserving object is accepted and does nothing — the stub let that class
# through for every component.
#

# Kubernetes::REST's own encoder (its _json attribute): what the PATCH body is.
my $WIRE = JSON::MaybeXS->new(utf8 => 1, canonical => 1, convert_blessed => 1);
sub on_the_wire { JSON::PP->new->utf8->decode($WIRE->encode($_[0])) }

# One node carrying the NFD label setup_gpu_operator looks for; nothing else on
# the cluster, so every step runs.
{
    package GpuNodeList;
    sub new   { bless {}, shift }
    sub items { [ bless {}, 'GpuNode' ] }
    package GpuNode;
    sub metadata { bless {}, 'GpuNodeMeta' }
    package GpuNodeMeta;
    sub name { 'crag' }
    package GpuClusterApi;
    sub new  { bless {}, shift }
    sub list { GpuNodeList->new }
    sub get  { die "404 not found\n" }
}

# Everything setup_gpu_operator hands to server-side apply, in order, after a
# test that it got to the end. Only the network is faked: the files are read
# and parsed by the code's own apply_yaml_file, which is how the first run
# against NVIDIA's real CRD found that it died on the file's two typographic
# apostrophes before a single byte went out (slurp_utf8 into YAML::XS::Load,
# "Wide character").
sub sent_by_setup {
    my (%gpu) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    my @sent;

    no warnings 'redefine';
    local *OCP::Cmd::Apply::K8s::server_side_apply = sub { push @sent, on_the_wire($_[2]); 1 };
    local *OCP::Cmd::Apply::_poll_deployment_ready = sub { 1 };
    local *OCP::Cmd::Apply::_crd_get = sub { { status => { state => 'ready' } } };
    local *OCP::Cmd::Apply::wait_seconds = sub { };

    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    $apply->{_k8s_api} = GpuClusterApi->new;

    my ($out, $outcome) = ('');
    my $ran = eval {
        open my $fh, '>', \$out or die $!;
        local *STDOUT = $fh;
        $outcome = $apply->_setup_gpu_operator(FakeConfig->new(dir => $dir, %gpu));
        1;
    };
    is $ran ? $outcome : "died: $@", 'deployed',
        setup_label(%gpu) . ': setup_gpu_operator gets through to the end';
    return @sent;
}

# The parts of a structural schema the API server holds an apply to: declared
# fields, required fields, types, enums and patterns. Returns one line per
# violation, named by its path.
sub schema_violations {
    my ($schema, $value, $where) = @_;
    my $type = $schema->{type} // '';
    my @found;

    if (ref $value eq 'HASH') {
        return "$where: an object, the CRD says $type" if $type && $type ne 'object';
        for my $field (@{ $schema->{required} // [] }) {
            push @found, "$where.$field: required by the CRD, not set"
                unless exists $value->{$field};
        }
        for my $field (sort keys %$value) {
            my $sub = $schema->{properties}{$field}
                // (ref $schema->{additionalProperties} eq 'HASH' ? $schema->{additionalProperties} : undef);
            if (!$sub) {
                push @found, "$where.$field: not declared in the CRD schema";
                next;
            }
            push @found, schema_violations($sub, $value->{$field}, "$where.$field");
        }
        return @found;
    }

    if (ref $value eq 'ARRAY') {
        return "$where: a list, the CRD says $type" if $type ne 'array';
        push @found, schema_violations($schema->{items}, $value->[$_], "${where}[$_]")
            for 0 .. $#$value;
        return @found;
    }

    if (JSON::PP::is_bool($value)) {
        return "$where: a boolean, the CRD says $type" if $type ne 'boolean';
        return;
    }

    # A plain scalar from here on.
    return "$where: a scalar, the CRD says $type"
        if $type eq 'object' || $type eq 'array' || $type eq 'boolean';
    return "$where: '$value' is no $type"
        if ($type eq 'integer' || $type eq 'number') && !looks_like_number($value);
    if (my $enum = $schema->{enum}) {
        push @found, "$where: '$value' is not one of " . join(', ', @$enum)
            unless grep { $_ eq $value } @$enum;
    }
    if (defined(my $pattern = $schema->{pattern})) {
        push @found, "$where: '$value' does not match $pattern"
            unless $value =~ /$pattern/;
    }
    return @found;
}

# Every combination of switches the generator branches on, so each field it
# can set is sent at least once.
my @setups = map {
    my $distribution = $_;
    map {
        my $driver = $_;
        map { { distribution => $distribution, gpu_driver => $driver, gpu_toolkit => $_ } } (1, 0);
    } qw(host operator);
} qw(rke2 k3s);

sub setup_label {
    my (%s) = @_;
    return "$s{distribution}, driver $s{gpu_driver}, toolkit " . ($s{gpu_toolkit} ? 'on' : 'off');
}

subtest 'the ClusterPolicy OCP sends is one the CRD it sends accepts' => sub {
    for my $setup (@setups) {
        my $label = setup_label(%$setup);
        my @sent = sent_by_setup(%$setup);

        my ($crd_at) = grep {
            ($sent[$_]{kind} // '') eq 'CustomResourceDefinition'
                && $sent[$_]{metadata}{name} eq 'clusterpolicies.nvidia.com'
        } 0 .. $#sent;
        my ($policy_at) = grep { ($sent[$_]{kind} // '') eq 'ClusterPolicy' } 0 .. $#sent;
        ok defined $crd_at && defined $policy_at,
            "$label: the ClusterPolicy CRD and a ClusterPolicy are both sent" or next;
        ok $crd_at < $policy_at, "$label: the CRD goes first";

        my $policy = $sent[$policy_at];
        my ($group, $version) = split m{/}, $policy->{apiVersion};
        my $crd = $sent[$crd_at];
        is $crd->{spec}{group}, $group, "$label: the CRD serves the policy's group";
        my ($served) = grep { $_->{name} eq $version && $_->{served} } @{ $crd->{spec}{versions} };
        ok $served, "$label: and serves its version, $version" or next;

        my $spec_schema = $served->{schema}{openAPIV3Schema}{properties}{spec};
        ok $spec_schema && $spec_schema->{properties},
            "$label: the CRD declares the fields of spec" or next;

        my @violations = schema_violations($spec_schema, $policy->{spec}, 'spec');
        is_deeply \@violations, [],
            "$label: every field OCP sets is declared, typed and valid in the CRD"
            or diag join "\n", @violations;
    }
};

#
# The bundle has to belong to the operator OCP deploys. NVIDIA generates both
# CRDs from the operator's Go types (controller-gen), so a bundle older than
# the operator does not know fields the operator reads — and OCP sets — and a
# newer one declares fields the operator ignores. The stub carried no version
# at all, and the NVIDIADriver CRD next to it was v24.9's, byte for byte,
# under a v26.3.3 pin. Nothing but this test ties the files to the pin: the
# header says where each file comes from, and the tag in it has to be
# gpu_operator's pin. Bump the pin, and this stays red until the bundle is
# fetched from the same tag.
#

subtest 'the CRD bundle comes from the tag OCP pins the operator to' => sub {
    my $pin = OCP::Versions->get_component_version('gpu_operator');
    my $dir = OCP::Share->dir->child('gpu-operator', 'crds');
    my @files = sort { "$a" cmp "$b" } $dir->children(qr/\.ya?ml\z/);
    ok @files, "CRD files in $dir" or return;

    my %in_bundle;
    for my $file (@files) {
        my $name = $file->basename;
        my ($tag) = $file->slurp_utf8 =~ m{
            ^\#\ Source:\ https://github\.com/NVIDIA/gpu-operator/blob/
            (\S+?)/deployments/gpu-operator/crds/\S+\.yaml$
        }xm;
        is $tag, $pin, "$name: fetched from NVIDIA/gpu-operator $pin, the pinned operator";

        my @docs = grep { ref } YAML::XS::Load($file->slurp_raw);
        is scalar @docs, 1, "$name: one document, the header is a comment";
        is $docs[0]{kind}, 'CustomResourceDefinition', "$name: and it is a CRD";
        $in_bundle{ $docs[0]{metadata}{name} } = 1;
    }

    my %sent = map { $_->{metadata}{name} => 1 }
        grep { ($_->{kind} // '') eq 'CustomResourceDefinition' } sent_by_setup(%{ $setups[0] });
    is_deeply [sort keys %sent], [sort keys %in_bundle],
        'setup_gpu_operator sends exactly the CRDs this checks, no more and no fewer';
};

#
# The real CRD requires spec.daemonsets, among others — the stub required
# nothing. OCP sends it empty: the operator reads an absent and an empty
# daemonsets as the same zero value, which is what it ran with on cortex, and
# the CRD's own default (updateStrategy: RollingUpdate) is the operator's too.
#

subtest 'daemonsets is sent, and sent empty' => sub {
    for my $setup (@setups) {
        my ($policy) = grep { ($_->{kind} // '') eq 'ClusterPolicy' } sent_by_setup(%$setup);
        is_deeply $policy->{spec}{daemonsets}, {},
            setup_label(%$setup) . ': present for the CRD, with nothing in it that '
          . 'changes what the operator ran with before';
    }
};

done_testing;

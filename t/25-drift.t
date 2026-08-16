#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::Drift;

#
# Fake Kubernetes API: hands back plain hashrefs, like the real client does
# once objects are converted.
#

package FakeApi {
    sub new { my ($class, %args) = @_; bless { objects => {}, lists => {}, %args }, $class }

    sub get {
        my ($self, $kind, %args) = @_;
        my $key = join '/', $kind, $args{namespace} // '', $args{name} // '';
        my $obj = $self->{objects}{$key};
        die "$kind $args{name} not found\n" unless $obj;
        return $obj;
    }

    sub list {
        my ($self, $kind) = @_;
        return $self->{lists}{$kind} // { items => [] };
    }
}

sub deployment {
    my ($image) = @_;
    return { spec => { template => { spec => { containers => [ { image => $image } ] } } } };
}

# Every probed component, at the version the manifest pins. A fixture that
# leaves one out is a cluster missing that component, not a matching one — so
# this is what "no drift" has to be measured against.
sub matching_cluster {
    return (
        'Deployment/kube-system/cilium-operator' => deployment('quay.io/cilium/operator-generic:v1.20.0'),
        'Deployment/cert-manager/cert-manager'   => deployment('quay.io/jetstack/cert-manager-controller:v1.21.1'),
        'Deployment/node-feature-discovery/nfd-master'
            => deployment('registry.k8s.io/nfd/node-feature-discovery:v0.18.3'),
    );
}

sub write_config {
    my (%args) = @_;
    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('ocp.yaml')->spew_utf8($args{spec});
    if ($args{status}) {
        path($dir)->child('.ocp')->mkpath;
        path($dir)->child('.ocp', 'status.yaml')->spew_utf8($args{status});
    }
    return OCP::Config->new(file => path($dir)->child('ocp.yaml')->stringify);
}

my $BASE_SPEC = <<'YAML';
name: testcluster
kubernetes:
  distribution: rke2
  version: v1.31.3+rke2r1
control_planes:
  provider: hetzner
  server_type: cx32
YAML

#
# Test: image_version
#

{
    is(OCP::Drift::image_version('quay.io/cilium/operator-generic:v1.19.2'), 'v1.19.2',
        'plain tag');
    is(OCP::Drift::image_version('quay.io/jetstack/cert-manager-controller:v1.14.0'), 'v1.14.0',
        'tag with dots');
    is(OCP::Drift::image_version('registry:5000/team/app:v2'), 'v2',
        'registry port is not the tag');
    is(OCP::Drift::image_version('quay.io/cilium/operator:v1.19.2@sha256:'. ('a' x 64)), 'v1.19.2',
        'digest stripped');
    is(OCP::Drift::image_version('nginx'), '', 'untagged image has no version');
    is(OCP::Drift::image_version(undef), '', 'undef is handled');
}

#
# Test: no drift when everything matches
#

{
    my $config = write_config(spec => $BASE_SPEC);
    my $api = FakeApi->new(
        objects => { matching_cluster() },
        lists => {
            Node => { items => [
                { metadata => { name => 'police1' },
                  status => { nodeInfo => { kubeletVersion => 'v1.31.3+rke2r1' } } },
            ] },
        },
    );

    my $drift = OCP::Drift->new(config => $config, api => $api)->detect;
    is_deeply($drift, [], 'matching cluster reports no drift');
}

#
# Test: version drift carries the remediation step
#

{
    my $config = write_config(spec => $BASE_SPEC);
    my $api = FakeApi->new(
        objects => {
            matching_cluster(),
            'Deployment/kube-system/cilium-operator' => deployment('quay.io/cilium/operator-generic:v1.17.0'),
        },
        lists => {
            Node => { items => [
                { metadata => { name => 'police1' },
                  status => { nodeInfo => { kubeletVersion => 'v1.31.3+rke2r1' } } },
            ] },
        },
    );

    my $drift = OCP::Drift->new(config => $config, api => $api)->detect;
    is(scalar @$drift, 1, 'one drift entry');
    is($drift->[0]{kind}, 'version', 'classified as version drift');
    is($drift->[0]{component}, 'cilium', 'names the component');
    is($drift->[0]{actual}, 'v1.17.0', 'running version, tag as written in the image');
    is($drift->[0]{expected}, '1.20.0', 'target version, as written in the manifest');
    is($drift->[0]{remedy}{task}, 'upgrade_cilium', 'remedy is the Rex upgrade task');
    is($drift->[0]{remedy}{params}{version}, '1.20.0', 'remedy carries the target version');
    like($drift->[0]{message}, qr/Cilium runs v1\.17\.0, expected 1\.20\.0/, 'readable message');
}

#
# Test: a leading v never counts as a difference
#

{
    my $config = write_config(spec => $BASE_SPEC);
    my $api = FakeApi->new(
        objects => {
            # manifest says v1.20.0, version manifest says 1.20.0
            'Deployment/kube-system/cilium-operator' => deployment('quay.io/cilium/operator-generic:v1.20.0'),
            'Deployment/cert-manager/cert-manager'   => deployment('quay.io/jetstack/cert-manager-controller:1.21.1'),
        },
    );

    my @drift = OCP::Drift->new(config => $config, api => $api)->component_drift;
    is_deeply([grep { $_->{kind} eq 'version' } @drift], [], 'v-prefix differences ignored');
}

#
# Test: missing component
#

{
    my $config = write_config(spec => $BASE_SPEC);
    my $api = FakeApi->new(
        objects => {
            'Deployment/cert-manager/cert-manager' => deployment('quay.io/jetstack/cert-manager-controller:v1.14.0'),
        },
    );

    my ($drift) = grep { $_->{component} eq 'cilium' }
                  OCP::Drift->new(config => $config, api => $api)->component_drift;
    is($drift->{kind}, 'missing', 'absent deployment reported as missing');
    is($drift->{remedy}, undef, 'missing components have no upgrade remedy');
}

#
# Test: nocert skips the cert-manager probe
#

{
    my $config = write_config(spec => $BASE_SPEC . "nocert: true\n");
    my $api = FakeApi->new(objects => {});

    my @drift = OCP::Drift->new(config => $config, api => $api)->component_drift;
    is_deeply([grep { $_->{component} eq 'cert_manager' } @drift], [],
        'cert-manager not checked when disabled');
}

#
# Test: a skip_if that names a method OCP::Config does not have is a
# programmer error and dies loudly. Before karr #106 the missing method made
# the can() probe fall through and the probe ran as if no skip_if was set --
# a cluster with `nocert: true` would then be reported as cert-manager-
# drifting after someone renamed or removed OCP::Config::no_cert.
#

{
    # Splicing a single bogus probe keeps the rest of the table from running
    # and going through the real skip_if code path, which is what we want to
    # exercise -- not the broader component_drift behaviour.
    local @OCP::Drift::COMPONENT_PROBES = (
        { component => 'never', label => 'Never', kind => 'Deployment',
          name => 'never', namespace => 'never',
          skip_if => 'definitely_not_a_real_method', },
    );

    my $config = write_config(spec => $BASE_SPEC);
    my $api = FakeApi->new(objects => {});

    eval { OCP::Drift->new(config => $config, api => $api)->component_drift };
    like($@, qr/definitely_not_a_real_method/,
        'croak names the offending skip_if target');
    like($@, qr/skip_if target not found on OCP::Config/,
        'croak says what is wrong');
}

#
# Test: the GPU stack
#
# @COMPONENT_PROBES had two entries, cilium and cert_manager, while the whole
# GPU stack sat in OCP::Versions unchecked — a version bump there never showed
# up in `ocp status`. Reconciliation did redeploy on the manifest hash, so the
# cluster converged; nothing said that it had to.
#
# Only what can be measured is probed. NFD and the GPU operator run from
# Deployments OCP writes itself, so their image carries the pinned version.
# The rest of the stack (toolkit, device plugin, DCGM, its exporter, the
# driver) goes into the ClusterPolicy and comes back out as DaemonSets the
# operator names and shapes — read off a guessed name, the "running version"
# would be a version this module cannot stand behind, so it is left out.
#

{
    my $config = write_config(spec => $BASE_SPEC);
    my $api = FakeApi->new(objects => {
        matching_cluster(),
        'Deployment/node-feature-discovery/nfd-master'
            => deployment('registry.k8s.io/nfd/node-feature-discovery:v0.17.0'),
    });

    my ($drift) = grep { $_->{component} eq 'nfd' }
                  OCP::Drift->new(config => $config, api => $api)->component_drift;

    ok($drift, 'an NFD behind the pin is drift');
    is($drift->{kind}, 'version', 'classified as version drift');
    is($drift->{actual}, 'v0.17.0', 'the tag the cluster runs');
    is($drift->{expected}, 'v0.18.3', 'the tag the manifest pins');
    is($drift->{remedy}, undef, 'no Rex task upgrades NFD');
    ok($drift->{self_healing}, 'ocp apply re-applies the manifest, and says so');
}

{
    # NFD is on every cluster, so its absence is a finding like any other.
    my $config = write_config(spec => $BASE_SPEC);
    my $api = FakeApi->new(objects => {
        'Deployment/kube-system/cilium-operator' => deployment('quay.io/cilium/operator-generic:v1.20.0'),
        'Deployment/cert-manager/cert-manager'   => deployment('quay.io/jetstack/cert-manager-controller:v1.21.1'),
    });

    my ($drift) = grep { $_->{component} eq 'nfd' }
                  OCP::Drift->new(config => $config, api => $api)->component_drift;

    is($drift->{kind}, 'missing', 'an NFD that is not there is reported');
    is($drift->{remedy}, undef, 'and still has no upgrade task');
}

{
    my $config = write_config(spec => $BASE_SPEC);
    my $api = FakeApi->new(objects => {
        matching_cluster(),
        'Deployment/gpu-operator/gpu-operator' => deployment('nvcr.io/nvidia/gpu-operator:v26.0.0'),
    });

    my ($drift) = grep { $_->{component} eq 'gpu_operator' }
                  OCP::Drift->new(config => $config, api => $api)->component_drift;

    ok($drift, 'a GPU operator behind the pin is drift');
    is($drift->{actual}, 'v26.0.0', 'the running version');
    is($drift->{expected}, 'v26.3.3', 'the pinned one');
    is($drift->{remedy}, undef, 'reported, not healed by a Rex task');
    like($drift->{message}, qr/GPU Operator runs v26\.0\.0/, 'readable message');
}

{
    # Most clusters have no NVIDIA card, and a permanent "GPU Operator is not
    # deployed" on `ocp status` would be noise nothing should ever act on.
    my $config = write_config(spec => $BASE_SPEC);
    my $api = FakeApi->new(objects => { matching_cluster() });

    is_deeply([grep { $_->{component} eq 'gpu_operator' }
               OCP::Drift->new(config => $config, api => $api)->component_drift],
        [], 'a cluster without the GPU operator is not drifted for lacking it');
}

{
    # What is deliberately absent, so a later reader does not take it for an
    # oversight: these are pinned in OCP::Versions but not probed.
    my %probed = map { $_->{component} => 1 } @OCP::Drift::COMPONENT_PROBES;

    ok(!$probed{$_}, "$_ is left unprobed — its version lives in the ClusterPolicy")
        for qw(nvidia_toolkit nvidia_device_plugin dcgm_exporter nvidia_dcgm nvidia_driver);
}

#
# Test: distribution drift, one entry per node, never auto-remedied
#

{
    my $config = write_config(spec => $BASE_SPEC);
    my $api = FakeApi->new(
        lists => {
            Node => { items => [
                { metadata => { name => 'police1' },
                  status => { nodeInfo => { kubeletVersion => 'v1.31.3+rke2r1' } } },
                { metadata => { name => 'worker-1' },
                  status => { nodeInfo => { kubeletVersion => 'v1.30.0+rke2r1' } } },
            ] },
        },
    );

    my @drift = OCP::Drift->new(config => $config, api => $api)->distribution_drift;
    is(scalar @drift, 1, 'only the outdated node drifts');
    is($drift[0]{label}, 'rke2 on worker-1', 'names the node');
    is($drift[0]{remedy}, undef, 'distribution upgrades stay manual');
}

#
# Test: spec drift against recorded status
#

{
    my $config = write_config(
        spec => <<'YAML',
name: testcluster
control_planes:
  provider: hetzner
  public_ip: 1.2.3.4
YAML
        status => <<'YAML',
nodes:
  - name: police1
    role: control-plane
    public_ip: 9.9.9.9
YAML
    );

    my @drift = OCP::Drift->new(config => $config)->spec_drift;
    is(scalar @drift, 1, 'pinned IP that moved is drift');
    is($drift[0]{kind}, 'spec', 'classified as spec drift');
    is($drift[0]{expected}, '1.2.3.4', 'expected from ocp.yaml');
    is($drift[0]{actual}, '9.9.9.9', 'actual from status.yaml');
}

{
    my $config = write_config(
        spec => <<'YAML',
name: testcluster
control_planes:
  provider: hetzner
  public_ip: 1.2.3.4
YAML
        status => <<'YAML',
nodes:
  - name: police1
    role: control-plane
    public_ip: 1.2.3.4
YAML
    );

    is_deeply([OCP::Drift->new(config => $config)->spec_drift], [], 'matching IP is not drift');
}

{
    # No status recorded yet: nothing to compare against
    my $config = write_config(spec => "name: t\ncontrol_planes:\n  public_ip: 1.2.3.4\n");
    is_deeply([OCP::Drift->new(config => $config)->spec_drift], [], 'no status means no drift');
}

#
# Test: detect without an API only looks at the spec
#

{
    my $config = write_config(spec => $BASE_SPEC);
    is_deeply(OCP::Drift->new(config => $config)->detect, [],
        'without an API no component drift is claimed');
}

#
# Test: format_lines
#

{
    my @lines = OCP::Drift->format_lines([ { message => 'something moved' } ]);
    is($lines[0], '  [drift] something moved', 'formats one line per entry');
}

done_testing;

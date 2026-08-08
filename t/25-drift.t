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
controlPlanes:
  provider: hetzner
  serverType: cx32
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
        objects => {
            'Deployment/kube-system/cilium-operator' => deployment('quay.io/cilium/operator-generic:v1.20.0'),
            'Deployment/cert-manager/cert-manager'   => deployment('quay.io/jetstack/cert-manager-controller:v1.21.1'),
        },
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
            'Deployment/kube-system/cilium-operator' => deployment('quay.io/cilium/operator-generic:v1.17.0'),
            'Deployment/cert-manager/cert-manager'   => deployment('quay.io/jetstack/cert-manager-controller:v1.21.1'),
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
controlPlanes:
  provider: hetzner
  publicIp: 1.2.3.4
YAML
        status => <<'YAML',
nodes:
  - name: police1
    role: control-plane
    publicIp: 9.9.9.9
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
controlPlanes:
  provider: hetzner
  publicIp: 1.2.3.4
YAML
        status => <<'YAML',
nodes:
  - name: police1
    role: control-plane
    publicIp: 1.2.3.4
YAML
    );

    is_deeply([OCP::Drift->new(config => $config)->spec_drift], [], 'matching IP is not drift');
}

{
    # No status recorded yet: nothing to compare against
    my $config = write_config(spec => "name: t\ncontrolPlanes:\n  publicIp: 1.2.3.4\n");
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

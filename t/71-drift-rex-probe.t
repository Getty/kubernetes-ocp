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
# The rex_probe detection mode: OCP::Drift's second way of seeing drift.
#
# component_drift asks the Kubernetes API; rex_probe_drift runs a read-only Rex
# task over SSH on the hosts a probe selects and reads its stdout for a marker.
# Its failure modes are the ones the API path does not have -- host down, no
# key, slow -- and none of them is drift: a probe that cannot run is carped and
# skipped, never blocks detect(), never claims a clean host.
#
# The prober is injected exactly like `api` is. Here it is a coderef that
# records its calls and hands back canned OCP::Rex-shaped results; the real one
# (OCP::Role::Cmd::rex_prober) wraps OCP::Rex.
#

sub write_config {
    my (%args) = @_;
    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('ocp.yaml')->spew_utf8($args{spec});
    return OCP::Config->new(file => path($dir)->child('ocp.yaml')->stringify);
}

# One control plane, addressed by its pinned public_ip. No status is recorded,
# so spec_drift stays quiet and only the rex probe can speak.
my $ONE_CP = <<'YAML';
name: testcluster
control_planes:
  provider: hetzner
  public_ip: 10.0.0.1
YAML

my $TWO_CP = <<'YAML';
name: testcluster
control_planes:
  - public_ip: 10.0.0.1
  - public_ip: 10.0.0.2
YAML

# A prober that returns the drift marker for the given set of hosts and clean
# output for the rest, recording every call into @$calls.
sub prober_for {
    my ($drifted, $calls) = @_;
    my %hit = map { $_ => 1 } @$drifted;
    return sub {
        my ($host, $task, $params) = @_;
        push @$calls, { host => $host, task => $task, params => $params };
        return {
            stdout => $hit{$host} ? "$OCP::Drift::REX_DRIFT_MARKER /var/lib/rancher/rke2/agent/etc/containerd/config.toml.tmpl\n" : "",
            exit   => 0,
        };
    };
}

#
# A host that answers with the marker becomes one drift entry, carrying the
# cleanup task as its remedy.
#
{
    my $config = write_config(spec => $ONE_CP);
    my @calls;
    my @drift = OCP::Drift->new(
        config     => $config,
        rex_prober => prober_for(['10.0.0.1'], \@calls),
    )->rex_probe_drift;

    is(scalar @drift, 1, 'a host reporting the marker is one drift entry');
    is($drift[0]{kind}, 'rex_probe', 'classified as a rex_probe drift');
    is($drift[0]{component}, 'legacy_containerd_template', 'names the component');
    is($drift[0]{host}, '10.0.0.1', 'the entry records which host drifted');
    is($drift[0]{remedy}{type}, 'rex', 'remedy is a Rex task');
    is($drift[0]{remedy}{task}, 'cleanup_legacy_containerd_template',
        'remedy is the cleanup task that already exists');
    is($drift[0]{remedy}{host}, '10.0.0.1',
        'remedy carries the host so it runs where the drift is');
    like($drift[0]{message}, qr/10\.0\.0\.1/, 'message names the host');

    is(scalar @calls, 1, 'the CP was probed once');
    is($calls[0]{task}, 'detect_legacy_containerd_template',
        'the read-only detection task was run, not the cleanup task');
    is($calls[0]{host}, '10.0.0.1', 'probed on the CP address from ocp.yaml');
}

#
# A host that answers clean is not drift.
#
{
    my $config = write_config(spec => $ONE_CP);
    my @calls;
    my @drift = OCP::Drift->new(
        config     => $config,
        rex_prober => prober_for([], \@calls),   # nobody drifted
    )->rex_probe_drift;

    is_deeply(\@drift, [], 'a clean host produces no entry');
    is(scalar @calls, 1, 'but it was still probed');
}

#
# Only the drifted host of several gets an entry.
#
{
    my $config = write_config(spec => $TWO_CP);
    my @calls;
    my @drift = OCP::Drift->new(
        config     => $config,
        rex_prober => prober_for(['10.0.0.2'], \@calls),
    )->rex_probe_drift;

    is(scalar @drift, 1, 'one of two CPs drifted');
    is($drift[0]{host}, '10.0.0.2', 'the entry is for the drifted host');
    is(scalar @calls, 2, 'both CPs were probed');
}

#
# A probe that throws (host unreachable, no key, timeout) is carped and
# skipped -- never an exception, never drift, never blocking the rest.
#
{
    my $config = write_config(spec => $TWO_CP);
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, $_[0] };

    my $prober = sub {
        my ($host, $task, $params) = @_;
        die "ssh: connect to host $host port 22: Connection timed out\n"
            if $host eq '10.0.0.1';
        return { stdout => "", exit => 0 };
    };

    my @drift = OCP::Drift->new(config => $config, rex_prober => $prober)->rex_probe_drift;

    is_deeply(\@drift, [], 'an unreachable host yields no drift, and no crash');
    ok(@warn, 'the failure was carped to stderr, not swallowed');
    like($warn[0], qr/10\.0\.0\.1/, 'the warning names the host that could not be reached');
    like($warn[0], qr/detect_legacy_containerd_template/, 'and the probe that failed');
}

#
# Without a prober, detect() never enters the SSH mode -- exactly the graceful
# degradation `ocp status` needs when no key is at hand.
#
{
    my $config = write_config(spec => $ONE_CP);
    my $drift = OCP::Drift->new(config => $config)->detect;
    is_deeply([grep { $_->{kind} eq 'rex_probe' } @$drift], [],
        'no prober means no host-side drift is claimed');
}

#
# detect() surfaces rex_probe entries alongside the rest.
#
{
    my $config = write_config(spec => $ONE_CP);
    my $drift = OCP::Drift->new(
        config     => $config,
        rex_prober => prober_for(['10.0.0.1'], []),
    )->detect;
    my ($entry) = grep { $_->{kind} eq 'rex_probe' } @$drift;
    ok($entry, 'detect() carries the host-side drift into the drift list');
    is($entry->{remedy}{task}, 'cleanup_legacy_containerd_template',
        'with its remedy, so the reconcile loop can act on it');
}

#
# An unknown host_selector is a programmer error, not a quiet empty result.
#
{
    my $config = write_config(spec => $ONE_CP);
    local @OCP::Drift::REX_PROBES = (
        { component => 'x', label => 'X', host_selector => 'not_a_selector',
          detection_task => 'd', remedy_task => 'r', message => 'm' },
    );
    eval {
        OCP::Drift->new(config => $config, rex_prober => prober_for([], []))->rex_probe_drift;
    };
    like($@, qr/unknown host_selector/, 'an unknown selector croaks');
}

done_testing;

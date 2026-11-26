#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);

use lib 'lib';
use OCP;
use OCP::Config;
use OCP::Drift;

#
# k460 (follow-up to k458): gateway_mode_drift compared only the on/off flag
# gateway-api-hostnetwork-enabled. A changed gateway.node_selector reaches a
# running cluster the same way -- a Cilium Helm value, re-run only by
# `ocp update --component cilium --force` -- and went unreported. The chart
# (Cilium 1.20, templates/cilium-configmap.yaml) renders
# gatewayAPI.hostNetwork.nodes.matchLabels into
# gateway-api-hostnetwork-nodelabelselector through its mapToString helper:
# key=value pairs, keys in sorted order (Go template range over a map), joined
# with ",". OCP::Drift now compares that key with what
# OCP::Config->cilium_helm_values renders, under host_network only.
#
# Network-free: OCP::Config on temp files, the API a hash of objects.
#

my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

sub config_for {
    my ($spec) = @_;
    my $name = 'c' . int(rand(1_000_000));
    my $f = path($tmpdir)->child("$name.yaml");
    $ocp->dump_file($f->stringify, { name => $name, %$spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

my $local = { control_planes => [{ provider => 'local' }] };
sub host_spec {
    my (%sel) = @_;
    return { %$local, gateway => { mode => 'host_network', node_selector => { %sel } } };
}

package FakeApi {
    sub new { my ($class, %o) = @_; bless { %o }, $class }
    sub get {
        my ($self, $kind, %a) = @_;
        $self->{gets}++;
        my $obj = $self->{objects}{ join '/', $kind, $a{namespace} // '', $a{name} // '' };
        die "Kubernetes API error (get $kind): 404 $kind not found\n" unless $obj;
        return $obj;
    }
    sub list { +{ items => [] } }
}

package main;

sub drift_for {
    my ($spec, $live) = @_;
    my $api = FakeApi->new(objects => { 'ConfigMap/kube-system/cilium-config' => { data => $live } });
    my @d = OCP::Drift->new(config => config_for($spec), api => $api)->gateway_mode_drift;
    return ($api, @d);
}

my $ON = 'gateway-api-hostnetwork-enabled';
my $NS = 'gateway-api-hostnetwork-nodelabelselector';

subtest 'the selector matches: no drift' => sub {
    my ($api, @d) = drift_for(host_spec('ocp.io/gateway' => 'true'),
        { $ON => 'true', $NS => 'ocp.io/gateway=true' });
    is_deeply \@d, [], 'one label, as the chart renders it';
    is $api->{gets}, 1, 'cilium-config read once for mode and selector';

    (undef, @d) = drift_for(host_spec('zone' => 'a', 'ocp.io/gateway' => 'true'),
        { $ON => 'true', $NS => 'ocp.io/gateway=true,zone=a' });
    is_deeply \@d, [], 'two labels, keys sorted as Go ranges over a map';

    (undef, @d) = drift_for(host_spec('zone' => 'a', 'ocp.io/gateway' => 'true'),
        { $ON => 'true', $NS => 'zone=a, ocp.io/gateway=true' });
    is_deeply \@d, [], 'order and blanks of the live string do not matter';

    (undef, @d) = drift_for(host_spec('edge' => '1', 'edge.zone' => 'a'),
        { $ON => 'true', $NS => 'edge=1,edge.zone=a' });
    is_deeply \@d, [], 'one key a prefix of another: keys sorted, not the pair strings';
};

subtest 'the selector changed in ocp.yaml: spec drift with the manual step' => sub {
    for my $case (
        [ 'another value', { $NS => 'ocp.io/gateway=false' } ],
        [ 'another label', { $NS => 'ocp.io/edge=true' } ],
        [ 'a label more',  { $NS => 'ocp.io/gateway=true,zone=a' } ],
        [ 'none live',     {} ],
    ) {
        my ($what, $live) = @$case;
        my (undef, @d) = drift_for(host_spec('ocp.io/gateway' => 'true'), { $ON => 'true', %$live });
        is scalar @d, 1, "$what: one entry" or next;
        my $e = $d[0];
        is $e->{kind}, 'spec', "$what: spec kind";
        is $e->{component}, 'cilium_gateway', "$what: component";
        is $e->{label}, 'Gateway node selector', "$what: label";
        is $e->{expected}, 'ocp.io/gateway=true', "$what: expected, as the chart renders it";
        is $e->{actual}, $live->{$NS} // '', "$what: actual, the live key";
        ok !$e->{remedy}, "$what: no remedy";
        like $e->{message}, qr/gateway\.node_selector/, "$what: names the ocp.yaml key";
        like $e->{manual_step}, qr/ocp update --component cilium --force/, "$what: names the step";
        ok !OCP::Drift->apply_closes($e), "$what: not one apply closes";
    }
};

subtest 'a mode difference is one entry, not two' => sub {
    my (undef, @d) = drift_for(host_spec('ocp.io/gateway' => 'true'), { $ON => 'false' });
    is scalar @d, 1, 'host_network expected, load_balancer live: the mode entry only';
    is $d[0]{label}, 'Gateway mode', 'the mode entry';

    (undef, @d) = drift_for($local, { $ON => 'true', $NS => 'ocp.io/gateway=true' });
    is scalar @d, 1, 'load_balancer expected, host_network live: the mode entry only';
    is $d[0]{label}, 'Gateway mode', 'the mode entry';
};

subtest 'load_balancer: the selector is not compared' => sub {
    my (undef, @d) = drift_for($local, { $ON => 'false', $NS => 'leftover=1' });
    is_deeply \@d, [], 'a selector left in cilium-config under load_balancer is not drift';
};

done_testing;

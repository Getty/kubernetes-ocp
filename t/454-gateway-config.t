#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);
use JSON::MaybeXS ();

use lib 'lib';
use lib 't/lib';
use OCPTest::Rexfile;
use OCP;
use OCP::Config;
use OCP::Drift;

no warnings 'once';

#
# k454: on Hetzner Cloud the Cilium Gateway cannot get a reachable address
# from LB-IPAM -- L2 announcement does not cross Hetzner's network, which
# delivers only the addresses Hetzner assigned. gateway: { mode: host_network,
# node_selector: {...} } puts Cilium's Gateway API in host-network mode: Envoy
# listens on 80/443 of the labelled nodes, and an edge proxy forwards to their
# private address. This file holds ocp.yaml's side:
#
#   1. no gateway: (or mode: load_balancer) renders no Helm values -- a
#      cluster that does not ask gets exactly what it got before
#   2. host_network renders gatewayAPI.hostNetwork (enabled, nodes.matchLabels)
#      and NET_BIND_SERVICE for the cilium-envoy DaemonSet; cilium.helm_values
#      merge over it, so they keep the last word on envoy
#   3. validate() refuses, at spec_errors' path gateway: no mapping, an
#      unknown key, an unknown mode, host_network without node_selector, a
#      node_selector without host_network, a selector that is no label set,
#      and a cilium.helm_values that sets gatewayAPI.hostNetwork itself or
#      takes Envoy out of its DaemonSet; the accessors refuse in those words
#   4. the values travel: the Cilium drift remedy and ocp update carry them,
#      install_cilium and upgrade_cilium hand them to Rex::Rancher::Cilium --
#      the station walk too, which merges gatewayAPI.enabled into them
#
# Network-free: OCP::Config on temp files, the Rexfile against recorders.
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
my $SEL   = { 'ocp.io/gateway' => 'true' };
my $HOST  = { mode => 'host_network', node_selector => $SEL };

sub host_values {
    my ($sel) = @_;
    return {
        gatewayAPI => { hostNetwork => { enabled => 1, nodes => { matchLabels => $sel } } },
        envoy      => { securityContext => { capabilities => {
            keepCapNetBindService => 1,
            envoy                 => [qw( NET_ADMIN SYS_ADMIN NET_BIND_SERVICE )],
        } } },
    };
}

# Booleans compared as Perl truth, the rest as it is.
sub plain {
    my ($v) = @_;
    return ref $v eq 'HASH'  ? { map { $_ => plain($v->{$_}) } keys %$v }
         : ref $v eq 'ARRAY' ? [ map { plain($_) } @$v ]
         : JSON::MaybeXS::is_bool($v) ? ($v ? 1 : 0)
         : $v;
}

# --- 1. the default -------------------------------------------------------

subtest 'no gateway: or mode load_balancer: no Helm values, as before' => sub {
    for my $case ([ 'no gateway:', {} ],
                  [ 'mode: load_balancer', { gateway => { mode => 'load_balancer' } } ],
                  [ 'gateway: {}', { gateway => {} } ]) {
        my ($what, $spec) = @$case;
        my $c = config_for({ %$local, %$spec });
        is_deeply [ $c->validate ], [], "$what: valid";
        is $c->gateway_mode, 'load_balancer', "$what: load_balancer";
        ok !$c->gateway_host_network, "$what: not host_network";
        is_deeply $c->gateway_node_selector, {}, "$what: no selector";
        is_deeply $c->gateway_helm_values, {}, "$what: no gateway values";
        is_deeply $c->cilium_helm_values, {}, "$what: cilium_helm_values still {}";
    }
    my $c = config_for({ %$local, cilium => { devices => ['eth1'] } });
    is_deeply $c->cilium_helm_values, { devices => ['eth1'] }, 'cilium: alone is what it was';
};

# --- 2. host_network --------------------------------------------------------

subtest 'host_network renders the mode, its nodes and NET_BIND_SERVICE' => sub {
    my $c = config_for({ %$local, gateway => $HOST });
    is_deeply [ $c->validate ], [], 'valid';
    is $c->gateway_mode, 'host_network', 'the mode';
    ok $c->gateway_host_network, 'host_network';
    is_deeply $c->gateway_node_selector, $SEL, 'the selector';

    my $v = $c->cilium_helm_values;
    is_deeply plain($v), host_values($SEL), 'the values';
    ok JSON::MaybeXS::is_bool($v->{gatewayAPI}{hostNetwork}{enabled}),
        'enabled is a boolean, so the YAML Helm reads says true';
    ok JSON::MaybeXS::is_bool($v->{envoy}{securityContext}{capabilities}{keepCapNetBindService}),
        'keepCapNetBindService too';

    my $two = { 'ocp.io/gateway' => 'true', 'topology.kubernetes.io/zone' => 'fsn1' };
    is_deeply plain(config_for({ %$local, gateway => { mode => 'host_network', node_selector => $two } })
        ->cilium_helm_values), host_values($two), 'every label of the selector';
};

subtest 'cilium: merges over the gateway values, and keeps the last word' => sub {
    my $c = config_for({ %$local, gateway => $HOST, cilium => {
        devices     => ['enp7s0'],
        helm_values => {
            bpf   => { masquerade => 1 },
            envoy => { securityContext => { capabilities => { envoy => ['NET_BIND_SERVICE'] } } },
        },
    } });
    is_deeply [ $c->validate ], [], 'valid';
    my $v = plain($c->cilium_helm_values);
    is_deeply $v->{devices}, ['enp7s0'], 'devices';
    is_deeply $v->{bpf}, { masquerade => 1 }, 'helm_values';
    is_deeply $v->{gatewayAPI}, host_values($SEL)->{gatewayAPI}, 'the gateway mode';
    is_deeply $v->{envoy}{securityContext}{capabilities},
        { keepCapNetBindService => 1, envoy => ['NET_BIND_SERVICE'] },
        'helm_values replace the capability list, the key beside it stays';
};

# --- 3. what is refused -------------------------------------------------------

sub gateway_lines {
    my ($gw, $cilium) = @_;
    my $c = config_for({ %$local, gateway => $gw, (defined $cilium ? (cilium => $cilium) : ()) });
    my @all = $c->validate;
    is_deeply [ $c->spec_errors('gateway') ], \@all, 'every line is at the path gateway'
        or diag explain \@all;
    return @all;
}

subtest 'validate refuses, at the path gateway' => sub {
    is_deeply [ gateway_lines('host_network') ],
        [ "gateway: must be a mapping (mode or node_selector), not 'host_network'" ], 'a string';
    is_deeply [ gateway_lines({ mode => 'host_network', node_selector => $SEL, nodes => 'w1' }) ],
        [ 'gateway.nodes: unknown key (must be mode or node_selector)' ], 'an unknown key';
    is_deeply [ gateway_lines({ mode => 'hostNetwork' }) ],
        [ "gateway.mode: must be load_balancer or host_network, not 'hostNetwork'" ], 'an unknown mode';
    is_deeply [ gateway_lines({ mode => 'host_network' }) ],
        [ 'gateway.mode is host_network, which needs gateway.node_selector: the labels of the '
        . 'nodes Envoy listens on, e.g. { ocp.io/gateway: "true" }' ], 'host_network without nodes';
    is_deeply [ gateway_lines({ node_selector => $SEL }) ],
        [ 'gateway.node_selector: is read under gateway.mode: host_network only -- delete it, '
        . 'or set that mode' ], 'a selector without the mode';
    is_deeply [ gateway_lines({ mode => 'load_balancer', node_selector => $SEL }) ],
        [ 'gateway.node_selector: is read under gateway.mode: host_network only -- delete it, '
        . 'or set that mode' ], '... or under load_balancer';
    is_deeply [ gateway_lines({ mode => 'host_network', node_selector => {} }) ],
        [ 'gateway.node_selector: must be a non-empty mapping of label => value, not a mapping' ],
        'an empty selector';
    is_deeply [ gateway_lines({ mode => 'host_network', node_selector => ['w1'] }) ],
        [ 'gateway.node_selector: must be a non-empty mapping of label => value, not a list' ],
        'a list';
    is_deeply [ gateway_lines({ mode => 'host_network',
                                node_selector => { 'ocp.io/gateway' => JSON::MaybeXS::true() } }) ],
        [ 'gateway.node_selector.ocp.io/gateway: value must be a string (quote true, false and numbers)' ],
        'an unquoted true, as pool labels refuse it';
    is_deeply [ gateway_lines({ mode => 'host_network', node_selector => { 'bad key!' => 'x' } }) ],
        [ "gateway.node_selector: 'bad key!' is not a valid label key" ], 'no label key';

    is_deeply [ gateway_lines($HOST, { helm_values => { gatewayAPI => { hostNetwork => { enabled => 1 } } } }) ],
        [ 'gateway.mode host_network and cilium.helm_values.gatewayAPI.hostNetwork: set one of them, not both' ],
        'the same question answered twice';
    is_deeply [ gateway_lines($HOST, { helm_values => { envoy => { enabled => JSON::MaybeXS::false() } } }) ],
        [ 'gateway.mode host_network needs the cilium-envoy DaemonSet, and cilium.helm_values.envoy.enabled '
        . 'false runs Envoy inside the Cilium agent, which OCP grants no NET_BIND_SERVICE for ports '
        . '80 and 443 -- delete envoy.enabled' ], 'Envoy in the agent';
    is_deeply [ gateway_lines($HOST, { helm_values => { envoy => { enabled => JSON::MaybeXS::true() } } }) ],
        [], 'envoy.enabled true is the DaemonSet: fine';
    is_deeply [ gateway_lines({ mode => 'load_balancer' },
                              { helm_values => { gatewayAPI => { hostNetwork => { enabled => 1 } } } }) ],
        [], 'load_balancer holds nothing against cilium.helm_values';
};

subtest 'the accessors refuse in validate()\'s words' => sub {
    my $c = config_for({ %$local, gateway => { mode => 'host_network' } });
    for my $m (qw( gateway_config gateway_mode gateway_host_network gateway_node_selector
                   gateway_helm_values cilium_helm_values )) {
        eval { $c->$m };
        like $@, qr/\Agateway\.mode is host_network, which needs gateway\.node_selector/, $m;
    }
};

# --- 4. the values travel -----------------------------------------------------

subtest 'the Cilium drift remedy and ocp update carry them' => sub {
    my $p = OCP::Drift->remedy_params(config_for({ %$local, gateway => $HOST }), 'cilium', '1.20.0');
    is_deeply plain($p->{helm_values}), host_values($SEL), 'cilium: the gateway values';
    ok !exists OCP::Drift->remedy_params(config_for($local), 'cilium', '1.20.0')->{helm_values},
        'no gateway:, no cilium:: none, as before';
};

my $KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n";
my %PINS = (version => '1.20.0', cli_version => 'v0.19.7', gateway_api_version => 'v1.6.1');

sub cilium_opts_after {
    my ($task, %params) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = sub { $_[0] =~ /^cat \S+\.yaml$/ ? ($KUBECONFIG, 0) : ('', 0) };
    OCPTest::Rexfile->run_task($task, { %PINS, %params });
    return OCPTest::Rexfile->lib_opts("Rex::Rancher::Cilium::$task");
}

# As OCP::Rex hands them over: one JSON blob, so booleans arrive as JSON's.
my $WIRE = JSON::MaybeXS->new(utf8 => 1, canonical => 1)->decode(
    JSON::MaybeXS->new(utf8 => 1, canonical => 1)->encode(
        config_for({ %$local, gateway => $HOST })->cilium_helm_values));

subtest 'install_cilium and upgrade_cilium hand them to Rex::Rancher::Cilium' => sub {
    for my $task (qw( install_cilium upgrade_cilium )) {
        my $opts = cilium_opts_after($task, helm_values => $WIRE);
        is_deeply plain($opts->{helm_values}), host_values($SEL), "$task: passed on";
        ok $opts->{gateway_api}, "$task: with Gateway API, which the library turns gatewayAPI.enabled on for";
    }
};

subtest 'the station walk keeps them beside gatewayAPI.enabled' => sub {
    my @asked;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = sub { $_[0] =~ /^cat / ? ($KUBECONFIG, 0) : ('', 0) };
    my $running = '1.18.0';
    local $OCPTest::Rexfile::LIB_CODE{'Rex::Rancher::Cilium::upgrade_cilium'} = sub {
        my (%o) = @_;
        push @asked, { %o };
        my ($rm) = $running =~ /^1\.(\d+)/;
        my ($wm) = $o{version} =~ /^1\.(\d+)/;
        die "Cilium runs $running, version $o{version} is more than one minor version away: go on\n"
            if abs($wm - $rm) > 1;
        $running = $o{version};
        return 1;
    };
    eval { OCPTest::Rexfile->run_task('upgrade_cilium',
        { %PINS, helm_values => $WIRE, cilium_stations => [qw( 1.19.2 1.20.0 )] }); 1 }
        or diag $@;
    my ($station) = grep { $_->{version} eq '1.19.2' } @asked;
    ok $station, 'walked through 1.19.2' or return;
    ok !$station->{gateway_api}, 'the station leaves the CRDs alone';
    ok $station->{helm_values}{gatewayAPI}{enabled}, 'and keeps gatewayAPI.enabled in the values';
    is_deeply plain($station->{helm_values}{gatewayAPI}{hostNetwork}),
        host_values($SEL)->{gatewayAPI}{hostNetwork}, 'beside hostNetwork';
    is_deeply plain($station->{helm_values}{envoy}), host_values($SEL)->{envoy}, 'and the envoy values';
};

# The library's own merge of them is held in t/454-gateway-host-network.t:
# OCPTest::Rexfile stands in for Rex::Rancher::Cilium here.

done_testing;

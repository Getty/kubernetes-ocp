#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);

use lib 'lib';
use lib 't/lib';
use OCPTest::Rexfile;
use OCP;
use OCP::Config;
use OCP::Drift;
use OCP::Rex;
use OCP::Cmd::Apply::Network;

no warnings 'once';

#
# k210: two things kept the CitiAI GB10s' QSFP/RoCE fabric (enp1s0f0np0,
# brain <-> cortex) from staying out of Cilium's way.
#
#   1. The built-in L2 announcement regex ^en[a-z0-9]+$ matched the fabric
#      NIC -- its comment said the opposite -- and missed the LAN port
#      enP7s7.30 (capital P, VLAN). The default now leaves out the
#      n<phys_port_name> suffix switchdev NICs carry, and takes the PCI domain
#      and a VLAN suffix.
#   2. Cilium's own devices could not be set: _cilium_opts handed
#      Rex::Rancher::Cilium no helm_values. ocp.yaml's cilium: (devices,
#      helm_values) now reaches install_cilium, and every upgrade_cilium too,
#      so a Helm upgrade does not drop them.
#
# Network-free: the Rexfile runs against recorders (t/lib/OCPTest/Rexfile.pm).
#

my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);
my $root   = path(__FILE__)->parent->parent;

sub config_for {
    my ($spec) = @_;
    my $name = 'c' . int(rand(1_000_000));
    my $f = path($tmpdir)->child("$name.yaml");
    $ocp->dump_file($f->stringify, { name => $name, %$spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

my $local = { control_planes => [{ provider => 'local' }] };

# --- 1. the L2 default --------------------------------------------------------

# Cilium compiles these as Go RE2; the patterns use nothing Perl and RE2 read
# differently (classes, groups, ?, anchors), so Perl's match is RE2's.
sub announces {
    my ($if) = @_;
    return scalar grep { $if =~ /$_/ } @{ config_for($local)->l2_interfaces };
}

subtest 'the default L2 interfaces leave the fabric out' => sub {
    for my $fabric (qw( enp1s0f0np0 enp1s0f1np1 enP2p1s0f0np0 ens5f0np0 )) {
        ok !announces($fabric), "$fabric (switchdev port name) is not announced on";
    }
    for my $lan (qw( eth0 eth1.30 eno1 ens18 enp1s0 enp0s31f6 enP7s7 enP7s7.30 enx001122aabbcc )) {
        ok announces($lan), "$lan is";
    }
    for my $other (qw( lo cilium_host docker0 wlan0 enp1s0;x )) {
        ok !announces($other), "$other is not";
    }
};

subtest 'one default, and the policy uses it' => sub {
    is_deeply config_for($local)->l2_interfaces, $OCP::Config::DEFAULT_L2_INTERFACES,
        'l2_interfaces without network.l2.interfaces';
    my $set = config_for({ %$local, network => { l2 => { interfaces => ['^bond0$'] } } });
    is_deeply $set->l2_interfaces, ['^bond0$'], 'network.l2.interfaces replaces it';

    my $res = OCP::Cmd::Apply::Network::lb_ipam_resources('10.0.0.1', undef);
    my ($policy) = grep { $_->{kind} eq 'CiliumL2AnnouncementPolicy' } @$res;
    is_deeply $policy->{spec}{interfaces}, $OCP::Config::DEFAULT_L2_INTERFACES,
        'the config-less fallback is the same list';
};

# --- 2. cilium: in ocp.yaml ---------------------------------------------------

subtest 'cilium_helm_values' => sub {
    is_deeply config_for($local)->cilium_helm_values, {}, 'nothing set: {}';
    is_deeply config_for({ %$local, cilium => { devices => ['enP7s7.30'] } })->cilium_helm_values,
        { devices => ['enP7s7.30'] }, 'devices becomes Helm devices';
    is_deeply config_for({ %$local, cilium => {
            devices     => ['enP7s7.30'],
            helm_values => { bpf => { masquerade => 1 } } } })->cilium_helm_values,
        { devices => ['enP7s7.30'], bpf => { masquerade => 1 } }, 'merged with helm_values';
};

sub cilium_errors {
    my ($c) = @_;
    return grep { /cilium/ } config_for({ %$local, cilium => $c })->validate;
}

subtest 'cilium: validation' => sub {
    is_deeply [ cilium_errors({ devices => ['enP7s7.30'] }) ], [], 'devices';
    is_deeply [ cilium_errors({ helm_values => { devices => ['eth0'] } }) ], [], 'helm_values';
    like join("\n", cilium_errors('eth0')), qr/^cilium: must be a mapping/, 'a scalar';
    like join("\n", cilium_errors({ devices => 'eth0' })),
        qr/cilium\.devices: must be a non-empty list/, 'devices as a string';
    like join("\n", cilium_errors({ devices => [] })),
        qr/cilium\.devices: must be a non-empty list/, 'an empty list';
    like join("\n", cilium_errors({ devices => [ { name => 'eth0' } ] })),
        qr/cilium\.devices: entries must be interface names/, 'a mapping as entry';
    like join("\n", cilium_errors({ helm_values => ['x'] })),
        qr/cilium\.helm_values: must be a mapping/, 'helm_values as a list';
    like join("\n", cilium_errors({ devices => ['a'], helm_values => { devices => ['b'] } })),
        qr/set one of them, not both/, 'devices twice';
    like join("\n", cilium_errors({ device => ['eth0'] })),
        qr/cilium\.device: unknown key \(must be devices or helm_values\)/, 'a typo';
};

# --- the values reach the library ---------------------------------------------

my $KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n";
my %PINS = (version => '1.20.0', cli_version => 'v0.19.7', gateway_api_version => 'v1.6.1');
my $VALUES = { devices => ['enP7s7.30'] };

sub cilium_opts_after {
    my ($task, %params) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = sub { $_[0] =~ /^cat \S+\.yaml$/ ? ($KUBECONFIG, 0) : ('', 0) };
    OCPTest::Rexfile->run_task($task, { %PINS, %params });
    return OCPTest::Rexfile->lib_opts("Rex::Rancher::Cilium::$task");
}

subtest 'install_cilium and upgrade_cilium hand helm_values to Rex::Rancher::Cilium' => sub {
    for my $task (qw( install_cilium upgrade_cilium )) {
        is_deeply cilium_opts_after($task, helm_values => $VALUES)->{helm_values}, $VALUES,
            "$task: passed on";
        ok !exists cilium_opts_after($task)->{helm_values}, "$task: none given, none passed";
        ok !exists cilium_opts_after($task, helm_values => {})->{helm_values},
            "$task: an empty mapping is none";
    }
};

subtest 'OCP::Rex::install_server passes cilium_helm_values to install_cilium' => sub {
    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 };
    local *OCP::Rex::fetch_kubeconfig_ssh   = sub { "apiVersion: v1\n" };
    local *OCP::Rex::_existing_server_token = sub { undef };
    my $key = path($tmpdir)->child('id'); $key->spew('k'); path("$key.pub")->spew('k');
    my $rex = OCP::Rex->new(host => '127.0.0.1', key_file => $key->stringify);

    $rex->install_server(distribution => 'rke2', version => 'v1', cilium_helm_values => $VALUES);
    my ($cilium) = grep { $_->[0] eq 'install_cilium' } @calls;
    is_deeply $cilium->[1]{helm_values}, $VALUES, 'set: passed';

    @calls = ();
    $rex->install_server(distribution => 'rke2', version => 'v1', cilium_helm_values => {});
    ($cilium) = grep { $_->[0] eq 'install_cilium' } @calls;
    ok !exists $cilium->[1]{helm_values}, 'empty: left out';
};

subtest 'the bootstrap hands install_server the configured values' => sub {
    my $boot = $root->child('lib/OCP/Cmd/Apply/Bootstrap.pm')->slurp_utf8;
    my ($call) = $boot =~ /(\$rex->install_server\(.*?\);)/s;
    like $call, qr/cilium_helm_values\s*=>\s*\$config->cilium_helm_values/,
        'cilium_helm_values => $config->cilium_helm_values';
};

subtest 'the Cilium drift remedy and ocp update carry them' => sub {
    my $with = config_for({ %$local, cilium => { devices => ['enP7s7.30'] } });
    is_deeply(OCP::Drift->remedy_params($with, 'cilium', '1.20.0')->{helm_values}, $VALUES,
        'cilium: the configured values');
    ok !exists OCP::Drift->remedy_params(config_for($local), 'cilium', '1.20.0')->{helm_values},
        'cilium without cilium:: none';
    ok !exists OCP::Drift->remedy_params($with, 'cert_manager', 'v1.0.0')->{helm_values},
        'another component: none';
};

done_testing;

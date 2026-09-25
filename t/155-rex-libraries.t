#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use YAML::XS ();

use Rex::Rancher::Node;
use Rex::Rancher::Server;
use Rex::Rancher::Agent;
use Rex::Rancher::Cilium;
use Rex::Rancher::Distribution;
use Rex::GPU::NVIDIA;
use Rex::GPU::NVIDIA::Setup::UbuntuDrivers;

#
# k155: the RKE2/K3s install, Cilium with the Gateway API CRDs, node
# preparation and the NVIDIA driver moved out of share/Rexfile into
# Rex::Rancher and Rex::GPU. The rest of the suite runs the Rexfile against
# recorders (t/lib/OCPTest/Rexfile.pm) and holds what OCP hands the libraries.
# This file holds the other half: the guarantees OCP used to implement itself
# and now takes from the REAL libraries -- the ones the earlier tests
# (k150/k154, k156, k157, k160, k164, k178, k182, k185, k191, the multi-arch
# fix) were written for. When a library release moves one of them, this is
# where it shows.
#
# 0.003 took over what OCP still did itself on top of 0.002: NTP that leaves a
# synchronised clock alone, the /etc/hosts entry without a domain, locale-gen
# (rex-rancher k42), cluster_cidr (k41), the join address in the agent's error
# (k44), the running Cilium's IPAM mode, pool and API address, the readiness
# wait and the CRD-only Gateway API apply (k43), and the Ubuntu driver chosen
# through ubuntu-drivers (rex-gpu k69).
#
# Some claims reach into the libraries' private helpers: those are where the
# behaviour lives, and a renamed helper is exactly the moment to re-check
# the guarantee (0.003 moved the RKE2/K3s differences into
# Rex::Rancher::Distribution). Nothing here touches a host: every Rex command
# a helper would run is replaced in the library's own package.
#

no warnings 'redefine';

# The libraries narrate through Rex::Logger; collected, so warnings can be read.
my @LOG;
*Rex::Logger::info = sub { push @LOG, [ @_ ] };

cmp_ok $Rex::Rancher::Server::VERSION, '>=', 0.003, 'Rex::Rancher 0.003 or later';
cmp_ok $Rex::GPU::NVIDIA::VERSION,     '>=', 0.003, 'Rex::GPU 0.003 or later';

subtest 'every entry point the Rexfile calls exists' => sub {
    for my $fq (qw(
        Rex::Rancher::Node::prepare_node
        Rex::Rancher::Server::install_server
        Rex::Rancher::Agent::install_agent
        Rex::Rancher::Cilium::install_cilium
        Rex::Rancher::Cilium::upgrade_cilium
        Rex::Rancher::Cilium::ensure_gateway_api_crds
        Rex::GPU::NVIDIA::install_driver
        Rex::GPU::NVIDIA::install_container_toolkit
        Rex::GPU::NVIDIA::verify_nvidia
    )) {
        no strict 'refs';
        ok defined &{$fq}, $fq;
    }
    ok 'Rex::GPU::NVIDIA::Setup::UbuntuDrivers'->isa(Rex::GPU::NVIDIA->setup_base_class),
        'the Ubuntu setup install_nvidia names is a Rex::GPU::NVIDIA::Setup';
};

# The shipped Rexfile, loaded with the real libraries: it compiles, and its
# option builders can be fed to the libraries' own validation below.
my $SANDBOX = 'Rex155::Rexfile';
my $src = path(__FILE__)->parent->parent->child('share', 'Rexfile')->slurp_raw;
ok eval("package $SANDBOX;\n#line 1 share/Rexfile\n$src\n;1"),
    'share/Rexfile loads against the real Rex::Rancher and Rex::GPU'
    or BAIL_OUT("share/Rexfile does not load: $@");
my $cilium_opts = $SANDBOX->can('_cilium_opts');

sub dist { Rex::Rancher::Distribution->new_for(@_) }

# --- prepare_node (rex-rancher k42) -------------------------------------------

# Runs the real prepare_node against a host described by %h; returns the
# commands, packages and /etc/hosts entries it asked for.
sub prepare_node_on {
    my ($opts, %h) = @_;
    my (@cmds, @pkgs, @hosts);
    local *Rex::Rancher::Node::run = sub {
        my ($cmd) = @_;
        push @cmds, $cmd;
        $? = 0;
        return $h{synced} ? "yes\n" : "no\n" if $cmd =~ /NTPSynchronized/;
        return $h{timesyncd} ? "active\n" : "inactive\n" if $cmd =~ /is-active systemd-timesyncd/;
        return '';
    };
    local *Rex::Rancher::Node::pkg = sub {
        push @pkgs, @{ $_[0] };
        die "E: Unable to locate package chrony\n" if $h{chrony_fails} && grep { $_ eq 'chrony' } @{ $_[0] };
        1;
    };
    local *Rex::Rancher::Node::host_entry = sub { push @hosts, [ @_ ]; 1 };
    local *Rex::Rancher::Node::get_host   = sub { $h{named} ? { ip => '203.0.113.7' } : () };
    local *Rex::Rancher::Node::file       = sub { 1 };
    local *Rex::Rancher::Node::delete_lines_matching = sub { 1 };
    local *Rex::Rancher::Node::is_debian  = sub { 1 };
    local *Rex::Rancher::Node::can_run    = sub { $_[0] eq 'locale-gen' || $_[0] =~ /ctl$/ ? 1 : 0 };
    @LOG = ();
    Rex::Rancher::Node::prepare_node(%$opts);
    return { cmds => \@cmds, pkgs => \@pkgs, hosts => \@hosts };
}

subtest 'prepare_node: a synchronised clock is left alone' => sub {
    my $r = prepare_node_on({ ntp => 1 }, synced => 1);
    ok !(grep { $_ eq 'chrony' } @{ $r->{pkgs} }), 'no chrony install';
};

subtest 'prepare_node: an unsynchronised clock gets chrony' => sub {
    my $r = prepare_node_on({ ntp => 1 });
    ok((grep { $_ eq 'chrony' } @{ $r->{pkgs} }), 'chrony');
    ok((grep { /systemctl (?:enable|start) chronyd/ } @{ $r->{cmds} }), 'enabled and started');
};

subtest 'prepare_node: a failed chrony install is not fatal' => sub {
    my $r = eval { prepare_node_on({ ntp => 1 }, chrony_fails => 1, timesyncd => 1) };
    ok $r, 'goes on' or return diag $@;
    ok((grep { /enable --now systemd-timesyncd/ } @{ $r->{cmds} }), 'falls back to systemd-timesyncd');

    $r = eval { prepare_node_on({ ntp => 1 }, chrony_fails => 1) };
    ok $r, 'goes on with neither' or return diag $@;
    ok((grep { ($_->[1] // '') eq 'warn' && $_->[0] =~ /NO TIME SYNCHRONIZATION/ } @LOG),
        'with a warning that no time synchronisation is active');
};

subtest 'prepare_node: ntp => 0 skips it' => sub {
    my $r = prepare_node_on({ ntp => 0 });
    ok !(grep { /NTPSynchronized/ } @{ $r->{cmds} }), 'nothing asked';
    ok !(grep { $_ eq 'chrony' } @{ $r->{pkgs} }), 'nothing installed';
};

subtest 'prepare_node: /etc/hosts without a domain' => sub {
    my $r = prepare_node_on({ hostname => 'raichu' });
    is scalar @{ $r->{hosts} }, 1, 'one entry' or return;
    my ($name, %o) = @{ $r->{hosts}[0] };
    is $name, 'raichu', 'for the hostname';
    is $o{ip}, '127.0.1.1', 'on 127.0.1.1';

    $r = prepare_node_on({ hostname => 'raichu' }, named => 1);
    is scalar @{ $r->{hosts} }, 0, 'a line that names the host already is left alone';
};

subtest 'prepare_node: the locale is generated before it is set' => sub {
    my $r = prepare_node_on({ locale => 'de_DE.UTF-8' });
    my ($gen) = grep { $r->{cmds}[$_] =~ /^locale-gen de_DE\.UTF-8$/ } 0 .. $#{ $r->{cmds} };
    my ($set) = grep { $r->{cmds}[$_] =~ /localectl set-locale LANG=de_DE\.UTF-8/ } 0 .. $#{ $r->{cmds} };
    ok defined $gen, 'locale-gen';
    ok defined $set && $set > $gen, 'then set';
    ok((grep { m{/etc/locale\.gen} } @{ $r->{cmds} }), 'enabled in /etc/locale.gen first');
};

subtest 'prepare_node: OCP\'s defaults pass, garbage dies before the host is touched' => sub {
    ok eval { prepare_node_on({ timezone => 'UTC', locale => 'en_US.UTF-8' }); 1 }, 'UTC, en_US.UTF-8'
        or diag $@;
    ok eval { prepare_node_on({ timezone => 'Europe/Berlin', locale => 'de_DE.utf8' }); 1 },
        'Europe/Berlin, de_DE.utf8' or diag $@;
    for my $bad ([ locale => 'en_US.UTF-8; rm -rf /' ], [ timezone => "UTC'; reboot" ]) {
        my $r;
        ok !eval { $r = prepare_node_on({ @$bad }); 1 }, "$bad->[0] '$bad->[1]' dies";
        like $@, qr/^\Q$bad->[0]\E must look like/, 'saying what it must look like';
    }
};

# --- server config.yaml (k8, k137, k178, k182, rke2 ingress) -------------------

sub server_config { YAML::XS::Load(YAML::XS::Dump(Rex::Rancher::Server::_build_server_config(@_))) }

subtest 'rke2 server: Cilium-only, no bundled ingress, server only when joining' => sub {
    my $c = server_config(dist('rke2'), 'tok', undef, [ '10.0.0.1', 'cp.example.com' ], undef, 1, 'police1', undef);
    is $c->{cni}, 'none', 'cni: none';
    ok $c->{'disable-kube-proxy'}, 'disable-kube-proxy';
    is_deeply $c->{disable}, [qw( rke2-ingress-nginx rke2-traefik rke2-traefik-crd )],
        'no bundled ingress controller (RKE2 v1.36 ships Traefik)';
    is_deeply $c->{'tls-san'}, [ '10.0.0.1', 'cp.example.com' ], 'one tls-san per address (k137)';
    is $c->{'node-name'}, 'police1', 'node-name';
    is $c->{token}, 'tok', 'token';
    ok !exists $c->{server}, 'no server: -- cluster-init (k8)';

    $c = server_config(dist('rke2'), 'tok', 'https://10.0.0.1:9345', undef, undef, 1, undef, undef);
    is $c->{server}, 'https://10.0.0.1:9345', 'server: when joining';
};

subtest 'k3s server: Flannel, network policy and kube-proxy off (k178)' => sub {
    my $c = server_config(dist('k3s'), 'tok', undef, ['203.0.113.7'], undef, 1, 'police1', undef);
    is $c->{'flannel-backend'}, 'none', 'flannel-backend: none';
    ok $c->{'disable-network-policy'}, 'disable-network-policy';
    ok $c->{'disable-kube-proxy'}, 'disable-kube-proxy';
    is_deeply [ sort @{ $c->{disable} } ], [qw( servicelb traefik )], 'traefik, servicelb';
};

subtest 'cluster_cidr is config.yaml\'s cluster-cidr on both distributions (k182, rex-rancher k41)' => sub {
    for my $d (qw( rke2 k3s )) {
        my $c = server_config(dist($d), 'tok', undef, undef, undef, 1, undef, undef, '172.20.0.0/16');
        is $c->{'cluster-cidr'}, '172.20.0.0/16', "$d: the value passed";
    }
    ok !exists server_config(dist('rke2'), 'tok', undef, undef, undef, 1, undef, undef)->{'cluster-cidr'},
        'rke2 without it: none written (OCP always passes one)';

    is(Rex::Rancher::Distribution->check_cluster_cidr('10.42.0.0/16'), '10.42.0.0/16', 'a CIDR passes');
    ok !eval { Rex::Rancher::Distribution->check_cluster_cidr('10.42.0.0/16; rm -rf /'); 1 },
        'anything else dies';
    like $@, qr/cluster_cidr must be one IPv4 CIDR/, 'and says why';

    my @host;
    local *Rex::Rancher::Server::run  = sub { push @host, $_[0]; $? = 0; '' };
    local *Rex::Rancher::Server::file = sub { push @host, $_[0]; 1 };
    local *Rex::Commands::Run::run    = sub { push @host, $_[0]; $? = 0; '' };
    ok !eval { Rex::Rancher::Server::install_server(distribution => 'rke2', token => 't',
                   cluster_cidr => '10.42.0.0/16; rm -rf /'); 1 },
        'install_server refuses it';
    is_deeply \@host, [], 'before the host is touched: no pod CIDR that is no CIDR reaches a node';
};

# --- the token (k150/k154, k156) -----------------------------------------

subtest 'no token: the sealed one is reused, only a fresh server gets a new one' => sub {
    my ($existing, @runs);
    local *Rex::Rancher::Server::run = sub {
        my ($cmd) = @_;
        push @runs, $cmd;
        if ($cmd =~ m{^cat /var/lib/rancher/rke2/server/token}) {
            $? = defined $existing ? 0 : 1;
            return $existing;
        }
        $? = 0;
        return 'FRESHFRESHFRESHFRESHFRESHFRESHFRESHFRESH';
    };

    $existing = "sealed-token\n";
    is Rex::Rancher::Server::_resolve_token(dist('rke2'), undef), 'sealed-token',
        'the server/token the datastore is sealed with';
    ok !(grep { /urandom/ } @runs), 'and nothing is generated';

    $existing = undef;
    like Rex::Rancher::Server::_resolve_token(dist('rke2'), undef), qr/^FRESH/, 'a fresh server gets one';
    is Rex::Rancher::Server::_resolve_token(dist('rke2'), 'passed'), 'passed', 'a passed token wins';
    is dist('k3s')->server_token, '/var/lib/rancher/k3s/server/token', 'k3s reads its own server/token';
};

subtest 'no installer line carries the token' => sub {
    my $k3s = dist('k3s')->script_install_cmd(undef, 'v1.36.4+k3s1');
    unlike $k3s, qr/TOKEN/, 'k3s server';
    like   $k3s, qr/INSTALL_K3S_SKIP_START=true/, 'k3s server: the script does not start it';
    for my $d (qw( k3s rke2 )) {
        my $cmd = dist($d, role => 'agent')->script_install_cmd('https://10.0.0.1:9345', 'v1');
        unlike $cmd, qr/TOKEN/, "$d agent";
    }
    like dist('k3s', role => 'agent')->script_install_cmd('https://10.0.0.1:6443', 'v1'),
        qr/INSTALL_K3S_SKIP_START=true/, 'k3s agent: the script does not start it (k185)';
};

subtest 'config.yaml is written 0600 from the first byte' => sub {
    my @seen;
    local *Rex::Commands::File::get_tmp_file_name = sub { '/etc/rancher/k3s/.rex.tmp.config.yaml' };
    local *Rex::Commands::Run::run   = sub { push @seen, [ run => $_[0] ]; $? = 0; '' };
    local *Rex::Commands::File::file = sub { push @seen, [ file => $_[0] ]; 1 };
    dist('k3s')->write_secret_file('/etc/rancher/k3s/config.yaml', "token: t\n");
    like $seen[0][1], qr/^install -m 600 -o root -g root \/dev\/null \S*config\.yaml/,
        'the tmp file Rex writes through exists 0600 first';
    is $seen[1][0], 'file', 'then the content';
    like $seen[2][1], qr/chmod 600 \/etc\/rancher\/k3s\/config\.yaml/, 'then the mode is asserted';
};

# --- bounded service start (k185) -----------------------------------------

subtest 'a unit that never gets active dies with its state and journal' => sub {
    my @states = qw( activating activating );
    local *Rex::Commands::Run::run = sub {
        my ($cmd) = @_;
        $? = 0;
        return shift(@states) // 'activating' if $cmd =~ /is-active/;
        return 'level=error msg="failed to get CA certs"' if $cmd =~ /journalctl/;
        return '';
    };
    ok !eval { dist('k3s', role => 'agent')->wait_for_service(attempts => 2, interval => 0); 1 },
        'dies';
    like $@, qr/k3s-agent\.service/, 'names the unit';
    like $@, qr/activating/, 'the state';
    like $@, qr/failed to get CA certs/, 'the journal';
};

sub enable_agent {
    my ($d, $server, $state) = @_;
    my @cmds;
    # Agent's own `run` calls land here too: Rex::Exporter's imports resolve by name.
    local *Rex::Commands::Run::run = sub {
        my ($cmd) = @_;
        push @cmds, $cmd;
        $? = 0;
        return $state if $cmd =~ /is-active/;
        return 'level=error msg="failed to get CA certs"' if $cmd =~ /journalctl/;
        return '';
    };
    my $ok = eval { Rex::Rancher::Agent::_enable_service(dist($d, role => 'agent'), $server); 1 };
    return ($ok, $@, \@cmds);
}

subtest 'agents are started without blocking' => sub {
    for my $t ([ k3s => 'restart --no-block k3s-agent.service' ], [ rke2 => 'start --no-block rke2-agent.service' ]) {
        my ($d, $want) = @$t;
        my ($ok, $err, $cmds) = enable_agent($d, 'https://10.0.0.1:9345', 'active');
        ok $ok, "$d: started" or diag $err;
        ok((grep { $_ eq "systemctl $want" } @$cmds), "$d: systemctl $want");
    }
};

subtest 'a join that never comes up names the address it joins through (rex-rancher k44)' => sub {
    for my $d (qw( k3s rke2 )) {
        my ($ok, $err) = enable_agent($d, 'https://ocpt-cp.vm:6443', 'failed');
        ok !$ok, "$d: dies";
        like $err, qr/$d-agent\.service is failed/, 'names the unit and its state';
        like $err, qr{via https://ocpt-cp\.vm:6443 -- check that this node can reach that address},
            'names the join URL';
        like $err, qr/failed to get CA certs/, 'carries the journal';
    }
};

# --- the NVIDIA runtime PATH for RKE2 ---------------------------------------

subtest 'the runtime PATH goes to /etc/default/rke2-*, never k3s' => sub {
    is dist('rke2')->env_file, '/etc/default/rke2-server', 'rke2 server';
    is dist('rke2', role => 'agent')->env_file, '/etc/default/rke2-agent', 'rke2 agent';
    ok !defined dist('k3s')->env_file, 'no env file for k3s';
    like dist('rke2')->env_with_runtime_path("FOO=1\n"), qr/^FOO=1\nPATH=\/usr\/local\/sbin:/m,
        'a PATH line, other lines kept';
};

# --- artifacts for the node's architecture ----------------------------------

subtest 'release artifacts are named by the node\'s GOARCH' => sub {
    my $D = 'Rex::Rancher::Distribution';
    is $D->goarch("x86_64\n"), 'amd64', 'x86_64 is amd64';
    is $D->goarch("aarch64\n"), 'arm64', 'aarch64 is arm64 -- the DGX Spark case';
    ok !eval { $D->goarch('riscv64'); 1 }, 'an unknown one dies instead of guessing';
    my $spec = dist('rke2')->artifact_spec('arm64', 'v1.36.4+rke2r1');
    is $spec->{asset}, 'rke2.linux-arm64.tar.gz', 'the RKE2 tarball';
    is $spec->{sums}, 'sha256sum-arm64.txt', 'its checksum file';
    like $spec->{asset_url}, qr/v1\.36\.4%2Brke2r1/, 'the + escaped in the URL';
};

# --- Cilium: OCP's options against the library (k157, k164, k178, k182) --------

# A Kubernetes::REST stand-in: objects by "Kind/name"; anything else is a 404,
# in the words Kubernetes::REST uses for one.
package Obj {
    our $AUTOLOAD;
    my %RAW = map { $_ => 1 } qw( data annotations labels );
    sub new { my ($c, $h) = @_; bless { %$h }, $c }
    sub AUTOLOAD {
        my ($s) = @_;
        (my $k = $AUTOLOAD) =~ s/.*:://;
        return if $k eq 'DESTROY';
        my $v = $s->{$k};
        return $v if $RAW{$k} || !ref $v;
        return ref $v eq 'HASH' ? Obj->new($v) : [ map { ref $_ eq 'HASH' ? Obj->new($_) : $_ } @$v ];
    }
}
package FakeApi {
    sub new { my ($c, %o) = @_; bless { objects => {}, patched => [], %o }, $c }
    sub list { Obj->new({ items => [] }) }
    sub get {
        my ($s, $kind, $name) = @_;
        my $o = $s->{objects}{"$kind/$name"}
            or die "Kubernetes API error (GET $kind/$name): 404 Not Found\n";
        return Obj->new($o);
    }
    sub patch { my ($s, @a) = @_; push @{ $s->{patched} }, [@a]; 1 }
}
package main;

my %pins = (version => '1.20.0', cli_version => 'v0.19.7', gateway_api_version => 'v1.6.1',
            kubeconfig => '/tmp/kc.yaml', wait_duration => 600);

# What the library makes of OCP's options on a cluster that runs $running
# (the shape _read_running returns; {} is no Cilium).
sub adopted {
    my ($running, %o) = @_;
    my $opts = Rex::Rancher::Cilium::_resolve_opts($cilium_opts->(%pins, %o));
    Rex::Rancher::Cilium::_adopt_running($opts, $running);
    Rex::Rancher::Cilium::_require_k8s_service_host($opts);
    return $opts;
}

subtest 'a fresh Cilium: cluster-pool on pod_cidr, on both distributions' => sub {
    my $o = adopted({}, distribution => 'rke2', cluster_cidr => '172.20.0.0/16');
    ok $o->{values}{kubeProxyReplacement}, 'kube-proxy replacement';
    is $o->{values}{k8sServiceHost}, '127.0.0.1', 'the API on 127.0.0.1:6443, served on every RKE2 node';
    is $o->{values}{ipam}{mode}, 'cluster-pool',
        'rke2: cluster-pool -- OCP overrides the library\'s rke2 default (kubernetes)';
    is_deeply $o->{values}{ipam}{operator}{clusterPoolIPv4PodCIDRList}, ['172.20.0.0/16'],
        'the pool is pod_cidr -- not Cilium\'s 10.0.0.0/8';
    ok $o->{values}{gatewayAPI}{enabled}, 'Gateway API';
    is $o->{gateway_api_channel}, 'standard', 'standard channel (k157)';
    is Rex::Rancher::Cilium::_gateway_api_url('v1.6.1', $o->{gateway_api_channel}),
        'https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/standard-install.yaml',
        'the standard bundle of the pin';
    ok $o->{wait}, 'waited on';
    is $o->{wait_duration}, 600, 'for the duration OCP asks';

    $o = adopted({}, distribution => 'k3s', cluster_cidr => '172.20.0.0/16', k8s_service_host => '203.0.113.7');
    is $o->{values}{ipam}{mode}, 'cluster-pool', 'k3s: cluster-pool';
    is_deeply $o->{values}{ipam}{operator}{clusterPoolIPv4PodCIDRList}, ['172.20.0.0/16'], 'k3s: pod_cidr';
};

subtest 'a running Cilium keeps its pool, whatever pod_cidr says (k182)' => sub {
    @LOG = ();
    my $o = adopted({ ipam_mode => 'cluster-pool', pool => ['10.0.0.0/8'] },
                    distribution => 'rke2', cluster_cidr => '10.42.0.0/16');
    is $o->{values}{ipam}{mode}, 'cluster-pool', 'the mode';
    is_deeply $o->{values}{ipam}{operator}{clusterPoolIPv4PodCIDRList}, ['10.0.0.0/8'],
        'the running pool, not pod_cidr';
    ok((grep { $_->[0] =~ /cluster_cidr 10\.42\.0\.0\/16 is not applied/ } @LOG), 'and says so');

    $o = adopted({ ipam_mode => 'cluster-pool', pool => ['10.0.0.0/8'] }, distribution => 'rke2');
    is_deeply $o->{values}{ipam}{operator}{clusterPoolIPv4PodCIDRList}, ['10.0.0.0/8'],
        'an upgrade (no cluster_cidr) keeps it too';
};

subtest 'a running Cilium in another IPAM mode is refused, never switched' => sub {
    ok !eval { adopted({ ipam_mode => 'kubernetes' }, distribution => 'rke2'); 1 }, 'dies';
    like $@, qr/Cilium runs ipam\.mode kubernetes .*cannot change the IPAM mode/s, 'naming both modes';
};

subtest 'k3s: the control plane address, never localhost (k178)' => sub {
    my $o = adopted({}, distribution => 'k3s', k8s_service_host => '203.0.113.7');
    is $o->{values}{k8sServiceHost}, '203.0.113.7', 'k8sServiceHost';
    is $o->{values}{k8sServicePort}, '6443', 'port 6443';

    $o = adopted({ k8s_service_host => '198.51.100.4' }, distribution => 'k3s');
    is $o->{values}{k8sServiceHost}, '198.51.100.4', 'none passed: the running agents\' address';

    ok !eval { adopted({}, distribution => 'k3s', k8s_service_host => '127.0.0.1'); 1 },
        'a loopback address is refused';
    ok !eval { adopted({}, distribution => 'k3s'); 1 }, 'none passed and none running: refused';
    like $@, qr/k8s_service_host/, 'naming the option';

    my ($o_rke2) = { $cilium_opts->(%pins, distribution => 'rke2', k8s_service_host => '203.0.113.7') };
    ok !exists $o_rke2->{k8s_service_host}, 'rke2: OCP::Rex\'s address is not passed (the library refuses it)';
};

subtest 'k3s without an address: install_cilium dies before the node is touched' => sub {
    my @host;
    local *Rex::Rancher::Cilium::_api = sub { FakeApi->new };
    local *Rex::Rancher::Cilium::run  = sub { push @host, $_[0]; $? = 0; '' };
    local *Rex::Rancher::Cilium::file = sub { push @host, $_[0]; 1 };
    ok !eval { Rex::Rancher::Cilium::install_cilium($cilium_opts->(%pins, distribution => 'k3s')); 1 },
        'dies';
    like $@, qr/k8s_service_host/, 'naming the option';
    is_deeply \@host, [], 'no command, no file on the node';
};

subtest 'upgrade_cilium needs the API, and gets it' => sub {
    ok !eval { Rex::Rancher::Cilium::upgrade_cilium(version => '1.20.0'); 1 }, 'without kubeconfig: dies';
    like $@, qr/upgrade_cilium needs kubeconfig/, 'saying why';
};

subtest 'a Cilium that never gets ready fails, naming its state (k178)' => sub {
    my %ds = (metadata => { generation => 2 },
              status   => { desiredNumberScheduled => 5, numberReady => 0, updatedNumberScheduled => 5,
                            observedGeneration => 2 });
    my %op = (metadata => { generation => 1 }, spec => { replicas => 1 },
              status   => { readyReplicas => 1, updatedReplicas => 1, observedGeneration => 1 });
    my $api = FakeApi->new(objects => { 'DaemonSet/cilium' => \%ds, 'Deployment/cilium-operator' => \%op });
    local *Rex::Rancher::Cilium::_sleep = sub {};
    ok !eval { Rex::Rancher::Cilium::_wait_ready($api, 10); 1 }, 'dies';
    like $@, qr/Cilium was not ready within 10s: cilium 0\/5 ready/, 'with the duration and the state';

    $ds{status}{numberReady} = 5;
    ok eval { Rex::Rancher::Cilium::_wait_ready($api, 10); 1 }, 'ready: returns' or diag $@;

    my $err_api = FakeApi->new;
    no warnings 'once';
    local *FakeApi::get = sub { die "Kubernetes API error (GET x): 403 Forbidden\n" };
    ok !eval { Rex::Rancher::Cilium::_wait_ready($err_api, 600); 1 }, 'an API error dies at once';
    like $@, qr/403/, 'with it';
};

subtest 'the bundle is skipped only when version and channel match (k164)' => sub {
    my %ann = ('gateway.networking.k8s.io/bundle-version' => 'v1.6.1',
               'gateway.networking.k8s.io/channel'        => 'standard');
    ok !Rex::Rancher::Cilium::_gateway_api_needs_apply(\%ann, 'v1.6.1', 'standard'), 'same: skipped';
    ok Rex::Rancher::Cilium::_gateway_api_needs_apply(\%ann, 'v1.7.0', 'standard'), 'new pin: applied';
    ok Rex::Rancher::Cilium::_gateway_api_needs_apply({ %ann, 'gateway.networking.k8s.io/channel' => 'experimental' },
        'v1.6.1', 'standard'), 'experimental on the cluster: applied';
    ok Rex::Rancher::Cilium::_gateway_api_needs_apply(undef, 'v1.6.1', 'standard'), 'missing: applied';
};

subtest 'ensure_gateway_api_crds: the CRDs alone, the operator bounced when they changed' => sub {
    my $api = FakeApi->new(objects => { 'Deployment/cilium-operator' => { spec => { replicas => 1 } } });
    local *Rex::Rancher::Cilium::_api = sub { $api };
    my @seen;
    local *Rex::Rancher::Cilium::_ensure_gateway_api_crds = sub { push @seen, [ @_[1, 2] ]; $api->{apply} };
    local *Rex::Rancher::Cilium::run = sub { die "the node is not used\n" };

    $api->{apply} = 1;
    is Rex::Rancher::Cilium::ensure_gateway_api_crds(kubeconfig => '/k', version => 'v1.6.1', channel => 'standard'),
        1, 'applied';
    is_deeply $seen[0], [ 'v1.6.1', 'standard' ], 'the pin, standard channel';
    is scalar @{ $api->{patched} }, 1, 'cilium-operator restarted';
    is_deeply [ @{ $api->{patched}[0] }[0, 1] ], [ 'Deployment', 'cilium-operator' ], 'the operator Deployment';

    $api->{apply} = 0; $api->{patched} = [];
    is Rex::Rancher::Cilium::ensure_gateway_api_crds(kubeconfig => '/k', version => 'v1.6.1', channel => 'standard'),
        0, 'already current: nothing applied';
    is scalar @{ $api->{patched} }, 0, 'and no restart';

    ok !eval { Rex::Rancher::Cilium::ensure_gateway_api_crds(kubeconfig => '/k', channel => 'standard'); 1 },
        'no version: dies';
};

subtest 'a deployed release with an explicit other IPAM mode is refused' => sub {
    ok !eval {
        Rex::Rancher::Cilium::_release_action(
            { status => 'deployed', chart_version => '1.19.0', config => { ipam => { mode => 'kubernetes' } } },
            '1.20.0', { ipam => { mode => 'cluster-pool' } });
        1;
    }, 'dies before cilium upgrade';
    like $@, qr/ipam\.mode/, 'naming the IPAM mode';
};

# --- the Ubuntu driver (k191, rex-gpu k69) ------------------------------------

# Setup::UbuntuDrivers on a DGX-Spark-shaped Ubuntu host, every host command
# answered by %answer (first matching pattern wins; the value is [out, exit]).
sub ubuntu_setup {
    my (%answer) = @_;
    my @cmds;
    my $setup = Rex::GPU::NVIDIA::Setup::UbuntuDrivers->new(
        gpus    => [ { device_id => '2e12', name => 'NVIDIA GPU [10de:2e12]' } ],
        os      => 'Ubuntu',
        release => '24.04',
        arch    => 'arm64',
        kernel  => '6.17.0-1029-nvidia',
    );
    my $run = sub {
        my ($cmd) = @_;
        push @cmds, $cmd;
        for my $re (keys %answer) {
            next unless $cmd =~ $re;
            my ($out, $exit) = @{ $answer{$re} };
            $? = ($exit // 0) << 8;
            return $out;
        }
        $? = 0;
        return '';
    };
    return ($setup, \@cmds, $run);
}

subtest 'Ubuntu: headers for the running kernel only' => sub {
    my ($setup) = ubuntu_setup();
    is_deeply [ $setup->kernel_packages ], ['linux-headers-6.17.0-1029-nvidia'],
        'linux-headers-$(uname -r) -- never linux-headers-generic, a different kernel on a vendor kernel';
};

subtest 'Ubuntu: ubuntu-drivers names the package, of the flavour the GPU needs' => sub {
    my ($setup, $cmds, $run) = ubuntu_setup(
        qr/ubuntu-drivers list --gpgpu/ => [ "nvidia-driver-580-server, (kernel modules provided by linux-modules-nvidia-580-server-nvidia)\n"
                                           . "nvidia-driver-580-server-open\nnvidia-driver-590-server-open\n", 0 ],
    );
    local *Rex::GPU::NVIDIA::Setup::run_cmd = sub { shift; $run->(@_) };
    my $plan = $setup->plan;
    is $plan->{source}{kernel_module}, 'open', 'a GB10 gets the open kernel module (Rex::GPU\'s choice)';
    $setup->resolve_plan($plan);
    is_deeply $plan->{source}{packages}, ['nvidia-driver-590-server-open'],
        'the newest -open package ubuntu-drivers lists for it';
    ok((grep { /ubuntu-drivers list --gpgpu/ } @$cmds), 'read-only: ubuntu-drivers list');
    ok !(grep { /ubuntu-drivers install/ } @$cmds), 'ubuntu-drivers install is never run';
};

subtest 'Ubuntu: no package is guessed when ubuntu-drivers cannot name one' => sub {
    for my $case ([ 'fails' => [ '', 1 ] ], [ 'names nothing for the card' => [ "nvidia-driver-580-server\n", 0 ] ]) {
        my ($label, $answer) = @$case;
        my ($setup, $cmds, $run) = ubuntu_setup(
            qr/^nvidia-smi -L/                => [ 'NVIDIA-SMI has failed', 9 ],
            qr/ubuntu-drivers list --gpgpu/  => $answer,
        );
        local *Rex::GPU::NVIDIA::Setup::run_cmd = sub { shift; $run->(@_) };
        ok !eval { $setup->install; 1 }, "ubuntu-drivers $label: dies";
        like $@, qr/No driver package was installed/, 'and says nothing was installed';
        ok !(grep { /apt-get.* install .*(?:nvidia-driver|linux-headers)/ } @$cmds),
            'no driver package, no headers went in';
    }
};

subtest 'Ubuntu: a working driver is left alone' => sub {
    my ($setup, $cmds, $run) = ubuntu_setup(
        qr/^nvidia-smi -L/ => [ "GPU 0: NVIDIA GB10 (UUID: GPU-1)\n", 0 ],
    );
    local *Rex::GPU::NVIDIA::Setup::run_cmd = sub { shift; $run->(@_) };
    is $setup->install, 0, 'nothing installed';
    ok !(grep { /ubuntu-drivers|apt-get/ } @$cmds), 'not even asked';
};

done_testing;

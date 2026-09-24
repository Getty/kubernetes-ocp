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
use Rex::GPU::NVIDIA;

#
# k155: the RKE2/K3s install, Cilium with the Gateway API CRDs, node
# preparation and the NVIDIA driver moved out of share/Rexfile into
# Rex::Rancher and Rex::GPU. The rest of the suite runs the Rexfile against
# recorders (t/lib/OCPTest/Rexfile.pm) and holds what OCP hands the libraries.
# This file holds the other half: the guarantees OCP used to implement itself
# and now takes from the REAL libraries -- the ones the earlier tests
# (k150/k154, k156, k157, k160, k178, k185, the multi-arch fix) were written
# for. When a library release moves one of them, this is where it shows.
#
# Some claims reach into the libraries' private helpers: those are where the
# behaviour lives, and a renamed helper is exactly the moment to re-check
# the guarantee. Nothing here touches a host: every Rex command a helper
# would run is replaced in the library's own package.
#

no warnings 'redefine';

# The libraries narrate through Rex::Logger; nothing to see in a test run.
*Rex::Logger::info = sub {};

cmp_ok $Rex::Rancher::Server::VERSION, '>=', 0.002, 'Rex::Rancher 0.002 or later';
cmp_ok $Rex::GPU::NVIDIA::VERSION,     '>=', 0.002, 'Rex::GPU 0.002 or later';

subtest 'every entry point the Rexfile calls exists' => sub {
    for my $fq (qw(
        Rex::Rancher::Node::prepare_node
        Rex::Rancher::Server::install_server
        Rex::Rancher::Agent::install_agent
        Rex::Rancher::Cilium::install_cilium
        Rex::Rancher::Cilium::upgrade_cilium
        Rex::GPU::NVIDIA::install_driver
        Rex::GPU::NVIDIA::install_container_toolkit
        Rex::GPU::NVIDIA::verify_nvidia
    )) {
        no strict 'refs';
        ok defined &{$fq}, $fq;
    }
};

# The shipped Rexfile, loaded with the real libraries: it compiles, and its
# option builders can be fed to the libraries' own validation below.
my $SANDBOX = 'Rex155::Rexfile';
my $src = path(__FILE__)->parent->parent->child('share', 'Rexfile')->slurp_raw;
ok eval("package $SANDBOX;\n#line 1 share/Rexfile\n$src\n;1"),
    'share/Rexfile loads against the real Rex::Rancher and Rex::GPU'
    or BAIL_OUT("share/Rexfile does not load: $@");
my $cilium_opts = $SANDBOX->can('_cilium_opts');

# --- server config.yaml (k8, k137, k178, rke2 ingress) ----------------------

sub server_config { YAML::XS::Load(YAML::XS::Dump(Rex::Rancher::Server::_build_server_config(@_))) }

subtest 'rke2 server: Cilium-only, no bundled ingress, server only when joining' => sub {
    my $c = server_config('rke2', 'tok', undef, [ '10.0.0.1', 'cp.example.com' ], undef, 1, 'police1', undef);
    is $c->{cni}, 'none', 'cni: none';
    ok $c->{'disable-kube-proxy'}, 'disable-kube-proxy';
    is_deeply $c->{disable}, [qw( rke2-ingress-nginx rke2-traefik rke2-traefik-crd )],
        'no bundled ingress controller (RKE2 v1.36 ships Traefik)';
    is_deeply $c->{'tls-san'}, [ '10.0.0.1', 'cp.example.com' ], 'one tls-san per address (k137)';
    is $c->{'node-name'}, 'police1', 'node-name';
    is $c->{token}, 'tok', 'token';
    ok !exists $c->{server}, 'no server: -- cluster-init (k8)';

    $c = server_config('rke2', 'tok', 'https://10.0.0.1:9345', undef, undef, 1, undef, undef);
    is $c->{server}, 'https://10.0.0.1:9345', 'server: when joining';
    ok !exists $c->{'cluster-cidr'}, 'no cluster-cidr: OCP states it in config.yaml.d (rex-rancher k41)';
};

subtest 'k3s server: Flannel, network policy and kube-proxy off (k178)' => sub {
    my $c = server_config('k3s', 'tok', undef, ['203.0.113.7'], undef, 1, 'police1', undef);
    is $c->{'flannel-backend'}, 'none', 'flannel-backend: none';
    ok $c->{'disable-network-policy'}, 'disable-network-policy';
    ok $c->{'disable-kube-proxy'}, 'disable-kube-proxy';
    is_deeply [ sort @{ $c->{disable} } ], [qw( servicelb traefik )], 'traefik, servicelb';
    is $c->{'cluster-cidr'}, '10.42.0.0/16',
        'cluster-cidr 10.42.0.0/16 -- which OCP\'s config.yaml.d drop-in overrides with pod_cidr';
};

# --- the token (k150/k154, k156) -----------------------------------------

subtest 'no token: the sealed one is reused, only a fresh server gets a new one' => sub {
    my $paths = Rex::Rancher::Server::_paths('rke2');
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
    is Rex::Rancher::Server::_resolve_token($paths, undef), 'sealed-token',
        'the server/token the datastore is sealed with';
    ok !(grep { /urandom/ } @runs), 'and nothing is generated';

    $existing = undef;
    like Rex::Rancher::Server::_resolve_token($paths, undef), qr/^FRESH/, 'a fresh server gets one';
    is Rex::Rancher::Server::_resolve_token($paths, 'passed'), 'passed', 'a passed token wins';
    is Rex::Rancher::Server::_paths('k3s')->{server_token}, '/var/lib/rancher/k3s/server/token',
        'k3s reads its own server/token';
};

subtest 'no installer line carries the token' => sub {
    my $k3s = Rex::Rancher::Server::_k3s_server_install_cmd(Rex::Rancher::Server::_paths('k3s'), undef, 'v1.36.4+k3s1');
    unlike $k3s, qr/TOKEN/, 'k3s server';
    like   $k3s, qr/INSTALL_K3S_SKIP_START=true/, 'k3s server: the script does not start it';
    for my $dist (qw( k3s rke2 )) {
        my $cmd = Rex::Rancher::Agent::_installer_cmd($dist, 'v1', 'https://10.0.0.1:9345');
        unlike $cmd, qr/TOKEN/, "$dist agent";
    }
    like Rex::Rancher::Agent::_installer_cmd('k3s', 'v1', 'https://10.0.0.1:6443'),
        qr/INSTALL_K3S_SKIP_START=true/, 'k3s agent: the script does not start it (k185)';
};

subtest 'config.yaml is written 0600 from the first byte' => sub {
    my @seen;
    local *Rex::Rancher::Server::run  = sub { push @seen, [ run => $_[0] ]; $? = 0; '' };
    local *Rex::Rancher::Server::file = sub { push @seen, [ file => $_[0] ]; 1 };
    Rex::Rancher::Server::_write_secret_file('/etc/rancher/k3s/config.yaml', "token: t\n");
    like $seen[0][1], qr/^install -m 600 -o root -g root \/dev\/null \S*config\.yaml/,
        'the tmp file Rex writes through exists 0600 first';
    is $seen[1][0], 'file', 'then the content';
    like $seen[2][1], qr/chmod 600 \/etc\/rancher\/k3s\/config\.yaml/, 'then the mode is asserted';
};

# --- bounded service start (k185) -----------------------------------------

subtest 'a unit that never gets active dies with its state and journal' => sub {
    my @states = qw( activating activating );
    local *Rex::Rancher::Server::run = sub {
        my ($cmd) = @_;
        $? = 0;
        return shift(@states) // 'activating' if $cmd =~ /is-active/;
        return 'level=error msg="failed to get CA certs"' if $cmd =~ /journalctl/;
        return '';
    };
    ok !eval { Rex::Rancher::Server::_wait_for_service('k3s-agent.service', attempts => 2, interval => 0); 1 },
        'dies';
    like $@, qr/k3s-agent\.service/, 'names the unit';
    like $@, qr/activating/, 'the state';
    like $@, qr/failed to get CA certs/, 'the journal';
};

subtest 'agents are started without blocking' => sub {
    for my $t ([ k3s => 'restart --no-block k3s-agent.service' ], [ rke2 => 'start --no-block rke2-agent.service' ]) {
        my ($dist, $want) = @$t;
        my @cmds;
        local *Rex::Rancher::Agent::run = sub { push @cmds, $_[0]; $? = 0; '' };
        local *Rex::Rancher::Server::_wait_for_service = sub { 1 };
        Rex::Rancher::Agent::_enable_service(Rex::Rancher::Agent::_paths($dist), $dist);
        ok((grep { $_ eq "systemctl $want" } @cmds), "$dist: systemctl $want");
    }
};

# --- the NVIDIA runtime PATH for RKE2 ---------------------------------------

subtest 'the runtime PATH goes to /etc/default/rke2-*, never k3s' => sub {
    is Rex::Rancher::Server::_paths('rke2')->{env_file}, '/etc/default/rke2-server', 'rke2 server';
    ok !exists Rex::Rancher::Server::_paths('k3s')->{env_file}, 'no env file for k3s';
    like Rex::Rancher::Server::_env_with_runtime_path("FOO=1\n"), qr/^FOO=1\nPATH=\/usr\/local\/sbin:/m,
        'a PATH line, other lines kept';
};

# --- artifacts for the node's architecture ----------------------------------

subtest 'release artifacts are named by the node\'s GOARCH' => sub {
    is Rex::Rancher::Server::_goarch("x86_64\n"), 'amd64', 'x86_64 is amd64';
    is Rex::Rancher::Server::_goarch("aarch64\n"), 'arm64', 'aarch64 is arm64 -- the DGX Spark case';
    ok !eval { Rex::Rancher::Server::_goarch('riscv64'); 1 }, 'an unknown one dies instead of guessing';
    my $spec = Rex::Rancher::Server::_artifact_spec('rke2', 'arm64', 'v1.36.4+rke2r1');
    is $spec->{asset}, 'rke2.linux-arm64.tar.gz', 'the RKE2 tarball';
    is $spec->{sums}, 'sha256sum-arm64.txt', 'its checksum file';
    like $spec->{asset_url}, qr/v1\.36\.4%2Brke2r1/, 'the + escaped in the URL';
};

# --- Cilium: OCP's options pass the library's validation (k157, k178, k182) ---

sub resolved { Rex::Rancher::Cilium::_resolve_opts($cilium_opts->(@_)) }

my %pins = (version => '1.20.0', cli_version => 'v0.19.7', gateway_api_version => 'v1.6.1',
            kubeconfig => '/tmp/kc.yaml');

subtest 'rke2: what OCP asks for is what Cilium gets' => sub {
    my $o = resolved(%pins, distribution => 'rke2', pool => ['172.20.0.0/16'],
                     k8s_service_host => 'ignored-on-rke2');
    ok $o->{values}{kubeProxyReplacement}, 'kube-proxy replacement';
    is $o->{values}{k8sServiceHost}, '127.0.0.1', 'the API on 127.0.0.1:6443, served on every RKE2 node';
    is $o->{values}{ipam}{mode}, 'cluster-pool',
        'cluster-pool -- OCP overrides the library\'s rke2 default (kubernetes, rex-rancher k43)';
    is_deeply $o->{values}{ipam}{operator}{clusterPoolIPv4PodCIDRList}, ['172.20.0.0/16'], 'the pool';
    ok $o->{values}{gatewayAPI}{enabled}, 'Gateway API';
    is $o->{gateway_api_channel}, 'standard', 'standard channel';
    is Rex::Rancher::Cilium::_gateway_api_url('v1.6.1', $o->{gateway_api_channel}),
        'https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/standard-install.yaml',
        'the standard bundle of the pin';
};

subtest 'k3s: the control plane address, never localhost' => sub {
    my $o = resolved(%pins, distribution => 'k3s', pool => ['10.42.0.0/16'], k8s_service_host => '203.0.113.7');
    is $o->{values}{k8sServiceHost}, '203.0.113.7', 'k8sServiceHost';
    is $o->{values}{k8sServicePort}, '6443', 'port 6443';
    ok !eval { resolved(%pins, distribution => 'k3s', pool => ['10.42.0.0/16'], k8s_service_host => '127.0.0.1'); 1 },
        'a loopback address is refused by the library too';
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

subtest 'a deployed release with an explicit other IPAM mode is refused' => sub {
    ok !eval {
        Rex::Rancher::Cilium::_release_action(
            { status => 'deployed', chart_version => '1.19.0', config => { ipam => { mode => 'kubernetes' } } },
            '1.20.0', { ipam => { mode => 'cluster-pool' } });
        1;
    }, 'dies before cilium upgrade';
    like $@, qr/ipam\.mode/, 'naming the IPAM mode';
};

done_testing;

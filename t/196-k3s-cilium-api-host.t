#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Rex;

#
# Live (k3s test, 2026-09-27): a k3s worker stayed NotReady, its Cilium agent in
# Init:0/6 on "Establishing connection to apiserver ... https://ocpt-cp.vm:6443".
#
# ocp.yaml had `control_planes: { provider: ssh, host: ocpt-cp.vm,
# public_ip: 10.5.10.20 }`. ocpt-cp.vm resolves in the CLI container only (via
# --add-host), not on the nodes. The worker's agent joined correctly at
# https://10.5.10.20:6443 -- bootstrap hands downstream OCP::Config::join_host,
# where the pinned public_ip wins (k185). Cilium was installed with the other
# address: OCP::Rex::install_server gave install_cilium advertised_host as
# k8s_service_host, and for the ssh provider that is `host`. On RKE2 nothing
# shows, because Rex::Rancher points Cilium at 127.0.0.1:6443 there; k3s agents
# serve the API on 127.0.0.1:6444, so k3s needs a real address (k178).
#
# The claims here:
#   1. Cilium's API address on k3s is the address agents join the control plane
#      at -- the pinned public_ip, else the advertised host;
#   2. tls-san and the kubeconfig `server` stay on advertised_host (k138): the
#      address the operator's machine reaches the cluster at is not changed.
#
# Held end to end through OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane
# with a real OCP::Rex; only run_task, the kubeconfig fetch over SSH and the
# on-disk token lookup are faked, so the params are those Rex would really get.
# What a live Cilium does with the address is NOT claimed here.
#

no warnings 'once';   # the stub packages below are only referenced by name

sub project {
    my ($yaml) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8($yaml);
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my $PINNED = <<'YAML';
name: ocpt
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: ocpt-cp.vm
  public_ip: 10.5.10.20
YAML

my $HOST_ONLY = <<'YAML';
name: ocpt
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: ocpt-cp.vm
YAML

package FakeOcp {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# ssh-provider-shaped: the machine exists, SSH reaches it at `host`, and that is
# also what it advertises (OCP::Role::Provider::ExistingHost).
package FakeProv {
    sub new { bless {}, $_[0] }
    sub upload_ssh_key     { }
    sub server_exists      { { ip => 'ocpt-cp.vm', newly_created => 0 } }
    sub create_server      { { ip => 'ocpt-cp.vm', newly_created => 0 } }
    sub wait_for_running   { $_[1] }
    sub advertised_host    { my ($s, %o) = @_; $o{host} }
    sub cleanup_on_failure { }
}

package FakeCond    { sub new { bless { t => $_[1], s => $_[2] }, $_[0] } sub type { $_[0]{t} } sub status { $_[0]{s} } }
package FakeStatus  { sub conditions { [ FakeCond->new('Ready', 'True') ] } }
package FakeNodeObj { sub status { bless {}, 'FakeStatus' } }
package FakeNodeList { sub items { [ bless {}, 'FakeNodeObj' ] } }
package FakeApi {
    sub _request { 1 }
    sub list     { bless {}, 'FakeNodeList' }
}

package main;

# Bootstrap with every machine-touching layer faked except OCP::Rex itself.
# Returns the Rex tasks it ran (name + params) and the host the kubeconfig
# `server` would have been pointed at.
sub run_bootstrap {
    my ($config) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    my (@tasks, $kubeconfig_server);

    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $old = select $fh;
    my $r = eval {
        no warnings 'redefine';
        local *OCP::Provider::for_spec        = sub { FakeProv->new };
        local *OCP::Cmd::Apply::_k8s_api      = sub { bless {}, 'FakeApi' };
        local *OCP::Secrets::save_kubeconfig  = sub { 1 };
        local *OCP::Secrets::ensure_age_key   = sub { 1 };
        local *OCP::SSH::new                  = sub { bless {}, 'OCP::SSH' };
        local *OCP::SSH::wait_for_ssh         = sub { 1 };
        local *OCP::SSH::run                  = sub { { stdout => 'Ready' } };
        local *OCP::Rex::run_task             = sub { my ($s, $t, %p) = @_; push @tasks, [ $t, \%p ]; 1 };
        local *OCP::Rex::_existing_server_token = sub { undef };
        # fetch_kubeconfig_ssh points the kubeconfig's server at advertised_host;
        # record which address that is.
        local *OCP::Rex::fetch_kubeconfig_ssh = sub { $kubeconfig_server = $_[0]->advertised_host; "apiVersion: v1\n" };
        OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
            $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
            # dev mode (no keys.yaml): the bootstrap key on disk is used
            admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
        );
    };
    my $err = $@;
    select $old;
    my %task = map { $_->[0] => $_->[1] } @tasks;
    return { r => $r, err => $err, out => $out, task => \%task,
             kubeconfig_server => $kubeconfig_server };
}

subtest 'k3s, ssh host by name, public_ip pinned: Cilium reaches the API at public_ip' => sub {
    my $res = run_bootstrap(project($PINNED));
    is $res->{err}, '', 'bootstrap ran to completion' or return diag $res->{out};

    my $cilium = $res->{task}{install_cilium};
    ok $cilium, 'install_cilium ran' or return;
    is $cilium->{distribution}, 'k3s', 'on k3s';
    is $cilium->{k8s_service_host}, '10.5.10.20',
        'k8s_service_host is the public_ip, not the name only the CLI resolves';
    is $cilium->{k8s_service_host}, $res->{r}{cp_ip},
        'the same address the workers join at';

    my $server = $res->{task}{install_k3s_server};
    ok $server, 'install_k3s_server ran' or return;
    is_deeply $server->{tls_san}, [ '10.5.10.20', 'ocpt-cp.vm' ],
        'tls-san unchanged: both addresses, the advertised name among them';
    is $res->{kubeconfig_server}, 'ocpt-cp.vm',
        'the kubeconfig server endpoint stays the advertised host (k138)';
};

subtest 'k3s, ssh host only: Cilium reaches the API at the host' => sub {
    my $res = run_bootstrap(project($HOST_ONLY));
    is $res->{err}, '', 'bootstrap ran to completion' or return diag $res->{out};

    my $cilium = $res->{task}{install_cilium};
    ok $cilium, 'install_cilium ran' or return;
    is $cilium->{k8s_service_host}, 'ocpt-cp.vm', 'nothing pinned: the advertised host';
    is $res->{kubeconfig_server}, 'ocpt-cp.vm', 'as is the kubeconfig server endpoint';
};

# --- OCP::Rex on its own --------------------------------------------------------

sub rex_install {
    my (%args) = @_;
    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub { my ($s, $t, %p) = @_; push @calls, [ $t, \%p ]; 1 };
    local *OCP::Rex::fetch_kubeconfig_ssh   = sub { "apiVersion: v1\n" };
    local *OCP::Rex::_existing_server_token = sub { undef };
    my $tmp = path(tempdir(CLEANUP => 1));
    my $key = $tmp->child('id');
    $key->spew('k');
    path("$key.pub")->spew('k');
    my $rex = OCP::Rex->new(host => '127.0.0.1', key_file => $key->stringify, %args);
    $rex->install_server(distribution => 'k3s', version => 'v1.36.4+k3s1');
    return ($rex, { map { $_->[0] => $_->[1] } @calls });
}

subtest 'OCP::Rex: node_api_host is Cilium\'s address, advertised_host the rest' => sub {
    my ($rex, $task) = rex_install(advertised_host => 'cp.example', node_api_host => '192.0.2.10');
    is $task->{install_cilium}{k8s_service_host}, '192.0.2.10', 'install_cilium gets node_api_host';
    is $task->{install_k3s_server}{tls_san}, 'cp.example', 'tls-san stays advertised_host';
    is $rex->advertised_host, 'cp.example', 'advertised_host untouched';
};

subtest 'OCP::Rex: node_api_host defaults to advertised_host' => sub {
    my ($rex, $task) = rex_install(advertised_host => '203.0.113.7');
    is $rex->node_api_host, '203.0.113.7', 'defaults to advertised_host';
    is $task->{install_cilium}{k8s_service_host}, '203.0.113.7',
        'so a caller that does not tell them apart is unchanged';
};

done_testing;

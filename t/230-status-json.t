#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use JSON::MaybeXS qw( decode_json );

use lib 'lib';

use OCP;
use OCP::Cmd::Status;
use OCP::Drift;
use OCP::Kubernetes;
use OCP::Versions;

# k230: `ocp status --json` -- one canonical object on STDOUT, diagnostics on
# STDERR, exit code as the text form.

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }
{ package Local::FakeSecrets; sub new { bless {}, $_[0] } sub read_kubeconfig { $main::KC } }
{
    package Local::FakeK8s;
    sub new { bless { nodes => $_[1] }, $_[0] }
    sub list_nodes { die "connection refused\n" if $main::API_DOWN; $_[0]{nodes} }
    sub api { undef }
    sub node_name { $_[1]{metadata}{name} }
    sub node_ready { $_[1]{ready} }
    sub node_roles { $_[1]{roles} }
    sub node_version { $_[1]{version} }
    sub node_internal_ip { $_[1]{internal_ip} }
    sub node_gpu_count { $_[1]{gpu} // 0 }
}

our ($KC, $API_DOWN);
my $ocp = OCP->new;
my $tmp = tempdir(CLEANUP => 1);

sub project {
    my ($name, $deployed) = @_;
    my $dir = path($tmp)->child($name);
    $dir->mkpath;
    my $cfg = $dir->child('ocp.yaml');
    $ocp->dump_file($cfg->stringify, {
        name => $name, version => 'v1.32.1+rke2r1',
        control_planes => [{ provider => 'hetzner', server_type => 'cx32' }],
        workers => [{ name => 'pool-a', provider => 'ssh', nodes => 2 }],
    });
    $dir->child('kubeconfig.yaml')->spew("x\n") if $deployed;
    return $cfg->stringify;
}

sub run_status {
    my ($cfg) = @_;
    my $cmd = OCP::Cmd::Status->new(json => 1, command_chain => [Local::FakeOCP->new(config => $cfg)]);
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die; open my $e, '>', \$err or die;
    my $rc;
    { local *STDOUT = $o; local *STDERR = $e; $rc = $cmd->execute([], []); }
    return ($rc, $out, $err);
}

no warnings 'redefine';
local *OCP::Secrets::new = sub { Local::FakeSecrets->new };
local *OCP::Kubernetes::new = sub {
    Local::FakeK8s->new([
        { metadata => { name => 'police2' }, ready => 0, roles => '<none>', version => 'v1.32.1', internal_ip => '10.0.0.11', gpu => 2 },
        { metadata => { name => 'police1' }, ready => 1, roles => 'control-plane', version => 'v1.32.1', internal_ip => '10.0.0.10' },
    ]);
};
local *OCP::Drift::detect = sub {
    [ { kind => 'version', component => 'cilium', message => 'cilium: b', expected => '2', actual => '1', remedy => { task => 'x' } },
      { kind => 'error', component => 'distribution', message => 'distribution: API failed', remedy => undef },
      { kind => 'version', component => 'cilium', message => 'cilium: a', remedy => undef } ];
};
local *OCP::Cmd::Status::rex_prober = sub { undef };

# not deployed
{
    my $cfg = project('fresh', 0);
    my ($rc, $out, $err) = run_status($cfg);
    is($rc, 0, 'undeployed: exit 0');
    my $d = decode_json($out);
    is_deeply([sort keys %$d], [sort qw(cluster config spec deployed nodes drift)], 'key set, no error key');
    ok(!$d->{deployed}, 'deployed false');
    is($d->{cluster}, 'fresh', 'cluster');
    is($d->{spec}{distribution}, 'rke2', 'distribution');
    is($d->{spec}{version}, OCP::Versions->get_component_version('rke2'), 'version falls back to the manifest');
    is_deeply($d->{spec}{control_planes}, { count => 1, provider => 'hetzner', server_type => 'cx32' }, 'control planes');
    is_deeply($d->{spec}{workers}, [{ name => 'pool-a', provider => 'ssh', nodes => 2 }], 'workers');
    is_deeply($d->{nodes}, [], 'no nodes');
}

# deployed
{
    my $cfg = project('live', 1);
    local $KC = "apiVersion: v1\n";
    my ($rc, $out, $err) = run_status($cfg);
    is($rc, 0, 'deployed: exit 0');
    is($err, '', 'nothing on STDERR on success');
    my $d = decode_json($out);
    ok($d->{deployed}, 'deployed true');
    is_deeply([map { $_->{name} } @{ $d->{nodes} }], [qw(police1 police2)], 'nodes sorted');
    is_deeply([sort keys %{ $d->{nodes}[0] }], [sort qw(name ready roles version internal_ip gpu)], 'node keys');
    ok($d->{nodes}[0]{ready}, 'ready true'); ok(!$d->{nodes}[1]{ready}, 'ready false');
    is($d->{nodes}[0]{gpu}, 0, 'gpu 0'); is($d->{nodes}[1]{gpu}, 2, 'gpu 2');
    is_deeply([map { "$_->{component}|$_->{message}" } @{ $d->{drift} }],
              ['cilium|cilium: a', 'cilium|cilium: b', 'distribution|distribution: API failed'], 'drift sorted');
    is_deeply([map { $_->{fixable} ? 1 : 0 } @{ $d->{drift} }], [0, 1, 0], 'fixable flag');
    is($d->{drift}[2]{kind}, 'error', 'error drift entry kept');
    unlike($out, qr/\d{4}-\d\d-\d\dT|\d+[smhd] ago/, 'no timestamps');
    my (undef, $again) = run_status($cfg);
    is($again, $out, 'second run is byte-identical');
    unlike($out, qr/=== Spec ===|Cluster:/, 'only JSON on STDOUT');
}

# kubeconfig cannot be decrypted
{
    my $cfg = project('nokc', 1);
    local $KC = undef;
    my ($rc, $out, $err) = run_status($cfg);
    is($rc, 1, 'undecryptable kubeconfig: exit 1');
    my $d = decode_json($out);
    like($d->{error}, qr/decrypt/, 'error field');
    like($err, qr/decrypt/, 'diagnosis on STDERR');
}

# API down
{
    my $cfg = project('down', 1);
    local $KC = "apiVersion: v1\n";
    local $API_DOWN = 1;
    my ($rc, $out, $err) = run_status($cfg);
    is($rc, 1, 'API failure: exit 1');
    my $d = decode_json($out);
    like($d->{error}, qr/connection refused/, 'error field names the cause');
    like($err, qr/connection refused/, 'diagnosis on STDERR');
}

done_testing;

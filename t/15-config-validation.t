#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Config;

local @ARGV = ();
my $ocp = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

#
# Test: Valid config has no errors
#

{
    my $f = path($tmpdir)->child('valid.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'mycluster',
        control_planes => [
            { provider => 'hetzner', server_type => 'cx32', location => 'fsn1' },
        ],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    is(scalar @errors, 0, 'valid hetzner config has no errors')
        or diag(join "\n", @errors);
}

#
# Test: Empty name
#

{
    my $f = path($tmpdir)->child('noname.yaml');
    $ocp->dump_file($f->stringify, {
        name          => '',
        control_planes => [{ provider => 'ssh', host => '10.0.0.1' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    ok((grep { /name is required/ } @errors), 'empty name detected');
}

#
# Test: Invalid provider
#

{
    my $f = path($tmpdir)->child('badprov.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'bad',
        control_planes => [{ provider => 'aws' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    ok((grep { /invalid provider/ } @errors), 'invalid provider detected');
}

#
# Test: Hetzner requires server_type and location
#

{
    my $f = path($tmpdir)->child('hz-missing.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'hz',
        control_planes => [{ provider => 'hetzner' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    ok((grep { /server_type required/ } @errors), 'hetzner server_type required');
    ok((grep { /location required/ } @errors), 'hetzner location required');
}

#
# Test: SSH requires host
#

{
    my $f = path($tmpdir)->child('ssh-nohost.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'ssh',
        control_planes => [{ provider => 'ssh' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    ok((grep { /host required/ } @errors), 'ssh host required');
}

#
# Test: Valid SSH config
#

{
    my $f = path($tmpdir)->child('ssh-ok.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'sshcluster',
        control_planes => [{ provider => 'ssh', host => '10.0.0.5' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    is(scalar @errors, 0, 'valid ssh config') or diag(join "\n", @errors);
}

#
# Test: Local provider is valid
#

{
    my $f = path($tmpdir)->child('local.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'local',
        control_planes => [{ provider => 'local' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    is(scalar @errors, 0, 'local provider valid') or diag(join "\n", @errors);
}

#
# Test: Worker validation
#

{
    my $f = path($tmpdir)->child('workers.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'wtest',
        control_planes => [{ provider => 'local' }],
        workers       => [
            { provider => 'hetzner' },  # missing name
        ],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    ok((grep { /worker.*name required/ } @errors), 'worker name required');
}

#
# Test: only canonical schema keys are read
#

{
    # Non-canonical keys (cps/k8s) must be ignored — no deprecation path.
    # Unknown keys fall through, so control_planes()/kubernetes() return
    # defaults, not anything from cps/k8s.
    my $f = path($tmpdir)->child('unknown-keys.yaml');
    $ocp->dump_file($f->stringify, {
        name => 'unknown',
        cps  => [{ provider => 'local' }],
        k8s  => { dist => 'rke2' },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };

    my $cps = $c->control_planes;
    is_deeply($cps, [{}], 'unknown cps key ignored: control_planes returns default');

    my $k8s = $c->kubernetes;
    is_deeply($k8s, {}, 'unknown k8s key ignored: kubernetes returns empty');

    is(scalar @warnings, 0, 'no warnings for unknown keys');
}

#
# Test: GPU config accessors
#

{
    my $f = path($tmpdir)->child('gpu.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'gpu',
        control_planes => [{ provider => 'local' }],
        gpu           => { enabled => 0, driver => 'operator' },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    ok(!$c->gpu_enabled, 'gpu_enabled false');
    is($c->gpu_driver, 'operator', 'gpu_driver from config');
}

{
    my $f = path($tmpdir)->child('nogpu.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'nogpu',
        control_planes => [{ provider => 'local' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    ok($c->gpu_enabled, 'gpu_enabled default true');
    is($c->gpu_driver, 'host', 'gpu_driver default host');
    is($c->gpu_toolkit, 1, 'gpu_toolkit default on — a plain host has no NVIDIA runtime');
}

#
# The switches travel into a Rex JSON payload and into a ClusterPolicy boolean,
# and YAML::XS hands `false` back as a JSON::PP::Boolean. Neither destination
# should have to know that, so the accessors normalise to 0/1.
#

{
    my $f = path($tmpdir)->child('gpu-booleans.yaml');
    path($f)->spew(<<'YAML');
name: gpu-booleans
control_planes:
  - provider: local
gpu:
  enabled: false
  toolkit: false
YAML
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    is($c->gpu_enabled, 0, 'a YAML false comes back as a plain 0, not a boolean object');
    is($c->gpu_toolkit, 0, 'same for gpu.toolkit');
}

#
# A typo used to fall back to 'host' in silence, which on a cluster configured
# for the operator-managed driver means no driver at all: Rex skips the host
# install for 'operator' and the ClusterPolicy would have kept the operator's
# driver DaemonSet off.
#

{
    my $f = path($tmpdir)->child('gpu-bad-driver.yaml');
    $ocp->dump_file($f->stringify, {
        name           => 'gpu-bad-driver',
        control_planes => [{ provider => 'local' }],
        gpu            => { driver => 'oprator' },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my $err = do { local $@; eval { $c->gpu_driver }; $@ };
    like($err, qr/gpu\.driver must be 'host' or 'operator'/,
        'an unknown gpu.driver is rejected instead of silently meaning host');
}

#
# Test: save_node_status
#

{
    my $projdir = path($tmpdir)->child('status-test');
    $projdir->mkpath;
    my $f = $projdir->child('ocp.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'stest',
        control_planes => [{ provider => 'local' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    # Save first node
    $c->save_node_status({
        name     => 'police1',
        role     => 'control-plane',
        provider => 'hetzner',
        public_ip => '1.2.3.4',
    });

    my $nodes = $c->nodes_status;
    is(scalar @$nodes, 1, 'one node in status');
    is($nodes->[0]{name}, 'police1', 'node name');

    # Update existing node (upsert)
    $c->save_node_status({
        name     => 'police1',
        role     => 'control-plane',
        provider => 'hetzner',
        public_ip => '5.6.7.8',
    });

    # Re-read fresh
    my $c2 = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    $nodes = $c2->nodes_status;
    is(scalar @$nodes, 1, 'still one node after upsert');
    is($nodes->[0]{public_ip}, '5.6.7.8', 'node IP updated');

    # Add second node
    $c2->save_node_status({
        name     => 'worker-1',
        role     => 'worker',
        provider => 'ssh',
        public_ip => '10.0.0.20',
    });

    my $c3 = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    $nodes = $c3->nodes_status;
    is(scalar @$nodes, 2, 'two nodes after adding worker');
}

done_testing;

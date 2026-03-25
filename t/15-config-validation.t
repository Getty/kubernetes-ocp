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
        controlPlanes => [
            { provider => 'hetzner', serverType => 'cx32', location => 'fsn1' },
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
        controlPlanes => [{ provider => 'ssh', host => '10.0.0.1' }],
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
        controlPlanes => [{ provider => 'aws' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    ok((grep { /invalid provider/ } @errors), 'invalid provider detected');
}

#
# Test: Hetzner requires serverType and location
#

{
    my $f = path($tmpdir)->child('hz-missing.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'hz',
        controlPlanes => [{ provider => 'hetzner' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    ok((grep { /serverType required/ } @errors), 'hetzner serverType required');
    ok((grep { /location required/ } @errors), 'hetzner location required');
}

#
# Test: SSH requires host
#

{
    my $f = path($tmpdir)->child('ssh-nohost.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'ssh',
        controlPlanes => [{ provider => 'ssh' }],
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
        controlPlanes => [{ provider => 'ssh', host => '10.0.0.5' }],
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
        controlPlanes => [{ provider => 'local' }],
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
        controlPlanes => [{ provider => 'local' }],
        workers       => [
            { provider => 'hetzner' },  # missing name
        ],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    my @errors = $c->validate;
    ok((grep { /worker.*name required/ } @errors), 'worker name required');
}

#
# Test: Deprecation warnings (cps -> controlPlanes)
#

{
    my $f = path($tmpdir)->child('deprecated.yaml');
    $ocp->dump_file($f->stringify, {
        name => 'dep',
        cps  => [{ provider => 'local' }],
        k8s  => { dist => 'rke2' },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };

    $c->control_planes;
    ok((grep { /cps.*deprecated/ } @warnings), 'cps deprecation warning');

    @warnings = ();
    $c->kubernetes;
    ok((grep { /k8s.*deprecated/ } @warnings), 'k8s deprecation warning');

    # Second call should NOT warn again
    @warnings = ();
    $c->control_planes;
    $c->kubernetes;
    is(scalar @warnings, 0, 'deprecation warns only once');
}

#
# Test: GPU config accessors
#

{
    my $f = path($tmpdir)->child('gpu.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'gpu',
        controlPlanes => [{ provider => 'local' }],
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
        controlPlanes => [{ provider => 'local' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    ok($c->gpu_enabled, 'gpu_enabled default true');
    is($c->gpu_driver, 'host', 'gpu_driver default host');
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
        controlPlanes => [{ provider => 'local' }],
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    # Save first node
    $c->save_node_status({
        name     => 'police1',
        role     => 'control-plane',
        provider => 'hetzner',
        publicIp => '1.2.3.4',
    });

    my $nodes = $c->nodes_status;
    is(scalar @$nodes, 1, 'one node in status');
    is($nodes->[0]{name}, 'police1', 'node name');

    # Update existing node (upsert)
    $c->save_node_status({
        name     => 'police1',
        role     => 'control-plane',
        provider => 'hetzner',
        publicIp => '5.6.7.8',
    });

    # Re-read fresh
    my $c2 = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    $nodes = $c2->nodes_status;
    is(scalar @$nodes, 1, 'still one node after upsert');
    is($nodes->[0]{publicIp}, '5.6.7.8', 'node IP updated');

    # Add second node
    $c2->save_node_status({
        name     => 'worker-1',
        role     => 'worker',
        provider => 'ssh',
        publicIp => '10.0.0.20',
    });

    my $c3 = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    $nodes = $c3->nodes_status;
    is(scalar @$nodes, 2, 'two nodes after adding worker');
}

done_testing;

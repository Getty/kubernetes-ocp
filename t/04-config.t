#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Config;

# Ensure OCP singleton exists for Config to use
local @ARGV = ();
my $ocp = OCP->new;

my $tmpdir = tempdir(CLEANUP => 1);

#
# Test: Load spec from YAML file
#

{
    my $config_file = path($tmpdir)->child('basic.yaml');
    $ocp->dump_file($config_file->stringify, {
        name => 'testcluster',
        kubernetes => { dist => 'rke2', version => 'v1.31.3' },
        control_planes => {
            provider   => 'hetzner',
            server_type => 'cx32',
            location   => 'fsn1',
            nodes      => 1,
        },
        workers => [],
    });

    my $config = OCP::Config->new(file => $config_file->stringify, ocp => $ocp);
    isa_ok($config, 'OCP::Config');

    is($config->name, 'testcluster', 'name accessor');
    is($config->distribution, 'rke2', 'distribution accessor');
    is($config->version, 'v1.31.3', 'version accessor');

    my $cps = $config->control_planes;
    is(ref $cps, 'ARRAY', 'control_planes returns ArrayRef');
    is($cps->[0]{provider}, 'hetzner', 'control_planes provider');
    is($cps->[0]{server_type}, 'cx32', 'control_planes server_type');
    is($cps->[0]{location}, 'fsn1', 'control_planes location');

    is_deeply($config->workers, [], 'empty workers');
}

#
# Test: control_planes array form (multiple CPs)
#

{
    my $config_file = path($tmpdir)->child('multicp.yaml');
    $ocp->dump_file($config_file->stringify, {
        name         => 'altcluster',
        kubernetes   => { dist => 'k3s' },
        control_planes => [
            { provider => 'ssh', host => '10.0.0.1' },
            { provider => 'ssh', host => '10.0.0.2' },
        ],
    });

    my $config = OCP::Config->new(file => $config_file->stringify, ocp => $ocp);

    is($config->distribution, 'k3s', 'kubernetes.dist');

    my $cps = $config->control_planes;
    is(scalar @$cps, 2, 'control_planes array form: 2 CPs');
    is($cps->[0]{provider}, 'ssh', 'control_planes[0] provider');
    is($cps->[0]{host}, '10.0.0.1', 'control_planes[0] host');
    is($cps->[1]{host}, '10.0.0.2', 'control_planes[1] host');
}

#
# Test: Default spec (no file)
#

{
    my $missing = path($tmpdir)->child('nonexistent.yaml')->stringify;
    my $config = OCP::Config->new(file => $missing, ocp => $ocp);

    is($config->name, 'mycluster', 'default name');
    is($config->distribution, 'rke2', 'default distribution');
}

#
# Test: project_dir derived from file
#

{
    my $subdir = path($tmpdir)->child('myproject');
    $subdir->mkpath;
    my $config_file = $subdir->child('ocp.yaml');
    $ocp->dump_file($config_file->stringify, { name => 'proj' });

    my $config = OCP::Config->new(file => $config_file->stringify, ocp => $ocp);
    is($config->project_dir->stringify, $subdir->stringify, 'project_dir from file path');
}

#
# Test: single_node detection
#

{
    # Single: 1 CP, 0 workers (array format)
    my $f1 = path($tmpdir)->child('single1.yaml');
    $ocp->dump_file($f1->stringify, {
        name => 'single',
        control_planes => [{ provider => 'local' }],
    });
    my $c1 = OCP::Config->new(file => $f1->stringify, ocp => $ocp);
    ok($c1->single_node, 'single node: 1 CP, 0 workers');

    # Inferred: 1 CP from hash format with nodes: 1, 0 workers
    my $f2 = path($tmpdir)->child('single2.yaml');
    $ocp->dump_file($f2->stringify, {
        name         => 'inferred-single',
        control_planes => { provider => 'hetzner', nodes => 1 },
        workers      => [],
    });
    my $c2 = OCP::Config->new(file => $f2->stringify, ocp => $ocp);
    ok($c2->single_node, 'inferred single node (hash format, 1 CP)');

    # Not single: has workers
    my $f3 = path($tmpdir)->child('multi.yaml');
    $ocp->dump_file($f3->stringify, {
        name         => 'multi',
        control_planes => [{ provider => 'hetzner' }],
        workers      => [{ name => 'pool1', provider => 'hetzner', nodes => 2 }],
    });
    my $c3 = OCP::Config->new(file => $f3->stringify, ocp => $ocp);
    ok(!$c3->single_node, 'not single when workers exist');

    # Not single: 3 CPs
    my $f4 = path($tmpdir)->child('ha.yaml');
    $ocp->dump_file($f4->stringify, {
        name         => 'ha',
        control_planes => [
            { provider => 'hetzner' },
            { provider => 'hetzner' },
            { provider => 'hetzner' },
        ],
    });
    my $c4 = OCP::Config->new(file => $f4->stringify, ocp => $ocp);
    ok(!$c4->single_node, 'not single with 3 CPs');
}

#
# Test: Add-on flags
#

{
    my $f = path($tmpdir)->child('addons.yaml');
    $ocp->dump_file($f->stringify, {
        name      => 'flags',
        nocert    => 1,
        lbipam    => 1,
        norobocop => 0,
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    ok($c->no_cert, 'nocert flag');
    ok($c->lbipam, 'lbipam opt-in flag');
    ok(!$c->robocop_enabled, 'robocop off without hetzner provider');
}

#
# Test: Registry configuration
#

{
    my $f = path($tmpdir)->child('registry.yaml');
    $ocp->dump_file($f->stringify, {
        name     => 'reg',
        registry => {
            cache    => 'http://external-cache:5000',
            upstream => 'http://external-reg:5000',
            name     => 'my.registry',
        },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    is($c->registry_cache, 'http://external-cache:5000', 'registry cache');
    is($c->registry_upstream, 'http://external-reg:5000', 'registry upstream');
    is($c->registry_name, 'my.registry', 'registry name');
    ok($c->has_external_cache, 'has external cache');
    ok($c->has_external_upstream, 'has external upstream');
}

{
    my $f = path($tmpdir)->child('noreg.yaml');
    $ocp->dump_file($f->stringify, { name => 'noreg' });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    is($c->registry_cache, '', 'no registry cache by default');
    is($c->registry_name, 'ocp.internal', 'default registry name');
    ok(!$c->has_external_cache, 'no external cache by default');
    ok(!$c->has_external_upstream, 'no external upstream by default');
}

#
# Test: SSL configuration
#

{
    my $f = path($tmpdir)->child('ssl.yaml');
    $ocp->dump_file($f->stringify, {
        name => 'ssl',
        ssl  => { email => 'admin@example.com' },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    is($c->ssl_email, 'admin@example.com', 'ssl email');
}

#
# Test: SSH key paths
#

{
    my $projdir = path($tmpdir)->child('sshtest');
    $projdir->mkpath;
    my $f = $projdir->child('ocp.yaml');
    $ocp->dump_file($f->stringify, {
        name => 'sshtest',
        ssh  => {
            private_key => '.ocp/id_ed25519',
            public_key  => '.ocp/id_ed25519.pub',
        },
    });
    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);

    like($c->ssh_private_key_path, qr/sshtest.*\.ocp.*id_ed25519$/, 'SSH private key path resolves relative');
    like($c->ssh_public_key_path, qr/sshtest.*\.ocp.*id_ed25519\.pub$/, 'SSH public key path resolves relative');
}

#
# Test: cluster_exists
#

{
    my $projdir = path($tmpdir)->child('clustertest');
    $projdir->mkpath;
    my $f = $projdir->child('ocp.yaml');
    $ocp->dump_file($f->stringify, { name => 'cltest' });

    my $c = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    ok(!$c->cluster_exists, 'cluster does not exist without kubeconfig.yaml');

    $projdir->child('kubeconfig.yaml')->spew('fake');
    ok($c->cluster_exists, 'cluster exists with kubeconfig.yaml');
}

#
# Test: write_spec (class method)
#

{
    my $f = path($tmpdir)->child('written.yaml')->stringify;
    OCP::Config->write_spec($f,
        name     => 'written',
        dist     => 'k3s',
        provider => 'hetzner',
    );

    ok(-f $f, 'write_spec creates file');
    my $config = OCP::Config->new(file => $f, ocp => $ocp);
    is($config->name, 'written', 'write_spec: name');
    is($config->distribution, 'k3s', 'write_spec: dist');

    my $cps = $config->control_planes;
    is(ref $cps, 'ARRAY', 'write_spec: returns array');
    is($cps->[0]{provider}, 'hetzner', 'write_spec: hetzner provider');
    is($cps->[0]{server_type}, 'cpx21', 'write_spec: default server_type');
}

{
    my $f = path($tmpdir)->child('written-ssh.yaml')->stringify;
    OCP::Config->write_spec($f,
        name     => 'sshcluster',
        provider => 'ssh',
        host     => '10.0.0.5',
    );

    my $config = OCP::Config->new(file => $f, ocp => $ocp);
    my $cps = $config->control_planes;
    is($cps->[0]{provider}, 'ssh', 'write_spec SSH: provider');
    is($cps->[0]{host}, '10.0.0.5', 'write_spec SSH: host');
}

{
    my $f = path($tmpdir)->child('written-local.yaml')->stringify;
    OCP::Config->write_spec($f,
        name     => 'localdev',
        provider => 'local',
    );

    my $config = OCP::Config->new(file => $f, ocp => $ocp);
    is($config->control_planes->[0]{provider}, 'local', 'write_spec local: provider');
    ok($config->single_node, 'write_spec local: single_node (inferred)');
}

# Test: write_spec with control_planes ArrayRef directly (multi-CP path)
{
    my $f = path($tmpdir)->child('written-array.yaml')->stringify;
    OCP::Config->write_spec($f,
        name => 'hacluster',
        dist => 'rke2',
        control_planes => [
            { provider => 'hetzner', server_type => 'cx32', location => 'fsn1', image => 'debian-13' },
            { provider => 'hetzner', server_type => 'cx32', location => 'fsn1', image => 'debian-13' },
            { provider => 'hetzner', server_type => 'cx32', location => 'fsn1', image => 'debian-13' },
        ],
    );

    my $config = OCP::Config->new(file => $f, ocp => $ocp);
    my $cps = $config->control_planes;
    is(scalar @$cps, 3, 'write_spec array: 3 CPs');
    is($cps->[0]{provider}, 'hetzner', 'write_spec array: provider');
    is($cps->[2]{server_type}, 'cx32', 'write_spec array: server_type on 3rd CP');
    ok(!$config->single_node, 'write_spec array: not single with 3 CPs');
}

done_testing;

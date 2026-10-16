#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();
use JSON::MaybeXS ();

use lib 'lib';
use OCP::Config;
use OCP::Cmd::Apply::CR;

#
# k29: xt/smoke.sh joins a worker through a pool it writes into the ocp.yaml
# `ocp init` made, then finds the node again in `ocp node ls --json`. Neither
# can run without a cluster, but the part that is plain data can be pinned:
# the pool must be one OCP::Config and the CR layer accept as a worker pool,
# the node must be found by pool, and the test pod must be pinned by hostname.
# What smoke does with a machine is not tested here -- that is the point of it.
#

require './xt/smoke-worker.pl';

sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    # What `ocp init --provider=ssh --host=cp.lab --name=smoke-rke2 --nopassword` writes, in outline.
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({
        name => 'smoke-rke2', dist => 'rke2',
        control_planes => { provider => 'ssh', host => 'cp.lab' },
    }));
    return $dir->child('ocp.yaml')->stringify;
}

# --- config: ssh ---------------------------------------------------------

{
    my $file = project();
    is main::add_worker_pool($file, mode => 'ssh', host => '10.230.30.52'), 'smoke-workers',
        'the pool has a fixed name smoke can look the node up by';

    my $config = OCP::Config->new(file => $file);
    is scalar @{ $config->workers }, 1, 'one pool in ocp.yaml';
    is $config->workers->[0]{provider}, 'ssh', 'an ssh pool';
    is $config->spec->{control_planes}{host}, 'cp.lab', 'the control plane entry is untouched';

    my @crs = OCP::Cmd::Apply::CR::worker_ocpnodes($config);
    is scalar @crs, 1, 'apply would write one worker OCPNode';
    is $crs[0]{metadata}{name}, '10-230-30-52', 'named after the host, as the lab runs saw it';
    is $crs[0]{spec}{host}, '10.230.30.52', 'spec.host is the worker host';
    is $crs[0]{spec}{role}, 'worker', 'role worker';

    eval { main::add_worker_pool($file, mode => 'ssh', host => 'x') };
    like $@, qr/already in/, 'a second run does not add the pool twice';
}

{
    eval { main::add_worker_pool(project(), mode => 'ssh') };
    like $@, qr/needs a host/, 'an ssh worker without a host is refused';
    eval { main::add_worker_pool(project(), mode => 'local') };
    like $@, qr/ssh or hetzner/, 'any other mode is refused';
}

# --- config: hetzner -----------------------------------------------------

{
    my $file = project();
    main::add_worker_pool($file, mode => 'hetzner', server_type => 'cpx21', location => 'fsn1');
    my $config = OCP::Config->new(file => $file);
    my $pool   = $config->workers->[0];
    is $pool->{provider}, 'hetzner', 'a hetzner pool';
    is $pool->{nodes}, 1, 'one server';
    is $pool->{server_type}, 'cpx21', 'server type as asked';
    is $pool->{location}, 'fsn1', 'location as asked';

    my $bare = project();
    main::add_worker_pool($bare, mode => 'hetzner');
    my $p = OCP::Config->new(file => $bare)->workers->[0];
    ok !exists $p->{server_type} && !exists $p->{location}, 'no server type or location: the project defaults apply';
}

# --- pick ----------------------------------------------------------------

{
    my $json = JSON::MaybeXS->new->encode([
        { name => 'smoke-rke2', role => 'control-plane', pool => undef, phase => 'Ready',
          kubernetesNodeName => 'smoke-rke2', host => 'cp.lab' },
        { name => '10-230-30-52', role => 'worker', pool => 'smoke-workers', phase => 'Installing',
          kubernetesNodeName => undef, host => '10.230.30.52' },
    ]);
    is_deeply main::pick_node($json, 'smoke-workers'), ['10-230-30-52', 'Installing', '', '10.230.30.52'],
        'the pool\'s node is found; a null kubernetesNodeName comes out empty, not guessed';
    is main::pick_node($json, 'other'), undef, 'another pool: no node';
    is main::pick_node('[]'), undef, 'an empty cluster: no node';

    my $ready = JSON::MaybeXS->new->decode($json);
    $ready->[1]{phase} = 'Ready';
    $ready->[1]{kubernetesNodeName} = 'worker-host-1';
    is_deeply main::pick_node(JSON::MaybeXS->new->encode($ready)),
        ['10-230-30-52', 'Ready', 'worker-host-1', '10.230.30.52'], 'the registered name is read from the status';
}

# --- pod -----------------------------------------------------------------

{
    my $pod = main::pod_manifest('worker-host-1');
    is $pod->{spec}{nodeSelector}{'kubernetes.io/hostname'}, 'worker-host-1', 'pinned by hostname label';
    is $pod->{spec}{containers}[0]{image}, 'registry.k8s.io/pause:3.10', 'default image is one every node has';
    is main::pod_manifest('n', 'busybox')->{spec}{containers}[0]{image}, 'busybox', 'image overridable';
    eval { main::pod_manifest('') };
    like $@, qr/node name is required/, 'no node, no pod';
}

# --- CLI -----------------------------------------------------------------

{
    my $file = project();
    my $out  = `$^X -Ilib xt/smoke-worker.pl config $file --mode ssh --host crag </dev/null`;
    is $out, "smoke-workers\n", 'config prints the pool name';
    is(OCP::Config->new(file => $file)->workers->[0]{nodes}[0], 'crag', 'and wrote the host');
}

# --- smoke.sh stays honest about what it costs ---------------------------

{
    my $sh = path('xt/smoke.sh')->slurp_utf8;
    like $sh, qr/OCP_SMOKE_WORKER_HOST/, 'smoke.sh has the ssh worker switch';
    like $sh, qr/OCP_SMOKE_HETZNER_WORKER/, 'smoke.sh has the Hetzner worker switch';
    like $sh, qr/HETZNER_WORKER.*\n.*HETZNER_API_TOKEN/, 'the paid mode wants a token up front';
    is system('bash', '-n', 'xt/smoke.sh'), 0, 'smoke.sh parses';
}

done_testing;

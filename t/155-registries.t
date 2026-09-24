#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

#
# k155: registries.yaml is written by Rex::Rancher (0600) from the hash the
# Rexfile builds: docker.io through ocp-cache (NodePort 30500), the internal
# registry under both of its names through ocp-registry (NodePort 30501),
# external endpoints from ocp.yaml replacing the NodePorts. RKE2 servers and
# agents get it; k3s never did and still does not.
#
# The Rexfile runs against recorders (t/lib/OCPTest/Rexfile.pm).
#

my $registries = OCPTest::Rexfile->helper('_registries');

subtest 'defaults: the in-cluster cache and registry' => sub {
    is_deeply $registries->({}), {
        mirrors => {
            'docker.io'      => { endpoint => ['http://localhost:30500'] },
            'registry.local' => { endpoint => ['http://localhost:30501'] },
            'ocp.internal'   => { endpoint => ['http://localhost:30501'] },
        },
    }, 'three mirrors';
};

subtest 'external endpoints and a custom name' => sub {
    is_deeply $registries->({
        registry_cache    => 'http://cache:5000',
        registry_upstream => 'http://reg:5000',
        registry_name     => 'my.registry',
    }), {
        mirrors => {
            'docker.io'      => { endpoint => ['http://cache:5000'] },
            'registry.local' => { endpoint => ['http://reg:5000'] },
            'my.registry'    => { endpoint => ['http://reg:5000'] },
        },
    }, 'replaced';
};

for my $t ([ install_rke2_server => 'Server::install_server', 1 ],
           [ install_rke2_agent  => 'Agent::install_agent',   1 ],
           [ install_k3s_server  => 'Server::install_server', 0 ],
           [ install_k3s_agent   => 'Agent::install_agent',   0 ]) {
    my ($task, $fn, $want) = @$t;
    subtest "$task: " . ($want ? 'registries.yaml' : 'no registries.yaml (as before)') => sub {
        OCPTest::Rexfile->reset;
        OCPTest::Rexfile->run_task($task,
            { token => 't', server => 'https://x:9345', registry_cache => 'http://cache:5000' });
        my $o = OCPTest::Rexfile->lib_opts("Rex::Rancher::$fn");
        if ($want) {
            is_deeply $o->{registries}{mirrors}{'docker.io'}{endpoint}, ['http://cache:5000'],
                'handed to the library';
        } else {
            ok !exists $o->{registries}, 'none';
        }
    };
}

done_testing;

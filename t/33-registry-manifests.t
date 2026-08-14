#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::Cmd::Apply;

#
# ocp-cache is registry:2 in pull-through mode. It resolves its upstream once,
# while starting, and panics if DNS does not answer — it has no retry. On a
# fresh cluster CoreDNS is regularly a few seconds behind the first workload,
# so the cache crash-looped its way to readiness (three restarts on the first
# bare-metal bootstrap) and every one of those logs looks like a real failure.
#
# ocp-registry serves only local content and has nothing to resolve, so it must
# not pay for the wait.
#

my $cache = OCP::Cmd::Apply::_registry_deployment('ocp-cache', {
    config_map    => 'ocp-cache-config',
    host_path     => '/var/lib/ocp/cache',
    wait_for_host => 'registry-1.docker.io',
});

my $registry = OCP::Cmd::Apply::_registry_deployment('ocp-registry', {
    host_path => '/var/lib/ocp/registry',
});

subtest 'the pull-through cache waits for DNS before it starts' => sub {
    my $pod = $cache->{spec}{template}{spec};

    my $init = $pod->{initContainers};
    is ref($init), 'ARRAY', 'cache has init containers';
    is scalar(@$init), 1, 'exactly one';

    my $wait = $init->[0];
    is $wait->{name}, 'wait-for-dns', 'named for what it does';
    is $wait->{image}, $pod->{containers}[0]{image},
        'reuses the registry image, so there is no second pull';

    my $script = join ' ', @{ $wait->{args} };
    like $script, qr/nslookup registry-1\.docker\.io/,
        'waits for the upstream the proxy config points at';
    like $script, qr/exit 1/, 'gives up eventually instead of hanging forever';
};

subtest 'the local registry has nothing to resolve and does not wait' => sub {
    my $pod = $registry->{spec}{template}{spec};
    ok !exists $pod->{initContainers}, 'no init container';
};

subtest 'both registries report readiness from /v2/' => sub {
    for my $d ($cache, $registry) {
        my $name  = $d->{metadata}{name};
        my $probe = $d->{spec}{template}{spec}{containers}[0]{readinessProbe};

        ok $probe, "$name has a readiness probe";
        is $probe->{httpGet}{path}, '/v2/', "$name probes the registry API";
        is $probe->{httpGet}{port}, 5000,   "$name probes the serving port";
    }
};

#
# Without a probe a Deployment counts as ready the moment the container starts,
# which is exactly what _poll_deployment_ready believes — it reads
# readyReplicas. `ocp apply` waits on ocp-cache and then configures containerd
# against it, so "ready" has to mean "answers".
#

subtest 'apply waits for the cache it is about to point containerd at' => sub {
    my $src = do {
        local $/;
        open my $fh, '<', 'lib/OCP/Cmd/Apply/Registry.pm' or die "open Registry.pm: $!";
        <$fh>;
    };

    like $src, qr/_poll_deployment_ready\(\$api, 'ocp-cache'/,
        'apply blocks on the cache becoming ready';
};

done_testing;

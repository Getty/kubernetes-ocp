#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::Cmd::Apply;
use YAML::XS ();

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

# k224: a pinned registry image, not the moving registry:2 tag.
for my $d ($cache, $registry) {
    is $d->{spec}{template}{spec}{containers}[0]{image},
        'registry:' . OCP::Versions->get_component_version('registry'),
        "$d->{metadata}{name}: registry image from OCP::Versions";
}
unlike(OCP::Versions->get_component_version('registry'), qr/\A2\z/, 'a full version, not the major tag');

#
# k224 follow-up (lab, 2026-10-16): both registries keep their data in a
# hostPath on whatever node the pod runs on. At bootstrap that is the control
# plane; pinning the image re-rolled both Deployments, the scheduler put them on
# a worker, and the local registry came up empty (robocop ImagePullBackOff, the
# cache cold, 9 GB stranded on the CP). They have to stay on the control plane,
# tolerate its taint, and never run two processes on one directory.
#
subtest 'both registries stay on the control plane where their data lives' => sub {
    for my $d ($cache, $registry) {
        my $name = $d->{metadata}{name};
        my $pod  = $d->{spec}{template}{spec};

        my $terms = $pod->{affinity}{nodeAffinity}
            {requiredDuringSchedulingIgnoredDuringExecution}{nodeSelectorTerms} // [];
        is_deeply $terms,
            [{ matchExpressions => [{
                key      => 'node-role.kubernetes.io/control-plane',
                operator => 'Exists',
            }] }],
            "$name: required to schedule on a control-plane node";

        my %tolerated = map { $_->{key} => $_ } @{ $pod->{tolerations} // [] };
        for my $key ('node-role.kubernetes.io/control-plane', 'node-role.kubernetes.io/master') {
            is_deeply $tolerated{$key},
                { key => $key, operator => 'Exists', effect => 'NoSchedule' },
                "$name: tolerates the $key taint";
        }

        is_deeply $d->{spec}{strategy}, { type => 'Recreate' },
            "$name: Recreate, never two registries on one hostPath";
    }
};

# The deploy hash is over the whole manifest, so a changed Deployment spec is
# re-applied on the next apply instead of being declared up to date.
{
    my $src = do {
        local $/;
        open my $fh, '<', 'lib/OCP/Cmd/Apply/Registry.pm' or die "open Registry.pm: $!";
        <$fh>;
    };
    like $src, qr/md5_hex\(\$manifest\)/, 'registry hash covers the full manifest';
    # generate_manifest only needs ->ocp->dump; OCP::dump ignores its invocant.
    my $self = bless {}, 'T33::Apply';
    no warnings 'once';
    *T33::Apply::ocp = sub { 'OCP' };
    require OCP;
    my $manifest = OCP::Cmd::Apply::Registry::generate_manifest($self, undef);
    my @deployments = grep { $_->{kind} eq 'Deployment' } YAML::XS::Load($manifest);
    is scalar(@deployments), 2, 'the hashed manifest holds both registry Deployments';
    is $_->{spec}{strategy}{type}, 'Recreate',
        "$_->{metadata}{name}: the hashed manifest carries the strategy"
        for @deployments;
}

done_testing;

package OCP::Cmd::Apply::Registry;
# ABSTRACT: Registry (ocp-cache + ocp-registry) deploy and version stamp

use strict;
use warnings;

use Digest::MD5;
use JSON::PP ();

use OCP::Versions;

=head1 SYNOPSIS

    my $outcome = OCP::Cmd::Apply::Registry::setup($apply, $config);
    OCP::Cmd::Apply::Registry::stamp_ocp_version($apply, $config);
    my $hash = OCP::Cmd::Apply::Registry::deployment('ocp-cache', { ... });

=head1 DESCRIPTION

Two parts of the cluster the apply path always owns: the docker.io pull-through
cache (ocp-cache) and the local registry (ocp-registry) — either of which can
be replaced with an external cache/upstream, and both default to a built-in
container registry fronted by a NodePort service. Plus C<stamp_ocp_version>,
which writes C<status.ocpVersion> so C<ocp update> knows what is deployed.

The "up to date" verdict here is interesting: the deploy-hash file in
.ocp/deployed.yaml is only one of two inputs. C<registry_running> asks the
cluster whether the deployment is actually there before deciding — otherwise
an `ocp destroy` left a record of a registry that no longer existed, and the
next apply happily declared it up to date (see the comment on
C<setup_registry>).

L<OCP::Cmd::Apply> re-exports every helper as a thin forwarder, including
C<deployment> and C<nodeport_service> — t/33 calls those as bare package subs.

=cut

sub setup {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    my $manifest = generate_manifest($self, $config);

    # "Up to date" is a statement about the cluster (ADR 0017), so the local
    # hash alone may never make it. `ocp destroy` left .ocp/deployed.yaml
    # behind, and the next apply — against a cluster built from scratch —
    # announced "Registry already deployed", skipped it, and pointed CoreDNS
    # at a registry that did not exist. NFD, the GPU operator and cert-manager
    # already ask the cluster first; the registry was the one that did not.
    my $hash = Digest::MD5::md5_hex($manifest);
    my $deployed = $self->_load_deployed_hashes($config);

    my $recorded = exists $deployed->{registry};
    my $running  = running($self, $config);

    if ($running && ($deployed->{registry} // '') eq $hash) {
        print "      Registry already deployed (up to date)\n";
        return 'unchanged';
    }

    # What the caller gets told afterwards. "restored" is the case this check
    # exists for: OCP had a record, the cluster had nothing.
    my $outcome = !$recorded ? 'deployed'
                : !$running  ? 'restored'
                :              'updated';

    # Log registry mode
    if ($config->has_external_cache) {
        print "      docker.io cache: ", $config->registry_cache, " (external)\n";
    } else {
        print "      docker.io cache: ocp-cache (built-in)\n";
    }
    if ($config->has_external_upstream) {
        print "      ", $config->registry_name, ": ", $config->registry_upstream, " (external)\n";
    } else {
        print "      ", $config->registry_name, ": ocp-registry (built-in)\n";
    }

    # Server-side apply all registry resources
    $self->_apply_yaml_string($api, $manifest);

    # Wait for deployed components
    unless ($config->has_external_cache) {
        print "      Waiting for ocp-cache...\n";
        $self->_poll_deployment_ready($api, 'ocp-cache', 'ocp-system', 120)
            or die "ocp-cache not ready within 120s\n";
    }

    unless ($config->has_external_upstream) {
        print "      Waiting for ocp-registry...\n";
        $self->_poll_deployment_ready($api, 'ocp-registry', 'ocp-system', 120)
            or die "ocp-registry not ready within 120s\n";
    }

    # Save hash so we skip next time if unchanged
    $self->_save_deployed_hash($config, 'registry', $hash);

    return $outcome;
}

# The registry as the cluster has it: the namespace, plus whichever of the two
# deployments this configuration actually rolls out. Mirrors generate_manifest
# — an external cache or upstream means OCP deploys nothing for that half and
# must not expect it to be there.
sub running {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    return 0 unless $self->_resource_exists($api, 'Namespace', 'ocp-system');

    unless ($config->has_external_cache) {
        return 0 unless $self->_resource_exists($api, 'Deployment', 'ocp-cache',
            namespace => 'ocp-system');
    }

    unless ($config->has_external_upstream) {
        return 0 unless $self->_resource_exists($api, 'Deployment', 'ocp-registry',
            namespace => 'ocp-system');
    }

    return 1;
}

sub generate_manifest {
    my ($self, $config) = @_;

    my $has_external_cache    = $config && $config->has_external_cache;
    my $has_external_upstream = $config && $config->has_external_upstream;

    my @resources;

    # Namespace (always)
    push @resources, {
        apiVersion => 'v1',
        kind       => 'Namespace',
        metadata   => { name => 'ocp-system' },
    };

    # ocp-cache: pull-through cache for docker.io (unless external cache)
    unless ($has_external_cache) {
        my $upstream_host = 'registry-1.docker.io';

        my $cache_config_yml = $self->ocp->dump({
            version => '0.1',
            proxy   => { remoteurl => "https://$upstream_host" },
            storage => {
                filesystem => { rootdirectory => '/var/lib/registry' },
                delete     => { enabled => JSON::PP::true },
            },
            http => { addr => ':5000' },
        });

        push @resources, {
            apiVersion => 'v1',
            kind       => 'ConfigMap',
            metadata   => { name => 'ocp-cache-config', namespace => 'ocp-system' },
            data       => { 'config.yml' => $cache_config_yml },
        };

        push @resources, deployment('ocp-cache', {
            config_map    => 'ocp-cache-config',
            host_path     => '/var/lib/ocp/cache',
            wait_for_host => $upstream_host,
        });

        push @resources, nodeport_service('ocp-cache', 30500);
    }

    # ocp-registry: local registry (unless external upstream)
    unless ($has_external_upstream) {
        push @resources, deployment('ocp-registry', {
            host_path => '/var/lib/ocp/registry',
            env       => [{ name => 'REGISTRY_STORAGE_DELETE_ENABLED', value => 'true' }],
        });

        push @resources, nodeport_service('ocp-registry', 30501);
    }

    return $self->ocp->dump(@resources);
}

# `ocp update` and `ocp version` both read status.ocpVersion — update refuses
# to run without it, version cannot name what is deployed. Nothing ever wrote
# it except update itself, so on a cluster this very CLI had just bootstrapped
# `ocp update` answered "Cluster not yet deployed. Run 'ocp apply' first."
sub stamp_ocp_version {
    my ($self, $config) = @_;
    $config->set_status('ocpVersion', $OCP::VERSION);
    $config->save_status;
    return;
}

sub deployment {
    my ($name, $opts) = @_;

    my $image = 'registry:2';

    my @volume_mounts;
    my @volumes;

    if ($opts->{config_map}) {
        push @volume_mounts, { name => 'config', mountPath => '/etc/docker/registry' };
        push @volumes, { name => 'config', configMap => { name => $opts->{config_map} } };
    }

    push @volume_mounts, { name => 'data', mountPath => '/var/lib/registry' };
    push @volumes, {
        name     => 'data',
        hostPath => { path => $opts->{host_path}, type => 'DirectoryOrCreate' },
    };

    my $container = {
        name         => 'registry',
        image        => $image,
        ports        => [{ containerPort => 5000, name => 'http' }],
        volumeMounts => \@volume_mounts,
        # /v2/ answers 200 as soon as the registry serves, in proxy mode too.
        # Without a probe the deployment counts as ready the moment the
        # container starts, which is what _poll_deployment_ready then believes.
        readinessProbe => {
            httpGet             => { path => '/v2/', port => 5000 },
            initialDelaySeconds => 2,
            periodSeconds       => 5,
        },
        resources    => {
            requests => { memory => '64Mi', cpu => '50m' },
            limits   => { memory => '512Mi' },
        },
    };

    $container->{env} = $opts->{env} if $opts->{env};

    # A proxying registry resolves its upstream once, while starting, and
    # panics if DNS does not answer yet. On a fresh cluster CoreDNS is
    # regularly a few seconds behind, so the cache crash-looped its way to
    # readiness. Wait for the name to resolve before the registry looks it up.
    my @init_containers;
    if (my $host = $opts->{wait_for_host}) {
        push @init_containers, {
            name    => 'wait-for-dns',
            image   => $image,
            command => ['/bin/sh', '-c'],
            args    => [
                join(' ',
                    'i=0;',
                    'while [ $i -lt 60 ]; do',
                    "nslookup $host >/dev/null 2>&1 && exit 0;",
                    'i=$((i+1)); sleep 2;',
                    'done;',
                    "echo 'DNS never resolved $host' >&2; exit 1",
                ),
            ],
            resources => { requests => { memory => '16Mi', cpu => '10m' } },
        };
    }

    return {
        apiVersion => 'apps/v1',
        kind       => 'Deployment',
        metadata   => { name => $name, namespace => 'ocp-system', labels => { app => $name } },
        spec       => {
            replicas => 1,
            selector => { matchLabels => { app => $name } },
            template => {
                metadata => { labels => { app => $name } },
                spec     => {
                    (@init_containers ? (initContainers => \@init_containers) : ()),
                    containers => [$container],
                    volumes    => \@volumes,
                },
            },
        },
    };
}

sub nodeport_service {
    my ($name, $node_port) = @_;
    return {
        apiVersion => 'v1',
        kind       => 'Service',
        metadata   => { name => $name, namespace => 'ocp-system' },
        spec       => {
            type     => 'NodePort',
            selector => { app => $name },
            ports    => [{
                port       => 5000,
                targetPort => 5000,
                nodePort   => $node_port,
                protocol   => 'TCP',
                name       => 'http',
            }],
        },
    };
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Versions>.

=cut

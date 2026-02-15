package OCP::Cmd::Apply;
# ABSTRACT: Reconcile cluster to match config

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);

use OCP::Config;
use OCP::Secrets;
use OCP::SSH;
use OCP::Rex;
use WWW::Hetzner::Cloud;

our $VERSION = '0.1.0';

option dry_run => (
    is    => 'ro',
    short => 'n',
    doc   => 'Show what would be done without doing it',
);

option only => (
    is     => 'ro',
    format => 's',
    doc    => 'Only apply: control-planes, workers, or node name',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $chain->[0]->config;
    my $verbose = $chain->[0]->verbose;

    unless (-f $file) {
        die "Config file '$file' not found. Run 'ocp init' first.\n";
    }

    my $config = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    print "Applying config: $file\n";
    print "Cluster: ", $config->name, "\n\n";

    # Get Hetzner token (from secrets or environment)
    my $hetzner_token = $secrets->hetzner_token;
    my $ssh_public_key = $config->ssh_public_key;

    # Initialize providers
    my $cloud;
    my $cp = $config->control_planes;
    if ($cp->{provider} eq 'hetzner') {
        unless ($hetzner_token) {
            die "Hetzner API token required.\n" .
                "Set HETZNER_API_TOKEN or run 'ocp init --hetzner' to configure.\n";
        }
        $cloud = WWW::Hetzner::Cloud->new(token => $hetzner_token);
    }

    # Calculate desired state
    my @desired_nodes = $self->_calculate_desired_nodes($config);

    # Get current state
    my @current_nodes = @{$config->nodes_status};

    # Calculate diff
    my (@to_create, @to_delete);

    my %current_by_name = map { $_->{name} => $_ } @current_nodes;
    my %desired_by_name = map { $_->{name} => $_ } @desired_nodes;

    for my $node (@desired_nodes) {
        if (!$current_by_name{$node->{name}}) {
            push @to_create, $node;
        }
    }

    for my $node (@current_nodes) {
        if (!$desired_by_name{$node->{name}}) {
            push @to_delete, $node;
        }
    }

    # Show plan
    if (@to_create) {
        print "Nodes to CREATE:\n";
        for my $n (@to_create) {
            print "  + $n->{name} ($n->{role}, $n->{provider})\n";
        }
        print "\n";
    }

    if (@to_delete) {
        print "Nodes to DELETE:\n";
        for my $n (@to_delete) {
            print "  - $n->{name}\n";
        }
        print "\n";
    }

    if (!@to_create && !@to_delete) {
        print "Nothing to do. Cluster matches config.\n";
        return;
    }

    if ($self->dry_run) {
        print "[Dry run - no changes made]\n";
        return;
    }

    # Execute changes
    my $cluster_info = $config->cluster_status;

    # Create nodes
    for my $node (@to_create) {
        my $display_name = $node->{name};
        # For SSH provider, show the host instead of generic name
        if ($node->{provider} eq 'ssh' && $node->{spec}{host}) {
            $display_name = $node->{spec}{host};
        }
        print "Creating $display_name...\n";

        my $created = $self->_create_node($node, $config, $cloud, $ssh_public_key);

        if ($created) {
            # Wait for SSH
            print "  Waiting for SSH...\n";
            my $ssh = OCP::SSH->new(
                host     => $created->{publicIp},
                key_file => $config->ssh_private_key_path,
            );

            eval { $ssh->wait_for_ssh(120) };
            if ($@) {
                print "  WARNING: SSH not ready: $@\n";
                $created->{phase} = 'SSHFailed';
            } else {
                print "  SSH ready.\n";

                # Get Kubernetes config
                my $k8s = $config->kubernetes;
                my $distribution = $k8s->{dist} || $k8s->{distribution} || 'rke2';
                my $version = $k8s->{version} || '';

                # API port depends on distribution
                my $api_port = $distribution eq 'k3s' ? 6443 : 9345;

                # Install Kubernetes
                if ($node->{role} eq 'control-plane' && !$cluster_info->{apiEndpoint}) {
                    # First control plane
                    print "  Installing $distribution server...\n";
                    my $rex = OCP::Rex->new(
                        host     => $created->{publicIp},
                        key_file => $config->ssh_private_key_path,
                        verbose  => $verbose,
                    );

                    my $result = $rex->install_server(
                        distribution => $distribution,
                        version      => $version,
                    );

                    $config->set_cluster_status(apiEndpoint => "https://$created->{publicIp}:$api_port");
                    $config->set_cluster_status(joinToken => $result->{token});
                    $config->set_cluster_status(kubeconfig => $result->{kubeconfig});
                    $config->set_cluster_status(distribution => $distribution);

                    # Refresh cluster_info for subsequent nodes
                    $cluster_info = $config->cluster_status;

                    # Single-node mode: untaint control plane
                    if ($config->single_node) {
                        print "  Single-node mode: untainting control plane...\n";
                        eval {
                            $rex->run_task('untaint_control_plane',
                                distribution => $distribution,
                            );
                        };
                        if ($@) {
                            print "  WARNING: Failed to untaint: $@\n";
                        } else {
                            print "  Control plane can now host workloads.\n";
                        }
                    }

                    # Install Cilium CNI
                    print "  Installing Cilium CNI...\n";
                    eval {
                        $rex->run_task('install_cilium',
                            distribution => $distribution,
                        );
                    };
                    if ($@) {
                        print "  WARNING: Cilium installation failed: $@\n";
                        print "  You can install manually later with: cilium install\n";
                    } else {
                        print "  Cilium ready.\n";
                    }

                    $created->{phase} = 'Ready';
                    print "  Control plane ready.\n";
                } else {
                    # Worker or additional control plane
                    my $api = $cluster_info->{apiEndpoint};
                    my $token = $cluster_info->{joinToken};

                    if ($api && $token) {
                        print "  Joining cluster...\n";
                        my $rex = OCP::Rex->new(
                            host     => $created->{publicIp},
                            key_file => $config->ssh_private_key_path,
                            verbose  => $verbose,
                        );

                        $rex->install_agent(
                            distribution => $distribution,
                            server       => $api,
                            token        => $token,
                            version      => $version,
                        );

                        $created->{phase} = 'Ready';
                        print "  Node joined.\n";
                    } else {
                        print "  WARNING: No cluster to join. Deploy control-plane first.\n";
                        $created->{phase} = 'Pending';
                    }
                }
            }

            $config->add_node_status($created);
        }
    }

    # Delete nodes
    for my $node (@to_delete) {
        print "Deleting $node->{name}...\n";
        $self->_delete_node($node, $config, $cloud);
        $config->remove_node_status($node->{name});
        print "  Deleted.\n";
    }

    # Update overall status
    $config->set_status(phase => 'Running');
    $config->save_status;

    print "\nApply complete. Run 'ocp status' to see results.\n";
}

sub _calculate_desired_nodes {
    my ($self, $config) = @_;

    my @nodes;

    # Control planes
    my $cp = $config->control_planes;
    my @cp_names = _parse_node_names($cp);

    for my $name (@cp_names) {
        push @nodes, {
            name     => $name,
            role     => 'control-plane',
            provider => $cp->{provider},
            spec     => $cp,
        };
    }

    # Workers
    for my $pool (@{$config->workers}) {
        my @worker_names = _parse_node_names($pool);

        for my $name (@worker_names) {
            push @nodes, {
                name     => $name,
                role     => 'worker',
                pool     => $pool->{name},
                provider => $pool->{provider} // 'ssh',
                spec     => $pool,
            };
        }
    }

    return @nodes;
}

sub _parse_node_names {
    my ($spec) = @_;

    # If 'nodes' is specified, use those names
    if (my $nodes = $spec->{nodes}) {
        # Can be comma-separated string or array
        if (ref $nodes eq 'ARRAY') {
            # Array of hashes (SSH nodes with host)
            if (ref $nodes->[0] eq 'HASH') {
                return map { $_->{name} } @$nodes;
            }
            return @$nodes;
        } else {
            return split /\s*,\s*/, $nodes;
        }
    }

    # Fall back to count with auto-generated names
    my $count = $spec->{count} // 1;
    my $prefix = $spec->{prefix} // 'node';
    return map { "$prefix-$_" } (1 .. $count);
}

sub _create_node {
    my ($self, $node, $config, $cloud, $ssh_public_key) = @_;

    my $provider = $node->{provider};

    if ($provider eq 'hetzner') {
        die "Hetzner token not configured\n" unless $cloud;

        my $spec = $node->{spec};
        my $cluster_name = $config->name;

        # Ensure SSH key exists in Hetzner
        my $key_name = "ocp-$cluster_name";
        if ($ssh_public_key) {
            $cloud->ssh_keys->ensure($key_name, $ssh_public_key);
        }

        my $server = $cloud->servers->create(
            name        => "$cluster_name-$node->{name}",
            server_type => $spec->{serverType} // 'cpx21',
            image       => $spec->{image} // 'debian-13',
            location    => $spec->{location} // 'fsn1',
            ssh_keys    => [$key_name],
            labels      => {
                'ocp-cluster' => $cluster_name,
                'ocp-role'    => $node->{role},
                'ocp-node'    => $node->{name},
            },
        );

        # Wait for running
        $server = $cloud->servers->wait_for_status($server->id, 'running', 120);

        return {
            name       => $node->{name},
            role       => $node->{role},
            pool       => $node->{pool},
            provider   => 'hetzner',
            providerId => $server->id,
            publicIp   => $server->ipv4,
            phase      => 'Provisioned',
            createdAt  => _timestamp(),
        };
    }
    elsif ($provider eq 'ssh') {
        # SSH provider - node must already exist
        my $spec = $node->{spec};

        # Find host for this node
        my $host;
        if (ref $spec->{nodes} eq 'ARRAY') {
            my ($node_spec) = grep { $_->{name} eq $node->{name} } @{$spec->{nodes}};
            $host = $node_spec->{host} if $node_spec;
        }
        $host //= $spec->{host};

        die "SSH node '$node->{name}' requires 'host' in spec\n" unless $host;

        return {
            name      => $node->{name},
            role      => $node->{role},
            pool      => $node->{pool},
            provider  => 'ssh',
            publicIp  => $host,
            phase     => 'Provisioned',
            createdAt => _timestamp(),
        };
    }
    else {
        die "Unknown provider: $provider\n";
    }
}

sub _delete_node {
    my ($self, $node, $config, $cloud) = @_;

    if ($node->{provider} eq 'hetzner' && $node->{providerId}) {
        $cloud->servers->delete($node->{providerId}) if $cloud;
    }
    # SSH nodes: nothing to delete (we don't own the server)
}

sub _timestamp {
    my @t = gmtime;
    return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
}

1;

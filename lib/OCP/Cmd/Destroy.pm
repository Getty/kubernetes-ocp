package OCP::Cmd::Destroy;
# ABSTRACT: Destroy cluster

use Moo;
use MooX::Cmd;
use MooX::Options;

use OCP;
use OCP::Config;
use OCP::Provider;
use OCP::Secrets;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

option force => (
    is    => 'ro',
    short => 'f',
    doc   => 'Skip confirmation',
);

option keep_status => (
    is  => 'ro',
    doc => 'Keep status file after destroy',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;

    unless (-f $file) {
        die "Config file '$file' not found.\n";
    }

    my $config = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    my $nodes = $config->nodes_status;

    # Initialize Hetzner provider if token available
    my $hetzner_token = $secrets->hetzner_token;
    my $hetzner_prov;
    if ($hetzner_token) {
        $hetzner_prov = OCP::Provider->for_spec(
            { provider => 'hetzner' },
            token        => $hetzner_token,
            cluster_name => $config->name,
        );
    }

    # If no nodes in status, check Hetzner directly for orphaned servers
    if (!@$nodes && $hetzner_prov) {
        my $servers = $hetzner_prov->list_servers_by_cluster($config->name);
        if (@$servers) {
            print "Found orphaned servers at Hetzner (not in status):\n";
            for my $s (@$servers) {
                push @$nodes, {
                    name       => $s->name,
                    provider   => 'hetzner',
                    providerId => $s->id,
                    public_ip => $s->ipv4 // '-',
                };
            }
        }
    }

    # Fall back to spec (control planes + workers) if still no nodes
    if (!@$nodes) {
        my $cps = $config->control_planes;
        my $idx = 0;
        for my $cp (@$cps) {
            $idx++;
            push @$nodes, {
                name     => $cp->{host} // ($config->name . "-cp-$idx"),
                provider => $cp->{provider} // 'ssh',
                public_ip => $cp->{host} // $cp->{public_ip} // '-',
            };
        }
        for my $w (@{$config->workers}) {
            if ($w->{provider} eq 'ssh' && $w->{nodes}) {
                for my $h (@{$w->{nodes}}) {
                    my $host = ref $h ? $h->{host} : $h;
                    push @$nodes, {
                        name     => $host,
                        provider => 'ssh',
                        public_ip => $host,
                    };
                }
            }
        }
    }

    unless (@$nodes) {
        print "No nodes to destroy.\n";
        return;
    }

    print "Cluster: ", $config->name, "\n";
    print "Nodes to destroy:\n";
    for my $node (@$nodes) {
        print "  - $node->{name} ($node->{provider}, $node->{public_ip})\n";
    }
    print "\n";

    unless ($self->force) {
        print "Are you sure you want to destroy this cluster? [y/N] ";
        my $answer = <STDIN>;
        chomp $answer;
        unless ($answer =~ /^y(es)?$/i) {
            print "Aborted.\n";
            return;
        }
    }

    # Delete nodes
    for my $node (@$nodes) {
        print "Deleting $node->{name}...\n";

        if ($node->{provider} eq 'hetzner' && $node->{providerId} && $hetzner_prov) {
            eval { $hetzner_prov->delete_server($node->{providerId}) };
            if ($@) {
                print "  Warning: $@\n";
            }
        }
        elsif ($node->{provider} eq 'ssh' && $node->{public_ip} && $node->{public_ip} ne '-') {
            print "  Uninstalling RKE2 on $node->{public_ip}...\n";
            my $ssh_prov = OCP::Provider->for_spec(
                { provider => 'ssh' },
                ssh_key_path => $config->ssh_private_key_path,
            );
            eval { $ssh_prov->delete_server(undef, host => $node->{public_ip}) };
            if ($@) {
                print "  Warning: Could not connect to $node->{public_ip} (may already be down).\n";
            } else {
                print "  RKE2/K3s uninstalled on $node->{public_ip}.\n";
            }
        }
    }

    # Clear status + kubeconfig
    unless ($self->keep_status) {
        my $status_file = $config->status_file;
        if (-f $status_file) {
            unlink $status_file;
            print "Status file removed.\n";
        }
    }

    my $kubeconfig = $config->project_dir->child('kubeconfig.yaml');
    if (-f $kubeconfig) {
        unlink $kubeconfig;
        print "Encrypted kubeconfig removed.\n";
    }

    print "\nCluster destroyed.\n";

    return 0;
}

1;

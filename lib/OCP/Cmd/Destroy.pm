package OCP::Cmd::Destroy;
# ABSTRACT: Destroy cluster

use Moo;
use MooX::Cmd;
use MooX::Options;

use OCP;
use OCP::Config;
use OCP::Secrets;
use OCP::SSH;
use WWW::Hetzner::Cloud;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

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

    # Get Hetzner client if token available
    my $cloud;
    my $hetzner_token = $secrets->hetzner_token;
    if ($hetzner_token) {
        $cloud = WWW::Hetzner::Cloud->new(token => $hetzner_token);
    }

    # If no nodes in status, check Hetzner directly for orphaned servers
    if (!@$nodes && $cloud) {
        my $servers = $cloud->servers->list_by_label("ocp-cluster=" . $config->name);
        if (@$servers) {
            print "Found orphaned servers at Hetzner (not in status):\n";
            for my $s (@$servers) {
                push @$nodes, {
                    name       => $s->name,
                    provider   => 'hetzner',
                    providerId => $s->id,
                    publicIp   => $s->ipv4 // '-',
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
                publicIp => $cp->{host} // $cp->{publicIp} // '-',
            };
        }
        for my $w (@{$config->workers}) {
            if ($w->{provider} eq 'ssh' && $w->{nodes}) {
                for my $h (@{$w->{nodes}}) {
                    my $host = ref $h ? $h->{host} : $h;
                    push @$nodes, {
                        name     => $host,
                        provider => 'ssh',
                        publicIp => $host,
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
        print "  - $node->{name} ($node->{provider}, $node->{publicIp})\n";
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

        if ($node->{provider} eq 'hetzner' && $node->{providerId} && $cloud) {
            eval { $cloud->servers->delete($node->{providerId}) };
            if ($@) {
                print "  Warning: $@\n";
            }
        }
        elsif ($node->{provider} eq 'ssh' && $node->{publicIp} && $node->{publicIp} ne '-') {
            print "  Uninstalling RKE2 on $node->{publicIp}...\n";
            my $ssh_key = $config->ssh_private_key_path;
            my $host = $node->{publicIp};
            my $ssh = OCP::SSH->new(
                host     => $host,
                key_file => $ssh_key,
            );
            my $result = $ssh->run(
                'rke2-uninstall.sh 2>/dev/null || k3s-uninstall.sh 2>/dev/null || true',
            );
            if ($result->{exit} == 0) {
                print "  RKE2/K3s uninstalled on $host.\n";
            } else {
                print "  Warning: Could not connect to $host (may already be down).\n";
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
}

1;

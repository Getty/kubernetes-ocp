package OCP::Cmd::Destroy;
# ABSTRACT: Destroy cluster

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);

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
    doc => 'Keep the local cluster state (.ocp/status.yaml, .ocp/deployed.yaml)',
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
    #
    # deployed.yaml goes with status.yaml, and for the same reason: both
    # describe the cluster that was just deleted (ADR 0004). Leaving the
    # manifest hashes behind made the next `ocp apply` compare a brand new
    # cluster against the components of the old one — it announced "Registry
    # already deployed (up to date)" on an empty ocp-system and then pointed
    # CoreDNS at a registry that was never rolled out. Nothing on the way to
    # that was an error, so nothing reported one.
    unless ($self->keep_status) {
        for my $file ($config->status_file, $config->deployed_file) {
            next unless -f $file;
            unlink $file;
            print "Removed ", path($file)->basename, ".\n";
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

__END__

=synopsis

    ocp destroy            # prompts for confirmation
    ocp destroy --force    # skip prompt
    ocp destroy --keep_status   # leave .ocp/status.yaml and .ocp/deployed.yaml behind

=description

C<ocp destroy> tears down every node recorded for the current cluster,
across both providers:

=over 4

=item *

Hetzner — each node carrying a C<providerId> is deleted via
L<OCP::Provider::Hetzner/delete_server>; the encrypted SSH key the
project uploaded is left in place and may be re-used by a later C<ocp apply>.

=item *

SSH — the RKE2/K3s uninstaller is run on the host.  Failures here are
best-effort: a host that is already gone is logged as a warning and the
tear-down continues.

=back

Sources for the node list, in order: C<.ocp/status.yaml>, the Hetzner
project (orphans that C<status.yaml> did not record, picked up via
L<OCP::Provider::Hetzner/list_servers_by_cluster>), and finally the
C<control_planes> and C<workers> sections of C<ocp.yaml> as a last resort.

After the nodes are gone, both C<.ocp/status.yaml> and
C<.ocp/deployed.yaml> are removed (unless C<--keep_status> is set) and the
encrypted C<kubeconfig.yaml> is deleted.  Leaving C<deployed.yaml> behind
was the bug behind C<ADR 0004>: a fresh C<ocp apply> compared a brand-new
cluster against the hash file of the previous one and announced every
component as "up to date" against a registry that was never rolled out.

=opt force

    --force, -f

Skip the C<Are you sure?> prompt.  Otherwise the command reads from
C<STDIN> and aborts unless the answer starts with C<y> or C<yes>
(case-insensitive).

=opt keep_status

    --keep-status

Keep C<.ocp/status.yaml> and C<.ocp/deployed.yaml> in place after
teardown.  Useful when the next step is C<ocp apply> against the same
spec and you want the reconcile path to start from a known-good hash set.

=method execute

    $cmd->execute($args, $chain)

Lists the candidate nodes, prompts for confirmation (unless C<--force>),
deletes each via its provider, removes the encrypted kubeconfig, and
returns 0.  Prints a warning and continues when a single Hetzner or SSH
delete fails.

=seealso

L<OCP::Cmd::Apply>, L<OCP::Cmd::Status>, L<OCP::Provider::Hetzner>,
L<OCP::Config>, L<OCP::Secrets>

=cut

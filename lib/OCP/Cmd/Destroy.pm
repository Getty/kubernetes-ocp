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

option force => (
    is    => 'ro',
    short => 'f',
    doc   => 'Skip confirmation',
);

option keep_status => (
    is  => 'ro',
    doc => 'Keep the local cluster state (.ocp/status.yaml, .ocp/deployed.yaml)',
);

# Servers this project paid for but which are not labelled with its name.
#
# Until karr #98, OCP::Provider::from_cr took the provider CR's OWN name for
# the cluster name, and `ocp apply` writes that CR as "<type>-default". So
# every worker brought up by `ocp node add` or robocop was labelled
# ocp-cluster=hetzner-default while the control plane carried the real cluster
# name. The teardown above searches ocp-cluster=<cluster> and walks straight
# past them — they keep running, keep billing, and this command still says
# "Cluster destroyed."
#
# The fix stops new ones appearing; it cannot relabel the machines already out
# there. So they get NAMED, never deleted. That label is generic by
# construction: a match may belong to a different OCP cluster in the same
# Hetzner project with the same defect, and deleting someone else's control
# plane to tidy up a labelling bug would be worse than the bug.
sub _report_mislabelled_servers {
    my ($self, $config, $hetzner_prov) = @_;
    return unless $hetzner_prov;

    # Exactly the names OCP::Cmd::Apply::CR::ensure_provider_cr writes, so this
    # is a derivation and not a guess. A provider added by hand under some
    # other name is out of reach here — the selector printed below finds those.
    my %stale;
    for my $entry (@{$config->control_planes}, @{$config->workers}) {
        my $type = $entry->{provider} // 'hetzner';
        next unless $type eq 'hetzner';
        my $label = "$type-default";
        next if $label eq $config->name;   # then the label was right all along
        $stale{$label} = 1;
    }
    return unless %stale;

    for my $label (sort keys %stale) {
        my $servers = eval { $hetzner_prov->list_servers_by_cluster($label) } || [];
        next unless @$servers;

        print "\n";
        printf "[!!] %d Hetzner server(s) carry the label ocp-cluster=%s and were\n",
               scalar @$servers, $label;
        print  "     NOT deleted. They are this cluster's, mislabelled before the\n";
        print  "     fix for karr #98 — they keep running and keep billing.\n";
        for my $s (@$servers) {
            printf "       - %s (id %s, %s)\n",
                   eval { $s->name } // '?',
                   eval { $s->id }   // '?',
                   eval { $s->ipv4 } // '-';
        }
        print  "     They are not removed automatically: that label is generic, so a\n";
        print  "     match can belong to another cluster in the same project. Check\n";
        print  "     and delete by hand:\n";
        print  "       hcloud server list -l ocp-cluster=$label\n";
        print  "       hcloud server delete <name>\n";
    }
}

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
        # karr #78: this early-return used to skip the cleanup that runs at
        # the bottom of execute(). It is exactly the shape a project takes
        # after a cluster was torn down out of band — status.yaml with
        # `nodes: []`, the spec slimmed down, no orphans at Hetzner — and
        # leaving deployed.yaml behind made the next `ocp apply` compare a
        # fresh cluster against the hashes of one that was gone (ADR 0004).
        # --keep_status opts out below.
        $self->_cleanup_project_state($config);
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

    # The key for the ssh-provider nodes: fetched ONCE, BEFORE the loop, in an
    # eval of its own. Three decisions in one block, and all three are about
    # never letting a cleanup step cost someone money.
    #
    #   * Why it is needed at all now. Until the two-tier decision this branch
    #     used the bootstrap key and could not fail: an unencrypted file, or
    #     no teardown. In secure mode there is no bootstrap key any more — an
    #     ssh machine trusts the admin key like every other machine — so the
    #     lookup is behind PIN2 and CAN die: wrong PIN, no terminal, no
    #     keys.yaml.
    #
    #   * Why before the loop. Each delete sits in its own eval so a host that
    #     is already gone is a warning, not the end of the run. A dying lookup
    #     inside the loop but outside those evals would abort the teardown
    #     midway — on a mixed cluster that leaves PAID Hetzner servers running
    #     because an ssh worker's key could not be unlocked. Hetzner deletes go
    #     through the API and need no SSH at all, so they must never depend on
    #     this.
    #
    #   * Why only when an ssh node is actually in the list. A pure Hetzner
    #     teardown must not grow a PIN2 prompt it never had.
    #
    # A failure here therefore downgrades to "the uninstall script did not
    # run on those machines", which is recoverable by hand, and says so.
    my $needs_ssh_key = grep {
        ($_->{provider} // '') eq 'ssh'
            && $_->{public_ip} && $_->{public_ip} ne '-'
    } @$nodes;

    my $ssh_key;
    if ($needs_ssh_key) {
        $ssh_key = eval {
            $self->cluster_ssh_key($config,
                provider => 'ssh',
                reason   => 'ocp destroy',
            );
        };
        unless ($ssh_key) {
            my $why = $@ || "unknown error\n";
            chomp $why;
            print "\n";
            print "[!!] Could not obtain the SSH key for the ssh-provider nodes:\n";
            print join('', map { "     $_\n" } split /\n/, $why);
            print "     Their RKE2/K3s uninstall will be SKIPPED. Everything\n";
            print "     that costs money is deleted through the provider API\n";
            print "     and is unaffected.\n";
            print "     To clean those machines up later, run on each of them:\n";
            print "       rke2-uninstall.sh   # or k3s-uninstall.sh\n";
            print "\n";
        }
    }

    # Delete nodes. $hinted keeps the migration diagnosis to one appearance
    # per run: six unreachable machines are six warnings, not six essays.
    my $hinted = 0;
    for my $node (@$nodes) {
        print "Deleting $node->{name}...\n";

        if ($node->{provider} eq 'hetzner' && $node->{providerId} && $hetzner_prov) {
            eval { $hetzner_prov->delete_server($node->{providerId}) };
            if ($@) {
                print "  Warning: $@\n";
            }
        }
        # An ssh-provider node: the machine survives, so what we can remove is
        # what we installed on it. The key comes from above, already resolved
        # or already known to be unavailable — nothing in this branch may die.
        elsif ($node->{provider} eq 'ssh' && $node->{public_ip} && $node->{public_ip} ne '-') {
            unless ($ssh_key) {
                print "  Skipped: no SSH key, $node->{public_ip} keeps its RKE2/K3s install.\n";
                next;
            }

            print "  Uninstalling RKE2 on $node->{public_ip}...\n";
            my $ssh_prov = OCP::Provider->for_spec(
                { provider => 'ssh' },
                ssh_key_path => $ssh_key->path,
            );
            my $result = eval {
                $ssh_prov->delete_server(undef, host => $node->{public_ip})
            };
            # OCP::SSH::run reports a failed connection as a non-zero exit
            # rather than an exception, so an unreachable host used to be
            # announced as a successful uninstall. Both shapes are a warning.
            my $failed = $@ || !ref $result || ($result->{exit} // 0) != 0;
            if ($failed) {
                print "  Warning: Could not uninstall on $node->{public_ip} (may already be down).\n";
                unless ($hinted++) {
                    print $ssh_key->migration_hint;
                }
            } else {
                print "  RKE2/K3s uninstalled on $node->{public_ip}.\n";
            }
        }
    }

    # Clear status + kubeconfig. Pulled into a helper so the early-return
    # path above ("no nodes to destroy") and the main path land at the same
    # code; the early-return bypass used to leave .ocp/deployed.yaml behind
    # when a cluster was torn down out of band (karr #78).
    $self->_cleanup_project_state($config);

    # Last, so it is the thing left on screen: a teardown that reported success
    # while paid machines kept running is the failure mode this is here for.
    $self->_report_mislabelled_servers($config, $hetzner_prov);

    print "\nCluster destroyed.\n";

    return 0;
}

# Remove the local files a successful destroy is meant to leave behind. Both
# paths through execute() -- the early "no nodes to destroy" return and the
# "nodes deleted, now tidy up" tail -- call this, so the local state dies with
# the cluster it described regardless of whether anything was actually torn
# down on the wire (karr #78).
#
# deployed.yaml goes with status.yaml, and for the same reason: both describe
# the cluster that was just deleted (ADR 0004). Leaving the manifest hashes
# behind made the next `ocp apply` compare a brand new cluster against the
# components of the old one — it announced "Registry already deployed (up to
# date)" on an empty ocp-system and then pointed CoreDNS at a registry that
# was never rolled out. Nothing on the way to that was an error, so nothing
# reported one.
#
# --keep_status is the documented opt-out; it covers status.yaml and
# deployed.yaml only. The encrypted kubeconfig is removed unconditionally —
# it is cluster access material, not cluster state.
sub _cleanup_project_state {
    my ($self, $config) = @_;

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

The key those SSH uninstalls use is resolved once, before the loop, and only
when the node list actually contains an ssh-provider machine (see
L<OCP::ClusterKey> — in secure mode that is the PIN2-protected admin key, so
it can fail; a Hetzner-only teardown never asks).  B<A failure to obtain it
does not stop the teardown.>  It is reported, the uninstall steps are skipped
with a per-host line, and every Hetzner server is still deleted through the
API — those cost money, an uninstall script does not.

Before the final line the teardown looks once more, under the C<ocp-cluster>
labels C<ocp apply> would have written a provider CR as
(C<< <type>-default >>), and B<names> anything still running there.  Those are
servers created before the fix for C<karr #98>, when the worker path took the
provider CR's own name for the cluster name: they belong to this cluster but
carry a label no teardown searches.  They are reported, never deleted — the
label is generic, so a match can belong to another OCP cluster in the same
Hetzner project.  The printed C<hcloud> selector is the way to inspect and
remove them by hand, and it is also the way to find servers under a provider
that was added with C<ocp provider add --name> rather than by C<ocp apply>.

Sources for the node list, in order: C<.ocp/status.yaml>, the Hetzner
project (orphans that C<status.yaml> did not record, picked up via
L<OCP::Provider::Hetzner/list_servers_by_cluster>), and finally the
C<control_planes> and C<workers> sections of C<ocp.yaml> as a last resort.

After the run, both C<.ocp/status.yaml> and C<.ocp/deployed.yaml> are
removed (unless C<--keep_status> is set) and the encrypted C<kubeconfig.yaml>
is deleted.  Leaving C<deployed.yaml> behind was the bug behind C<ADR 0004>:
a fresh C<ocp apply> compared a brand-new cluster against the hash file of
the previous one and announced every component as "up to date" against a
registry that was never rolled out.  Cleanup runs even when no nodes were
found to delete (C<karr #78>) — a teardown that discovers nothing on the
wire is exactly the shape a project directory takes after a cluster was
torn down out of band.

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

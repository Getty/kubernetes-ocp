package OCP::Cmd::Destroy;
# ABSTRACT: Destroy cluster

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::K8s;
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

# The cluster API. Built from the encrypted kubeconfig on first use; tests
# hand in a double.
has k8s => (is => 'rw');

# Set once the API failed to answer, so the teardown does not wait out a
# second timeout on it.
has _api_down => (is => 'rw');

# Servers this project paid for but which are not labelled with its name.
#
# Until k98, OCP::Provider::from_cr took the provider CR's OWN name for
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

        print STDERR "\n";
        printf STDERR "[!!] %d Hetzner server(s) carry the label ocp-cluster=%s and were\n",
               scalar @$servers, $label;
        print  STDERR "     NOT deleted. They are this cluster's, mislabelled before the\n";
        print  STDERR "     fix for k98 — they keep running and keep billing.\n";
        for my $s (@$servers) {
            printf STDERR "       - %s (id %s, %s)\n",
                   eval { $s->name } // '?',
                   eval { $s->id }   // '?',
                   eval { $s->ipv4 } // '-';
        }
        print  STDERR "     They are not removed automatically: that label is generic, so a\n";
        print  STDERR "     match can belong to another cluster in the same project. Check\n";
        print  STDERR "     and delete by hand:\n";
        print  STDERR "       hcloud server list -l ocp-cluster=$label\n";
        print  STDERR "       hcloud server delete <name>\n";
    }
}

# The cluster API, or undef when there is none to ask. Nothing here may die:
# a teardown has to run on a project whose kubeconfig is already gone, whose
# age key is missing, or whose control plane is half down -- that is when
# people run it. Whether the API really answers is only known at the first
# call; _ocpnode_entries makes that call and says so when it fails.
sub _cluster_api {
    my ($self, $config) = @_;
    return $self->k8s if $self->k8s;

    my $api = eval {
        my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
        my $kc      = $secrets->read_kubeconfig or return;

        my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
        print {$kc_fh} $kc;
        close $kc_fh;
        # Anchored on the instance: File::Temp unlinks on destruction.
        $self->{_kc_temp} = $kc_fh;

        my $api = Kubernetes::REST::Kubeconfig->new(
            kubeconfig_path => $kc_fh->filename,
        )->api;
        OCP::K8s->register($api);
        $api;
    };
    return $self->k8s($api) if $api;
    return;
}

# Every machine this cluster has, one entry each, workers first (k177).
#
# status.yaml records the control planes -- nothing else. Workers robocop
# brought up exist only as OCPNodes, so while the API answers those are read
# as the source of truth; the Hetzner label search and the ocp.yaml worker
# pools are merged in on every run, not only when status.yaml is empty, so a
# worker is still found when the API is already gone. The control-plane
# guess from ocp.yaml stays a last resort: its names are made up
# ("<cluster>-cp-N") and would never match a recorded node.
#
# Workers go first because a control plane torn down first takes the API --
# and with it the only record of the workers -- along.
sub _collect_nodes {
    my ($self, $config, $hetzner_prov, $api) = @_;

    my (@nodes, %by_key);
    my $add = sub {
        my ($node, @aliases) = @_;
        my @keys = $self->_node_keys($node, @aliases);
        my ($have) = grep { defined } @by_key{@keys};
        if ($have) {
            # The same machine from a second source: fill in what the first
            # did not know (a role, a providerId), never overwrite it.
            $have->{$_} //= $node->{$_} for keys %$node;
            $by_key{$_} = $have for @keys;
            return 0;
        }
        push @nodes, $node;
        $by_key{$_} = $node for @keys;
        return 1;
    };

    $add->({ %$_ }) for @{ $config->nodes_status };

    $add->(@$_) for $self->_ocpnode_entries($api);

    # Hetzner servers carrying this cluster's label that no other source knew.
    if ($hetzner_prov) {
        my $servers = eval { $hetzner_prov->list_servers_by_cluster($config->name) } || [];
        my $announced;
        for my $s (@$servers) {
            my $new = $add->({
                name       => $s->name,
                provider   => 'hetzner',
                providerId => $s->id,
                public_ip  => $s->ipv4 // '-',
            });
            next unless $new;
            print "Found orphaned servers at Hetzner (not in status):\n"
                unless $announced++;
            print '  - '.$s->name."\n";
        }
    }

    $add->(@$_) for $self->_spec_worker_entries($config);

    # Last resort: the control planes as ocp.yaml describes them.
    #
    # The gate uses OCP::Provider->known_type rather than `eq 'ssh'`, so a
    # CP carrying `provider: local` reaches the destroy loop instead of being
    # dropped on the floor -- the same seam k103 found in six other input
    # checks. A missing or unknown provider is skipped rather than relabelled
    # ssh: a literal `// 'ssh'` would put an unsupported node on the
    # destruction list (k116).
    unless (@nodes) {
        my $idx = 0;
        for my $cp (@{ $config->control_planes }) {
            next unless OCP::Provider->known_type($cp->{provider} // q());
            $idx++;
            $add->({
                name      => $cp->{host} // ($config->name . "-cp-$idx"),
                provider  => $cp->{provider},
                role      => 'control-plane',
                public_ip => $cp->{host} // $cp->{public_ip} // '-',
            });
        }
    }

    my @workers = grep { ($_->{role} // '') eq 'worker' } @nodes;
    my @rest    = grep { ($_->{role} // '') ne 'worker' } @nodes;
    return [ @workers, @rest ];
}

# What identifies a machine across the sources: its name, its address, its
# provider id -- any one of them matching is the same machine. A name is
# compared by its first label, the way `ocp apply` names an ssh worker's
# OCPNode after its host (OCP::Cmd::Apply::CR::worker_ocpnodes).
sub _node_keys {
    my ($self, $node, @aliases) = @_;
    my @keys;
    if (defined $node->{name} && length $node->{name}) {
        my ($short) = split /\./, lc $node->{name}, 2;
        push @keys, 'name:'.$short;
    }
    for my $host ($node->{public_ip}, @aliases) {
        next unless defined $host && length $host && $host ne '-';
        push @keys, 'host:'.lc $host;
    }
    push @keys, 'id:'.$node->{providerId}
        if defined $node->{providerId} && length $node->{providerId};
    return @keys;
}

# Every OCPNode, every role, as [ node entry, alias addresses ]. The provider
# TYPE comes from the OCPNodeProvider the node names; failing that from the
# "<type>-default" name `ocp apply` gives the CRs it writes (the derivation
# _report_mislabelled_servers relies on). A node neither answers is named on
# STDERR: it keeps running, and saying nothing about it is the bug this
# closes.
sub _ocpnode_entries {
    my ($self, $api) = @_;
    return unless $api;

    my $list = eval { $api->list('OCPNode', namespace => 'ocp-system') };
    unless ($list) {
        $self->_api_down(1);
        my $why = $@ || "no answer\n";
        chomp $why;
        print STDERR "[!!] Could not read the OCPNodes from the cluster API:\n";
        print STDERR "     $why\n";
        print STDERR "     Workers come from .ocp/status.yaml, Hetzner labels and\n";
        print STDERR "     ocp.yaml only; a worker added with `ocp node add` may be\n";
        print STDERR "     missed and keep running.\n";
        return;
    }

    my %type = map { ($_->{metadata}{name} => $_->{spec}{type}) }
               $self->provider_crs($api);

    my @entries;
    for my $cr (map { $api->k8s->object_to_struct($_) } @{ $list->items // [] }) {
        my $name   = $cr->{metadata}{name};
        my $spec   = $cr->{spec}   // {};
        my $status = $cr->{status} // {};
        my $ref    = $spec->{providerRef} // q();

        my $type = $type{$ref};
        ($type) = $ref =~ /\A(\w+)-default\z/ unless defined $type;
        unless (defined $type && OCP::Provider->known_type($type)) {
            print STDERR "[!!] OCPNode $name: provider '$ref' is unknown here;"
                       . " it is NOT torn down.\n";
            next;
        }

        push @entries, [ {
            name      => $name,
            provider  => $type,
            role      => $spec->{role} // 'worker',
            public_ip => $spec->{host} // $status->{publicIP} // '-',
            (defined $status->{providerId}
                ? (providerId => $status->{providerId}) : ()),
        }, grep { defined } $status->{publicIP}, $spec->{host} ];
    }
    return @entries;
}

# The worker machines ocp.yaml names by host -- `nodes: [host, ...]` and the
# single-host `host:` form alike -- as [ node entry ]. A pool that gives a
# count (`nodes: 2`) names no machine; its servers are found by label or by
# OCPNode, not here.
sub _spec_worker_entries {
    my ($self, $config) = @_;
    my @entries;
    for my $w (@{ $config->workers }) {
        next unless OCP::Provider->known_type($w->{provider} // q());
        my @hosts = ref $w->{nodes} eq 'ARRAY'
            ? map { ref $_ ? $_->{host} : $_ } @{ $w->{nodes} }
            : ($w->{host} // ());
        for my $host (grep { defined && length } @hosts) {
            push @entries, [ {
                name      => $host,
                provider  => $w->{provider},
                role      => 'worker',
                public_ip => $host,
            } ];
        }
    }
    return @entries;
}

# robocop reconciles OCPNodes: left running, it would see a worker vanish
# under it and provision a replacement -- a new paid server, created after the
# label search, that nothing is left to delete. Scaled to zero before the
# first delete. Best-effort: a cluster without robocop answers 404.
sub _stop_robocop {
    my ($self, $api) = @_;
    return if !$api || $self->_api_down;
    my $ok = eval {
        $api->patch('Deployment', 'robocop',
            namespace => 'ocp-system',
            patch     => { spec => { replicas => 0 } },
            type      => 'merge',
        );
        1;
    };
    if ($ok) {
        print "robocop stopped.\n";
        return 1;
    }
    my $why = $@ // q();
    return if $why =~ /\b404\b/;
    chomp $why;
    print STDERR "  Warning: could not stop robocop ($why);"
               . " it may re-provision a worker.\n";
    return;
}

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;

    unless (-f $file) {
        die "Config file '$file' not found.\n";
    }

    my $config = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
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

    # The cluster API, if it still answers: its OCPNodes are the only record
    # of the workers robocop brought up (k177).
    my $api   = $self->_cluster_api($config);
    my $nodes = $self->_collect_nodes($config, $hetzner_prov, $api);

    unless (@$nodes) {
        print "No nodes to destroy.\n";
        # k78: this early-return used to skip the cleanup that runs at
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

    $self->_stop_robocop($api);

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
            print STDERR "\n";
            print STDERR "[!!] Could not obtain the SSH key for the ssh-provider nodes:\n";
            print STDERR join('', map { "     $_\n" } split /\n/, $why);
            print STDERR "     Their RKE2/K3s uninstall will be SKIPPED. Everything\n";
            print STDERR "     that costs money is deleted through the provider API\n";
            print STDERR "     and is unaffected.\n";
            print STDERR "     To clean those machines up later, run on each of them:\n";
            print STDERR "       rke2-uninstall.sh   # or k3s-uninstall.sh\n";
            print STDERR "\n";
        }
    }

    # Delete nodes. $hinted keeps the migration diagnosis to one appearance
    # per run: six unreachable machines are six warnings, not six essays.
    #
    # @undeleted records the nodes whose PROVIDER delete failed -- a paid
    # server the API did not remove. It gates the cleanup below: status.yaml
    # is the only local record of a Hetzner server's providerId, so throwing
    # it away while the server is still running strands a billing machine with
    # no handle to find it by. That is the money-losing failure the ssh-key
    # block above guards against, in the one delete path that was not. An
    # existing-host (ssh/local) uninstall that fails is deliberately NOT
    # counted here: the machine is pre-existing, OCP never provisioned or
    # billed it, and the k116 branch below already treats "host already gone"
    # as a recoverable warning, not a stranded resource.
    #
    # Those go to @still_installed instead, as [ host, reason ]: the machines
    # that keep their RKE2/K3s install. They do not hold the cleanup back --
    # nothing in the local state is needed to reach them again, and a host
    # that is already gone would otherwise make the project impossible to tear
    # down -- but they do make the run incomplete: named at the end, exit 1
    # (k180).
    my $hinted = 0;
    my @undeleted;
    my @still_installed;
    for my $node (@$nodes) {
        print "Deleting $node->{name}...\n";

        if ($node->{provider} eq 'hetzner' && $node->{providerId} && $hetzner_prov) {
            # The address goes along so its host key leaves known_hosts with
            # the machine (k168).
            my $ip = ($node->{public_ip} // '-') ne '-' ? $node->{public_ip} : undef;
            eval {
                $hetzner_prov->delete_server($node->{providerId},
                    ($ip ? (host => $ip) : ()));
            };
            if ($@) {
                print STDERR "  Warning: $@\n";
                push @undeleted, $node;
            }
        }
        # An existing-host node (ssh, local): the machine survives, so what we
        # remove is what we installed on it. The branch used to hard-code
        # `eq 'ssh'`, so a local-provider node fell through with nothing --
        # the same way a future provider type would silently fall through
        # today. Both consume OCP::Role::Provider::ExistingHost, so the
        # delete call is identical; only ssh needs the key (the cluster
        # key comes from above, resolved or already known to be unavailable
        # -- nothing in this branch may die).
        #
        # The uninstall target is the provider's OWN resolve_host, not the
        # node's public_ip -- so which nodes can be cleaned up is the provider's
        # call, expressed through the ExistingHost contract, rather than a
        # string test on the provider name here. A spec-fallback node with no
        # `host` in ocp.yaml arrives with public_ip '-'; that is passed through
        # as "no host". ssh has nowhere to go without one -- resolve_host dies
        # and the node is skipped, exactly as before -- while the local
        # provider ignores the host entirely (resolve_host is a constant
        # 127.0.0.1) and still tears the box down. That last case is the bug
        # this closes: a `provider: local` cluster discovered only via the spec
        # fallback used to keep RKE2 installed after `ocp destroy` because the
        # old `public_ip ne '-'` gate dropped it (k146).
        elsif (OCP::Provider->known_type($node->{provider} // q())
               && $node->{provider} ne 'hetzner') {
            my $host_prov = OCP::Provider->for_spec(
                { provider => $node->{provider} },
                ($node->{provider} eq 'ssh' && $ssh_key
                    ? (ssh_key_path => $ssh_key->path)
                    : ()),
            );

            # '-' is the spec-fallback marker for "no host was recorded"; hand
            # the provider undef in that case so ssh's resolve_host dies rather
            # than treating '-' as a literal target, while local ignores it.
            my $ip = ($node->{public_ip} && $node->{public_ip} ne '-')
                ? $node->{public_ip} : undef;
            my $target = eval { $host_prov->resolve_host(host => $ip) };
            next unless defined $target && length $target;

            if ($node->{provider} eq 'ssh') {
                unless ($ssh_key) {
                    print STDERR "  Skipped: no SSH key, $target keeps its RKE2/K3s install.\n";
                    push @still_installed, [ $target, 'no SSH key' ];
                    next;
                }
            }

            print "  Uninstalling RKE2 on $target...\n";
            my $result = eval {
                $host_prov->delete_server(undef, host => $target)
            };
            # ExistingHost::delete_server dies with the host, the exit code and
            # the uninstaller's stderr (k175); a provider that returns a
            # non-zero exit instead is the same failure. Either way the reason
            # is what gets printed -- a fixed "may already be down" threw it
            # away and left the operator guessing (k180).
            my $why = $@;
            if (!$why && (!ref $result || ($result->{exit} // 0) != 0)) {
                my $exit   = ref $result ? $result->{exit} : '?';
                my $stderr = ref $result ? $result->{stderr} // '' : '';
                $stderr =~ s/\s+\z//;
                $why = "Uninstall of RKE2/K3s on $target failed (exit $exit)"
                     . (length $stderr ? ": $stderr" : '');
            }
            if ($why) {
                chomp $why;
                print STDERR "  Warning: could not uninstall on $target:\n";
                print STDERR join('', map { "    $_\n" } split /\n/, $why);
                push @still_installed, [ $target, $why ];
                # The migration hint names the bootstrap-vs-admin key story,
                # which is ssh-only. A local uninstall has no key.
                if ($node->{provider} eq 'ssh' && !$hinted++) {
                    print STDERR $ssh_key->migration_hint;
                }
            } else {
                print "  RKE2/K3s uninstalled on $target.\n";
            }
        }
    }

    # Clear status + kubeconfig. Pulled into a helper so the early-return
    # path above ("no nodes to destroy") and the main path land at the same
    # code; the early-return bypass used to leave .ocp/deployed.yaml behind
    # when a cluster was torn down out of band (k78).
    #
    # Skipped entirely when a provider delete failed (k140): the local state
    # is the only record of the surviving server's providerId, and removing it
    # would leave a paid machine running with nothing to find it by. Keeping
    # status.yaml (and deployed.yaml, and the kubeconfig that still reaches the
    # live cluster) intact lets a re-run pick up exactly where this one
    # stopped once the cause is fixed.
    unless (@undeleted) {
        $self->_cleanup_project_state($config);
    }

    # Last, so it is the thing left on screen: a teardown that reported success
    # while paid machines kept running is the failure mode this is here for.
    $self->_report_mislabelled_servers($config, $hetzner_prov);

    # A failed provider delete is the money-losing case: say so plainly, name
    # the survivors, and exit non-zero so callers and CI do not read this as a
    # clean teardown. Diagnosis on STDERR, per the output-channel rule (k105);
    # the "Cluster destroyed." payload below is only ever printed when the run
    # really did tear everything down.
    if (@undeleted) {
        print STDERR "\n";
        printf STDERR "[!!] Teardown INCOMPLETE: %d node(s) could not be deleted and\n",
               scalar @undeleted;
        print  STDERR "     are still running (and, at Hetzner, still billing):\n";
        for my $node (@undeleted) {
            printf STDERR "       - %s (%s, id %s)\n",
                   $node->{name}, $node->{provider},
                   $node->{providerId} // $node->{public_ip} // '?';
        }
        print  STDERR "     .ocp/status.yaml is kept so a re-run can find them by\n";
        print  STDERR "     providerId: fix the cause, then run `ocp destroy` again.\n";
    }

    # The machines that are not billed but not clean either (k180). The same
    # exit code as above: a caller needs to know "not everything is gone",
    # and the STDERR list says which kind of leftover it is.
    if (@still_installed) {
        print STDERR "\n";
        printf STDERR "[!!] Teardown INCOMPLETE: %d machine(s) keep their RKE2/K3s install:\n",
               scalar @still_installed;
        for my $left (@still_installed) {
            my ($host, $why) = @$left;
            my ($first) = split /\n/, $why;
            print STDERR "       - $host: $first\n";
        }
        print  STDERR "     Nothing is billed for them through OCP. Once they are\n";
        print  STDERR "     reachable, run on each of them:\n";
        print  STDERR "       rke2-uninstall.sh   # or k3s-uninstall.sh\n";
    }

    return 1 if @undeleted || @still_installed;

    print "\nCluster destroyed.\n";

    return 0;
}

# Remove the local files a successful destroy is meant to leave behind. Both
# paths through execute() -- the early "no nodes to destroy" return and the
# "nodes deleted, now tidy up" tail -- call this, so the local state dies with
# the cluster it described regardless of whether anything was actually torn
# down on the wire (k78).
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

SSH / local — the RKE2/K3s uninstaller is run on the host.  A failure here
does not stop the tear-down: the reason the uninstaller gave (host, exit
code, its stderr) is printed on STDERR and the next machine is tried.  At
the end every machine that kept its install is listed with its reason and
the command returns 1 (C<k180>).  The local state is still removed — the
machine is not billed through OCP and nothing in C<status.yaml> is needed to
reach it again, while holding the cleanup back would make a project whose
host is already gone impossible to tear down.

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
servers created before the fix for C<k98>, when the worker path took the
provider CR's own name for the cluster name: they belong to this cluster but
carry a label no teardown searches.  They are reported, never deleted — the
label is generic, so a match can belong to another OCP cluster in the same
Hetzner project.  The printed C<hcloud> selector is the way to inspect and
remove them by hand, and it is also the way to find servers under a provider
that was added with C<ocp provider add --name> rather than by C<ocp apply>.

The node list is merged from every source, one entry per machine
(matched by name, address or provider id): C<.ocp/status.yaml> (the
control planes); every OCPNode in the cluster, all roles, while the
cluster API answers (the only record of the workers robocop or
C<ocp node add> brought up); the Hetzner servers carrying this cluster's
label (L<OCP::Provider::Hetzner/list_servers_by_cluster>); and the worker
pools of C<ocp.yaml> that name their machines, in the C<nodes: [...]> and the
single C<host:> form.  The C<control_planes> section of C<ocp.yaml> is a last
resort, used only when nothing else found a node.  An API that does not
answer is reported on STDERR and the teardown continues from the other
sources (C<k177>).

Workers are torn down before the control planes, and robocop is scaled to
zero first so it does not provision a replacement for a worker it sees
disappear.  A Hetzner server is deleted together with its known_hosts
entries (C<k168>).

After the run, both C<.ocp/status.yaml> and C<.ocp/deployed.yaml> are
removed (unless C<--keep_status> is set) and the encrypted C<kubeconfig.yaml>
is deleted.  Leaving C<deployed.yaml> behind was the bug behind C<ADR 0004>:
a fresh C<ocp apply> compared a brand-new cluster against the hash file of
the previous one and announced every component as "up to date" against a
registry that was never rolled out.  Cleanup runs even when no nodes were
found to delete (C<k78>) — a teardown that discovers nothing on the
wire is exactly the shape a project directory takes after a cluster was
torn down out of band.  It is B<skipped>, though, when any provider delete
failed: the survivor is still running (and still billing) and
C<status.yaml> is the only local record of its C<providerId>, so keeping it
is what lets a re-run finish the job (C<k140>).

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
deletes each via its provider and, on a clean run, removes the local state
and the encrypted kubeconfig and returns 0.  A failed or skipped SSH/local
uninstall does not stop the run and does not keep the local state, but it is
named with its reason at the end and the command returns 1 (C<k180>).  A
failed B<provider>
delete — a Hetzner server the API did not remove — is different: the local
state is B<kept> so a re-run can find the survivor by its C<providerId>, the
teardown is reported B<incomplete> on STDERR, and the command returns
non-zero (C<k140>).

=seealso

L<OCP::Cmd::Apply>, L<OCP::Cmd::Status>, L<OCP::Provider::Hetzner>,
L<OCP::Config>, L<OCP::Secrets>

=cut

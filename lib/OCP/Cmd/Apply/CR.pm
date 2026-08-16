package OCP::Cmd::Apply::CR;
# ABSTRACT: CR-first worker/CP reconciliation (OCPNode / OCPNodeProvider)

use strict;
use warnings;

use MIME::Base64 ();
use Path::Tiny qw(path);
use YAML::XS ();

use OCP::K8s;
use OCP::Node;
use OCP::Provider;
use OCP::SSH;

=head1 SYNOPSIS

    OCP::Cmd::Apply::CR::ensure_crds($apply, $api);
    OCP::Cmd::Apply::CR::ensure_providers($apply, $api, $config, $secrets);
    OCP::Cmd::Apply::CR::ensure_cp_ocpnode($apply, $api, $cp_info);
    OCP::Cmd::Apply::CR::ensure_worker_ocpnodes($apply, $api, $config);
    OCP::Cmd::Apply::CR::migrate_legacy_nodes($apply, $api);
    OCP::Cmd::Apply::CR::ensure_robocop($apply, $api);
    OCP::Cmd::Apply::CR::wait_robocop_ready($apply, $api, $timeout);
    OCP::Cmd::Apply::CR::drive_workers($apply, $api, $config, $deps);
    OCP::Cmd::Apply::CR::print_worker_status($apply, $results);

=head1 DESCRIPTION

The whole CR layer that surrounds the bootstrap: OCPNode/OCPNodeProvider
schemas, provider credentials, per-pool Pending OCPNode writes, the
legacy-k8s-node migration, robocop deployment, and the worker reconcile
loop. Apply.pm calls these helpers in two places — the deploy path and the
reconcile path — so this module is the single source of truth for what
"CR-first" means here.

Worker reconcile has two modes. When robocop is the loop owner (the typical
cluster), C<drive_workers> just polls each OCPNode's status phase until it
reaches Ready/Failed or times out. When robocop is disabled or not yet
ready, it falls back to C<OCP::Node->reconcile_until_ready> per worker —
that's the CLI path, and it is what t/38-reconcile-path.t exercises.

On that fallback path a worker that never reaches Ready is explained with
L<OCP::ClusterKey/migration_hint>, once per run however many machines are
unreachable. That belongs here and not in L<OCP::Node>: the same class runs
inside Robocop, which joins with the robo key and has no C<ocp keys show> to
point anybody at. The hint changes nothing about the result rows — a worker
that did not come up is still C<Failed>.

L<OCP::Cmd::Apply> re-exports every helper as a thin C<_method>
forwarder — the existing test surface (t/20-apply-refactor.t,
t/36-ocpnode-status.t, t/38-reconcile-path.t) keeps working.

=cut

sub ensure_crds {
    my ($self, $api) = @_;
    my $share_dir = $self->_find_share_dir;
    my $crd_dir   = $share_dir->child('robocop', 'crds');
    return unless -d $crd_dir;

    # Server-side apply the CRDs as raw manifests instead of ensure().
    #
    # ensure() inflates the hashref into a typed CustomResourceDefinition, and a
    # CRD schema is full of union-typed fields — `default: false`, `enum:`,
    # `items:`, `additionalProperties:`. IO::K8s ships no classes for those
    # unions (JSON, JSONSchemaPropsOr{Array,Bool,StringArray}), so the inflate
    # dies outright. Even once those classes exist, a union arm that is a bare
    # scalar has nowhere to go in an attribute-based inflate, and the CRD would
    # be written back missing its defaults — silent damage instead of a crash.
    #
    # Nothing here needs a typed round-trip; the NFD and GPU CRDs already go the
    # same way via _apply_yaml_file.
    for my $file_path (sort $crd_dir->children(qr/\.ya?ml$/)) {
        my @docs = YAML::XS::LoadFile($file_path->stringify);
        for my $doc (@docs) {
            next unless ref $doc eq 'HASH' && $doc->{kind} && $doc->{metadata}{name};
            $self->_server_side_apply($api, $doc);
            print "  [ok] ensured $doc->{kind}/$doc->{metadata}{name}\n";
        }
    }
}

sub ensure_providers {
    my ($self, $api, $config, $secrets) = @_;
    my $ns = 'ocp-system';

    # Ensure ocp-system namespace exists (idempotent via ensure).
    $api->ensure({
        apiVersion => 'v1',
        kind       => 'Namespace',
        metadata   => { name => $ns },
    });

    my %seen;
    for my $entry (@{$config->control_planes}, @{$config->workers}) {
        my $type = $entry->{provider} // 'hetzner';
        next if $seen{$type}++;
        ensure_provider_cr($self, $api, $type, $ns, $config, $secrets);
    }
}

sub ensure_provider_cr {
    my ($self, $api, $type, $ns, $config, $secrets) = @_;

    my $name = "$type-default";

    # clusterName sits OUTSIDE the per-type branch on purpose: it is the
    # cluster this provider serves, not a Hetzner setting, and one write here
    # covers every provider type present and future. The CR name is
    # "<type>-default" and says nothing about the cluster, so from_cr reading
    # metadata.name gave every worker's server the label
    # ocp-cluster=hetzner-default — invisible to `ocp destroy`, invisible to
    # server_exists, and billed for either way (karr #98).
    my $spec = { type => $type, clusterName => $config->name };
    if ($type eq 'hetzner') {
        my $secret_name = "hetzner-api-token-$type";
        my $token = eval { $secrets->hetzner_token };
        if ($token) {
            $api->ensure({
                apiVersion => 'v1',
                kind       => 'Secret',
                type       => 'Opaque',
                metadata   => {
                    name      => $secret_name,
                    namespace => $ns,
                },
                data => {
                    token => MIME::Base64::encode_base64($token, ''),
                },
            });
            print "  [ok] ensured Secret/$secret_name\n";
        }
        # sshKeyName is what makes the worker path reachable at all. OCP::Node
        # is trigger-neutral and carries no cluster identity, and robocop has
        # none either — so the provider CR is the only thing that can tell a
        # Hetzner worker which uploaded key to boot with. This is the same
        # derivation bootstrap uses when it uploads it (karr #92).
        $spec->{hetzner} = {
            tokenSecretRef => { name => $secret_name, key => 'token' },
            sshKeyName     => $config->admin_ssh_key_name,
        };
    } elsif ($type eq 'ssh') {
        $spec->{ssh} = { user => 'root' };
    }

    $api->ensure({
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNodeProvider',
        metadata   => { name => $name, namespace => $ns },
        spec       => $spec,
    });
    print "  [ok] ensured OCPNodeProvider/$name\n";
}

# Address of a Kubernetes Node object: ExternalIP wins, InternalIP is the
# fallback. Returns undef when the Node is not (yet) registered.
sub k8s_node_ip {
    my ($self, $api, $name) = @_;

    my $node = eval { $api->get('Node', $name) } or return undef;
    my $hash = ref($node) eq 'HASH' ? $node : $api->k8s->object_to_struct($node);

    for my $want (qw(ExternalIP InternalIP)) {
        for my $addr (@{ $hash->{status}{addresses} // [] }) {
            return $addr->{address} if $addr->{type} eq $want && $addr->{address};
        }
    }
    return undef;
}

# Write an observational OCPNode CR for the just-bootstrapped control
# plane with phase=Ready. CP reconcile is not in scope; this CR makes
# `ocp node ls` show CP + workers uniformly.
#
# Ownership: robocop only ever reconciles workers, and on a CLI-only cluster it
# is not running at all — so nobody but `ocp apply` can report the state of the
# control plane it just bootstrapped. Hence status is written here, stamped
# reconciler=cli, and stays observational: no reconcile loop reads it back.
#
# Spec and status are two writes on purpose. The CRD enables the status
# subresource, so the API server drops status from the ensure (see
# OCP::K8s::patch_status) — it has to go to /status separately.
sub ensure_cp_ocpnode {
    my ($self, $api, $cp_info) = @_;
    my $ns   = 'ocp-system';
    my $name = $cp_info->{name};
    my $type = $cp_info->{provider} // 'hetzner';

    $api->ensure({
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => $name, namespace => $ns },
        spec       => {
            role        => 'control-plane',
            providerRef => "$type-default",
        },
    });

    # Prefer the address the Node object reports, so `ocp node ls` and
    # `ocp status` agree. cp_info->{host} is whatever the user configured and
    # is frequently a DNS name rather than an IP.
    my $ip = k8s_node_ip($self, $api, $name) // $cp_info->{host};

    my $ok = eval {
        OCP::K8s->patch_status($api,
            kind      => 'OCPNode',
            name      => $name,
            namespace => $ns,
            status    => {
                phase              => 'Ready',
                ($ip ? (publicIP => $ip) : ()),
                kubernetesNodeName => $name,
                reconciler         => 'cli',
            },
        );
        1;
    };

    if ($ok) {
        print "  [ok] ensured OCPNode/$name (control-plane, Ready)\n";
    } else {
        print "  [WARN] ensured OCPNode/$name, but its status stayed unwritten: $@";
    }
}

# For each k8s Node not yet tracked by an OCPNode CR, synthesize an
# observational OCPNode CR with phase=Ready and providerRef=legacy.
# Safe to run on every apply — already-synthesized CRs are no-ops via ensure.
sub migrate_legacy_nodes {
    my ($self, $api) = @_;

    my $cr_list = eval { $api->list('OCPNode', namespace => 'ocp-system') };
    return unless $cr_list;

    my %tracked = map {
        my $n = $api->k8s->object_to_struct($_);
        ($n->{metadata}{name} => 1);
    } @{ $cr_list->items // [] };

    my $node_list = eval { $api->list('Node') };
    return unless $node_list;

    my @untracked;
    for my $obj (@{ $node_list->items // [] }) {
        my $n    = $api->k8s->object_to_struct($obj);
        my $name = $n->{metadata}{name};
        next if $tracked{$name};
        push @untracked, $n;
    }

    return unless @untracked;

    $api->ensure({
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNodeProvider',
        metadata   => {
            name        => 'legacy',
            namespace   => 'ocp-system',
            annotations => { 'ocp.internal/synthetic' => 'true' },
        },
        spec => { type => 'ssh' },
    });

    for my $n (@untracked) {
        my $name  = $n->{metadata}{name};
        my $is_cp = exists $n->{metadata}{labels}{'node-role.kubernetes.io/control-plane'};
        my $public_ip;
        for my $addr (@{ $n->{status}{addresses} // [] }) {
            $public_ip = $addr->{address}, last if $addr->{type} eq 'ExternalIP';
        }
        unless ($public_ip) {
            for my $addr (@{ $n->{status}{addresses} // [] }) {
                $public_ip = $addr->{address}, last if $addr->{type} eq 'InternalIP';
            }
        }

        my $cr = {
            apiVersion => 'ocp.internal/v1',
            kind       => 'OCPNode',
            metadata   => {
                name        => $name,
                namespace   => 'ocp-system',
                annotations => { 'ocp.internal/synthetic' => 'true' },
            },
            spec => {
                role        => $is_cp ? 'control-plane' : 'worker',
                providerRef => 'legacy',
            },
        };
        $api->ensure($cr);

        # Separate write: the ensure above cannot carry status past the
        # status subresource (see OCP::K8s::patch_status).
        eval {
            OCP::K8s->patch_status($api,
                kind      => 'OCPNode',
                name      => $name,
                namespace => 'ocp-system',
                status    => {
                    phase              => 'Ready',
                    kubernetesNodeName => $name,
                    ($public_ip ? (publicIP => $public_ip) : ()),
                },
            );
            1;
        } or print "  [WARN] status for migrated OCPNode/$name stayed unwritten: $@";

        printf "  [migrated] %s (%s, %s)\n", $name,
               $cr->{spec}{role}, $public_ip // 'no-ip';
    }
}

# Write one Pending OCPNode CR per worker entry. If role/provider/etc. on
# the CR already differs in the cluster, the ensure preserves status
# (patch semantics are owned by the controller/CLI later).
sub ensure_worker_ocpnodes {
    my ($self, $api, $config) = @_;
    my $ns = 'ocp-system';
    my @crs;

    my $pool_idx = 0;
    for my $pool (@{$config->workers}) {
        my $pool_name = $pool->{name} // 'pool' . ++$pool_idx;
        my $type      = $pool->{provider} // 'hetzner';
        my $count     = $pool->{nodes} // 1;

        my @hosts;
        if ($type eq 'ssh') {
            if (ref $pool->{nodes} eq 'ARRAY') {
                @hosts = map { ref $_ ? $_->{host} : $_ } @{$pool->{nodes}};
            } elsif ($pool->{host}) {
                @hosts = ($pool->{host});
            }
            $count = scalar @hosts || 1;
        }

        for my $i (1 .. $count) {
            my $w_name = "$pool_name-$i";
            my $host;
            if ($type eq 'ssh') {
                $host = $hosts[$i - 1] // next;
                ($w_name) = split(/\./, $host, 2);
            }

            my $spec = {
                role        => 'worker',
                providerRef => "$type-default",
            };
            $spec->{host}       = $host                     if $host;
            $spec->{serverType} = $pool->{server_type}      if $pool->{server_type};
            $spec->{image}      = $pool->{image}            if $pool->{image};
            $spec->{location}   = $pool->{location}         if $pool->{location};

            my $cr = {
                apiVersion => 'ocp.internal/v1',
                kind       => 'OCPNode',
                metadata   => { name => $w_name, namespace => $ns },
                spec       => $spec,
            };
            $api->ensure($cr);
            print "  [ok] ensured OCPNode/$w_name (worker, Pending)\n";
            push @crs, $cr;
        }
    }
    return @crs;
}

# Apply RBAC + Deployment for robocop. CRDs were already applied in
# ensure_crds. Mirrors OCP::Cmd::DeployRobocop's loop but scoped to the
# non-CRD files under share/robocop/.
sub ensure_robocop {
    my ($self, $api) = @_;
    my $share_dir   = $self->_find_share_dir;
    my $robocop_dir = $share_dir->child('robocop');

    my @other_files = grep { $_->basename ne 'kustomization.yaml' }
                           $robocop_dir->children(qr/\.ya?ml$/);

    for my $file_path (sort @other_files) {
        my @docs = YAML::XS::LoadFile($file_path->stringify);
        for my $doc (@docs) {
            next unless ref $doc eq 'HASH' && $doc->{kind} && $doc->{metadata}{name};
            $api->ensure($doc);
            print "  [ok] ensured $doc->{kind}/$doc->{metadata}{name}\n";
        }
    }
}

sub wait_robocop_ready {
    my ($self, $api, $timeout) = @_;
    $timeout //= 60;

    my $deadline = time + $timeout;
    while (time < $deadline) {
        my $dep = eval { $api->get('Deployment', 'robocop', namespace => 'ocp-system') };
        if ($dep) {
            my $ready = eval { $dep->status->readyReplicas } // 0;
            return 1 if $ready && $ready >= 1;
        }
        $self->wait_seconds(5);
    }
    return 0;
}

# Drive worker reconcile. Either poll CR phases (if robocop is running)
# or run the CLI reconcile path (via OCP::Node) in-process. Returns a
# list of { name, phase, message } results.
sub drive_workers {
    my ($self, $api, $config, $deps) = @_;

    my $ns      = 'ocp-system';
    my $workers = $config->workers;
    my @names;

    my $pool_idx = 0;
    for my $pool (@$workers) {
        my $pool_name = $pool->{name} // 'pool' . ++$pool_idx;
        my $type      = $pool->{provider} // 'hetzner';
        my $count     = $pool->{nodes} // 1;

        my @hosts;
        if ($type eq 'ssh') {
            if (ref $pool->{nodes} eq 'ARRAY') {
                @hosts = map { ref $_ ? $_->{host} : $_ } @{$pool->{nodes}};
            } elsif ($pool->{host}) {
                @hosts = ($pool->{host});
            }
            $count = scalar @hosts || 1;
        }

        for my $i (1 .. $count) {
            my $w_name = "$pool_name-$i";
            if ($type eq 'ssh') {
                my $host = $hosts[$i - 1] // next;
                ($w_name) = split(/\./, $host, 2);
            }
            push @names, $w_name;
        }
    }

    if ($deps->{robocop_ready}) {
        return poll_nodes_until_terminal($self, $api, \@names, 600);
    }

    # CLI fallback: drive each OCPNode via OCP::Node.
    return cli_reconcile_workers($self, $api, $config, \@names, $deps);
}

sub poll_nodes_until_terminal {
    my ($self, $api, $names, $timeout) = @_;
    $timeout //= 600;
    my $ns = 'ocp-system';

    my $deadline = time + $timeout;
    my %terminal;

    while (time < $deadline && scalar(keys %terminal) < scalar(@$names)) {
        for my $name (@$names) {
            next if $terminal{$name};
            my $cr = eval { $api->get('OCPNode', $name, namespace => $ns) };
            my $hash = $cr
                ? (ref($cr) eq 'HASH' ? $cr : $api->k8s->object_to_struct($cr))
                : undef;
            my $phase = $hash && $hash->{status} && $hash->{status}{phase} || 'Pending';
            my $msg   = $hash && $hash->{status} && $hash->{status}{message} || '';
            if ($phase eq 'Ready' || $phase eq 'Failed') {
                $terminal{$name} = { name => $name, phase => $phase, message => $msg };
            }
        }
        last if scalar(keys %terminal) == scalar(@$names);
        $self->wait_seconds(10);
    }

    my @results;
    for my $name (@$names) {
        push @results, $terminal{$name} // {
            name    => $name,
            phase   => 'Unknown',
            message => "timed out waiting for phase (after ${timeout}s)",
        };
    }
    return @results;
}

sub cli_reconcile_workers {
    my ($self, $api, $config, $names, $deps) = @_;
    my $ns = 'ocp-system';

    my $ssh_key_path = $deps->{ssh_key_path};
    my $cp_ip        = $deps->{cp_ip};
    my $secrets      = $deps->{secrets};
    my $distribution = $config->distribution || 'rke2';

    # What a machine that will not answer probably means, ready to print.
    #
    # $deps carries only the key's PATH, but the OCP::ClusterKey it came from
    # is parked on the command object by
    # OCP::Cmd::Apply::Bootstrap::setup_ssh_key — which is exactly what the
    # caching in OCP::Role::Cmd was built for, and the only route this sub has
    # to the key's ORIGIN. A path cannot answer "was this the admin key", and
    # rebuilding the condition here would be a second copy of a decision that
    # already has one home.
    #
    # The non-building lookup on purpose: a rollout must not stop for a PIN2
    # prompt just to work out whether to print a paragraph. No key on the
    # object, no hint.
    #
    # OCP::Node learns none of this. It is the same class robocop runs in the
    # cluster, where `ocp keys show` is not a command anyone can type; robocop
    # also joins with the robo key, so its failure is a different one
    # (karr #97, ADR 0027).
    my $key  = $self->cluster_ssh_key_if_known($config);
    my $hint = $key ? $key->migration_hint : '';

    # One appearance per run, the way `ocp destroy` does it: five unreachable
    # machines are five failures, not five essays.
    my $hinted = 0;

    # Retrieve join token from the CP once, reused for every worker.
    my $join_token = '';
    my $server_url = $config->join_url($cp_ip);
    my $ssh_key    = eval { path($ssh_key_path)->slurp } // '';

    eval {
        my $cp_ssh = OCP::SSH->new(
            host     => $cp_ip,
            key_file => $ssh_key_path,
            user     => 'root',
        );
        my $token_path = $distribution eq 'k3s'
            ? '/var/lib/rancher/k3s/server/node-token'
            : '/var/lib/rancher/rke2/server/node-token';
        my $res = $cp_ssh->run("cat $token_path");
        $join_token = $res->{stdout} // '';
        chomp $join_token;
    };
    if ($@ || !$join_token) {
        # The control plane itself refused the key — same diagnosis, and the
        # workers below are never attempted, so this is the only place it can
        # be said on this run.
        print $hint if $hint && !$hinted++;
        my @results = map { {
            name    => $_,
            phase   => 'Failed',
            message => "Could not read join token from CP: " . ($@ // 'empty'),
        } } @$names;
        return @results;
    }

    my @results;
    for my $name (@$names) {
        my $cr = eval { $api->get('OCPNode', $name, namespace => $ns) };
        my $hash = $cr
            ? (ref($cr) eq 'HASH' ? $cr : $api->k8s->object_to_struct($cr))
            : undef;
        unless ($hash) {
            push @results, { name => $name, phase => 'Failed',
                             message => 'CR not found after ensure' };
            next;
        }

        # from_cr reads its argument as a plain hash ($cr->{spec}{hetzner}...).
        # get() returns a typed IO::K8s object, which only answers that because
        # IO::K8s objects happen to be blessed hashes -- convert it, the way
        # the OCPNode above and OCP::Robocop::Controller already do.
        my $provider = eval {
            my $prov_cr = $api->get('OCPNodeProvider',
                $hash->{spec}{providerRef}, namespace => $ns);
            OCP::Provider->from_cr(
                ref($prov_cr) eq 'HASH' ? $prov_cr : $api->k8s->object_to_struct($prov_cr),
                k8s => $api,
            );
        };
        if ($@ || !$provider) {
            push @results, { name => $name, phase => 'Failed',
                             message => "Provider resolve failed: " . ($@ // 'unknown') };
            next;
        }

        my $node = OCP::Node->from_cr($hash,
            k8s          => $api,
            provider     => $provider,
            ssh_key      => $ssh_key,
            server_url   => $server_url,
            join_token   => $join_token,
            distribution => $distribution,
            verbose      => $self->ocp->verbose,
        );

        # The interval is this path's own (workers are driven one after the
        # other, so poll less often); the budget is not. It is the same
        # question `ocp node add` asks, and OCP::Node answers it once, in
        # $OCP::Node::READY_TIMEOUT -- the 600 named here was a third copy of a
        # number that no longer covered the waits underneath it (karr #109).
        my $ok = eval { $node->reconcile_until_ready(interval => 10) };
        my $phase = $ok ? 'Ready' : ($node->phase || 'Failed');

        # Only from here, where a key was actually offered to a machine. The
        # two `next` branches above failed before any SSH happened — blaming
        # authorized_keys for a missing CR would be a guess wearing a
        # diagnosis's clothes.
        #
        # Printed as it happens rather than after the loop, so the operator
        # reads it at the first refusal instead of after four more timeouts.
        # The result row is unchanged: this worker stays Failed and `ocp
        # apply` still ends the way it would have.
        print $hint if !$ok && $hint && !$hinted++;

        push @results, {
            name    => $name,
            phase   => $phase,
            message => $hash->{status}{message} // '',
        };
    }
    return @results;
}

sub print_worker_status {
    my ($self, $results) = @_;
    return unless $results && @$results;
    print "\n";
    print "  Worker status:\n";
    for my $r (@$results) {
        my $tag = $r->{phase} eq 'Ready'  ? '[ok]'
                : $r->{phase} eq 'Failed' ? '[!!]'
                :                           '[..]';
        print "    $tag $r->{name} — $r->{phase}" .
              ($r->{message} ? " ($r->{message})" : "") . "\n";
    }
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Node>, L<OCP::K8s>.

=cut

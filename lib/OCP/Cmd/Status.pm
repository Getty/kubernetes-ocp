package OCP::Cmd::Status;
# ABSTRACT: Show cluster status

use Moo;
use MooX::Cmd;
use MooX::Options;
use JSON::MaybeXS ();
use Scalar::Util ();

use OCP;
use OCP::Choices;
use OCP::Config;
use OCP::Drift;
use OCP::Kubernetes;
use OCP::Secrets;
use OCP::Versions;

with 'OCP::Role::Cmd';

=opt json

    --json

Print one canonical JSON document on STDOUT instead of the text report;
diagnostics go to STDERR.  See L</JSON OUTPUT>.

=cut

option json => (
    is  => 'ro',
    doc => 'Print the status as canonical JSON on STDOUT (diagnostics on STDERR, no timestamps)',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;

    unless (-f $file) {
        die "Config file '$file' not found. Run 'ocp init' first.\n";
    }

    my $config = OCP::Config->new(file => $file);

    return $self->_execute_json($config, $file) if $self->json;

    print "Cluster: ", $config->name, "\n";
    print "Config:  $file\n";
    print "\n";

    # Spec summary
    my $cps = $config->control_planes;
    my @workers = @{$config->workers};

    print "=== Spec ===\n";
    # Show what would actually be installed, not the word 'latest' — an unpinned
    # version means the manifest decides, and that is a concrete number.
    my $dist = $config->distribution;
    my $dist_version = $config->version
        || OCP::Versions->get_component_version($dist)
        || 'latest';
    print "Distribution: $dist $dist_version\n";

    my $cp_count = scalar @$cps;
    my $cp_provider = $cps->[0]{provider} || 'hetzner';
    my $cp_type     = $cps->[0]{server_type};
    print "Control Planes: $cp_count (",
          join(', ', ($cp_type ? $cp_type : ()), $cp_provider), ")\n";

    for my $pool (@workers) {
        my $nodes = ref($pool->{nodes}) eq 'ARRAY' ? scalar(@{$pool->{nodes}}) : ($pool->{nodes} // $pool->{count} // 0);
        my $provider = $pool->{provider} // 'ssh';
        print "Workers ($pool->{name}): $nodes ($provider)\n";
    }
    print "\n";

    # Live status via the Kubernetes API (typed client)
    unless ($config->cluster_exists) {
        print "=== Status ===\n";
        print "No cluster deployed yet. Run 'ocp apply' to deploy.\n";
        return 0;
    }

    print "=== Status ===\n";
    print "Cluster exists (kubeconfig.yaml found)\n\n";

    # Decrypt kubeconfig to temp file
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    my $kc_content = $secrets->read_kubeconfig;

    # What went wrong and why goes to STDERR (k257); the report on STDOUT ends
    # where it got to, the API case on the kubeconfig hint a good run ends on.
    unless ($kc_content) {
        print STDERR "ERROR: Cannot decrypt kubeconfig.yaml\n";
        print STDERR "Make sure .ocp/age.key exists.\n";
        return 1;
    }

    my $k8s = OCP::Kubernetes->new(kubeconfig => $kc_content);

    my $nodes = eval { $k8s->list_nodes };
    if (!$nodes || $@) {
        my $error = $@ || 'Unknown Kubernetes API error';
        chomp $error;
        print STDERR "WARNING: Cannot connect to cluster API\n";
        print STDERR "Error: $error\n";
        print "\nKubeconfig available. Export with: ocp kubeconfig -e\n";
        return 1;
    }
    my @nodes = @$nodes;

    unless (@nodes) {
        print "No nodes found in cluster.\n";
        return 0;
    }

    # Show nodes
    printf "%-20s %-10s %-20s %-16s %s\n",
        'NAME', 'STATUS', 'ROLES', 'VERSION', 'INTERNAL-IP';
    print "-" x 80, "\n";

    for my $node (@nodes) {
        my $name = $k8s->node_name($node);
        my $version = $k8s->node_version($node);
        my $ready = $k8s->node_ready($node) ? 'Ready' : 'NotReady';
        my $roles = $k8s->node_roles($node);
        my $internal_ip = $k8s->node_internal_ip($node);

        printf "%-20s %-10s %-20s %-16s %s\n",
            $name, $ready, $roles, $version, $internal_ip;
    }

    # GPU Status. NVIDIA nodes are read off their capacity as before; AMD
    # nodes (k252) follow in a block of their own, and a cluster without one
    # prints exactly what it printed before and reads nothing more.
    my $gpu_nodes = $k8s->gpu_nodes;
    my @amd_nodes = grep { $self->_amd_gpu_node($_) } @nodes;
    if (@$gpu_nodes || @amd_nodes) {
        print "\n=== GPU Status ===\n";
        for my $gnode (@$gpu_nodes) {
            my $gname = $k8s->node_name($gnode);
            my $gcount = $k8s->node_gpu_count($gnode);
            printf "  %s: %dx NVIDIA GPU\n", $gname, $gcount;
        }
        $self->_print_amd_gpu($config, $k8s, \@amd_nodes) if @amd_nodes;
    }

    # Drift between what ocp.yaml/the version manifest say and what runs.
    #
    # rex_prober adds OCP::Drift's SSH-side detection (host residue no API query
    # can see). It is non-prompting and returns undef when no key is at hand, so
    # this stays as read-only and interaction-free as the rest of the command --
    # an unreachable host or a missing key degrades to "not checked", never a
    # prompt and never a failure of `ocp status`.
    my $drift = eval {
        OCP::Drift->new(
            config     => $config,
            api        => $k8s->api,
            rex_prober => $self->rex_prober($config),
        )->detect;
    } // [];

    if (@$drift) {
        print "\n=== Drift ===\n";
        print "$_\n" for OCP::Drift->format_lines($drift);

        my $fixable = grep { $_->{remedy} } @$drift;
        print "\n$fixable of ", scalar(@$drift),
              " can be reconciled automatically: run 'ocp apply'.\n" if $fixable;
    }

    print "\n";
    print "Kubeconfig: ocp kubeconfig -e\n";

    return 0;
}

# The --json form of the report. Same data as the text form, one object, and
# nothing else on STDOUT; whatever went wrong is told on STDERR as well. The
# AMD GPU lines (k252) are text-only so far: their JSON shape is not decided.
sub _execute_json {
    my ($self, $config, $file) = @_;

    my @workers = @{ $config->workers };
    my $cps     = $config->control_planes;
    my $dist    = $config->distribution;

    my %out = (
        cluster  => $config->name,
        config   => $file,
        deployed => JSON::MaybeXS::false(),
        nodes    => [],
        drift    => [],
        spec     => {
            distribution  => $dist,
            version       => ($config->version || OCP::Versions->get_component_version($dist) || 'latest'),
            control_planes => {
                count       => scalar(@$cps),
                provider    => ($cps->[0]{provider} || 'hetzner'),
                server_type => $cps->[0]{server_type},
            },
            workers => [ map {
                +{
                    name     => $_->{name},
                    provider => ($_->{provider} // 'ssh'),
                    nodes    => (ref($_->{nodes}) eq 'ARRAY' ? scalar(@{$_->{nodes}}) : ($_->{nodes} // $_->{count} // 0)) + 0,
                }
            } @workers ],
        },
    );

    my $exit = $self->_collect_json($config, \%out);

    print JSON::MaybeXS->new(canonical => 1, pretty => 1)->encode(\%out);
    return $exit;
}

sub _collect_json {
    my ($self, $config, $out) = @_;

    return 0 unless $config->cluster_exists;
    $out->{deployed} = JSON::MaybeXS::true();

    my $secrets    = OCP::Secrets->new(project_dir => $config->project_dir);
    my $kc_content = $secrets->read_kubeconfig;
    unless ($kc_content) {
        $out->{error} = 'Cannot decrypt kubeconfig.yaml (is .ocp/age.key present?)';
        print STDERR "ERROR: $out->{error}\n";
        return 1;
    }

    my $k8s   = OCP::Kubernetes->new(kubeconfig => $kc_content);
    my $nodes = eval { $k8s->list_nodes };
    if (!$nodes || $@) {
        my $error = $@ || 'Unknown Kubernetes API error';
        chomp $error;
        $out->{error} = 'Cannot connect to cluster API: ' . $error;
        print STDERR "WARNING: $out->{error}\n";
        return 1;
    }

    $out->{nodes} = [ sort { $a->{name} cmp $b->{name} } map {
        +{
            name        => $k8s->node_name($_),
            ready       => ($k8s->node_ready($_) ? JSON::MaybeXS::true() : JSON::MaybeXS::false()),
            roles       => $k8s->node_roles($_),
            version     => $k8s->node_version($_),
            internal_ip => $k8s->node_internal_ip($_),
            gpu         => ($k8s->node_gpu_count($_) // 0) + 0,
        }
    } @$nodes ];

    my $drift = eval {
        OCP::Drift->new(
            config     => $config,
            api        => $k8s->api,
            rex_prober => $self->rex_prober($config),
        )->detect;
    } // [];

    $out->{drift} = [ sort { $a->{component} cmp $b->{component} || $a->{message} cmp $b->{message} } map {
        +{
            kind        => $_->{kind},
            component   => $_->{component} // $_->{label} // '',
            expected    => $_->{expected},
            actual      => $_->{actual},
            message     => $_->{message} // '',
            manual_step => $_->{manual_step},
            fixable     => ($_->{remedy} ? JSON::MaybeXS::true() : JSON::MaybeXS::false()),
        }
    } @$drift ];

    return 0;
}

#
# AMD GPU nodes in the GPU section (k252; design spec 2026-10-31, section 6)
#

# The resource the AMD device plugin registers and the name of AMD's DRA
# driver. The stack itself comes from Rex::Rancher::K8s; this is only where
# its objects are read back.
my $AMD_GPU_RESOURCE   = 'amd.com/gpu';
my $AMD_GPU_DRA_DRIVER = 'gpu.amd.com';

# A node with an AMD GPU: the host step's marker label, or amd.com/gpu on the
# node at all (a node labelled by hand or before k249). Under DRA allocatable
# is 0 and only the marker is left; whether a count is real is the count
# line's business, not this test's.
sub _amd_gpu_node {
    my ($self, $node) = @_;
    return 1 if ($self->_node_labels($node)->{$OCP::Config::AMD_GPU_PRESENT_LABEL} // '') eq 'true';
    return 1 if $self->_amd_gpu_quantity($node, 'allocatable');
    return 1 if $self->_amd_gpu_quantity($node, 'capacity');
    return 0;
}

sub _print_amd_gpu {
    my ($self, $config, $k8s, $nodes) = @_;

    my $default = $self->_amd_gpu_default_allocation($config);
    for my $node (@$nodes) {
        print '  '.$k8s->node_name($node).": AMD GPU\n";
        print '    '.$AMD_GPU_RESOURCE.': '.$self->_amd_gpu_count($node)."\n";
        print '    gfx target:  '.$self->_amd_gpu_gfx_targets($node)."\n";
        print '    allocation:  '.$self->_amd_gpu_allocation($node, $default)."\n";
    }

    my $api = $k8s->api;
    print '  '.$_."\n" for $self->_amd_gpu_slice_lines($api);

    print "  AMD DaemonSets:\n";
    for my $role (sort keys %OCP::Drift::AMD_GPU_DAEMONSETS) {
        my $ds = $OCP::Drift::AMD_GPU_DAEMONSETS{$role};
        print '    '.$ds->{namespace}.'/'.$ds->{name}
            .($role eq 'dra' ? ' [experimental]' : '')
            .': '.$self->_amd_gpu_daemonset($api, $ds)."\n";
    }
}

# Allocatable is the count: it is what the scheduler hands out. Capacity
# stands beside it only, because the kubelet keeps it after a device plugin
# unregisters (seen live 2026-10-31) -- capacity never says the plugin runs.
sub _amd_gpu_count {
    my ($self, $node) = @_;
    my $allocatable = $self->_amd_gpu_quantity($node, 'allocatable') // 0;
    my $capacity    = $self->_amd_gpu_quantity($node, 'capacity');
    my $count = $allocatable.' allocatable';
    return $count unless defined $capacity;
    return $count.' (capacity '.$capacity.')' if $capacity eq $allocatable;
    return $count.' (capacity '.$capacity.': stale after a device plugin unregisters,'
        .' or unhealthy devices; only allocatable schedules)';
}

sub _amd_gpu_quantity {
    my ($self, $node, $field) = @_;
    my $resources = $self->_dig($node, 'status', $field);
    return ref $resources eq 'HASH' ? $resources->{$AMD_GPU_RESOURCE} : undef;
}

# Both forms the host step writes: one target as the label's value, several
# as one label per target (key plus ".<gfx>") valued with the count.
sub _amd_gpu_gfx_targets {
    my ($self, $node) = @_;
    my $labels = $self->_node_labels($node);
    my $key    = $OCP::Config::AMD_GPU_GFX_TARGET_LABEL;
    my @targets = (
        (defined $labels->{$key} && length $labels->{$key} ? $labels->{$key} : ()),
        (map { $labels->{$_}.'x '.substr($_, length($key) + 1) }
            sort grep { index($_, $key.'.') == 0 } keys %$labels),
    );
    return @targets ? join(', ', @targets) : 'not labelled';
}

# The node's override label wins, else gpu.amd.allocation; the line names
# which. A label value OCP does not know is shown as it is and said to be
# unknown -- what the stack's affinity terms make of it is theirs to decide.
sub _amd_gpu_allocation {
    my ($self, $node, $default) = @_;
    my $label  = $OCP::Config::AMD_GPU_ALLOCATION_LABEL;
    my $value  = $self->_node_labels($node)->{$label};
    my $source = defined $value ? 'node label '.$label : 'cluster default gpu.amd.allocation';
    $value //= $default;
    return 'unknown (gpu.amd.allocation is invalid, see STDERR)' unless defined $value;

    my @known = @OCP::Config::GPU_AMD_ALLOCATIONS;
    return (length $value ? $value : "''")
        .($value eq 'dra' ? ' [experimental]' : '')
        .' ('.$source
        .(grep({ $_ eq $value } @known) ? '' : '; not one of '.OCP::Choices::or_list(@known))
        .')';
}

# gpu.amd.allocation, or undef when ocp.yaml holds a value OCP::Config
# refuses. The reason goes to STDERR once and the report goes on: a read-only
# command that died on a typo would hide everything else it can tell.
sub _amd_gpu_default_allocation {
    my ($self, $config) = @_;
    my $allocation = eval { $config->gpu_amd_allocation };
    return $allocation if defined $allocation;
    (my $err = "$@") =~ s/ at .+? line \d+\.?\n*\z//s;
    print STDERR 'WARNING: '.$err.'; AMD nodes without their own '
        .$OCP::Config::AMD_GPU_ALLOCATION_LABEL." label show their allocation as unknown\n";
    return undef;
}

# The header line, then one line per node. A 404 on the list means the
# cluster does not serve resource.k8s.io/v1: a state, not a fault.
sub _amd_gpu_slice_lines {
    my ($self, $api) = @_;
    my $head = 'AMD DRA ResourceSlices (driver '.$AMD_GPU_DRA_DRIVER.') [experimental]:';

    my $list = eval { $api->list('ResourceSlice') };
    if (my $err = $@) {
        return $head." not served (this cluster's API has no resource.k8s.io/v1)" if $err =~ /\b404\b/;
        $self->_amd_gpu_read_failed('ResourceSlices', $err);
        return $head.' unknown (read failed, see STDERR)';
    }

    my $devices = $self->_amd_gpu_slice_devices($list->items);
    return $head.' none published' unless %$devices;
    return $head, map {
        '  '.$_.': '.$devices->{$_}.($devices->{$_} == 1 ? ' device' : ' devices')
    } sort keys %$devices;
}

# Devices per node over the slices of AMD's driver. A pool republishes under
# a higher generation and only the newest one counts (the scheduler ignores
# the rest), so a slice of the old generation still listed is not added.
sub _amd_gpu_slice_devices {
    my ($self, $slices) = @_;
    my @ours = grep { ($self->_dig($_, qw(spec driver)) // '') eq $AMD_GPU_DRA_DRIVER } @$slices;

    my %newest;
    for my $slice (@ours) {
        my $pool = $self->_dig($slice, qw(spec pool name)) // '';
        my $gen  = $self->_dig($slice, qw(spec pool generation)) // 0;
        $newest{$pool} = $gen if !defined $newest{$pool} || $gen > $newest{$pool};
    }

    my %devices;
    for my $slice (@ours) {
        my $pool = $self->_dig($slice, qw(spec pool name)) // '';
        next if ($self->_dig($slice, qw(spec pool generation)) // 0) < $newest{$pool};
        my $node = $self->_dig($slice, qw(spec nodeName)) // $pool;
        my $list = $self->_dig($slice, qw(spec devices));
        $devices{$node} += ref $list eq 'ARRAY' ? scalar @$list : 0;
    }
    return \%devices;
}

# ready/desired of one DaemonSet of %OCP::Drift::AMD_GPU_DAEMONSETS. The
# stack exists only where an AMD card and gpu.enabled are, and gpu.amd picks
# which of the four run: one that is not there is "not deployed", not a fault.
sub _amd_gpu_daemonset {
    my ($self, $api, $ds) = @_;
    my $object = eval {
        $api->get('DaemonSet', name => $ds->{name}, namespace => $ds->{namespace});
    };
    if (my $err = $@) {
        return 'not deployed' if $err =~ /\b404\b/;
        $self->_amd_gpu_read_failed('DaemonSet '.$ds->{namespace}.'/'.$ds->{name}, $err);
        return 'unknown (read failed, see STDERR)';
    }
    return ($self->_dig($object, qw(status numberReady)) // 0).'/'
        .($self->_dig($object, qw(status desiredNumberScheduled)) // 0).' ready';
}

sub _amd_gpu_read_failed {
    my ($self, $what, $err) = @_;
    my $reason = "$err";
    chomp $reason;
    print STDERR 'WARNING: Cannot read '.$what.': '.$reason."\n";
}

sub _node_labels {
    my ($self, $node) = @_;
    my $labels = $self->_dig($node, qw(metadata labels));
    return ref $labels eq 'HASH' ? $labels : {};
}

# A field of a node, DaemonSet or ResourceSlice, whether the api handed over
# IO::K8s objects or plain hashes -- the way OCP::Kubernetes reads nodes.
sub _dig {
    my ($self, $value, @path) = @_;
    for my $part (@path) {
        return undef unless defined $value;
        if (ref $value eq 'HASH') {
            $value = $value->{$part};
        } elsif (Scalar::Util::blessed($value) && $value->can($part)) {
            $value = $value->$part;
        } else {
            return undef;
        }
    }
    return $value;
}

1;

__END__

=synopsis

    ocp status

=description

C<ocp status> is the read-only inspection command for a project.  It prints
the spec summary (cluster name, distribution + pinned version, control planes,
worker pools) from C<ocp.yaml> and, when the cluster has been deployed, the
live state from the Kubernetes API: node name, Ready/NotReady, role labels,
kubelet version, InternalIP, GPU capacity and any L<OCP::Drift> entries that
the spec or version manifest disagree with.

If C<ocp.yaml> is missing the command dies with a hint to run C<ocp init>.
If the cluster has never been deployed the spec section is printed and the
status section says so.  The kubeconfig is read through L<OCP::Secrets>, so
the C<.ocp/age.key> must be present for the live-status section to render.
When the kubeconfig cannot be decrypted or the API cannot be reached, the
report on STDOUT stops there, the error and its diagnosis go to STDERR, and
the exit code is 1.

The command never modifies cluster state.  Drift entries that carry a
C<remedy> are listed together with the count that C<ocp apply> would resolve.

=head1 GPU SECTION

NVIDIA nodes are listed with their C<nvidia.com/gpu> capacity.  Below them
comes every AMD GPU node, i.e. a node with the marker label
C<ocp.internal/amd-gpu.present=true> or an C<amd.com/gpu> resource:

=over 4

=item * C<amd.com/gpu> allocatable.  Capacity is shown beside it only: the
kubelet keeps capacity after a device plugin unregisters, so capacity never
says that the plugin runs.

=item * its gfx target, from C<ocp.internal/amd-gpu.gfx-target> or, on a node
with several targets, from one C<ocp.internal/amd-gpu.gfx-target.E<lt>gfxE<gt>>
label per target with its count;

=item * its effective allocation and where it comes from: the node label
C<ocp.internal/amd-gpu.allocation> if set, else C<gpu.amd.allocation>.

=back

Then the devices per node in the ResourceSlices of driver C<gpu.amd.com>
(C<resource.k8s.io/v1>), and ready/desired of the AMD DaemonSets named in
C<%OCP::Drift::AMD_GPU_DAEMONSETS>.  DRA is marked C<[experimental]>.  A
DaemonSet that does not exist is "not deployed", a cluster that does not
serve C<resource.k8s.io/v1> says so; a read that fails shows "unknown" in the
report and the API error on STDERR.  A cluster without an AMD node prints the
section as before and reads none of these objects.  The AMD lines are in the
text form only; C<--json> does not carry them yet.

=head1 JSON OUTPUT

C<ocp status --json> prints exactly one JSON object (canonical: sorted keys,
pretty-printed, no timestamps or ages) on STDOUT; diagnostics go to STDERR.
Two runs against an unchanged cluster print identical bytes, so a script can
compare them.  The exit code is that of the text form: 1 when the kubeconfig
cannot be decrypted or the API cannot be reached (the object then carries an
C<error> string and whatever could be collected), else 0.

    {
       "cluster" : "mycluster",
       "config" : "ocp.yaml",
       "deployed" : true,
       "drift" : [
          {
             "actual" : "v1.32.0+rke2r1",
             "component" : "rke2",
             "expected" : "v1.32.1+rke2r1",
             "fixable" : false,
             "kind" : "version",
             "manual_step" : null,
             "message" : "rke2: ..."
          }
       ],
       "nodes" : [
          {
             "gpu" : 0,
             "internal_ip" : "10.0.0.10",
             "name" : "police1",
             "ready" : true,
             "roles" : "control-plane",
             "version" : "v1.32.1+rke2r1"
          }
       ],
       "spec" : {
          "control_planes" : { "count" : 1, "provider" : "hetzner", "server_type" : "cx32" },
          "distribution" : "rke2",
          "version" : "v1.32.1+rke2r1",
          "workers" : [ { "name" : "pool-a", "nodes" : 2, "provider" : "ssh" } ]
       }
    }

C<nodes> are sorted by name, C<drift> by component and message; a drift
entry's C<fixable> says whether C<ocp apply> carries a remedy for it.  The
drift list includes the C<< kind => 'error' >> entry that
L<OCP::Drift> reports when the API call behind a check failed.

=method execute

    $cmd->execute($args, $chain)

Prints the spec summary, then — when the cluster is deployed — the live
node table, GPU nodes and drift entries.  Returns 0 on success, 1 when the
kubeconfig could not be decrypted or the API could not be reached.

=seealso

L<OCP::Cmd::Apply>, L<OCP::Cmd::Destroy>, L<OCP::Config>,
L<OCP::Drift>, L<OCP::Kubernetes>, L<OCP::Secrets>, L<OCP::Versions>

=cut

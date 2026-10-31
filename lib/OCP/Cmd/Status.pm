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

    # GPU Status. NVIDIA nodes are counted by allocatable (k270), capacity
    # beside it where the two differ; AMD nodes (k252) follow in a block of
    # their own, and a cluster without one prints exactly what it printed
    # before and reads nothing more.
    my $gpu_nodes = $k8s->gpu_nodes;
    my @amd_nodes = grep { $self->_amd_gpu_node($_) } @nodes;
    if (@$gpu_nodes || @amd_nodes) {
        print "\n=== GPU Status ===\n";
        for my $gnode (@$gpu_nodes) {
            print '  '.$k8s->node_name($gnode).': '.$self->_nvidia_gpu_count($k8s, $gnode)."\n";
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
    my ($drift, $drift_error) = $self->_detect_drift($config, $k8s);

    if (@$drift) {
        print "\n=== Drift ===\n";
        print "$_\n" for $self->_drift_lines($drift);

        # A check that could not be made found no drift: not counted (k262).
        my @found   = grep { !$self->_drift_unknown($_) } @$drift;
        my $fixable = grep { $_->{remedy} } @found;
        print "\n$fixable of ", scalar(@found),
              " can be reconciled automatically: run 'ocp apply'.\n" if $fixable;
    }

    print "\n";
    print "Kubeconfig: ocp kubeconfig -e\n";

    return defined $drift_error ? 1 : 0;
}

# The --json form of the report. Same data as the text form, one object, and
# nothing else on STDOUT; whatever went wrong is told on STDERR as well. The
# AMD GPU block (k252) is the amd_gpu object (k258), there only when the
# cluster has an AMD node.
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

    # gpu is nvidia.com/gpu allocatable since k270 (it was capacity before);
    # gpu_capacity stands beside it, null on a node without one.
    $out->{nodes} = [ sort { $a->{name} cmp $b->{name} } map {
        my $gpu_capacity = $k8s->node_gpu_capacity($_);
        +{
            name         => $k8s->node_name($_),
            ready        => ($k8s->node_ready($_) ? JSON::MaybeXS::true() : JSON::MaybeXS::false()),
            roles        => $k8s->node_roles($_),
            version      => $k8s->node_version($_),
            internal_ip  => $k8s->node_internal_ip($_),
            gpu          => ($k8s->node_gpu_count($_) // 0) + 0,
            gpu_capacity => (defined $gpu_capacity ? $gpu_capacity + 0 : undef),
        }
    } @$nodes ];

    my @amd_nodes = grep { $self->_amd_gpu_node($_) } @$nodes;
    $out->{amd_gpu} = $self->_amd_gpu_json($config, $k8s, \@amd_nodes) if @amd_nodes;

    my ($drift, $drift_error) = $self->_detect_drift($config, $k8s);

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

    # The exit and the error field of a cluster that cannot be read: the
    # object is the report as far as it got, error says what it is missing.
    if (defined $drift_error) {
        $out->{error} = 'Cannot detect drift: '.$drift_error;
        return 1;
    }

    return 0;
}

# OCP::Drift's entries, the same for both forms, and the cause when detection
# itself died (undef when it did not). A die used to read as an empty list:
# no drift, exit 0, nothing on STDERR (k262). Now the cause goes to STDERR
# and the list holds one entry of kind error -- the shape OCP::Drift gives a
# probe it could not read (k256, k268) -- so both forms say drift unknown,
# never none.
sub _detect_drift {
    my ($self, $config, $k8s) = @_;

    my $drift = eval {
        OCP::Drift->new(
            config     => $config,
            api        => $k8s->api,
            rex_prober => $self->rex_prober($config),
        )->detect;
    };
    return ($drift, undef) if ref $drift eq 'ARRAY';

    my $reason = $@ ? "$@" : 'OCP::Drift->detect returned no list';
    chomp $reason;
    print STDERR 'WARNING: Cannot detect drift: '.$reason."\n";
    return ([ {
        kind      => 'error',
        component => 'drift',
        label     => 'Drift detection',
        expected  => undef,
        actual    => undef,
        message   => 'Drift detection: could not complete, drift unknown: '.$reason,
        remedy    => undef,
    } ], $reason);
}

# A drift entry that is a check OCP::Drift could not make, not a finding.
sub _drift_unknown {
    my ($self, $entry) = @_;
    return ($entry->{kind} // '') eq 'error';
}

# The drift section's lines. A check that could not be made reads as `ocp
# apply` words it (k267): "could not be checked", then the message with its
# cause -- never as a plain [drift] finding.
sub _drift_lines {
    my ($self, $drift) = @_;
    return map {
        $self->_drift_unknown($_)
            ? '  [drift] could not be checked: '.$_->{message}
            : OCP::Drift->format_lines([ $_ ])
    } @$drift;
}

#
# AMD GPU nodes in the GPU section (k252; design spec 2026-10-31, section 6)
#

# The resource the AMD device plugin registers and the name of AMD's DRA
# driver. The stack itself comes from Rex::Rancher::K8s; this is only where
# its objects are read back. OCP::Cmd::Apply::AMDGPU (k251) holds a second
# copy of both; they are not shared through OCP::Config yet.
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

# The same block as the amd_gpu object of --json (k258), read in the same
# order, so STDERR tells a failed read in the same order too. Counts are
# numbers; what could not be read is null, never a guess.
sub _amd_gpu_json {
    my ($self, $config, $k8s, $nodes) = @_;

    my $default = $self->_amd_gpu_default_allocation($config);
    my @nodes = sort { $a->{name} cmp $b->{name} } map {
        my ($allocation, $source) = $self->_amd_gpu_effective_allocation($_, $default);
        my $capacity = $self->_amd_gpu_quantity($_, 'capacity');
        my %targets  = map { $_->[0] => 1 } $self->_amd_gpu_gfx_target_labels($_);
        +{
            name              => $k8s->node_name($_),
            allocatable       => ($self->_amd_gpu_quantity($_, 'allocatable') // 0) + 0,
            capacity          => (defined $capacity ? $capacity + 0 : undef),
            gfx_targets       => [ sort keys %targets ],
            allocation        => $allocation,
            allocation_source => $source,
        }
    } @$nodes;

    my $api    = $k8s->api;
    my $slices = $self->_amd_gpu_slices($api);
    my %daemonsets;
    for my $role (sort keys %OCP::Drift::AMD_GPU_DAEMONSETS) {
        my $ds = $OCP::Drift::AMD_GPU_DAEMONSETS{$role};
        $daemonsets{$role} = {
            namespace => $ds->{namespace},
            name      => $ds->{name},
            %{ $self->_amd_gpu_daemonset_status($api, $ds) },
        };
    }

    return {
        nodes           => \@nodes,
        resource_slices => $slices,
        daemonsets      => \%daemonsets,
    };
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
    return $count.$self->_stale_gpu_capacity($capacity);
}

# The NVIDIA line counts allocatable the same way (k270). Where capacity
# agrees it is the line of before, so a healthy node prints what it always
# did; where it does not, the count says allocatable and capacity stands
# beside it with the AMD line's reason.
sub _nvidia_gpu_count {
    my ($self, $k8s, $node) = @_;
    my $allocatable = $k8s->node_gpu_count($node);
    my $capacity    = $k8s->node_gpu_capacity($node);
    my $count = sprintf '%dx NVIDIA GPU', $allocatable;
    return $count if !defined $capacity || $capacity eq $allocatable;
    return $count.' allocatable'.$self->_stale_gpu_capacity($capacity);
}

sub _stale_gpu_capacity {
    my ($self, $capacity) = @_;
    return ' (capacity '.$capacity.': stale after a device plugin unregisters,'
        .' or unhealthy devices; only allocatable schedules)';
}

sub _amd_gpu_quantity {
    my ($self, $node, $field) = @_;
    my $resources = $self->_dig($node, 'status', $field);
    return ref $resources eq 'HASH' ? $resources->{$AMD_GPU_RESOURCE} : undef;
}

# Both forms the host step writes: one target as the label's value, several
# as one label per target (key plus ".<gfx>") valued with the count. As
# [ target, count ] pairs, count undef for the one-label form.
sub _amd_gpu_gfx_target_labels {
    my ($self, $node) = @_;
    my $labels = $self->_node_labels($node);
    my $key    = $OCP::Config::AMD_GPU_GFX_TARGET_LABEL;
    return (
        (defined $labels->{$key} && length $labels->{$key} ? [ $labels->{$key}, undef ] : ()),
        (map { [ substr($_, length($key) + 1), $labels->{$_} ] }
            sort grep { index($_, $key.'.') == 0 } keys %$labels),
    );
}

sub _amd_gpu_gfx_targets {
    my ($self, $node) = @_;
    my @targets = map { defined $_->[1] ? $_->[1].'x '.$_->[0] : $_->[0] }
        $self->_amd_gpu_gfx_target_labels($node);
    return @targets ? join(', ', @targets) : 'not labelled';
}

# The node's override label wins, else gpu.amd.allocation: the value, undef
# when ocp.yaml holds one OCP::Config refuses, and where it came from
# (node-label or config).
sub _amd_gpu_effective_allocation {
    my ($self, $node, $default) = @_;
    my $value = $self->_node_labels($node)->{$OCP::Config::AMD_GPU_ALLOCATION_LABEL};
    return defined $value ? ($value, 'node-label') : ($default, 'config');
}

# The line names where the allocation comes from. A label value OCP does not
# know is shown as it is and said to be unknown -- what the stack's affinity
# terms make of it is theirs to decide.
sub _amd_gpu_allocation {
    my ($self, $node, $default) = @_;
    my ($value, $from) = $self->_amd_gpu_effective_allocation($node, $default);
    my $source = $from eq 'node-label'
        ? 'node label '.$OCP::Config::AMD_GPU_ALLOCATION_LABEL
        : 'cluster default gpu.amd.allocation';
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

# The header line, then one line per node.
sub _amd_gpu_slice_lines {
    my ($self, $api) = @_;
    my $head = 'AMD DRA ResourceSlices (driver '.$AMD_GPU_DRA_DRIVER.') [experimental]:';

    my $slices = $self->_amd_gpu_slices($api);
    return $head." not served (this cluster's API has no resource.k8s.io/v1)"
        if $slices->{state} eq 'not-served';
    return $head.' unknown (read failed, see STDERR)' if $slices->{state} eq 'unknown';

    my $devices = $slices->{devices};
    return $head.' none published' unless %$devices;
    return $head, map {
        '  '.$_.': '.$devices->{$_}.($devices->{$_} == 1 ? ' device' : ' devices')
    } sort keys %$devices;
}

# The devices per node and the state of the read: served, not-served (a 404
# on the list: the cluster has no resource.k8s.io/v1, a state and not a
# fault, so there are none) or unknown (the read failed, said on STDERR, and
# devices is undef -- not known, not none).
sub _amd_gpu_slices {
    my ($self, $api) = @_;
    my $list = eval { $api->list('ResourceSlice') };
    if (my $err = $@) {
        return { state => 'not-served', devices => {} } if $err =~ /\b404\b/;
        $self->_amd_gpu_read_failed('ResourceSlices', $err);
        return { state => 'unknown', devices => undef };
    }
    return { state => 'served', devices => $self->_amd_gpu_slice_devices($list->items) };
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

sub _amd_gpu_daemonset {
    my ($self, $api, $ds) = @_;
    my $status = $self->_amd_gpu_daemonset_status($api, $ds);
    return 'not deployed' if $status->{state} eq 'not-deployed';
    return 'unknown (read failed, see STDERR)' if $status->{state} eq 'unknown';
    return $status->{ready}.'/'.$status->{desired}.' ready';
}

# ready/desired of one DaemonSet of %OCP::Drift::AMD_GPU_DAEMONSETS and its
# state: ready (every desired pod is, 0 of 0 included), partial,
# not-deployed or unknown (the read failed, said on STDERR). The stack exists
# only where an AMD card and gpu.enabled are, and gpu.amd picks which of the
# four run: one that is not there is not deployed, not a fault. ready and
# desired are undef unless the DaemonSet was read.
sub _amd_gpu_daemonset_status {
    my ($self, $api, $ds) = @_;
    my $object = eval {
        $api->get('DaemonSet', name => $ds->{name}, namespace => $ds->{namespace});
    };
    if (my $err = $@) {
        return { state => 'not-deployed', ready => undef, desired => undef } if $err =~ /\b404\b/;
        $self->_amd_gpu_read_failed('DaemonSet '.$ds->{namespace}.'/'.$ds->{name}, $err);
        return { state => 'unknown', ready => undef, desired => undef };
    }
    my $ready   = ($self->_dig($object, qw(status numberReady)) // 0) + 0;
    my $desired = ($self->_dig($object, qw(status desiredNumberScheduled)) // 0) + 0;
    return { state => ($ready >= $desired ? 'ready' : 'partial'), ready => $ready, desired => $desired };
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
kubelet version, InternalIP, the GPUs each node can hand out and any
L<OCP::Drift> entries that the spec or version manifest disagree with.

If C<ocp.yaml> is missing the command dies with a hint to run C<ocp init>.
If the cluster has never been deployed the spec section is printed and the
status section says so.  The kubeconfig is read through L<OCP::Secrets>, so
the C<.ocp/age.key> must be present for the live-status section to render.
When the kubeconfig cannot be decrypted or the API cannot be reached, the
report on STDOUT stops there, the error and its diagnosis go to STDERR, and
the exit code is 1.

The command never modifies cluster state.  Drift entries that carry a
C<remedy> are listed together with the count that C<ocp apply> would resolve.
A check L<OCP::Drift> could not make (an entry of kind C<error>: an RBAC
denial, an apiserver 5xx) is listed as C<could not be checked> with its
cause, and is not counted as drift:

    [drift] could not be checked: Worker host probes: could not list OCPNode in ocp-system, drift unknown: 403 ...

When drift detection itself dies, the cause goes to STDERR
(C<WARNING: Cannot detect drift: ...>), the drift section says that drift
could not be determined, and the exit code is 1:

    [drift] could not be checked: Drift detection: could not complete, drift unknown: ...

=head1 GPU SECTION

NVIDIA nodes, i.e. nodes with an C<nvidia.com/gpu> allocatable or capacity,
are listed with their C<nvidia.com/gpu> allocatable, the count the scheduler
hands out:

    police2: 1x NVIDIA GPU
    police3: 0x NVIDIA GPU allocatable (capacity 1: stale after a device plugin unregisters, or unhealthy devices; only allocatable schedules)

Capacity is named beside it only where the two differ: the kubelet keeps
capacity after the device plugin unregisters, so a node whose plugin is gone
shows 0 allocatable and its capacity, not a usable GPU.  Below them comes
every AMD GPU node, i.e. a node with the marker label
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
section as before and reads none of these objects.  C<--json> carries the
same as its C<amd_gpu> object, see L</JSON OUTPUT>.

=head1 JSON OUTPUT

C<ocp status --json> prints exactly one JSON object (canonical: sorted keys,
pretty-printed, no timestamps or ages) on STDOUT; diagnostics go to STDERR.
Two runs against an unchanged cluster print identical bytes, so a script can
compare them.  The exit code is that of the text form: 1 when the kubeconfig
cannot be decrypted, the API cannot be reached or drift detection dies (the
object then carries an C<error> string and whatever could be collected),
else 0.

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
             "gpu_capacity" : null,
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
L<OCP::Drift> reports when the API call behind a check failed: drift unknown
for what it names, never C<fixable>.  When drift detection itself dies, the
list is not empty but holds one such entry with C<component> C<drift>, and
C<error> says C<Cannot detect drift: ...>.  An empty list means no drift was
found.  A node's
C<gpu> is its C<nvidia.com/gpu> allocatable (0 when it has none), the same
as C<gpu> in C<ocp node ls --json>, and C<gpu_capacity> its C<nvidia.com/gpu>
capacity (C<null> when it has none).  Earlier builds reported the capacity as
C<gpu>; the two differ only on a node whose device plugin is gone or whose
devices are unhealthy, and there C<gpu> now says what can be scheduled.

A cluster with an AMD GPU node (see L</GPU SECTION>) adds an C<amd_gpu>
object; any other cluster prints the object above without it, byte for byte:

    "amd_gpu" : {
       "daemonsets" : {
          "device_plugin" : {
             "desired" : 1,
             "name" : "amdgpu-device-plugin-daemonset",
             "namespace" : "kube-system",
             "ready" : 1,
             "state" : "ready"
          },
          "dra" : { "desired" : null, "name" : "...", "namespace" : "kube-system", "ready" : null, "state" : "not-deployed" },
          "labeller" : { ... },
          "metrics" : { ... }
       },
       "nodes" : [
          {
             "allocatable" : 1,
             "allocation" : "device-plugin",
             "allocation_source" : "config",
             "capacity" : 1,
             "gfx_targets" : [ "gfx1151" ],
             "name" : "synapse"
          }
       ],
       "resource_slices" : {
          "devices" : { "synapse" : 1 },
          "state" : "served"
       }
    }

=over 4

=item * C<nodes>, sorted by name: C<amd.com/gpu> C<allocatable> (0 when the
node has none) and C<capacity> (C<null> when the node has none), the sorted
C<gfx_targets> from the gfx target labels (C<[]> when unlabelled), the
effective C<allocation> and its C<allocation_source>: C<node-label> or
C<config>.  C<allocation> is C<null> when C<gpu.amd.allocation> is invalid
and the node has no label of its own (the reason is on STDERR); a label
value OCP does not know is carried as it is.

=item * C<resource_slices>: the C<devices> per node in the newest generation
of each pool of driver C<gpu.amd.com>, and the C<state> of the read:
C<served>, C<not-served> (no C<resource.k8s.io/v1>; C<devices> is C<{}>) or
C<unknown> (the read failed; C<devices> is C<null>).

=item * C<daemonsets>, keyed by role as in C<%OCP::Drift::AMD_GPU_DAEMONSETS>:
C<namespace>, C<name>, C<ready>, C<desired> and C<state>: C<ready> (every
desired pod is ready, 0 of 0 too), C<partial>, C<not-deployed> or C<unknown>
(the read failed).  C<ready> and C<desired> are C<null> unless the DaemonSet
was read.

=back

A read that fails here is told on STDERR and leaves the exit code alone.

=method execute

    $cmd->execute($args, $chain)

Prints the spec summary, then — when the cluster is deployed — the live
node table, GPU nodes and drift entries.  Returns 0 on success, 1 when the
kubeconfig could not be decrypted, the API could not be reached or drift
detection died.

=seealso

L<OCP::Cmd::Apply>, L<OCP::Cmd::Destroy>, L<OCP::Config>,
L<OCP::Drift>, L<OCP::Kubernetes>, L<OCP::Secrets>, L<OCP::Versions>

=cut

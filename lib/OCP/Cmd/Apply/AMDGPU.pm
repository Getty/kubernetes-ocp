package OCP::Cmd::Apply::AMDGPU;
# ABSTRACT: The AMD GPU cluster stack on AMD nodes (device plugin, DRA driver, labeller, metrics)

use strict;
use warnings;

use Digest::MD5 ();
use JSON::MaybeXS ();

use OCP::Choices ();
use OCP::Config ();
use OCP::Drift ();
use OCP::Versions;
use OCP::Cmd::Apply::DeployedHash ();
use OCP::Cmd::Apply::K8s ();

=head1 SYNOPSIS

    print "  [..] Checking AMD GPU stack...\n";
    my $r = OCP::Cmd::Apply::AMDGPU::step($apply, $config);
    push @failed, @{ $r->{failed} };

    # once the worker step brought nodes up
    push @failed, OCP::Cmd::Apply::AMDGPU::after_join($apply, $config, \@results);

=head1 DESCRIPTION

What a cluster runs on its AMD GPU nodes, once the host step installed the
driver (k249): ROCm's device plugin (C<amd.com/gpu>), ROCm's DRA driver
(ResourceSlices of driver C<gpu.amd.com>, experimental), AMD's node labeller
and, with C<gpu.amd.metrics>, ROCm's device-metrics-exporter (C</metrics> on
port 5000; upstream does not support Ryzen APUs, where many of its fields
read 0). The objects themselves come from L<Rex::Rancher::K8s>; this module
decides which of them the cluster needs, where they run, and whether they
came up.

=over

=item Trigger

C<gpu.enabled> and at least one Node with
C<$OCP::Config::AMD_GPU_PRESENT_LABEL> set to C<true> -- the marker the host
step sets at registration for a GPU it set up. NFD's C<pci-*_1002> labels are
not asked: they cannot tell an iGPU the integrated gate skipped from one OCP
set up.

=item Placement

Every component selects on the marker; the labeller and the metrics exporter
on nothing else. The device plugin and the DRA driver also select on the
node's allocation: the C<$OCP::Config::AMD_GPU_ALLOCATION_LABEL>
label where a node has one, else C<gpu.amd.allocation>. The default
allocation's component takes C<NotIn> the other two values, the other one
C<In> its own value only, so a node gets exactly one of them (L</affinity>).

=item Selection

A component no AMD node selects is not deployed, and one OCP recorded or the
cluster has is removed: the last AMD node gone, C<gpu.enabled: false>, the
labeller or the metrics exporter switched off, the allocation switched. Unlike the NVIDIA GPU
Operator, which nothing removes: these are a few DaemonSets in
C<kube-system> with nothing of the user's in them, and a device plugin left
on a node whose allocation switched to DRA would hand out the same GPU twice.

=item Reconcile

Each component's options (version pin, affinity, resource naming) are hashed
into C<.ocp/deployed.yaml>; an equal hash with the DaemonSet still in the
cluster is C<unchanged>, anything else re-deploys, then waits for the
component to be ready by OCP's own check (300 s, C<ready_timeout>): the DaemonSet
rolled out, then C<status.allocatable> C<amd.com/gpu> on every node the plugin
selects, or a ResourceSlice of driver C<gpu.amd.com> for every node the DRA
driver selects. The labeller and the metrics exporter are ready with their
DaemonSet (the exporter has no readinessProbe upstream, so its pods turn
Ready a few seconds before port 5000 answers; apply does not probe it).

=back

A Rex::Rancher without the AMD functions (0.004 and 0.005 have none) is one
C<[WARN]> on STDERR and nothing deployed -- never a failed apply.

=cut

# What each component is, in the order removals run: the DRA driver first,
# so a node never has the plugin and the driver at once while one goes.
my @COMPONENTS = qw( dra device_plugin labeller metrics );

my %COMPONENT = (
    device_plugin => {
        label      => 'AMD GPU device plugin',
        key        => 'amd-gpu-device-plugin',
        allocation => 'device-plugin',
        deploy     => 'deploy_amd_device_plugin',
        remove     => 'remove_amd_device_plugin',
        version    => 'amd_device_plugin',
    },
    dra => {
        label      => 'AMD GPU DRA driver',
        key        => 'amd-gpu-dra-driver',
        allocation => 'dra',
        deploy     => 'deploy_amd_dra_driver',
        remove     => 'remove_amd_dra_driver',
        version    => 'amd_dra_driver',
    },
    labeller => {
        label      => 'AMD GPU node labeller',
        key        => 'amd-gpu-node-labeller',
        deploy     => 'deploy_amd_node_labeller',
        remove     => 'remove_amd_node_labeller',
        # A second image of the device plugin's release, under its own tag.
        version    => 'amd_device_plugin',
    },
    metrics => {
        # The label OCP::Drift's probe uses for the same DaemonSet.
        label      => 'AMD device metrics exporter',
        key        => 'amd-gpu-metrics-exporter',
        deploy     => 'deploy_amd_metrics_exporter',
        remove     => 'remove_amd_metrics_exporter',
        version    => 'amd_metrics_exporter',
    },
);

my $LIB = 'Rex::Rancher::K8s';

# The names a ready component shows in the cluster: the device plugin's
# resource (mixed naming adds partitioned ones under the same prefix) and the
# DRA driver's name on its ResourceSlices. A local copy, as OCP::Cmd::Status
# has one: k258 moves both onto shared variables in OCP::Config.
my $AMD_GPU_RESOURCE   = 'amd.com/gpu';
my $AMD_GPU_PREFIX     = 'amd.com/';
my $AMD_GPU_DRA_DRIVER = 'gpu.amd.com';

# Readiness budget per component, in seconds: the DaemonSet's pods pull their
# image cold through the registry cache, then the plugin has to report.
sub ready_timeout  { 300 }
sub ready_interval { 10 }

=head1 FUNCTIONS

=head2 affinity

    my $affinity = OCP::Cmd::Apply::AMDGPU::affinity($component, $default_allocation);

The pod affinity for C<device_plugin>, C<dra>, C<labeller> or C<metrics>,
given C<gpu.amd.allocation>. Marker C<In [true]>, and for the two allocation
components the allocation term.

=cut

sub affinity {
    my ($component, $default) = @_;

    my @terms = ({
        key => $OCP::Config::AMD_GPU_PRESENT_LABEL, operator => 'In', values => ['true'],
    });
    if (my $own = $COMPONENT{$component}{allocation}) {
        push @terms, $own eq $default
            ? { key => $OCP::Config::AMD_GPU_ALLOCATION_LABEL, operator => 'NotIn',
                values => [ grep { $_ ne $own } @OCP::Config::GPU_AMD_ALLOCATIONS ] }
            : { key => $OCP::Config::AMD_GPU_ALLOCATION_LABEL, operator => 'In',
                values => [ $own ] };
    }

    return { nodeAffinity => { requiredDuringSchedulingIgnoredDuringExecution => {
        nodeSelectorTerms => [ { matchExpressions => \@terms } ],
    } } };
}

# Whether $affinity selects a node with $labels -- the scheduler's reading of
# In and NotIn (NotIn holds for a node without the label), the only two
# operators affinity() writes. The same terms that go to the cluster decide
# here which nodes a component is for, so the two cannot disagree.
sub selects {
    my ($affinity, $labels) = @_;
    my $terms = $affinity->{nodeAffinity}{requiredDuringSchedulingIgnoredDuringExecution}{nodeSelectorTerms};
    TERM: for my $term (@$terms) {
        for my $e (@{ $term->{matchExpressions} }) {
            my $v  = $labels->{ $e->{key} };
            my $in = defined $v && grep { $_ eq $v } @{ $e->{values} };
            next TERM if $e->{operator} eq 'In' ? !$in : $in;
        }
        return 1;
    }
    return 0;
}

=head2 setup

    my @results = OCP::Cmd::Apply::AMDGPU::setup($apply, $config);

Brings the stack to what C<$config> and the marker nodes ask for. Returns one
result per component it acted on or confirmed: C<< { label, outcome } >> with
an outcome for L<OCP::Cmd::Apply::DeployedHash/report_component>
(C<removed> included), or C<< { label, error, hint } >> for one that failed.
A cluster with nothing to do is one C<skipped> result for C<AMD GPU stack>,
and so is a Rex::Rancher without the AMD functions (with C<warned>). Dies
only when the Nodes cannot be listed: then nothing is removed either.

=cut

sub setup {
    my ($self, $config) = @_;

    my $api     = $self->_k8s_api;
    my $default = $config->gpu_amd_allocation;
    my @nodes   = $config->gpu_enabled ? marker_nodes($api) : ();

    my (%affinity, %for);
    for my $c (@COMPONENTS) {
        $affinity{$c} = affinity($c, $default);
        $for{$c} = [ grep { selects($affinity{$c}, $_->{labels}) } @nodes ];
    }
    $for{labeller} = [] unless $config->gpu_amd_labeller;
    $for{metrics}  = [] unless $config->gpu_amd_metrics;

    if (@nodes) {
        my %alloc = map { $_->{name} => 'none' } @nodes;
        for my $c (qw(device_plugin dra)) {
            $alloc{ $_->{name} } = $COMPONENT{$c}{allocation} for @{ $for{$c} };
        }
        print "      AMD GPU node(s): "
            . join(', ', map { "$_->{name} ($alloc{ $_->{name} })" } @nodes) . "\n";
        warn_bad_allocation_labels($default, @nodes);
    }

    my $deployed = $self->_load_deployed_hashes($config);
    my @remove = grep {
        !@{ $for{$_} } && (defined $deployed->{ $COMPONENT{$_}{key} } || ds_present($self, $api, $_))
    } @COMPONENTS;
    my @deploy = grep { @{ $for{$_} } } @COMPONENTS;

    unless (@remove || @deploy) {
        print !$config->gpu_enabled
            ? "      gpu.enabled is false — nothing to deploy\n"
            : !@nodes
            ? "      No AMD GPU nodes (no node carries $OCP::Config::AMD_GPU_PRESENT_LABEL=true)\n"
            : "      No AMD GPU node selects a component (allocation none, labeller and metrics off)\n";
        return ({ label => 'AMD GPU stack', outcome => 'skipped' });
    }

    # One look before any call: a Rex::Rancher that lacks one function this
    # run needs gets no call at all, rather than half a stack.
    my @need    = ((map { $COMPONENT{$_}{remove} } @remove), (map { $COMPONENT{$_}{deploy} } @deploy));
    my @missing = lib_missing(@need);
    if (@missing) {
        my $version = do { no strict 'refs'; ${"${LIB}::VERSION"} } // 'not loadable';
        print STDERR "  [WARN] The AMD GPU stack needs a newer Rex::Rancher: $LIB $version has no "
            . join(', ', @missing) . "; nothing deployed or removed\n";
        return ({ label => 'AMD GPU stack', outcome => 'skipped', warned => 1 });
    }

    my $kubeconfig = OCP::Cmd::Apply::K8s::kubeconfig_path($self);
    my @results;

    for my $c (@remove) {
        my $comp = $COMPONENT{$c};
        my $why  = !$config->gpu_enabled                 ? 'gpu.enabled is false'
                 : !@nodes                               ? 'no AMD GPU node left'
                 : $c eq 'labeller'                      ? 'gpu.amd.labeller is false'
                 : $c eq 'metrics'                       ? 'gpu.amd.metrics is false'
                 :                                         "no AMD GPU node has allocation $comp->{allocation}";
        print "      Removing $comp->{label} ($why)...\n";
        my $ok = eval {
            lib_call($comp->{remove}, kubeconfig => $kubeconfig);
            OCP::Cmd::Apply::DeployedHash::forget($self, $config, $comp->{key});
            1;
        };
        push @results, $ok ? { label => $comp->{label}, outcome => 'removed' }
                           : { label => $comp->{label}, error => $@ };
    }

    # The component that narrows to In first, the default's NotIn after it: a
    # switched allocation takes the old one off a node before the new one
    # lands there.
    my %is_default = map { $_ => ($COMPONENT{$_}{allocation} // '') eq $default } @deploy;
    my @order = ((grep { $COMPONENT{$_}{allocation} && !$is_default{$_} } @deploy),
                 (grep { $is_default{$_} } @deploy),
                 (grep { !$COMPONENT{$_}{allocation} } @deploy));

    for my $c (@order) {
        my %opts = (
            version  => OCP::Versions->get_component_version($COMPONENT{$c}{version}),
            affinity => $affinity{$c},
            ($c eq 'device_plugin' ? (
                resource_naming => $config->gpu_amd_resource_naming,
                # OCP waits by its own check (wait_ready), and deploys the
                # labeller as its own component.
                wait            => 0,
                node_labeller   => 0,
            ) : ()),
        );
        my $outcome = eval { ensure($self, $config, $api, $kubeconfig, $c, \%opts, $for{$c}) };
        if (my $err = $@) {
            push @results, { label => $COMPONENT{$c}{label}, error => $err,
                             hint  => $c eq 'dra' ? dra_hint($err) : undef };
        } else {
            push @results, { label => $COMPONENT{$c}{label}, outcome => $outcome };
        }
    }

    return @results;
}

# The Nodes with the marker, as { name, labels }, sorted by name. The label
# selector asks the cluster; the value is checked again here.
sub marker_nodes {
    my ($api) = @_;
    my $list = $api->list('Node', labelSelector => "$OCP::Config::AMD_GPU_PRESENT_LABEL=true");
    my @nodes;
    for my $node (@{ $list->items // [] }) {
        my $h      = $api->k8s->object_to_struct($node);
        my $labels = $h->{metadata}{labels} // {};
        next unless ($labels->{$OCP::Config::AMD_GPU_PRESENT_LABEL} // '') eq 'true';
        push @nodes, { name => $h->{metadata}{name}, labels => $labels };
    }
    return sort { $a->{name} cmp $b->{name} } @nodes;
}

# A node whose allocation label is none of the three values gets the default
# (NotIn holds, no In does): said, since the label was meant to say otherwise.
sub warn_bad_allocation_labels {
    my ($default, @nodes) = @_;
    my $key = $OCP::Config::AMD_GPU_ALLOCATION_LABEL;
    for my $n (@nodes) {
        my $v = $n->{labels}{$key};
        next if !defined $v || grep { $_ eq $v } @OCP::Config::GPU_AMD_ALLOCATIONS;
        print STDERR "  [WARN] Node '$n->{name}': $key=$v is not "
            . OCP::Choices::or_list(@OCP::Config::GPU_AMD_ALLOCATIONS)
            . "; the node gets gpu.amd.allocation ($default)\n";
    }
    return;
}

sub ds_present {
    my ($self, $api, $c) = @_;
    my $ds = $OCP::Drift::AMD_GPU_DAEMONSETS{$c};
    return $self->_resource_exists($api, 'DaemonSet', $ds->{name}, namespace => $ds->{namespace});
}

# The functions of @names the loaded Rex::Rancher::K8s lacks (all of them when
# it does not load).
sub lib_missing {
    my (@names) = @_;
    return @names unless eval { require Rex::Rancher::K8s; 1 };
    return grep { !$LIB->can($_) } @names;
}

# A Rex::Rancher::K8s call with Rex::Logger quiet: it logs coloured lines to
# STDERR, which is the error channel here. The progress is OCP's own, on STDOUT.
sub lib_call {
    my ($name, %opts) = @_;
    my $fn = $LIB->can($name) or die "$LIB has no $name\n";
    require Rex::Logger;
    no warnings 'once';
    local $Rex::Logger::silent = 1;
    return $fn->(%opts);
}

# The hash of what a component is deployed with: the call, its options, and
# the Rex::Rancher release, whose specs are the manifest.
sub options_hash {
    my ($c, $opts) = @_;
    my $version = do { no strict 'refs'; ${"${LIB}::VERSION"} } // '';
    return Digest::MD5::md5_hex(JSON::MaybeXS->new(canonical => 1)->encode({
        call => $COMPONENT{$c}{deploy}, lib => "$version", options => $opts,
    }));
}

sub ensure {
    my ($self, $config, $api, $kubeconfig, $c, $opts, $nodes) = @_;
    my $comp = $COMPONENT{$c};

    my $hash     = options_hash($c, $opts);
    my $deployed = $self->_load_deployed_hashes($config);
    my $recorded = defined $deployed->{ $comp->{key} };
    my $present  = ds_present($self, $api, $c);

    if ($recorded && $deployed->{ $comp->{key} } eq $hash && $present) {
        print "      $comp->{label} already deployed (up to date)\n";
        return 'unchanged';
    }

    my $outcome = !$recorded ? 'deployed'
                : !$present  ? 'restored'
                :              'updated';

    print "      Deploying $comp->{label} $opts->{version}...\n";
    lib_call($comp->{deploy}, kubeconfig => $kubeconfig, %$opts);

    print "      Waiting for $comp->{label} on " . join(', ', map { $_->{name} } @$nodes) . "...\n";
    wait_ready($self, $api, $c, $opts, $nodes);

    $self->_save_deployed_hash($config, $comp->{key}, $hash);
    return $outcome;
}

sub wait_ready {
    my ($self, $api, $c, $opts, $nodes) = @_;
    my $interval = ready_interval();
    my $tries    = int(ready_timeout() / $interval);
    my $short;
    for my $try (0 .. $tries) {
        $short = not_ready($self, $api, $c, $opts, $nodes);
        return 1 unless defined $short;
        $self->wait_seconds($interval) if $try < $tries;
    }
    die "$COMPONENT{$c}{label} not ready after " . ready_timeout() . "s: $short\n";
}

# Why component $c is not ready yet, or undef when it is. Readiness is what
# a workload can use: the DaemonSet rolled out, and for the plugin the GPU in
# status.allocatable (not capacity, which a failing plugin leaves standing),
# for the DRA driver a ResourceSlice per node. The labeller and the metrics
# exporter have nothing beyond their DaemonSet to ask; the exporter's /metrics
# is not probed from here (no readinessProbe upstream, and apply is no
# scraper).
sub not_ready {
    my ($self, $api, $c, $opts, $nodes) = @_;
    my $ds_ref = $OCP::Drift::AMD_GPU_DAEMONSETS{$c};
    my $where  = "DaemonSet $ds_ref->{namespace}/$ds_ref->{name}";

    my $ds = eval { $api->get('DaemonSet', name => $ds_ref->{name}, namespace => $ds_ref->{namespace}) };
    return "$where not found" unless $ds;
    my $h = $api->k8s->object_to_struct($ds);
    my $st = $h->{status} // {};
    my $desired = $st->{desiredNumberScheduled} // 0;
    return "$where not rolled out yet (generation not observed)"
        if ($st->{observedGeneration} // 0) < ($h->{metadata}{generation} // 0);
    return "$where schedules no pod" unless $desired;
    return "$where has " . ($st->{numberReady} // 0) . " of $desired pod(s) ready"
        if ($st->{numberReady} // 0) < $desired;
    return "$where has " . ($st->{updatedNumberScheduled} // 0) . " of $desired pod(s) updated"
        if ($st->{updatedNumberScheduled} // 0) < $desired;

    if ($c eq 'device_plugin') {
        my $mixed = ($opts->{resource_naming} // 'single') eq 'mixed';
        for my $n (@$nodes) {
            my $node  = eval { $api->get('Node', name => $n->{name}) };
            my $alloc = $node ? ($api->k8s->object_to_struct($node)->{status}{allocatable} // {}) : {};
            my @gpu   = grep { $mixed ? index($_, $AMD_GPU_PREFIX) == 0 : $_ eq $AMD_GPU_RESOURCE } keys %$alloc;
            next if grep { ($alloc->{$_} // '0') =~ /\A([0-9]+)/ && $1 > 0 } @gpu;
            return "node '$n->{name}' shows no " . ($mixed ? "$AMD_GPU_PREFIX*" : $AMD_GPU_RESOURCE)
                . " in status.allocatable";
        }
    }
    elsif ($c eq 'dra') {
        my $slices = $self->_crd_get($api, '/apis/resource.k8s.io/v1/resourceslices') // {};
        my %has = map { ($_->{spec}{nodeName} // '') => 1 }
                  grep { ($_->{spec}{driver} // '') eq $AMD_GPU_DRA_DRIVER } @{ $slices->{items} // [] };
        for my $n (@$nodes) {
            return "no ResourceSlice of driver $AMD_GPU_DRA_DRIVER for node '$n->{name}'"
                unless $has{ $n->{name} };
        }
    }
    return undef;
}

# What the DRA driver's refusal on a cluster without resource.k8s.io/v1
# means for the nodes, and the way out.
sub dra_hint {
    my ($err) = @_;
    return undef unless ($err // '') =~ m{resource\.k8s\.io/v1};
    return "       Nodes with allocation dra get no GPU until the cluster runs Kubernetes 1.34 or later;\n"
         . "       use gpu.amd.allocation (or the node's $OCP::Config::AMD_GPU_ALLOCATION_LABEL label)\n"
         . "       device-plugin meanwhile.\n";
}

=head2 step

    my $r = OCP::Cmd::Apply::AMDGPU::step($apply, $config);

L</setup>, reported: one C<[ok]> line per result on STDOUT, a failure as
C<[!!]> on STDERR with its cause. Never dies. Returns
C<< { changed, failed => [labels], warned } >>, also kept on the command
object for L</after_join>. The caller prints the C<[..] Checking AMD GPU
stack...> line in front of it.

=cut

sub step {
    my ($self, $config) = @_;

    my $r = { changed => 0, failed => [], warned => 0 };
    my @results = eval { setup($self, $config) };
    if (my $err = $@) {
        $err .= "\n" unless $err =~ /\n\z/;
        print STDERR "  [!!] AMD GPU stack setup failed: $err";
        push @{ $r->{failed} }, 'AMD GPU stack';
    }
    for my $res (@results) {
        if (defined $res->{error}) {
            my $err = $res->{error};
            $err .= "\n" unless $err =~ /\n\z/;
            print STDERR "  [!!] $res->{label} setup failed: $err";
            print STDERR $res->{hint} if $res->{hint};
            push @{ $r->{failed} }, $res->{label};
            next;
        }
        $r->{warned} = 1 if $res->{warned};
        $r->{changed} += $self->_report_component($res->{label}, $res->{outcome});
    }

    $self->{_amd_gpu_step} = $r;
    return $r;
}

=head2 after_join

    my @failed = OCP::Cmd::Apply::AMDGPU::after_join($apply, $config, \@worker_results);

The AMD check once more after the worker step, when a worker that came up
Ready carries the marker: its allocation may need a component the first
check had no node for. The marker is set at registration, so there is
nothing to wait for. Not run when the first check failed or warned (said
already), or did not run. Returns the labels that failed, empty otherwise.

=cut

sub after_join {
    my ($self, $config, $results) = @_;

    my $first = $self->{_amd_gpu_step} or return;
    return if @{ $first->{failed} } || $first->{warned};
    return unless $config->gpu_enabled;

    my @joined = map { $_->{name} } grep { ($_->{phase} // '') eq 'Ready' } @{ $results // [] };
    return unless @joined;

    my $api = $self->_k8s_api;
    my @amd = grep {
        my $node   = eval { $api->get('Node', name => $_) };
        my $labels = $node ? ($api->k8s->object_to_struct($node)->{metadata}{labels} // {}) : {};
        ($labels->{$OCP::Config::AMD_GPU_PRESENT_LABEL} // '') eq 'true';
    } map {
        my $name = $_;
        my $cr = eval { $api->get('OCPNode', name => $name, namespace => 'ocp-system') };
        my $h  = $cr ? $api->k8s->object_to_struct($cr) : {};
        $h->{status}{kubernetesNodeName} // $name;
    } @joined;
    return unless @amd;

    print "  [..] Checking AMD GPU stack again, after the worker join (" . join(', ', @amd) . ")...\n";
    return @{ step($self, $config)->{failed} };
}

1;

__END__

=head1 SEE ALSO

L<Rex::Rancher::K8s>, L<OCP::Cmd::Apply::Workloads> (the NVIDIA side),
L<OCP::Drift/%AMD_GPU_DAEMONSETS>, F<docs/superpowers/specs/2026-10-31-amd-gpu-worker-design.md>.

=cut

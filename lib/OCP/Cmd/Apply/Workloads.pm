package OCP::Cmd::Apply::Workloads;
# ABSTRACT: Opt-in cluster workloads (NFD + GPU operator)

use strict;
use warnings;

use Digest::MD5;
use JSON::PP ();
use Path::Tiny qw(path);

use OCP::Versions;

our $VERSION = '0.001';

=head1 SYNOPSIS

    OCP::Cmd::Apply::Workloads::setup_nfd($apply, $config);
    OCP::Cmd::Apply::Workloads::setup_gpu_operator($apply, $config);

=head1 DESCRIPTION

The two opt-in cluster workloads the deploy path installs alongside the
core stack. NFD runs everywhere (it is how the GPU operator later finds the
hardware), the GPU operator only when a node has an NFD-detected NVIDIA card
AND C<gpu.enabled> is true in ocp.yaml.

Both follow the same shape: hash the manifest + the CRD bundle, ask the
cluster whether the deployment is actually there, and only then decide
"unchanged / restored / deployed / updated". The cluster-truth check is the
lesson registry paid for the hard way — without it, an `ocp destroy` left
a record of a workload the next apply happily skipped.

L<OCP::Cmd::Apply> re-exports these as thin forwarders so the test surface
(t/40-gpu-clusterpolicy.t) keeps working.

=cut

sub setup_nfd {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    # Ensure NFD image is built and pushed to ocp-registry
    # (required because released NFD versions crash on K8s 1.34+)
    ensure_nfd_image($self, $config);

    # Apply CRDs first (before any NFD components)
    my $share_dir = $self->_find_share_dir;
    # Full upstream CRD bundle: NodeFeature + NodeFeatureGroup + NodeFeatureRule.
    # All three are required — nfd-master v0.17 watches NodeFeatureGroup and
    # gets stuck in an error loop if the CRD is missing, never processing labels.
    my $crd_file = $share_dir->child('nfd', 'crds', 'nfd-api-crds.yaml');
    die "NFD CRD file not found: $crd_file\n" unless -f $crd_file;

    my $manifest = generate_nfd_manifest($self);


    my $hash = Digest::MD5::md5_hex($manifest . path($crd_file)->slurp);
    my $deployed = $self->_load_deployed_hashes($config);

    # Check if NFD is actually running (not just hash match)
    my $ns_exists = $self->_resource_exists($api, 'Namespace', 'node-feature-discovery');
    my $nfd_running = $ns_exists &&
        $self->_resource_exists($api, 'Deployment', 'nfd-master', namespace => 'node-feature-discovery');

    my $recorded = exists $deployed->{nfd};

    if (($deployed->{nfd} // '') eq $hash && $nfd_running) {
        print "      NFD already deployed (up to date)\n";
        return 'unchanged';
    }

    my $outcome = !$recorded    ? 'deployed'
                : !$nfd_running ? 'restored'
                :                 'updated';

    # Apply CRDs
    print "      Applying NFD CRDs...\n";
    $self->_apply_yaml_file($api, $crd_file->stringify);

    # Apply NFD components
    print "      Deploying NFD master + worker...\n";
    $self->_apply_yaml_string($api, $manifest);

    # Wait for nfd-master
    print "      Waiting for nfd-master...\n";
    $self->_poll_deployment_ready($api, 'nfd-master', 'node-feature-discovery', 120)
        or die "nfd-master not ready within 120s\n";

    # Wait for nfd-worker DaemonSet
    print "      Waiting for nfd-worker...\n";
    for my $i (1..12) {
        my $ds = eval { $api->get('DaemonSet', 'nfd-worker', namespace => 'node-feature-discovery') };
        if ($ds && $ds->status && ($ds->status->numberReady // 0) > 0) {
            print "      NFD worker running on " . $ds->status->numberReady . " node(s)\n";
            last;
        }
        sleep 10;
    }

    # Wait for NFD to label nodes (needs a few seconds after worker starts)
    print "      Waiting for NFD labels...\n";
    for my $i (1..12) {
        my $nodes = eval { $api->list('Node') };
        if ($nodes && $nodes->items && @{ $nodes->items }) {
            my $labels = $nodes->items->[0]->metadata->labels;
            if ($labels && grep { /^feature\.node\.kubernetes\.io/ } keys %$labels) {
                print "      NFD labels detected on nodes\n";
                last;
            }
        }
        if ($i == 12) {
            die "NFD labels not detected on any node after 120s\n";
        }
        sleep 10;
    }

    $self->_save_deployed_hash($config, 'nfd', $hash);

    return $outcome;
}

sub ensure_nfd_image {
    my ($self, $config) = @_;

    # Use pinned release image from registry.k8s.io (no Kaniko build needed)
    my $nfd_version = OCP::Versions->get_component_version('nfd');
    print "      Using NFD release image: registry.k8s.io/nfd/node-feature-discovery:$nfd_version\n";

    # No build needed — the manifest references the upstream image directly
    return;
}

sub generate_nfd_manifest {
    my ($self) = @_;

    my $nfd_version = OCP::Versions->get_component_version('nfd');
    my $nfd_image = "registry.k8s.io/nfd/node-feature-discovery:$nfd_version";

    my @resources = (
        # Namespace
        {
            apiVersion => 'v1',
            kind       => 'Namespace',
            metadata   => { name => 'node-feature-discovery' },
        },

        # ServiceAccount
        {
            apiVersion => 'v1',
            kind       => 'ServiceAccount',
            metadata   => {
                name      => 'nfd-master',
                namespace => 'node-feature-discovery',
            },
        },
        {
            apiVersion => 'v1',
            kind       => 'ServiceAccount',
            metadata   => {
                name      => 'nfd-worker',
                namespace => 'node-feature-discovery',
            },
        },

        # ClusterRole for nfd-master — mirrors upstream NFD v0.17 RBAC.
        # Every rule here is required: missing any single one makes nfd-master
        # start cleanly but silently stop processing NodeFeatures somewhere
        # along the pipeline, with the symptom of "no labels appearing".
        # In particular, 'namespaces: watch, list' is needed for NodeFeature
        # discovery, and 'nodefeaturegroups' was introduced in v0.16.
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRole',
            metadata   => { name => 'nfd-master' },
            rules      => [
                {
                    apiGroups => [''],
                    resources => ['namespaces'],
                    verbs     => ['list', 'watch'],
                },
                {
                    apiGroups => [''],
                    resources => ['nodes', 'nodes/status'],
                    verbs     => ['get', 'list', 'watch', 'patch', 'update'],
                },
                {
                    apiGroups => ['nfd.k8s-sigs.io'],
                    resources => ['nodefeatures', 'nodefeaturerules', 'nodefeaturegroups'],
                    verbs     => ['get', 'list', 'watch'],
                },
                {
                    apiGroups => ['nfd.k8s-sigs.io'],
                    resources => ['nodefeaturegroups/status'],
                    verbs     => ['patch', 'update'],
                },
                {
                    apiGroups => ['coordination.k8s.io'],
                    resources => ['leases'],
                    verbs     => ['create', 'delete', 'get', 'list', 'update', 'watch'],
                },
            ],
        },

        # ClusterRoleBinding for nfd-master
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRoleBinding',
            metadata   => { name => 'nfd-master' },
            roleRef    => {
                apiGroup => 'rbac.authorization.k8s.io',
                kind     => 'ClusterRole',
                name     => 'nfd-master',
            },
            subjects => [{
                kind      => 'ServiceAccount',
                name      => 'nfd-master',
                namespace => 'node-feature-discovery',
            }],
        },

        # ClusterRole for nfd-worker — upstream NFD v0.17 uses a namespaced
        # Role, but ClusterRole is a valid superset here and matches our
        # pattern elsewhere. The 'pods: get' rule is required because the
        # worker reads its own pod spec for some feature sources.
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRole',
            metadata   => { name => 'nfd-worker' },
            rules      => [
                {
                    apiGroups => ['nfd.k8s-sigs.io'],
                    resources => ['nodefeatures'],
                    verbs     => ['create', 'get', 'update'],
                },
                {
                    apiGroups => [''],
                    resources => ['pods'],
                    verbs     => ['get'],
                },
            ],
        },

        # ClusterRoleBinding for nfd-worker
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRoleBinding',
            metadata   => { name => 'nfd-worker' },
            roleRef    => {
                apiGroup => 'rbac.authorization.k8s.io',
                kind     => 'ClusterRole',
                name     => 'nfd-worker',
            },
            subjects => [{
                kind      => 'ServiceAccount',
                name      => 'nfd-worker',
                namespace => 'node-feature-discovery',
            }],
        },

        # nfd-master Deployment (Controller)
        {
            apiVersion => 'apps/v1',
            kind       => 'Deployment',
            metadata   => {
                name      => 'nfd-master',
                namespace => 'node-feature-discovery',
                labels    => { app => 'nfd-master' },
            },
            spec => {
                replicas => 1,
                selector => { matchLabels => { app => 'nfd-master' } },
                template => {
                    metadata => { labels => { app => 'nfd-master' } },
                    spec     => {
                        serviceAccountName => 'nfd-master',
                        tolerations        => [{
                            key      => 'node-role.kubernetes.io/master',
                            operator => 'Exists',
                            effect   => 'NoSchedule',
                        }, {
                            key      => 'node-role.kubernetes.io/control-plane',
                            operator => 'Exists',
                            effect   => 'NoSchedule',
                        }],
                        affinity => {
                            nodeAffinity => {
                                preferredDuringSchedulingIgnoredDuringExecution => [{
                                    weight     => 1,
                                    preference => {
                                        matchExpressions => [{
                                            key      => 'node-role.kubernetes.io/control-plane',
                                            operator => 'Exists',
                                        }],
                                    },
                                }],
                            },
                        },
                        containers => [{
                            name            => 'nfd-master',
                            image           => $nfd_image,
                            imagePullPolicy => 'IfNotPresent',
                            command         => ['nfd-master'],
                            # Mirror the upstream helm template defaults. Without
                            # explicit args the master starts but doesn't enable
                            # leader election, and never writes node labels.
                            #
                            # Keep this list minimal: nfd-master rejects any flag
                            # it doesn't know, and its usage dump then trips a Go
                            # bug (`panic calling String method on zero
                            # featuregate.featureGate`) that buries the real cause.
                            # Two flags that look plausible but do NOT exist:
                            #   -featurerules-controller — config-file option only;
                            #     the controller is on by default since v0.17.
                            #   -metrics / -grpc-health   — folded into the single
                            #     -port flag (default 8080) as of v0.18.
                            args => [
                                '-enable-leader-election',
                                '-enable-taints',
                                '-resync-period=1h',
                            ],
                            # -port serves metrics and healthz. Not gRPC: the
                            # gRPC transport is gone since v0.17, workers report
                            # through the NodeFeature API instead.
                            ports           => [{ containerPort => 8080, name => 'metrics' }],
                            env             => [{ name => 'NODE_NAME', valueFrom => { fieldRef => { fieldPath => 'spec.nodeName' } } }],
                            securityContext => {
                                allowPrivilegeEscalation => JSON::PP::false,
                                capabilities             => { drop => ['ALL'] },
                                readOnlyRootFilesystem   => JSON::PP::true,
                                runAsNonRoot             => JSON::PP::true,
                            },
                            resources => {
                                requests => { cpu => '50m',  memory => '64Mi' },
                                limits   => { cpu => '200m', memory => '128Mi' },
                            },
                        }],
                    },
                },
            },
        },

        # nfd-worker DaemonSet
        {
            apiVersion => 'apps/v1',
            kind       => 'DaemonSet',
            metadata   => {
                name      => 'nfd-worker',
                namespace => 'node-feature-discovery',
                labels    => { app => 'nfd-worker' },
            },
            spec => {
                selector => { matchLabels => { app => 'nfd-worker' } },
                template => {
                    metadata => { labels => { app => 'nfd-worker' } },
                    spec     => {
                        serviceAccountName => 'nfd-worker',
                        dnsPolicy          => 'ClusterFirstWithHostNet',
                        tolerations        => [{
                            operator => 'Exists',
                            effect   => 'NoSchedule',
                        }],
                        containers => [{
                            name            => 'nfd-worker',
                            image           => $nfd_image,
                            imagePullPolicy => 'IfNotPresent',
                            command         => ['nfd-worker'],
                            env             => [{ name => 'NODE_NAME', valueFrom => { fieldRef => { fieldPath => 'spec.nodeName' } } }],
                            securityContext => {
                                allowPrivilegeEscalation => JSON::PP::false,
                                capabilities             => { drop => ['ALL'] },
                                readOnlyRootFilesystem   => JSON::PP::true,
                                runAsNonRoot             => JSON::PP::true,
                            },
                            resources => {
                                requests => { cpu => '50m',  memory => '64Mi' },
                                limits   => { cpu => '200m', memory => '128Mi' },
                            },
                            volumeMounts => [
                                { name => 'host-boot',     mountPath => '/host-boot',     readOnly => JSON::PP::true },
                                { name => 'host-os-release', mountPath => '/host-etc/os-release', readOnly => JSON::PP::true },
                                { name => 'host-sys',      mountPath => '/host-sys',      readOnly => JSON::PP::true },
                                { name => 'host-usr-lib',  mountPath => '/host-usr/lib',   readOnly => JSON::PP::true },
                                { name => 'host-lib',      mountPath => '/host-lib',       readOnly => JSON::PP::true },
                            ],
                        }],
                        volumes => [
                            { name => 'host-boot',       hostPath => { path => '/boot' } },
                            { name => 'host-os-release', hostPath => { path => '/etc/os-release' } },
                            { name => 'host-sys',        hostPath => { path => '/sys' } },
                            { name => 'host-usr-lib',    hostPath => { path => '/usr/lib' } },
                            { name => 'host-lib',        hostPath => { path => '/lib' } },
                        ],
                    },
                },
            },
        },

        # Service for nfd-master metrics/healthz
        {
            apiVersion => 'v1',
            kind       => 'Service',
            metadata   => {
                name      => 'nfd-master',
                namespace => 'node-feature-discovery',
            },
            spec => {
                selector => { app => 'nfd-master' },
                ports    => [{ port => 8080, targetPort => 8080, protocol => 'TCP', name => 'metrics' }],
                type     => 'ClusterIP',
            },
        },
    );

    return $self->ocp->dump(@resources);
}

sub setup_gpu_operator {
    my ($self, $config) = @_;

    # `gpu.enabled: false` is one switch for the whole GPU story: Rex skips the
    # host driver, and nothing gets deployed in-cluster either. Deploying the
    # operator anyway would put the stack back on a node the spec asked to keep
    # GPU-free.
    unless ($config->gpu_enabled) {
        print "  [ok] GPU Operator skipped (gpu.enabled: false)\n";
        return;
    }

    my $api = $self->_k8s_api;

    # Check if any node has NVIDIA GPU via NFD labels.
    # NFD v0.17 labels use the format pci-{CLASS}_{VENDOR}.present:
    #   0300 = VGA controller (consumer/workstation GPUs: RTX, GTX, Quadro)
    #   0302 = 3D controller  (datacenter GPUs: Tesla, A100, H100, L40)
    my @gpu_nodes;
    for my $pci_class (qw(0300_10de 0302_10de)) {
        my $list = eval {
            $api->list('Node', labelSelector => "feature.node.kubernetes.io/pci-${pci_class}.present=true")
        };
        if ($list && $list->items) {
            push @gpu_nodes, @{ $list->items };
        }
    }
    # Deduplicate (a node could theoretically have both classes)
    my %seen;
    @gpu_nodes = grep { !$seen{$_->metadata->name}++ } @gpu_nodes;

    unless (@gpu_nodes) {
        print "      No GPU nodes detected (no NFD pci-0300_10de or pci-0302_10de label)\n";
        print "  [ok] GPU Operator skipped (no GPU hardware)\n";
        return;
    }

    my @gpu_names = map { $_->metadata->name } @gpu_nodes;
    print "      GPU node(s) detected: ", join(', ', @gpu_names), "\n";

    # Apply CRDs first
    my $share_dir = $self->_find_share_dir;
    my $crd_file = $share_dir->child('gpu-operator', 'crds', 'clusterpolicy-crd.yaml');
    die "GPU Operator CRD file not found: $crd_file\n" unless -f $crd_file;
    my $driver_crd_file = $share_dir->child('gpu-operator', 'crds', 'nvidiadriver-crd.yaml');
    die "NVIDIADriver CRD file not found: $driver_crd_file\n" unless -f $driver_crd_file;

    my $manifest = generate_gpu_operator_manifest($self, $config);

    my $hash = Digest::MD5::md5_hex($manifest . path($crd_file)->slurp . path($driver_crd_file)->slurp);
    my $deployed = $self->_load_deployed_hashes($config);

    # Check if GPU Operator is actually running (not just hash match)
    my $gpu_ns_exists = $self->_resource_exists($api, 'Namespace', 'gpu-operator');
    my $gpu_running = $gpu_ns_exists &&
        $self->_resource_exists($api, 'Deployment', 'gpu-operator', namespace => 'gpu-operator');

    if (($deployed->{'gpu-operator'} // '') eq $hash && $gpu_running) {
        print "      GPU Operator already deployed (up to date)\n";
        return;
    }

    # Apply CRDs (ClusterPolicy + NVIDIADriver)
    print "      Applying GPU Operator CRDs...\n";
    $self->_apply_yaml_file($api, $crd_file->stringify);
    $self->_apply_yaml_file($api, $driver_crd_file->stringify);

    # Wait briefly for CRDs to be established
    sleep 3;

    # Apply operator + ClusterPolicy
    print "      Deploying GPU Operator...\n";
    $self->_apply_yaml_string($api, $manifest);

    # Wait for operator deployment
    print "      Waiting for gpu-operator...\n";
    $self->_poll_deployment_ready($api, 'gpu-operator', 'gpu-operator', 120)
        or die "gpu-operator not ready within 120s\n";

    # Check ClusterPolicy status via raw API (CRD, no IO::K8s class)
    my $cp_path = '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';
    for my $i (1..12) {
        my $cp = $self->_crd_get($api, $cp_path);
        if ($cp && $cp->{status} && ($cp->{status}{state} // '') eq 'ready') {
            print "  [ok] GPU Operator ready (ClusterPolicy state: ready)\n";
            last;
        }
        if ($i == 12) {
            my $state = ($cp && $cp->{status}) ? ($cp->{status}{state} // 'unknown') : 'unknown';
            print "      ClusterPolicy state: $state (may still be reconciling)\n";
        }
        sleep 10;
    }

    $self->_save_deployed_hash($config, 'gpu-operator', $hash);
}

sub generate_gpu_operator_manifest {
    my ($self, $config) = @_;

    my $gpu_version = OCP::Versions->get_component_version('gpu_operator');
    my $operator_image = "nvcr.io/nvidia/gpu-operator:$gpu_version";
    my $distribution = $config->distribution || 'rke2';

    # Where the operator finds containerd. Both values are paths on the *node*:
    # the operator mounts the directory of each into the toolkit DaemonSet, as
    # /runtime/sock-dir and /runtime/config-dir. A directory that merely exists
    # is therefore not good enough — what has to be in it is the socket.
    #
    # The socket does NOT differ between the distributions. RKE2 runs k3s' agent
    # code and inherits its containerd invocation along with it; measured on an
    # RKE2 node (v1.36.3+rke2r1, aarch64), the process is:
    #
    #   containerd -c /var/lib/rancher/rke2/agent/etc/containerd/config.toml
    #              -a /run/k3s/containerd/containerd.sock
    #              --state /run/k3s/containerd
    #              --root  /var/lib/rancher/rke2/agent/containerd
    #
    # The value here used to be .../rke2/agent/containerd/containerd.sock for
    # RKE2, which is --root with a socket name pinned on: the directory exists,
    # so the hostPath mounted without complaint and the DaemonSet only fell over
    # much later, when it tried to SIGHUP containerd through a socket that had
    # never been there ("unable to dial: connect: no such file or directory",
    # CrashLoopBackOff). Same reason the RKE2 GPU docs name /run/k3s/... too.
    #
    # /run, not /var/run: /run is the path containerd binds and the one in the
    # command line above. /var/run is a compatibility symlink onto it, so it
    # resolves to the same socket — but only as long as the symlink exists, and
    # it buys nothing.
    my $containerd_socket = '/run/k3s/containerd/containerd.sock';

    # The config path DOES differ, because each distribution keeps its agent
    # state under its own name. Only that name varies, so vary only the name:
    # two full paths side by side is what let the socket drift in the first
    # place. Unknown values fall back to RKE2 rather than interpolating into
    # the path — kubernetes.dist is not validated anywhere.
    my $rancher_dir = $distribution eq 'k3s' ? 'k3s' : 'rke2';
    my $containerd_config = "/var/lib/rancher/$rancher_dir/agent/etc/containerd/config.toml";

    # CONTAINERD_SET_AS_DEFAULT / CONTAINERD_RUNTIME_CLASS are the archived
    # 22.9 recipe and measured inert at the pinned operator (see karr #30): the
    # operator derives NVIDIA_RUNTIME_SET_AS_DEFAULT from cdi.enabled and hands
    # the toolkit that instead, so the node keeps runc as its default runtime
    # no matter what stands here. Left in place deliberately — removing them is
    # #30's job, not a bug fix's.
    my $containerd_set_as_default = '1';
    my $containerd_runtime_class = 'nvidia';

    # Who installs the driver, and does the toolkit need installing at all?
    #
    # driver: the two halves must never both be on — a driver container on top
    # of a host driver is two drivers for one card. 'host' is the default and
    # what Rex does; 'operator' flips both sides at once (OCP::Rex stops the
    # Rex-side install with the same config value).
    #
    # toolkit: on by default, because a plain host has no NVIDIA runtime. A
    # vendor image does: on a DGX, /usr/bin/nvidia-container-runtime and
    # nvidia-ctk are there before OCP is, and NVIDIA's guidance for those hosts
    # is toolkit.enabled=false next to driver.enabled=false, so the toolkit
    # DaemonSet does not rewrite a containerd configuration that already works.
    my $driver_by_operator = $config->gpu_driver eq 'operator';
    my $toolkit_enabled    = $config->gpu_toolkit;

    my @resources = (
        # Namespace
        {
            apiVersion => 'v1',
            kind       => 'Namespace',
            metadata   => { name => 'gpu-operator' },
        },

        # ServiceAccount
        {
            apiVersion => 'v1',
            kind       => 'ServiceAccount',
            metadata   => {
                name      => 'gpu-operator',
                namespace => 'gpu-operator',
            },
        },

        # ClusterRole
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRole',
            metadata   => { name => 'gpu-operator' },
            rules      => [
                {
                    apiGroups => [''],
                    resources => ['nodes', 'nodes/status', 'pods', 'pods/eviction', 'configmaps', 'events',
                                  'secrets', 'serviceaccounts', 'services', 'namespaces',
                                  'endpoints', 'persistentvolumeclaims'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['apps'],
                    resources => ['deployments', 'daemonsets', 'replicasets', 'statefulsets'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['rbac.authorization.k8s.io'],
                    resources => ['clusterroles', 'clusterrolebindings', 'roles', 'rolebindings'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['nvidia.com'],
                    resources => [
                        'clusterpolicies', 'clusterpolicies/status', 'clusterpolicies/finalizers',
                        'nvidiadrivers', 'nvidiadrivers/status', 'nvidiadrivers/finalizers',
                    ],
                    verbs     => ['*'],
                },
                {
                    # GPU Operator probes config.openshift.io to detect OpenShift.
                    # On non-OpenShift clusters the API group doesn't exist, so this
                    # returns 404 ("not OpenShift") — but only if RBAC allows the
                    # request.  Without this rule the SA gets 403 Forbidden, which
                    # the operator treats as a fatal error.
                    apiGroups => ['config.openshift.io'],
                    resources => ['clusterversions'],
                    verbs     => ['get', 'list', 'watch'],
                },
                {
                    apiGroups => ['scheduling.k8s.io'],
                    resources => ['priorityclasses'],
                    verbs     => ['get', 'list', 'watch', 'create', 'update'],
                },
                {
                    apiGroups => ['coordination.k8s.io'],
                    resources => ['leases'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['node.k8s.io'],
                    resources => ['runtimeclasses'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['apiextensions.k8s.io'],
                    resources => ['customresourcedefinitions'],
                    verbs     => ['get', 'list', 'watch'],
                },
            ],
        },

        # ClusterRoleBinding
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRoleBinding',
            metadata   => { name => 'gpu-operator' },
            roleRef    => {
                apiGroup => 'rbac.authorization.k8s.io',
                kind     => 'ClusterRole',
                name     => 'gpu-operator',
            },
            subjects => [{
                kind      => 'ServiceAccount',
                name      => 'gpu-operator',
                namespace => 'gpu-operator',
            }],
        },

        # GPU Operator Deployment
        {
            apiVersion => 'apps/v1',
            kind       => 'Deployment',
            metadata   => {
                name      => 'gpu-operator',
                namespace => 'gpu-operator',
                labels    => { app => 'gpu-operator' },
            },
            spec => {
                replicas => 1,
                selector => { matchLabels => { app => 'gpu-operator' } },
                template => {
                    metadata => { labels => { app => 'gpu-operator' } },
                    spec     => {
                        serviceAccountName => 'gpu-operator',
                        tolerations        => [{
                            key      => 'node-role.kubernetes.io/control-plane',
                            operator => 'Exists',
                            effect   => 'NoSchedule',
                        }],
                        # Operator needs host's /etc/os-release to detect OS for
                        # templating DaemonSets like dcgm-exporter.
                        volumes => [{
                            name     => 'host-os-release',
                            hostPath => { path => '/etc/os-release' },
                        }],
                        containers => [{
                            name            => 'gpu-operator',
                            image           => $operator_image,
                            command         => ['gpu-operator'],
                            env             => [
                                { name => 'WATCH_NAMESPACE', value => '' },
                                { name => 'OPERATOR_NAMESPACE', value => 'gpu-operator' },
                                { name => 'USE_OSHIFT_DRIVER_TOOLKIT', value => 'false' },
                                { name => 'CLUSTER_PLATFORM', value => 'container' },
                                { name => 'POD_NAME', valueFrom => { fieldRef => { fieldPath => 'metadata.name' } } },
                            ],
                            volumeMounts => [{
                                name      => 'host-os-release',
                                mountPath => '/host-etc/os-release',
                                readOnly  => JSON::PP::true,
                            }],
                            securityContext => {
                                allowPrivilegeEscalation => JSON::PP::false,
                                capabilities             => { drop => ['ALL'] },
                            },
                            resources => {
                                requests => { cpu => '100m',  memory => '128Mi' },
                                limits   => { cpu => '500m',  memory => '256Mi' },
                            },
                            ports => [{ containerPort => 8080, name => 'metrics' }],
                        }],
                    },
                },
            },
        },

        # ClusterPolicy CR (GPU Operator configuration)
        # driver.enabled follows gpu.driver — see above
        # nfd.enabled: false — we deploy NFD ourselves
        # gfd.enabled: false — NFD handles GPU feature discovery
        {
            apiVersion => 'nvidia.com/v1',
            kind       => 'ClusterPolicy',
            metadata   => { name => 'gpu-cluster-policy' },
            spec       => {
                operator => {
                    defaultRuntime => 'containerd',
                },
                driver => $driver_by_operator
                    ? {
                        enabled         => JSON::PP::true,
                        repository      => 'nvcr.io/nvidia',
                        image           => 'driver',
                        version         => OCP::Versions->get_component_version('nvidia_driver'),
                        imagePullPolicy => 'IfNotPresent',
                    }
                    : { enabled => JSON::PP::false },
                toolkit => {
                    enabled         => $toolkit_enabled ? JSON::PP::true : JSON::PP::false,
                    repository      => 'nvcr.io/nvidia/k8s',
                    image           => 'container-toolkit',
                    version         => OCP::Versions->get_component_version('nvidia_toolkit'),
                    imagePullPolicy => 'IfNotPresent',
                    env => [
                        { name => 'CONTAINERD_SOCKET', value => $containerd_socket },
                        { name => 'CONTAINERD_CONFIG', value => $containerd_config },
                        { name => 'CONTAINERD_SET_AS_DEFAULT', value => $containerd_set_as_default },
                        { name => 'CONTAINERD_RUNTIME_CLASS', value => $containerd_runtime_class },
                    ],
                },
                devicePlugin => {
                    enabled         => JSON::PP::true,
                    repository      => 'nvcr.io/nvidia',
                    image           => 'k8s-device-plugin',
                    version         => OCP::Versions->get_component_version('nvidia_device_plugin'),
                    imagePullPolicy => 'IfNotPresent',
                },
                dcgmExporter => {
                    enabled         => JSON::PP::true,
                    repository      => 'nvcr.io/nvidia/k8s',
                    image           => 'dcgm-exporter',
                    version         => OCP::Versions->get_component_version('dcgm_exporter'),
                    imagePullPolicy => 'IfNotPresent',
                },
                dcgm => {
                    enabled         => JSON::PP::true,
                    repository      => 'nvcr.io/nvidia/cloud-native',
                    image           => 'dcgm',
                    version         => OCP::Versions->get_component_version('nvidia_dcgm'),
                    imagePullPolicy => 'IfNotPresent',
                },
                gfd => {
                    enabled => JSON::PP::false,  # NFD handles feature discovery
                },
                nfd => {
                    enabled => JSON::PP::false,  # We deploy NFD ourselves
                },
                migManager => {
                    enabled => JSON::PP::false,
                },
                # The standalone gpu-operator-validator image stops at v25.3.4:
                # from v25.10 on the operator image carries the validator
                # itself (/usr/bin/nvidia-validator), which is why upstream's
                # values.yaml points validator at nvcr.io/nvidia/gpu-operator
                # with the chart's own appVersion. Anything else 404s and every
                # GPU DaemonSet stays in Init:ImagePullBackOff — its init
                # container is the validator.
                validator => {
                    enabled         => JSON::PP::true,
                    repository      => 'nvcr.io/nvidia',
                    image           => 'gpu-operator',
                    version         => $gpu_version,
                    imagePullPolicy => 'IfNotPresent',
                },
                nodeStatusExporter => {
                    enabled => JSON::PP::false,
                },
            },
        },
    );

    return $self->ocp->dump(@resources);
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Versions>.

=cut

package OCP::Config;
# ABSTRACT: OCP configuration and status management

use Moo;
use OCP;
use OCP::Choices;
use OCP::NodeMeta;
use OCP::Provider;
use JSON::MaybeXS;
use Path::Tiny qw(path);
use Carp qw(croak);
use Socket ();
use YAML::XS ();

# The Hetzner control-plane defaults a fresh spec gets. Kept here because two
# places need the same three values: write_spec falls back to them, and the
# pickers in OCP::Cmd::Init preselect them so pressing Enter reproduces
# exactly what a non-interactive init would have written.
our %HETZNER_DEFAULTS = (
    server_type => 'cpx21',
    location    => 'fsn1',
    image       => 'debian-13',
);

has ocp => (
    is      => 'lazy',
    default => sub { OCP->instance },
);

# Config file path (ocp.yaml)
has file => (
    is       => 'ro',
    required => 1,
);

# Project directory (derived from config file)
has project_dir => (
    is      => 'lazy',
    builder => sub { path(shift->file)->parent },
);

# Spec data (from ocp.yaml)
has spec => (
    is      => 'lazy',
    builder => '_load_spec',
);

#
# Loaders
#

sub _load_spec {
    my ($self) = @_;
    return $self->_default_spec unless -f $self->file;
    return $self->ocp->load_file($self->file);
}

sub _default_spec {
    return {
        name => 'mycluster',
        kubernetes => {
            dist    => 'rke2',  # or 'k3s'
            version => '',      # latest if empty
        },
        control_planes => {
            provider => 'hetzner',
            %HETZNER_DEFAULTS,
        },
        workers => [],
        ssh => {
            private_key => '.ocp/id_ed25519',
            public_key  => '.ocp/id_ed25519.pub',
        },
    };
}

#
# Spec accessors
#

sub name { shift->spec->{name} // 'mycluster' }

# The name this cluster's admin public key carries in a provider's key store.
#
# Bootstrap uploads the key under this name before the control plane exists
# (OCP::Provider::Hetzner::upload_ssh_key is an ensure; ssh/local ignore it),
# and every server created for the cluster afterwards has to reference the
# very same one -- a Hetzner worker created with a different name, or with
# none, boots with an empty authorized_keys and is unreachable for good
# (k92).
#
# It lives here because OCP::Config is the only place that knows the cluster
# name in both modes: secure mode uploads the PIN2-protected admin key,
# --nopassword mode uploads the bootstrap key, and both land under this name.
# Two hand-written copies of the string is exactly how the worker path and
# the bootstrap path would drift apart again.
sub admin_ssh_key_name { 'ocp-' . shift->name . '-admin' }

# The name this cluster's robo (automation) public key carries in a provider's
# key store, mirroring admin_ssh_key_name. Bootstrap uploads the robo public
# half beside the admin one so that every Hetzner machine trusts the key
# robocop holds -- otherwise a worker robocop provisions has only the admin key
# in authorized_keys and refuses the robo key, so its install never connects
# and the node goes Failed (k101, variant a). Only the PUBLIC half travels
# to the provider, and it sits behind the age layer alone, so no PIN2 is
# involved -- the age-encrypted robo tier ADR 0006/0027 deliberately keep.
#
# Lives here for the same reason as admin_ssh_key_name: OCP::Config is the one
# place that knows the cluster name, so the bootstrap path and the (later)
# worker path derive the identical string instead of drifting apart.
sub robo_ssh_key_name { 'ocp-' . shift->name . '-robo' }

sub kubernetes {
    my ($self) = @_;
    return $self->spec->{kubernetes} // {};
}

# The most control planes `nodes: N` stands for (k305). Every RKE2/K3s
# server is an etcd member, and etcd advises no more than seven: a write
# waits for a majority of them, so each member past that slows every write
# and buys a failure tolerance no one runs (etcd FAQ, "What is maximum
# cluster size?"; 1, 3, 5 and 7 are the sizes in use). It is also what keeps
# control_planes() from taking a nodes: of 10^12 as a repeat count. Since
# k315 it bounds the list form too.
#
# An even count (2, 4, 6) tolerates no more failures than one less does, but
# it works, so it is no refusal; and validate() returns errors only, with no
# channel for a warning. Left for a ticket (k315's notes), not invented here.
our $MAX_CONTROL_PLANE_NODES = 7;

sub control_planes {
    my ($self) = @_;
    my $raw = $self->spec->{control_planes};

    # Array form: one entry per control plane
    return $raw if ref $raw eq 'ARRAY';

    # Hash form: single CP, or `nodes: N` for N identical CPs
    if (ref $raw eq 'HASH') {
        my %cp = %$raw;
        my $count = delete $cp{nodes} // 1;

        # A nodes: that is no whole number, or more than the bound, stands
        # for one control plane, so its entry is still read once; validate()
        # refuses it (k296, k305). Taken as a repeat count, a list numifies
        # to its address and asks for some 10^14 copies, and 10^12 runs out
        # of memory just the same.
        $count = 1 unless _is_whole_number($count) && $count <= $MAX_CONTROL_PLANE_NODES;
        return [(%cp ? \%cp : {}) x $count];
    }

    return [{}];  # Default: 1 empty CP
}

sub workers { shift->spec->{workers} // [] }

sub ssh_config { shift->spec->{ssh} // {} }
sub single_node {
    my $self = shift;
    my $cps = $self->control_planes;
    my $workers = $self->workers;
    return (scalar(@$cps) <= 1 && scalar(@$workers) == 0);
}

sub distribution {
    my ($self) = @_;
    return $self->kubernetes->{dist} // 'rke2';
}

sub version {
    my $self = shift;
    my $k8s = $self->kubernetes;
    return $k8s->{version} // '';
}

# RKE2 keeps its registration endpoint on a supervisor port of its own,
# next to the apiserver on 6443. k3s serves both from 6443. An agent that
# is pointed at the wrong one never joins.
sub supervisor_port { shift->distribution eq 'k3s' ? 6443 : 9345 }

# The address workers join the control plane at: the public_ip ocp.yaml pins,
# else the host the provider advertised. The reconcile path has always read
# public_ip // host (cluster_status); bootstrap handed the advertised host on,
# which for the ssh provider is `host` -- so a CP with `host: cp.vm` and a
# public_ip had its first-apply workers join via a hostname they could not use,
# and its later ones via the IP (k185).
sub join_host {
    my ($self, $advertised) = @_;
    my $ip = ($self->control_planes->[0] // {})->{public_ip};
    return defined $ip && length $ip ? $ip : $advertised;
}

sub join_url {
    my ($self, $host) = @_;
    return sprintf 'https://%s:%d', $host, $self->supervisor_port;
}

sub api_url {
    my ($self, $host) = @_;
    return "https://$host:6443";
}

# Add-on flags (default: enabled, set to true to disable)
sub no_cert { shift->spec->{nocert} // 0 }

# robocop may be a scalar toggle (robocop: true) or a mapping that also
# carries security_level (robocop: { enabled: true, security_level: secret }).
#
#   scalar         → that boolean
#   mapping        → its `enabled` key when set, else on: writing a robocop
#                    mapping at all is an explicit opt-in (as gpu: is), and
#                    enabled:false is how you keep the mapping but turn it off
#   absent         → the hetzner auto-on rule
#
# Anything else is refused in validate()'s words (k315): read on, robocop: no
# was a string Perl calls true, and robocop: { enable: false } a mapping
# without enabled -- both turned robocop on. A croak rather than off, as
# gpu_config and robocop_security_level do: every reader of the switch asks
# this method (ocp apply, ocp keys secure, the health gate), and none of them
# may read the one ocp.yaml another way than validate() does -- not even in
# the safe direction, where robocop: yes would mean off.
sub robocop_enabled {
    my $self = shift;
    my $val = $self->spec->{robocop};

    my @errors = _robocop_errors($val);
    croak join '; ', @errors if @errors;

    if (ref $val eq 'HASH') {
        return $val->{enabled} ? 1 : 0 if defined $val->{enabled};
        return 1;
    }
    return $val ? 1 : 0 if defined $val;

    return 1 if $self->_any_hetzner_provider;
    return 0;
}

# The keys of the mapping form, as the robocop: line and an unknown key name them.
our @ROBOCOP_KEYS = qw( enabled security_level image );

# What is wrong with robocop: as a switch, one line each, or nothing (k305,
# k315): validate() lists the lines and robocop_enabled refuses on them, so
# the two cannot disagree. security_level and image have accessors and lines
# of their own.
sub _robocop_errors {
    my ($val) = @_;
    return () if !defined $val || _is_switch($val);
    return 'robocop: must be true, false or a mapping (' . join(', ', @ROBOCOP_KEYS) . '), not '
        . _shown_value($val) . _boolean_hint('robocop', $val)
        unless ref $val eq 'HASH';

    my $en = $val->{enabled};
    return (
        (defined $en && !_is_switch($en)
            ? 'robocop.enabled: must be true or false, not ' . _shown_value($en)
              . _boolean_hint('enabled', $en)
            : ()),
        _unknown_keys('robocop', $val, @ROBOCOP_KEYS),
    );
}

# A true or false as robocop: takes it (k315): a YAML boolean, or 1 or 0 --
# how a spec written from Perl spells one, and what robocop: 1 always meant.
# No other string: Perl calls 'no' true.
sub _is_switch {
    my ($value) = @_;
    return 1 if JSON::MaybeXS::is_bool($value);
    return defined $value && !ref $value && $value =~ /\A[01]\z/ ? 1 : 0;
}

# "; write KEY: false" for a string that spells a boolean in YAML 1.1's words
# -- no, off, n, a quoted or capitalised false -- which YAML::XS reads as the
# string it is; only a bare true and false are booleans. The gpu: false hint's
# twin: say what was meant where that is plain, and nothing where it is not.
sub _boolean_hint {
    my ($key, $value) = @_;
    return '' if ref $value || !defined $value;
    my $meant = $value =~ /\A(?:y|yes|true|on)\z/i  ? 'true'
              : $value =~ /\A(?:n|no|false|off)\z/i ? 'false'
              :                                        undef;
    return defined $meant ? "; write $key: $meant" : '';
}

=method robocop_arch_warning

Returns a C<[WARN]> line when robocop is enabled but no control plane can run
its image, undef otherwise (k197). The robocop image is amd64 only; when every
control plane is a Hetzner CAX (ARM) server the pod stays Pending and no
worker joins through robocop. A warning, never a refusal: a mixed cluster, an
amd64 control plane or C<robocop: false> say nothing.

=cut

sub robocop_arch_warning {
    my ($self) = @_;
    return unless $self->robocop_enabled;

    my @cps = @{ $self->control_planes };
    return unless @cps;
    for my $cp (@cps) {
        return unless ref $cp eq 'HASH'
            && ($cp->{provider} // '') eq 'hetzner'
            && ($cp->{server_type} // '') =~ /^cax/i;
    }

    return '[WARN] robocop image is amd64 only, but every control plane is an ARM server (cax*): '
        . 'the robocop pod stays Pending and worker joins through robocop do not run. '
        . 'Set `robocop: false` or add an amd64 control plane (cpx/cx).';
}

# How the private robo (automation) SSH key reaches the cluster (k129),
# read from `robocop.security_level` (the mapping form of the robocop key):
#
#   secret           `ocp deploy-robocop` decrypts the robo key with PIN1 and
#                    writes it into a K8s Secret; a pod restart self-heals.
#   secret_approved  as secret, but writing the Secret is gated behind PIN2.
#   inject           in-memory, never persisted (k2): the Secret carries only
#                    the public half; `ocp inject-key` (PIN2) hands the private
#                    key to the running pod over a port-forward, and a pod
#                    restart needs a new injection.
#
# Default secret: an automation controller must survive pod restarts
# unattended, so the key has to rest in the cluster.
our @ROBOCOP_SECURITY_LEVELS = qw( secret secret_approved inject );

# Croaks on an unknown value — the accessor is the point of use (DeployRobocop),
# and a typo there must not silently fall back to a level the operator did not
# ask for, exactly as gpu_driver refuses an unknown driver. validate() carries
# the report-only twin for `ocp apply`.
sub robocop_security_level {
    my ($self) = @_;

    my $level = $self->_raw_robocop_security_level // 'secret';

    croak "robocop.security_level must be "
        . OCP::Choices::or_list(@ROBOCOP_SECURITY_LEVELS)
        . ", not " . _shown_value($level)
        unless _is_choice($level, @ROBOCOP_SECURITY_LEVELS);

    return $level;
}

sub _raw_robocop_security_level {
    my ($self) = @_;
    my $val = $self->spec->{robocop};
    return ref $val eq 'HASH' ? $val->{security_level} : undef;
}

# robocop.image (k227): the image the robocop Deployment runs, in the mapping
# form of the robocop key. Undef when not set -- OCP::Robocop::Manifest then
# names the CLI's own version. `ocp apply` writes the Deployment on every run,
# so this is where a non-default image has to live to survive it;
# `ocp deploy-image` alone is a one-off override.
sub robocop_image {
    my ($self) = @_;
    my $val = $self->spec->{robocop};
    return undef unless ref $val eq 'HASH' && defined $val->{image};
    my $err = _image_ref_error($val->{image});
    croak "robocop.image: $err" if $err;
    return $val->{image};
}

# A reference as docker writes it: repo:tag or repo@sha256:<64 hex>. No
# implicit tag -- the same rule `ocp deploy-image` has.
sub _image_ref_error {
    my ($ref) = @_;
    return "must be an image reference like raudssus/ocp:1.2.3, not "
        . _shown_value($ref) if ref $ref;
    return "must not be empty" unless length($ref // '');
    return "must not contain whitespace ('$ref')" if $ref =~ /\s/;
    return undef if $ref =~ m{\A[^@\s]+\@sha256:[0-9a-f]{64}\z};
    return undef if $ref =~ m{\A(?:[^/\s]+/)*[^/:\s@]+:[^/:\s@]+\z};
    return "needs a tag or a digest, like raudssus/ocp:1.2.3 or repo\@sha256:<64 hex> ('$ref')";
}

sub _any_hetzner_provider {
    my $self = shift;
    for my $cp (@{$self->control_planes}) {
        return 1 if ($cp->{provider} // '') eq 'hetzner';
    }
    for my $pool (@{$self->workers}) {
        return 1 if ($pool->{provider} // '') eq 'hetzner';
    }
    return 0;
}

# Opt-in flags (default: disabled, set to true to enable)
# lbipam is opt-in because its default behaviour (pool = host public IP
# + L2 announcement) makes Cilium hijack ARP for the host IP, which breaks
# host-bound ports like sshd and kube-apiserver. Enable only when you have
# a proper design for exposing LoadBalancer services.
sub lbipam { shift->spec->{lbipam} // 0 }

# Registry configuration
sub registry_config      { shift->spec->{registry} // {} }
sub registry_cache       { shift->registry_config->{cache} // '' }
sub registry_upstream    { shift->registry_config->{upstream} // '' }
sub registry_name        { shift->registry_config->{name} // 'ocp.internal' }
sub has_external_cache   { shift->registry_cache ne '' }
sub has_external_upstream { shift->registry_upstream ne '' }

# Network configuration — the Cilium LB-IPAM pool and L2 announcement policy
# (k127). All optional; a cluster that sets nothing keeps the historical
# single-node behaviour (pool = node IP /32, announce on every node).
#
#   network:
#     lb_pool:
#       start: 10.230.30.240      # a range, as the citiai cluster uses,
#       stop:  10.230.30.249      # ... or:
#       cidr:  10.230.30.240/28   # a block (mutually exclusive with start/stop)
#     l2:
#       node_selector:            # limit announcement to labelled nodes instead
#         ai.citilan.de/l2-announce: "true"   # of trusting interface names
#       interfaces:               # override the built-in (anchored) regexes
#         - "^eth[0-9]+$"
sub network_config { shift->spec->{network} // {} }

# The keys the accessors here read under network:, and so the keys validate()
# takes there (k292): anything else is a typo whose default stays in force.
our @NETWORK_KEYS = qw( pod_cidr lb_pool l2 );
our @LB_POOL_KEYS = qw( cidr start stop );
our @L2_KEYS      = qw( node_selector interfaces );

sub lb_pool_config { shift->network_config->{lb_pool} // {} }

# The CiliumLoadBalancerIPPool blocks list, or undef when no pool is
# configured — the caller then falls back to the node IP, but only on a
# single-node cluster.
sub lb_pool_blocks {
    my $self = shift;
    my $p = $self->lb_pool_config;
    return undef unless %$p;
    return [{ cidr => $p->{cidr} }] if defined $p->{cidr};
    return [{ start => $p->{start}, stop => $p->{stop} }];
}

# The pod network (k182): the cluster-cidr RKE2/k3s are installed with and
# the cluster pool Cilium's IPAM hands out, which must agree. The default is
# the built-in cluster-cidr of both distributions; Cilium's own default,
# 10.0.0.0/8, overlaps most host LANs and is what an RKE2 cluster ran before.
# Only read at install time: a running cluster keeps its pool, and OCP::Drift
# reports a difference instead of moving it.
#
#   network:
#     pod_cidr: 10.42.0.0/16
our $DEFAULT_POD_CIDR = '10.42.0.0/16';

# The service network OCP never changes: RKE2's and k3s' built-in
# service-cidr. The pod CIDR must stay clear of it.
our $SERVICE_CIDR = '10.43.0.0/16';

sub pod_cidr        { shift->network_config->{pod_cidr} // $DEFAULT_POD_CIDR }
sub pod_cidr_is_set { defined shift->network_config->{pod_cidr} }

sub l2_config        { shift->network_config->{l2} // {} }
sub l2_node_selector { shift->l2_config->{node_selector} // {} }

# The interface-name regexes for CiliumL2AnnouncementPolicy, when
# network.l2.interfaces sets none. Cilium compiles them as Go (RE2) regexes,
# so there is no lookahead to say "but not that one" -- the exclusion has to
# be spelled into the character class.
#
# The en* pattern leaves out every predictable name that carries an "n": in
# systemd's naming scheme the only "n" after the "en" prefix is the
# n<phys_port_name> suffix, which switchdev-capable NICs (Mellanox/NVIDIA
# ConnectX and the like) get -- the QSFP/RoCE fabric between brain and cortex
# is enp1s0f0np0. Announcing ARP for LoadBalancer IPs there answers on a
# fabric no client sits on (k210). Capital P (PCI domain, enP7s7 on a GB10)
# and a VLAN suffix (enP7s7.30) are allowed: that is the LAN port of the same
# machine. A fabric NIC that comes without the suffix still matches; set
# network.l2.interfaces or l2.node_selector on such a cluster.
our $DEFAULT_L2_INTERFACES = [ '^eth[0-9]+(\\.[0-9]+)?$', '^en[a-mo-zP0-9]+(\\.[0-9]+)?$' ];

sub l2_interfaces {
    my $self = shift;
    my $i = $self->l2_config->{interfaces};
    return $i if ref $i eq 'ARRAY' && @$i;
    return [ @$DEFAULT_L2_INTERFACES ];
}

# Cilium's own Helm values (k210), for what OCP has no key of its own for --
# above all `devices`, the interfaces Cilium attaches its datapath to, which
# Cilium otherwise picks itself and which then include a fabric NIC.
#
#   cilium:
#     devices: [ "enP7s7.30" ]      # Helm `devices`
#     helm_values:                  # anything else, deep-merged over what
#       bpf: { masquerade: true }   # Rex::Rancher::Cilium generates
#
# devices is the short form of helm_values.devices; setting both is an error.
# The values travel to install_cilium and, so an upgrade keeps them, to every
# upgrade_cilium. OCP's own choices (ipam, gatewayAPI, k8sServiceHost) stay
# OCP's: a contradicting ipam.mode dies in Rex::Rancher::Cilium before the
# host is touched.
sub cilium_config { shift->spec->{cilium} // {} }

# The merged Helm values, {} when ocp.yaml sets none.
sub cilium_helm_values {
    my $self = shift;
    my $c = $self->cilium_config;
    return {} unless ref $c eq 'HASH';
    my %values = ref $c->{helm_values} eq 'HASH' ? %{ $c->{helm_values} } : ();
    $values{devices} = [ @{ $c->{devices} } ] if ref $c->{devices} eq 'ARRAY';
    return \%values;
}

# SSL configuration (for cert-manager)
sub ssl_config { shift->spec->{ssl} // {} }
sub ssl_email { shift->spec->{ssl}{email} // '' }

# System configuration (hostname, timezone, locale, NTP)
sub system_config { shift->spec->{system} // {} }
sub timezone      { shift->system_config->{timezone} // 'UTC' }
sub locale        { shift->system_config->{locale} // 'en_US.UTF-8' }
sub ntp_enabled   { shift->system_config->{ntp} // 1 }

# GPU configuration
#
# Three independent facts, each one switch:
#
#   enabled  Whether OCP touches the GPU at all. Off means Rex skips hardware
#            detection on every node and no GPU Operator is deployed.
#   driver   Who installs the kernel driver. 'host' lets Rex do it and pins
#            the operator's driver DaemonSet off; 'operator' is the reverse —
#            Rex leaves the host alone entirely, because the operator that
#            brings the driver brings the container toolkit with it.
#   toolkit  Whether the operator installs the NVIDIA container toolkit. Vendor
#            images ship it: on a DGX the runtime is in /usr/bin before OCP
#            arrives, and NVIDIA's guidance for those hosts is
#            toolkit.enabled=false alongside driver.enabled=false, so that the
#            toolkit DaemonSet does not rewrite a containerd config that
#            already works.
#
# A gpu: that is no mapping is refused here in validate()'s words (k296):
# read on, every accessor below died inside Perl ("Can't use string as a
# HASH ref"), and taken for absent, gpu: false would mean enabled.
sub gpu_config {
    my ($self) = @_;
    my $gpu = $self->spec->{gpu} // {};
    my $err = _gpu_shape_error($gpu);
    croak "gpu $err" if defined $err;
    return $gpu;
}

# What is wrong with the value of gpu:, or undef. robocop: takes a boolean,
# so gpu: false is the likely slip, and the line says what was meant.
sub _gpu_shape_error {
    my ($gpu) = @_;
    return undef if !defined $gpu || ref $gpu eq 'HASH';
    return 'must be a mapping, not ' . _shown_value($gpu)
        . (JSON::MaybeXS::is_bool($gpu)
            ? '; write gpu: { enabled: ' . ($gpu ? 'true' : 'false') . ' }' : '');
}

# Normalised to 0/1: these travel to the Rexfile as JSON and into a
# ClusterPolicy as a YAML boolean, and YAML::XS hands back JSON::PP::Boolean
# objects that neither destination should have to know about.
sub gpu_enabled { my $v = shift->gpu_config->{enabled}; return 1 unless defined $v; return $v ? 1 : 0 }
sub gpu_toolkit { my $v = shift->gpu_config->{toolkit}; return 1 unless defined $v; return $v ? 1 : 0 }

our @GPU_DRIVERS = qw( host operator );

sub gpu_driver {
    my ($self) = @_;
    my $driver = $self->gpu_config->{driver} // 'host';

    # A typo here would silently fall back to 'host' and leave the operator's
    # driver DaemonSet disabled on a cluster that was configured for it.
    croak "gpu.driver must be 'host' or 'operator', not " . _shown_value($driver)
        unless _is_choice($driver, @GPU_DRIVERS);

    return $driver;
}

# gpu.amd (k250): the Kubernetes side of an AMD GPU node. gpu.driver stays
# vendor-neutral (who installs the kernel driver); everything here is about
# what the cluster runs on AMD nodes once the driver is there. Absent means
# the defaults.
#
#   allocation       how an AMD node's GPUs are handed out by default:
#                    device-plugin (amd.com/gpu), dra (ResourceClaims against
#                    DeviceClass gpu.amd.com) or none. A node overrides it with
#                    the $AMD_GPU_ALLOCATION_LABEL label, so one cluster offers
#                    both paths; which workload gets which is not OCP's call.
#   resource_naming  single or mixed, handed to the device plugin as is.
#   labeller         AMD's node labeller (amd.com/gpu.* labels) on AMD nodes.
#   metrics          AMD's device-metrics-exporter. Off by default: upstream
#                    serves Instinct and Radeon AI only, not Ryzen APUs.
#   integrated       set up integrated AMD GPUs (the iGPU of a Ryzen CPU or
#                    APU) on every node. Off by default: detection runs on
#                    every node, control planes included, and a Hetzner AX42
#                    has a Phoenix iGPU nobody asked OCP to drive. A node
#                    joined with `ocp node add --gpu` opts in on its own
#                    (OCP::Node ORs the two).
our @GPU_AMD_ALLOCATIONS     = qw( device-plugin dra none );
our @GPU_AMD_RESOURCE_NAMING = qw( single mixed );
our @GPU_AMD_KEYS            = qw( allocation resource_naming labeller metrics integrated );

# The node labels that go with gpu.amd, named once for every reader and writer
# (the stack's affinity terms, ocp status, the Rexfile through its params).
#
#   $AMD_GPU_PRESENT_LABEL     'true' on a node where the host step accepted at
#                              least one AMD GPU. The cluster stack selects on
#                              it rather than on NFD's pci-*_1002 labels, which
#                              cannot tell an iGPU the integrated gate skipped
#                              from one OCP set up.
#   $AMD_GPU_ALLOCATION_LABEL  per-node override of gpu.amd.allocation, same
#                              values; set with `ocp node add --label` or by
#                              the GPU management system.
#   $AMD_GPU_GFX_TARGET_LABEL  the node's gfx target (gfx1151), which nothing
#                              upstream publishes. A node with more than one
#                              target gets one label per target instead, this
#                              key plus ".<gfx>", valued with the count.
our $AMD_GPU_PRESENT_LABEL    = 'ocp.internal/amd-gpu.present';
our $AMD_GPU_ALLOCATION_LABEL = 'ocp.internal/amd-gpu.allocation';
our $AMD_GPU_GFX_TARGET_LABEL = 'ocp.internal/amd-gpu.gfx-target';

# The names the AMD stack shows in the cluster, named once for everything
# that reads them back (ocp apply's readiness wait, ocp status). The stack
# itself is written by Rex::Rancher::K8s.
#
#   $AMD_GPU_RESOURCE         the device plugin's extended resource.
#   $AMD_GPU_RESOURCE_PREFIX  where resource_naming: mixed puts the
#                             partitioned resources (amd.com/<partition>).
#   $AMD_GPU_DRA_DRIVER       the DRA driver's name on its ResourceSlices,
#                             and its DeviceClass.
our $AMD_GPU_RESOURCE        = 'amd.com/gpu';
our $AMD_GPU_RESOURCE_PREFIX = 'amd.com/';
our $AMD_GPU_DRA_DRIVER      = 'gpu.amd.com';

sub gpu_amd_config {
    my ($self) = @_;
    my $amd = $self->gpu_config->{amd};
    return {} unless defined $amd;
    croak 'gpu.amd must be a mapping ('.OCP::Choices::or_list(@GPU_AMD_KEYS).')'
        unless ref $amd eq 'HASH';
    return $amd;
}

# Croak on an unknown value, as gpu_driver does: a typo would otherwise mean
# the default in silence, and the wrong allocation path on every AMD node.
sub gpu_amd_allocation {
    my ($self) = @_;
    return $self->_gpu_amd_choice('allocation', 'device-plugin', @GPU_AMD_ALLOCATIONS);
}

sub gpu_amd_resource_naming {
    my ($self) = @_;
    return $self->_gpu_amd_choice('resource_naming', 'single', @GPU_AMD_RESOURCE_NAMING);
}

# 0/1 for the same reason gpu_toolkit is.
sub gpu_amd_labeller   { my $v = shift->gpu_amd_config->{labeller};   return 1 unless defined $v; return $v ? 1 : 0 }
sub gpu_amd_metrics    { my $v = shift->gpu_amd_config->{metrics};    return 0 unless defined $v; return $v ? 1 : 0 }
sub gpu_amd_integrated { my $v = shift->gpu_amd_config->{integrated}; return 0 unless defined $v; return $v ? 1 : 0 }

sub _gpu_amd_choice {
    my ($self, $key, $default, @choices) = @_;
    my $value = $self->gpu_amd_config->{$key} // $default;
    croak "gpu.amd.$key must be ".OCP::Choices::or_list(@choices)
        .", not "._shown_value($value)
        unless _is_choice($value, @choices);
    return $value;
}

# Whether $value is one of @choices. A reference never is: a list, a mapping,
# or a YAML boolean, which is a JSON::PP::Boolean. Until OCP.pm fixed the eq
# overload Cpanel::JSON::XS gives that class (k314), `'secret' eq $true` was
# true for any string Perl calls true, and this guard alone kept `true` from
# being every choice (k305). It stays, so the answer does not hang on that
# overload.
sub _is_choice {
    my ($value, @choices) = @_;
    return 0 if ref $value;
    return grep({ $_ eq $value } @choices) ? 1 : 0;
}

# 0, 1, 2, ... as YAML gives them: a plain scalar, no sign, no fraction. A
# boolean is a reference and no number.
sub _is_whole_number {
    my ($value) = @_;
    return defined $value && !ref $value && $value =~ /\A[0-9]+\z/ ? 1 : 0;
}

# A value as an error message quotes it. YAML hands `false` back as a boolean
# object, which would otherwise read as '0'.
sub _shown_value {
    my ($value) = @_;
    return !defined $value                ? 'null'
         : JSON::MaybeXS::is_bool($value) ? ($value ? 'true' : 'false')
         : ref $value eq 'HASH'           ? 'a mapping'
         : ref $value eq 'ARRAY'          ? 'a list'
         :                                  "'$value'";
}

#
# Status file (.ocp/status.yaml)
#

sub status_file {
    my ($self) = @_;
    return $self->project_dir->child('.ocp', 'status.yaml')->stringify;
}

# Manifest hashes of the components last rolled out (.ocp/deployed.yaml).
# Cluster state, kept locally: it describes THIS cluster and nothing else, so
# it dies with the cluster (ADR 0004). The path lives here because two
# commands need it — apply writes it, destroy removes it — and a second
# spelling of it is how it survived a destroy in the first place: the next
# apply then compared against the state of a cluster that no longer existed
# and skipped components that were gone.
sub deployed_file {
    my ($self) = @_;
    return $self->project_dir->child('.ocp', 'deployed.yaml')->stringify;
}

# Runtime status (.ocp/status.yaml). Loaded once and kept, so callers can
# mutate it and persist with save_status.
has status => (
    is      => 'lazy',
    builder => '_load_status',
);

sub _load_status {
    my ($self) = @_;
    my $file = $self->status_file;
    return {} unless -f $file;
    return $self->ocp->load_file($file) // {};
}

sub nodes_status {
    my ($self) = @_;
    return $self->status->{nodes} //= [];
}

# The control plane we can reach: the recorded node status if we have one,
# otherwise whatever the spec pins.
sub cluster_status {
    my ($self) = @_;

    for my $node (@{ $self->nodes_status }) {
        next if ($node->{role} // 'control-plane') =~ /worker/;
        my $ip = $node->{public_ip};
        return $node if defined $ip && length $ip && $ip ne '-';
    }

    my $cp = $self->control_planes->[0] // {};
    my $ip = $cp->{public_ip} // $cp->{host};

    # A local control plane resolves its own address rather than the operator
    # pinning it. The machine ocp runs on IS the control plane, so its provider
    # reports the routable IP bootstrap already advertised in the tls-san, the
    # kubeconfig server endpoint and the CP OCPNode (advertised_host, k138) --
    # falling back to 127.0.0.1 when no route can be found. Without this a local
    # cluster returned no address here, and every reader -- the reconcile-path
    # drift remedies, `ocp node add`'s worker join URL, `ocp update`, `ocp
    # deploy-robocop` -- reported "no control plane address known" unless
    # control_planes.public_ip was set by hand (k152). ssh pins host and hetzner
    # pins public_ip in the spec, so neither ever reaches this branch.
    if (!(defined $ip && length $ip) && ($cp->{provider} // '') eq 'local') {
        $ip = OCP::Provider->for_spec($cp)->advertised_host;
    }

    return {} unless defined $ip && length $ip;
    return { name => $cp->{name} // 'cp-1', public_ip => $ip };
}

sub set_status {
    my ($self, $key, $value) = @_;
    $self->status->{$key} = $value;
    return $value;
}

sub save_status {
    my ($self) = @_;
    return $self->_save_status($self->status);
}

#
# Cluster existence check (BITSOW!)
#

sub cluster_exists {
    my ($self) = @_;
    return -f $self->project_dir->child('kubeconfig.yaml');
}

#
# SSH key helpers
#

sub ssh_private_key_path {
    my ($self) = @_;
    my $key_path = $self->ssh_config->{private_key} // '.ocp/id_ed25519';
    return $self->_resolve_path($key_path);
}

sub ssh_public_key_path {
    my ($self) = @_;
    my $key_path = $self->ssh_config->{public_key} // '.ocp/id_ed25519.pub';
    return $self->_resolve_path($key_path);
}

sub ssh_public_key {
    my ($self) = @_;
    my $path = $self->ssh_public_key_path;
    return path($path)->slurp if -f $path;
    return undef;
}

sub _resolve_path {
    my ($self, $p) = @_;
    $p =~ s/^~/$ENV{HOME}/;
    # Relative paths are relative to project dir
    return $p if $p =~ m{^/};
    return $self->project_dir->child($p)->stringify;
}

#
# Validation
#

sub validate {
    my ($self) = @_;
    my @errors;

    # A name that is a list or mapping passed (k305), and every key name the
    # cluster derives from it said ARRAY(0x...).
    if (ref $self->spec->{name}) {
        push @errors, "name: must be a string (the cluster's name), not "
            . _shown_value($self->spec->{name});
    }
    else {
        push @errors, "name is required" unless $self->name && $self->name =~ /\S/;
    }

    my $cps = $self->control_planes;

    # The shape first (k296). A control_planes that is neither form would be
    # read as one hetzner control plane with nothing set, and refused for
    # what nobody wrote; a list entry that is no mapping died inside Perl.
    my $raw_cps = $self->spec->{control_planes};
    if (defined $raw_cps && ref $raw_cps ne 'HASH' && ref $raw_cps ne 'ARRAY') {
        push @errors, "control_planes: must be a mapping (one control plane, or nodes: N of them) "
            . "or a list of mappings, not " . _shown_value($raw_cps);
        $cps = [];
    }
    push @errors, "control_planes: must list at least one control plane, not an empty list"
        if ref $raw_cps eq 'ARRAY' && !@$raw_cps;
    my $etcd_bound = "every control plane is an etcd member, and etcd advises no more "
        . "than $MAX_CONTROL_PLANE_NODES";
    if (ref $raw_cps eq 'HASH' && defined(my $nodes = $raw_cps->{nodes})) {
        my $whole = _is_whole_number($nodes);
        push @errors, "control_planes.nodes: must be a whole number from 1 to "
            . "$MAX_CONTROL_PLANE_NODES, not " . _shown_value($nodes)
            . ($whole && $nodes > $MAX_CONTROL_PLANE_NODES ? "; $etcd_bound" : '')
            unless $whole && $nodes >= 1 && $nodes <= $MAX_CONTROL_PLANE_NODES;
    }
    # The list form holds no more than nodes: may stand for (k315): the bound
    # is etcd's, whichever way the control planes are written. Its entries are
    # still checked below.
    push @errors, "control_planes: must list at most $MAX_CONTROL_PLANE_NODES control planes, not "
        . scalar(@$raw_cps) . "; $etcd_bound"
        if ref $raw_cps eq 'ARRAY' && @$raw_cps > $MAX_CONTROL_PLANE_NODES;

    # The mapping form with `nodes: N` is N copies of one entry (see
    # control_planes), so a node_ip there would be every one of them's (k254).
    # Refused once, not per copy; its syntax is not worth a line then.
    my $shared  = $self->_control_planes_shared;
    push @errors, "control_planes: node_ip with nodes: " . scalar(@$cps)
        . " would give all " . scalar(@$cps) . " control planes the same address; "
        . "list them one by one (control_planes: as a list), each with its own node_ip"
        if $shared && defined $raw_cps->{node_ip};

    my %node_ip_at;    # address (as an IP) => the control plane that has it
    for my $i (0 .. $#$cps) {
        my $cp = $cps->[$i];
        my $idx = $i + 1;
        unless (ref $cp eq 'HASH') {
            push @errors, "control_planes[$idx]: must be a mapping (one control plane), not "
                . _shown_value($cp);
            next;
        }
        my $prov = $cp->{provider} // 'hetzner';

        # The wording this rejection has always had; the SET behind it now
        # comes from the factory that builds those providers instead of being
        # spelled out a second time here (k103). Same three words, one
        # source -- a fourth provider type appears in this message the moment
        # OCP::Provider can construct it.
        # !ref: a boolean is no provider, whatever eq on it says; see
        # _is_choice (k305, k314).
        unless (!ref $prov && OCP::Provider->known_type($prov)) {
            push @errors, "control_planes[$idx]: invalid provider " . _shown_value($prov) . " (must be "
                . OCP::Choices::or_list(OCP::Provider->types) . ")";
        }

        # host and server_type (k315): one name each, which the provider is
        # handed and the OCPNode's spec carries as is. A list passed for being
        # true, and named the machine ARRAY(0x...). One line for the shape,
        # not a "required" beside it.
        my %malformed;
        for my $s ([ host => 'a host name or IP address' ],
                   [ server_type => 'a Hetzner server type like cx32' ]) {
            my ($key, $what) = @$s;
            my $err = _not_a_string($cp->{$key}, $what) // next;
            push @errors, "control_planes[$idx].$key: $err";
            $malformed{$key} = 1;
        }

        if ($prov eq 'hetzner') {
            push @errors, "control_planes[$idx]: server_type required for hetzner"
                unless $cp->{server_type} || $malformed{server_type};
            push @errors, "control_planes[$idx]: location required for hetzner"
                unless $cp->{location};
        }

        if ($prov eq 'ssh') {
            push @errors, "control_planes[$idx]: host required for ssh"
                unless $cp->{host} || $malformed{host};
        }

        # node_ip (k254): the address this control plane registers by, in the
        # words `ocp node add --node_ip` and an OCPNode's spec.nodeIP are
        # refused with.
        if (!$shared && defined $cp->{node_ip}) {
            my $err = OCP::Choices::node_ip_error($cp->{node_ip});
            push @errors, "control_planes[$idx].node_ip: $err" if defined $err;
            push @errors, $self->_node_ip_clashes($cp->{node_ip}, $idx, \%node_ip_at)
                unless defined $err;
        }
    }

    push @errors, $self->_validate_network;
    push @errors, $self->_validate_cilium;
    my $gpu_err = _gpu_shape_error($self->spec->{gpu});
    push @errors, "gpu: $gpu_err" if defined $gpu_err;
    push @errors, $self->_validate_gpu_driver;
    push @errors, $self->_validate_gpu_amd;
    my $net = ref $self->spec->{network} eq 'HASH' ? $self->spec->{network} : {};
    push @errors, $self->_validate_pod_cidr($net);
    push @errors, $self->_validate_service_cidr($net);

    # robocop as a list, a string, a robocop.enabled that is neither true nor
    # false, or a key of the mapping that is none of its three: each read as
    # true and turned robocop on (k305, k315). The lines are robocop_enabled's
    # refusal too.
    push @errors, _robocop_errors($self->spec->{robocop});

    # robocop.security_level, report-only (k129). The accessor croaks; here
    # we collect one line so `ocp apply` lists it with every other config error.
    my $rl = $self->_raw_robocop_security_level;
    if (defined $rl && !_is_choice($rl, @ROBOCOP_SECURITY_LEVELS)) {
        push @errors, "robocop.security_level: invalid value " . _shown_value($rl) . " (must be "
            . OCP::Choices::or_list(@ROBOCOP_SECURITY_LEVELS) . ")";
    }

    # robocop.image, report-only (k227), same reason as security_level above.
    if (ref $self->spec->{robocop} eq 'HASH' && defined $self->spec->{robocop}{image}) {
        my $ie = _image_ref_error($self->spec->{robocop}{image});
        push @errors, "robocop.image: $ie" if $ie;
    }

    # A workers that is no list, or an entry that is no mapping, died inside
    # Perl (k296).
    my $workers = $self->spec->{workers} // [];
    if (ref $workers ne 'ARRAY') {
        push @errors, "workers: must be a list of worker pools, not " . _shown_value($workers);
        $workers = [];
    }
    my $pool_n = 0;
    for my $w (@$workers) {
        $pool_n++;
        unless (ref $w eq 'HASH') {
            push @errors, "workers[$pool_n]: must be a mapping (a worker pool), not " . _shown_value($w);
            next;
        }
        if (ref $w->{name}) {
            push @errors, "workers[$pool_n].name: must be a string (the pool's name), not "
                . _shown_value($w->{name});
        }
        else {
            push @errors, "worker pool: name required" unless $w->{name};
        }
        my $where = $self->_pool_where($w, $pool_n);
        my $wprov = $w->{provider} // '';
        if ($wprov eq '') {
            push @errors, "$where: provider required";
        } elsif (ref $wprov || !OCP::Provider->known_type($wprov)) {
            # Same set, same source as the control-plane check above --
            # spelling the regex here again is what k103 deleted for
            # the control planes and what k110 made stale (k115).
            push @errors, "$where: invalid provider " . _shown_value($wprov) . " (must be "
                . OCP::Choices::or_list(OCP::Provider->types) . ")";
        }

        # host and nodes (k315), see _pool_nodes_errors. Which nodes: a pool
        # takes hangs on its provider, so only a known one is asked.
        if (defined(my $err = _not_a_string($w->{host}, 'a host name or IP address'))) {
            push @errors, "$where: host $err";
        }
        push @errors, $self->_pool_nodes_errors($w, $where)
            if !ref $wprov && $wprov ne '' && OCP::Provider->known_type($wprov);

        # labels / taints (k211): what the pool's OCPNodes carry.
        push @errors, OCP::NodeMeta->label_errors("$where: labels", $w->{labels})
            if defined $w->{labels};
        if (defined(my $taints = $w->{taints})) {
            if (ref $taints ne 'ARRAY') {
                push @errors, "$where: taints must be a list like [ \"key=value:NoSchedule\" ]";
            }
            else {
                for my $t (@$taints) {
                    my $err = OCP::NodeMeta->taint_error($t);
                    push @errors, "$where: $err" if defined $err;
                }
            }
        }

        # node_ip (k254) is one machine's address, so a pool takes none; nor
        # does an entry of its nodes list, which apply does not read it from.
        # Refused rather than ignored: ignored, the node would join on its
        # default route's address, which is what node_ip is there to prevent.
        my $per_node = 'set it per node: ocp node add NAME --node_ip ADDRESS, '
            . 'or spec.nodeIP on its OCPNode';
        push @errors, "$where: node_ip cannot be set on a pool, one address cannot be "
            . "every machine's; $per_node"
            if defined $w->{node_ip};
        if (ref $w->{nodes} eq 'ARRAY') {
            for my $n (0 .. $#{ $w->{nodes} }) {
                my $entry = $w->{nodes}[$n];
                push @errors, "$where: nodes[" . ($n + 1) . "].node_ip is not read from "
                    . "a pool's nodes; $per_node"
                    if ref $entry eq 'HASH' && defined $entry->{node_ip};
            }
        }
    }

    return @errors;
}

# The mapping form with nodes: N > 1, one entry standing for N control planes
# (see control_planes). A node_ip there is refused once (k254) and counted
# for nothing else.
sub _control_planes_shared {
    my ($self) = @_;
    return ref $self->spec->{control_planes} eq 'HASH' && @{ $self->control_planes } > 1 ? 1 : 0;
}

# How an error line names worker pool $n (1-based): by its name, or by its
# place when it has none a line can quote, as a control plane is named
# (k305) -- not "worker pool 'ARRAY(0x...)'", not "worker pool ''".
sub _pool_where {
    my ($self, $pool, $n) = @_;
    my $name = $pool->{name};
    return defined $name && !ref $name && length $name ? "worker pool '$name'" : "workers[$n]";
}

# A pool's nodes: as worker_ocpnodes (OCP::Cmd::Apply::CR) reads it (k315),
# one line per problem. An ssh pool names its machines -- host: for one, or
# nodes: a list of hosts, each a host name or address or a mapping with host
# -- and every other provider counts them, nodes: N. Counted, a list
# numified to its address and ran out of memory building OCPNodes; named, a
# boolean died inside Perl ("Not a HASH reference"), and a count named no
# machine at all. Only for a pool whose provider is known.
sub _pool_nodes_errors {
    my ($self, $pool, $where) = @_;
    my $nodes = $pool->{nodes};
    return () unless defined $nodes;

    if ($pool->{provider} ne 'ssh') {
        return () if _is_whole_number($nodes);
        return "$where: nodes must be a whole number (how many machines the pool has), not "
            . _shown_value($nodes);
    }

    return "$where: nodes must be a list of hosts for an ssh pool (each a host name or IP "
        . "address, or a mapping with host), not " . _shown_value($nodes)
        unless ref $nodes eq 'ARRAY';

    my @errors;
    for my $n (1 .. @$nodes) {
        my $entry = $nodes->[$n - 1];
        if (ref $entry eq 'HASH') {
            my $host = $entry->{host};
            if (defined(my $err = _not_a_string($host, 'a host name or IP address'))) {
                push @errors, "$where: nodes[$n].host $err";
            }
            elsif (!length($host // '')) {
                push @errors, "$where: nodes[$n] needs a host";
            }
        }
        elsif (ref $entry || !length($entry // '')) {
            push @errors, "$where: nodes[$n] must be a host name or IP address, or a mapping "
                . "with host, not " . _shown_value($entry);
        }
    }
    return @errors;
}

# "must be a string (WHAT), not a list" for a list, a mapping or a boolean,
# else undef (k315): host and server_type are one name each.
sub _not_a_string {
    my ($value, $what) = @_;
    return undef unless ref $value;
    return "must be a string ($what), not " . _shown_value($value);
}

# Two control planes with one node-ip register at one address (k254), as the
# mapping form with nodes: N would. Compared address by address and as IPs,
# so '10.0.0.1,fd00::1' clashes with '10.0.0.1', and 'FD00::1' is 'fd00::1'.
# $seen maps each address to the first control plane that has it; one line
# per earlier control plane this one shares an address with.
sub _node_ip_clashes {
    my ($self, $node_ip, $idx, $seen) = @_;
    my %with;
    for my $part (split /,/, $node_ip) {
        my $key = $self->_node_ip_key($part);
        if (defined(my $other = $seen->{$key})) { push @{ $with{$other} }, $part }
        else                                    { $seen->{$key} = $idx }
    }
    return map {
        "control_planes[$idx].node_ip: " . join(' and ', @{ $with{$_} })
            . (@{ $with{$_} } > 1 ? ' are' : ' is')
            . " control_planes[$_].node_ip too; two control planes cannot register at one address"
    } sort { $a <=> $b } keys %with;
}

# An IP in one spelling: the packed address, as OCP::Node->node_ip_mismatch
# compares them. Only for values node_ip_error passed, so always an IP.
sub _node_ip_key {
    my ($self, $ip) = @_;
    for my $af (Socket::AF_INET(), Socket::AF_INET6()) {
        my $packed = Socket::inet_pton($af, $ip);
        return $af . ':' . $packed if defined $packed;
    }
    return $ip;
}

# network.lb_pool / network.l2 validation (k127). Report-only: returns a
# list of human-readable errors, same contract as validate() itself.
sub _validate_network {
    my ($self) = @_;
    my $net = $self->spec->{network};
    return () unless defined $net;
    return ("network: must be a mapping") unless ref $net eq 'HASH';

    my @errors = _unknown_keys('network', $net, @NETWORK_KEYS);

    if (defined(my $pool = $net->{lb_pool})) {
        if (ref $pool ne 'HASH') {
            push @errors, "network.lb_pool: must be a mapping (cidr, or start+stop)";
        }
        else {
            push @errors, _unknown_keys('network.lb_pool', $pool, @LB_POOL_KEYS);
            my $has_cidr  = defined $pool->{cidr};
            my $has_start = defined $pool->{start};
            my $has_stop  = defined $pool->{stop};

            if ($has_cidr && ($has_start || $has_stop)) {
                push @errors, "network.lb_pool: use either cidr or start+stop, not both";
            }
            elsif ($has_cidr) {
                push @errors, "network.lb_pool.cidr: " . _shown_value($pool->{cidr}) . " is not an IPv4 CIDR (e.g. 10.0.0.240/28)"
                    unless _looks_like_cidr($pool->{cidr});
            }
            elsif ($has_start || $has_stop) {
                push @errors, "network.lb_pool: start and stop must both be set"
                    unless $has_start && $has_stop;
                push @errors, "network.lb_pool.start: " . _shown_value($pool->{start}) . " is not an IPv4 address"
                    if $has_start && !_looks_like_ipv4($pool->{start});
                push @errors, "network.lb_pool.stop: " . _shown_value($pool->{stop}) . " is not an IPv4 address"
                    if $has_stop && !_looks_like_ipv4($pool->{stop});

                # Compared as addresses: 10.0.0.9 comes before 10.0.0.10.
                # Equal is a pool of one.
                push @errors, "network.lb_pool: start '$pool->{start}' is after stop "
                    . "'$pool->{stop}' (the pool runs from start up to stop)"
                    if _looks_like_ipv4($pool->{start}) && _looks_like_ipv4($pool->{stop})
                    && (_cidr_range("$pool->{start}/32"))[0] > (_cidr_range("$pool->{stop}/32"))[0];
            }
            else {
                push @errors, "network.lb_pool: needs cidr or start+stop";
            }
        }
    }

    if (defined(my $l2 = $net->{l2})) {
        if (ref $l2 ne 'HASH') {
            push @errors, "network.l2: must be a mapping";
        }
        else {
            push @errors, _unknown_keys('network.l2', $l2, @L2_KEYS);
            if (defined(my $ns = $l2->{node_selector})) {
                if (ref $ns ne 'HASH' || !%$ns) {
                    push @errors, "network.l2.node_selector: must be a non-empty mapping of label => value";
                }
                else {
                    for my $k (sort keys %$ns) {
                        push @errors, "network.l2.node_selector.$k: value must be a scalar"
                            if ref $ns->{$k};
                    }
                }
            }
            if (defined(my $if = $l2->{interfaces})) {
                if (ref $if ne 'ARRAY' || !@$if) {
                    push @errors, "network.l2.interfaces: must be a non-empty list of interface-name regexes";
                }
                elsif (grep { ref $_ } @$if) {
                    push @errors, "network.l2.interfaces: entries must be strings";
                }
            }
        }
    }

    return @errors;
}

# One line per key of $map that is not one of @known, sorted, in the words
# cilium.* and gpu.amd.* are refused in (k292).
sub _unknown_keys {
    my ($path, $map, @known) = @_;
    my %known = map { $_ => 1 } @known;
    return map { "$path.$_: unknown key (must be " . OCP::Choices::or_list(@known) . ')' }
        grep { !$known{$_} } sort keys %$map;
}

# cilium: (k210). Report-only, same contract as validate().
sub _validate_cilium {
    my ($self) = @_;
    my $c = $self->spec->{cilium};
    return () unless defined $c;
    return ("cilium: must be a mapping (devices, helm_values)") unless ref $c eq 'HASH';

    my @errors;
    for my $k (sort keys %$c) {
        push @errors, "cilium.$k: unknown key (must be "
            . OCP::Choices::or_list(qw( devices helm_values )) . ")"
            unless $k eq 'devices' || $k eq 'helm_values';
    }
    if (defined(my $d = $c->{devices})) {
        if (ref $d ne 'ARRAY' || !@$d) {
            push @errors, "cilium.devices: must be a non-empty list of interface names";
        }
        elsif (grep { ref $_ || !defined $_ || !length $_ } @$d) {
            push @errors, "cilium.devices: entries must be interface names (strings)";
        }
    }
    if (defined(my $hv = $c->{helm_values})) {
        if (ref $hv ne 'HASH') {
            push @errors, "cilium.helm_values: must be a mapping of Helm values";
        }
        elsif (defined $c->{devices} && exists $hv->{devices}) {
            push @errors, "cilium.devices and cilium.helm_values.devices: set one of them, not both";
        }
    }
    return @errors;
}

# gpu.driver (k255). Report-only, same contract as validate(); gpu_driver
# croaks on the same values, but only where a GPU node is set up -- after a
# control plane was built.
sub _validate_gpu_driver {
    my ($self) = @_;
    my $gpu = $self->spec->{gpu};
    return () unless ref $gpu eq 'HASH' && defined $gpu->{driver};
    return () if _is_choice($gpu->{driver}, @GPU_DRIVERS);
    return ('gpu.driver: invalid value '._shown_value($gpu->{driver})
        .' (must be '.OCP::Choices::or_list(@GPU_DRIVERS).')');
}

# gpu.amd (k250). Report-only, same contract as validate(); the accessors
# croak on the same values at the point of use. An unknown key is reported
# too: a misspelt `alocation` would otherwise leave the default in force.
sub _validate_gpu_amd {
    my ($self) = @_;
    my $gpu = $self->spec->{gpu};
    return () unless ref $gpu eq 'HASH' && defined $gpu->{amd};

    my $amd = $gpu->{amd};
    my $keys = OCP::Choices::or_list(@GPU_AMD_KEYS);
    return ("gpu.amd: must be a mapping ($keys)") unless ref $amd eq 'HASH';

    my @errors;
    for my $k (sort keys %$amd) {
        push @errors, "gpu.amd.$k: unknown key (must be $keys)"
            unless grep { $_ eq $k } @GPU_AMD_KEYS;
    }

    my %choices = (
        allocation      => \@GPU_AMD_ALLOCATIONS,
        resource_naming => \@GPU_AMD_RESOURCE_NAMING,
    );
    for my $k (sort keys %choices) {
        my $v = $amd->{$k};
        next if !defined $v || _is_choice($v, @{ $choices{$k} });
        push @errors, "gpu.amd.$k: invalid value "._shown_value($v)
            .' (must be '.OCP::Choices::or_list(@{ $choices{$k} }).')';
    }
    return @errors;
}

# network.pod_cidr (k182). Checked whether set or not: the default can
# collide with a node address just as well, and then the error has to say it
# was the default that did.
sub _validate_pod_cidr {
    my ($self, $net) = @_;
    my $set  = defined $net->{pod_cidr};
    my $cidr = $set ? $net->{pod_cidr} : $DEFAULT_POD_CIDR;
    my $what = $set ? "network.pod_cidr: '$cidr'" : "network.pod_cidr (default $cidr)";

    return ("network.pod_cidr: " . _shown_value($cidr) . " is not an IPv4 CIDR (e.g. 10.42.0.0/16)")
        unless _looks_like_cidr($cidr);

    my ($net_ip, $bits) = _cidr_range($cidr);
    my $canonical = _int_to_ipv4($net_ip) . "/$bits";
    return ("$what has host bits set; the network address is $canonical")
        unless $cidr eq $canonical;

    # Cilium's cluster pool gives every node a /24 out of this.
    return ("$what is too small: Cilium gives every node a /24 of it, "
        . "so the pod CIDR needs a shorter prefix than /24 (e.g. /16)")
        if $bits >= 24;

    my @taken = ([ "the service network $SERVICE_CIDR", $SERVICE_CIDR ], $self->_taken_addresses($net));

    my $hint = $set ? '' : ' -- set network.pod_cidr to a range nothing else uses';
    my @errors;
    for my $t (@taken) {
        push @errors, "$what overlaps $t->[0]$hint"
            if _cidrs_overlap($cidr, $t->[1]);
    }
    return @errors;
}

# The service network (k299): RKE2's and K3s's built-in service-cidr, which
# ocp.yaml has no key for. Held against the addresses the pod CIDR is held
# against, in the same words: one of them inside it can be handed to a
# Service as its ClusterIP. Checked whatever the pod CIDR is.
sub _validate_service_cidr {
    my ($self, $net) = @_;
    my $what = "the service network (default $SERVICE_CIDR)";
    my $hint = ' -- ocp.yaml has no key to move it; use an address outside it';
    return map { "$what overlaps $_->[0]$hint" }
        grep { _cidrs_overlap($SERVICE_CIDR, $_->[1]) } $self->_taken_addresses($net);
}

# The addresses ocp.yaml names that a cluster network must stay clear of
# (k182, k279, k299), as [ what, CIDR ]: each control plane's host,
# public_ip, private_ip and node_ip, each worker pool host, the LB pool. An
# address that is no IPv4 literal is not counted -- a host name is not
# resolved, a refused node_ip has its own line.
sub _taken_addresses {
    my ($self, $net) = @_;
    my @taken;
    my $cps = $self->control_planes;
    for my $i (0 .. $#$cps) {
        next unless ref $cps->[$i] eq 'HASH';    # validate() has its line (k296)
        for my $key (qw( host public_ip private_ip )) {
            my $addr = $cps->[$i]{$key};
            push @taken, [ "control_planes[" . ($i + 1) . "].$key $addr", "$addr/32" ]
                if _looks_like_ipv4($addr);
        }

        # node_ip (k279), the address the node registers by: each part, the
        # IPv4 one, as both networks held against it are IPv4. Only a value
        # validate() accepted counts; a refused one has its own line already.
        my $node_ip = $cps->[$i]{node_ip};
        next if !defined $node_ip || $self->_control_planes_shared
            || defined OCP::Choices::node_ip_error($node_ip);
        push @taken, map { [ "control_planes[" . ($i + 1) . "].node_ip $_", "$_/32" ] }
            grep { _looks_like_ipv4($_) } split /,/, $node_ip;
    }
    my $workers = $self->workers;
    my @pools = ref $workers eq 'ARRAY' ? @$workers : ();
    for my $n (1 .. @pools) {
        my $pool = $pools[$n - 1];
        next unless ref $pool eq 'HASH';
        my @hosts = ($pool->{host},
            map { ref $_ eq 'HASH' ? $_->{host} : $_ } @{ ref $pool->{nodes} eq 'ARRAY' ? $pool->{nodes} : [] });
        my $where = $self->_pool_where($pool, $n);
        push @taken, map { [ "$where host $_", "$_/32" ] } grep { _looks_like_ipv4($_) } @hosts;
    }
    if (ref(my $lb = $net->{lb_pool}) eq 'HASH') {
        push @taken, [ "network.lb_pool $lb->{cidr}", $lb->{cidr} ] if _looks_like_cidr($lb->{cidr});
        for my $key (qw( start stop )) {
            push @taken, [ "network.lb_pool.$key $lb->{$key}", "$lb->{$key}/32" ]
                if _looks_like_ipv4($lb->{$key});
        }
    }
    return @taken;
}

# (network address as an integer, prefix length) of a valid IPv4 CIDR.
sub _cidr_range {
    my ($ip, $bits) = split m{/}, shift;
    my $n = 0;
    $n = $n * 256 + $_ for split /\./, $ip;
    my $mask = $bits ? (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF : 0;
    return ($n & $mask, $bits);
}

sub _int_to_ipv4 {
    my $n = shift;
    return join '.', map { ($n >> $_) & 255 } 24, 16, 8, 0;
}

# Two blocks overlap when one contains the other's network address under the
# shorter of the two prefixes.
sub _cidrs_overlap {
    my ($a, $b) = @_;
    my ($an, $ab) = _cidr_range($a);
    my ($bn, $bb) = _cidr_range($b);
    my $bits = $ab < $bb ? $ab : $bb;
    my $mask = $bits ? (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF : 0;
    return (($an & $mask) == ($bn & $mask)) ? 1 : 0;
}

sub _looks_like_ipv4 {
    my $ip = shift;
    return 0 unless defined $ip && !ref $ip;
    return 0 unless $ip =~ /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/;
    return 0 if grep { $_ > 255 } ($1, $2, $3, $4);
    return 1;
}

sub _looks_like_cidr {
    my $c = shift;
    return 0 unless defined $c && !ref $c;
    return 0 unless $c =~ m{^(.+)/([0-9]{1,2})$};
    my ($ip, $bits) = ($1, $2);
    return 0 if $bits > 32;
    return _looks_like_ipv4($ip);
}

#
# Status write methods
#

sub save_node_status {
    my ($self, $node) = @_;

    my $nodes = $self->nodes_status;

    # Upsert by name
    my $found = 0;
    for my $existing (@$nodes) {
        if ($existing->{name} eq $node->{name}) {
            %$existing = %$node;
            $found = 1;
            last;
        }
    }
    push @$nodes, $node unless $found;

    $self->save_status;
}

sub _save_status {
    my ($self, $status) = @_;
    my $file = path($self->status_file);
    $file->parent->mkpath unless -d $file->parent;
    $self->ocp->dump_file($file->stringify, $status);
}

#
# Class methods for initialization
#

sub write_spec {
    my ($class, $file, %opts) = @_;

    my $spec = {
        name => $opts{name} // 'mycluster',
        kubernetes => {
            dist => $opts{dist} // 'rke2',
        },
        ssh => {
            private_key => $opts{ssh_private_key} // '.ocp/id_ed25519',
            public_key  => $opts{ssh_public_key} // '.ocp/id_ed25519.pub',
        },
    };

    # Only add version if specified
    if ($opts{version}) {
        $spec->{kubernetes}{version} = $opts{version};
    }

    # Only add workers if specified
    if ($opts{workers} && @{$opts{workers}}) {
        $spec->{workers} = $opts{workers};
    }

    # System config (timezone, locale, ntp)
    if ($opts{system} && ref $opts{system} eq 'HASH' && %{$opts{system}}) {
        $spec->{system} = $opts{system};
    }

    # Control planes: compact where possible
    # 1 CP → Hash, N identical CPs → Hash + nodes, mixed → Array
    if ($opts{control_planes} && ref $opts{control_planes} eq 'ARRAY') {
        $spec->{control_planes} = _compact_control_planes($opts{control_planes});
    } else {
        my $provider = $opts{provider} // 'hetzner';

        if ($provider eq 'hetzner') {
            $spec->{control_planes} = {
                provider    => 'hetzner',
                server_type => $opts{server_type} // $HETZNER_DEFAULTS{server_type},
                location    => $opts{location}    // $HETZNER_DEFAULTS{location},
                image       => $opts{image}       // $HETZNER_DEFAULTS{image},
            };
        } elsif ($provider eq 'ssh') {
            my $cp = { provider => 'ssh' };
            $cp->{host} = $opts{host} if $opts{host};
            $spec->{control_planes} = $cp;
        } elsif ($provider eq 'local') {
            my $cp = { provider => 'local' };
            if ($opts{service} && $opts{service} ne 'none') {
                $cp->{service} = $opts{service};
            }
            $spec->{control_planes} = $cp;
        }
    }

    OCP->instance->dump_file($file, $spec);
}

sub _compact_control_planes {
    my ($control_planes) = @_;
    return $control_planes->[0] if @$control_planes == 1;

    # Check if all entries are identical → Hash + nodes
    # canonical sorts keys, so two hashes with the same content compare equal
    # regardless of insertion order.
    my $json = JSON::MaybeXS->new(canonical => 1, convert_blessed => 1);

    my $first = $json->encode($control_planes->[0]);
    my $all_same = 1;
    for my $i (1 .. $#$control_planes) {
        if ($json->encode($control_planes->[$i]) ne $first) {
            $all_same = 0;
            last;
        }
    }

    if ($all_same) {
        my %cp = %{$control_planes->[0]};
        $cp{nodes} = scalar @$control_planes;
        return \%cp;
    }

    return $control_planes;
}

1;

__END__

=head1 NAME

OCP::Config - OCP configuration and status management

=head1 SYNOPSIS

    use OCP::Config;

    my $config = OCP::Config->new(file => 'ocp.yaml');

    # Read spec
    print $config->name;
    my $cp = $config->control_planes;

    # Read/write status
    $config->set_status(phase => 'Running');
    $config->add_node_status({ name => 'cp-1', ... });
    $config->save_status;

=head1 DESCRIPTION

OCP::Config manages two files:

=over 4

=item * C<ocp.yaml> - Cluster specification (what you want)

=item * C<.ocp/status.yaml> - Cluster status (what exists)

=back

The spec file is meant to be version controlled. The status file is
meant to be gitignored as it changes frequently during operations.

=head2 control_planes[].node_ip

    control_planes:
      - provider: ssh
        host: otho.lab
        node_ip: 10.230.30.52          # or "10.230.30.52,fd00::52"

The address a control plane registers as its C<InternalIP> -- RKE2's and
K3s's C<node-ip> (k254). Without it the node registers the address of its
default route, which on a multi-homed host (a second NIC, a VLAN) may be one
the other nodes cannot reach: the node shows Ready while Cilium's tunnel to it
is broken. One IPv4 or IPv6 literal, or one of each joined by a comma for
dual-stack; C<validate> refuses anything else with the line
L<OCP::Choices/node_ip_error> gives, prefixed C<control_planes[N].node_ip: >.
It is never guessed: unset, no node-ip is passed at all.

Only where it names one machine:

=over 4

=item * the mapping form of C<control_planes> takes it as long as it is one
control plane; with C<nodes: N> above 1 it would be every copy's address and
is refused -- list the control planes one by one instead;

=item * in the list form, no two control planes may share an address. They
are compared address by address and as IPs, so C<10.0.0.1,fd00::1> clashes
with C<10.0.0.1>, and C<FD00::1> with C<fd00::1>; the line names both
entries;

=item * its IPv4 address, either part of a dual-stack value, must lie outside
C<network.pod_cidr> (default C<10.42.0.0/16>): it is a node address like
C<host> and C<public_ip>, and refused in the same words when the pod CIDR
contains it (k279);

=item * a C<workers> pool takes none, and neither does an entry of a pool's
C<nodes> list. Both are refused rather than ignored, and the line points to
C<ocp node add NAME --node_ip ADDRESS> or C<spec.nodeIP> on the OCPNode.

=back

=cut

package OCP::Config;
# ABSTRACT: OCP configuration and status management

use Moo;
use OCP;
use OCP::Choices;
use OCP::Provider;
use JSON::MaybeXS;
use Path::Tiny qw(path);
use Carp qw(croak);
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

sub control_planes {
    my ($self) = @_;
    my $raw = $self->spec->{control_planes};

    # Array form: one entry per control plane
    return $raw if ref $raw eq 'ARRAY';

    # Hash form: single CP, or `nodes: N` for N identical CPs
    if (ref $raw eq 'HASH') {
        my %cp = %$raw;
        my $count = delete $cp{nodes} // 1;
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
sub robocop_enabled {
    my $self = shift;
    my $val = $self->spec->{robocop};

    if (ref $val eq 'HASH') {
        return $val->{enabled} ? 1 : 0 if defined $val->{enabled};
        return 1;
    }
    return $val ? 1 : 0 if defined $val;

    return 1 if $self->_any_hetzner_provider;
    return 0;
}

# How the private robo (automation) SSH key reaches the cluster (k129),
# read from `robocop.security_level` (the mapping form of the robocop key):
#
#   secret           `ocp deploy-robocop` decrypts the robo key with PIN1 and
#                    writes it into a K8s Secret; a pod restart self-heals.
#   secret_approved  as secret, but writing the Secret is gated behind PIN2.
#   inject           in-memory, never persisted (k2) — deferred; the
#                    config accepts it, the deploy path refuses it cleanly.
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
        . ", not '$level'"
        unless grep { $_ eq $level } @ROBOCOP_SECURITY_LEVELS;

    return $level;
}

sub _raw_robocop_security_level {
    my ($self) = @_;
    my $val = $self->spec->{robocop};
    return ref $val eq 'HASH' ? $val->{security_level} : undef;
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

sub l2_config        { shift->network_config->{l2} // {} }
sub l2_node_selector { shift->l2_config->{node_selector} // {} }

# The interface-name regexes for CiliumL2AnnouncementPolicy. The built-in list
# is anchored on both ends: an unanchored "^en[a-z0-9]+" matched the QSFP
# fabric (enp1s0f0np0) it had no business announcing on. A node with more than
# one interface should use l2.node_selector rather than lean on these.
sub l2_interfaces {
    my $self = shift;
    my $i = $self->l2_config->{interfaces};
    return $i if ref $i eq 'ARRAY' && @$i;
    return ['^eth[0-9]+$', '^en[a-z0-9]+$'];
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
sub gpu_config  { shift->spec->{gpu} // {} }

# Normalised to 0/1: these travel to the Rexfile as JSON and into a
# ClusterPolicy as a YAML boolean, and YAML::XS hands back JSON::PP::Boolean
# objects that neither destination should have to know about.
sub gpu_enabled { my $v = shift->gpu_config->{enabled}; return 1 unless defined $v; return $v ? 1 : 0 }
sub gpu_toolkit { my $v = shift->gpu_config->{toolkit}; return 1 unless defined $v; return $v ? 1 : 0 }

sub gpu_driver {
    my ($self) = @_;
    my $driver = $self->gpu_config->{driver} // 'host';

    # A typo here would silently fall back to 'host' and leave the operator's
    # driver DaemonSet disabled on a cluster that was configured for it.
    croak "gpu.driver must be 'host' or 'operator', not '$driver'"
        unless $driver eq 'host' || $driver eq 'operator';

    return $driver;
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

    push @errors, "name is required" unless $self->name && $self->name =~ /\S/;

    my $cps = $self->control_planes;
    for my $i (0 .. $#$cps) {
        my $cp = $cps->[$i];
        my $idx = $i + 1;
        my $prov = $cp->{provider} // 'hetzner';

        # The wording this rejection has always had; the SET behind it now
        # comes from the factory that builds those providers instead of being
        # spelled out a second time here (k103). Same three words, one
        # source -- a fourth provider type appears in this message the moment
        # OCP::Provider can construct it.
        unless (OCP::Provider->known_type($prov)) {
            push @errors, "control_planes[$idx]: invalid provider '$prov' (must be "
                . OCP::Choices::or_list(OCP::Provider->types) . ")";
        }

        if ($prov eq 'hetzner') {
            push @errors, "control_planes[$idx]: server_type required for hetzner"
                unless $cp->{server_type};
            push @errors, "control_planes[$idx]: location required for hetzner"
                unless $cp->{location};
        }

        if ($prov eq 'ssh') {
            push @errors, "control_planes[$idx]: host required for ssh"
                unless $cp->{host};
        }
    }

    push @errors, $self->_validate_network;

    # robocop.security_level, report-only (k129). The accessor croaks; here
    # we collect one line so `ocp apply` lists it with every other config error.
    my $rl = $self->_raw_robocop_security_level;
    if (defined $rl && !grep { $_ eq $rl } @ROBOCOP_SECURITY_LEVELS) {
        push @errors, "robocop.security_level: invalid value '$rl' (must be "
            . OCP::Choices::or_list(@ROBOCOP_SECURITY_LEVELS) . ")";
    }

    for my $w (@{$self->workers}) {
        push @errors, "worker pool: name required" unless $w->{name};
        my $wprov = $w->{provider} // '';
        if ($wprov eq '') {
            push @errors, "worker pool '$w->{name}': provider required";
        } elsif (!OCP::Provider->known_type($wprov)) {
            # Same set, same source as the control-plane check above --
            # spelling the regex here again is what k103 deleted for
            # the control planes and what k110 made stale (k115).
            push @errors, "worker pool '$w->{name}': invalid provider '$wprov' (must be "
                . OCP::Choices::or_list(OCP::Provider->types) . ")";
        }
    }

    return @errors;
}

# network.lb_pool / network.l2 validation (k127). Report-only: returns a
# list of human-readable errors, same contract as validate() itself.
sub _validate_network {
    my ($self) = @_;
    my $net = $self->spec->{network};
    return () unless defined $net;
    return ("network: must be a mapping") unless ref $net eq 'HASH';

    my @errors;

    if (defined(my $pool = $net->{lb_pool})) {
        if (ref $pool ne 'HASH') {
            push @errors, "network.lb_pool: must be a mapping (cidr, or start+stop)";
        }
        else {
            my $has_cidr  = defined $pool->{cidr};
            my $has_start = defined $pool->{start};
            my $has_stop  = defined $pool->{stop};

            if ($has_cidr && ($has_start || $has_stop)) {
                push @errors, "network.lb_pool: use either cidr or start+stop, not both";
            }
            elsif ($has_cidr) {
                push @errors, "network.lb_pool.cidr: '$pool->{cidr}' is not an IPv4 CIDR (e.g. 10.0.0.240/28)"
                    unless _looks_like_cidr($pool->{cidr});
            }
            elsif ($has_start || $has_stop) {
                push @errors, "network.lb_pool: start and stop must both be set"
                    unless $has_start && $has_stop;
                push @errors, "network.lb_pool.start: '$pool->{start}' is not an IPv4 address"
                    if $has_start && !_looks_like_ipv4($pool->{start});
                push @errors, "network.lb_pool.stop: '$pool->{stop}' is not an IPv4 address"
                    if $has_stop && !_looks_like_ipv4($pool->{stop});
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

=cut

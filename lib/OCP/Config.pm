package OCP::Config;
# ABSTRACT: OCP configuration and status management

use Moo;
use OCP;
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
# (karr #92).
#
# It lives here because OCP::Config is the only place that knows the cluster
# name in both modes: secure mode uploads the PIN2-protected admin key,
# --nopassword mode uploads the bootstrap key, and both land under this name.
# Two hand-written copies of the string is exactly how the worker path and
# the bootstrap path would drift apart again.
sub admin_ssh_key_name { 'ocp-' . shift->name . '-admin' }

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

sub robocop_enabled {
    my $self = shift;
    my $val = $self->spec->{robocop};
    return $val ? 1 : 0 if defined $val;
    return 1 if $self->_any_hetzner_provider;
    return 0;
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

        unless ($prov =~ /^(hetzner|ssh|local)$/) {
            push @errors, "control_planes[$idx]: invalid provider '$prov' (must be hetzner, ssh, or local)";
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

    for my $w (@{$self->workers}) {
        push @errors, "worker pool: name required" unless $w->{name};
        my $wprov = $w->{provider} // '';
        push @errors, "worker pool '$w->{name}': provider required"
            unless $wprov =~ /^(hetzner|ssh)$/;
    }

    return @errors;
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
            if ($opts{network_interface}) {
                $cp->{network_interface} = $opts{network_interface};
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

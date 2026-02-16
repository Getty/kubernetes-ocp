package OCP::Config;
# ABSTRACT: OCP configuration and status management

use Moo;
use OCP;
use Path::Tiny qw(path);
use Carp qw(croak);

our $VERSION = '0.1.0';

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
        k8s => {
            dist    => 'rke2',  # or 'k3s'
            version => '',      # latest if empty
        },
        cps => {
            nodes      => 'cp',
            provider   => 'hetzner',
            serverType => 'cpx21',
            location   => 'fsn1',
            image      => 'debian-13',
        },
        workers => [],
        ssh => {
            privateKey => '.ocp/id_ed25519',
            publicKey  => '.ocp/id_ed25519.pub',
        },
    };
}

#
# Spec accessors
#

sub name { shift->spec->{name} // 'mycluster' }

sub kubernetes {
    my $self = shift;
    # Support both 'kubernetes' and 'k8s'
    return $self->spec->{kubernetes} // $self->spec->{k8s} // {};
}

sub control_planes {
    my $self = shift;
    # Support both 'controlPlanes' and 'cps'
    return $self->spec->{controlPlanes} // $self->spec->{cps} // {};
}

sub workers { shift->spec->{workers} // [] }
sub ssh_config { shift->spec->{ssh} // {} }
sub single_node {
    my $self = shift;
    # Explicit flag or inferred (1 CP, 0 workers)
    return $self->spec->{single} if exists $self->spec->{single};
    my $cp = $self->control_planes;
    my $workers = $self->workers;
    return (scalar(@$workers) == 0 && ($cp->{nodes} // $cp->{count} // 1) == 1);
}

sub distribution {
    my $self = shift;
    my $k8s = $self->kubernetes;
    return $k8s->{dist} // $k8s->{distribution} // 'rke2';
}

sub version {
    my $self = shift;
    my $k8s = $self->kubernetes;
    return $k8s->{version} // '';
}

# Add-on flags (default: enabled, set to true to disable)
sub no_traefik { shift->spec->{notraefik} // 0 }
sub no_cert { shift->spec->{nocert} // 0 }
sub no_lbipam { shift->spec->{nolbipam} // 0 }
sub no_robocop { shift->spec->{norobocop} // 0 }

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
    my $key_path = $self->ssh_config->{privateKey} // '.ocp/id_ed25519';
    return $self->_resolve_path($key_path);
}

sub ssh_public_key_path {
    my ($self) = @_;
    my $key_path = $self->ssh_config->{publicKey} // '.ocp/id_ed25519.pub';
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
# Class methods for initialization
#

sub write_spec {
    my ($class, $file, %opts) = @_;

    my $provider = $opts{provider} // 'hetzner';

    my $spec = {
        name => $opts{name} // 'mycluster',
        k8s => {
            dist => $opts{dist} // 'rke2',
        },
        ssh => {
            privateKey => $opts{ssh_private_key} // '.ocp/id_ed25519',
            publicKey  => $opts{ssh_public_key} // '.ocp/id_ed25519.pub',
        },
    };

    # Only add version if specified
    if ($opts{version}) {
        $spec->{k8s}{version} = $opts{version};
    }

    # Only add workers if specified
    if ($opts{workers} && @{$opts{workers}}) {
        $spec->{workers} = $opts{workers};
    }

    # Control plane config - provider specific
    if ($provider eq 'hetzner') {
        $spec->{cps} = {
            provider   => 'hetzner',
            nodes      => $opts{cp_nodes} // 'cp',
            serverType => $opts{server_type} // 'cpx21',
            location   => $opts{location} // 'fsn1',
            image      => $opts{image} // 'debian-13',
        };
    } elsif ($provider eq 'ssh') {
        $spec->{cps} = {
            provider => 'ssh',
        };
        # Host is required for SSH provider
        if ($opts{host}) {
            $spec->{cps}{host} = $opts{host};
        } else {
            # If nodes specified without host, use that
            $spec->{cps}{nodes} = $opts{cp_nodes} // 'cp';
        }
    } elsif ($provider eq 'local') {
        $spec->{cps} = {
            provider => 'local',
            nodes    => $opts{cp_nodes} // 'cp',
        };
        # Only set service if not 'none' (default)
        if ($opts{service} && $opts{service} ne 'none') {
            $spec->{cps}{service} = $opts{service};
        }
        if ($opts{network_interface}) {
            $spec->{cps}{networkInterface} = $opts{network_interface};
        }
    }

    # Single node setup
    if ($opts{single_node}) {
        $spec->{single} = 1;  # YAML will render as boolean true
    }

    OCP->instance->dump_file($file, $spec);
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

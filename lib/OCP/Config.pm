package OCP::Config;
# ABSTRACT: OCP configuration and status management

use Moo;
use YAML::XS qw(LoadFile DumpFile);
use Path::Tiny qw(path);
use Carp qw(croak);

our $VERSION = '0.1.0';

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

# Status directory (.ocp/)
has status_dir => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('.ocp') },
);

# Status file (.ocp/status.yaml)
has status_file => (
    is      => 'lazy',
    builder => sub { shift->status_dir->child('status.yaml') },
);

# Spec data (from ocp.yaml)
has spec => (
    is      => 'lazy',
    builder => '_load_spec',
);

# Status data (from .ocp/status.yaml)
has status => (
    is      => 'lazy',
    builder => '_load_status',
);

has _status_dirty => (
    is      => 'rw',
    default => 0,
);

#
# Loaders
#

sub _load_spec {
    my ($self) = @_;
    return $self->_default_spec unless -f $self->file;
    return LoadFile($self->file);
}

sub _load_status {
    my ($self) = @_;
    return {} unless -f $self->status_file;
    return LoadFile($self->status_file) // {};
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

# Add-on flags (default: enabled, set to true to disable)
sub no_traefik { shift->spec->{notraefik} // 0 }
sub no_cert { shift->spec->{nocert} // 0 }

# SSL configuration (for cert-manager)
sub ssl_config { shift->spec->{ssl} // {} }
sub ssl_email { shift->spec->{ssl}{email} // '' }

#
# Status accessors
#

sub cluster_status { shift->status->{cluster} // {} }
sub nodes_status { shift->status->{nodes} // [] }
sub phase { shift->status->{phase} // 'Unknown' }
sub last_reconciled { shift->status->{lastReconciled} }

#
# Status management
#

sub set_status {
    my ($self, $key, $value) = @_;
    $self->status->{$key} = $value;
    $self->_status_dirty(1);
}

sub set_cluster_status {
    my ($self, $key, $value) = @_;
    $self->status->{cluster} //= {};
    $self->status->{cluster}{$key} = $value;
    $self->_status_dirty(1);
}

sub add_node_status {
    my ($self, $node) = @_;
    $self->status->{nodes} //= [];

    my $nodes = $self->status->{nodes};
    my $found = 0;
    for my $n (@$nodes) {
        if ($n->{name} eq $node->{name}) {
            %$n = %$node;
            $found = 1;
            last;
        }
    }
    push @$nodes, $node unless $found;
    $self->_status_dirty(1);
}

sub remove_node_status {
    my ($self, $name) = @_;
    return unless $self->status->{nodes};
    $self->status->{nodes} = [
        grep { $_->{name} ne $name } @{$self->status->{nodes}}
    ];
    $self->_status_dirty(1);
}

sub get_node_status {
    my ($self, $name) = @_;
    return unless $self->status->{nodes};
    my ($node) = grep { $_->{name} eq $name } @{$self->status->{nodes}};
    return $node;
}

#
# Save methods
#

sub save_status {
    my ($self) = @_;

    # Ensure status directory exists
    $self->status_dir->mkpath unless -d $self->status_dir;

    # Update timestamp
    $self->status->{lastReconciled} = _timestamp();

    DumpFile($self->status_file->stringify, $self->status);
    $self->_status_dirty(0);
}

sub save_status_if_dirty {
    my ($self) = @_;
    $self->save_status if $self->_status_dirty;
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
# Helpers
#

sub _timestamp {
    my @t = gmtime;
    return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
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
            dist    => $opts{dist} // 'rke2',
            version => $opts{version} // '',
        },
        workers => [],
        ssh => {
            privateKey => $opts{ssh_private_key} // '.ocp/id_ed25519',
            publicKey  => $opts{ssh_public_key} // '.ocp/id_ed25519.pub',
        },
    };

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

    DumpFile($file, $spec);
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

package OCP::Versions;
# ABSTRACT: OCP version manifest and component versions

use strict;
use warnings;

our $VERSION = '0.1.0';

# Version manifest: OCP version -> component versions
# Add new components here, standard updates = just bump version numbers
our $VERSIONS = {
    '0.1.0' => {
        components => {
            # Kubernetes distributions
            rke2 => 'v1.31.3+rke2r1',
            k3s  => 'v1.31.3+k3s1',

            # CNI and networking
            cilium     => '1.17.0',
            cilium_cli => 'v0.16.23',

            # Ingress and SSL
            traefik      => 'v3.2.0',
            cert_manager => 'v1.14.0',
        },
        notes => 'Initial release with RKE2/K3s, Cilium CNI, Traefik ingress, cert-manager',
    },
};

# Get component versions for a specific OCP version
sub get_versions {
    my ($class, $version) = @_;
    $version //= $VERSION;  # Default to current version
    return $VERSIONS->{$version};
}

# Get component version
sub get_component_version {
    my ($class, $component, $ocp_version) = @_;
    $ocp_version //= $VERSION;
    my $versions = $class->get_versions($ocp_version);
    return unless $versions && $versions->{components};
    return $versions->{components}{$component};
}

# List all components
sub list_components {
    my ($class, $ocp_version) = @_;
    $ocp_version //= $VERSION;
    my $versions = $class->get_versions($ocp_version);
    return unless $versions && $versions->{components};
    return keys %{$versions->{components}};
}

# Check if upgrade has breaking changes
sub has_breaking_changes {
    my ($class, $from_version, $to_version) = @_;
    my $target = $class->get_versions($to_version);
    return 0 unless $target;
    return $target->{breaking_changes} ? 1 : 0;
}

# Get breaking changes
sub get_breaking_changes {
    my ($class, $from_version, $to_version) = @_;
    my $target = $class->get_versions($to_version);
    return unless $target;
    return $target->{breaking_changes} || [];
}

# Get manual steps
sub get_manual_steps {
    my ($class, $from_version, $to_version) = @_;
    my $target = $class->get_versions($to_version);
    return unless $target;
    return $target->{manual_steps} || [];
}

1;

__END__

=head1 NAME

OCP::Versions - OCP version manifest and component versions

=head1 SYNOPSIS

    use OCP::Versions;

    # Get current OCP version's component versions
    my $versions = OCP::Versions->get_versions('0.1.0');
    my $cilium_version = $versions->{components}{cilium};

    # Get specific component version
    my $traefik = OCP::Versions->get_component_version('traefik', '0.1.0');

    # List all components
    my @components = OCP::Versions->list_components('0.1.0');

    # Check for breaking changes
    if (OCP::Versions->has_breaking_changes('0.1.0', '0.2.0')) {
        my $changes = OCP::Versions->get_breaking_changes('0.1.0', '0.2.0');
    }

=head1 DESCRIPTION

OCP::Versions maintains the version manifest that defines which component
versions are bundled with each OCP release.

=head2 Adding New Components

To add a new component, simply add it to the C<components> hash for the
current version:

    '0.2.0' => {
        components => {
            ...
            my_new_component => 'v1.0.0',
        },
    }

=head2 Standard Updates

For standard version bumps without breaking changes, just update the
version numbers:

    '0.2.0' => {
        components => {
            cilium => '1.18.0',  # bumped from 1.17.0
        },
        notes => 'Updated Cilium to 1.18.0',
    }

=head2 Breaking Changes

For updates with breaking changes, add documentation:

    '0.2.0' => {
        components => { ... },
        breaking_changes => [
            'Cilium 1.18 requires kernel 5.4+',
            'RKE2 1.32 changes kubeconfig location',
        ],
        manual_steps => [
            'Run: kubectl drain nodes before upgrade',
            'Run: cilium migrate config',
        ],
    }

=head1 METHODS

=head2 get_versions

    my $versions = OCP::Versions->get_versions('0.1.0');

Returns the complete version manifest for a specific OCP version.

=head2 get_component_version

    my $version = OCP::Versions->get_component_version('cilium', '0.1.0');

Returns the version string for a specific component.

=head2 list_components

    my @components = OCP::Versions->list_components('0.1.0');

Returns list of all components for a specific OCP version.

=head2 has_breaking_changes

    if (OCP::Versions->has_breaking_changes('0.1.0', '0.2.0')) { ... }

Returns true if upgrading from one version to another has breaking changes.

=head2 get_breaking_changes

    my $changes = OCP::Versions->get_breaking_changes('0.1.0', '0.2.0');

Returns arrayref of breaking changes.

=head2 get_manual_steps

    my $steps = OCP::Versions->get_manual_steps('0.1.0', '0.2.0');

Returns arrayref of manual steps required for upgrade.

=cut

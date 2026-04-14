package OCP::Cmd::Version;
# ABSTRACT: Show OCP and component versions

use Moo;
use MooX::Cmd;
use OCP::Config;
use OCP::Versions;
use OCP;

our $VERSION = '0.001';

sub execute {
    my ($self, $args_ref, $chain_ref) = @_;

    print "OCP CLI Version: $OCP::VERSION\n\n";

    # Try to load config and status
    my $config_file = -f 'ocp.yaml' ? 'ocp.yaml' : undef;

    unless ($config_file) {
        print "No ocp.yaml found. Run 'ocp init' to create a cluster.\n";
        print "\nBundled component versions for OCP $OCP::VERSION:\n";
        $self->_show_bundled_versions();
        return 0;
    }

    my $config = OCP::Config->new(file => $config_file);

    # Show cluster info if deployed
    my $ocp_version = $config->status->{ocpVersion};
    my $components = $config->status->{components} // {};

    if ($ocp_version) {
        print "Deployed OCP Version: $ocp_version\n";
        print "Cluster: " . $config->name . "\n\n";

        if (keys %$components) {
            print "Installed Components:\n";
            for my $comp (sort keys %$components) {
                printf("  %-20s %s\n", $comp, $components->{$comp});
            }
        } else {
            print "No component versions tracked yet.\n";
        }

        # Show if update available
        if ($ocp_version ne $OCP::VERSION) {
            print "\n";
            print "⚠️  Update available: $ocp_version -> $OCP::VERSION\n";
            print "Run 'ocp update' to upgrade components.\n";

            # Check for breaking changes
            if (OCP::Versions->has_breaking_changes($ocp_version, $OCP::VERSION)) {
                print "\n⚠️  This update contains BREAKING CHANGES!\n";
                print "Run 'ocp update --dry-run' to see details.\n";
            }
        }
    } else {
        print "Cluster not yet deployed. Run 'ocp apply'.\n\n";
        print "Will install component versions for OCP $OCP::VERSION:\n";
        $self->_show_bundled_versions();
    }

    return 0;
}

sub _show_bundled_versions {
    my ($self) = @_;

    my $versions = OCP::Versions->get_versions($OCP::VERSION);
    return unless $versions && $versions->{components};

    my $comps = $versions->{components};
    for my $comp (sort keys %$comps) {
        printf("  %-20s %s\n", $comp, $comps->{$comp});
    }

    if ($versions->{notes}) {
        print "\nNotes: $versions->{notes}\n";
    }
}

1;

__END__

=head1 NAME

OCP::Cmd::Version - Show OCP and component versions

=head1 SYNOPSIS

    ocp version

=head1 DESCRIPTION

Shows:
- OCP CLI version
- Deployed cluster version (if any)
- Installed component versions
- Update availability

=head1 EXAMPLES

    # Show versions
    ocp version

    # Output:
    # OCP CLI Version: 0.2.0
    #
    # Deployed OCP Version: 0.1.0
    # Cluster: mycluster
    #
    # Installed Components:
    #   cilium               1.17.0
    #   cert_manager         v1.14.0
    #
    # ⚠️  Update available: 0.1.0 -> 0.2.0
    # Run 'ocp update' to upgrade components.

=cut

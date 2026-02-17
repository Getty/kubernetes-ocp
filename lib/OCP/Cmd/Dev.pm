package OCP::Cmd::Dev;
# ABSTRACT: Development tools

use Moo;
use MooX::Cmd;
use MooX::Options;

use OCP;
use OCP::Config;
use OCP::DevRegistry;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

option build => (
    is    => 'ro',
    short => 'b',
    doc   => 'Build and push robocop image',
);

option deploy_registry => (
    is    => 'ro',
    short => 'r',
    doc   => 'Deploy dev registry only',
);

option update => (
    is    => 'ro',
    short => 'u',
    doc   => 'Update robocop deployment with new image',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;
    my $verbose = $self->ocp->verbose;

    unless (-f $file) {
        die "Config file '$file' not found. Run 'ocp init' first.\n";
    }

    my $config = OCP::Config->new(file => $file);
    my $registry = OCP::DevRegistry->new(
        config  => $config,
        verbose => $verbose,
    );

    # Just deploy registry
    if ($self->deploy_registry) {
        $registry->deploy;
        return;
    }

    # Build and push (default)
    my $image = $registry->build_and_push(
        image      => 'ocp',
        tag        => 'dev',
        dockerfile => 'Dockerfile.robocop',
    );

    # Update deployment if requested
    if ($self->update) {
        $registry->update_robocop_image($image);
        print "\nRobocop restarted with new image.\n";
        print "Watch status: kubectl get pods -n ocp-system -w\n";
    } else {
        print "\nImage built and pushed: $image\n";
        print "To update robocop: ocp dev --update\n";
    }
}

1;

__END__

=head1 NAME

OCP::Cmd::Dev - Development tools for OCP

=head1 SYNOPSIS

    # Deploy dev registry into cluster
    ocp dev --deploy-registry

    # Build and push robocop image
    ocp dev --build

    # Build, push, and update robocop deployment
    ocp dev --build --update

    # Or just:
    ocp dev -bu

=head1 DESCRIPTION

Development tools for working with OCP from source.

When you run C<ocp apply> from your source directory, there's no pre-built
Docker image for robocop. This command:

1. Deploys a mini registry into the cluster (registry:2 on NodePort 30500)
2. Builds the robocop image from source (Dockerfile.robocop)
3. Pushes to the in-cluster registry
4. Updates the robocop deployment to use the new image

=head1 OPTIONS

=head2 --deploy-registry, -r

Deploy only the development registry (don't build image).

=head2 --build, -b

Build and push robocop image (default if no flags).

=head2 --update, -u

Update robocop deployment after building.

=head1 EXAMPLES

    # First time setup
    ocp dev -r     # Deploy registry
    ocp dev -bu    # Build and update robocop

    # After code changes
    ocp dev -bu    # Rebuild and restart

=cut

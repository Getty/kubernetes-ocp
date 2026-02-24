package OCP::DevRegistry;
# ABSTRACT: Development registry manager for local image builds

use Moo;
use File::Temp;
use IPC::Run;
use Path::Tiny qw(path);
use Carp qw(croak);
use File::ShareDir::ProjectDistDir qw(dist_dir);

our $VERSION = '0.1.0';

has config => (
    is       => 'ro',
    required => 1,
);

has verbose => (
    is      => 'ro',
    default => 0,
);

has registry_host => (
    is      => 'lazy',
    builder => '_build_registry_host',
);

sub _build_registry_host {
    my ($self) = @_;

    # Get control plane public IP
    my $nodes = $self->config->nodes_status;
    my ($cp) = grep { $_->{role} eq 'control-plane' } @$nodes;

    unless ($cp && $cp->{publicIp}) {
        croak "No control plane found. Run 'ocp apply' first.\n";
    }

    # Registry is exposed on NodePort 30500
    return "$cp->{publicIp}:30500";
}

sub is_deployed {
    my ($self) = @_;

    # Check if registry deployment exists
    my $result = $self->_kubectl(
        'get', 'deployment', 'registry',
        '-n', 'dev-registry',
        '--ignore-not-found',
        '-o', 'name',
    );

    return $result->{stdout} =~ /deployment/;
}

sub deploy {
    my ($self) = @_;

    $self->log("Deploying development registry...");

    my $manifest = $self->_find_manifest('dev-registry.yaml');

    $self->_kubectl_apply($manifest);

    # Wait for ready
    $self->log("Waiting for registry to be ready...");
    $self->_kubectl(
        'wait', '--for=condition=available',
        'deployment/registry',
        '-n', 'dev-registry',
        '--timeout=120s',
    );

    $self->log("Registry ready at ${\$self->registry_host}");
}

sub build_and_push {
    my ($self, %opts) = @_;

    my $image_name = $opts{image} // 'ocp';
    my $tag = $opts{tag} // 'latest';
    my $dockerfile = $opts{dockerfile} // 'Dockerfile.robocop';

    # Ensure registry is deployed
    unless ($self->is_deployed) {
        $self->deploy;
    }

    my $registry = $self->registry_host;
    my $full_tag = "$registry/$image_name:$tag";

    $self->log("Building image $full_tag...");

    # Build image
    my $project_dir = path($self->config->project_dir)->parent;

    my @build_cmd = (
        'docker', 'build',
        '-f', $dockerfile,
        '-t', $full_tag,
        '.',
    );

    $self->log("  Running: " . join(' ', @build_cmd)) if $self->verbose;

    my $result = $self->_run_in_dir($project_dir, @build_cmd);

    if ($result->{exit}) {
        croak "Docker build failed:\n$result->{stderr}\n";
    }

    $self->log("Pushing image to registry...");

    # Push to registry
    my @push_cmd = ('docker', 'push', $full_tag);
    $result = $self->_run(@push_cmd);

    if ($result->{exit}) {
        croak "Docker push failed:\n$result->{stderr}\n";
    }

    $self->log("Image pushed: $full_tag");

    return $full_tag;
}

sub deploy_robocop {
    my ($self) = @_;

    $self->log("Deploying robocop with dev image...");

    # Create temporary kustomization with registry host
    my $overlay_dir = $self->_find_manifest_dir('robocop/overlays/dev');
    my $temp_kustomization = $self->_prepare_dev_kustomization($overlay_dir);

    # Apply kustomization
    $self->_kubectl('apply', '-k', $temp_kustomization->parent);

    # Wait for ready
    $self->log("Waiting for robocop to be ready...");
    $self->_kubectl(
        'wait', '--for=condition=available',
        'deployment/robocop',
        '-n', 'ocp-system',
        '--timeout=120s',
    );

    $self->log("Robocop deployed");
}

sub update_robocop_image {
    my ($self, $image) = @_;

    $self->log("Updating robocop deployment to use $image...");

    # Patch deployment
    $self->_kubectl(
        'set', 'image',
        'deployment/robocop',
        "controller=$image",
        '-n', 'ocp-system',
    );

    # Restart deployment
    $self->_kubectl(
        'rollout', 'restart',
        'deployment/robocop',
        '-n', 'ocp-system',
    );

    $self->log("Robocop deployment updated");
}

sub _prepare_dev_kustomization {
    my ($self, $overlay_dir) = @_;

    my $registry = $self->registry_host;

    # Read kustomization template
    my $kustomization_file = path($overlay_dir)->child('kustomization.yaml');
    my $content = $kustomization_file->slurp_utf8;

    # Replace placeholder with actual registry
    $content =~ s/REGISTRY_HOST_PLACEHOLDER/$registry/g;

    # Write to temp file

    my $temp_dir = File::Temp->newdir(CLEANUP => 1);
    my $temp_file = path($temp_dir)->child('kustomization.yaml');
    $temp_file->spew_utf8($content);

    return $temp_file;
}

sub _find_manifest_dir {
    my ($self, $subdir) = @_;

    my $project_dir = path(dist_dir('OCP'));
    my $manifest_dir = $project_dir->child('manifests', $subdir);

    return $manifest_dir->stringify if $manifest_dir->exists;

    croak "Manifest directory not found: $subdir\n";
}

#
# Helpers
#

sub _find_manifest {
    my ($self, $name) = @_;

    my $project_dir = path(dist_dir('OCP'));
    my $manifest = $project_dir->child('manifests', $name);

    return $manifest->stringify if $manifest->exists;

    croak "Manifest not found: $name\n";
}

sub _kubectl {
    my ($self, @args) = @_;

    my $kubeconfig = $self->config->kubeconfig_path;

    my @cmd = ('kubectl', "--kubeconfig=$kubeconfig", @args);

    return $self->_run(@cmd);
}

sub _kubectl_apply {
    my ($self, $manifest) = @_;

    $self->_kubectl('apply', '-f', $manifest);
}

sub _run {
    my ($self, @cmd) = @_;



    my ($out, $err);
    my $success = IPC::Run::run(\@cmd, \undef, \$out, \$err);

    return {
        stdout => $out // '',
        stderr => $err // '',
        exit   => $? >> 8,
    };
}

sub _run_in_dir {
    my ($self, $dir, @cmd) = @_;

    my $cwd = path()->absolute;
    chdir $dir or croak "Can't chdir to $dir: $!\n";

    my $result = $self->_run(@cmd);

    chdir $cwd or croak "Can't chdir back to $cwd: $!\n";

    return $result;
}

sub log {
    my ($self, $msg) = @_;
    print "$msg\n";
}

1;

__END__

=head1 NAME

OCP::DevRegistry - Development registry for local image builds

=head1 SYNOPSIS

    use OCP::DevRegistry;

    my $registry = OCP::DevRegistry->new(
        config => $ocp_config,
    );

    # Deploy registry into cluster
    $registry->deploy;

    # Build and push robocop image
    my $image = $registry->build_and_push(
        image      => 'ocp',
        tag        => 'latest',
        dockerfile => 'Dockerfile.robocop',
    );

    # Update robocop deployment
    $registry->update_robocop_image($image);

=head1 DESCRIPTION

OCP::DevRegistry manages an in-cluster Docker registry for development.

When working from source, you need to build a robocop controller image and
make it available to the cluster. This module:

1. Deploys a registry:2 container as NodePort 30500
2. Builds Docker images from source
3. Pushes images to the in-cluster registry
4. Updates robocop deployment to use the new image

The registry is exposed via NodePort on the control plane's public IP.

=head1 METHODS

=head2 deploy

Deploy the development registry into the cluster (namespace: dev-registry).

=head2 build_and_push

Build Docker image and push to registry. Returns full image tag.

=head2 update_robocop_image

Update robocop deployment to use new image and restart.

=head2 is_deployed

Check if registry is already deployed.

=cut

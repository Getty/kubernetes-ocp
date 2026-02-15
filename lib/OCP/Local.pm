package OCP::Local;
# ABSTRACT: Local RKE2/K3s installation (no SSH)

use Moo;
use Carp qw(croak);
use IPC::Run qw(run);

our $VERSION = '0.1.0';

has verbose => (
    is      => 'ro',
    default => 0,
);

sub install_server {
    my ($self, %opts) = @_;

    my $distribution = $opts{distribution} || 'rke2';
    my $version = $opts{version} || '';
    my $node_name = $opts{node_name} || '';

    print "Installing $distribution server locally...\n";

    # Check if running as root
    unless ($< == 0) {
        croak "Local installation requires root. Run with sudo.\n";
    }

    # Prepare node
    $self->_run('swapoff -a || true');
    $self->_run('modprobe br_netfilter || true');
    $self->_run('modprobe overlay || true');

    # Install RKE2 or K3s
    if ($distribution eq 'rke2') {
        $self->_install_rke2(%opts);
    } else {
        $self->_install_k3s(%opts);
    }

    # Get kubeconfig
    my $kubeconfig_path = $distribution eq 'k3s'
        ? '/etc/rancher/k3s/k3s.yaml'
        : '/etc/rancher/rke2/rke2.yaml';

    my $kubeconfig = $self->_read_file($kubeconfig_path);

    # Get token
    my $token_path = $distribution eq 'k3s'
        ? '/var/lib/rancher/k3s/server/node-token'
        : '/var/lib/rancher/rke2/server/node-token';

    my $token = $self->_read_file($token_path);
    chomp $token;

    return {
        token      => $token,
        kubeconfig => $kubeconfig,
    };
}

sub _install_rke2 {
    my ($self, %opts) = @_;

    my $version = $opts{version} || '';
    my $node_name = $opts{node_name} || '';

    # Create RKE2 config
    my $config = "cni: none\ndisable-kube-proxy: true\n";
    $config .= "node-name: $node_name\n" if $node_name;
    $config .= "disable:\n  - rke2-ingress-nginx\n";

    $self->_write_file('/etc/rancher/rke2/config.yaml', $config);

    # Install RKE2
    my $cmd = "curl -sfL https://get.rke2.io | ";
    $cmd .= "INSTALL_RKE2_VERSION=$version " if $version;
    $cmd .= "sh -";

    print "  Downloading RKE2...\n";
    $self->_run($cmd);

    # Start service
    print "  Starting RKE2 server...\n";
    $self->_run('systemctl enable rke2-server.service');
    $self->_run('systemctl start rke2-server.service');

    # Wait for ready
    print "  Waiting for RKE2 to be ready...\n";
    $self->_run('while ! /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes 2>/dev/null; do sleep 2; done', 300);
}

sub _install_k3s {
    my ($self, %opts) = @_;

    my $version = $opts{version} || '';
    my $node_name = $opts{node_name} || '';

    # Install K3s
    my $cmd = "curl -sfL https://get.k3s.io | ";
    $cmd .= "INSTALL_K3S_VERSION=$version " if $version;
    $cmd .= "K3S_NODE_NAME=$node_name " if $node_name;
    $cmd .= "sh -s - server --disable=traefik --disable=servicelb --write-kubeconfig-mode=644";

    print "  Downloading K3s...\n";
    $self->_run($cmd);

    # Wait for ready
    print "  Waiting for K3s to be ready...\n";
    $self->_run('while ! kubectl get nodes 2>/dev/null; do sleep 2; done', 300);
}

sub untaint_control_plane {
    my ($self, %opts) = @_;

    my $distribution = $opts{distribution} || 'rke2';

    print "Untainting control plane...\n";

    if ($distribution eq 'rke2') {
        my $kubectl = '/var/lib/rancher/rke2/bin/kubectl';
        my $kubeconfig = '/etc/rancher/rke2/rke2.yaml';

        $self->_run("$kubectl --kubeconfig=$kubeconfig wait --for=condition=ready node --all --timeout=60s");

        my $node = `$kubectl --kubeconfig=$kubeconfig get nodes -o jsonpath='{.items[0].metadata.name}'`;
        chomp $node;

        $self->_run("$kubectl --kubeconfig=$kubeconfig taint nodes $node node-role.kubernetes.io/control-plane:NoSchedule- || true");
        $self->_run("$kubectl --kubeconfig=$kubeconfig taint nodes $node node-role.kubernetes.io/master:NoSchedule- || true");
    } else {
        $self->_run("kubectl wait --for=condition=ready node --all --timeout=60s");

        my $node = `kubectl get nodes -o jsonpath='{.items[0].metadata.name}'`;
        chomp $node;

        $self->_run("kubectl taint nodes $node node-role.kubernetes.io/control-plane:NoSchedule- || true");
        $self->_run("kubectl taint nodes $node node-role.kubernetes.io/master:NoSchedule- || true");
    }
}

sub install_cilium {
    my ($self, %opts) = @_;

    my $distribution = $opts{distribution} || 'rke2';

    print "Installing Cilium CNI...\n";

    # Install Cilium CLI
    print "  Installing Cilium CLI...\n";
    $self->_run('curl -sfL https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz | tar xz -C /usr/local/bin');
    $self->_run('chmod +x /usr/local/bin/cilium');

    # Install Cilium
    my $kubeconfig = $distribution eq 'k3s' ? '/etc/rancher/k3s/k3s.yaml' : '/etc/rancher/rke2/rke2.yaml';

    print "  Installing Cilium into cluster...\n";
    $self->_run("KUBECONFIG=$kubeconfig cilium install --version 1.17.0");

    print "  Waiting for Cilium to be ready...\n";
    $self->_run("KUBECONFIG=$kubeconfig cilium status --wait --wait-duration=5m", 360);
}

#
# Helpers
#

sub _run {
    my ($self, $cmd, $timeout) = @_;

    $timeout //= 120;

    print "  Running: $cmd\n" if $self->verbose;

    my ($out, $err);
    my $success = run(
        ['bash', '-c', $cmd],
        \undef,
        \$out,
        \$err,
        IPC::Run::timeout($timeout),
    );

    unless ($success) {
        croak "Command failed: $cmd\nError: $err\n";
    }

    return $out;
}

sub _write_file {
    my ($self, $path, $content) = @_;

    require Path::Tiny;
    my $file = Path::Tiny::path($path);
    $file->parent->mkpath;
    $file->spew_utf8($content);
}

sub _read_file {
    my ($self, $path) = @_;

    require Path::Tiny;
    return Path::Tiny::path($path)->slurp_utf8;
}

1;

__END__

=head1 NAME

OCP::Local - Local RKE2/K3s installation without SSH

=head1 SYNOPSIS

    use OCP::Local;

    my $local = OCP::Local->new(verbose => 1);

    # Install RKE2 server locally
    my $result = $local->install_server(
        distribution => 'rke2',
        node_name    => 'localhost',
    );

    # Untaint for single-node
    $local->untaint_control_plane(distribution => 'rke2');

    # Install Cilium
    $local->install_cilium(distribution => 'rke2');

=head1 DESCRIPTION

OCP::Local installs Kubernetes directly on localhost without SSH.

Runs commands directly via system() instead of SSH/Rex.

Requires root (use sudo).

=head1 METHODS

=head2 install_server

Install RKE2 or K3s server on localhost.

Returns hashref with token and kubeconfig.

=head2 untaint_control_plane

Remove control-plane taints for single-node mode.

=head2 install_cilium

Install Cilium CNI.

=cut

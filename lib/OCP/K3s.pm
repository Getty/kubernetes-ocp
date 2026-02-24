package OCP::K3s;
# ABSTRACT: K3s installation and management

use Moo;
use Carp qw(croak);
use MIME::Base64;

our $VERSION = '0.1.0';

has ssh => (
    is       => 'ro',
    required => 1,
);

has version => (
    is      => 'ro',
    default => 'v1.31.3+k3s1',
);

sub install_server {
    my ($self, $token) = @_;

    $token //= $self->_generate_token();

    # Prepare node
    $self->_prepare_node();

    my $version = $self->version;

    # Install k3s server
    my $script = <<"SCRIPT";
#!/bin/bash
set -e
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$PATH"
export INSTALL_K3S_VERSION="$version"
export K3S_TOKEN="$token"

echo "Installing k3s $version..."
curl -sfL https://get.k3s.io | sh -s - server \\
    --disable=traefik \\
    --disable=servicelb \\
    --write-kubeconfig-mode=644

echo "k3s installation complete"
SCRIPT

    my $result = $self->ssh->run_script($script);
    croak "k3s install failed: $result->{stderr}" if $result->{exit};

    # Wait for k3s to be ready
    $self->_wait_for_k3s();

    # Get kubeconfig
    my $kubeconfig = $self->get_kubeconfig();

    return {
        token      => $token,
        kubeconfig => $kubeconfig,
    };
}

sub install_agent {
    my ($self, $server_url, $token) = @_;

    croak "server_url required" unless $server_url;
    croak "token required" unless $token;

    # Prepare node
    $self->_prepare_node();

    my $version = $self->version;

    # Install k3s agent
    my $script = <<"SCRIPT";
#!/bin/bash
set -e
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$PATH"
export INSTALL_K3S_VERSION="$version"
export K3S_URL="$server_url"
export K3S_TOKEN="$token"

echo "Installing k3s agent..."
curl -sfL https://get.k3s.io | sh -s - agent
echo "k3s agent installation complete"
SCRIPT

    my $result = $self->ssh->run_script($script);
    croak "k3s agent install failed: $result->{stderr}" if $result->{exit};

    return 1;
}

sub join_server {
    my ($self, $server_url, $token) = @_;

    croak "server_url required" unless $server_url;
    croak "token required" unless $token;

    # Prepare node
    $self->_prepare_node();

    my $version = $self->version;

    # Join as server (HA)
    my $script = <<"SCRIPT";
#!/bin/bash
set -e
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$PATH"
export INSTALL_K3S_VERSION="$version"
export K3S_URL="$server_url"
export K3S_TOKEN="$token"

echo "Joining k3s cluster as server..."
curl -sfL https://get.k3s.io | sh -s - server \\
    --disable=traefik \\
    --disable=servicelb
echo "k3s server join complete"
SCRIPT

    my $result = $self->ssh->run_script($script);
    croak "k3s server join failed: $result->{stderr}" if $result->{exit};

    return 1;
}

sub uninstall {
    my ($self) = @_;

    my $script = <<'SCRIPT';
if [ -f /usr/local/bin/k3s-uninstall.sh ]; then
    /usr/local/bin/k3s-uninstall.sh
elif [ -f /usr/local/bin/k3s-agent-uninstall.sh ]; then
    /usr/local/bin/k3s-agent-uninstall.sh
fi
SCRIPT

    $self->ssh->run($script);
    return 1;
}

sub get_kubeconfig {
    my ($self) = @_;

    my $result = $self->ssh->run('cat /etc/rancher/k3s/k3s.yaml');
    croak "Failed to get kubeconfig" if $result->{exit};

    my $kubeconfig = $result->{stdout};

    # Replace localhost with actual IP
    my $host = $self->ssh->host;
    $kubeconfig =~ s/127\.0\.0\.1/$host/g;

    return $kubeconfig;
}

sub get_token {
    my ($self) = @_;

    my $result = $self->ssh->run('cat /var/lib/rancher/k3s/server/node-token');
    return undef if $result->{exit};

    my $token = $result->{stdout};
    chomp $token;
    return $token;
}

sub is_installed {
    my ($self) = @_;

    my $result = $self->ssh->run('command -v k3s');
    return $result->{exit} == 0;
}

sub _prepare_node {
    my ($self) = @_;

    my $script = <<'SCRIPT';
#!/bin/bash
set -e

# Ensure sbin paths are available
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Disable swap
swapoff -a || true
sed -i '/swap/d' /etc/fstab || true

# Load kernel modules
modprobe br_netfilter || true
modprobe overlay || true

cat > /etc/modules-load.d/k3s.conf <<EOF
br_netfilter
overlay
EOF

# Sysctl settings
cat > /etc/sysctl.d/99-k3s.conf <<EOF
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF

sysctl --system > /dev/null 2>&1

echo "Node prepared successfully"
SCRIPT

    my $result = $self->ssh->run_script($script);
    if ($result->{exit}) {
        die "Failed to prepare node: $result->{stderr}\n";
    }
}

sub _wait_for_k3s {
    my ($self, $timeout) = @_;
    $timeout //= 120;

    my $start = time;
    while (time - $start < $timeout) {
        my $result = $self->ssh->run('export PATH="/usr/local/bin:$PATH"; kubectl get nodes 2>/dev/null');
        return 1 if $result->{exit} == 0;
        sleep 5;
    }

    croak "Timeout waiting for k3s to be ready";
}

sub _generate_token {
    my ($self) = @_;

    # Generate secure token
    my $result = $self->ssh->run('head -c 48 /dev/urandom | base64 | tr -d "\n+/="');
    return $result->{stdout} if $result->{exit} == 0;

    # Fallback to local generation

    my $bytes = '';
    open my $fh, '<', '/dev/urandom' or croak "Can't open /dev/urandom: $!";
    read $fh, $bytes, 48;
    close $fh;
    my $token = MIME::Base64::encode_base64($bytes, '');
    $token =~ tr/+\///d;
    return substr($token, 0, 48);
}

1;

__END__

=head1 NAME

OCP::K3s - K3s installation and management

=head1 SYNOPSIS

    use OCP::K3s;
    use OCP::SSH;

    my $ssh = OCP::SSH->new(host => '1.2.3.4');
    my $k3s = OCP::K3s->new(ssh => $ssh);

    # Install server (first control plane)
    my $result = $k3s->install_server();
    print "Token: $result->{token}\n";
    print "Kubeconfig: $result->{kubeconfig}\n";

    # Install agent (worker)
    $k3s->install_agent($server_url, $token);

=cut

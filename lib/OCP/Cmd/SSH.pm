package OCP::Cmd::SSH;
# ABSTRACT: SSH into cluster nodes with admin key

use Moo;
use MooX::Cmd;
use MooX::Options;
use OCP;
use OCP::Config;
use OCP::Keys;
use OCP::Kubernetes;
use OCP::Password;
use OCP::Secrets;
use OCP::SSH;
use Path::Tiny qw(path);
use File::Temp;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

option node => (
    is     => 'ro',
    format => 's',
    doc    => 'Node name or IP to SSH into',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $config_file = $self->ocp->config;
    my $config = OCP::Config->new(file => $config_file);

    unless ($config->cluster_exists) {
        die "No cluster deployed yet. Run 'ocp apply' first.\n";
    }

    my @positional = grep { !/^--/ } @$args;
    my $node_arg = $self->node // $positional[0];
    unless ($node_arg) {
        die "Usage: ocp ssh --node <name|ip>\n" .
            "       ocp ssh <name|ip>\n";
    }

    print "╔═══════════════════════════════════════════════════════════════╗\n";
    print "║  ADMIN-SSH ACCESS (requires PIN2)                            ║\n";
    print "╚═══════════════════════════════════════════════════════════════╝\n\n";

    # Admin authentication
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    $secrets->ensure_age_key();

    my $keys = OCP::Keys->new(project_dir => $config->project_dir);
    my $pin2 = OCP::Password::prompt_password("Enter PIN2 (admin-key): ");

    my $admin_key = $keys->get_admin_key($pin2);
    unless ($admin_key) {
        die "ERROR: Wrong PIN2 or no admin-key found!\n";
    }

    print "[ok] admin-key decrypted: $admin_key->{name}\n";

    # Determine target host
    my $target_host;

    # Try to find node in spec
    my $spec = $config->spec;
    my $cp_spec = $spec->{controlPlanes};

    # Check if it's a control plane node
    if ($node_arg eq 'police1' || $node_arg =~ /^police\d+$/ || $node_arg =~ /^cp/) {
        if ($cp_spec->{provider} eq 'ssh') {
            $target_host = $cp_spec->{host};
        } elsif ($cp_spec->{provider} eq 'hetzner') {
            # Look up the node's IP via the Kubernetes API
            print "[..] Looking up control plane IP via Kubernetes API...\n";
            $target_host = $self->_lookup_node_ip($secrets, $node_arg);
        }
    } else {
        # Assume it's an IP or hostname
        $target_host = $node_arg;
    }

    unless ($target_host) {
        die "ERROR: Could not determine host for node: $node_arg\n";
    }

    print "[ok] Target: $target_host\n";
    print "[..] Connecting...\n\n";

    # Write admin key to temp file
    my $key_file = File::Temp->new(SUFFIX => '.key', UNLINK => 1);
    print $key_file $admin_key->{private};
    close $key_file;
    chmod 0600, $key_file->filename;

    # SSH via OCP::SSH
    my $ssh = OCP::SSH->new(
        host     => $target_host,
        key_file => $key_file->filename,
    );
    $ssh->interactive;
}

sub _lookup_node_ip {
    my ($self, $secrets, $node_name) = @_;

    return undef unless $secrets->has_kubeconfig;

    my $kubeconfig = $secrets->read_kubeconfig
        or return undef;

    my $k8s = OCP::Kubernetes->new(kubeconfig => $kubeconfig);

    for my $node (@{ $k8s->list_nodes }) {
        my $name = $k8s->node_name($node);
        next unless $name =~ /\Q$node_name\E/i;

        my $ip = $k8s->node_external_ip($node);
        return $ip if $ip;

        $ip = $k8s->node_internal_ip($node);
        return $ip if $ip;
    }

    return undef;
}

1;

__END__

=head1 NAME

OCP::Cmd::SSH - SSH into cluster nodes with admin-key

=head1 SYNOPSIS

    # SSH into control plane
    ocp ssh police1

    # SSH into node by IP
    ocp ssh 1.2.3.4

    # SSH with --node flag
    ocp ssh --node worker-1

=head1 DESCRIPTION

Connects to cluster nodes via SSH using the admin-ssh key (requires PIN2).

B<Security:> admin-key is protected with PIN2 (password). Only admins with
PIN2 can SSH into nodes. Robocop controller uses robo-key and cannot access
control planes!

=head1 OPTIONS

=head2 --node <name|ip>

Node name or IP address to SSH into.

=cut

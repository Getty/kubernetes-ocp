package OCP::Cmd::SSH;
# ABSTRACT: SSH into cluster nodes with admin key

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use File::Temp;

our $VERSION = '0.1.0';

option node => (
    is     => 'ro',
    format => 's',
    doc    => 'Node name or IP to SSH into',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $config_file = $chain->[0]->config;
    my $config = OCP::Config->new(file => $config_file);

    unless ($config->cluster_exists) {
        die "No cluster deployed yet. Run 'ocp apply' first.\n";
    }

    my $node_arg = $self->node // $args->[0];
    unless ($node_arg) {
        die "Usage: ocp ssh --node <name|ip>\n" .
            "       ocp ssh <name|ip>\n";
    }

    print "╔═══════════════════════════════════════════════════════════════╗\n";
    print "║  ADMIN-SSH ACCESS (requires PIN2)                            ║\n";
    print "╚═══════════════════════════════════════════════════════════════╝\n\n";

    # Admin authentication
    require OCP::Keys;
    require OCP::Password;
    require OCP::Secrets;

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
            # Need to get IP from Hetzner or kubectl
            print "[..] Looking up control plane IP via kubectl...\n";
            $target_host = $self->_get_node_ip_from_kubectl($node_arg);
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

    # SSH!
    exec('ssh', '-i', $key_file->filename, '-o', 'StrictHostKeyChecking=no', "root\@$target_host");
}

sub _get_node_ip_from_kubectl {
    my ($self, $node_name) = @_;

    # Get nodes from kubectl
    my $json = `kubectl get nodes -o json 2>/dev/null`;
    return undef unless $json;

    require JSON::MaybeXS;
    my $data = JSON::MaybeXS->new->decode($json);

    for my $node (@{$data->{items} // []}) {
        my $name = $node->{metadata}{name};
        next unless $name =~ /$node_name/i;

        # Get external IP
        for my $addr (@{$node->{status}{addresses} // []}) {
            if ($addr->{type} eq 'ExternalIP') {
                return $addr->{address};
            }
        }

        # Fallback to internal IP
        for my $addr (@{$node->{status}{addresses} // []}) {
            if ($addr->{type} eq 'InternalIP') {
                return $addr->{address};
            }
        }
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

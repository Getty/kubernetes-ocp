package OCP::Cmd::InjectKey;
# ABSTRACT: Inject robocop SSH key into memory (requires admin approval)

use Moo;
use MooX::Cmd;
use MooX::Options;
use OCP;
use Path::Tiny qw(path);
use IO::Socket::INET;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

sub execute {
    my ($self, $args, $chain) = @_;

    my $config_file = $self->ocp->config;
    my $config = OCP::Config->new(file => $config_file);

    unless ($config->cluster_exists) {
        die "No cluster deployed yet. Run 'ocp apply' first.\n";
    }

    print "╔═══════════════════════════════════════════════════════════════╗\n";
    print "║  ROBO-KEY INJECTION (requires admin approval via PIN2)       ║\n";
    print "╚═══════════════════════════════════════════════════════════════╝\n\n";

    print "This will inject the robo-ssh key into robocop's memory.\n";
    print "The key will only exist in RAM, never on persistent disk!\n\n";

    # Admin authentication required!
    require OCP::Keys;
    require OCP::Password;
    require OCP::Secrets;

    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    $secrets->ensure_age_key();

    my $keys = OCP::Keys->new(project_dir => $config->project_dir);
    my $pin2 = OCP::Password::prompt_password("Enter PIN2 (admin approval): ");

    my $admin_key = $keys->get_admin_key($pin2);
    unless ($admin_key) {
        die "ERROR: Wrong PIN2! Admin approval denied.\n";
    }

    print "[ok] Admin authenticated: $admin_key->{name}\n\n";

    # Get robo-key (automation key, no PIN2 needed for reading!)
    print "[..] Decrypting robo-ssh key from keys.yaml...\n";

    my $robo_key = $keys->get_automation_key();
    unless ($robo_key) {
        die "ERROR: No robo-ssh key found in keys.yaml!\n" .
            "       Run 'ocp init' to generate keys.\n";
    }

    print "[ok] robo-key found: $robo_key->{name}\n";
    print "     Purpose: $robo_key->{purpose}\n";
    print "     Type: $robo_key->{type}\n\n";

    # Check if robocop pod exists
    print "[..] Checking if robocop is deployed...\n";

    my $pod_check = `kubectl get pod -n ocp-system -l app=robocop -o name 2>/dev/null`;
    chomp $pod_check;

    unless ($pod_check) {
        die "ERROR: Robocop pod not found!\n" .
            "       Deploy robocop first: ocp deploy robocop\n";
    }

    my ($pod_name) = $pod_check =~ m{pod/(.+)};
    print "[ok] Robocop pod found: $pod_name\n\n";

    # Setup port-forward
    print "[..] Setting up port-forward to robocop pod...\n";

    my $local_port = 19999;
    my $pf_pid = fork();

    if ($pf_pid == 0) {
        # Child: run kubectl port-forward
        open(STDERR, '>', '/dev/null');  # Suppress kubectl output
        exec('kubectl', 'port-forward', "-n", "ocp-system", "pod/$pod_name", "$local_port:9999");
        exit(1);
    }

    # Parent: wait for port-forward to be ready
    sleep(3);

    print "[ok] Port-forward established on localhost:$local_port\n";
    print "[..] Injecting SSH key into robocop memory...\n";

    # Connect and send key
    my $socket = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $local_port,
        Proto    => 'tcp',
        Timeout  => 10,
    );

    unless ($socket) {
        kill 'TERM', $pf_pid;
        waitpid($pf_pid, 0);
        die "ERROR: Could not connect to robocop: $!\n";
    }

    # Send private key
    print $socket $robo_key->{private};
    close $socket;

    print "[ok] robo-ssh key injected into robocop memory!\n";
    print "[ok] Robocop will create CRIU checkpoint...\n\n";

    # Cleanup port-forward
    kill 'TERM', $pf_pid;
    waitpid($pf_pid, 0);

    print "╔═══════════════════════════════════════════════════════════════╗\n";
    print "║  ROBOCOP ACTIVATED!                                          ║\n";
    print "╚═══════════════════════════════════════════════════════════════╝\n\n";

    print "Robocop can now provision worker nodes automatically.\n";
    print "The robo-key is stored in robocop's memory only (RAM).\n\n";

    print "Security notes:\n";
    print "  • robo-key is NOT in Kubernetes Secret (not on disk!)\n";
    print "  • Robocop created CRIU checkpoint in /dev/shm (RAM)\n";
    print "  • If robocop crashes, it restores from checkpoint\n";
    print "  • If node reboots, you need to re-inject the key\n\n";

    print "To add worker nodes:\n";
    print "  kubectl apply -f worker-pool.yaml\n\n";
}

1;

__END__

=head1 NAME

OCP::Cmd::InjectKey - Inject robo-ssh key into robocop memory

=head1 SYNOPSIS

    # Inject robo-key (requires admin PIN2)
    ocp inject-key

=head1 DESCRIPTION

Injects the robo-ssh automation key into robocop controller's memory.

B<Security Model:>

=over 4

=item 1. Requires admin approval (PIN2)

=item 2. Key injected into RAM only (never persistent disk)

=item 3. Robocop creates CRIU checkpoint in /dev/shm (RAM)

=item 4. Crash recovery via checkpoint (no re-injection needed)

=item 5. Node reboot → checkpoint lost, need admin to re-inject

=back

This ensures robocop can only be activated by an admin, and the SSH key
is never written to persistent storage.

=cut

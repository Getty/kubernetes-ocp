package OCP::Robocop;
# ABSTRACT: Kubernetes controller for automated worker management

use Moo;
use IO::Async::Loop;
use IO::Async::Listener;
use IO::Async::Stream;
use Path::Tiny qw(path);
use Carp qw(croak);

our $VERSION = '0.1.0';

has checkpoint_dir => (
    is      => 'ro',
    default => sub { $ENV{CHECKPOINT_DIR} // '/dev/shm/robocop' },
);

has checkpoint_file => (
    is      => 'lazy',
    builder => sub { path(shift->checkpoint_dir)->child('robocop.criu') },
);

has ssh_key => (
    is  => 'rw',
    doc => 'SSH private key (stored in memory only!)',
);

has loop => (
    is      => 'lazy',
    builder => sub { IO::Async::Loop->new },
);

sub run {
    my ($self) = @_;

    print "[robocop] Starting...\n";

    # Try to restore from CRIU checkpoint first
    if (-f $self->checkpoint_file) {
        print "[robocop] Found checkpoint, attempting restore...\n";
        if ($self->restore_from_checkpoint) {
            print "[robocop] Restored successfully! SSH key in memory.\n";
            return $self->start_reconciliation_loop;
        } else {
            print "[robocop] Checkpoint restore failed, waiting for key injection...\n";
        }
    }

    # No checkpoint or restore failed - wait for key injection
    print "[robocop] Waiting for SSH key injection...\n";
    print "[robocop] Listening on port 9999 for key injection...\n";

    $self->wait_for_key_injection;

    # Key received, create checkpoint
    print "[robocop] SSH key received, creating CRIU checkpoint...\n";
    $self->create_checkpoint;
    print "[robocop] Checkpoint created at " . $self->checkpoint_dir . "\n";

    # Start working
    $self->start_reconciliation_loop;
}

sub wait_for_key_injection {
    my ($self) = @_;

    my $listener = IO::Async::Listener->new(
        on_stream => sub {
            my ($self_listener, $stream) = @_;

            $stream->configure(
                on_read => sub {
                    my ($stream, $buffref, $eof) = @_;

                    # Receive SSH key
                    my $ssh_key = $$buffref;
                    $$buffref = '';

                    # Store in memory only!
                    $self->{ssh_key} = $ssh_key;

                    print "[robocop] SSH key received in memory! (" . length($ssh_key) . " bytes)\n";

                    # Stop listening
                    $self->loop->stop;

                    return 0;
                },
            );

            $self->loop->add($stream);
        },
    );

    $self->loop->add($listener);

    $listener->listen(
        service  => 9999,
        socktype => 'stream',
    )->get;

    print "[robocop] Listening on 0.0.0.0:9999\n";

    # Block until key received
    $self->loop->run;
}

sub create_checkpoint {
    my ($self) = @_;

    # Ensure checkpoint directory exists
    my $checkpoint_dir = path($self->checkpoint_dir);
    $checkpoint_dir->mkpath unless -d $checkpoint_dir;

    # Fork: child freezes for checkpoint, parent continues
    my $pid = fork();

    if ($pid == 0) {
        # Child: freeze for CRIU snapshot
        print "[robocop-checkpoint] Freezing for CRIU snapshot (PID $$)...\n";
        sleep(5);  # Give CRIU time to dump
        exit(0);
    }

    # Parent: trigger CRIU checkpoint of child
    my @cmd = (
        'criu', 'dump',
        '--images-dir'  => $checkpoint_dir->stringify,
        '--tree'        => $pid,
        '--shell-job',
        '--leave-running',  # Don't kill the process!
    );

    print "[robocop] Running CRIU dump: " . join(' ', @cmd) . "\n";

    my $ret = system(@cmd);
    if ($ret != 0) {
        warn "[robocop] WARNING: CRIU checkpoint failed: $?\n";
        warn "[robocop] Continuing without checkpoint (key injection required on restart)\n";
    } else {
        print "[robocop] CRIU checkpoint successful!\n";
    }

    waitpid($pid, 0);

    return $ret == 0;
}

sub restore_from_checkpoint {
    my ($self) = @_;

    my $checkpoint_dir = $self->checkpoint_dir;

    return 0 unless -d $checkpoint_dir;

    # Restore via CRIU
    my @cmd = (
        'criu', 'restore',
        '--images-dir' => $checkpoint_dir,
        '--shell-job',
    );

    print "[robocop] Running CRIU restore: " . join(' ', @cmd) . "\n";

    my $ret = system(@cmd);

    if ($ret == 0) {
        print "[robocop] CRIU restore successful!\n";
        return 1;
    } else {
        warn "[robocop] CRIU restore failed: $?\n";
        return 0;
    }
}

sub start_reconciliation_loop {
    my ($self) = @_;

    unless ($self->ssh_key) {
        croak "No SSH key in memory! Cannot start reconciliation loop.";
    }

    print "[robocop] Starting reconciliation loop...\n";
    print "[robocop] SSH key loaded: " . length($self->ssh_key) . " bytes\n";

    # TODO: Watch for Node and NodePool CRDs
    # TODO: Reconcile desired state with actual state
    # TODO: Provision/deprovision worker nodes

    print "[robocop] Reconciliation loop not yet implemented!\n";
    print "[robocop] Sleeping forever (placeholder)...\n";

    # For now, just sleep
    while (1) {
        sleep(60);
        print "[robocop] Still alive (SSH key in memory: " . (defined $self->ssh_key ? "YES" : "NO") . ")\n";
    }
}

1;

__END__

=head1 NAME

OCP::Robocop - Kubernetes controller for automated worker management

=head1 SYNOPSIS

    use OCP::Robocop;

    my $robocop = OCP::Robocop->new;
    $robocop->run;  # Starts controller, waits for key injection

=head1 DESCRIPTION

Robocop is the in-cluster Kubernetes controller that manages worker nodes.

B<Security Model:>

=over 4

=item 1. Runs as Deployment in the cluster

=item 2. Receives robo-ssh key via TCP socket (admin approval required!)

=item 3. Stores key in memory only (never on disk!)

=item 4. Creates CRIU checkpoint in /dev/shm (RAM, tmpfs)

=item 5. Crash recovery via CRIU restore (no re-injection needed)

=item 6. Node reboot → checkpoint lost, need admin to re-inject

=item 7. CANNOT access control planes (robo-key not authorized!)

=back

=head1 WORKFLOW

    # 1. Deploy robocop (no key)
    ocp deploy robocop

    # 2. Inject robo-key (requires PIN2)
    ocp inject-key

    # 3. Robocop creates CRIU checkpoint
    # 4. Robocop provisions workers via CRDs

=head1 CRDs

Robocop watches for these CRDs:

=over 4

=item * B<OCPNode> - Individual nodes (SSH provider, Hetzner, GPU servers)

=item * B<OCPNodeProvider> - Infrastructure provider configuration (Hetzner, SSH)

=back

=cut

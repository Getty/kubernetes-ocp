package OCP::Exec;
# ABSTRACT: run a child process, capturing stdout and stderr without deadlock

use strict;
use warnings;
use Carp qw(croak);
use Errno qw(EINTR);
use Exporter qw(import);
use IPC::Open3 qw(open3);
use IO::Select;
use POSIX qw(WNOHANG);
use Symbol qw(gensym);

our @EXPORT_OK = qw(capture_command);

# Conventional exit code for "killed because it ran past its deadline",
# matching GNU coreutils timeout(1). Callers only test truthiness, but a
# recognisable number helps when one gets printed.
our $TIMEOUT_EXIT = 124;

# capture_command(\@cmd, %opts) -> { stdout, stderr, exit, signal, timed_out }
#
#   timeout => seconds before the child is killed (undef = no deadline)
#   stdin   => scalar sent to the child's stdin, then closed (optional)
#
# One place gets the open3 read loop right, so OCP::SSH and every ExistingHost
# provider (Local, SSH) share it instead of each carrying its own copy that
# drifts. The three defects this fixes, all present in the hand-rolled
# serial-read version it replaces:
#
#   R1 Deadlock. Reading stdout to EOF before touching stderr hangs the moment
#      the child writes more than a pipe buffer (~64KB) to stderr before it
#      finishes stdout: the child blocks on its stderr write, we block reading a
#      stdout it will never close. IO::Select drains both as data arrives.
#   R2 No timeout. A wedged child hung `ocp apply` forever. A deadline bounds it.
#   R3 Signal death read as success. A child killed by a signal decodes to 0
#      through `>> 8`, so the old code reported it as exit 0. The signal lives
#      in the low 7 bits; report 128 + signal, the shell convention.
sub capture_command {
    my ($cmd, %opts) = @_;
    croak 'capture_command needs an arrayref command'
        unless ref $cmd eq 'ARRAY';

    my $timeout = $opts{timeout};   # undef -> no deadline
    my $stdin   = $opts{stdin};

    my $err = gensym;
    my $pid = open3(my $in, my $out, $err, @$cmd);

    # Feed stdin up front, then close it. Inputs here are small (a shell script
    # at most); a child that outruns the stdin pipe before we start draining is
    # not a case this layer needs to serve.
    print {$in} $stdin if defined $stdin;
    close $in;

    my ($stdout, $stderr) = ('', '');
    my $sel      = IO::Select->new($out, $err);
    my $deadline = defined $timeout ? time + $timeout : undef;
    my $timed_out = 0;

    while ($sel->count) {
        my $wait;
        if (defined $deadline) {
            $wait = $deadline - time;
            if ($wait <= 0) { $timed_out = 1; last }
        }
        my @ready = $sel->can_read($wait);
        unless (@ready) {
            $timed_out = 1 if defined $deadline && time >= $deadline;
            last if $timed_out;
            next;
        }
        for my $fh (@ready) {
            my $chunk = '';
            my $n = sysread($fh, $chunk, 65536);
            if (!defined $n) {
                # Interrupted mid-read (a caller's signal handler, e.g. the
                # $SIG{INT} wait_for_ssh installs): retry, keep the fd. Only a
                # real read error ends the pipe. Mirrors the can_read handling.
                next if $! == EINTR;
                $sel->remove($fh);
                next;
            }
            if ($n == 0) {   # EOF: this pipe is done
                $sel->remove($fh);
                next;
            }
            if ($fh == $out) { $stdout .= $chunk } else { $stderr .= $chunk }
        }
    }

    close $out;
    close $err;

    if ($timed_out) {
        _terminate($pid);
    } elsif (defined $deadline) {
        # The read loop can exit with time to spare: a child that closes both
        # pipes but keeps running hits EOF here while still alive. Reap against
        # the SAME deadline rather than blocking forever on waitpid($pid, 0);
        # if it outlives the deadline, kill it down the timeout path.
        while (waitpid($pid, WNOHANG) != $pid) {
            if (time >= $deadline) {
                $timed_out = 1;
                _terminate($pid);
                last;
            }
            select undef, undef, undef, 0.1;
        }
    } else {
        waitpid($pid, 0);
    }

    my $signal = $? & 127;
    # A timeout means we sent TERM/KILL, so $? carries signal 15/9 -- our doing,
    # not the child dying by a signal of its own. Report no signal (exit is 124).
    $signal = 0 if $timed_out;
    my $exit
        = $timed_out ? $TIMEOUT_EXIT
        : $signal    ? 128 + $signal
        :              $? >> 8;

    return {
        stdout    => $stdout,
        stderr    => $stderr,
        exit      => $exit,
        signal    => $signal,
        timed_out => $timed_out ? 1 : 0,
    };
}

# TERM, a short grace, then KILL. The child is already past its deadline; the
# point is to get the call to return, not to keep waiting on a wedged process.
sub _terminate {
    my ($pid) = @_;
    kill 'TERM', $pid;
    for (1 .. 30) {   # ~3s grace
        return if waitpid($pid, WNOHANG) == $pid;
        select undef, undef, undef, 0.1;
    }
    kill 'KILL', $pid;
    waitpid($pid, 0);
}

1;

__END__

=head1 NAME

OCP::Exec - run a child process, capturing stdout and stderr without deadlock

=head1 SYNOPSIS

    use OCP::Exec qw(capture_command);

    my $r = capture_command(['sh', '-c', 'uptime'], timeout => 30);
    print $r->{stdout};
    die "failed" if $r->{exit};

    # Feed a script on stdin
    my $r2 = capture_command(['bash', '-s'], stdin => $script);

=head1 DESCRIPTION

C<capture_command> runs a command, drains its stdout and stderr concurrently
(so a chatty child can never deadlock the parent), enforces an optional
deadline, and decodes the wait status so that a signal-killed child is reported
as a failure instead of as exit 0.

It returns a hashref shaped like L<OCP::SSH/run>: C<stdout>, C<stderr> and
C<exit>, plus C<signal> (the terminating signal number, 0 if none) and
C<timed_out> (true when the deadline killed the child).

The C<exit> field is the child's exit code for a normal exit, C<128 + signal>
for a signal death, and C<$OCP::Exec::TIMEOUT_EXIT> (124) for a timeout -- so
existing callers that only test C<< $r->{exit} >> for truthiness treat all
three failure modes as failures.

=cut

package OCP::SSH;
# ABSTRACT: SSH operations for OCP

use Moo;
use Carp qw(croak);
use OCP::Exec qw(capture_command);
use OCP::KnownHosts;

has host => (
    is       => 'ro',
    required => 1,
);

has user => (
    is      => 'ro',
    default => 'root',
);

has port => (
    is      => 'ro',
    default => 22,
);

has key_file => (
    is      => 'ro',
    default => sub { $ENV{OCP_SSH_KEY} },
);

has connect_timeout => (
    is      => 'ro',
    default => 10,
);

# How long a single remote command may run before it is killed. Bounds a
# wedged child so it can't hang `ocp apply` forever; generous because the
# commands that go through here are short (a probe, a `cat`, the uninstall
# script) -- the minutes-long installs run through OCP::Rex, not this path.
# `our`-backed default so a test can shorten it without waiting the real thing.
has command_timeout => (
    is      => 'ro',
    default => 600,
);

# The known_hosts file this connection verifies against and records into
# (k168). The CLI exports the project's .ocp/known_hosts as OCP_KNOWN_HOSTS for
# the whole run; robocop falls back to its pod-local file. See OCP::KnownHosts.
has known_hosts => (
    is      => 'lazy',
    builder => sub { OCP::KnownHosts->default_file },
);

has _known_hosts => (
    is      => 'lazy',
    builder => sub { OCP::KnownHosts->new(file => $_[0]->known_hosts) },
);

# Central SSH options - ignore user config, use only our key.
#
# Host keys are trusted on first use (k168). accept-new records the key of a
# host the file does not know yet and refuses one that differs from what is
# recorded -- the second half is the point: StrictHostKeyChecking=no with
# /dev/null as the file, which stood here before, accepted anything and left
# nothing behind for Rex::LibSSH, which since 0.004 refuses a host it cannot
# find in known_hosts. The system-wide file is kept out for the same reason
# the user's ssh config is: the answer must not depend on the machine OCP runs
# on. Plain (unhashed) entries, so OCP::KnownHosts and a human can read them.
sub _ssh_opts {
    my ($self) = @_;
    return (
        '-F', '/dev/null',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'UserKnownHostsFile=' . $self->_ssh_path($self->known_hosts),
        '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'HashKnownHosts=no',
        '-o', 'IdentitiesOnly=yes',
        '-o', "ConnectTimeout=${\$self->connect_timeout}",
    );
}

# ssh splits UserKnownHostsFile on whitespace (it takes a list) and expands
# %-tokens in it; a project directory with either would otherwise point ssh at
# the wrong file.
sub _ssh_path {
    my ($self, $file) = @_;
    $file =~ s/%/%%/g;
    return $file =~ /\s/ ? '"' . $file . '"' : $file;
}

# Every non-interactive ssh goes through here: the known_hosts directory is
# made first, a changed host key ends the run instead of reading as "not
# reachable", and the first successful contact with a host is announced with
# the fingerprint that was trusted.
sub _capture {
    my ($self, $cmd, %opt) = @_;

    my $kh = $self->_known_hosts;
    $kh->ensure_dir;
    $self->{_was_known} //= $kh->knows($self->host, $self->port);

    my $result = capture_command($cmd, %opt);
    $self->_check_host_key($result);

    if (!$self->{_was_known} && !$self->{_announced} && !$result->{exit}
        && $kh->knows($self->host, $self->port)) {
        $self->{_announced} = 1;
        # Diagnosis, not payload: STDERR, where robocop's log and a human
        # running `ocp apply` both see it, and a piped STDOUT stays clean.
        print STDERR 'Trusted host key of ' . $self->host
            . ' on first contact, recorded in ' . $kh->file . ': '
            . join(', ', $kh->fingerprints($self->host, $self->port)) . "\n";
    }

    return $result;
}

sub _check_host_key {
    my ($self, $result) = @_;
    return unless ($result->{exit} // 0) == 255;
    my $stderr = $result->{stderr} // '';
    return unless $stderr =~ /REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed/;

    my $kh = $self->_known_hosts;
    die 'Host key of ' . $self->host . ' does not match the one recorded in '
      . $kh->file . ".\n"
      . "Either the machine was reinstalled or replaced, or something is intercepting\n"
      . "the connection. If the machine was rebuilt on purpose, remove the stale entry\n"
      . "and run again:\n"
      . '  ' . $kh->remove_hint($self->host, $self->port) . "\n";
}

sub _build_ssh_cmd {
    my ($self, @extra) = @_;

    my @cmd = ('ssh');
    push @cmd, $self->_ssh_opts;
    push @cmd, '-o', 'LogLevel=ERROR';
    push @cmd, '-o', 'BatchMode=yes';
    push @cmd, '-p', $self->port if $self->port != 22;
    push @cmd, '-i', $self->key_file if $self->key_file;
    push @cmd, $self->user . '@' . $self->host;
    push @cmd, @extra;

    return @cmd;
}

sub _build_scp_cmd {
    my ($self) = @_;

    $self->_known_hosts->ensure_dir;

    my @cmd = ('scp');
    push @cmd, $self->_ssh_opts;
    push @cmd, '-o', 'LogLevel=ERROR';
    push @cmd, '-P', $self->port if $self->port != 22;
    push @cmd, '-i', $self->key_file if $self->key_file;

    return @cmd;
}

sub run {
    my ($self, $command) = @_;

    my @ssh_cmd = $self->_build_ssh_cmd($command);
    return $self->_capture(\@ssh_cmd, timeout => $self->command_timeout);
}

sub run_script {
    my ($self, $script) = @_;

    # bash -s reads the script from stdin.
    my @ssh_cmd = $self->_build_ssh_cmd('bash', '-s');
    return $self->_capture(\@ssh_cmd,
        stdin   => $script,
        timeout => $self->command_timeout,
    );
}

# Interactive SSH session (replaces current process via exec). ssh itself
# prints the changed-key warning here; there is nothing left to catch after exec.
sub interactive {
    my ($self) = @_;

    $self->_known_hosts->ensure_dir;

    my @cmd = ('ssh');
    push @cmd, $self->_ssh_opts;
    push @cmd, '-p', $self->port if $self->port != 22;
    push @cmd, '-i', $self->key_file if $self->key_file;
    push @cmd, $self->user . '@' . $self->host;

    exec(@cmd);
}

sub scp_to {
    my ($self, $local_path, $remote_path) = @_;

    my @cmd = $self->_build_scp_cmd;
    push @cmd, $local_path;
    push @cmd, $self->user . '@' . $self->host . ':' . $remote_path;

    system(@cmd) == 0 or croak "SCP failed: $?";
    return 1;
}

sub scp_from {
    my ($self, $remote_path, $local_path) = @_;

    my @cmd = $self->_build_scp_cmd;
    push @cmd, $self->user . '@' . $self->host . ':' . $remote_path;
    push @cmd, $local_path;

    system(@cmd) == 0 or croak "SCP failed: $?";
    return 1;
}

# No timeout parameter on purpose. SSH's own ConnectTimeout (the
# C<connect_timeout> attribute) bounds this call -- it is a single probe, not a
# wait -- so any number the caller passed in would have been cosmetic. The
# parameter used to be there, set with `$timeout //= 5` and never read: a
# caller thinking "give it 10 seconds" actually got one probe with a 10 s
# ConnectTimeout, and was told its number meant something (k112).
sub is_reachable {
    my ($self) = @_;

    my $result = $self->run('true');
    return $result->{exit} == 0;
}

# Make sure the host's key is in known_hosts by contacting it once. OCP::Rex
# calls this before handing a host to Rex::LibSSH, which verifies against the
# same file but cannot record a new key (k168). A changed key dies in _capture
# like on every other call; a host that cannot be reached dies here with ssh's
# own reason, since the Rex run after it could only fail with a vaguer one.
sub learn_host_key {
    my ($self) = @_;

    my $result = $self->run('true');
    return 1 unless $result->{exit};

    my $reason = $result->{stderr} // '';
    $reason =~ s/\s+\z//;
    die 'Cannot reach ' . $self->host . ' over SSH to record its host key'
      . (length $reason ? ': ' . $reason : '') . "\n";
}

# How long a machine that is coming up may take to answer on SSH.
#
# One number for one wait. Both callers that wait for a boot do the same thing
# to the same kind of freshly created machine -- OCP::Cmd::Apply::Bootstrap for
# the control plane, OCP::Node for every worker -- and both used to restate
# this module's default themselves: 120 there, 60 here. Nothing justified the
# half budget, and it was the terminal one: OCP::Node marks the node Failed,
# which is final, so a server whose sshd needed 70s was lost for good and kept
# billing (k109). The worker was the outlier; 120 is what the
# control-plane path has always spent on exactly this wait.
#
# Waiting for a boot means passing nothing and taking this. A caller asking a
# different question still names its own budget -- OCP::Provider::SSH's
# is_reachable probes a host that is supposed to be up already and gives it
# 10s, which is a reachability check, not a wait.
#
# `our` so a test can shorten it without timing the real thing.
our $WAIT_TIMEOUT = 120;

sub wait_for_ssh {
    my ($self, $timeout, $interval) = @_;
    $timeout //= $WAIT_TIMEOUT;
    $interval //= 2;

    # Allow Ctrl-C to interrupt
    my $interrupted = 0;
    local $SIG{INT} = sub {
        $interrupted = 1;
        die "Interrupted by user (Ctrl-C)\n";
    };

    my $start = time;
    while (time - $start < $timeout) {
        return 1 if $self->is_reachable;
        sleep $interval;
        last if $interrupted;
    }

    die "SSH not reachable on ${\$self->host} after ${timeout}s\n" if !$interrupted;
}

1;

__END__

=head1 NAME

OCP::SSH - SSH operations for OCP using IPC::Open3

=head1 SYNOPSIS

    use OCP::SSH;

    my $ssh = OCP::SSH->new(
        host     => '192.168.1.100',
        user     => 'root',
        key_file => '.ocp/id_ed25519',
    );

    # Wait for a machine that is booting to answer
    $ssh->wait_for_ssh;

    # Run a command
    my $result = $ssh->run('uname -a');
    print $result->{stdout};

    # Run a multi-line script via stdin
    my $result = $ssh->run_script(<<'SCRIPT');
    #!/bin/bash
    set -e
    apt-get update
    apt-get install -y curl
    SCRIPT

    # Copy files
    $ssh->scp_to('/local/file', '/remote/path');
    $ssh->scp_from('/remote/file', '/local/path');

    # Interactive session (replaces process)
    $ssh->interactive;

=head1 DESCRIPTION

Central SSH module for OCP. All SSH connections go through this module
to ensure consistent options: ignores user F<~/.ssh/config> (via C<-F /dev/null>),
verifies host keys against OCP's own known_hosts file, and uses only the
explicitly provided key.

=head2 Host keys

Host keys are trusted on first use (k168). C<known_hosts> (default:
L<OCP::KnownHosts/default_file> -- C<OCP_KNOWN_HOSTS>, which C<ocp> sets to the
project's F<.ocp/known_hosts>) is handed to ssh with
C<StrictHostKeyChecking=accept-new>: the first successful contact records the
key and announces its fingerprint on STDERR, every later one must present the
same key. A different key makes C<run>, C<run_script>, C<is_reachable> and
C<wait_for_ssh> die at once with the C<ssh-keygen -R> command that removes the
stale entry -- never a silent "not reachable".

C<learn_host_key> contacts the host once so its key is recorded. L<OCP::Rex>
calls it before Rex::LibSSH, which verifies against the same file but cannot
record a new key itself.

=head2 Waiting for a machine to come up

C<wait_for_ssh> called without an argument counts down from
C<$OCP::SSH::WAIT_TIMEOUT> (120 s). That is the budget for the same wait
everywhere it happens: L<OCP::Cmd::Apply::Bootstrap> after the control-plane
server reaches C<running>, and L<OCP::Node> after a worker does. Neither names
a number of its own — they used to, with 120 and 60, and the worker's half
budget failed nodes that were merely slow to boot (k109).

An explicit argument is for a different question. L<OCP::Provider::SSH>'s
C<is_reachable> passes 10: it probes a host that is supposed to be up already
and wants a quick no, not a boot wait.

=cut

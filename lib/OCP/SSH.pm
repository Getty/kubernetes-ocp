package OCP::SSH;
# ABSTRACT: SSH operations for OCP

use Moo;
use Carp qw(croak);
use IPC::Open3 qw(open3);
use Symbol qw(gensym);

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

# Central SSH options - ignore user config, use only our key
sub _ssh_opts {
    my ($self) = @_;
    return (
        '-F', '/dev/null',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'IdentitiesOnly=yes',
        '-o', "ConnectTimeout=${\$self->connect_timeout}",
    );
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

    my $err = gensym;
    my $pid = open3(my $in, my $out, $err, @ssh_cmd);

    close $in;

    my $stdout = do { local $/; <$out> };
    my $stderr = do { local $/; <$err> };

    close $out;
    close $err;

    waitpid($pid, 0);
    my $exit = $? >> 8;

    return {
        stdout => $stdout // '',
        stderr => $stderr // '',
        exit   => $exit,
    };
}

sub run_script {
    my ($self, $script) = @_;

    # Use bash -s to read script from stdin
    my @ssh_cmd = $self->_build_ssh_cmd('bash', '-s');

    my $err = gensym;
    my $pid = open3(my $in, my $out, $err, @ssh_cmd);

    # Send script to stdin
    print $in $script;
    close $in;

    my $stdout = do { local $/; <$out> };
    my $stderr = do { local $/; <$err> };

    close $out;
    close $err;

    waitpid($pid, 0);
    my $exit = $? >> 8;

    return {
        stdout => $stdout // '',
        stderr => $stderr // '',
        exit   => $exit,
    };
}

# Interactive SSH session (replaces current process via exec)
sub interactive {
    my ($self) = @_;

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
# ConnectTimeout, and was told its number meant something (karr #112).
sub is_reachable {
    my ($self) = @_;

    my $result = $self->run('true');
    return $result->{exit} == 0;
}

# How long a machine that is coming up may take to answer on SSH.
#
# One number for one wait. Both callers that wait for a boot do the same thing
# to the same kind of freshly created machine -- OCP::Cmd::Apply::Bootstrap for
# the control plane, OCP::Node for every worker -- and both used to restate
# this module's default themselves: 120 there, 60 here. Nothing justified the
# half budget, and it was the terminal one: OCP::Node marks the node Failed,
# which is final, so a server whose sshd needed 70s was lost for good and kept
# billing (karr #109). The worker was the outlier; 120 is what the
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
disables host key checking, and uses only the explicitly provided key.

=head2 Waiting for a machine to come up

C<wait_for_ssh> called without an argument counts down from
C<$OCP::SSH::WAIT_TIMEOUT> (120 s). That is the budget for the same wait
everywhere it happens: L<OCP::Cmd::Apply::Bootstrap> after the control-plane
server reaches C<running>, and L<OCP::Node> after a worker does. Neither names
a number of its own — they used to, with 120 and 60, and the worker's half
budget failed nodes that were merely slow to boot (karr #109).

An explicit argument is for a different question. L<OCP::Provider::SSH>'s
C<is_reachable> passes 10: it probes a host that is supposed to be up already
and wants a quick no, not a boot wait.

=cut

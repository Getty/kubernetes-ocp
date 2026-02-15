package OCP::SSH;
# ABSTRACT: SSH operations for OCP

use Moo;
use Carp qw(croak);
use IPC::Open3 qw(open3);
use Symbol qw(gensym);

our $VERSION = '0.1.0';

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

sub _build_ssh_cmd {
    my ($self, @extra) = @_;

    my @cmd = ('ssh');
    push @cmd, '-o', 'StrictHostKeyChecking=no';
    push @cmd, '-o', 'UserKnownHostsFile=/dev/null';
    push @cmd, '-o', 'LogLevel=ERROR';
    push @cmd, '-o', 'BatchMode=yes';
    push @cmd, '-o', "ConnectTimeout=${\$self->connect_timeout}";
    push @cmd, '-p', $self->port if $self->port != 22;
    push @cmd, '-i', $self->key_file if $self->key_file;
    push @cmd, $self->user . '@' . $self->host;
    push @cmd, @extra;

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

sub scp_to {
    my ($self, $local_path, $remote_path) = @_;

    my @cmd = ('scp');
    push @cmd, '-o', 'StrictHostKeyChecking=no';
    push @cmd, '-o', 'UserKnownHostsFile=/dev/null';
    push @cmd, '-o', 'LogLevel=ERROR';
    push @cmd, '-P', $self->port if $self->port != 22;
    push @cmd, '-i', $self->key_file if $self->key_file;
    push @cmd, $local_path;
    push @cmd, $self->user . '@' . $self->host . ':' . $remote_path;

    system(@cmd) == 0 or croak "SCP failed: $?";
    return 1;
}

sub scp_from {
    my ($self, $remote_path, $local_path) = @_;

    my @cmd = ('scp');
    push @cmd, '-o', 'StrictHostKeyChecking=no';
    push @cmd, '-o', 'UserKnownHostsFile=/dev/null';
    push @cmd, '-o', 'LogLevel=ERROR';
    push @cmd, '-P', $self->port if $self->port != 22;
    push @cmd, '-i', $self->key_file if $self->key_file;
    push @cmd, $self->user . '@' . $self->host . ':' . $remote_path;
    push @cmd, $local_path;

    system(@cmd) == 0 or croak "SCP failed: $?";
    return 1;
}

sub is_reachable {
    my ($self, $timeout) = @_;
    $timeout //= 5;

    my $result = $self->run('true');
    return $result->{exit} == 0;
}

sub wait_for_ssh {
    my ($self, $timeout, $interval) = @_;
    $timeout //= 120;
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
        key_file => '~/.ssh/id_rsa',
    );

    # Wait for SSH to be available
    $ssh->wait_for_ssh(60);

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

=cut

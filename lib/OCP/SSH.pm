package OCP::SSH::HostKeyChanged;
# ABSTRACT: The exception for a host key that differs from the recorded one

# A string would do for the CLI; OCP::Node needs to tell this failure from
# every other one (k171): a changed key leaves the node's phase alone and
# touches nothing, where "not reachable" fails the node. Stringifies to the
# operator-facing text, so everything that treated the error as a string still
# does.
use overload '""' => sub { $_[0]{text} }, fallback => 1;

sub new { my ($class, %args) = @_; return bless {%args}, $class }
sub host { $_[0]{host} }
sub port { $_[0]{port} // 22 }
sub file { $_[0]{file} }

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

# The key as the operator knows it ("the admin key 'admin-ssh' from
# keys.yaml"), for the one message that names it: a refusal in wait_for_ssh.
# key_file is regularly a temporary copy whose path means nothing to them
# (k226). Optional; without it the message names key_file, as before.
has key_label => (
    is => 'ro',
);

# Which of the two secure-mode keys key_file is (k209): 'admin' for the CLI,
# 'automation' for robocop's robo key. Optional, and only read by the refusal
# in wait_for_ssh: knowing the purpose, it can name the missing key and the
# command that prints it, instead of a generic "add the public key there".
# Absent -- dev mode's bootstrap key, or a caller that does not say -- the
# message stays the generic one.
has key_purpose => (
    is  => 'ro',
    isa => sub {
        croak __PACKAGE__.'->key_purpose must be admin, automation or operator, not '
            .(defined $_[0] ? "'$_[0]'" : 'undef')
            unless defined $_[0] && $_[0] =~ /\A(?:admin|automation|operator)\z/;
    },
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

# The one recogniser for "this name does not resolve" (k236), shared by the
# host probes (OCP::Role::Cmd), wait_for_ssh/learn_host_key here and, through
# the error text they die with, OCP::Node's status.message. It reads whatever
# a connection attempt printed: OpenSSH ("Could not resolve hostname X: Name or
# service not known", "...Temporary failure in name resolution"), libssh via
# Rex::Interface::Connection::LibSSH ("Failed to resolve hostname X (...)",
# carried in Rex's ERROR lines) and the libc getaddrinfo strings both wrap.
# A refused key never matches: sshd answered, the name was fine.
sub name_unresolved {
    my ($self, $text) = @_;
    return 0 unless defined $text && length $text;
    return $text =~ /(?:Could\s+not|Failed\s+to|Unable\s+to|Cannot)\s+resolve\s+(?:host\s*name|address)
                    |Name or service not known
                    |Temporary failure in name resolution
                    |nodename nor servname provided
                    |No address associated with hostname
                    |getaddrinfo/xi ? 1 : 0;
}

# What to tell the operator for such a failure, in place of the generic
# "not reachable" or a key complaint. $host is the name that was tried.
# One source, two contexts (k240): the CLI looked the name up on the
# operator's machine; with context => 'cluster' (robocop) the lookup ran in
# its pod, through the cluster DNS (CoreDNS), and the way out is a DNS entry
# there or the IP address.
sub unresolved_message {
    my ( $self, $host, %opt ) = @_;
    return "Name '$host' does not resolve: the lookup failed inside the cluster"
         . " (CoreDNS, from the robocop pod), so no SSH connection was attempted."
         . " This is not a key problem. Add the name to the cluster DNS or use"
         . " the IP address.\n"
        if ( $opt{context} // '' ) eq 'cluster';
    return "Name '$host' does not resolve: the lookup failed on this machine"
         . " (DNS or /etc/hosts), so no SSH connection was attempted. This is"
         . " not a key problem. Fix the name or use the IP address.\n";
}

sub _check_host_key {
    my ($self, $result) = @_;
    return unless ($result->{exit} // 0) == 255;
    my $stderr = $result->{stderr} // '';
    return unless $stderr =~ /REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed/;

    my $kh = $self->_known_hosts;
    die OCP::SSH::HostKeyChanged->new(
        host => $self->host,
        port => $self->port,
        file => $kh->file,
        text => 'Host key of ' . $self->host . ' does not match the one recorded in '
          . $kh->file . ".\n"
          . "Either the machine was reinstalled or replaced, or something is intercepting\n"
          . "the connection. If the machine was rebuilt on purpose, remove the stale entry\n"
          . "and run again:\n"
          . '  ' . $kh->remove_hint($self->host, $self->port) . "\n",
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
#
# With @command, ssh runs that instead of a login shell (k229, `ocp ssh --node
# X -- CMD`): its output is the process's own STDOUT/STDERR and ssh exits with
# its exit status. The `--` ends ssh's own options for good: OpenSSH reads
# options right after the destination as well. ssh joins the words with
# spaces and the remote shell reads the line, as with plain ssh.
sub interactive {
    my ($self, @command) = @_;

    $self->_known_hosts->ensure_dir;

    my @cmd = ('ssh');
    push @cmd, $self->_ssh_opts;
    push @cmd, '-p', $self->port if $self->port != 22;
    push @cmd, '-i', $self->key_file if $self->key_file;
    push @cmd, $self->user . '@' . $self->host;
    push @cmd, '--', @command if @command;

    exec(@cmd) or die "Could not run ssh: $!\n";
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
    $self->{_last_probe} = $result;
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

    die $self->unresolved_message($self->host)
        if $self->name_unresolved($result->{stderr});

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

# The fingerprint ssh-keygen -l prints for a key file, or undef. The key file
# OCP::Node hands over is a temporary copy, so its path alone tells the operator
# nothing; the fingerprint is what they can compare on the host (k204).
sub _key_fingerprint {
    my ($key) = @_;
    return undef unless defined $key && -f $key;
    open my $fh, '-|', 'ssh-keygen', '-l', '-f', $key or return undef;
    my $line = do { local $/; <$fh> } // '';
    close $fh;
    return $line =~ /(SHA256:\S+)/ ? $1 : undef;
}

# What a refused key needs, by purpose (k209). The generic line names "ocp
# inject-key, or by hand" -- but inject-key hands robocop its PRIVATE key and
# writes no authorized_keys anywhere, which made it the wrong advice for the
# case that came up live: a robocop join to an ssh worker that only ever got
# the admin key. With the purpose known, the advice names the key and the
# command that prints it; without, it stays as it was.
my %KEY_ROLE = (
    automation => 'the robo key (purpose automation), which robocop joins and '
                . 'tears down workers with',
    admin      => 'the admin key (purpose admin), which ocp apply, ocp ssh and '
                . 'ocp node add/rm reach machines with',
    operator   => 'the operator key (purpose operator), which a Leitstand '
                . 'reaches machines with (OCP_OPERATOR_KEY)',
);

sub _rejection_advice {
    my ($self) = @_;

    my $purpose = $self->key_purpose;
    return "Add the public key there (ocp inject-key, or by hand) and run again.\n"
        unless defined $purpose;

    my $user = $self->user;
    my $host = $self->host;

    return "It needs $KEY_ROLE{$purpose}. With whatever access you have to\n"
      . "that machine, add it and run again:\n"
      . "  ocp keys authorized-keys --purpose $purpose | ssh $user\@$host "
      . "'cat >> ~/.ssh/authorized_keys'\n"
      . ($purpose eq 'operator' ? '' :
          "In secure mode a worker on the ssh provider needs both keys, admin and robo;\n"
        . "'ocp keys authorized-keys' without --purpose prints both.\n");
}

# Did this probe result (run's hashref) end in a refused key? sshd is up and
# said no (k204).
sub probe_rejected {
    my ($self, $result) = @_;
    return (($result // {})->{stderr} // '') =~ /Permission denied/i ? 1 : 0;
}

# The whole refusal: user, key (label, else file, plus fingerprint), the fact
# that the host is reachable, and what the key needs (k204, k209, k226). One
# text for wait_for_ssh and `ocp ssh` (k237).
sub rejection_message {
    my ($self) = @_;

    my $key = defined $self->key_label ? $self->key_label
            : 'key ' . ($self->key_file // 'the default ssh identity');
    my $fp  = _key_fingerprint($self->key_file);
    $key .= " ($fp)" if $fp;
    return "SSH key rejected by ${\$self->host}: user "
      . $self->user . " with $key was refused (Permission denied).\n"
      . "The host is reachable; its authorized_keys does not hold this key.\n"
      . $self->_rejection_advice;
}

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
        my $result = delete $self->{_last_probe} // {};

        # A name that does not resolve is no boot in progress either, and
        # not the key's fault (k236).
        die $self->unresolved_message($self->host)
            if $self->name_unresolved($result->{stderr});

        # A refused key is an answer, not a boot in progress: sshd is up and
        # said no, and waiting out the budget would only send the operator to
        # look at the network (k204).
        die $self->rejection_message if $self->probe_rejected($result);

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

    # A command instead of a shell (replaces process; its exit status is ssh's)
    $ssh->interactive('uptime');

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

=head2 A refused key

A C<Permission denied> answer ends the wait at once (k204): the host is up and
said no. The message (L</rejection_message>) names user, key (C<key_label>,
else C<key_file>) and the key's fingerprint. With C<key_purpose> set
(C<admin>, C<automation> or C<operator>, k209, k237) it also names which key
is missing and the command that installs it:

    ocp keys authorized-keys --purpose automation | ssh root@HOST 'cat >> ~/.ssh/authorized_keys'

together, for C<admin> and C<automation>, with the rule that a worker on the
C<ssh> provider needs both keys.  The C<operator> key is the one a Leitstand
reaches machines with (C<OCP_OPERATOR_KEY>); that rule is left out for it.
L<OCP::Node> passes the purpose on from its C<ssh_key_purpose>; C<ocp ssh>
passes it for the admin and operator key (L<OCP::Cmd::SSH>).

=head2 key_purpose

Optional attribute: C<admin>, C<automation> or C<operator>; anything else
croaks.  Only the refusal reads it.  Absent (dev mode's bootstrap key, or a
caller that does not say), the message gives the generic "add the public key
there" advice.

=head2 probe_rejected

    if ($ssh->probe_rejected($result)) { ... }

Returns 1 when the result of a probe (the hashref C<run> returns; C<undef> is
accepted) ended in a refused key -- C<Permission denied> on its C<stderr>:
sshd is up and said no -- else 0.

=head2 rejection_message

    die $ssh->rejection_message;

The whole refusal as text, ending in a newline: user, key (label, else file,
plus fingerprint), the fact that the host is reachable, and what the key needs
according to C<key_purpose>.  One text for C<wait_for_ssh> and for the probe
of C<ocp ssh> (k237).

=head2 A name that does not resolve

A host given by name that the lookup cannot resolve is no boot in progress and
no key problem, so C<wait_for_ssh> and C<learn_host_key> die at once with
L</unresolved_message> instead of waiting out the budget or blaming the key
(k236).  The same recogniser serves the host probes of L<OCP::Role::Cmd> and,
through the error text, the C<status.message> of an L<OCP::Node>.  The lookup
that failed is the one of the machine running this code: for robocop that is
the cluster's DNS, for the CLI the CLI host.

=head2 name_unresolved

    if ($ssh->name_unresolved($result->{stderr})) { ... }

Returns true (1) when the text says a host name could not be resolved, else 0
(also for C<undef> or an empty string).  It reads what a connection attempt
printed: OpenSSH ("Could not resolve hostname", "Name or service not known",
"Temporary failure in name resolution"), libssh via
L<Rex::Interface::Connection::LibSSH> ("Failed to resolve hostname") and the
C<getaddrinfo> strings both wrap.  A refused key never matches: sshd answered,
so the name was fine.

=head2 unresolved_message

    die $ssh->unresolved_message($ssh->host);

Returns the operator-facing text for such a failure, ending in a newline:
"Name 'HOST' does not resolve ... This is not a key problem. Fix the name or
use the IP address."  C<$host> is the name that was tried.  With
C<< context => 'cluster' >> (robocop) the text says the lookup failed inside
the cluster (CoreDNS, from the robocop pod) and points at the cluster DNS or
the IP address instead; the CLI wording is unchanged.

=cut

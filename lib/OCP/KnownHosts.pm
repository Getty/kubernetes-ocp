package OCP::KnownHosts;
# ABSTRACT: The known_hosts file OCP verifies machine host keys against

use Moo;
use Carp qw( croak );
use Digest::SHA qw( sha256 hmac_sha1 );
use MIME::Base64 qw( decode_base64 encode_base64 );
use Path::Tiny qw( path );

# One file, two readers (k168). OCP::SSH hands it to the OpenSSH client as
# UserKnownHostsFile with StrictHostKeyChecking=accept-new, which is what
# RECORDS a key on first contact; OCP::Rex hands the same path to the Rexfile,
# where Rex::LibSSH VERIFIES against it (libssh has no accept-new of its own --
# Net::LibSSH 0.004 either finds the key or refuses). This class never writes
# a key itself: recording stays with OpenSSH, so the file is always in the
# format both clients read.
#
# What it does own is everything around that: where the file is, whether a
# host is in it yet (OCP::Rex's "learn it first" decision), the fingerprint
# OCP::SSH logs on first contact, and removing an entry that belongs to a
# machine that no longer exists.
has file => (
    is      => 'lazy',
    builder => sub { $_[0]->default_file },
    coerce  => sub { "$_[0]" },
);

# Where the file is when nobody says otherwise.
#
#   1. OCP_KNOWN_HOSTS -- the CLI sets it for the whole run to the project's
#      .ocp/known_hosts (OCP::run_cli, via project_file below), and OCP::Rex
#      passes it on to the rex child the same way.
#   2. $TMPDIR/ocp-known_hosts-<uid> -- the robocop pod, which has no project
#      directory. /tmp there is the pod's emptyDir: shared by the forked
#      reconcile children, kept across container restarts, gone with the pod.
#      So robocop trusts a worker on first contact per pod (the fingerprint is
#      in its log, see OCP::SSH) and verifies it for as long as the pod lives.
#      The uid in the name keeps two users on one machine out of each other's
#      file.
sub default_file {
    my ($class) = @_;
    return $ENV{OCP_KNOWN_HOSTS}
        if defined $ENV{OCP_KNOWN_HOSTS} && length $ENV{OCP_KNOWN_HOSTS};
    my $tmp = defined $ENV{TMPDIR} && length $ENV{TMPDIR} ? $ENV{TMPDIR} : '/tmp';
    return path($tmp)->child('ocp-known_hosts-' . $<)->stringify;
}

# The project's own file. Local state under .ocp/ next to status.yaml: a host
# key is nothing the user could have set (ADR 0004), apply learns it, and a
# fresh clone learns it again on its first contact.
sub project_file {
    my ($class, $project_dir) = @_;
    croak __PACKAGE__ . '->project_file needs a project directory'
        unless defined $project_dir && length $project_dir;
    return path($project_dir)->absolute->child('.ocp', 'known_hosts')->stringify;
}

# How OpenSSH and libssh spell a host in known_hosts: bare on port 22,
# "[host]:port" on any other.
sub host_pattern {
    my ($self, $host, $port) = @_;
    $port //= 22;
    return $port == 22 ? $host : '[' . $host . ']:' . $port;
}

# Every recorded key for the host, as { type, key } in file order. Reads plain
# and hashed (|1|salt|hash) host fields; @cert-authority and @revoked lines
# are not host keys and are skipped.
sub entries {
    my ($self, $host, $port) = @_;
    my $pattern = $self->host_pattern($host, $port);
    my $file = path($self->file);
    return () unless -f $file;

    my @found;
    for my $line ($file->lines_utf8({ chomp => 1 })) {
        my ($hosts, $type, $key) = $self->_parse_line($line);
        next unless defined $key;
        next unless $self->_hosts_match($hosts, $pattern);
        push @found, { type => $type, key => $key };
    }
    return @found;
}

sub knows {
    my ($self, $host, $port) = @_;
    my @entries = $self->entries($host, $port);
    return @entries ? 1 : 0;
}

# The fingerprints as `ssh-keygen -l` prints them: SHA256:<base64, no padding>,
# followed by the key type.
sub fingerprints {
    my ($self, $host, $port) = @_;
    return map { $self->fingerprint($_->{key}) . ' (' . $_->{type} . ')' }
        $self->entries($host, $port);
}

sub fingerprint {
    my ($self, $key_b64) = @_;
    my $fp = encode_base64(sha256(decode_base64($key_b64)), '');
    $fp =~ s/=+\z//;
    return 'SHA256:' . $fp;
}

# Remove every entry for the host. Returns how many lines went. For a machine
# that is gone or was just created in its place: whatever key is recorded for
# that address belongs to a previous machine and would only fail the next
# connection as "changed".
sub forget {
    my ($self, $host, $port) = @_;
    my $pattern = $self->host_pattern($host, $port);
    my $file = path($self->file);
    return 0 unless -f $file;

    my ($removed, @keep) = (0);
    for my $line ($file->lines_utf8) {
        my ($hosts, undef, $key) = $self->_parse_line($line);
        if (defined $key && $self->_hosts_match($hosts, $pattern)) {
            $removed++;
            next;
        }
        push @keep, $line;
    }
    $file->spew_utf8(@keep) if $removed;
    return $removed;
}

# The command that removes a stale entry by hand -- what a "host key changed"
# error tells the operator to run once they know the machine was rebuilt.
sub remove_hint {
    my ($self, $host, $port) = @_;
    return "ssh-keygen -R '" . $self->host_pattern($host, $port)
         . "' -f '" . $self->file . "'";
}

# The directory has to exist before OpenSSH is asked to record into the file:
# with it missing, ssh only warns "Failed to add the host" and carries on, and
# the Rex connection after it fails for an unknown key.
sub ensure_dir {
    my ($self) = @_;
    path($self->file)->parent->mkpath;
    return;
}

sub _parse_line {
    my ($self, $line) = @_;
    return if $line =~ /\A\s*(?:#|\z)/;
    return if $line =~ /\A\s*@/;
    my ($hosts, $type, $key) = split ' ', $line;
    return unless defined $key && length $key;
    return ($hosts, $type, $key);
}

sub _hosts_match {
    my ($self, $hosts, $pattern) = @_;
    if ($hosts =~ /\A\|1\|([^|]+)\|([^|]+)\z/) {
        my ($salt, $hash) = (decode_base64($1), $2);
        return encode_base64(hmac_sha1($pattern, $salt), '') eq $hash ? 1 : 0;
    }
    return scalar grep { $_ eq $pattern } split /,/, $hosts;
}

1;

__END__

=synopsis

    use OCP::KnownHosts;

    my $kh = OCP::KnownHosts->new;            # OCP_KNOWN_HOSTS, or the per-uid tmp file
    my $kh = OCP::KnownHosts->new(file => OCP::KnownHosts->project_file('.'));

    print join("\n", $kh->fingerprints('10.0.0.5')), "\n" if $kh->knows('10.0.0.5');
    $kh->forget('10.0.0.5');                  # the machine behind that address is new

=description

OCP verifies every machine it reaches over SSH against a known_hosts file of
its own, on trust-on-first-use terms: the first successful contact records the
host key, every later one -- over L<OCP::SSH> or over Rex/libssh via
L<OCP::Rex> -- must present the same key, and a different key fails the
connection with the command that removes the stale entry (k168).

The CLI keeps the file at F<.ocp/known_hosts> in the project (local state,
gitignored, like F<.ocp/status.yaml>); C<ocp> exports that path as
C<OCP_KNOWN_HOSTS> for the run. robocop has no project directory and uses
C<$TMPDIR/ocp-known_hosts-E<lt>uidE<gt>>, which in its pod is the C</tmp>
emptyDir: first contact per pod, verified for the life of the pod.

OpenSSH records, this class only reads, fingerprints and removes entries.

=method default_file

C<$ENV{OCP_KNOWN_HOSTS}> when set, otherwise C<$TMPDIR/ocp-known_hosts-E<lt>uidE<gt>>.

=method project_file

    my $file = OCP::KnownHosts->project_file($project_dir);

The absolute path of F<.ocp/known_hosts> under C<$project_dir>.

=method knows

    $kh->knows($host, $port);

True when the file holds at least one key for the host (port defaults to 22).

=method fingerprints

List of C<SHA256:... (type)> strings, one per recorded key of the host.

=method forget

Removes every entry of the host and returns how many there were.

=method remove_hint

The C<ssh-keygen -R> command line that removes the host's entries from this
file by hand.

=cut

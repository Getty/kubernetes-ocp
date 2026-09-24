package OCP::Rex;
# ABSTRACT: Rex task executor wrapper

use Moo;
use Carp qw(croak);
use IPC::Run qw(run);
use JSON::MaybeXS;
use MIME::Base64;
use Path::Tiny qw(path);
use File::Temp ();
use OCP::KnownHosts;
use OCP::Share;
use OCP::SSH;
use OCP::Versions;

has host => (
    is       => 'ro',
    required => 1,
);

# Where the API server tells the world it lives -- the tls-san and the kubeconfig
# `server` endpoint -- as opposed to `host`, which is only where Rex/SSH connect.
# Defaults to `host`, so every caller that does not distinguish the two (Hetzner,
# SSH: reached at the same address they advertise) is unchanged. The local
# provider is the one that sets it apart: transport 127.0.0.1, advertised the
# machine's routable IP (k138). See OCP::Cmd::Apply::Bootstrap.
has advertised_host => (
    is      => 'lazy',
    builder => sub { $_[0]->host },
);

has user => (
    is      => 'ro',
    default => 'root',
);

has key_file => (
    is       => 'ro',
    required => 1,
);

has verbose => (
    is      => 'ro',
    default => 0,
);

# The known_hosts file Rex::LibSSH verifies the host against -- the same one
# OCP::SSH records into (k168). Reaches the rex child as OCP_KNOWN_HOSTS, which
# the Rexfile turns into UserKnownHostsFile.
has known_hosts => (
    is      => 'lazy',
    builder => sub { OCP::KnownHosts->default_file },
);

# Every SSH call this class makes itself, on the same host, key and
# known_hosts file as the Rex run.
sub _ssh {
    my ($self) = @_;
    return OCP::SSH->new(
        host        => $self->host,
        user        => $self->user,
        key_file    => $self->key_file,
        known_hosts => $self->known_hosts,
    );
}

# Rex::LibSSH (0.004) refuses a host whose key is not in known_hosts and has
# no way to record one: libssh verifies, it does not trust on first use. So a
# host the file does not know yet is contacted once through OCP::SSH, whose
# accept-new records the key, and only then handed to Rex. A known host goes
# straight to Rex, and libssh does the verifying.
sub _ensure_host_key {
    my ($self) = @_;
    my $kh = OCP::KnownHosts->new(file => $self->known_hosts);
    return if $kh->knows($self->host);
    $self->_ssh->learn_host_key;
    return;
}

sub run_task {
    my ($self, $task, %params) = @_;

    $self->_ensure_host_key;

    # A private, writable copy of the shipped Rexfile — see _runtime_rexfile.
    my $rexfile = $self->_runtime_rexfile;

    # OCP_REX_DEBUG makes a long task observable: rex runs with its own -d
    # debug output, and run() below streams that output live instead of
    # buffering it until the task ends (see the run/tee block).
    my $debug = $ENV{OCP_REX_DEBUG};

    my @cmd = (
        'rex',
        '-f', $rexfile,
        '-H', $self->host,
        '-u', $self->user,
    );
    push @cmd, '-d' if $debug;

    # Pass SSH keys via environment variables (Rex way)
    # Must NOT use 'local' as it doesn't propagate to subprocesses!
    my $old_private_key = $ENV{REX_PRIVATE_KEY};
    my $old_public_key = $ENV{REX_PUBLIC_KEY};
    my $old_params = $ENV{REX_TASK_PARAMS};
    my $old_known_hosts = $ENV{OCP_KNOWN_HOSTS};

    $ENV{OCP_KNOWN_HOSTS} = $self->known_hosts;

    if ($self->key_file) {
        $ENV{REX_PRIVATE_KEY} = $self->key_file;
        $ENV{REX_PUBLIC_KEY} = $self->key_file . '.pub';
    }

    # Parameters travel as one JSON blob in the environment, picked up by
    # task_params() in the Rexfile. Not as trailing key=value CLI arguments:
    # those put the RKE2/K3s join token into the command line, where `ps`
    # hands it to every local user, and they flatten nested structures.
    delete $ENV{REX_TASK_PARAMS};
    if (%params) {
        my $json = JSON::MaybeXS->new(utf8 => 1, canonical => 1, convert_blessed => 1);
        $ENV{REX_TASK_PARAMS} = $json->encode(\%params);
    }

    push @cmd, $task;

    print "Running Rex task: $task\n";
    print "Command: ", join(' ', @cmd), "\n" if $self->verbose;

    my ($out, $err) = ('', '');
    my $success;
    if ($debug) {
        # Tee each chunk: print it to STDERR the moment it arrives, and keep
        # collecting it for the return value. Buffering the whole task showed
        # the operator nothing until it finished -- and when install_rke2_server
        # brought up Cilium and the CNI cut the network mid-task, that meant a
        # frozen terminal with no output at all, right when they most needed to
        # see where it stopped. IPC::Run's coderef sinks give live + collected.
        $success = run \@cmd, \undef,
            '>',  sub { my $c = shift; print STDERR $c; $out .= $c },
            '2>', sub { my $c = shift; print STDERR $c; $err .= $c };
    } else {
        $success = run \@cmd, \undef, \$out, \$err;
    }

    # Restore ENV
    if (defined $old_private_key) { $ENV{REX_PRIVATE_KEY} = $old_private_key; } else { delete $ENV{REX_PRIVATE_KEY}; }
    if (defined $old_public_key) { $ENV{REX_PUBLIC_KEY} = $old_public_key; } else { delete $ENV{REX_PUBLIC_KEY}; }
    if (defined $old_params) { $ENV{REX_TASK_PARAMS} = $old_params; } else { delete $ENV{REX_TASK_PARAMS}; }
    if (defined $old_known_hosts) { $ENV{OCP_KNOWN_HOSTS} = $old_known_hosts; } else { delete $ENV{OCP_KNOWN_HOSTS}; }

    # Rex output is diagnosis, so it goes to STDERR -- STDOUT is reserved for the
    # payload and the apply progress narrative a parser may read (house rule:
    # output channels). In debug mode it already streamed live above; don't
    # print it a second time.
    print STDERR "--- Rex Output ---\n";
    unless ($debug) {
        print STDERR $out if length $out;
        print STDERR $err if length $err;
    }
    print STDERR "--- End Rex Output ---\n";

    if (!$success) {
        # libssh's refusal of a key that differs from the recorded one: it
        # names the danger but not the way out once the machine is known to
        # have been rebuilt (k168). OCP::SSH says the same for its own calls.
        my $hint = "$out$err" =~ /host key (?:has changed|type differs)/
            ? "\nThe host key of " . $self->host . ' does not match the one recorded in '
              . $self->known_hosts . ". If the machine was rebuilt on purpose,\n"
              . "remove the stale entry and run again:\n  "
              . OCP::KnownHosts->new(file => $self->known_hosts)->remove_hint($self->host) . "\n"
            : '';
        croak "Rex task '$task' failed: $err$hint";
    }

    return {
        stdout => $out,
        stderr => $err,
        exit   => $? >> 8,
    };
}

sub _find_rexfile {
    my ($self) = @_;
    return OCP::Share->rexfile->stringify;
}

# Rex writes its lock file next to the Rexfile (Rex::CLI::handle_lock_file,
# unconditionally — even -F only skips the staleness check), so the directory
# holding the Rexfile has to be writable. share/ regularly is not: mounted
# :ro into the container, or installed root-owned through File::ShareDir. Rex
# then dies with "Read-only file system" before running a single task.
#
# The Rexfile is input, the lock file is runtime state; they have no business
# sharing a directory. Run from a private copy instead. That also keeps
# Rexfile.lock out of the working tree, and the copy is self-contained — the
# Rexfile reads no sibling files, its parameters arrive through the
# environment.
sub _rex_workdir {
    my ($self) = @_;
    return $self->{_rex_workdir} ||= File::Temp->newdir(TEMPLATE => 'ocp-rex-XXXXXX', TMPDIR => 1);
}

sub _runtime_rexfile {
    my ($self) = @_;
    return $self->{_runtime_rexfile} if $self->{_runtime_rexfile};

    my $workdir = $self->_rex_workdir;   # File::Temp::Dir, lives as long as $self
    my $source  = path($self->_find_rexfile);
    my $target  = path("$workdir")->child('Rexfile');
    $source->copy($target);

    return $self->{_runtime_rexfile} = "$target";
}

sub install_server {
    my ($self, %opts) = @_;

    my $distribution = $opts{distribution} || 'rke2';
    my $version = $opts{version} || '';
    # Never rotate the token a control plane is already sealed with. RKE2/K3s
    # derive the datastore encryption key from this token at bootstrap and only
    # re-check it at the NEXT start, so minting a fresh one into config.yaml on a
    # re-apply arms a fatal "bootstrap data already found and encrypted with
    # different token" the next time the server restarts -- a latent cluster-down
    # that stays invisible until the reboot (k150). Reuse what the machine
    # already carries; generate only for a server that has none yet.
    my $token = $opts{token}
        || $self->_existing_server_token($distribution)
        || $self->_generate_token();
    # tls_san may be a LIST (every control-plane address, for HA -- k137) or a
    # single value; both travel through run_task's JSON blob unchanged, and the
    # Rexfile emits one "  - <addr>" line per entry. Absent (or an empty list)
    # falls back to the single advertised address, so a lone control plane is
    # exactly as before.
    my $tls_san = $opts{tls_san};
    $tls_san = undef if ref $tls_san eq 'ARRAY' && !@$tls_san;
    $tls_san ||= $self->advertised_host;
    my $node_name = $opts{node_name} || '';

    my $registry_cache    = $opts{registry_cache}    || '';
    my $registry_upstream = $opts{registry_upstream}  || '';
    my $registry_name     = $opts{registry_name}      || '';

    my $hostname = $opts{hostname} || '';
    my $domain   = $opts{domain}   || '';
    my $timezone = $opts{timezone} || 'UTC';
    my $locale   = $opts{locale}   || 'en_US.UTF-8';
    my $ntp      = $opts{ntp}      // 1;

    # Defaults match the Rexfile's own: absent means "do the GPU work".
    my $gpu        = $opts{gpu}        // 1;
    my $gpu_driver = $opts{gpu_driver} || 'host';

    my $task = $distribution eq 'k3s' ? 'install_k3s_server' : 'install_rke2_server';

    $self->run_task($task,
        token             => $token,
        version           => $version,
        tls_san           => $tls_san,
        node_name         => $node_name,
        registry_cache    => $registry_cache,
        registry_upstream => $registry_upstream,
        registry_name     => $registry_name,
        hostname          => $hostname,
        domain            => $domain,
        timezone          => $timezone,
        locale            => $locale,
        ntp               => $ntp,
        gpu               => $gpu ? 1 : 0,
        gpu_driver        => $gpu_driver,
    );

    # Get kubeconfig directly via SSH (more reliable than parsing Rex output)
    my $kubeconfig = $self->fetch_kubeconfig_ssh($distribution);

    # Install Cilium (CNI) - required for nodes to become Ready.
    # Pass the versions explicitly: the Rexfile carries its own constants as a
    # fallback for hand-runs, and those drifted behind OCP::Versions — a fresh
    # cluster came up on the older Cilium and OCP::Drift immediately reported it
    # against its own manifest.
    $self->run_task('install_cilium',
        distribution => $distribution,
        version      => $opts{cilium_version}
            || OCP::Versions->get_component_version('cilium') || '',
        cli_version  => $opts{cilium_cli_version}
            || OCP::Versions->get_component_version('cilium_cli') || '',
        gateway_api_version => $opts{gateway_api_version}
            || OCP::Versions->get_component_version('gateway_api') || '',
    );

    return {
        token      => $token,
        kubeconfig => $kubeconfig,
    };
}

sub fetch_kubeconfig_ssh {
    my ($self, $distribution) = @_;

    $distribution ||= 'rke2';

    my $path = $distribution eq 'k3s' ? '/etc/rancher/k3s/k3s.yaml' : '/etc/rancher/rke2/rke2.yaml';

    my $result = $self->_ssh->run("cat $path");

    if ($result->{exit}) {
        die "Failed to fetch kubeconfig from $path on ${\$self->host}\n" .
            "Error: $result->{stderr}\n" .
            "The kubeconfig file may not exist yet. RKE2/K3s installation might still be in progress.\n";
    }

    my $kubeconfig = $result->{stdout};

    # Point the kubeconfig `server` at the advertised address, not the transport.
    # The file is fetched over SSH to $self->host (127.0.0.1 for the local
    # provider), but a kubeconfig pinned to 127.0.0.1 only works from the machine
    # itself. advertised_host defaults to host, so this is a no-op everywhere
    # except the local provider, where it is the routable IP (k138).
    my $advertised = $self->advertised_host;
    $kubeconfig =~ s/127\.0\.0\.1/$advertised/g;
    $kubeconfig =~ s/localhost/$advertised/g;

    # Remove certificate-authority-data and add insecure-skip-tls-verify
    # (TLS cert only valid for short hostname, not FQDN)
    $kubeconfig =~ s/^\s*certificate-authority-data:.*\n//mg;
    $kubeconfig =~ s/(server: https:\/\/[^\n]+)/$1\n    insecure-skip-tls-verify: true/g;

    return $kubeconfig;
}

sub install_agent {
    my ($self, %opts) = @_;

    my $distribution = $opts{distribution} || 'rke2';
    my $server = $opts{server} or croak "server URL required";
    my $token = $opts{token} or croak "token required";
    my $version = $opts{version} || '';
    my $node_name = $opts{node_name} || '';

    my $registry_cache    = $opts{registry_cache}    || '';
    my $registry_upstream = $opts{registry_upstream}  || '';
    my $registry_name     = $opts{registry_name}      || '';

    my $hostname = $opts{hostname} || '';
    my $domain   = $opts{domain}   || '';
    my $timezone = $opts{timezone} || 'UTC';
    my $locale   = $opts{locale}   || 'en_US.UTF-8';
    my $ntp      = $opts{ntp}      // 1;

    my $gpu        = $opts{gpu}        // 1;
    my $gpu_driver = $opts{gpu_driver} || 'host';

    my $task = $distribution eq 'k3s' ? 'install_k3s_agent' : 'install_rke2_agent';

    $self->run_task($task,
        server            => $server,
        token             => $token,
        version           => $version,
        node_name         => $node_name,
        registry_cache    => $registry_cache,
        registry_upstream => $registry_upstream,
        registry_name     => $registry_name,
        hostname          => $hostname,
        domain            => $domain,
        timezone          => $timezone,
        locale            => $locale,
        ntp               => $ntp,
        gpu               => $gpu ? 1 : 0,
        gpu_driver        => $gpu_driver,
    );

    return 1;
}

sub get_kubeconfig {
    my ($self, $distribution) = @_;

    $distribution ||= 'rke2';

    my $task = $distribution eq 'k3s' ? 'get_k3s_kubeconfig' : 'get_rke2_kubeconfig';
    my $result = $self->run_task($task);

    my $kubeconfig = $result->{stdout};

    # Point the kubeconfig `server` at the advertised address, not the transport
    # (see fetch_kubeconfig_ssh). advertised_host defaults to host, so this is a
    # no-op except on the local provider (k138).
    my $advertised = $self->advertised_host;
    $kubeconfig =~ s/127\.0\.0\.1/$advertised/g;
    $kubeconfig =~ s/localhost/$advertised/g;

    # Remove certificate-authority-data and add insecure-skip-tls-verify
    # (TLS cert only valid for short hostname, not FQDN)
    $kubeconfig =~ s/^\s*certificate-authority-data:.*\n//mg;
    $kubeconfig =~ s/(server: https:\/\/[^\n]+)/$1\n    insecure-skip-tls-verify: true/g;

    return $kubeconfig;
}

sub get_token {
    my ($self, $distribution) = @_;

    $distribution ||= 'rke2';

    my $task = $distribution eq 'k3s' ? 'get_k3s_token' : 'get_rke2_token';
    my $result = $self->run_task($task);

    my $token = $result->{stdout};
    chomp $token;
    return $token;
}

# The cluster token a control plane is already sealed with, read straight off
# the machine, or undef when there is none. install_server reuses this instead
# of minting a new token so a re-apply against an existing cluster never rotates
# it (k150) -- see the comment there for why a rotation is a latent cluster-down.
# A brand-new server has no such file: `cat` exits non-zero, this returns undef,
# and the caller generates a token exactly as before. Wrapped in eval and
# tolerant of an unreachable host on purpose -- a failed read must degrade to
# "no existing token", never abort the install with the token half-decided.
#
# The file is read verbatim (only trailing whitespace trimmed): RKE2/K3s write
# the very value they seal the datastore with here, so handing it back as the
# config `token:` reproduces the same encryption key.
sub _existing_server_token {
    my ($self, $distribution) = @_;
    $distribution ||= 'rke2';

    my $path = $distribution eq 'k3s'
        ? '/var/lib/rancher/k3s/server/token'
        : '/var/lib/rancher/rke2/server/token';

    my $result = eval { $self->_ssh->run("cat $path") };
    return undef unless $result && !$result->{exit};

    my $token = $result->{stdout} // '';
    $token =~ s/\s+\z//;
    return length $token ? $token : undef;
}

sub _generate_token {
    my ($self) = @_;


    my $bytes = '';
    open my $fh, '<', '/dev/urandom' or croak "Can't open /dev/urandom: $!";
    read $fh, $bytes, 48;
    close $fh;
    my $token = MIME::Base64::encode_base64($bytes, '');
    $token =~ tr/+\///d;
    return substr($token, 0, 48);
}

1;

__END__

=head1 NAME

OCP::Rex - Rex task executor wrapper

=head1 SYNOPSIS

    use OCP::Rex;

    my $rex = OCP::Rex->new(
        host     => '1.2.3.4',
        key_file => '/path/to/id_ed25519',
    );

    # Install RKE2 server
    my $result = $rex->install_server(
        distribution => 'rke2',
        version      => 'v1.31.3+rke2r1',
    );

    print "Token: $result->{token}\n";
    print "Kubeconfig: $result->{kubeconfig}\n";

    # Install agent
    $rex->install_agent(
        distribution => 'rke2',
        server       => 'https://1.2.3.4:9345',
        token        => $result->{token},
    );

=head1 DESCRIPTION

OCP::Rex wraps Rex tasks defined in the Rexfile, providing a clean Perl API
for Kubernetes cluster bootstrapping.

=head2 Host keys

Rex connects through Rex::LibSSH, which verifies the host key against
C<known_hosts> (default: L<OCP::KnownHosts/default_file>, the same file
L<OCP::SSH> uses) and refuses a host it cannot find there. libssh cannot record
a key itself, so C<run_task> first contacts a host the file does not know yet
through L<OCP::SSH/learn_host_key>, which trusts it on first use; a known host
goes straight to Rex. The file reaches the Rexfile as C<OCP_KNOWN_HOSTS>. A
refused changed key fails the task with the C<ssh-keygen -R> command that
removes the stale entry (k168).

=head1 METHODS

=head2 run_task

    $rex->run_task('task_name', param1 => 'value', ...);

Execute a Rex task with parameters.

=head2 install_server

    my $result = $rex->install_server(
        distribution => 'rke2',  # or 'k3s'
        version      => '',      # empty = latest
        token        => '...',   # see below if omitted
        gpu          => 1,       # 0 skips GPU detection entirely
        gpu_driver   => 'host',  # 'operator' leaves the host driver alone
    );

Install Kubernetes control plane. Detects NVIDIA hardware and installs the
driver plus container toolkit unless C<gpu> is false or C<gpu_driver> is
C<operator>.

When C<token> is omitted, an existing cluster's token is B<reused> rather than
regenerated: the machine's on-disk C<server/token> is read first, and a fresh
token is minted only when there is none. RKE2/K3s seal the datastore with this
token at bootstrap and re-check it at the next start, so rotating it on a
re-apply would arm a fatal reconcile failure on the following restart (k150).

Returns hashref with C<token> and C<kubeconfig>.

=head2 install_agent

    $rex->install_agent(
        distribution => 'rke2',
        server       => 'https://cp-ip:9345',
        token        => '...',
    );

Join node to cluster as worker.

=head2 get_kubeconfig

    my $kubeconfig = $rex->get_kubeconfig('rke2');

Fetch kubeconfig from remote server.

=head2 get_token

    my $token = $rex->get_token('rke2');

Fetch join token from control plane.

=cut

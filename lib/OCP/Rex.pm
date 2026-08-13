package OCP::Rex;
# ABSTRACT: Rex task executor wrapper

use Moo;
use Carp qw(croak);
use IPC::Run qw(run);
use JSON::MaybeXS;
use MIME::Base64;
use Path::Tiny qw(path);
use File::Temp ();
use OCP::Share;
use OCP::SSH;
use OCP::Versions;

our $VERSION = '0.001';

has host => (
    is       => 'ro',
    required => 1,
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

sub run_task {
    my ($self, $task, %params) = @_;

    # A private, writable copy of the shipped Rexfile — see _runtime_rexfile.
    my $rexfile = $self->_runtime_rexfile;

    my @cmd = (
        'rex',
        '-f', $rexfile,
        '-H', $self->host,
        '-u', $self->user,
    );

    # Pass SSH keys via environment variables (Rex way)
    # Must NOT use 'local' as it doesn't propagate to subprocesses!
    my $old_private_key = $ENV{REX_PRIVATE_KEY};
    my $old_public_key = $ENV{REX_PUBLIC_KEY};
    my $old_params = $ENV{REX_TASK_PARAMS};

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

    my ($out, $err);
    my $success = run \@cmd, \undef, \$out, \$err;

    # Restore ENV
    if (defined $old_private_key) { $ENV{REX_PRIVATE_KEY} = $old_private_key; } else { delete $ENV{REX_PRIVATE_KEY}; }
    if (defined $old_public_key) { $ENV{REX_PUBLIC_KEY} = $old_public_key; } else { delete $ENV{REX_PUBLIC_KEY}; }
    if (defined $old_params) { $ENV{REX_TASK_PARAMS} = $old_params; } else { delete $ENV{REX_TASK_PARAMS}; }

    # Always show Rex output for debugging
    print "--- Rex Output ---\n";
    print $out if $out;
    print $err if $err;
    print "--- End Rex Output ---\n";

    if (!$success) {
        croak "Rex task '$task' failed: $err";
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
    my $token = $opts{token} || $self->_generate_token();
    my $tls_san = $opts{tls_san} || $self->host;
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

    my $ssh = OCP::SSH->new(
        host     => $self->host,
        user     => $self->user,
        key_file => $self->key_file,
    );

    my $result = $ssh->run("cat $path");

    if ($result->{exit}) {
        die "Failed to fetch kubeconfig from $path on ${\$self->host}\n" .
            "Error: $result->{stderr}\n" .
            "The kubeconfig file may not exist yet. RKE2/K3s installation might still be in progress.\n";
    }

    my $kubeconfig = $result->{stdout};

    # Replace localhost/127.0.0.1 with actual host
    my $host = $self->host;
    $kubeconfig =~ s/127\.0\.0\.1/$host/g;
    $kubeconfig =~ s/localhost/$host/g;

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

    # Replace localhost/127.0.0.1 with actual host
    my $host = $self->host;
    $kubeconfig =~ s/127\.0\.0\.1/$host/g;
    $kubeconfig =~ s/localhost/$host/g;

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

=head1 METHODS

=head2 run_task

    $rex->run_task('task_name', param1 => 'value', ...);

Execute a Rex task with parameters.

=head2 install_server

    my $result = $rex->install_server(
        distribution => 'rke2',  # or 'k3s'
        version      => '',      # empty = latest
        token        => '...',   # auto-generated if not provided
        gpu          => 1,       # 0 skips GPU detection entirely
        gpu_driver   => 'host',  # 'operator' leaves the host driver alone
    );

Install Kubernetes control plane. Detects NVIDIA hardware and installs the
driver plus container toolkit unless C<gpu> is false or C<gpu_driver> is
C<operator>.

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

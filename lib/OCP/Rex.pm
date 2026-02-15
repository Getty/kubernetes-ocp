package OCP::Rex;
# ABSTRACT: Rex task executor wrapper

use Moo;
use Carp qw(croak);
use IPC::Run qw(run);
use Path::Tiny qw(path);
use File::ShareDir::ProjectDistDir;

our $VERSION = '0.1.0';

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

    # Find Rexfile in project root
    my $rexfile = $self->_find_rexfile;

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

    # Pass parameters as environment variables
    # Rex can't easily take params via CLI, so we encode as JSON env var
    if (%params) {
        require JSON::MaybeXS;
        my $json = JSON::MaybeXS->new->utf8->canonical;
        $ENV{REX_TASK_PARAMS} = $json->encode(\%params);
    }

    push @cmd, $task;

    print "Running: ", join(' ', @cmd), "\n" if $self->verbose;

    my ($out, $err);
    my $success = run \@cmd, \undef, \$out, \$err;

    # Restore ENV
    if (defined $old_private_key) { $ENV{REX_PRIVATE_KEY} = $old_private_key; } else { delete $ENV{REX_PRIVATE_KEY}; }
    if (defined $old_public_key) { $ENV{REX_PUBLIC_KEY} = $old_public_key; } else { delete $ENV{REX_PUBLIC_KEY}; }
    if (defined $old_params) { $ENV{REX_TASK_PARAMS} = $old_params; } else { delete $ENV{REX_TASK_PARAMS}; }

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

    # Use File::Share::ProjectDistDir to find Rexfile
    # In dev: project root
    # In installed: share/ directory
    my $project_dir = path(dist_dir('OCP'));
    my $rexfile = $project_dir->child('Rexfile');

    return $rexfile->stringify if $rexfile->exists;

    croak "Rexfile not found in project directory: $project_dir";
}

sub install_server {
    my ($self, %opts) = @_;

    my $distribution = $opts{distribution} || 'rke2';
    my $version = $opts{version} || '';
    my $token = $opts{token} || $self->_generate_token();
    my $tls_san = $opts{tls_san} || $self->host;

    my $task = $distribution eq 'k3s' ? 'install_k3s_server' : 'install_rke2_server';

    $self->run_task($task,
        token   => $token,
        version => $version,
        tls_san => $tls_san,
    );

    # Get kubeconfig directly via SSH (more reliable than parsing Rex output)
    my $kubeconfig = $self->_fetch_kubeconfig_ssh($distribution);

    return {
        token      => $token,
        kubeconfig => $kubeconfig,
    };
}

sub _fetch_kubeconfig_ssh {
    my ($self, $distribution) = @_;

    $distribution ||= 'rke2';

    my $path = $distribution eq 'k3s' ? '/etc/rancher/k3s/k3s.yaml' : '/etc/rancher/rke2/rke2.yaml';

    # Use OCP::SSH to fetch kubeconfig
    require OCP::SSH;
    my $ssh = OCP::SSH->new(
        host     => $self->host,
        user     => $self->user,
        key_file => $self->key_file,
    );

    my $result = $ssh->run("cat $path");
    return '' if $result->{exit};

    my $kubeconfig = $result->{stdout};

    # Replace localhost/127.0.0.1 with actual host
    my $host = $self->host;
    $kubeconfig =~ s/127\.0\.0\.1/$host/g;
    $kubeconfig =~ s/localhost/$host/g;

    return $kubeconfig;
}

sub install_agent {
    my ($self, %opts) = @_;

    my $distribution = $opts{distribution} || 'rke2';
    my $server = $opts{server} or croak "server URL required";
    my $token = $opts{token} or croak "token required";
    my $version = $opts{version} || '';

    my $task = $distribution eq 'k3s' ? 'install_k3s_agent' : 'install_rke2_agent';

    $self->run_task($task,
        server  => $server,
        token   => $token,
        version => $version,
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

    require MIME::Base64;
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
    );

Install Kubernetes control plane. Detects GPU and installs drivers automatically.

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

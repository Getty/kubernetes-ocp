package OCP;
# ABSTRACT: Omni Control Plane - Kubernetes Cluster Management

use Moo;
with 'MooX::Singleton';
use MooX::Cmd;
use MooX::Options;
use YAML::XS ();
use JSON::PP ();

# Enable proper YAML boolean serialization (JSON::PP::true/false → true/false)
#
# Keep the explicit `use JSON::PP ()`: JSON::MaybeXS does NOT pull JSON::PP in
# when Cpanel::JSON::XS is installed, and JSON::PP::true written as a bareword
# has to resolve at compile time. 'JSON::PP' below is also a fixed YAML::XS
# mode name, not a module choice.
$YAML::XS::Boolean = 'JSON::PP';

our $VERSION = '0.001';

# Register MooX::Cmd-created instance as singleton
sub BUILD {
    my ($self) = @_;
    no strict 'refs';
    ${"OCP::_instance"} //= $self;
}

#
# YAML (central serialization)
#

sub dump {
    my ($self, @resources) = @_;
    return join('', map { YAML::XS::Dump($_) } @resources);
}

sub load {
    my ($self, $string) = @_;
    return YAML::XS::Load($string);
}

sub dump_file {
    my ($self, $file, $data) = @_;
    return YAML::XS::DumpFile("$file", $data);
}

sub load_file {
    my ($self, $file) = @_;
    return YAML::XS::LoadFile("$file");
}

option verbose => (
    is      => 'ro',
    short   => 'v',
    doc     => 'Verbose output',
    default => 0,
);

#
# CLI entry point
#
# Wraps new_with_cmd so users never see a Perl stacktrace. Commands report
# problems with `die "message\n"`; anything carrying an " at FILE line N."
# is an internal error and says so. --verbose keeps the raw message.
#
# Returns the process exit code: the value the command's execute returned,
# or 1 when it died.
#

# MooX::Cmd derives command names from class names, so OCP::Cmd::DeployRobocop
# is 'deployrobocop'. Accept the readable spelling too.
our %COMMAND_ALIASES = (
    'deploy-robocop' => 'deployrobocop',
    'inject-key'     => 'injectkey',
);

sub run_cli {
    my ($class) = @_;

    my $verbose = grep { $_ eq '-v' || $_ eq '--verbose' } @ARGV;

    for my $i (0 .. $#ARGV) {
        last if $ARGV[$i] =~ /\A-/;                 # options end command lookup
        if (my $real = $COMMAND_ALIASES{$ARGV[$i]}) {
            $ARGV[$i] = $real;
            last;
        }
    }

    my $root = eval { $class->new_with_cmd };
    if (my $err = $@) {
        return _report_error($err, $verbose);
    }

    my $ret = $root->execute_return;
    return 0 unless ref $ret eq 'ARRAY' && defined $ret->[0];
    return $ret->[0] =~ /\A-?\d+\z/ ? $ret->[0] : 0;
}

# Split an exception into (message, is_internal). Anything that ends in a
# source location was raised without a trailing newline, i.e. not meant for
# the user.
sub _clean_message {
    my ($err) = @_;

    my $msg = "$err";
    $msg =~ s/\n\s+\S+::\S+ called at .*\z//s;   # Carp::confess trace tail
    my $internal = $msg =~ s/ at \S+ line \d+\.?\s*\z//s ? 1 : 0;
    $msg =~ s/\s+\z//;
    $msg =~ s/\A(?:ERROR|Error|error):\s*//;     # normalize existing prefixes
    $msg = 'unknown error' unless length $msg;

    return ($msg, $internal);
}

sub _report_error {
    my ($err, $verbose) = @_;

    if ($verbose) {
        my $raw = "$err";
        $raw .= "\n" unless $raw =~ /\n\z/;
        print STDERR $raw;
        return 1;
    }

    my ($msg, $internal) = _clean_message($err);
    my $label = eval {
        require Term::ANSIColor;
        -t STDERR ? Term::ANSIColor::colored('Error:', 'red bold') : 'Error:';
    } || 'Error:';

    print STDERR "$label $msg\n";
    print STDERR "\nThis is an internal error. Run again with --verbose for the full trace.\n"
        if $internal;

    return 1;
}

option config => (
    is      => 'ro',
    short   => 'c',
    format  => 's',
    doc     => 'Config file path',
    default => sub { 'ocp.yaml' },
);

sub execute {
    my ($self, $args_ref, $chain_ref) = @_;

    print <<"HELP";
OCP - Omni Control Plane v$VERSION

Usage: ocp <command> [options]

Commands:
  init            Initialize OCP project (git, keys, config)
  apply           Reconcile cluster to match config, fix drift
  status          Show cluster status and drift
  destroy         Destroy cluster
  kubeconfig      Print kubeconfig (-e merges it into ~/.kube/config)
  ssh             SSH into a cluster node
  node            Manage nodes: ls, add, rm
  provider        Manage providers: ls, add, rm
  version         Show OCP and component versions
  update          Update components to the bundled versions
  deploy-robocop  Deploy the robocop controller
  inject-key      Inject the robo-ssh key (currently disabled)
  hetzner         Hetzner Cloud debugging

Options:
  -c, --config=FILE   Config file (default: ocp.yaml)
  -v, --verbose       Verbose output

Examples:
  ocp init --hetzner          # Initialize with Hetzner token setup
  ocp apply                   # Deploy/update cluster
  ocp status                  # Check cluster health and drift
  ocp kubeconfig -e           # Merge into ~/.kube/config
  ocp node add worker-1       # Add a worker
HELP

    return 1;   # no command given is a usage error
}

1;

__END__

=head1 NAME

OCP - Omni Control Plane - Kubernetes Cluster Management

=head1 SYNOPSIS

    # Initialize project
    ocp init --hetzner

    # Deploy cluster
    ocp apply

    # Check status
    ocp status

    # Export kubeconfig
    ocp kubeconfig > ~/.kube/config

    # Destroy cluster
    ocp destroy

=head1 DESCRIPTION

OCP (Omni Control Plane) is a Kubernetes cluster management tool that deploys
RKE2/K3s clusters using a single configuration file. It supports multiple providers:

=over 4

=item * B<Hetzner Cloud> - Creates and manages cloud servers via Hetzner API

=item * B<SSH> - Adds existing servers as workers

=back

=head2 Key Features

=over 4

=item * Single config file (ocp.yaml) for entire cluster specification

=item * Spec/Status separation for clean state management

=item * Encrypted secrets using L<Crypt::Age> and L<File::SOPS> (pure Perl, no external tools)

=item * Automatic SSH and age key generation

=item * Idempotent operations - run C<ocp apply> repeatedly to converge

=back

=head1 COMMANDS

=over 4

=item B<init>

Initialize OCP project with git, keys, and config template.
Use C<--hetzner> for interactive Hetzner token setup.

=item B<apply>

Reconcile cluster to match configuration. Creates servers, installs
RKE2/K3s, joins nodes, and runs the upgrade step for any drift it can fix
automatically. Idempotent.

=item B<status>

Show current cluster status including node health, IPs and drift against the
spec and version manifest.

=item B<destroy>

Destroy all cluster resources. Deletes servers from providers.

=item B<kubeconfig>

Output kubeconfig for kubectl. C<-e> merges it into C<$KUBECONFIG> or
F<~/.kube/config>, C<-o FILE> writes it to a file. See
L<OCP::Cmd::Kubeconfig>.

=item B<ssh>

SSH into a cluster node using the admin key.

=item B<node>

Manage nodes as C<OCPNode> CRs: C<ls>, C<add NAME>, C<rm NAME>.

=item B<provider>

Manage infrastructure providers as C<OCPNodeProvider> CRs: C<ls>, C<add>,
C<rm NAME>.

=item B<version>

Show the OCP version and the component versions it bundles.

=item B<update>

Update cluster components to the bundled versions. C<--dry-run> shows what
would change, C<--component NAME> limits it to one component.

=item B<deploy-robocop>

Deploy the robocop controller and its CRDs into the cluster.

=item B<inject-key>

Inject the robo-ssh key into robocop's memory. Currently disabled, see
L<OCP::Cmd::InjectKey>.

=item B<hetzner>

Debug command to list Hetzner servers.

=back

=head1 METHODS

=head2 run_cli

    exit OCP->run_cli;

Entry point used by F<bin/ocp>. Runs the command chain, turns exceptions
into a single-line error message (unless C<--verbose> is given) and returns
the process exit code.

=head1 CONFIGURATION

OCP uses C<ocp.yaml> for cluster specification:

    name: mycluster

    control_planes:
      provider: hetzner
      server_type: cpx21
      location: fsn1

    workers:
      - name: cloud-workers
        provider: hetzner
        server_type: cpx31
        nodes: 2

      - name: bare-metal
        provider: ssh
        nodes:
          - name: gpu-1
            host: 192.168.1.50

Status is stored separately in C<.ocp/status.yaml> (gitignored).

=head1 FILES

=over 4

=item C<ocp.yaml> - Cluster specification (version controlled)

=item C<secrets.yaml> - Encrypted secrets (SOPS, version controlled)

=item C<keys.yaml> - SSH keys: admin-ssh + robo-ssh (SOPS encrypted, version controlled)

=item C<age.key.enc> - PIN1-protected age key (version controlled)

=item C<kubeconfig.yaml> - Cluster access (SOPS encrypted, version controlled)

=item C<.ocp/> - Local state directory (gitignored)

=item C<.ocp/status.yaml> - Runtime status

=item C<.ocp/age.key> - Age private key (decrypted cache)

=back

=head1 ENVIRONMENT

=over 4

=item C<HETZNER_API_TOKEN> - Hetzner Cloud API token (alternative to secrets.yaml)

=back

=head1 SEE ALSO

L<OCP::Config>, L<OCP::Secrets>, L<OCP::Keys>, L<OCP::SSH>, L<OCP::Rex>

L<Crypt::Age>, L<File::SOPS>, L<WWW::Hetzner>

=cut

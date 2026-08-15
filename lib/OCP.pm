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

# MooX::Cmd derives command names from class names, so OCP::Cmd::DeployImage
# is 'deployimage' and OCP::Cmd::DeployRobocop is 'deployrobocop'. Accept the
# readable spellings too.
our %COMMAND_ALIASES = (
    'deploy-image'   => 'deployimage',
    'deploy-robocop' => 'deployrobocop',
);

# MooX::Cmd resolves a word it does not recognise by quietly falling back to
# the enclosing command: `ocp typo --help` printed the root usage and exited
# 0, and `ocp typo apply` ran apply. A tool that bootstraps clusters must not
# accept input it does not understand, so every command word is checked
# against its own level before MooX::Cmd ever sees the argument vector.

# The commands a class dispatches to, keyed by the name MooX::Cmd derives from
# the class name. Empty for a leaf command.
sub _command_map {
    my ($cmd_class) = @_;

    return {} unless $cmd_class->can('_build_command_commands');
    return $cmd_class->_build_command_commands({});
}

# Index of the next command word in $argv at or after $from: the first
# argument that is neither an option nor an option's value. Options declared
# with a format consume the following argument, unless they were written in
# the --option=value form. Returns -1 when there is no command word left.
sub _command_word_index {
    my ($cmd_class, $argv, $from) = @_;

    my %takes_value;
    if ($cmd_class->can('_options_data')) {
        my %data = $cmd_class->_options_data;
        for my $name (keys %data) {
            next unless defined $data{$name}{format};
            my $dashed = $name;
            $dashed =~ tr/_/-/;
            $takes_value{$name} = $takes_value{$dashed} = 1;
            $takes_value{ $data{$name}{short} } = 1
                if defined $data{$name}{short};
        }
    }

    for (my $i = $from; $i <= $#$argv; $i++) {
        my $arg = $argv->[$i];
        return -1 if $arg eq '--';
        return $i unless $arg =~ /\A-\S/;
        next if $arg =~ /=/;
        my ($name) = $arg =~ /\A--?(?:no-?)?(\S+)\z/;
        $i++ if defined $name && $takes_value{$name};
    }

    return -1;
}

# Walk the command words in $argv level by level, rewriting the root-level
# aliases in place. Dies naming the available commands as soon as one of them
# does not resolve.
sub _resolve_commands {
    my ($class, $argv) = @_;

    my %spelling = reverse %COMMAND_ALIASES;
    my $current  = $class;
    my $from     = 0;
    my @path     = ('ocp');

    while (1) {
        my $known = _command_map($current);
        last unless %$known;

        my $i = _command_word_index($current, $argv, $from);
        last if $i < 0;

        my $word = $argv->[$i];
        my $name = @path == 1 ? ($COMMAND_ALIASES{$word} // $word) : $word;

        my $cmd_class = $known->{$name}
            or die sprintf "Unknown command '%s' for '%s'.\nAvailable: %s\n",
                $word, join(' ', @path),
                join(', ', sort map { $spelling{$_} // $_ } keys %$known);

        $argv->[$i] = $name;

        my $file = $cmd_class;
        $file =~ s{::}{/}g;
        require "$file.pm";

        push @path, $word;
        $current = $cmd_class;
        $from    = $i + 1;
    }

    return;
}

sub run_cli {
    my ($class) = @_;

    my $verbose = grep { $_ eq '-v' || $_ eq '--verbose' } @ARGV;

    my $root = eval {
        _resolve_commands($class, \@ARGV);
        $class->new_with_cmd;
    };
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
  deploy-image    Roll out a new robocop image (--tag)
  hetzner         Hetzner Cloud debugging (list servers the token sees)

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

=item B<deploy-image>

Roll out a new robocop image into the running cluster. Patches the
Deployment in place via L<Kubernetes::REST> (no C<kubectl> per ADR 0007),
optionally triggers a rollout restart, and optionally waits for all pods
to be Ready. See L<OCP::Cmd::DeployImage>.

=item B<hetzner>

Debug commands against the Hetzner Cloud API. Currently just
C<list>; the cluster adapter lives in L<OCP::Provider::Hetzner>.

=back

=head1 METHODS

=head2 run_cli

    exit OCP->run_cli;

Entry point used by F<bin/ocp>. Runs the command chain, turns exceptions
into a single-line error message (unless C<--verbose> is given) and returns
the process exit code.

Every command word is resolved against its own level first. A word that
names no command is reported on STDERR together with the commands that do
exist, and the process exits non-zero — L<MooX::Cmd> would otherwise fall
back to the enclosing command and report success.

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

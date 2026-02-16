package OCP;
# ABSTRACT: Omni Control Plane - Kubernetes Cluster Management

use Moo;
with 'MooX::Singleton';
use MooX::Cmd;
use MooX::Options;
use YAML::XS ();

our $VERSION = '0.1.0';

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
  init        Initialize OCP project (git, keys, config)
  apply       Reconcile cluster to match config
  status      Show cluster status
  destroy     Destroy cluster
  kubeconfig  Export kubeconfig

  hetzner     Hetzner Cloud debugging

Options:
  -c, --config=FILE   Config file (default: ocp.yaml)
  -v, --verbose       Verbose output

Examples:
  ocp init                    # Initialize project
  ocp init --hetzner          # Initialize with Hetzner token setup
  ocp apply                   # Deploy/update cluster
  ocp status                  # Check cluster health
  ocp kubeconfig -e           # Export to ~/.kube/config
HELP
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
k3s clusters using a single configuration file. It supports multiple providers:

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

Reconcile cluster to match configuration. Creates servers, installs k3s,
joins nodes. Idempotent.

=item B<status>

Show current cluster status including node health and IPs.

=item B<destroy>

Destroy all cluster resources. Deletes servers from providers.

=item B<kubeconfig>

Output kubeconfig for kubectl. Use C<-e> to export to ~/.kube/config.

=item B<hetzner>

Debug command to list Hetzner servers.

=back

=head1 CONFIGURATION

OCP uses C<ocp.yaml> for cluster specification:

    name: mycluster

    controlPlanes:
      provider: hetzner
      serverType: cpx21
      location: fsn1

    workers:
      - name: cloud-workers
        provider: hetzner
        serverType: cpx31
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

=item C<secrets.yaml> - Encrypted secrets (version controlled)

=item C<.ocp/> - Local state directory (gitignored)

=item C<.ocp/status.yaml> - Runtime status

=item C<.ocp/age.key> - Age private key for secrets

=item C<.ocp/id_ed25519> - SSH private key

=back

=head1 ENVIRONMENT

=over 4

=item C<HETZNER_API_TOKEN> - Hetzner Cloud API token (alternative to secrets.yaml)

=back

=head1 SEE ALSO

L<OCP::Config>, L<OCP::Secrets>, L<OCP::SSH>, L<OCP::K3s>

L<Crypt::Age>, L<File::SOPS>, L<WWW::Hetzner>

=cut

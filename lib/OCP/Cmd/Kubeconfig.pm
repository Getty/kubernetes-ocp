package OCP::Cmd::Kubeconfig;
# ABSTRACT: Export kubeconfig

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::Kubeconfig;
use OCP::Secrets;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

option export => (
    is    => 'ro',
    short => 'e',
    doc   => 'Merge into $KUBECONFIG or ~/.kube/config',
);

option output => (
    is     => 'ro',
    format => 's',
    short  => 'o',
    doc    => 'Write to specific file',
);

option refresh => (
    is    => 'ro',
    short => 'r',
    doc   => 'Fetch fresh kubeconfig from server',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;

    unless (-f $file) {
        die "Config file '$file' not found.\n";
    }

    my $config = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $kubeconfig;

    if ($self->refresh) {
        # Would mean fetching /etc/rancher/*/….yaml off the control plane
        # again via Rex. Only useful once the stored one can go stale.
        die "--refresh is not implemented. The stored kubeconfig.yaml is authoritative.\n";
    } else {
        unless ($config->cluster_exists) {
            die "No cluster deployed. Run 'ocp apply' first.\n";
        }

        $kubeconfig = $secrets->read_kubeconfig;

        unless ($kubeconfig) {
            die "Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n";
        }
    }

    if ($self->output) {
        # Write to specific file
        my $out_file = $self->output;
        path($out_file)->parent->mkpath;
        path($out_file)->spew($kubeconfig);
        path($out_file)->chmod(0600);
        print "Kubeconfig written to $out_file\n";
    } elsif ($self->export) {
        # Merge into the user's kubeconfig, keeping other clusters intact
        my $result = OCP::Kubeconfig->export(
            kubeconfig => $kubeconfig,
            name       => $config->name,
        );

        print "  [ok] backup: ", _tilde($result->{backup}), "\n" if $result->{backup};
        print "  [ok] context '$result->{context}' merged into ",
              _tilde($result->{target}), "\n";
        print "  [ok] current-context: $result->{context}\n";

        if (OCP::Kubeconfig->in_container) {
            print <<"MSG";

WARNING: This is running in a container, so ${\ _tilde($result->{target}) } is
         inside the container and gone when it exits (unless your home
         directory is mounted). To get the kubeconfig onto your machine:

           ocp kubeconfig > ~/.kube/config
           ocp kubeconfig -o /ocp/kubeconfig
MSG
        }
    } else {
        # Print to stdout
        print $kubeconfig;
    }

    return 0;
}

# Shorten $HOME to ~ for output
sub _tilde {
    my ($path) = @_;
    return $path unless defined $path;

    my $home = $ENV{HOME} // '';
    return $path unless length $home;

    (my $short = $path) =~ s/\A\Q$home\E(?=\/|\z)/~/;
    return $short;
}

1;

__END__

=head1 NAME

OCP::Cmd::Kubeconfig - Output or install the cluster kubeconfig

=head1 SYNOPSIS

    ocp kubeconfig                 # print to stdout
    ocp kubeconfig -e              # merge into $KUBECONFIG or ~/.kube/config
    ocp kubeconfig -o /path/file   # write to a specific file

=head1 DESCRIPTION

Decrypts F<kubeconfig.yaml> and hands it out. Without options it goes to
stdout, so it can be redirected anywhere.

C<--export> merges it into your existing kubeconfig instead of overwriting
it: cluster, user and context are renamed from the distribution's C<default>
to the OCP cluster name, entries of other clusters stay untouched, and the
previous file is kept as F<< <target>.ocp-bak >>. See L<OCP::Kubeconfig>.

Inside a container the merge target is the container's home directory, so
C<--export> warns and points at stdout or C<--output> instead.

=head1 OPTIONS

=head2 --export, -e

Merge into C<$KUBECONFIG> (first entry) or F<~/.kube/config>.

=head2 --output FILE, -o FILE

Write the kubeconfig to FILE (mode 0600). No merging.

=head2 --refresh, -r

Not implemented. The stored F<kubeconfig.yaml> is authoritative.

=cut

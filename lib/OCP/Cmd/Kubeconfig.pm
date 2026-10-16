package OCP::Cmd::Kubeconfig;
# ABSTRACT: Export kubeconfig

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::K8s;
use OCP::Kubeconfig;
use OCP::ReadonlyKubeconfig;
use OCP::Secrets;

with 'OCP::Role::Cmd';

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

option readonly => (
    is    => 'ro',
    doc   => 'Print a read-only kubeconfig (ServiceAccount token) to STDOUT',
);

option name => (
    is     => 'ro',
    format => 's',
    doc    => 'With --readonly: name of the read-only account (default: leitstand)',
);

option revoke => (
    is    => 'ro',
    doc   => 'With --readonly: remove the account and its token',
);

# Test seams: an api and an admin kubeconfig can be handed in.
has k8s => (is => 'rw');
has admin_kubeconfig => (is => 'rw');
has cluster_name => (is => 'rw');

sub _check_options {
    my ($self) = @_;

    unless ($self->readonly) {
        die "--revoke only works together with --readonly.\n" if $self->revoke;
        die "--name only works together with --readonly.\n" if defined $self->name;
        return;
    }

    for my $pair (['--export', $self->export], ['--output', $self->output],
                  ['--refresh', $self->refresh]) {
        die "--readonly prints to STDOUT only; it cannot be combined with $pair->[0].\n"
            if $pair->[1];
    }

    my $name = $self->name // OCP::ReadonlyKubeconfig->default_name;
    if (my $err = OCP::ReadonlyKubeconfig->validate_name($name)) {
        die $err;
    }
    return $name;
}

sub _readonly {
    my ($self, $name) = @_;

    my $admin = $self->admin_kubeconfig;
    my $cname = $self->cluster_name;
    my $api   = $self->k8s;

    unless ($admin && $cname && $api) {
        my $file = $self->ocp->config;
        die "Config file '$file' not found.\n" unless -f $file;
        my $config = OCP::Config->new(file => $file);
        die "No cluster deployed. Run 'ocp apply' first.\n"
            unless $config->cluster_exists;

        my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
        $admin //= $secrets->read_kubeconfig;
        die "Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
            unless $admin;
        $cname //= $config->name;

        unless ($api) {
            my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
            print {$kc_fh} $admin;
            close $kc_fh;
            $api = Kubernetes::REST::Kubeconfig->new(
                kubeconfig_path => $kc_fh->filename,
            )->api;
            OCP::K8s->register($api);
        }
    }

    my $user = OCP::ReadonlyKubeconfig->sa_name($name);

    if ($self->revoke) {
        my @gone = OCP::ReadonlyKubeconfig->revoke($api, $name);
        print STDERR @gone
            ? "Revoked '$user': deleted " . join(', ', @gone) . ".\n"
            : "Nothing to revoke: '$user' does not exist.\n";
        return 0;
    }

    my $token = OCP::ReadonlyKubeconfig->ensure($api, $name);
    print OCP::ReadonlyKubeconfig->kubeconfig(
        admin_kubeconfig => $admin,
        cluster_name     => $cname,
        name             => $name,
        token            => $token,
    );
    print STDERR "Read-only kubeconfig for '$user' on STDOUT. The token is a secret; "
        . "revoke with: ocp kubeconfig --readonly --revoke --name $name\n";
    return 0;
}

sub execute {
    my ($self, $args, $chain) = @_;

    if ($self->readonly || $self->revoke || defined $self->name) {
        my $name = $self->_check_options;
        return $self->_readonly($name);
    }

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
    ocp kubeconfig --readonly [--name NAME] > readonly.yaml
    ocp kubeconfig --readonly --revoke --name NAME

=head1 DESCRIPTION

Decrypts F<kubeconfig.yaml> and hands it out. Without options it goes to
stdout, so it can be redirected anywhere.

C<--export> merges it into your existing kubeconfig instead of overwriting
it: cluster, user and context are renamed from the distribution's C<default>
to the OCP cluster name, entries of other clusters stay untouched, and the
previous file is kept as F<< <target>.ocp-bak >>. See L<OCP::Kubeconfig>.

Inside a container the merge target is the container's home directory, so
C<--export> warns and points at stdout or C<--output> instead.

=head1 READ-ONLY ACCESS

C<--readonly> hands out a kubeconfig for someone who must look at the cluster
but not touch it, with no SSH and without the sops-encrypted admin kubeconfig
(PIN/age as for any other command are needed once, by whoever runs this).
It creates, idempotently via Server-Side Apply, in C<ocp-system>:

=over

=item * ServiceAccount C<ocp-readonly-NAME>

=item * ClusterRoleBinding to the built-in ClusterRole C<view>

=item * ClusterRole C<ocp-readonly> (get/list/watch on Nodes, OCPNodes,
OCPNodeProviders) with its ClusterRoleBinding

=item * Secret C<ocp-readonly-NAME-token> (service-account-token)

=back

and prints a kubeconfig carrying that token to STDOUT (server and CA from the
admin kubeconfig; context and cluster are the cluster name, user is
C<ocp-readonly-NAME>). Hints go to STDERR. Nothing is saved in F<.ocp/> or
the project. Running it again returns the same token.

The token is a secret. It is read-only, but note what C<view> covers: no
Secrets, and no Nodes or OCP CRDs, which the extra ClusterRole C<ocp-readonly>
adds. Treat the file like a password.

Revoke with C<ocp kubeconfig --readonly --revoke --name NAME>: deletes the
token Secret, both ClusterRoleBindings and the ServiceAccount (the token stops
working at once). The shared ClusterRole C<ocp-readonly> always stays; it
grants nothing without a binding. Revoking twice is fine.

=head1 OPTIONS

=head2 --readonly

See above. Cannot be combined with C<-e>, C<-o> or C<-r>.

=head2 --name NAME

Account name, a DNS label of at most 32 characters. Default C<leitstand>.
Only with C<--readonly>.

=head2 --revoke

Remove the account. Only with C<--readonly>.

=head2 --export, -e

Merge into C<$KUBECONFIG> (first entry) or F<~/.kube/config>.

=head2 --output FILE, -o FILE

Write the kubeconfig to FILE (mode 0600). No merging.

=head2 --refresh, -r

Not implemented. The stored F<kubeconfig.yaml> is authoritative.

=cut

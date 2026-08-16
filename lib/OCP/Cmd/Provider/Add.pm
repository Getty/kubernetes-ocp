package OCP::Cmd::Provider::Add;
# ABSTRACT: Add an OCPNodeProvider CR

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use MIME::Base64 qw(encode_base64);
use Kubernetes::REST::Kubeconfig;
use OCP::Choices;
use OCP::Config;
use OCP::Provider;
use OCP::Secrets;
use OCP::K8s;

with 'OCP::Role::Cmd';

option name => (
    is       => 'ro',
    format   => 's',
    required => 1,
    doc      => 'Provider name',
);

option type => (
    is       => 'ro',
    format   => 's',
    required => 1,
    doc      => 'Provider type: hetzner|ssh|local',
);

option token_file => (
    is     => 'ro',
    format => 's',
    doc    => 'File containing API token',
);

option location => (
    is     => 'ro',
    format => 's',
    doc    => 'Default location (hetzner only)',
);

option server_type => (
    is     => 'ro',
    format => 's',
    doc    => 'Default server type (hetzner only)',
);

option image => (
    is     => 'ro',
    format => 's',
    doc    => 'Default image (hetzner only)',
);

option ssh_key_name => (
    is     => 'ro',
    format => 's',
    doc    => 'Uploaded SSH key every server gets (hetzner only; '
            . 'defaults to ocp-<cluster>-admin)',
);

option default => (
    is      => 'ro',
    is_bool => 1,
    doc     => 'Mark as default provider',
);

has k8s => (is => 'rw');

sub _k8s {
    my $self = shift;
    return $self->k8s if $self->k8s;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config  = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $kc_content = $secrets->read_kubeconfig;
    die "ERROR: Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
        unless $kc_content;

    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$kc_fh} $kc_content;
    close $kc_fh;

    my $api = Kubernetes::REST::Kubeconfig->new(
        kubeconfig_path => $kc_fh->filename,
    )->api;

    OCP::K8s->register($api);
    $self->k8s($api);
    return $api;
}

sub _validate_flags {
    my ($self) = @_;

    my $type = $self->type;

    if ($type eq 'hetzner') {
        die "--token-file is required for type 'hetzner'\n"
            unless $self->token_file;
    }
    elsif ($type eq 'ssh' || $type eq 'local') {
        die "--token-file is only valid for type 'hetzner'\n"
            if $self->token_file;
        die "--location is only valid for type 'hetzner' (--location given for '$type')\n"
            if $self->location;
        die "--server-type is only valid for type 'hetzner' (--server-type given for '$type')\n"
            if $self->server_type;
        die "--image is only valid for type 'hetzner' (--image given for '$type')\n"
            if $self->image;
        die "--ssh-key-name is only valid for type 'hetzner' (--ssh-key-name given for '$type')\n"
            if $self->ssh_key_name;
    }
    else {
        die OCP::Choices::unknown('provider type', $type,
            [ OCP::Provider->types ]);
    }
}

# Which uploaded key servers created through this provider boot with.
#
# Without it the provider is written, `ocp node add` reaches
# OCP::Provider::Hetzner::create_server with no key, and that refuses (karr
# #92) — so the default matters. It is derived from the project config,
# which is the same source bootstrap uploads the key from
# (OCP::Config::admin_ssh_key_name); --ssh-key-name overrides it for a
# Hetzner project whose key was uploaded under some other name.
#
# No project on disk (the command is being driven with an injected k8s
# client) means there is nothing to derive from, and guessing a key name
# would be worse than leaving it out: create_server then says what is
# missing instead of creating a machine nobody can reach.
sub _resolve_ssh_key_name {
    my ($self) = @_;

    return $self->ssh_key_name if $self->ssh_key_name;

    my $file = eval { $self->ocp->config } or return undef;
    return undef unless -f $file;

    my $config = eval { OCP::Config->new(file => $file) } or return undef;
    return $config->admin_ssh_key_name;
}

# Which cluster the provider being written serves.
#
# Same source and same reason as the key name above: the project config is
# what `ocp apply` labels its own servers from, so a provider added by hand
# has to agree with it or its servers land under a different ocp-cluster label
# than the control plane's and `ocp destroy` walks past them (karr #98).
#
# No flag overrides this. The cluster has exactly one name and it is in
# ocp.yaml; an override would only be a way to get it wrong. With no project
# on disk there is nothing to read, and the field is then left off rather than
# guessed — OCP::Provider::from_cr refuses with a message the moment the CR is
# used, which is better than a machine nobody can find.
sub _resolve_cluster_name {
    my ($self) = @_;

    my $file = eval { $self->ocp->config } or return undef;
    return undef unless -f $file;

    my $config = eval { OCP::Config->new(file => $file) } or return undef;
    return $config->name;
}

sub _strip_default_annotation {
    my ($self, $api) = @_;

    my $ns   = 'ocp-system';
    my $list = $api->list('OCPNodeProvider', namespace => $ns);

    for my $obj (@{ $list->items // [] }) {
        my $p   = $api->k8s->object_to_struct($obj);
        my $ann = $p->{metadata}{annotations} // {};
        next unless ($ann->{'ocp.internal/default'} // '') eq 'true';
        next if $p->{metadata}{name} eq $self->name;

        my %new_ann = %$ann;
        delete $new_ann{'ocp.internal/default'};

        $api->patch(
            'OCPNodeProvider',
            name      => $p->{metadata}{name},
            namespace => $ns,
            patch     => { metadata => { annotations => \%new_ann } },
        );
    }
}

sub execute {
    my ($self, $args, $chain) = @_;

    $self->_validate_flags;

    my $api  = $self->_k8s;
    my $ns   = 'ocp-system';
    my $name = $self->name;
    my $type = $self->type;

    # Resolved once for every provider type: it describes the cluster, not the
    # backend, and both CR shapes below carry it.
    my $cluster_name = $self->_resolve_cluster_name;

    if ($type eq 'hetzner') {
        my $token_file = $self->token_file;
        die "Token file '$token_file' not found\n" unless -f $token_file;

        open my $fh, '<', $token_file or die "Cannot read '$token_file': $!\n";
        my $token = do { local $/; <$fh> };
        close $fh;
        $token =~ s/\s+$//;

        my $secret_name = "ocp-provider-${name}-token";
        my $token_b64   = encode_base64($token, '');

        my $secret = {
            apiVersion => 'v1',
            kind       => 'Secret',
            metadata   => {
                name      => $secret_name,
                namespace => $ns,
            },
            type => 'Opaque',
            data => {
                token => $token_b64,
            },
        };

        $api->ensure($secret);

        if ($self->default) {
            $self->_strip_default_annotation($api);
        }

        my %annotations = ();
        $annotations{'ocp.internal/default'} = 'true' if $self->default;

        my %hetzner_spec = (
            tokenSecretRef => { name => $secret_name, key => 'token' },
        );
        $hetzner_spec{location}   = $self->location    if $self->location;
        $hetzner_spec{serverType} = $self->server_type if $self->server_type;
        $hetzner_spec{image}      = $self->image        if $self->image;

        my $key_name = $self->_resolve_ssh_key_name;
        $hetzner_spec{sshKeyName} = $key_name if $key_name;

        my $cr = {
            apiVersion => 'ocp.internal/v1',
            kind       => 'OCPNodeProvider',
            metadata   => {
                name        => $name,
                namespace   => $ns,
                annotations => \%annotations,
            },
            spec => {
                type    => 'hetzner',
                ($cluster_name ? (clusterName => $cluster_name) : ()),
                hetzner => \%hetzner_spec,
            },
        };

        $api->ensure($cr);
    }
    elsif ($type eq 'ssh' || $type eq 'local') {
        if ($self->default) {
            $self->_strip_default_annotation($api);
        }

        my %annotations = ();
        $annotations{'ocp.internal/default'} = 'true' if $self->default;

        my $cr = {
            apiVersion => 'ocp.internal/v1',
            kind       => 'OCPNodeProvider',
            metadata   => {
                name        => $name,
                namespace   => $ns,
                annotations => \%annotations,
            },
            spec => {
                type => $type,
                ($cluster_name ? (clusterName => $cluster_name) : ()),
            },
        };

        $api->ensure($cr);
    }

    print "Provider '$name' ($type) added.\n";
    return 0;
}

1;

__END__

=head1 NAME

OCP::Cmd::Provider::Add - Add an OCPNodeProvider CR

=head1 SYNOPSIS

    ocp provider add --name hetzner-a --type hetzner \
                     --token-file token.txt --default
    ocp provider add --name local-a   --type local

=head1 DESCRIPTION

Creates an OCPNodeProvider CR in the C<ocp-system> namespace.  For
Hetzner providers it also creates an C<Opaque> Secret containing the API
token (base64-encoded).  The C<--default> flag sets the
C<ocp.internal/default> annotation and removes it from any previous
default provider.

Every CR carries C<spec.clusterName>, the name of the cluster the provider
serves, read from C<ocp.yaml>.  It is what L<OCP::Provider::Hetzner> stamps
onto each server as the C<ocp-cluster> label and what C<ocp destroy> searches
by, so a hand-added provider that disagreed with the project would produce
servers no teardown ever finds.  There is deliberately no flag for it — the
cluster has one name.  With no project on disk it is left off, and
L<OCP::Provider/from_cr> then refuses to build the adapter at all.

C<--location>, C<--server-type> and C<--image> write
C<spec.hetzner.location>, C<.serverType> and C<.image>: what every node of
this provider gets when its own OCPNode spec names none.  That is rank 3 of
the four L<OCP::Provider::Hetzner/create_server> resolves — a node's own
C<ocp node add --location> still wins, and with none of them given the code
default applies.  A provider named C<hetzner-nbg1> is worth having for
exactly this reason; until karr #100 the fields were written here and read
nowhere, so C<--location nbg1> changed no server.

Each is written only when the flag is given.  Leaving one out is a real
answer — "this provider does not care" — and the OCPNodeProvider CRD
deliberately declares no schema default, so nothing materialises one behind
your back.

A Hetzner CR also carries C<spec.hetzner.sshKeyName>, the uploaded key every
server created through it boots with.  It defaults to the cluster's admin key
name (C<ocp-E<lt>clusterE<gt>-admin>, what C<ocp apply> uploads during
bootstrap); pass C<--ssh-key-name> when the key lives in the Hetzner project
under a different name.  Without it L<OCP::Provider::Hetzner> refuses to
create a server rather than leaving an unreachable machine running.

=head1 SEE ALSO

L<OCP::Cmd::Provider::Rm>, L<OCP::Cmd::Provider::Ls>, L<OCP::Provider>

=cut

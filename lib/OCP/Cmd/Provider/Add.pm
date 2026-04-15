package OCP::Cmd::Provider::Add;
# ABSTRACT: Add an OCPNodeProvider CR

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use MIME::Base64 qw(encode_base64);
use Kubernetes::REST::Kubeconfig;
use OCP::Config;
use OCP::Secrets;
use OCP::K8s;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

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
    }
    else {
        die "Unknown provider type '$type'. Valid: hetzner, ssh, local\n";
    }
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
            },
        };

        $api->ensure($cr);
    }

    print "Provider '$name' ($type) added.\n";
    return 0;
}

1;

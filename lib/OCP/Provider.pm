package OCP::Provider;
# ABSTRACT: Provider factory for infrastructure backends

use strict;
use warnings;

our $VERSION = '0.001';

sub from_cr {
    my ($class, $cr, %opts) = @_;

    my $k8s  = $opts{k8s};
    my $type = $cr->{spec}{type} // 'hetzner';
    my $name = $cr->{metadata}{name};
    my $ns   = $cr->{metadata}{namespace} // 'ocp-system';

    if ($type eq 'hetzner') {
        require OCP::Provider::Hetzner;
        require MIME::Base64;

        my $hspec  = $cr->{spec}{hetzner} // {};
        my $ref    = $hspec->{tokenSecretRef} // {};
        my $secret_name = $ref->{name} or die "from_cr: spec.hetzner.tokenSecretRef.name missing\n";
        my $secret_key  = $ref->{key} // 'token';

        die "from_cr: k8s client required for hetzner provider\n" unless $k8s;

        my $secret = $k8s->get(
            'Secret',
            name      => $secret_name,
            namespace => $ns,
        );
        my $encoded = $secret->{data}{$secret_key}
            or die "from_cr: Secret '$secret_name' has no key '$secret_key'\n";
        my $token = MIME::Base64::decode_base64($encoded);

        return OCP::Provider::Hetzner->new(
            token        => $token,
            cluster_name => $name,
        );
    } elsif ($type eq 'ssh') {
        require OCP::Provider::SSH;
        my $ssh_key_path = $cr->{spec}{ssh}{keyPath} // '';
        return OCP::Provider::SSH->new(
            ($ssh_key_path ? (ssh_key_path => $ssh_key_path) : ()),
        );
    } elsif ($type eq 'local') {
        require OCP::Provider::Local;
        return OCP::Provider::Local->new();
    } else {
        die "Unsupported provider type: $type\n";
    }
}

sub for_spec {
    my ($class, $spec, %opts) = @_;
    my $type = $spec->{provider} // 'hetzner';

    if ($type eq 'hetzner') {
        require OCP::Provider::Hetzner;
        return OCP::Provider::Hetzner->new(
            token        => $opts{token},
            cluster_name => $opts{cluster_name},
        );
    } elsif ($type eq 'ssh') {
        require OCP::Provider::SSH;
        return OCP::Provider::SSH->new(
            ssh_key_path => $opts{ssh_key_path},
        );
    } elsif ($type eq 'local') {
        require OCP::Provider::Local;
        return OCP::Provider::Local->new(
            verbose => $opts{verbose} // 0,
        );
    } else {
        die "Unsupported provider: $type\n";
    }
}

1;

__END__

=head1 NAME

OCP::Provider - Factory for infrastructure provider backends

=head1 SYNOPSIS

    use OCP::Provider;

    my $provider = OCP::Provider->for_spec($cp_spec,
        token        => $hetzner_token,
        cluster_name => $config->name,
        ssh_key_path => $ssh_key_path,
    );

    $provider->upload_ssh_key($key_name, $pubkey);
    my $server = $provider->create_server(%opts);
    $provider->cleanup_on_failure($server->{id});

=head1 DESCRIPTION

Factory that returns the appropriate provider based on the control plane spec.

=cut

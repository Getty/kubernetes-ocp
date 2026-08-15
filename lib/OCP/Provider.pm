package OCP::Provider;
# ABSTRACT: Provider factory for infrastructure backends

use strict;
use warnings;

# Two entry points, one dispatch.
#
# `for_spec` is the CLI/bootstrap path: the control plane spec is a plain hash
# from the YAML file, and credentials (Hetzner token, SSH key path) come in as
# named arguments because the CLI just decrypted them.
#
# `from_cr` is the in-cluster path: an OCPNodeProvider CR is the source of
# truth, and the Hetzner token lives in a Kubernetes Secret that only a
# Kubernetes client can fetch.
#
# Both normalise to the same %args shape and call _build(). Adding a fourth
# provider is one `elsif` in _build(); the entry points stay thin because they
# only know how to gather credentials, not how to dispatch.
sub from_cr {
    my ($class, $cr, %opts) = @_;

    my $type = $cr->{spec}{type} // 'hetzner';
    my %args = (
        type => $type,
        ($opts{k8s} ? (k8s => $opts{k8s}) : ()),
    );

    if ($type eq 'hetzner') {
        my $k8s = $opts{k8s}
            or die "from_cr: k8s client required for hetzner provider\n";

        my $name = $cr->{metadata}{name};
        my $ns   = $cr->{metadata}{namespace} // 'ocp-system';

        require MIME::Base64;
        my $hspec  = $cr->{spec}{hetzner} // {};
        my $ref    = $hspec->{tokenSecretRef} // {};
        my $secret_name = $ref->{name}
            or die "from_cr: spec.hetzner.tokenSecretRef.name missing\n";
        my $secret_key  = $ref->{key} // 'token';

        my $secret = $k8s->get(
            'Secret',
            name      => $secret_name,
            namespace => $ns,
        );
        my $secret_hash = ref($secret) eq 'HASH'
            ? $secret
            : $k8s->k8s->object_to_struct($secret);
        my $encoded = $secret_hash->{data}{$secret_key}
            or die "from_cr: Secret '$secret_name' has no key '$secret_key'\n";

        $args{token}        = MIME::Base64::decode_base64($encoded);
        $args{cluster_name} = $name;
    }
    elsif ($type eq 'ssh') {
        $args{ssh_key_path} = $cr->{spec}{ssh}{keyPath} // '';
    }
    # 'local' needs no extra args from the CR.

    return $class->_build(\%args);
}

sub for_spec {
    my ($class, $spec, %opts) = @_;

    return $class->_build({
        type         => $spec->{provider} // 'hetzner',
        token        => $opts{token},
        cluster_name => $opts{cluster_name},
        ssh_key_path => $opts{ssh_key_path},
        verbose      => $opts{verbose},
    });
}

# The single dispatch. Each branch is the construction contract for one
# provider — what attributes it needs, which package to load. The two entry
# points above are just ways of gathering those attributes.
sub _build {
    my ($class, $args) = @_;
    my $type = $args->{type};

    if ($type eq 'hetzner') {
        require OCP::Provider::Hetzner;
        return OCP::Provider::Hetzner->new(
            token        => $args->{token},
            cluster_name => $args->{cluster_name},
        );
    }
    elsif ($type eq 'ssh') {
        require OCP::Provider::SSH;
        return OCP::Provider::SSH->new(
            ($args->{ssh_key_path} ? (ssh_key_path => $args->{ssh_key_path}) : ()),
        );
    }
    elsif ($type eq 'local') {
        require OCP::Provider::Local;
        return OCP::Provider::Local->new(
            verbose => $args->{verbose} // 0,
        );
    }
    else {
        die "Unsupported provider: $type\n";
    }
}

1;

__END__

=synopsis

    use OCP::Provider;

    # CLI/bootstrap path — credentials come in as named args
    my $prov = OCP::Provider->for_spec($cp_spec,
        token        => $hetzner_token,
        cluster_name => $config->name,
        ssh_key_path => $ssh_key_path,
        verbose      => 1,
    );

    # In-cluster path — credentials are fetched from a Kubernetes Secret
    my $prov = OCP::Provider->from_cr($provider_cr, k8s => $api);

    $prov->upload_ssh_key($key_name, $pubkey);
    my $server = $prov->create_server(name => ..., node => ..., role => ...);
    $prov->cleanup_on_failure($server->{id});

=description

Factory that returns the appropriate L<OCP::Provider> adapter based on the
provider declared in either the control-plane spec (C<provider: hetzner|ssh|local>)
or an C<OCPNodeProvider> CR (C<spec.type>).

Two entry points exist because the source of the credentials differs:

=over 4

=item *

C<for_spec($spec, %opts)> — used by C<ocp apply> and C<ocp destroy>. The Hetzner
token was just decrypted from C<secrets.yaml> and arrives as a named argument.

=item *

C<from_cr($cr, k8s => $api)> — used by C<ocp node add|rm> and robocop. The
token lives in a Kubernetes Secret referenced by the CR, so a C<k8s> client
is required to fetch it.

=back

Both entry points normalise to the same internal shape and dispatch through a
single private C<_build> method. Add a fourth provider in exactly one place.

=method for_spec

    my $prov = OCP::Provider->for_spec($spec,
        token        => ...,
        cluster_name => ...,
        ssh_key_path => ...,
        verbose      => 0|1,
    );

CLI/bootstrap entry point.  C<$spec> is the control-plane spec hash; the
named arguments carry the credentials.

=method from_cr

    my $prov = OCP::Provider->from_cr($cr, k8s => $api);

In-cluster entry point.  C<$cr> is an C<OCPNodeProvider> resource as a hash;
C<k8s> is a L<Kubernetes::REST> client, required when C<spec.type> is
C<hetzner> (the token is fetched from the referenced Secret).

=seealso

L<OCP::Provider::Hetzner>, L<OCP::Provider::SSH>, L<OCP::Provider::Local>,
L<OCP::Role::Provider::ExistingHost>

=cut

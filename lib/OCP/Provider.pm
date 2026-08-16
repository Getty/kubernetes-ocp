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

        $args{token} = MIME::Base64::decode_base64($encoded);

        # The cluster this provider serves — and NOT the CR's own name.
        #
        # It used to be $cr->{metadata}{name}, which ensure_provider_cr writes
        # as "<type>-default". So every server the worker path created was
        # labelled ocp-cluster=hetzner-default while bootstrap labelled the
        # control plane ocp-cluster=<cluster>. Two silent consequences, both
        # costing money: `ocp destroy` searches ocp-cluster=<cluster> and never
        # saw those machines — they keep running and keep billing while the
        # teardown reports success — and server_exists searched the same wrong
        # label pair, so a second provisioning pass created a SECOND server
        # instead of recognising the one already standing there (karr #98).
        #
        # The CR is the carrier because nothing else can be: OCP::Node is
        # trigger-neutral, and robocop has no cluster identity beyond what is
        # stored in the cluster. Exactly the reason sshKeyName lives here too
        # (karr #92), and the reason a label on the CR was rejected in its
        # favour — metadata is shared ground that kustomize, kubectl and other
        # controllers rewrite, and this value decides which paid servers a
        # teardown finds.
        #
        # Absent means refuse, for the same reason the missing key below does:
        # an adapter built without it produces machines that run, bill, and
        # cannot be found again. One `ocp apply` rewrites the CR.
        my $cluster = $cr->{spec}{clusterName};
        die "from_cr: OCPNodeProvider/$name in $ns has no spec.clusterName.\n"
          . "Servers created through it would be labelled with the provider's "
          . "name instead of the cluster's, and `ocp destroy` would never find "
          . "them again — they would run and be billed forever.\n"
          . "Run `ocp apply` once to rewrite the provider CR, or set "
          . "spec.clusterName to the cluster name from ocp.yaml.\n"
            unless defined $cluster && length $cluster;
        $args{cluster_name} = $cluster;

        # Which uploaded SSH key a server created through this provider gets.
        # The CR is the carrier because it is the only end of the seam that
        # knows: OCP::Node is trigger-neutral, and robocop -- the other
        # caller of create_server -- never learns the cluster name. Absent
        # here means create_server refuses rather than building a machine
        # with an empty authorized_keys (karr #92).
        $args{ssh_key_name} = $hspec->{sshKeyName};

        # What every node of this provider gets when it names nothing itself.
        # These three were written by `ocp provider add` and shown by `ocp
        # provider ls` since the beginning and read by NOBODY, so
        # `--location nbg1` moved no server (karr #100). They land at rank 3 of
        # OCP::Provider::Hetzner::create_server's four: below the node's own
        # spec, above the code default.
        #
        # They stay under spec.hetzner, unlike clusterName, because that is
        # what they are: Hetzner backend configuration. clusterName went
        # top-level in karr #98 for the opposite reason -- it names the cluster,
        # not the backend, and every provider type has one.
        #
        # Only from_cr fills them. for_spec is the bootstrap path and there is
        # no provider CR there at all; the control plane's server type comes
        # out of ocp.yaml and is passed to create_server by name, which is
        # rank 1 and beats this outright.
        $args{default_server_type} = $hspec->{serverType};
        $args{default_image}       = $hspec->{image};
        $args{default_location}    = $hspec->{location};
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
            # Guarded rather than passed straight: the attributes default to
            # '' and treat '' as absent, and an explicit undef would defeat
            # both. Absent from the CR must arrive as absent on the adapter.
            ($args->{ssh_key_name} ? (ssh_key_name => $args->{ssh_key_name}) : ()),
            ($args->{default_server_type}
                ? (default_server_type => $args->{default_server_type}) : ()),
            ($args->{default_image}
                ? (default_image       => $args->{default_image})       : ()),
            ($args->{default_location}
                ? (default_location    => $args->{default_location})    : ()),
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

For C<hetzner>, C<spec.clusterName> becomes the adapter's
L<OCP::Provider::Hetzner/cluster_name> — the value of the C<ocp-cluster>
label every server gets, and the selector C<ocp destroy> tears the cluster
down by.  It is B<not> the CR's own name: C<ocp apply> writes the CR as
C<< <type>-default >>, so taking C<metadata.name> labelled every worker
C<ocp-cluster=hetzner-default> while the control plane carried the real
cluster name.  Those workers survived C<ocp destroy> and kept billing, and
C<server_exists> could never match one, so a repeat provisioning run built a
second server next to the first (karr #98).

A CR without C<spec.clusterName> makes C<from_cr> die rather than build an
adapter that would create unfindable machines; one C<ocp apply> rewrites it.

For C<hetzner>, C<spec.hetzner.sshKeyName> becomes the adapter's
L<OCP::Provider::Hetzner/ssh_key_name> — the key every server created
through this provider boots with.  It is the only route by which a worker
learns which key to use: L<OCP::Node> is trigger-neutral and neither it nor
robocop knows the cluster name.

C<spec.hetzner.serverType>, C<.image> and C<.location> become
L<OCP::Provider::Hetzner/default_server_type>, L</default_image> and
L</default_location> — what a node of this provider gets when its own OCPNode
spec names none.  They sit at rank 3 of the four
L<OCP::Provider::Hetzner/create_server> resolves: below the node's own spec,
above the code default.  Written since the beginning by C<ocp provider add>
and read by nobody until karr #100, which is why C<--location nbg1> used to
move no server at all.

C<for_spec> sets none of them, and that is the point rather than an omission:
it is the bootstrap path, there is no provider CR in it, and the control
plane's server type comes out of C<ocp.yaml> as a named C<create_server>
argument — rank 1, which beats every rank below.

=seealso

L<OCP::Provider::Hetzner>, L<OCP::Provider::SSH>, L<OCP::Provider::Local>,
L<OCP::Role::Provider::ExistingHost>

=cut

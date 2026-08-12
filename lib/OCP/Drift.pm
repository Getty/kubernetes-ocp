package OCP::Drift;
# ABSTRACT: Detect drift between the OCP spec and the running cluster

use Moo;
use OCP::Versions;

our $VERSION = '0.001';

has config => (is => 'ro', required => 1);

# Kubernetes::REST api. Without it only spec drift is detectable.
has api => (is => 'ro');

# Components whose running version can be read off a workload image.
# 'remedy' is the Rex task that brings the cluster back to the target.
our @COMPONENT_PROBES = (
    {
        component => 'cilium',
        label     => 'Cilium',
        kind      => 'Deployment',
        name      => 'cilium-operator',
        namespace => 'kube-system',
        remedy    => 'upgrade_cilium',
    },
    {
        component => 'cert_manager',
        label     => 'cert-manager',
        kind      => 'Deployment',
        name      => 'cert-manager',
        namespace => 'cert-manager',
        remedy    => 'upgrade_cert_manager',
        skip_if   => 'no_cert',
    },
);

sub detect {
    my ($self) = @_;

    my @drift = $self->spec_drift;
    push @drift, $self->component_drift if $self->api;

    return \@drift;
}

#
# Spec drift: what ocp.yaml pinned vs. what we recorded as real
#

sub spec_drift {
    my ($self) = @_;

    my $config  = $self->config;
    my @status  = @{ $config->nodes_status };
    my @cps     = @{ $config->control_planes };
    my @drift;

    my $index = 0;
    for my $cp (@cps) {
        $index++;

        my $pinned = $cp->{public_ip};
        next unless defined $pinned && length $pinned;

        # Match by name when the spec names the node. A single unnamed
        # control plane maps onto the single recorded control plane.
        my $name = $cp->{name};
        my ($node) = $name
            ? grep { ($_->{name} // '') eq $name } @status
            : (@cps == 1 ? grep { ($_->{role} // 'control-plane') !~ /worker/ } @status : ());
        next unless $node;

        my $actual = $node->{public_ip};
        next unless defined $actual && length $actual && $actual ne '-';
        next if $actual eq $pinned;

        my $label = $name // $node->{name} // "cp-$index";

        push @drift, {
            kind      => 'spec',
            component => $label,
            label     => $label,
            expected  => $pinned,
            actual    => $actual,
            message   => "$label: ocp.yaml pins public_ip $pinned, recorded state says $actual",
            remedy    => undef,
        };
    }

    return @drift;
}

#
# Component drift: target versions vs. what runs in the cluster
#

sub component_drift {
    my ($self) = @_;

    my $config = $self->config;
    my @drift;

    for my $probe (@COMPONENT_PROBES) {
        my $skip = $probe->{skip_if};
        next if $skip && $config->can($skip) && $config->$skip;

        my $expected = OCP::Versions->get_component_version($probe->{component});
        next unless defined $expected;

        my $object = eval {
            $self->api->get($probe->{kind},
                name      => $probe->{name},
                namespace => $probe->{namespace},
            );
        };

        unless ($object) {
            push @drift, {
                kind      => 'missing',
                component => $probe->{component},
                label     => $probe->{label},
                expected  => $expected,
                actual    => undef,
                message   => "$probe->{label} is not deployed (expected $expected)",
                remedy    => undef,   # a full deploy handles this, not an upgrade
            };
            next;
        }

        my $image = _dig($object, qw(spec template spec containers)) || [];
        $image = ref $image eq 'ARRAY' ? _dig($image->[0], 'image') : undef;
        my $actual = image_version($image);

        next unless length $actual;
        next if _same_version($actual, $expected);

        push @drift, {
            kind      => 'version',
            component => $probe->{component},
            label     => $probe->{label},
            expected  => $expected,
            actual    => $actual,
            message   => "$probe->{label} runs $actual, expected $expected",
            remedy    => {
                type   => 'rex',
                task   => $probe->{remedy},
                params => { version => $expected },
            },
        };
    }

    push @drift, $self->distribution_drift;

    return @drift;
}

# The Kubernetes distribution itself. Upgrading it is a node-by-node dance,
# so this is reported but never auto-remedied.
sub distribution_drift {
    my ($self) = @_;

    my $config = $self->config;
    my $dist   = $config->distribution;
    my $expected = $config->version || OCP::Versions->get_component_version($dist);
    return unless defined $expected && length $expected;

    my $list = eval { $self->api->list('Node') } or return;
    my $items = _dig($list, 'items') || [];
    return unless ref $items eq 'ARRAY' && @$items;

    my @drift;
    for my $node (@$items) {
        my $name    = _dig($node, qw(metadata name)) // '<unknown>';
        my $running = _dig($node, qw(status nodeInfo kubeletVersion));
        next unless defined $running && length $running;
        next if _same_version($running, $expected);

        push @drift, {
            kind      => 'version',
            component => $dist,
            label     => "$dist on $name",
            expected  => $expected,
            actual    => $running,
            message   => "$name runs $running, expected $expected",
            remedy    => undef,
        };
    }

    return @drift;
}

#
# Helpers
#

# Tag of a container image reference, digest and registry port aware.
sub image_version {
    my ($image) = @_;
    return '' unless defined $image && length $image;

    (my $ref = $image) =~ s/\@sha256:[0-9a-f]+\z//i;
    my ($tag) = $ref =~ m{:([^:/]+)\z};

    return $tag // '';
}

# Version strings are written inconsistently across manifests ('1.19.2' vs
# 'v1.19.2', '+rke2r1' suffixes). Compare on the numeric core.
sub _same_version {
    my ($a, $b) = @_;
    return 0 unless defined $a && defined $b;

    for ($a, $b) {
        s/\A[vV]//;
        s/\s+\z//;
    }

    return $a eq $b ? 1 : 0;
}

# Works on both plain hashrefs and IO::K8s objects.
sub _dig {
    my ($value, @path) = @_;

    for my $part (@path) {
        return undef unless defined $value;
        if (ref($value) eq 'HASH') {
            $value = $value->{$part};
        } elsif (ref($value) && eval { $value->can($part) }) {
            $value = $value->$part();
        } else {
            return undef;
        }
    }

    return $value;
}

# One line per drift entry, ready to print.
sub format_lines {
    my ($class, $drift) = @_;
    return map { "  [drift] $_->{message}" } @$drift;
}

1;

__END__

=head1 NAME

OCP::Drift - Detect drift between the OCP spec and the running cluster

=head1 SYNOPSIS

    use OCP::Drift;

    my $drift = OCP::Drift->new(config => $config, api => $api)->detect;

    for my $entry (@$drift) {
        print "$entry->{message}\n";
        next unless $entry->{remedy};
        $rex->run_task($entry->{remedy}{task}, %{ $entry->{remedy}{params} });
    }

=head1 DESCRIPTION

OCP writes computed values back into F<ocp.yaml> and pins component versions
in L<OCP::Versions>. Reality can move away from both: a server gets a new
address, a component was upgraded by hand, a deploy half-finished. This
module compares the two and reports every difference it finds, together with
the step that would fix it where such a step exists.

Detection is read-only. Applying the remedies is L<OCP::Cmd::Apply>'s job.

=head2 Drift entries

Each entry is a hashref:

=over 4

=item * B<kind> - C<spec>, C<version> or C<missing>

=item * B<component> - key in the version manifest, or the node name for spec drift

=item * B<label> - human readable name

=item * B<expected> / B<actual> - the two versions or values

=item * B<message> - one-line description

=item * B<remedy> - C<< { type => 'rex', task => ..., params => {...} } >>, or undef
when no automatic fix exists

=back

=head1 ATTRIBUTES

=head2 config

An L<OCP::Config>. Required.

=head2 api

A L<Kubernetes::REST> API object. Without it, only spec drift is detected.

=head1 METHODS

=head2 detect

    my $drift = $detector->detect;

All drift, as an arrayref of entries.

=head2 spec_drift

Values pinned in F<ocp.yaml> that no longer match F<.ocp/status.yaml>.

=head2 component_drift

Running component versions that differ from the version manifest, plus
components that should be deployed but are missing.

=head2 distribution_drift

Nodes whose kubelet version differs from the configured distribution version.
Never carries a remedy — distribution upgrades are a manual, node-by-node
operation.

=head2 image_version

    my $tag = OCP::Drift::image_version('quay.io/cilium/operator-generic:v1.19.2');

The tag of a container image reference. Handles digests and registry ports.

=head2 format_lines

    print "$_\n" for OCP::Drift->format_lines($drift);

Drift entries as printable lines.

=cut

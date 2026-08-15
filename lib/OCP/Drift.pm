package OCP::Drift;
# ABSTRACT: Detect drift between the OCP spec and the running cluster

use Moo;
use Socket;
use OCP::Versions;

has config => (is => 'ro', required => 1);

# Kubernetes::REST api. Without it only spec drift is detectable.
has api => (is => 'ro');

# Components whose running version can be read off a workload image.
#
#   remedy       the Rex task that brings the cluster back to the target, or
#                undef when nothing upgrades this in place
#   skip_if      config predicate: this cluster asked not to have the thing
#   optional     absence is not drift — the component only exists on some
#                clusters, so "not deployed" is a normal state and not a fault
#   self_healing a plain `ocp apply` re-applies this component's manifest, so
#                the run that reports the difference is also the run that
#                closes it. Reconcile uses it to not send the user looking for
#                a manual step, the same reason 'missing' entries stay quiet.
#
# What is NOT in here, and why: the rest of the GPU stack (nvidia_toolkit,
# nvidia_device_plugin, dcgm_exporter, nvidia_dcgm, nvidia_driver) is pinned in
# OCP::Versions but never appears in a workload OCP writes. OCP puts those
# versions into the ClusterPolicy CR and the GPU operator turns them into
# DaemonSets under names and container layouts it owns and changes between
# releases. Reading an image off a guessed DaemonSet name would report a
# version this module cannot stand behind; measuring them honestly means
# reading the ClusterPolicy spec, which has no IO::K8s class and needs a raw
# request plus a field path per component — a different mechanism than a probe
# table, and not one to invent on the way past.
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
    # NFD is deployed on every cluster (the GPU operator's gating reads the
    # labels it writes), from a manifest OCP generates, so both "not there"
    # and "wrong version" are real findings. No Rex task upgrades it: the
    # version is in the manifest, and apply re-applies the manifest.
    {
        component    => 'nfd',
        label        => 'NFD',
        kind         => 'Deployment',
        name         => 'nfd-master',
        namespace    => 'node-feature-discovery',
        remedy       => undef,
        self_healing => 1,
    },
    # The GPU operator only exists where there is an NVIDIA card and
    # gpu.enabled — which is why absence is not drift here. A cluster that has
    # one still gets told when the pinned version moved; that OCP writes this
    # Deployment itself is what makes the image readable at all.
    {
        component    => 'gpu_operator',
        label        => 'GPU Operator',
        kind         => 'Deployment',
        name         => 'gpu-operator',
        namespace    => 'gpu-operator',
        remedy       => undef,
        optional     => 1,
        self_healing => 1,
    },
);

# CoreDNS ships under a different name per distribution: k3s (like stock
# Kubernetes) calls the ConfigMap "coredns", RKE2 installs CoreDNS from a Helm
# chart and ends up with "rke2-coredns-rke2-coredns". The list lives here
# because both the writer (OCP::Cmd::Apply) and this reader need it, and Apply
# already loads this module — one list means the two can never end up looking
# in different places.
our @COREDNS_CONFIGMAPS = ('coredns', 'rke2-coredns-rke2-coredns');

# The name `ocp apply` points at the node that serves the registry NodePorts.
our $REGISTRY_HOSTNAME = 'registry.local';

sub detect {
    my ($self) = @_;

    my @drift = $self->spec_drift;
    if ($self->api) {
        push @drift, $self->component_drift;
        push @drift, $self->registry_dns_drift;
    }

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
            # Not every component belongs on every cluster. Reporting the GPU
            # operator as missing on a machine with no NVIDIA card would put a
            # permanent finding on `ocp status` that nothing should ever act on.
            next if $probe->{optional};

            push @drift, {
                kind      => 'missing',
                component => $probe->{component},
                label     => $probe->{label},
                expected  => $expected,
                actual    => undef,
                message   => "$probe->{label} is not deployed (expected $expected)",
                remedy    => undef,   # a full deploy handles this, not an upgrade
                ($probe->{self_healing} ? (self_healing => 1) : ()),
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
            remedy    => $probe->{remedy} ? {
                type   => 'rex',
                task   => $probe->{remedy},
                params => { version => $expected },
            } : undef,
            ($probe->{self_healing} ? (self_healing => 1) : ()),
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
# registry.local in CoreDNS
#
# Neither distribution lets OCP own this record. On k3s the ConfigMap belongs
# to the coredns addon (owner-gvk k3s.cattle.io/v1, Kind=Addon); the deploy
# controller restores its own Corefile whenever it re-applies that addon — a
# k3s upgrade, a server restart — and takes the registry.local entry with it.
# On RKE2 the ConfigMap belongs to the rke2-coredns Helm release and a chart
# upgrade resets it the same way. Observed on cortex: the entry was gone.
#
# `ocp apply` writes it back on every run, so the cluster heals itself the next
# time someone applies. What it did not do is say that the record was missing
# in the meantime, and the gap is quiet: image pulls for registry.local go
# through the containerd mirror to localhost:30501 and never ask DNS, so
# nothing breaks loudly. This probe is what makes the window visible.
#
# Why a probe and not an upgrade-proof record:
#
#   * k3s has a hook for it — the coredns-custom ConfigMap, mounted at
#     /etc/coredns/custom with optional=true (verified on the live k3s CoreDNS
#     deployment), imported by the stock Corefile as `*.server` outside the
#     root block. A `registry.local:53 { hosts { IP registry.local } }` snippet
#     there survives every addon re-apply, and CoreDNS 1.14.6 picks it up
#     live: its reload plugin hashes the Corefile *after* import expansion, so
#     a new snippet takes effect within one reload interval, no restart.
#   * RKE2 has no such hook. Its chart renders extraConfig as name plus
#     parameters and nothing else, so no `hosts { ... }` block can be
#     expressed through it; the only other lever is replacing the whole
#     `servers:` list in a HelmChartConfig, which means carrying a copy of the
#     chart's default Corefile in OCP and keeping it in sync per chart version.
#   * Running both at once is worse than either: measured, the more specific
#     `registry.local:53` block shadows the inline record completely, so a
#     stale snippet would silently win over the entry OCP keeps correct and
#     `ocp apply` would report an address the cluster does not answer with.
#
# So an upgrade-proof record would replace one verified common path with one
# verified path, one brittle path, and a migration to strip the inline entry
# from every existing cluster — for a name no OCP component resolves. Report
# the window instead; fix it when something is actually shown to fall into it.
#
sub registry_dns_drift {
    my ($self) = @_;

    # The same value the writer is handed (OCP::Cmd::Apply's reconcile path
    # passes cluster_status->{public_ip} straight into _configure_registry_dns)
    # and, crucially, put through the same resolution — see resolve_address.
    my $cp = $self->config->cluster_status->{public_ip};
    return unless defined $cp && length $cp && $cp ne '-';

    my $expected = resolve_address($cp);
    return unless defined $expected;

    my $corefile;
    for my $name (@COREDNS_CONFIGMAPS) {
        my $cm = eval {
            $self->api->get('ConfigMap', name => $name, namespace => 'kube-system');
        } or next;
        $corefile = _dig($cm, qw(data Corefile));
        last if defined $corefile;
    }

    # No CoreDNS ConfigMap under a name we know: not this probe's business.
    return unless defined $corefile;

    my $actual = corefile_host_address($corefile, $REGISTRY_HOSTNAME);
    return if defined $actual && $actual eq $expected;

    my $what = defined $actual
        ? "$REGISTRY_HOSTNAME resolves to $actual, expected $expected"
        : "$REGISTRY_HOSTNAME is missing from the CoreDNS Corefile (expected $expected)";

    # 'missing', not 'spec': `ocp apply` puts the record back as part of a
    # normal run, so the reconcile path must not tell the user to go looking
    # for a manual step. The message says so as a statement rather than as an
    # instruction, because the reconcile path prints it in the middle of the
    # very apply that is about to fix it.
    return {
        kind      => 'missing',
        component => 'registry_dns',
        label     => "$REGISTRY_HOSTNAME DNS",
        expected  => $expected,
        actual    => $actual,
        message   => "$what; ocp apply restores it",
        remedy    => undef,
    };
}

#
# Helpers
#

# A control plane's address as a dotted quad, or undef when it does not
# resolve to one.
#
# `control_planes: host:` is routinely a DNS name — cortex is reached as
# cortex.ai.citilan.de and answers on 10.230.30.155 — and with no node status
# recorded yet OCP::Config's cluster_status hands that name back as the
# public_ip. A Corefile can only carry an address, so the writer resolves
# before it writes. A reader that skips that step compares a name against an
# address and calls every correctly configured cluster drifted, which is what
# the first version of registry_dns_drift did. Both sides go through here.
sub resolve_address {
    my ($value) = @_;
    return undef unless defined $value && length $value;
    return $value if $value =~ /^\d+\.\d+\.\d+\.\d+$/;

    my $packed = Socket::inet_aton($value) or return undef;
    return Socket::inet_ntoa($packed);
}

# The address a Corefile maps a name to, or undef when it maps none.
#
# A hosts-plugin record is a line whose first token is an address and whose
# remaining tokens are names, wherever in the file that line sits. OCP writes
# it into the block the distribution already runs, but a server block someone
# added by hand answers for the name just as well — and a probe that only
# looked where OCP writes would call a working cluster drifted.
sub corefile_host_address {
    my ($corefile, $hostname) = @_;
    return undef unless defined $corefile && defined $hostname;

    for my $line (split /\n/, $corefile) {
        my @token = split ' ', $line;
        next unless @token >= 2;

        # An address, not a plugin name: hex digits, dots and colons only,
        # and at least one separator (`cache 30` is not a record).
        next unless $token[0] =~ /^[0-9a-fA-F.:]+$/ && $token[0] =~ /[.:]/;

        return $token[0] if grep { $_ eq $hostname } @token[1 .. $#token];
    }

    return undef;
}

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

=item * B<self_healing> - present and true when a plain C<ocp apply> re-applies
this component and thereby closes the entry. The reconcile path uses it to not
point the user at a manual step it is about to take itself.

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

Probed are Cilium, cert-manager, NFD and the GPU operator: the four whose
running version can be read off a workload OCP writes itself. The remaining
GPU pins (toolkit, device plugin, DCGM, DCGM exporter, driver) go into the
C<ClusterPolicy> the operator reconciles, not into a Deployment of OCP's, and
are deliberately not guessed at — see the comment on C<@COMPONENT_PROBES>.

Absence of the GPU operator is not reported: it only belongs on a cluster with
an NVIDIA card. Neither it nor NFD carries a remedy, because no Rex task
upgrades them — their version lives in a generated manifest that C<ocp apply>
re-applies, which is what C<self_healing> on those entries says.

=head2 distribution_drift

Nodes whose kubelet version differs from the configured distribution version.
Never carries a remedy — distribution upgrades are a manual, node-by-node
operation.

=head2 registry_dns_drift

The C<registry.local> record in the CoreDNS Corefile: missing, or pointing at
an address that is not the control plane's. Both distributions own that
ConfigMap themselves and reset it on an upgrade or a restart, taking the record
with them; C<ocp apply> writes it back, so the entry reports the window in
between rather than a permanent fault, and carries no remedy of its own.

=head2 resolve_address

    my $ip = OCP::Drift::resolve_address('cortex.ai.citilan.de');

A control plane's address as a dotted quad, or C<undef> when it does not
resolve to one. Addresses pass through untouched. Both the writer of the
C<registry.local> record and L</registry_dns_drift> derive the address they
expect through this function, so a control plane named by DNS cannot read as
drifted.

=head2 corefile_host_address

    my $ip = OCP::Drift::corefile_host_address($corefile, 'registry.local');

The address a Corefile maps a name to, or C<undef> when it maps none.

=head2 image_version

    my $tag = OCP::Drift::image_version('quay.io/cilium/operator-generic:v1.20.0');

The tag of a container image reference. Handles digests and registry ports.

=head2 format_lines

    print "$_\n" for OCP::Drift->format_lines($drift);

Drift entries as printable lines.

=cut

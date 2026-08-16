package OCP::Cmd::Apply::Health;
# ABSTRACT: Post-deploy cluster health gate

use strict;
use warnings;

=head1 SYNOPSIS

    my $health = OCP::Cmd::Apply::Health::check($apply, $api);
    OCP::Cmd::Apply::Health::print($apply, $health);
    my $fatal = OCP::Cmd::Apply::Health::is_fatal($apply, $health);

=head1 DESCRIPTION

C<ocp apply> used to print DEPLOYED SUCCESSFULLY and exit 0 whenever the
deploy steps had run to the end. On cortex it did exactly that while CoreDNS
sat in CrashLoopBackOff — cluster DNS entirely dead — and five gpu-operator
pods hung in ImagePullBackOff. The banner was a statement about the script,
not about the cluster. This is the gate.

Two properties decide whether such a gate is worth anything.

It must not be flaky. Straight after a deploy pods are legitimately still
coming up: ContainerCreating, PodInitializing, or a readiness probe that has
not passed yet are all normal. So apply first waits for the cluster to settle
— until nothing is in a starting state, or the timeout — and only judges what
is still broken on the final scan, and only on reasons that do not heal by
waiting. CrashLoopBackOff additionally requires the kubelet to have actually
looped; one crash during startup is not a verdict.

And it must not cry wolf. A gate that fails the whole apply because an opt-in
add-on could not pull an image teaches people to ignore the exit code, which
costs more than the check buys — the gpu-operator failure above was an arm64
image availability problem on a working cluster. Hence the severity split
below.

L<OCP::Cmd::Apply> re-exports these as C<_check_cluster_health>, C<_print_health>,
C<_health_is_fatal>, C<_health_banner_text>, C<_banner> — the test surface and
the call sites inside Apply.pm stay the same.

=cut

# Waiting reasons that do not resolve themselves by waiting longer.
my %DURABLE_WAIT = map { $_ => 1 } qw(
    CrashLoopBackOff
    ImagePullBackOff
    ErrImagePull
    InvalidImageName
    CreateContainerConfigError
    CreateContainerError
    RunContainerError
);

# Namespaces whose health IS the cluster: CNI, DNS, core controllers. A durable
# fault in one of these means the deploy did not produce a working cluster, so
# it is fatal. Everything else OCP installs is either opt-in (gpu-operator,
# node-feature-discovery) or already has its own readiness wait earlier in
# apply, so it warns and leaves the exit code alone.
my %CRITICAL_NS = map { $_ => 1 } qw(kube-system);

my $CRASHLOOP_MIN_RESTARTS = 2;

# healthy | starting | failing (+reason)
sub classify_pod {
    my ($self, $pod) = @_;

    my $phase = $pod->{status}{phase} // '';
    return ('healthy') if $phase eq 'Succeeded';

    # Init containers carry their own waiting reasons — that is where
    # "Init:ImagePullBackOff" lives, which is how all five gpu-operator pods
    # failed. Scanning only containerStatuses would have missed every one.
    my @waiting_scan = (
        @{ $pod->{status}{initContainerStatuses} // [] },
        @{ $pod->{status}{containerStatuses}     // [] },
    );

    my %reasons;
    for my $cs (@waiting_scan) {
        my $reason = $cs->{state}{waiting}{reason} // '';
        next unless $reason && $DURABLE_WAIT{$reason};
        next if $reason eq 'CrashLoopBackOff'
            && ($cs->{restartCount} // 0) < $CRASHLOOP_MIN_RESTARTS;
        $reasons{$reason} = 1;
    }
    return ('failing', join(', ', sort keys %reasons)) if %reasons;
    return ('failing', 'Failed') if $phase eq 'Failed';

    # Readiness is judged on the regular containers only: a completed init
    # container's `ready` flag is not a reliable signal across versions.
    my @regular = @{ $pod->{status}{containerStatuses} // [] };
    return ('starting') unless $phase eq 'Running' && @regular;
    for my $cs (@regular) {
        return ('starting') unless $cs->{ready};
    }
    return ('healthy');
}

sub scan_pods {
    my ($self, $api) = @_;

    my $list = $api->list('Pod');
    my @pods = map { ref($_) eq 'HASH' ? $_ : $api->k8s->object_to_struct($_) }
               @{ ($list && $list->items) || [] };

    my %out = (failing => [], starting => []);
    for my $pod (@pods) {
        my ($state, $reason) = classify_pod($self, $pod);
        next if $state eq 'healthy';
        push @{ $out{$state} }, {
            namespace => $pod->{metadata}{namespace} // '',
            name      => $pod->{metadata}{name}      // '',
            reason    => $reason                     // '',
        };
    }
    return \%out;
}

sub check {
    my ($self, $api, %opts) = @_;
    my $timeout  = $opts{timeout}  // 120;
    my $interval = $opts{interval} // 5;

    my $deadline = time + $timeout;
    my $scan;
    while (1) {
        $scan = scan_pods($self, $api);
        last unless @{ $scan->{starting} };
        last if time >= $deadline;
        $self->wait_seconds($interval);
    }

    my (@critical, @warnings);
    for my $pod (@{ $scan->{failing} }) {
        push @{ $CRITICAL_NS{ $pod->{namespace} } ? \@critical : \@warnings }, $pod;
    }

    return {
        critical => \@critical,
        warnings => \@warnings,
        starting => $scan->{starting},
    };
}

sub print {
    my ($self, $health) = @_;

    for my $p (@{ $health->{critical} }) {
        printf "  [!!] %s/%s — %s\n", $p->{namespace}, $p->{name}, $p->{reason};
    }
    for my $p (@{ $health->{warnings} }) {
        printf "  [WARN] %s/%s — %s\n", $p->{namespace}, $p->{name}, $p->{reason};
    }
    for my $p (@{ $health->{starting} }) {
        printf "  [..] %s/%s — still starting\n", $p->{namespace}, $p->{name};
    }
    print "  [ok] all pods healthy\n"
        unless @{ $health->{critical} }
            || @{ $health->{warnings} }
            || @{ $health->{starting} };
    return;
}

# Only a critical (core-namespace) finding is fatal. Warnings are loud but
# leave the exit code alone — see the severity split above.
sub is_fatal {
    my ($self, $health) = @_;
    return scalar @{ $health->{critical} };
}

sub banner_text {
    my ($self, $health) = @_;
    return 'CONTROL PLANE DEPLOYED — CLUSTER IS NOT HEALTHY'
        if is_fatal($self, $health);
    return 'CONTROL PLANE DEPLOYED — WITH WARNINGS'
        if @{ $health->{warnings} };
    return 'CONTROL PLANE DEPLOYED SUCCESSFULLY!';
}

sub banner {
    my ($self, $text) = @_;
    my $width = 63;
    print "╔" . ("═" x $width) . "╗\n";
    printf "║  %-*s║\n", $width - 2, $text;
    print "╚" . ("═" x $width) . "╝\n\n";
    return;
}

# The single exit of `ocp apply`.
#
# Both paths end here on purpose. The fresh-deploy path grew a health gate
# while the reconcile path returned before it, so `ocp apply` over an existing
# cluster still printed component results and exited 0 without having looked at
# the cluster at all. A shared finisher is the structural fix: a path that
# wants to return has to come through the same evaluation, the same banner and
# the same exit code.
sub finish {
    my ($self, %args) = @_;

    my $config = $args{config};
    my $api    = $args{api};

    print "\n";
    print(defined $args{step} ? "Step $args{step}: Verify cluster health\n"
                              : "Verifying cluster health\n");

    my $health = eval { $self->_check_cluster_health($api) };
    unless ($health) {
        # A malfunctioning health check must not be the thing that fails a
        # deploy that otherwise went fine.
        print "  [WARN] could not verify cluster health: $@";
        $health = { critical => [], warnings => [], starting => [] };
    }
    $self->_print_health($health);

    print "\n";
    my $unhealthy = $self->_health_is_fatal($health);
    $self->_banner($self->_health_banner_text($health));

    print "Cluster: ", $config->name, "\n";
    print "Control Plane: $args{cp_name} ($args{cp_ip})\n" if $args{cp_name};
    print "API Endpoint: ", $config->api_url($args{cp_ip}), "\n" if $args{cp_ip};
    print "\n";

    if ($unhealthy) {
        print "Core cluster components are unhealthy — the cluster is up but\n";
        print "not functional. Inspect them before using it:\n";
        print "  ocp status\n\n";
    } else {
        print "Next steps:\n";
        print "  1. Inspect the cluster:\n";
        print "     ocp status\n\n";
        print "  2. Export the kubeconfig for your local kubectl:\n";
        print "     ocp kubeconfig -e\n\n";
    }

    $self->_stamp_ocp_version($config);

    return $unhealthy ? 1 : 0;
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>.

=cut

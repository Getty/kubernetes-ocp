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

# A DaemonSet pod that needs its sibling first (dcgm-exporter waits for the
# hostengine, k202) crashes a few times while it comes up and then settles. A
# pod younger than this with fewer restarts than the cap is still starting up,
# not in a durable CrashLoop.
my $CRASHLOOP_GRACE_SECONDS = 300;
my $CRASHLOOP_GRACE_RESTARTS = 5;

# A pod that is still not up after this long is not starting, it is stuck
# (k228 point 4): the GPU pods on crag sat in Init with
# FailedCreatePodSandBox for over 15 minutes without a single restart, and
# apply called them "still starting" and reported SUCCESS. Long enough for a
# cold pull of the largest image OCP rolls out (the driver image, several GB,
# through the pull-through cache) -- a pod that needs longer than that is
# worth a line either way.
our $STUCK_SECONDS = 900;

sub _pod_age_seconds {
    my ($pod) = @_;
    my $ts = $pod->{metadata}{creationTimestamp} // return undef;
    require Time::Local;
    my @t = $ts =~ /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)/ or return undef;
    my $epoch = eval { Time::Local::timegm($t[5], $t[4], $t[3], $t[2], $t[1] - 1, $t[0]) };
    return defined $epoch ? time - $epoch : undef;
}

our $ROBOCOP_ARCH_REASON = 'robocop-Image nur amd64, keine amd64-Control-Plane';

# healthy | starting | failing (+reason)
sub classify_pod {
    my ($self, $pod, $no_amd64_cp) = @_;

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
        # A young pod is starting up however often it restarted: two GPU
        # nodes coming up at once took the dcgm-exporters to 5-7 restarts in
        # about four minutes, then they settled (lab note 26, the #202 gap).
        # Once it is past the grace period the restart count decides, here
        # and in the between-crashes rule below; one that never comes up is
        # stuck after $STUCK_SECONDS.
        if ($reason eq 'CrashLoopBackOff') {
            my $age = _pod_age_seconds($pod);
            next if defined $age && $age < $CRASHLOOP_GRACE_SECONDS;
        }
        $reasons{$reason} = 1;
    }

    # A looping container is waiting in CrashLoopBackOff only between crashes;
    # in the windows around each one it is running or terminated, and the
    # waiting scan above sees nothing. Past both grace limits, an unready
    # container is a crash loop whatever window the scan hits — the restart
    # count is the evidence. k202, lab 2026-10-16: crash-old (6 restarts,
    # 5m47s) was reported "still starting" because the last scan caught it
    # between crashes, one apply after another had flagged it failing.
    my $age = _pod_age_seconds($pod);
    unless (defined $age && $age < $CRASHLOOP_GRACE_SECONDS) {
        for my $cs (@{ $pod->{status}{containerStatuses} // [] }) {
            next if $cs->{ready};
            next if ($cs->{restartCount} // 0) < $CRASHLOOP_GRACE_RESTARTS;
            $reasons{CrashLoopBackOff} = 1;
        }
    }
    return ('failing', join(', ', sort keys %reasons)) if %reasons;
    return ('failing', 'Failed') if $phase eq 'Failed';

    # Readiness is judged on the regular containers only: a completed init
    # container's `ready` flag is not a reliable signal across versions.
    my @regular = @{ $pod->{status}{containerStatuses} // [] };
    my $up = $phase eq 'Running' && @regular && !grep { !$_->{ready} } @regular;
    return ('healthy') if $up;
    return ('starting') unless defined $age && $age >= $STUCK_SECONDS;
    # k197: an unschedulable robocop pod on a cluster without an amd64
    # control plane is the image, not a mystery.
    return ('failing', $ROBOCOP_ARCH_REASON)
        if $no_amd64_cp && _is_robocop_pod($pod) && _unschedulable($pod);
    return ('failing', _stuck_reason($pod, $phase, $age));
}

sub _is_robocop_pod {
    my ($pod) = @_;
    return ($pod->{metadata}{namespace} // '') eq 'ocp-system'
        && ($pod->{metadata}{labels}{app} // '') eq 'robocop';
}

sub _unschedulable {
    my ($pod) = @_;
    return scalar grep {
        ($_->{type} // '') eq 'PodScheduled' && ($_->{status} // '') ne 'True'
    } @{ $pod->{status}{conditions} // [] };
}

# Nodes as plain structs; empty when the list fails (k197).
sub _nodes {
    my ($api) = @_;
    my @nodes = eval {
        my $list = $api->list('Node');
        map { ref($_) eq 'HASH' ? $_ : $api->k8s->object_to_struct($_) }
            @{ ($list && $list->items) || [] };
    };
    return @nodes;
}

# True when control-plane Nodes are known and none of them is amd64.
sub _no_amd64_cp {
    my ($api) = @_;
    my @cp = grep {
        my $l = $_->{metadata}{labels} // {};
        exists $l->{'node-role.kubernetes.io/control-plane'}
            || exists $l->{'node-role.kubernetes.io/master'}
    } _nodes($api);
    return 0 unless @cp;
    return (grep { ($_->{metadata}{labels}{'kubernetes.io/arch'} // '') eq 'amd64' } @cp) ? 0 : 1;
}

=method robocop_arch_warning

C<< robocop_arch_warning($apply, $api) >> returns a C<[WARN]> line when robocop
is enabled and the cluster's control-plane Nodes include no amd64 one, else
undef (k197). Reads the Nodes tolerantly: a failed or empty list warns nothing.

=cut

sub robocop_arch_warning {
    my ($self, $api) = @_;
    return unless $self->config->robocop_enabled;
    return unless _no_amd64_cp($api);
    return '[WARN] robocop image is amd64 only, but no control-plane Node is amd64: '
        . 'the robocop pod stays Pending and worker joins through robocop do not run. '
        . 'Set `robocop: false` or add an amd64 control plane.';
}

# "stuck in Init for 17m (ContainerCreating)": the phase, how long, and the
# most telling reason at hand -- a waiting reason of any container, else why
# the pod is not scheduled, else nothing.
sub _stuck_reason {
    my ($pod, $phase, $age) = @_;

    my ($why) = grep { length }
        map { $_->{state}{waiting}{reason} // '' }
        @{ $pod->{status}{initContainerStatuses} // [] },
        @{ $pod->{status}{containerStatuses}     // [] };
    unless ($why) {
        ($why) = map { $_->{reason} // () }
            grep { ($_->{type} // '') eq 'PodScheduled' && ($_->{status} // '') ne 'True' }
            @{ $pod->{status}{conditions} // [] };
    }
    my $init_pending = grep { !$_->{ready} } @{ $pod->{status}{initContainerStatuses} // [] };
    my $where = $init_pending        ? 'in Init'
              : $phase eq 'Running'  ? 'not ready'
              :                        'in ' . ($phase || 'Pending');
    my $text = sprintf 'stuck %s for %dm', $where, int($age / 60);
    return $why ? "$text ($why)" : $text;
}

sub scan_pods {
    my ($self, $api) = @_;

    my $list = $api->list('Pod');
    my @pods = map { ref($_) eq 'HASH' ? $_ : $api->k8s->object_to_struct($_) }
               @{ ($list && $list->items) || [] };

    # The Nodes are only read when an unschedulable robocop pod makes the
    # architecture relevant; a healthy cluster costs no extra list call.
    my $no_amd64_cp = (grep { _is_robocop_pod($_) && _unschedulable($_) } @pods)
        ? _no_amd64_cp($api) : 0;
    my %out = (failing => [], starting => []);
    for my $pod (@pods) {
        my ($state, $reason) = classify_pod($self, $pod, $no_amd64_cp);
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
        printf STDERR "  [!!] %s/%s — %s\n", $p->{namespace}, $p->{name}, $p->{reason};
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
    # A component that failed is an apply that did not finish, however healthy
    # the pods look: the exit code already says so, the banner must too (k203,
    # lab 2026-10-15: SUCCESSFULLY between "[!!] GPU Operator setup failed"
    # and "Apply did not complete").
    return 'CONTROL PLANE DEPLOYED — APPLY INCOMPLETE'
        if @{ $self->{_failed_components} // [] };
    return 'CONTROL PLANE DEPLOYED — WITH WARNINGS'
        if @{ $health->{warnings} } || @{ $self->{_apply_warnings} // [] };
    return 'CONTROL PLANE DEPLOYED SUCCESSFULLY!';
}

sub banner {
    my ($self, $text) = @_;
    my $width = 63;
    print "╔" . ("═" x $width) . "╗\n";
    # Padded by characters, not bytes: the text is UTF-8 bytes like the rest
    # of OCP, and "—" is three of them.
    require Encode;
    my $pad = $width - 2 - length(Encode::decode_utf8($text));
    print "║  " . $text . (' ' x ($pad > 0 ? $pad : 0)) . "║\n";
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

    my $arch = eval { robocop_arch_warning($self, $api) };
    if ($arch) {
        print "  $arch\n";
        push @{ $self->{_apply_warnings} }, 'robocop arch';
    }

    print "\n";
    my $unhealthy = $self->_health_is_fatal($health);
    $self->_banner($self->_health_banner_text($health));

    print "Cluster: ", $config->name, "\n";
    print "Control Plane: $args{cp_name} ($args{cp_ip})\n" if $args{cp_name};
    print "API Endpoint: ", $config->api_url($args{cp_ip}), "\n" if $args{cp_ip};
    print "\n";

    my @failed = @{ $self->{_failed_components} // [] };

    if ($unhealthy) {
        print "Core cluster components are unhealthy — the cluster is up but\n";
        print "not functional. Inspect them before using it:\n";
        print "  ocp status\n\n";
    } elsif (@failed) {
        print "Not every component reached its spec; see the [!!] lines above.\n";
        print "  ocp status\n\n";
    } else {
        print "Next steps:\n";
        print "  1. Inspect the cluster:\n";
        print "     ocp status\n\n";
        print "  2. Export the kubeconfig for your local kubectl:\n";
        print "     ocp kubeconfig -e\n\n";
    }

    if (@failed) {
        print STDERR "Apply did not complete: " . join(', ', @failed) . " failed.\n";
        print STDERR "The cluster is not at spec; fix the cause and run ocp apply again.\n";
    }

    $self->_stamp_ocp_version($config);

    return ($unhealthy || @failed) ? 1 : 0;
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>.

=cut

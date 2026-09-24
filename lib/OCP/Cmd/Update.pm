package OCP::Cmd::Update;
# ABSTRACT: Update cluster components to current OCP version

use Moo;
use MooX::Cmd;
use MooX::Options;
use OCP::Choices;
use OCP::Config;
use OCP::Drift;
use OCP::Versions;
use OCP::Rex;
use OCP;
use Term::ANSIColor qw(colored);

with 'OCP::Role::Cmd';

option dry_run => (
    is      => 'ro',
    short   => 'n',
    doc     => 'Show what would be updated without making changes',
);

option component => (
    is      => 'ro',
    format  => 's',
    short   => 'c',
    doc     => 'Update only specific component (e.g. cilium, cert_manager)',
);

option force => (
    is      => 'ro',
    short   => 'f',
    doc     => 'Force update even if versions match',
);

sub execute {
    my ($self, $args_ref, $chain_ref) = @_;

    my $file = $self->ocp->config;
    unless (-f $file) {
        die "Config file '$file' not found. Run 'ocp init' first.\n";
    }

    my $config = OCP::Config->new(file => $file);

    # Check if cluster is deployed
    unless ($config->status->{ocpVersion}) {
        die "Cluster not yet deployed. Run 'ocp apply' first.\n"
            unless $config->cluster_exists;

        die "This cluster was deployed by an OCP that did not record its "
          . "version.\nRun 'ocp apply' once to stamp it, then 'ocp update'.\n";
    }

    my $current_version = $config->status->{ocpVersion};
    my $target_version = $OCP::VERSION;

    print "Current OCP Version: $current_version\n";
    print "Target OCP Version:  $target_version\n\n";

    # Check if update needed
    if ($current_version eq $target_version && !$self->force) {
        print "✓ Already up to date.\n";
        return 0;
    }

    # Get version manifests
    my $current_manifest = OCP::Versions->get_versions($current_version);
    my $target_manifest = OCP::Versions->get_versions($target_version);

    unless ($target_manifest) {
        # $target_version is $OCP::VERSION — this OCP's own version, never
        # something the operator typed. So the hint is always true here: the
        # only way to reach this line is an OCP.pm bumped without a matching
        # entry in OCP::Versions, and saying so is more use than saying the
        # version is unknown (k103).
        die OCP::Choices::unknown('OCP version', $target_version,
            [ OCP::Versions->known_versions ],
            hint => "This OCP reports version $target_version, and"
                  . " OCP::Versions carries no component manifest for it.\n",
        );
    }

    my $current_comps = $current_manifest->{components} // {};
    my $target_comps = $target_manifest->{components};

    # Determine what needs updating
    my @updates;
    my $selected = $self->component;

    # k113: --component TYPO used to skip every iteration of the loop
    # below, fall through with @updates empty, and reach the
    # "All components up to date" branch as if nothing had happened. Refuse
    # here instead — same shape `ocp quatschkommando` answers in (k67,
    # k103). Without this guard, a typo is indistinguishable from a real
    # no-op: same line, same exit 0.
    die OCP::Choices::unknown('component', $selected, [ sort keys %$target_comps ])
        if $selected && !exists $target_comps->{$selected};

    for my $comp (sort keys %$target_comps) {
        # Skip if specific component requested and this isn't it
        next if $selected && $comp ne $selected;

        my $current = $current_comps->{$comp} // 'not installed';
        my $target = $target_comps->{$comp};

        if ($current ne $target || $self->force) {
            push @updates, {
                component => $comp,
                from      => $current,
                to        => $target,
            };
        }
    }

    unless (@updates) {
        print "✓ All components up to date.\n";
        return 0;
    }

    # Decide every component's outcome before anything runs (k165), so the
    # plan printed below, a --dry-run and a refusal all tell the same story.
    my %planned = map { $_->{component} => 1 } @updates;
    $_->{plan} = $self->_plan_component($config, $_, \%planned) for @updates;

    # Show update plan
    print "Updates planned:\n";
    for my $update (@updates) {
        printf("  %-20s %s -> %s  (%s)\n",
            $update->{component},
            $update->{from},
            colored($update->{to}, 'green'),
            $self->_plan_label($update->{plan}),
        );
    }
    print "\n";

    # Check for breaking changes
    if (OCP::Versions->has_breaking_changes($current_version, $target_version)) {
        print colored("⚠️  BREAKING CHANGES:\n", 'yellow bold');
        my $changes = OCP::Versions->get_breaking_changes($current_version, $target_version);
        for my $change (@$changes) {
            print colored("  - $change\n", 'yellow');
        }
        print "\n";
    }

    # Check for manual steps
    my $manual_steps = OCP::Versions->get_manual_steps($current_version, $target_version);
    if (@$manual_steps) {
        print colored("⚠️  MANUAL STEPS REQUIRED:\n", 'yellow bold');
        for my $step (@$manual_steps) {
            print colored("  - $step\n", 'yellow');
        }
        print "\n";
    }

    # A refusal stops the run before anything changes: half an update plus an
    # unstamped status is harder to reason about than none. Every refusal
    # says what to do instead, and --component still reaches the rest.
    my @refused = grep { $_->{plan}{action} eq 'refuse' } @updates;
    if (@refused) {
        print STDERR colored("✗ $_->{component}: ", 'red').$_->{plan}{note} for @refused;
        print STDERR "Nothing was changed. 'ocp update --component NAME' updates"
                   . " the other components on their own.\n";
        return 1;
    }

    # Dry-run exit
    if ($self->dry_run) {
        print colored("Dry-run mode. No changes made.\n", 'cyan');
        print "Run without --dry-run to apply updates.\n";
        return 0;
    }

    # Confirm before proceeding
    if (@$manual_steps) {
        print "Manual steps required. Continue? [y/N]: ";
        my $answer = <STDIN>;
        chomp $answer;
        unless ($answer =~ /^y/i) {
            print "Update cancelled.\n";
            return 1;
        }
    }

    # Perform updates
    print "\nStarting updates...\n\n";

    for my $update (@updates) {
        eval {
            $self->_update_component($config, $update);
        };
        if ($@) {
            print STDERR colored("✗ Failed to update $update->{component}: $@", 'red');
            return 1;
        }
    }

    # Update OCP version in status
    $config->set_status('ocpVersion', $target_version);
    $config->save_status;

    print "\n";
    print colored("✓ All updates completed successfully.\n", 'green bold');
    print "Cluster is now at OCP version $target_version.\n";

    my @by_apply = map { $_->{component} }
                   grep { $_->{plan}{action} eq 'apply' } @updates;
    print "Run 'ocp apply' to roll out: ".join(', ', @by_apply).".\n"
        if @by_apply;

    return 0;
}

# Components whose version lives in a manifest `ocp apply` generates and
# re-applies: a pin bump changes the manifest hash and apply rolls it out
# (OCP::Drift marks NFD and the GPU operator self_healing for the same
# reason). No Rex task upgrades them, so ocp update leaves them to apply.
our %APPLIED_BY_APPLY = map { $_ => 1 } qw(
    nfd gpu_operator nvidia_toolkit nvidia_driver
    nvidia_device_plugin dcgm_exporter nvidia_dcgm
);

our %DIST_UPGRADE_DOCS = (
    rke2 => 'https://docs.rke2.io/upgrade/basic_upgrade',
    k3s  => 'https://docs.k3s.io/upgrades',
);

# What ocp update does with one component of the plan (k165). Before, a
# component without an _update_<comp> method fell back to a Rex task
# update_<comp> the Rexfile mostly did not have, and the distribution
# updaters ran whatever the cluster's distribution was. Now every component
# gets one of
#
#   { action => 'rex',    task => ... }  run that Rex task on the control plane
#   { action => 'skip',   note => ... }  nothing to do here, and why
#   { action => 'apply',  note => ... }  `ocp apply` rolls the new pin out
#   { action => 'refuse', note => ... }  ocp update will not do this, and what
#                                        to do instead (ends in a newline)
#
# $planned holds the components in this run: what moves with Cilium needs to
# know whether Cilium moves.
sub _plan_component {
    my ( $self, $config, $update, $planned ) = @_;
    my $comp = $update->{component};
    my $dist = $config->distribution;

    if ($DIST_UPGRADE_DOCS{$comp}) {
        return { action => 'skip', note => 'not relevant for '.$dist }
            unless $comp eq $dist;
        # OCP::Drift::distribution_drift measures against the same value: an
        # explicit version in ocp.yaml wins over the manifest pin.
        return { action => 'skip',
                 note   => 'ocp.yaml pins kubernetes.version ('.$config->version.')' }
            if length $config->version;
        return { action => 'skip', note => 'pin unchanged; ocp update does not reinstall '.$comp }
            if $update->{from} eq $update->{to};
        return { action => 'refuse', note =>
            'the pin moved '.$update->{from}.' -> '.$update->{to}.', and ocp update'
          . " does not upgrade the Kubernetes distribution in place:\n"
          . "  that is a node-by-node upgrade. Upgrade the nodes by hand ("
          . $DIST_UPGRADE_DOCS{$comp}.")\n"
          . "  and record the version they run as kubernetes.version in ocp.yaml,"
          . " then run 'ocp update' again.\n" };
    }

    return { action => 'rex', task => 'upgrade_cilium' } if $comp eq 'cilium';

    # upgrade_cilium installs the CLI (remedy_pins), and there is no task
    # that installs it alone.
    if ($comp eq 'cilium_cli') {
        return { action => 'skip', note => 'installed with cilium' } if $planned->{cilium};
        return { action => 'skip', note =>
            "moves with cilium; 'ocp update --component cilium --force' refreshes it" };
    }

    # upgrade_cilium applies the CRD bundle as well (k160); running
    # update_gateway_api after it would only bounce the operator again.
    if ($comp eq 'gateway_api') {
        return { action => 'skip', note => 'applied with cilium' } if $planned->{cilium};
        return { action => 'rex', task => 'update_gateway_api' };
    }

    if ($comp eq 'cert_manager') {
        return { action => 'skip', note => 'cert-manager is disabled (nocert)' }
            if $config->no_cert;
        return { action => 'rex', task => 'upgrade_cert_manager' };
    }

    if ($APPLIED_BY_APPLY{$comp}) {
        return { action => 'skip', note => 'GPU stack is off (gpu.enabled: false)' }
            if $comp ne 'nfd' && !$config->gpu_enabled;
        return { action => 'apply', note => "rolled out by 'ocp apply' (it re-applies the manifest)" };
    }

    # A component added to OCP::Versions without a line here: refuse rather
    # than guess a task name.
    return { action => 'refuse', note =>
        "ocp update has no updater for this component.\n"
      . "  Run 'ocp apply', which reconciles what it can, and check 'ocp status'.\n" };
}

sub _plan_label {
    my ( $self, $plan ) = @_;
    return $plan->{action} eq 'rex'    ? 'via '.$plan->{task}
         : $plan->{action} eq 'apply'  ? 'via ocp apply'
         : $plan->{action} eq 'refuse' ? 'refused, see below'
         :                               'skip: '.$plan->{note};
}

sub _update_component {
    my ($self, $config, $update) = @_;

    my $comp = $update->{component};
    my $version = $update->{to};
    my $plan = $update->{plan}
        // $self->_plan_component($config, $update, { $comp => 1 });

    unless ($plan->{action} eq 'rex') {
        # execute stops on refusals before this runs; a direct caller gets
        # one as the error it is.
        die $plan->{note} if $plan->{action} eq 'refuse';
        print "- $comp: $plan->{note}\n";
        return;
    }

    print "Updating $comp to $version...\n";
    $self->_update_via_rex($config, $comp, $version, $plan->{task});

    # Track in status
    $config->status->{components} //= {};
    $config->status->{components}{$comp} = $version;
    $config->save_status;

    print colored("✓ $comp updated to $version\n", 'green');
}

# Both Rex paths below reach the control plane over SSH, and both used to
# hand Rex $config->ssh_private_key_path unconditionally. In secure mode that
# file is the wrong answer twice over: the machines trust the ADMIN key, and
# `ocp init` does not even create a bootstrap key there — so `ocp update` on a
# secure cluster could not work at all. OCP::ClusterKey answers the question
# properly; cluster_ssh_key caches it so a multi-component update prompts for
# PIN2 once. k87.
sub _update_via_rex {
    my ($self, $config, $component, $version, $task) = @_;

    my $cp_status = $config->cluster_status;
    my $host = $cp_status->{public_ip} or die "No control plane IP found\n";

    my $rex = OCP::Rex->new(
        host     => $host,
        key_file => $self->cluster_ssh_key($config, reason => 'ocp update')->path,
    );

    # Same params the drift remedy passes for this task (k163): before, only
    # the version travelled, so cert-manager on k3s ran RKE2's kubectl.
    $rex->run_task($task,
        %{ OCP::Drift->remedy_params($config, $component, $version) },
    );
}

1;

__END__

=head1 NAME

OCP::Cmd::Update - Update cluster components to current OCP version

=head1 SYNOPSIS

    # Show what would be updated
    ocp update --dry-run

    # Update all components
    ocp update

    # Update only Cilium
    ocp update --component cilium

    # Force update even if versions match
    ocp update --force

=head1 DESCRIPTION

Updates cluster components to the versions bundled with the current OCP CLI
version.

The update process:

1. Compares installed versions with target versions
2. Plans an outcome per component (see L</COMPONENT-SPECIFIC UPDATES>)
3. Shows breaking changes and manual steps if any
4. Stops on STDERR, before any change, if a component is refused
5. Performs updates via Rex tasks
6. Tracks updated versions in status.yaml

=head1 SSH ACCESS

Updates run over SSH on the control plane, so C<ocp update> needs the key
that machine trusts (see L<OCP::ClusterKey>).

In a secure-mode project that is the PIN2-protected admin key, whatever the
provider, and the first component to be updated prompts for PIN2 once.  A
C<--dry-run>, an already-up-to-date cluster and a C<--nopassword> project
never prompt: the first two reach no Rex task, and the last uses the
unencrypted bootstrap key in F<.ocp/id_ed25519>.

=head1 OPTIONS

=head2 --dry-run, -n

Show what would be updated without making changes.

=head2 --component COMPONENT, -c COMPONENT

Update only a specific component (e.g. cilium, cert_manager).

=head2 --force, -f

Force update even if versions already match.

=head1 EXAMPLES

    # Check what needs updating
    ocp version
    ocp update --dry-run

    # Update all components
    ocp update

    # Update only Cilium
    ocp update -c cilium

=head1 COMPONENT-SPECIFIC UPDATES

Every component in the version manifest has one outcome, shown in the plan:

=over 4

=item * B<cilium> - Rex task C<upgrade_cilium>, which also installs the
pinned Cilium CLI and applies the pinned Gateway API CRDs.

=item * B<cilium_cli> - moves with cilium. On its own it is skipped;
C<ocp update --component cilium --force> refreshes it.

=item * B<gateway_api> - applied with cilium when cilium is updated too,
otherwise Rex task C<update_gateway_api>.

=item * B<cert_manager> - Rex task C<upgrade_cert_manager>; skipped with
C<nocert>.

=item * B<nfd> and the GPU stack (C<gpu_operator>, C<nvidia_*>, C<dcgm_*>) -
their versions live in manifests C<ocp apply> re-applies, so C<ocp update>
leaves them to it and names them at the end. The GPU stack is skipped when
C<gpu.enabled> is false.

=item * B<rke2>/B<k3s> - the other distribution is skipped. A moved pin of
the cluster's own distribution is refused before anything changes: that is a
node-by-node upgrade done by hand. Recording the running version as
C<kubernetes.version> in F<ocp.yaml> makes the manifest pin irrelevant, and
the next C<ocp update> skips it.

=back

A component C<ocp update> does not know is refused, never guessed at.

=cut

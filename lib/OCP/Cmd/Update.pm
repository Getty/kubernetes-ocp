package OCP::Cmd::Update;
# ABSTRACT: Update cluster components to current OCP version

use Moo;
use MooX::Cmd;
use MooX::Options;
use OCP::Config;
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
        die "Unknown target version: $target_version\n";
    }

    my $current_comps = $current_manifest->{components} // {};
    my $target_comps = $target_manifest->{components};

    # Determine what needs updating
    my @updates;
    my $selected = $self->component;

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

    # Show update plan
    print "Updates planned:\n";
    for my $update (@updates) {
        printf("  %-20s %s -> %s\n",
            $update->{component},
            $update->{from},
            colored($update->{to}, 'green')
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
            print colored("✗ Failed to update $update->{component}: $@\n", 'red');
            return 1;
        }
    }

    # Update OCP version in status
    $config->set_status('ocpVersion', $target_version);
    $config->save_status;

    print "\n";
    print colored("✓ All updates completed successfully.\n", 'green bold');
    print "Cluster is now at OCP version $target_version.\n";

    return 0;
}

sub _update_component {
    my ($self, $config, $update) = @_;

    my $comp = $update->{component};
    my $version = $update->{to};

    print "Updating $comp to $version...\n";

    # Map component to update method
    my $method = "_update_$comp";
    $method =~ s/-/_/g;  # cert-manager -> _update_cert_manager

    if ($self->can($method)) {
        $self->$method($config, $version);
    } else {
        # Generic update via Rex if task exists
        my $task = "update_$comp";
        $self->_update_via_rex($config, $comp, $version, $task);
    }

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
# PIN2 once. karr #87.
sub _update_via_rex {
    my ($self, $config, $component, $version, $task) = @_;

    my $cp_status = $config->cluster_status;
    my $host = $cp_status->{public_ip} or die "No control plane IP found\n";

    my $rex = OCP::Rex->new(
        host     => $host,
        key_file => $self->cluster_ssh_key($config, reason => 'ocp update')->path,
    );

    $rex->run_task($task,
        version => $version,
    );
}

# Component-specific update methods
# These can be overridden for special handling

sub _update_cilium {
    my ($self, $config, $version) = @_;

    # Cilium updates need special handling (CLI + cluster upgrade)
    my $cp_status = $config->cluster_status;
    my $host = $cp_status->{public_ip} or die "No control plane IP found\n";

    my $rex = OCP::Rex->new(
        host     => $host,
        key_file => $self->cluster_ssh_key($config, reason => 'ocp update')->path,
    );

    # Use Rex task for cilium upgrade
    $rex->run_task('upgrade_cilium',
        version => $version,
    );
}

sub _update_cert_manager {
    my ($self, $config, $version) = @_;
    $self->_update_via_rex($config, 'cert_manager', $version, 'upgrade_cert_manager');
}

# RKE2/K3s updates are more complex - just show warning for now
sub _update_rke2 {
    my ($self, $config, $version) = @_;
    print colored("⚠️  RKE2 updates require manual intervention.\n", 'yellow');
    print "See: https://docs.rke2.io/upgrade/basic_upgrade\n";
    die "RKE2 update not implemented yet\n";
}

sub _update_k3s {
    my ($self, $config, $version) = @_;
    print colored("⚠️  K3s updates require manual intervention.\n", 'yellow');
    print "See: https://docs.k3s.io/upgrades\n";
    die "K3s update not implemented yet\n";
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

Updates cluster components (Cilium, cert-manager) to the versions
bundled with the current OCP CLI version.

The update process:

1. Compares installed versions with target versions
2. Shows breaking changes and manual steps if any
3. Performs updates via Rex tasks
4. Tracks updated versions in status.yaml

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

Some components require special handling:

=over 4

=item * B<Cilium> - Updates both CLI and cluster installation

=item * B<cert-manager> - Updates manifests

=item * B<RKE2/K3s> - Requires manual intervention (not automated)

=back

=cut

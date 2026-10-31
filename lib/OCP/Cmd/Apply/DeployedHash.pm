package OCP::Cmd::Apply::DeployedHash;
# ABSTRACT: Track which manifests OCP last rolled out to the cluster

use strict;
use warnings;

use Path::Tiny qw(path);

=head1 SYNOPSIS

    my $deployed = $apply->ocp->load_file($path->stringify);
    OCP::Cmd::Apply::DeployedHash::save($apply, $config, 'registry', $hash);

=head1 DESCRIPTION

The hashes say what OCP last rolled out, not what the cluster has. They are
an optimisation over re-applying everything (ADR 0008) and never evidence on
their own: every component that consults them also asks the cluster whether
the thing is actually there before it claims to be up to date. A record
without that question survived C<ocp destroy> and told a freshly built
cluster its registry was already deployed.

L<OCP::Cmd::Apply> re-exports these as C<_load_deployed_hashes>,
C<_save_deployed_hash> and C<_report_component> — the test surface, and the
call site that the rest of C<Apply.pm> still uses, stays the same.

=cut

sub hashes_path {
    my ($self, $config) = @_;
    return path($config->deployed_file);
}

sub load {
    my ($self, $config) = @_;
    my $path = hashes_path($self, $config);
    return {} unless -f $path;

    return $self->ocp->load_file($path->stringify) || {};
}

sub save {
    my ($self, $config, $component, $hash) = @_;
    my $hashes = load($self, $config);
    $hashes->{$component} = $hash;
    my $path = hashes_path($self, $config);
    $path->parent->mkpath unless -d $path->parent;

    $self->ocp->dump_file($path->stringify, $hashes);
}

# Drops the record of a component OCP removed from the cluster, so the next
# run does not read it as deployed. Nothing to drop is nothing to write.
sub forget {
    my ($self, $config, $component) = @_;
    my $hashes = load($self, $config);
    return unless exists $hashes->{$component};
    delete $hashes->{$component};
    $self->ocp->dump_file(hashes_path($self, $config)->stringify, $hashes);
}

# One vocabulary for what a hash-gated setup step did. The step itself is the
# only place that knows — it holds both the record and the answer from the
# cluster — so reconcile reports its verdict instead of forming a second one
# from the file. Returns whether anything changed, which is what the reconcile
# summary counts.
#
# 'skipped' is the odd one out: the component is not part of this cluster's
# spec (no NVIDIA card, gpu.enabled: false), so there is nothing to be up to
# date about. The step has already printed why on the line above; this one only
# states the verdict, and it counts as no change — a cluster with no GPU must
# not read as "1 component updated" on every run.
#
# 'removed' is a change: the component left the spec (the AMD GPU stack, k251)
# and this run took it out of the cluster.
#
# $changed says what an 'updated' changed: the manifest, for the hash-gated
# components. The Cilium Gateway's step reads metadata.generation, which
# moves with the spec and nothing else, so it says 'spec changed', as the
# step's own line does (k318).
sub report_component {
    my ($self, $label, $outcome, $changed) = @_;
    $outcome //= 'unchanged';
    $changed //= 'manifest changed';

    my %line = (
        unchanged => "$label up to date",
        deployed  => "$label deployed (was missing)",
        restored  => "$label redeployed (was gone from the cluster)",
        updated   => "$label updated ($changed)",
        skipped   => "$label skipped",
        removed   => "$label removed (no longer selected)",
    );

    print "  [ok] " . ($line{$outcome} // "$label $outcome") . "\n";

    return $outcome eq 'unchanged' || $outcome eq 'skipped' ? 0 : 1;
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Config/deployed_file>.

=cut

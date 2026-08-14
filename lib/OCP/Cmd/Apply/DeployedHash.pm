package OCP::Cmd::Apply::DeployedHash;
# ABSTRACT: Track which manifests OCP last rolled out to the cluster

use strict;
use warnings;

use Path::Tiny qw(path);

our $VERSION = '0.001';

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

# One vocabulary for what a hash-gated setup step did. The step itself is the
# only place that knows — it holds both the record and the answer from the
# cluster — so reconcile reports its verdict instead of forming a second one
# from the file. Returns whether anything changed, which is what the reconcile
# summary counts.
sub report_component {
    my ($self, $label, $outcome) = @_;
    $outcome //= 'unchanged';

    my %line = (
        unchanged => "$label up to date",
        deployed  => "$label deployed (was missing)",
        restored  => "$label redeployed (was gone from the cluster)",
        updated   => "$label updated (manifest changed)",
    );

    print "  [ok] " . ($line{$outcome} // "$label $outcome") . "\n";

    return $outcome eq 'unchanged' ? 0 : 1;
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Config/deployed_file>.

=cut

package OCP::Cmd::Apply::SopsRepair;
# ABSTRACT: Re-quote a bare sops lastmodified before ocp apply decrypts, or name the files under --dry-run

use strict;
use warnings;

=head1 SYNOPSIS

    # In OCP::Cmd::Apply::execute, after the banner, before either path
    # decrypts:
    OCP::Cmd::Apply::SopsRepair::repair_sops_files($self, $secrets);

=head1 DESCRIPTION

A SOPS file that File::SOPS 0.002 wrote carries its C<lastmodified> as a bare
timestamp, which C<sops -d> refuses. C<ocp apply> re-quotes those files before
the bootstrap or the reconcile reads any of them
(L<OCP::Secrets/repair_sops_lastmodified>, k259): one C<[ok]> line per file,
then a blank line.

That writes, so a dry run does not. It names each file a real run would
repair instead, on STDOUT and in the same place, as the rest of the dry run
names what a real run would change (k266):

    [..] A real run would repair keys.yaml: its sops lastmodified is a bare timestamp, which sops -d refuses

The files come from L<OCP::Secrets/bare_sops_lastmodified_files>, the
selection the repair itself makes, read off the text. A real run repairs only
with the key it already holds (F<.ocp/age.key>, or C<SOPS_AGE_KEY_FILE>) and
never asks PIN1 for it, so with neither at hand it repairs nothing this run
-- and a dry run names nothing.

=cut

sub repair_sops_files {
    my ($self, $secrets) = @_;

    unless ($self->dry_run) {
        print "\n" if $secrets->repair_sops_lastmodified;
        return;
    }
    return unless $secrets->sops_age_key_file || $secrets->has_age_key;

    my @bare = $secrets->bare_sops_lastmodified_files or return;
    print "[..] A real run would repair $_: its sops lastmodified is a bare timestamp,"
        . " which sops -d refuses\n" for @bare;
    print "\n";
    return;
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Secrets/repair_sops_lastmodified>.

=cut

package OCP::Cmd::Apply::Validate;
# ABSTRACT: Refuse an ocp.yaml with errors before ocp apply touches anything

use strict;
use warnings;

=head1 SYNOPSIS

    # First thing in OCP::Cmd::Apply::execute, --dry-run included:
    OCP::Cmd::Apply::Validate::refuse_invalid_config($config);

=head1 DESCRIPTION

C<ocp apply> refuses an F<ocp.yaml> that L<OCP::Config/validate> finds
errors in, before it asks for a PIN, writes a file, or reaches a host or the
cluster (k255). Every error is named at once, one line each, so a human fixes
them in one pass rather than one run per mistake:

    Error: ocp.yaml has 2 errors:
      - control_planes[1].node_ip: '10.230.30.52/24' is a network (CIDR), not an address: write the node's own address, without /24
      - gpu.driver: invalid value 'oprator' (must be host or operator)
    Nothing was done: ocp apply checks ocp.yaml before it touches a host or the cluster. Fix the lines above and run it again.

The refusal is a C<die>, so L<OCP/run_cli> prints it on STDERR and exits 1;
STDOUT stays empty. The croaking accessors of L<OCP::Config> stay as the
guard at the point of use, but they fire only where a value is read -- an
unknown C<gpu.amd.allocation> on the first AMD node, after a control plane
was built.

C<ocp status> does not gate on this: it is the read side and has to show a
cluster whose F<ocp.yaml> has a mistake.

=cut

sub refuse_invalid_config {
    my ($config) = @_;

    my @errors = $config->validate;
    return 1 unless @errors;

    my $file = $config->file;
    die "$file has " . scalar(@errors) . (@errors == 1 ? " error:\n" : " errors:\n")
      . join('', map { "  - $_\n" } @errors)
      . "Nothing was done: ocp apply checks $file before it touches a host or the cluster. "
      . "Fix the lines above and run it again.\n";
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Config/validate>.

=cut

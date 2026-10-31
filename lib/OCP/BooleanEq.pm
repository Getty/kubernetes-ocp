package OCP::BooleanEq;
# ABSTRACT: Compare a JSON::PP::Boolean the same on either side of eq and ne

use strict;
use warnings;

# Load order is the fix's precondition: JSON::PP for the class, then
# JSON::MaybeXS, which loads Cpanel::JSON::XS wherever it is installed. Cpanel
# overloads the class only on its first load, so it has to be loaded before
# the block below corrects it, or it would come later and put its own handler
# back.
use JSON::PP ();
use JSON::MaybeXS ();
use overload ();

# Every true and false ocp reads is a JSON::PP::Boolean: from YAML through
# OCP.pm's $YAML::XS::Boolean = 'JSON::PP', from a CR because Kubernetes::REST
# decodes with JSON::MaybeXS, from a task parameter because the Rexfile's
# task_params() does. Cpanel::JSON::XS -- JSON::MaybeXS's backend wherever it
# is installed, so in the image -- re-overloads eq and ne on that class when
# it loads, and its handler swaps the operands when the boolean stands on the
# RIGHT: the plain string is then taken for the boolean and only its truth
# compared. So `'hetzner' eq $true` was 1 for any string Perl calls true, and
# `grep { $_ eq $value } @choices` took a `true` for every choice (k305, k314).
# With the boolean on the left it was right all along. Cpanel's POD says what
# eq means -- true eq 'true' or 1, false eq 'false', '' or 0 -- and its own
# tests only ever put the boolean on the left. Seen in Cpanel::JSON::XS 4.40
# (the pin) and still in 4.80; the handler dates from 4.06.
#
# eq and ne are symmetric, so the fix is to hand Cpanel's own handlers the
# operands as overload passes them, the boolean first, and drop the swap flag.
# Nothing else changes: the class, truth, is_bool, and true/false in JSON and
# in YAML are as before, which is why this beats switching $YAML::XS::Boolean
# to builtin booleans -- those are no references, so the k305 `ref` guards
# would take `nodes: true` for 1 and `name: true` for '1', and a CR's booleans
# would still be JSON::PP::Boolean. On a fixed Cpanel this is a harmless
# wrapper; without Cpanel there is no handler and nothing to fix.
#
# Loading this module is the whole fix, once per process, and every process
# that compares what it read loads it before it reads: OCP.pm does, so bin/ocp
# and robocop's controller; share/Rexfile does, for the rex child that runs it
# (k316). That child loads no OCP.pm and cannot see lib/ on its own in the
# image, so OCP::Rex hands it the lib/ tree it came from in PERL5LIB.
# t/314-boolean-eq.t holds both orders, t/316-rexfile-boolean-eq.t the child.
{
    package    # not this module's package; hidden from the indexer, as Cpanel hides it
        JSON::PP::Boolean;
    my $eq = overload::Method(__PACKAGE__, 'eq');
    my $ne = overload::Method(__PACKAGE__, 'ne');
    if ($eq && $ne) {
        overload->unimport(qw( eq ne ));    # no "redefined" warning under -w
        overload->import(
            eq => sub { $eq->($_[0], $_[1], '') },
            ne => sub { $ne->($_[0], $_[1], '') },
        );
    }
}

1;

__END__

=synopsis

    use OCP::BooleanEq ();    # before anything is read

=description

Loading this module corrects how a C<JSON::PP::Boolean> compares under C<eq>
and C<ne> when L<Cpanel::JSON::XS> is installed: Cpanel's handler swaps the
operands when the boolean stands on the right, so C<'hetzner' eq $true> was
true. After loading, a boolean compares the same on either side, as Cpanel
documents it. The class, its truth, C<is_bool> and its JSON and YAML output
are unchanged.

L<OCP> loads it, and so does the Rexfile in the distribution's share
directory. It exports nothing.

=cut

package OCP::ErrorLine;
# ABSTRACT: An exception as one line for STDERR

use strict;
use warnings;

# k342: where a command names a failure in one line -- "[!!] w1: could not
# add the keys: <why>", "Could not read the Hetzner catalogue: <why>" -- the
# <why> is an exception: croak's and die's text with Perl's " at FILE line
# N." on it, LWP's reason with its own, a message over several lines. Two
# helpers each made one line of it, OCP::Role::Cmd::Machines' _oneline (k96)
# and OCP::Cmd::Init's _catalogue_error (k265), and said the same failure two
# ways. This is the one they both are now.
#
# Every source location goes, not only a last one: a die that wraps another
# carries both, and LWP puts its own inside the message it hands on (k265).
# _oneline took only one at the very end; it says it as Init does now.
# A secret the caller holds -- the token a request went out with -- is masked
# before anything else, should an answer ever echo it back. Nothing left is
# 'unknown error', unless the caller says what nothing is (empty).
sub one_line {
    my ($err, %opt) = @_;

    my $line = defined $err ? "$err" : '';
    my $mask = $opt{mask};
    $line =~ s/\Q$mask\E/********/g if defined $mask && length $mask;
    $line =~ s/ at \S+ line \d+\.?//g;
    $line =~ s/\s+/ /g;
    $line =~ s/\A | \z//g;

    return length $line ? $line : $opt{empty} // 'unknown error';
}

1;

__END__

=head1 NAME

OCP::ErrorLine - An exception as one line for STDERR

=head1 SYNOPSIS

    use OCP::ErrorLine;

    print STDERR "[!!] $label: could not add the keys: "
        . OCP::ErrorLine::one_line($@) . "\n";

    # The token the request went out with never reaches the terminal.
    my $why = OCP::ErrorLine::one_line($@, mask => $token);

=head1 DESCRIPTION

What a command prints after "could not ...": the exception, as one line.
Shared by L<OCP::Role::Cmd::Machines> (and through it L<OCP::Cmd::Keys::Secure>
and the operator commands) and L<OCP::Cmd::Init> (k342), so a failure reads
the same wherever it is named.

=head1 FUNCTIONS

=head2 one_line

    my $line = OCP::ErrorLine::one_line($err, %opt);

C<$err> as a string (an exception object stringified), with every Perl
source location (C< at FILE line N.>) taken out, each run of whitespace --
newlines too -- folded into one space, and none at either end. Options:

=over

=item mask

A secret to replace with C<********> wherever it appears, before anything
else is done -- the API token a request went out with.

=item empty

What to return when nothing is left (C<undef>, an empty or blank C<$err>, a
bare source location). C<'unknown error'> when not given.

=back

=cut

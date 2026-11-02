package OCP::ErrorLine;
# ABSTRACT: An exception as one line for STDERR

use strict;
use warnings;
use Scalar::Util ();

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
# before anything else, should an answer ever echo it back, and so is every
# secret the registry below holds (k398). Nothing left is 'unknown error',
# unless the caller says what nothing is (empty).
sub one_line {
    my ($err, %opt) = @_;

    my $line = _masked(defined $err ? "$err" : '', $opt{mask});
    $line =~ s/ at \S+ line \d+\.?//g;
    $line =~ s/\s+/ /g;
    $line =~ s/\A | \z//g;

    return length $line ? $line : $opt{empty} // 'unknown error';
}

# k398: every secret this process has read -- a Hetzner token, from the
# environment, secrets.yaml or a provider CR's Secret -- for the life of the
# process. The code that reads one adds it; one_line, and OCP.pm's renderer
# through mask_secrets, put ******** where it stands, so no message names it,
# whichever way it took to the terminal. Process-wide on purpose, as
# OCP::Password's $PINS_STDIN is: a secret read anywhere is a secret
# everywhere, and the code that prints holds no handle on the code that read.
#
# A value shorter than 8 characters is no secret here: an empty or a short
# one (a "0", a test's "tok") would mask unrelated text, every number with a
# 0 in it. Longest first, the mask one_line is given among them, so a secret
# inside a longer one never leaves the longer one half masked.
my %SECRET;

sub add_secret {
    my ($value) = @_;
    $SECRET{$value} = 1 if defined $value && length $value >= 8;
    return;
}

sub mask_secrets { _masked($_[0]) }

sub _masked {
    my ($text, @also) = @_;
    return '' unless defined $text;
    $text = "$text";
    for my $secret (sort { length $b <=> length $a || $a cmp $b }
                    keys %SECRET, grep { defined $_ && length $_ } @also) {
        $text =~ s/\Q$secret\E/********/g;
    }
    return $text;
}

# k384, k387, moved here from OCP::Role::Cmd::cluster_api_error (k398), so
# the one renderer in OCP.pm can say it too: what became of a request to the
# API server, as one line. Kubernetes::REST dies with an APIError: for an
# answer of 400 and up, and with code 599 for no answer at all (its "Error
# contract"). Its text carries the caller's source location, and a 599's
# body LWP's own as well, so where it reached OCP.pm it read "This is an
# internal error". By the code:
#   599       no answer (refused, no route, TLS, a timeout): "could not be
#             reached", and the first line of the transport reason. LWP says
#             it there whole; the lines after it say it again, with LWP's
#             own location ("Connection refused" twice, k387). No line at
#             all is 'unknown error', never an empty reason.
#   401       "refused the credentials in the kubeconfig": a token or a client
#             certificate it does not know, or no longer.
#   403       "denied the request": the credentials are good, RBAC says no.
#   500-598   "failed": the API server could not do it.
#   any other "answered" -- a 404 too: an answer, never "could not be
#             reached", and nothing here makes it "absent".
# Behind the words the status, with the reason of a Kubernetes Status body in
# words ("403 Forbidden", "500 Internal Error"), then the API's message, unless
# it only repeats that reason (a 401 says "Unauthorized" twice). A body that
# is no Status object (a proxy's page, Go's "404 page not found") is the
# message, as one line; no body, no message.
#
# The server is named when the caller knows it: "The cluster API at
# <endpoint>"; without one, "The cluster API".
sub api_error_line {
    my ($err, $endpoint) = @_;
    return unless Scalar::Util::blessed($err)
        && $err->isa('Kubernetes::REST::APIError');
    my $at   = 'The cluster API'.(defined $endpoint ? ' at '.$endpoint : '');
    my $code = $err->code;
    if ($code == 599) {
        my ($why) = $err->body =~ /^(.*\S.*)$/m;
        return "$at could not be reached: ".one_line($why);
    }
    my $what = $code == 401 ? 'refused the credentials in the kubeconfig'
             : $code == 403 ? 'denied the request'
             : $code >= 500 ? 'failed'
             :                'answered';
    (my $reason = $err->reason // '') =~ s/(?<=[a-z])(?=[A-Z])/ /g;
    my $message = one_line($err->message // $err->body, empty => '');
    $message = '' if lc $message eq lc $reason;
    return "$at $what (".join(' ', $code, length $reason ? $reason : ())
        .')'.(length $message ? ": $message" : '');
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
else is done -- the API token a request went out with.  Every secret
L</add_secret> was given is masked as well, without being named here.

=item empty

What to return when nothing is left (C<undef>, an empty or blank C<$err>, a
bare source location). C<'unknown error'> when not given.

=back

=head2 add_secret

    OCP::ErrorLine::add_secret($token);

Remembers C<$token> as a secret for the life of the process: from then on
L</one_line> and L</mask_secrets> replace it with C<********> wherever it
appears.  C<undef> and any value shorter than 8 characters are ignored, so an
empty or a short value does not mask unrelated text.  Returns nothing.
L<OCP::Secrets/hetzner_token>, L<OCP::Provider::Hetzner> and
L<OCP::Hetzner::Picker> add the Hetzner token they read or are built with
(k398).

=head2 mask_secrets

    print STDERR OCP::ErrorLine::mask_secrets($text);

C<$text> with every secret L</add_secret> was given replaced by C<********>,
the longest first, so a secret inside a longer one never leaves part of the
longer one standing.  C<undef> comes back as C<''>.  Nothing else about the
text changes: no folding, no source locations taken out.

=head2 api_error_line

    my $line = OCP::ErrorLine::api_error_line($err, $endpoint);
    # The cluster API at https://10.0.0.1:6443 could not be reached: Can't connect to 10.0.0.1:6443 (Connection refused)

For a L<Kubernetes::REST::APIError>, one line saying what became of the
request and why; for anything else nothing (C<undef>).  C<$endpoint> is the
API server the client talks to: given, the line starts C<The cluster API at
$endpoint>; C<undef>, it starts C<The cluster API>.  By the status:

=over

=item 599, no answer

C<could not be reached:> and the first line of the transport reason;
C<unknown error> when the body has none.

=item 401

C<refused the credentials in the kubeconfig>.

=item 403

C<denied the request>.

=item 500 and up

C<failed>.

=item any other status

C<answered>; a C<404> too, which is an answer, never "could not be reached".

=back

Behind the words, for an answer: the status in brackets, with the C<reason>
of a Kubernetes C<Status> body in words (C<403 Forbidden>), then the API's
C<message> -- or the body, when it is no C<Status> object -- as one line by
L</one_line>, left out when it only repeats the reason.
L<OCP::Role::Cmd/cluster_api_error> says it with the client's endpoint
(k384, k387).

=cut

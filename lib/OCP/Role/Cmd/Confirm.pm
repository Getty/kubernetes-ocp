package OCP::Role::Cmd::Confirm;
# ABSTRACT: A person's yes at a terminal, for the commands that ask for one

use Carp qw( croak );

use Moo::Role;

# Whether someone at a terminal can answer. A pipe, a CI step or a
# here-string is no one: what it carries is not a person's yes (k293, k301,
# k303). An attribute so tests can stand in for the terminal.
#
# Its own role, not OCP::Role::Cmd: every command consumes that one, and
# OCP::Cmd::Init declares an _interactive of its own, which Moo refuses to
# compose over ("cannot overwrite a locally defined method").
has _interactive => (is => 'lazy');

sub _build__interactive { -t STDIN ? 1 : 0 }

# A terminal's stdin is the confirmation. Without a terminal STDIN is not
# read at all -- a piped "y" does not count -- and STDERR says what is needed
# instead: a person at a terminal, or the command's own switch. The question
# goes to STDERR too: it is not payload. Only y or yes counts, trimmed and in
# any case; anything else, or an EOF, is a no.
#
#   question  what is asked, printed as it is and followed by " [y/N] "
#   action    what needs the yes, for the refusal ("destroying cluster 'x'")
#   switch    the option that confirms without a terminal, if the command
#             has one ('--force'); without it the refusal names none
sub confirmed {
    my ($self, %arg) = @_;

    croak __PACKAGE__.'->confirmed needs a question and an action'
        unless defined $arg{question} && defined $arg{action};

    unless ($self->_interactive) {
        print STDERR 'No terminal to confirm on: '.$arg{action}
                   . ' needs a person at a terminal'
                   . (defined $arg{switch} ? ', or '.$arg{switch} : '')
                   . ".\n";
        return 0;
    }

    print STDERR $arg{question}.' [y/N] ';
    my $answer = <STDIN>;
    return defined $answer && $answer =~ /\A\s*y(?:es)?\s*\z/i;
}

1;

__END__

=description

The confirmation the commands that destroy or forget something ask for:
C<ocp destroy>, C<ocp node trust-host>, and C<ocp update> when the version
manifest lists manual steps.  The consumer also consumes L<OCP::Role::Cmd>.

=method confirmed

    return 1 unless $self->force || $self->confirmed(
        question => 'Are you sure you want to destroy this cluster?',
        action   => "destroying cluster '$name'",
        switch   => '--force',
    );

True when a person at a terminal answered C<y> or C<yes> (trimmed, any case)
to I<question>, asked on STDERR with C< [y/N] > after it.  Anything else, and
an EOF, is a no.

Without a terminal on STDIN it reads nothing and returns false, after saying
on STDERR that I<action> needs a person at a terminal, or I<switch> when the
command has one.  A piped C<y> is not a confirmation.

=cut

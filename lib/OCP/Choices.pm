package OCP::Choices;
# ABSTRACT: The one shape OCP refuses input in

use strict;
use warnings;

# Since karr #67 an OCP command that refuses input names the input and then
# says what would have worked -- `ocp quatschkommando` answers "Unknown
# command 'quatschkommando' for 'ocp'." with an "Available: ..." line under
# it. karr #89 gave provider names the same answer; karr #103 found six more
# rejections that only ever said no.
#
# This module is that shape and nothing else, so that six call sites produce
# ONE error picture rather than six similar ones, and so the seventh costs a
# single line.
#
# It deliberately knows no sets. A set of valid values belongs to whatever
# owns the concept -- OCP::Provider knows its types, OCP::Node its roles,
# OCP::Versions its manifests, a cluster its CRs -- and the listing in the
# message has to come from the same place as the check that produced the
# message. A hand-written list passed in here would read right and drift
# tomorrow, which is the failure karr #102, #109, #110 and #112 were all
# filed for.

# One choice as it appears in a listing: a plain string, or [ name, note ]
# for "name (note)". The note carries whatever the operator most plausibly
# typed instead -- a provider's TYPE next to its name (karr #89), a key's
# purpose next to its name -- because showing the right answer without
# showing why it is the right answer teaches nothing.
sub choice_list {
    return join ', ', map { ref $_ eq 'ARRAY' ? "$_->[0] ($_->[1])" : $_ } @_;
}

sub available {
    return 'Available: ' . choice_list(@_) . "\n";
}

# For prose that has to read as a sentence rather than as a listing --
# OCP::Config::validate collects one line per problem and has no room for a
# second line under it.
sub or_list {
    my @choices = map { ref $_ eq 'ARRAY' ? $_->[0] : $_ } @_;

    return ''                                                   unless @choices;
    return $choices[0]                                          if @choices == 1;
    return "$choices[0] or $choices[1]"                         if @choices == 2;
    return join(', ', @choices[0 .. $#choices - 1]) . ", or $choices[-1]";
}

# The rejection itself.
#
#   Unknown provider 'ssh'.
#   Available: hetzner-default (type hetzner), ssh-default (type ssh)
#   'ssh' is a provider type, not a provider name. ...
#
# $choices is either an ARRAY ref of choices -- formatted by available(),
# with `empty` used instead when the list turns out to be empty -- or a
# ready-made block of text, for a caller that already owns a listing function
# and its own empty case (OCP::Role::Cmd::provider_choices does).
#
# `hint` is appended verbatim and is the CALLER's judgement, never this
# module's: a hint is a claim about the input ("'ssh' is a provider type"),
# and whether that claim is true is domain knowledge. karr #89 settled the
# rule -- a hint appears only where it is true, so a genuine typo gets the
# listing without it.
sub unknown {
    my ($what, $input, $choices, %opt) = @_;

    my $block
        = !defined $choices       ? ''
        : ref $choices eq 'ARRAY' ? (@$choices ? available(@$choices)
                                               : ($opt{empty} // ''))
        :                           $choices;

    return "Unknown $what '" . (defined $input ? $input : '') . "'.\n"
         . $block
         . ($opt{hint} // '');
}

1;

__END__

=synopsis

    use OCP::Choices;

    die OCP::Choices::unknown('role', $role, [ OCP::Node->roles ]);

    # Unknown role 'quatsch'.
    # Available: control-plane, worker

    die OCP::Choices::unknown('node', $name, [ @node_names ],
        empty => "No OCPNode exists in this cluster; 'ocp node add' creates one.\n",
    );

    # A listing on its own, for a rejection that is not "unknown X"
    die "Multiple providers found, --provider required.\n"
      . OCP::Choices::available(map { [ $_->{name}, "type $_->{type}" ] } @p);

=description

The shape every OCP rejection takes: name the word that was not understood,
then say what would have worked.

    Unknown provider 'ssh'.
    Available: hetzner-default (type hetzner), ssh-default (type ssh)
    'ssh' is a provider type, not a provider name. 'ocp apply' names its CR 'ssh-default'.

C<ocp> has answered unknown B<commands> like this since karr #67 and unknown
B<provider names> since karr #89.  This module exists so that the other six
rejections found in karr #103 -- an unknown node, an unknown key, an unknown
key purpose, an unknown version, an unknown provider type, an unknown
C<--role> -- produce B<one> error picture instead of six similar ones, and so
that the next one costs a single line.

=head2 It knows no sets

Every function here is handed the valid values; none of them stores any.
That is the whole discipline: the set of valid providers belongs to
L<OCP::Provider>, the set of roles to L<OCP::Node>, the set of versions to
L<OCP::Versions>, and the set of a cluster's CRs to the cluster.  The listing
printed in an error must come from the same place as the check that produced
the error, or the two drift and the message starts lying -- the failure
recorded in karr #102, #109, #110 and #112.

=method choice_list

    my $text = OCP::Choices::choice_list('hetzner', 'ssh', 'local');
    # hetzner, ssh, local

    my $text = OCP::Choices::choice_list([ 'ssh-default', 'type ssh' ]);
    # ssh-default (type ssh)

The comma-separated listing, with no prefix and no newline.  A choice is
either a plain string or an array ref C<[ $name, $note ]>, rendered as
C<name (note)>.

Use the note for whatever the operator most plausibly typed instead: a
provider's type next to its name, a key's purpose next to its name.

=method available

    print OCP::Choices::available(@choices);
    # Available: hetzner, ssh, local\n

L</choice_list> under the C<Available:> label, newline-terminated -- the
second line of the house rejection.  Useful on its own for a rejection that
is not an unknown value, e.g. C<Multiple providers found, --provider
required.>

=method or_list

    my $text = OCP::Choices::or_list(OCP::Provider->types);
    # hetzner, ssh, or local

The same choices as a sentence fragment, for prose with no room for a listing
line -- L<OCP::Config/validate> collects one line per problem.

=method unknown

    die OCP::Choices::unknown($what, $input, \@choices, %opt);
    die OCP::Choices::unknown($what, $input, $ready_made_block, %opt);

The rejection: C<< Unknown $what '$input'. >> followed by the choices.

C<$choices> is either an array ref, which is rendered by L</available> (or
replaced by C<< empty => $text >> when the list is empty), or a ready-made
newline-terminated block for a caller that already owns its listing and its
own empty case.

C<< hint => $text >> is appended verbatim.  Whether to pass one is the
caller's decision and always a judgement about the input: karr #89 settled
that a hint appears only where it is B<true>, so C<--provider ssh> is told
that C<ssh> is a type rather than a name, while the typo C<ssh-defualt> gets
the listing and no such claim.

=seealso

L<OCP::Role::Cmd>, L<OCP::Provider>, L<OCP::Node>, L<OCP::Versions>

=cut

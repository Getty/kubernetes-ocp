package OCP::Choices;
# ABSTRACT: The one shape OCP refuses input in

use strict;
use warnings;

use Socket ();

# Since k67 an OCP command that refuses input names the input and then
# says what would have worked -- `ocp quatschkommando` answers "Unknown
# command 'quatschkommando' for 'ocp'." with an "Available: ..." line under
# it. k89 gave provider names the same answer; k103 found six more
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
# tomorrow, which is the failure k102, k109, k110 and k112 were all
# filed for.

# One choice as it appears in a listing: a plain string, or [ name, note ]
# for "name (note)". The note carries whatever the operator most plausibly
# typed instead -- a provider's TYPE next to its name (k89), a key's
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
# and whether that claim is true is domain knowledge. k89 settled the
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

# node-ip (k254): the address a node registers by. It is given in three
# places -- `ocp node add --node_ip`, ocp.yaml control_planes[].node_ip, an
# OCPNode's spec.nodeIP -- none of which owns it, and all three must refuse
# the same values in the same words, which is this module's reason to exist.
# It holds no set: what passes is IP syntax, and that does not drift.
#
# What passes here is handed on as written, to Rex::Rancher, whose preflight
# (Rex::Rancher::Options::check_node_addresses, rex-rancher k100) splits on
# the comma WITHOUT trimming and puts every part through inet_pton. So
# whitespace is refused rather than trimmed: a trimmed check would pass
# '10.0.0.1, fd00::1' and the lib would die on it later. Refused beyond the
# lib: what kubelet's validateNodeIP refuses at join (loopback, unspecified,
# link-local, multicast), and what kubelet would misread -- it counts
# '::ffff:10.0.0.1' as IPv4, and two of one family is not dual-stack.
my $NODE_IP_FORMS = 'expected an IPv4 or IPv6 address, or one of each joined by a comma, like 10.0.0.1,fd00::1';

sub node_ip_error {
    my ($value) = @_;

    return undef unless defined $value;
    return 'must be one string like 10.0.0.1 or 10.0.0.1,fd00::1, not a '
         . (ref $value eq 'ARRAY' ? 'list' : ref $value eq 'HASH' ? 'mapping' : 'reference')
        if ref $value;
    return 'must not be empty; ' . $NODE_IP_FORMS if $value =~ /\A\s*\z/;

    if ($value =~ /\s/) {
        (my $bare = $value) =~ s/\s+//g;
        return _quoted($value) . ' contains whitespace'
             . (defined node_ip_error($bare) ? '; ' . $NODE_IP_FORMS : ': write ' . _quoted($bare));
    }

    my @ips = split /,/, $value, -1;
    return _quoted($value) . ' has an empty address next to a comma; ' . $NODE_IP_FORMS
        if grep { !length } @ips;
    return _quoted($value) . ' lists ' . scalar(@ips) . ' addresses; ' . $NODE_IP_FORMS
        if @ips > 2;

    my @parsed;
    for my $ip (@ips) {
        my ($family, $packed) = _parse_ip($ip);
        unless ($family) {
            my ($addr, $bits) = $ip =~ m{\A([^/]+)/(\d+)\z};
            my ($is_ip) = defined $addr ? _parse_ip($addr) : ();
            return _quoted($ip) . ' is a network (CIDR), not an address: write the '
                 . "node's own address, without /" . $bits
                if $is_ip;
            return _quoted($ip) . ' is not an IP address (hostnames are not resolved); '
                 . $NODE_IP_FORMS;
        }

        my $mapped = $family eq 'IPv6' && substr($packed, 0, 12) eq ("\0" x 10) . "\xff\xff";
        ($family, $packed) = ('IPv4', substr($packed, 12)) if $mapped;

        if (defined(my $kind = _unusable_node_ip($family, $packed))) {
            return _quoted($ip) . ' is ' . $kind . ', which kubelet refuses as a '
                 . 'node-ip; expected an address the other nodes reach this one by';
        }
        return _quoted($ip) . ' is an IPv4 address written as IPv6: write '
             . Socket::inet_ntop(Socket::AF_INET(), $packed)
            if $mapped;

        push @parsed, [ $family, $packed ];
    }

    return undef unless @parsed == 2;
    return _quoted($value) . ' names the same address twice; dual-stack takes one '
         . 'IPv4 and one IPv6 address'
        if $parsed[0][1] eq $parsed[1][1];
    return _quoted($value) . ' holds two ' . $parsed[0][0] . ' addresses; dual-stack '
         . 'takes one IPv4 and one IPv6 address'
        if $parsed[0][0] eq $parsed[1][0];
    return undef;
}

# ( 'IPv4' | 'IPv6', packed ) for an IP literal, the test Rex::Rancher runs;
# nothing for anything else. The character check comes first because
# inet_pton reads a C string: '10.0.0.1' followed by a NUL byte and more would
# pass it.
sub _parse_ip {
    my ($text) = @_;

    return unless $text =~ /\A[0-9A-Fa-f.:]+\z/;
    my $packed = Socket::inet_pton(Socket::AF_INET(), $text);
    return ('IPv4', $packed) if defined $packed;
    $packed = Socket::inet_pton(Socket::AF_INET6(), $text);
    return ('IPv6', $packed) if defined $packed;
    return;
}

# What kubelet's validateNodeIP calls the address when it refuses it as a
# node IP, or undef.
sub _unusable_node_ip {
    my ($family, $packed) = @_;

    my @b = unpack 'C*', $packed;
    return 'the unspecified address' unless grep { $_ } @b;
    if ($family eq 'IPv4') {
        return 'a loopback address'   if $b[0] == 127;
        return 'a link-local address' if $b[0] == 169 && $b[1] == 254;
        return 'a multicast address'  if $b[0] >= 224 && $b[0] <= 239;
        return undef;
    }
    return 'a loopback address'   if $b[15] == 1 && !grep { $_ } @b[0 .. 14];
    return 'a link-local address' if $b[0] == 0xfe && ($b[1] & 0xc0) == 0x80;
    return 'a multicast address'  if $b[0] == 0xff;
    return undef;
}

# A value as a diagnosis quotes it: on one line, whatever it holds.
sub _quoted {
    my ($text) = @_;

    $text =~ s/([^\x20-\x7e])/sprintf('\\x{%x}', ord $1)/ge;
    return "'" . $text . "'";
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

    # A value that is not one of a set, but must be refused alike everywhere
    my $err = OCP::Choices::node_ip_error($self->node_ip);
    die "--node_ip: $err\n" if defined $err;

    # --node_ip: '10.230.30.50/24' is a network (CIDR), not an address: ...

=description

The shape every OCP rejection takes: name the word that was not understood,
then say what would have worked.

    Unknown provider 'ssh'.
    Available: hetzner-default (type hetzner), ssh-default (type ssh)
    'ssh' is a provider type, not a provider name. 'ocp apply' names its CR 'ssh-default'.

C<ocp> has answered unknown B<commands> like this since k67 and unknown
B<provider names> since k89.  This module exists so that the other six
rejections found in k103 -- an unknown node, an unknown key, an unknown
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
recorded in k102, k109, k110 and k112.

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
caller's decision and always a judgement about the input: k89 settled
that a hint appears only where it is B<true>, so C<--provider ssh> is told
that C<ssh> is a type rather than a name, while the typo C<ssh-defualt> gets
the listing and no such claim.

=method node_ip_error

    my $err = OCP::Choices::node_ip_error($value);

    # undef for '10.230.30.50', 'fd00::5', '10.230.30.50,fd00::5'
    # "'synapse.lan' is not an IP address (hostnames are not resolved); expected ..."

What is wrong with a node-ip -- the address a node registers by, RKE2's and
K3s's C<node-ip> -- in one line, or C<undef> when nothing is.  C<undef> is
also the answer for C<undef>: no value is nothing to refuse, and the node-ip
is then left out.  It never dies.

Accepted is a string holding one IPv4 or IPv6 literal, or two joined by a
comma for dual-stack, one IPv4 and one IPv6, in either order.  Refused, each
with a line that names the part at fault and what would have worked:

=over

=item * anything not a string (a YAML list included), and the empty string;

=item * whitespace anywhere, B<around the comma too>: the value is handed on
as written to L<Rex::Rancher>, which splits on the comma without trimming
and refuses C<' fd00::1'>.  The line names the value without it when that
one would pass;

=item * an empty part (C<'10.0.0.1,'>), and more than two parts;

=item * a hostname, or anything else that is not an IP literal -- it is
never resolved here;

=item * a CIDR (C<'10.230.30.50/24'>);

=item * the addresses kubelet refuses as a node IP: loopback (C<127.0.0.0/8>,
C<::1>), unspecified (C<0.0.0.0>, C<::>), B<link-local> (C<169.254.0.0/16>,
C<fe80::/10>) and multicast (C<224.0.0.0/4>, C<ff00::/8>);

=item * an IPv4-mapped IPv6 literal (C<'::ffff:10.0.0.1'>), which kubelet
counts as IPv4: the line names the IPv4 form;

=item * the same address twice, and two addresses of one family.

=back

The line carries no field name: the caller prefixes its own, so the
command line, F<ocp.yaml> and an OCPNode refuse in the same words --

    die "--node_ip: $err\n" if defined $err;             # in execute()
    push @errors, "control_planes[$idx].node_ip: $err"   # OCP::Config::validate
        if defined $err;

For an option, call it in C<execute>, before the API is asked anything --
where C<ocp node add> checks C<--label> and C<--taint>.  Not as the option's
C<isa>: L<MooX::Options> answers a failed C<isa> with the whole usage text.

=seealso

L<OCP::Role::Cmd>, L<OCP::Provider>, L<OCP::Node>, L<OCP::Versions>

=cut

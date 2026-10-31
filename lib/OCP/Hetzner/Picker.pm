package OCP::Hetzner::Picker;
# ABSTRACT: Hetzner Cloud catalogue wrapper (pickers, NOT a cluster adapter)

use Moo;
use WWW::Hetzner::Cloud;

has token => (is => 'ro', required => 1);

has _cloud => (is => 'lazy', builder => sub {
    WWW::Hetzner::Cloud->new(token => shift->token)
});

has _locations => (is => 'lazy', builder => sub {
    shift->_cloud->locations->list_all
});

has _server_types => (is => 'lazy', builder => sub {
    shift->_cloud->server_types->list_all
});

sub location_options {
    my ($self) = @_;
    return [
        map {{
            label => sprintf('%s (%s, %s)', $_->name, $_->city, $_->country),
            value => $_->name,
        }}
        @{$self->_locations}
    ];
}

# Every server type that can still be ordered, both architectures. Hetzner's
# ARM line (CAX*) is a first-class target — OCP runs on aarch64 — so a picker
# that defaults to x86 would silently hide half the catalogue. Pass
# architecture => 'arm' | 'x86' to narrow it deliberately; the label names
# the architecture either way, so equally-sized CAX and CPX sit side by side.
#
# Whether a type can be ordered is a per-location fact: each entry of its
# `locations` says `available` and carries `deprecation` (null, or the
# announced end of the type there). The top-level `deprecated` flag leaves
# the API on 2026-11-02 and is not read. Pass location => 'fsn1' to offer only
# what can be ordered in that location; without one, a type that can be
# ordered in at least one location is offered.
sub server_type_options {
    my ($self, %filter) = @_;
    my $arch     = $filter{architecture};
    my $location = $filter{location};

    my @types = grep {
        (!defined $arch || $_->architecture eq $arch)
        && $self->_orderable($_, $location)
    } @{$self->_server_types};

    return [
        map {{
            label => sprintf('%s (%s, %d CPU, %dGB, %dGB %s)',
                $_->name, $_->architecture, $_->cores, $_->memory,
                $_->disk, $_->cpu_type),
            value => $_->name,
        }}
        sort { $a->cores <=> $b->cores
            || $a->memory <=> $b->memory
            || $a->name cmp $b->name }
        @types
    ];
}

# WWW::Hetzner hands the API's locations entries through as plain hashes;
# an explicit `locations: null` arrives as undef. Anything that is not a hash
# is skipped rather than dereferenced.
sub _orderable {
    my ($self, $type, $location) = @_;
    for my $entry (@{ $type->locations // [] }) {
        next unless ref $entry eq 'HASH';
        next if defined $location && ($entry->{name} // '') ne $location;
        return 1 if $entry->{available} && !defined $entry->{deprecation};
    }
    return 0;
}

1;

__END__

=synopsis

    use OCP::Hetzner::Picker;

    my $hz = OCP::Hetzner::Picker->new(token => $ENV{HETZNER_API_TOKEN});

    my $locations = $hz->location_options;
    # [ { label => 'Falkenstein (Falkenstein, DE)', value => 'fsn1' }, ... ]

    # aarch64-first cluster: pin to ARM server types only
    my $arm_types = $hz->server_type_options(architecture => 'arm');

=description

C<OCP::Hetzner::Picker> is the read-only catalogue wrapper around the
Hetzner Cloud API.  It exists to feed the pickers in C<ocp init>
(location and server type) — it does not create or delete servers; for
that, see L<OCP::Provider::Hetzner>, which is what C<ocp apply> actually
uses.

Both lazy builders (C<_locations>, C<_server_types>) fetch every page once
from L<WWW::Hetzner::Cloud> (C<list_all>) and cache on the instance.  Pickers
therefore cost one round trip per catalogue page per process.

=attr token

    my $hz = OCP::Hetzner::Picker->new(token => $token);

Hetzner Cloud API token.  Required.

=method location_options

    my $list = $hz->location_options;

Returns an arrayref of C<{ label, value }> pairs for every location
Hetzner advertises, formatted as C<"Name (City, COUNTRY)">.

=method server_type_options

    my $list = $hz->server_type_options;
    my $arm = $hz->server_type_options(architecture => 'arm');
    my $x86 = $hz->server_type_options(architecture => 'x86');
    my $fsn = $hz->server_type_options(location => 'fsn1');
    my $both = $hz->server_type_options(location => 'fsn1', architecture => 'arm');

Returns an arrayref of C<{ label, value }> pairs for every server type that
can be ordered.  Labels include the architecture name on purpose — OCP runs
on aarch64, so a picker that defaulted to x86 would silently hide half of
the catalogue.  Pass C<architecture> to narrow the list to one target
arch; the default returns both.  Sorted by cores, then memory, then name.

Orderability is read per location, from the type's C<locations> entries
(L<WWW::Hetzner::Cloud::ServerType/locations>): an entry counts when it is
C<available> and its C<deprecation> is null.  With C<location>, a type is
offered only when the entry of that name counts; a type not offered in that
location at all is left out.  Without C<location>, a type is offered when at
least one of its entries counts, so the list is useful before a location is
chosen.  The top-level C<deprecated> flag, which Hetzner removes from the API
on 2026-11-02, is not read.

=seealso

L<OCP::Provider::Hetzner>, L<OCP::Cmd::Init>, L<WWW::Hetzner::Cloud>

=cut

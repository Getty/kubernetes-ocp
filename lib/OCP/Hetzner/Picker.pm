package OCP::Hetzner::Picker;
# ABSTRACT: Hetzner Cloud catalogue wrapper (pickers, NOT a cluster adapter)

use Moo;
use WWW::Hetzner::Cloud;

our $VERSION = '0.001';

has token => (is => 'ro', required => 1);

has _cloud => (is => 'lazy', builder => sub {
    WWW::Hetzner::Cloud->new(token => shift->token)
});

has _locations => (is => 'lazy', builder => sub {
    shift->_cloud->locations->list
});

has _server_types => (is => 'lazy', builder => sub {
    shift->_cloud->server_types->list
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

# Every non-deprecated server type, both architectures. Hetzner's ARM line
# (CAX*) is a first-class target — OCP runs on aarch64 — so a picker that
# defaults to x86 would silently hide half the catalogue. Pass
# architecture => 'arm' | 'x86' to narrow it deliberately; the label names
# the architecture either way, so equally-sized CAX and CPX sit side by side.
sub server_type_options {
    my ($self, %filter) = @_;
    my $arch = $filter{architecture};

    my @types = grep {
        !$_->deprecated
        && (!defined $arch || $_->architecture eq $arch)
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

Both lazy builders (C<_locations>, C<_server_types>) fetch once from
L<WWW::Hetzner::Cloud> and cache on the instance.  Pickers therefore cost
one round trip per process.

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

Returns an arrayref of C<{ label, value }> pairs for every non-deprecated
server type.  Labels include the architecture name on purpose — OCP runs
on aarch64, so a picker that defaulted to x86 would silently hide half of
the catalogue.  Pass C<architecture> to narrow the list to one target
arch; the default returns both.  Sorted by cores, then memory, then name.

=seealso

L<OCP::Provider::Hetzner>, L<OCP::Cmd::Init>, L<WWW::Hetzner::Cloud>

=cut

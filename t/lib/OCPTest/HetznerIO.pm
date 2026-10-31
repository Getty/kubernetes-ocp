package OCPTest::HetznerIO;
# ABSTRACT: An offline WWW::Hetzner IO backend that pages its lists like the API

use Moo;
use Carp qw( croak );
use JSON::MaybeXS qw( encode_json );
use WWW::Hetzner::Cloud;
use WWW::Hetzner::HTTPResponse;
use namespace::clean;

with 'WWW::Hetzner::Role::IO';

# Sits under a real WWW::Hetzner::Cloud, so the client code above it --
# controllers, wrapping, Role::Pagination -- runs as it ships and only the
# HTTP round trip is answered from here. Nothing leaves the process.
#
#   my $io = OCPTest::HetznerIO->new(
#     collections => {
#       servers      => [ { id => 1, name => 'police1', labels => {...}, ... } ],
#       locations    => [ ... ],
#       server_types => [ ... ],
#     },
#   );
#   my $cloud = $io->cloud;   # WWW::Hetzner::Cloud on top of this IO
#   $io->requests;            # [ { method, path, query => {...} }, ... ]
#
# A GET on /<collection> answers the way the API does: label_selector
# filtered server side (k=v terms, comma is AND), per_page items a page --
# default 2, so three entries already span two pages -- and
# meta.pagination.next_page set while a further page remains. Anything else
# is a 404, which WWW::Hetzner turns into "Hetzner API error: ...".

has collections => (is => 'ro', default => sub { {} });
has per_page    => (is => 'ro', default => 2);
has requests    => (is => 'ro', default => sub { [] });

sub cloud {
    my ($self) = @_;
    return WWW::Hetzner::Cloud->new(
        token   => 'fake-token',
        io      => $self,
        sleeper => sub {},
    );
}

sub call {
    my ($self, $req) = @_;

    my ($path, $qs) = split /\?/, $req->url, 2;
    $path =~ s{\Ahttps://api\.hetzner\.cloud/v1}{};
    my %query = map { $self->_unescape($_) } map { split /=/, $_, 2 } split /&/, $qs // '';
    push @{ $self->requests },
        { method => $req->method, path => $path, query => \%query };

    my ($name) = $path =~ m{\A/(\w+)\z};
    my $items  = $req->method eq 'GET' && defined $name
        ? $self->collections->{$name}
        : undef;
    return $self->_respond(404, { error => {
        code    => 'not_found',
        message => 'no route: ' . $req->method . ' ' . $path,
    } }) unless $items;

    my @match    = grep { $self->_matches($_, $query{label_selector}) } @$items;
    my $per_page = $query{per_page} // $self->per_page;
    my $page     = $query{page} // 1;
    my $last     = int((@match + $per_page - 1) / $per_page) || 1;
    my @slice    = grep { defined } @match[ ($page - 1) * $per_page .. $page * $per_page - 1 ];

    return $self->_respond(200, {
        $name => \@slice,
        meta  => { pagination => {
            page          => $page,
            per_page      => $per_page,
            previous_page => $page > 1     ? $page - 1 : undef,
            next_page     => $page < $last ? $page + 1 : undef,
            last_page     => $last,
            total_entries => scalar @match,
        } },
    });
}

sub _matches {
    my ($self, $item, $selector) = @_;
    return 1 unless defined $selector;
    my $labels = $item->{labels} // {};
    for my $term (split /,/, $selector) {
        my ($k, $v) = $term =~ /\A([^=!]+)=([^=]*)\z/
            or croak __PACKAGE__ . " understands k=v selector terms only, got '$term'";
        return 0 unless defined $labels->{$k} && $labels->{$k} eq $v;
    }
    return 1;
}

sub _unescape {
    my ($self, $s) = @_;
    $s =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
    return $s;
}

sub _respond {
    my ($self, $status, $body) = @_;
    return WWW::Hetzner::HTTPResponse->new(
        status  => $status,
        content => encode_json($body),
    );
}

1;

package OCP::Hetzner;
# ABSTRACT: Hetzner Cloud API helper for OCP

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

sub server_type_options {
    my ($self, %filter) = @_;
    my $arch = $filter{architecture} // 'x86';

    my @types = grep {
        !$_->deprecated
        && $_->architecture eq $arch
    } @{$self->_server_types};

    return [
        map {{
            label => sprintf('%s (%d CPU, %dGB, %dGB %s)',
                $_->name, $_->cores, $_->memory, $_->disk, $_->cpu_type),
            value => $_->name,
        }}
        sort { $a->cores <=> $b->cores || $a->memory <=> $b->memory }
        @types
    ];
}

1;

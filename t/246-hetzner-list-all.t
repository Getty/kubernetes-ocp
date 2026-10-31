#!/usr/bin/env perl
use strict;
use warnings;
use lib 'lib';
use lib 't/lib';
use Test::More;
use JSON::MaybeXS ();

use OCP::Cmd::Hetzner::List;
use OCP::Hetzner::Picker;
use OCP::Provider::Hetzner;
use OCPTest::HetznerIO;

# k246: every Hetzner list OCP read stopped at page one. WWW::Hetzner's list
# and list_by_label fetch a single page; list_all follows
# meta.pagination.next_page. The fake IO pages two entries at a time, so the
# third entry of any list below sits on page 2 -- the one a single-page read
# never sees. Everything above the HTTP round trip is real WWW::Hetzner.

my $false = JSON::MaybeXS::false;
my $true  = JSON::MaybeXS::true;

sub server {
    my ($id, $name, %labels) = @_;
    return {
        id          => $id,
        name        => $name,
        status      => 'running',
        public_net  => { ipv4 => { ip => "203.0.113.$id" } },
        server_type => { id => 1, name => 'cx22' },
        location    => { name => 'fsn1' },
        image       => { name => 'debian-13' },
        labels      => \%labels,
    };
}

# Three servers of cluster prod (pages 1 and 2 of that selector) and one of a
# neighbour cluster in the same Hetzner project.
sub servers {
    return [
        server(1, 'prod-police1', 'ocp-cluster' => 'prod', 'ocp-node' => 'police1'),
        server(2, 'other-police1', 'ocp-cluster' => 'other', 'ocp-node' => 'police1'),
        server(3, 'prod-worker1', 'ocp-cluster' => 'prod', 'ocp-node' => 'worker1'),
        server(4, 'prod-worker2', 'ocp-cluster' => 'prod', 'ocp-node' => 'worker2'),
    ];
}

sub pages_asked {
    my ($io, $path) = @_;
    return [ map { $_->{query}{page} // 1 } grep { $_->{path} eq $path } @{ $io->requests } ];
}

sub capture_stdout {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die "capture: $!";
    my $old = select $fh;
    my $ok  = eval { $code->(); 1 };
    my $err = $@;
    select $old;
    close $fh;
    return ($out, $ok, $err);
}

# ---------------------------------------------------------------- provider --

sub provider {
    my ($io) = @_;
    return OCP::Provider::Hetzner->new(
        token        => 'fake-token',
        cluster_name => 'prod',
        cloud        => $io->cloud,
    );
}

subtest 'list_servers_by_cluster returns servers from every page' => sub {
    # `ocp destroy` sweeps orphans with this; a server on page 2 would keep
    # running and billing after "Cluster destroyed."
    my $io = OCPTest::HetznerIO->new(collections => { servers => servers() });

    my $got = provider($io)->list_servers_by_cluster('prod');

    is_deeply [ sort map { $_->name } @$got ],
        [qw( prod-police1 prod-worker1 prod-worker2 )],
        'all three prod servers, none of the neighbour cluster';
    is_deeply pages_asked($io, '/servers'), [1, 2], 'page 2 was fetched';
    is_deeply [ map { $_->{query}{label_selector} } @{ $io->requests } ],
        [ 'ocp-cluster=prod', 'ocp-cluster=prod' ],
        'the cluster label goes to the API as label_selector on every page';
};

subtest 'server_exists asks for the cluster/node pair through list_all' => sub {
    # A cluster+node selector matches one server, so it never spans a page:
    # this pins the request it sends, not the paging (k246 switched it for the
    # same read path as the sweep).
    my $io = OCPTest::HetznerIO->new(collections => { servers => servers() });

    my $found = provider($io)->server_exists('worker2');

    is $found && $found->id, 4, 'the labelled server is found';
    is $io->requests->[0]{query}{label_selector}, 'ocp-cluster=prod,ocp-node=worker2',
        'cluster and node travel as one AND selector';
    is provider($io)->server_exists('worker9'), undef, 'no match is undef';
};

# ----------------------------------------------------------- hetzner list --

subtest 'ocp hetzner list prints servers from every page' => sub {
    my $io = OCPTest::HetznerIO->new(collections => { servers => servers() });

    my ($out, $ok, $err) = capture_stdout(sub {
        OCP::Cmd::Hetzner::List->new(cloud => $io->cloud)->execute([], []);
    });

    ok $ok, 'the listing runs to the end' or diag $err;
    like $out, qr/^\Q$_\E\s/m, "server $_ is listed" for 1 .. 4;
    is_deeply pages_asked($io, '/servers'), [1, 2], 'page 2 was fetched';
};

subtest 'ocp hetzner list --label filters server side, across pages' => sub {
    my $io = OCPTest::HetznerIO->new(collections => { servers => servers() });

    my ($out, $ok, $err) = capture_stdout(sub {
        OCP::Cmd::Hetzner::List->new(label => 'ocp-cluster=prod', cloud => $io->cloud)
            ->execute([], []);
    });

    ok $ok, 'the listing runs to the end' or diag $err;
    like $out, qr/^\Q$_\E\s/m, "prod server $_ is listed" for 1, 3, 4;
    unlike $out, qr/other-police1/, 'the neighbour cluster is filtered out';
    is_deeply [ map { $_->{query}{label_selector} } @{ $io->requests } ],
        [ 'ocp-cluster=prod', 'ocp-cluster=prod' ],
        '--label goes to the API as label_selector on every page';
};

# ------------------------------------------------------------------ picker --

sub location {
    my ($id, $name, $city, $country) = @_;
    return { id => $id, name => $name, city => $city, country => $country,
        network_zone => 'eu-central', description => $city };
}

# The shape GET /server_types answers with (docs.hetzner.cloud/cloud.spec.json):
# one locations[] entry per location the type is offered in.
sub server_type {
    my ($id, $name, $cores, $memory, $arch) = @_;
    return {
        id => $id, name => $name, description => uc $name,
        cores => $cores, memory => $memory, disk => 40,
        cpu_type => 'shared', architecture => $arch,
        locations => [ { id => 1, name => 'fsn1', deprecation => undef,
            recommended => $false, available => $true } ],
    };
}

sub picker {
    my ($io) = @_;
    return OCP::Hetzner::Picker->new(token => 'fake-token', _cloud => $io->cloud);
}

subtest 'location_options offers locations from every page' => sub {
    my $io = OCPTest::HetznerIO->new(collections => { locations => [
        location(1, 'fsn1', 'Falkenstein', 'DE'),
        location(2, 'nbg1', 'Nuremberg',   'DE'),
        location(3, 'hel1', 'Helsinki',    'FI'),
    ] });

    is_deeply [ map { $_->{value} } @{ picker($io)->location_options } ],
        [qw( fsn1 nbg1 hel1 )], 'hel1 from page 2 is offered';
    is_deeply pages_asked($io, '/locations'), [1, 2], 'page 2 was fetched';
};

subtest 'server_type_options offers types from every page' => sub {
    my $io = OCPTest::HetznerIO->new(collections => { server_types => [
        server_type(1, 'cx22',  2, 4,  'x86'),
        server_type(2, 'cax11', 2, 4,  'arm'),
        server_type(3, 'cx32',  4, 8,  'x86'),
    ] });

    is_deeply [ map { $_->{value} } @{ picker($io)->server_type_options } ],
        [qw( cax11 cx22 cx32 )], 'cx32 from page 2 is offered';
    is_deeply pages_asked($io, '/server_types'), [1, 2], 'page 2 was fetched';
};

done_testing;

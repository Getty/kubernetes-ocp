#!/usr/bin/env perl
use strict;
use warnings;
use lib 'lib';
use lib 't/lib';
use Test::More;

use OCP::Cmd::Hetzner::List;
use OCPTest::HetznerIO;

# k245: `ocp hetzner list` died on the first server it printed. The TYPE column
# read $server->server_type->{name}, but WWW::Hetzner::Cloud::Server's
# server_type is the type NAME as a plain string -- the raw hash is
# server_type_data -- so strict refs killed the command with "Can't use string
# ("cx22") as a HASH ref". Everything under the command here is real
# WWW::Hetzner; only the HTTP round trip is answered offline.

sub server {
    my (%a) = @_;
    return {
        id          => $a{id},
        name        => $a{name},
        status      => 'running',
        public_net  => { ipv4 => { ip => $a{ip} } },
        server_type => { id => 1, name => $a{type}, cores => 2 },
        location    => { name => 'fsn1' },
        image       => { name => 'debian-13' },
        labels      => $a{labels} // {},
    };
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

subtest 'a listed server shows its type name in the TYPE column' => sub {
    my $io = OCPTest::HetznerIO->new(collections => { servers => [
        server(id => 4711, name => 'prod-police1', ip => '203.0.113.10',
            type => 'cx22', labels => { 'ocp-cluster' => 'prod' }),
    ] });
    my $cmd = OCP::Cmd::Hetzner::List->new(cloud => $io->cloud);

    my ($out, $ok, $err) = capture_stdout(sub { $cmd->execute([], []) });

    ok $ok, 'the listing runs to the end' or diag $err;
    like $out, qr/^4711\s+prod-police1\s+running\s+203\.0\.113\.10\s+cx22\s+ocp-cluster=prod$/m,
        'the row carries id, name, status, IPv4, type name and labels';
};

subtest 'a server without a public IPv4 still lists' => sub {
    my $io = OCPTest::HetznerIO->new(collections => { servers => [
        { %{ server(id => 7, name => 'private1', type => 'cax11') }, public_net => {} },
    ] });
    my ($out, $ok, $err) = capture_stdout(sub {
        OCP::Cmd::Hetzner::List->new(cloud => $io->cloud)->execute([], []);
    });

    ok $ok, 'the listing runs to the end' or diag $err;
    like $out, qr/^7\s+private1\s+running\s+-\s+cax11\s+-$/m,
        'missing IPv4 and labels print as -';
};

done_testing;

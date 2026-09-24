#!/usr/bin/env perl
# karr k170 -- the TLS path of the async Kubernetes client must be loadable.
#
# Net::Async::Kubernetes speaks https (list, get, watch) through
# Net::Async::HTTP and wss (port_forward, exec) through
# Net::Async::WebSocket::Client. Both load IO::Async::SSL only when a request
# actually uses TLS, and list it as a recommendation, not a requirement. The
# shipped image did not have it: every watch robocop started and every
# `ocp inject-key` port-forward failed with "Can't locate IO/Async/SSL.pm",
# which no load test could see because nothing loads it up front.
#
# So this file goes down the real request path of both transports against a
# loopback port nobody listens on -- no network, no cluster. With
# IO::Async::SSL present the request gets as far as the TCP connect and fails
# there; without it, it fails on the missing module first.
use strict;
use warnings;
use Test::More;

use IO::Async::Loop;
use IO::Socket::INET;
use IO::K8s;
use Future;
use Net::Async::Kubernetes;

use_ok('IO::Async::SSL');
ok(IO::Async::Loop->can('SSL_connect'),
    'IO::Async::SSL adds SSL_connect to the loop (what Net::Async::HTTP calls)');

# A loopback port that is certainly closed: bind one, note it, let it go.
sub closed_port {
    my $sock = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Listen    => 1,
    ) or die 'cannot bind a loopback port: ' . $!;
    my $port = $sock->sockport;
    close $sock;
    return $port;
}

my $loop = IO::Async::Loop->new;

sub kube {
    my $kube = Net::Async::Kubernetes->new(
        server       => { endpoint => 'https://127.0.0.1:' . closed_port() },
        credentials  => { token => 'test-token' },
        resource_map => IO::K8s->default_resource_map,
    );
    $loop->add($kube);
    return $kube;
}

# The request's failure, or a timeout -- never a hang.
sub failure_of {
    my ($f) = @_;
    my $both = Future->wait_any(
        $f,
        $loop->delay_future(after => 10)->then_fail('timed out'),
    );
    $loop->await($both);
    return $both->failure;
}

subtest 'https (list, the watch transport) reaches the TCP connect' => sub {
    my $err = failure_of(kube()->list('Pod', namespace => 'default'));
    ok(defined $err, 'the request to a closed port fails');
    unlike($err // '', qr{IO/Async/SSL\.pm|IO::Async::SSL},
        'not on a missing IO::Async::SSL');
    unlike($err // '', qr/timed out/, 'and not by hanging');
    note('failure: ' . ($err // 'none'));
};

subtest 'wss (port_forward, the inject-key transport) reaches the TCP connect' => sub {
    my $err = failure_of(kube()->port_forward('Pod', 'robocop-0',
        namespace => 'ocp-system',
        ports     => [9999],
    ));
    ok(defined $err, 'the port-forward to a closed port fails');
    unlike($err // '', qr{IO/Async/SSL\.pm|IO::Async::SSL},
        'not on a missing IO::Async::SSL');
    unlike($err // '', qr/timed out/, 'and not by hanging');
    note('failure: ' . ($err // 'none'));
};

done_testing;

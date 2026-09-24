#!/usr/bin/env perl
# karr k2 -- the robo-key injection protocol between `ocp inject-key` and
# robocop (robocop.security_level: inject).
#
# The private robo key never rests in a Secret or on disk: the admin hands it
# over a Kubernetes port-forward into the running pod, robocop validates it and
# holds it in memory. This file pins the protocol both ends speak, the robocop
# side that answers it, and the CLI side that drives it over port_forward.
#
# Network-free: the server is exercised over a socketpair, the client over a
# fake port-forward session that feeds the real server logic. No listening
# socket is ever opened, no cluster is ever contacted.

use strict;
use warnings;
use Test::More;

use Future;
use IO::Async::Loop;
use IO::Async::OS;
use IO::Async::Stream;

use lib 'lib';

use OCP::Robocop::KeyInjection;

my $KI = 'OCP::Robocop::KeyInjection';

# TEST FIXTURES ONLY. Generated for this file with ssh-keygen, trusted nowhere.
my $ROBO_PRIV = <<'KEY';
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCjx1LAEqprX25BhoqMOTYatLiWTFUp5yZ3QeRVFERELAAAAJBghgLhYIYC
4QAAAAtzc2gtZWQyNTUxOQAAACCjx1LAEqprX25BhoqMOTYatLiWTFUp5yZ3QeRVFERELA
AAAEB4j2YTstm3JkTHirZKgotr5qZlJtYh9RdFBD1clvK63qPHUsASqmtfbkGGiow5Nhq0
uJZMVSnnJndB5FUUREQsAAAADGZpeHR1cmUtcm9ibwE=
-----END OPENSSH PRIVATE KEY-----
KEY
my $ROBO_PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKPHUsASqmtfbkGGiow5Nhq0uJZMVSnnJndB5FUUREQs fixture-robo';
my $ROBO_FP  = 'SHA256:nqNyKkWIC8O8E3VIvmGZ4SqG0Pq9iXqcUpZCIVpLsSk';   # ssh-keygen -lf

my $OTHER_PRIV = <<'KEY';
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCoScP8vkN8fscBTm8Vaqv6244du7QLOXTNs9K96AHAMQAAAJBLDB/ESwwf
xAAAAAtzc2gtZWQyNTUxOQAAACCoScP8vkN8fscBTm8Vaqv6244du7QLOXTNs9K96AHAMQ
AAAEDXPJHzfIm0tSc/n3eDATj3NXCo1NcaM9xCdpFpTfZFmKhJw/y+Q3x+xwFObxVqq/rb
jh27tAs5dM2z0r3oAcAxAAAADWZpeHR1cmUtb3RoZXI=
-----END OPENSSH PRIVATE KEY-----
KEY

# Passphrase-protected: parses, but robocop could never use it.
my $ENC_PRIV = <<'KEY';
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCwsfWRw0
Ydl7ZmpRq8v7TyAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAICHNITTwCGfIejPL
dFQW6YXX+vhp4Fm97w+VlPLMs5VCAAAAkCZkEsli9ApCxFhlc50TigoUKgAwOG0t98joPC
YlsqZcTzNA6KESdwD7uZsD+EPU730v3aUqYAz5pf5WyEUItx1Q1yOh6iGULaNBP5xhF1AS
Cjh5GjxgEMd2yHfCJNbCPRKm/UlSNGGJbViFrVDnnFS3Jllb6OJSb8x/fTn4J/Dls7DgJq
3ZL78l6vBgYpnHzQ==
-----END OPENSSH PRIVATE KEY-----
KEY

sub dies_with (&) {
    my ($code) = @_;
    local $@;
    eval { $code->(); 1 } and return '';
    return $@;
}

# ==========================================================================
# Key validation
# ==========================================================================

subtest 'fingerprint is what ssh-keygen -l prints' => sub {
    is $KI->fingerprint($ROBO_PUB), $ROBO_FP, 'SHA256 of the public blob';
    is $KI->fingerprint("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKPHUsASqmtfbkGGiow5Nhq0uJZMVSnnJndB5FUUREQs\n"),
        $ROBO_FP, 'the comment does not take part';
};

subtest 'validate_key accepts the matching robo key' => sub {
    is $KI->validate_key($ROBO_PRIV, $ROBO_PUB), $ROBO_FP,
        'returns the fingerprint of the accepted key';
    is $KI->validate_key($ROBO_PRIV, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKPHUsASqmtfbkGGiow5Nhq0uJZMVSnnJndB5FUUREQs other-comment'),
        $ROBO_FP, 'a different comment on the expected key still matches';
    is $KI->validate_key($ROBO_PRIV), $ROBO_FP,
        'without an expected public key it only has to parse';
};

subtest 'validate_key refuses what robocop could not use' => sub {
    like dies_with { $KI->validate_key("hello\n", $ROBO_PUB) },
        qr/not an OpenSSH private key/, 'garbage';
    like dies_with { $KI->validate_key('', $ROBO_PUB) },
        qr/not an OpenSSH private key/, 'empty';
    like dies_with { $KI->validate_key($ENC_PRIV) },
        qr/passphrase/, 'a passphrase-protected key';

    my $err = dies_with { $KI->validate_key($OTHER_PRIV, $ROBO_PUB) };
    like $err, qr/does not match/, 'a key that is not the robo key';
    like $err, qr/\Q$ROBO_FP\E/, 'and the error names the key robocop expects';
    unlike $err, qr/PRIVATE KEY|b3BlbnNzaC/, 'but never echoes key material';
};

# ==========================================================================
# Wire format
# ==========================================================================

subtest 'request framing' => sub {
    my $bytes = $KI->encode_request($ROBO_PRIV);
    like $bytes, qr/\AOCP-INJECT-KEY 1 (\d+)\n/, 'magic, version and length header';
    my ($len) = $bytes =~ /\AOCP-INJECT-KEY 1 (\d+)\n/;
    is $len, length $ROBO_PRIV, 'the length is the key material length';

    is_deeply +{ $KI->parse_request(substr $bytes, 0, 8) }, {},
        'an incomplete header asks for more';
    is_deeply +{ $KI->parse_request(substr $bytes, 0, length($bytes) - 1) }, {},
        'an incomplete body asks for more';
    is_deeply +{ $KI->parse_request($bytes) }, { key => $ROBO_PRIV },
        'a complete request yields the key';

    like +{ $KI->parse_request("GET / HTTP/1.1\r\n") }->{error},
        qr/protocol/i, 'a foreign protocol is refused';
    like +{ $KI->parse_request("OCP-INJECT-KEY 2 10\n") }->{error},
        qr/version/i, 'an unknown version is refused';
    like +{ $KI->parse_request("OCP-INJECT-KEY 1 99999999\n") }->{error},
        qr/too large/i, 'an oversized key is refused before it is read';
    like +{ $KI->parse_request('x' x 300) }->{error},
        qr/header/i, 'an endless header line is refused';
};

subtest 'response framing' => sub {
    is_deeply +{ $KI->parse_response("OK $ROBO_FP") }, {}, 'no newline yet: more';
    is_deeply +{ $KI->parse_response("OK $ROBO_FP\n") }, { ok => $ROBO_FP }, 'OK';
    is_deeply +{ $KI->parse_response("ERR key does not match\n") },
        { error => 'key does not match' }, 'ERR';
    like +{ $KI->parse_response("WAT\n") }->{error}, qr/unexpected/i,
        'anything else is an error';
};

# ==========================================================================
# robocop side
# ==========================================================================

sub server {
    my (%opt) = @_;
    my (@keys, @rejects);
    my $srv = $KI->new(
        expected_public_key => $ROBO_PUB,
        on_key    => sub { push @keys, [@_]; $opt{on_key}->(@_) if $opt{on_key} },
        on_reject => sub { push @rejects, $_[0] },
        %{ $opt{args} // {} },
    );
    return ($srv, \@keys, \@rejects);
}

subtest 'server listens on loopback only, on the documented port' => sub {
    my ($srv) = server();
    is $srv->host, '127.0.0.1',
        'port-forward enters the pod on localhost; nothing else in the cluster reaches it';
    is $srv->port, 9999, 'port 9999';
};

subtest 'handle_request: accepted key is handed over and acknowledged' => sub {
    my ($srv, $keys, $rejects) = server();

    is $srv->handle_request(substr $KI->encode_request($ROBO_PRIV), 0, 5), undef,
        'incomplete: no answer yet';

    my $resp = $srv->handle_request($KI->encode_request($ROBO_PRIV));
    is $resp, "OK $ROBO_FP\n", 'OK with the fingerprint';
    is scalar @$keys, 1, 'on_key called once';
    is $keys->[0][0], $ROBO_PRIV, 'with the key material';
    is $keys->[0][1], $ROBO_FP,   'and its fingerprint';
    is scalar @$rejects, 0, 'nothing rejected';
};

subtest 'handle_request: a wrong key is refused and never handed over' => sub {
    my ($srv, $keys, $rejects) = server();

    my $resp = $srv->handle_request($KI->encode_request($OTHER_PRIV));
    like $resp, qr/\AERR .*does not match.*\n\z/, 'ERR with the reason';
    is scalar @$keys, 0, 'on_key never called';
    is scalar @$rejects, 1, 'on_reject told about it';

    like $srv->handle_request("BOGUS\n"), qr/\AERR /, 'protocol garbage: ERR';
};

subtest 'handle_request: a failing on_key turns into ERR' => sub {
    my ($srv) = server(on_key => sub { die "cannot hold key\n" });
    like $srv->handle_request($KI->encode_request($ROBO_PRIV)),
        qr/\AERR cannot hold key\n\z/, 'the failure is reported to the injector';
};

subtest 'handle_stream answers over a real stream and closes it' => sub {
    my $loop = IO::Async::Loop->new;
    my ($srv, $keys) = server();

    my ($s1, $s2) = IO::Async::OS->socketpair or die "socketpair: $!";

    my $server_stream = IO::Async::Stream->new(handle => $s1);
    $srv->handle_stream($server_stream);
    $loop->add($server_stream);

    my $answer = '';
    my $eof    = $loop->new_future;
    my $client = IO::Async::Stream->new(
        handle  => $s2,
        on_read => sub {
            my ($s, $buf, $at_eof) = @_;
            $answer .= $$buf;
            $$buf = '';
            $eof->done if $at_eof && !$eof->is_ready;
            return 0;
        },
    );
    $loop->add($client);

    # Split across two writes: the server must buffer, not answer early.
    my $req = $KI->encode_request($ROBO_PRIV);
    $client->write(substr $req, 0, 20);
    $loop->loop_once(0.05);
    is $answer, '', 'no answer on a partial request';
    $client->write(substr $req, 20);

    $loop->await(Future->wait_any($eof, $loop->delay_future(after => 5)));
    ok $eof->is_done, 'the server closed the connection after answering';
    is $answer, "OK $ROBO_FP\n", 'and the answer was OK';
    is scalar @$keys, 1, 'the key reached on_key';

    $loop->remove($client) if $client->loop;
};

# ==========================================================================
# CLI side: send_key over port_forward
# ==========================================================================

# Stands in for Net::Async::Kubernetes. port_forward resolves to a session
# whose writes are fed to a REAL server (handle_request); the answer comes
# back as port-forward frames, with the 2-byte little-endian port header the
# kubelet puts first on every channel.
package FakeSession {
    sub new { my ($c, %a) = @_; bless { writes => [], closed => 0, %a }, $c }
    sub write_channel {
        my ($self, $ch, $payload) = @_;
        push @{ $self->{writes} }, [ $ch, $payload ];
        $self->{on_write}->($self, $ch, $payload) if $self->{on_write};
        return Future->done;
    }
    sub close { $_[0]{closed}++; Future->done }
}

package FakeKube {
    sub new  { my ($c, %a) = @_; bless { calls => [], %a }, $c }
    sub loop { $_[0]{loop} }
    sub port_forward {
        my ($self, $kind, $name, %args) = @_;
        push @{ $self->{calls} }, { kind => $kind, name => $name, %args };
        return Future->fail($self->{pf_fail}) if $self->{pf_fail};
        my $session = FakeSession->new(on_write => sub {
            my ($sess, $ch, $payload) = @_;
            $self->{respond}->($args{on_frame}, $args{on_close}, $payload) if $self->{respond};
        });
        $self->{session} = $session;
        return $self->loop->new_future->done($session);
    }
}

package main;

my $HDR = pack 'v', 9999;

sub fake_kube {
    my ($loop, $respond, %extra) = @_;
    return FakeKube->new(loop => $loop, respond => $respond, %extra);
}

# Answer via the real server, delivered as the kubelet would.
sub real_server_responder {
    my ($loop, $srv, %opt) = @_;
    return sub {
        my ($on_frame, undef, $payload) = @_;
        my $resp = $srv->handle_request($payload) // return;
        $loop->later(sub {
            if ($opt{glued}) {
                $on_frame->(0, $HDR . $resp);
            } else {
                $on_frame->(0, $HDR);
                $on_frame->(1, $HDR);
                $on_frame->(0, $resp);
            }
        });
    };
}

subtest 'send_key: the key crosses the port-forward and comes back acknowledged' => sub {
    my $loop = IO::Async::Loop->new;
    my ($srv, $keys) = server();
    my $kube = fake_kube($loop, real_server_responder($loop, $srv));

    my $fp = $KI->send_key(
        kube => $kube, pod => 'robocop-abc', namespace => 'ocp-system',
        key  => $ROBO_PRIV,
    )->get;

    is $fp, $ROBO_FP, 'resolves to the fingerprint robocop acknowledged';
    my $call = $kube->{calls}[0];
    is $call->{kind}, 'Pod',            'port-forward to a Pod';
    is $call->{name}, 'robocop-abc',    'the robocop pod';
    is $call->{namespace}, 'ocp-system', 'in ocp-system';
    is_deeply $call->{ports}, [9999],   'on the injection port';
    is $kube->{session}{writes}[0][0], 0, 'the request goes out on data channel 0';
    is scalar @$keys, 1, 'the server received the key';
    ok $kube->{session}{closed}, 'the session is closed afterwards';
};

subtest 'send_key: port header and answer in one frame' => sub {
    my $loop = IO::Async::Loop->new;
    my ($srv) = server();
    my $kube = fake_kube($loop, real_server_responder($loop, $srv, glued => 1));

    is $KI->send_key(kube => $kube, pod => 'p', namespace => 'ocp-system',
                     key => $ROBO_PRIV)->get,
        $ROBO_FP, 'the 2-byte header is stripped, not parsed as the answer';
};

subtest 'send_key: robocop refuses -> fails with its reason' => sub {
    my $loop = IO::Async::Loop->new;
    my ($srv) = server();
    my $kube = fake_kube($loop, real_server_responder($loop, $srv));

    my $f = $KI->send_key(kube => $kube, pod => 'p', namespace => 'ocp-system',
                          key => $OTHER_PRIV);
    $loop->await($f);
    ok $f->is_failed, 'failed';
    like scalar $f->failure, qr/does not match/, 'with robocop\'s reason';
    ok $kube->{session}{closed}, 'the session is closed on failure too';
};

subtest 'send_key: an error on the port-forward error channel fails' => sub {
    my $loop = IO::Async::Loop->new;
    my $kube = fake_kube($loop, sub {
        my ($on_frame) = @_;
        $loop->later(sub {
            $on_frame->(0, $HDR);
            $on_frame->(1, $HDR . 'dial tcp4 127.0.0.1:9999: connect: connection refused');
        });
    });

    my $f = $KI->send_key(kube => $kube, pod => 'p', namespace => 'ocp-system',
                          key => $ROBO_PRIV);
    $loop->await($f);
    ok $f->is_failed, 'failed';
    like scalar $f->failure, qr/connection refused/, 'names what the kubelet said';
};

subtest 'send_key: the connection closes before an answer' => sub {
    my $loop = IO::Async::Loop->new;
    my $kube = fake_kube($loop, sub {
        my (undef, $on_close) = @_;
        $loop->later(sub { $on_close->() });
    });

    my $f = $KI->send_key(kube => $kube, pod => 'p', namespace => 'ocp-system',
                          key => $ROBO_PRIV);
    $loop->await($f);
    ok $f->is_failed, 'failed';
    like scalar $f->failure, qr/closed/i, 'says the connection closed';
};

subtest 'send_key: no answer -> times out instead of hanging' => sub {
    my $loop = IO::Async::Loop->new;
    my $kube = fake_kube($loop, sub { });   # swallows the request

    my $f = $KI->send_key(kube => $kube, pod => 'p', namespace => 'ocp-system',
                          key => $ROBO_PRIV, timeout => 0.2);
    $loop->await($f);
    ok $f->is_failed, 'failed';
    like scalar $f->failure, qr/timed out/i, 'timed out';
    ok $kube->{session}{closed}, 'and closed the session';
};

subtest 'send_key: port_forward itself fails' => sub {
    my $loop = IO::Async::Loop->new;
    my $kube = fake_kube($loop, undef, pf_fail => "403 Forbidden\n");

    my $f = $KI->send_key(kube => $kube, pod => 'p', namespace => 'ocp-system',
                          key => $ROBO_PRIV);
    $loop->await($f);
    ok $f->is_failed, 'failed';
    like scalar $f->failure, qr/403/, 'with the API error';
};

done_testing;

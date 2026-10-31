#!/usr/bin/env perl
use strict;
use warnings;
use lib 'lib';
use Test::More;
use IO::Socket::INET;
use WWW::Hetzner::Cloud;
use WWW::Hetzner::HTTPResponse;

use OCP::Cmd::Init;
use OCP::Hetzner::Picker;

# k265: when `ocp init --hetzner` could not read the Hetzner catalogue it said
# "[!!] Could not read the Hetzner catalogue — keeping the defaults" and
# dropped the exception, so a bad token (401), a rate limit or a network
# failure all looked the same and none was named. The line now carries what
# WWW::Hetzner said -- the API's message, or the status when the body has
# none -- on one line, without a Perl source location and never with the
# token in it. The step itself still never fails an init.

my $TOKEN = 'tok-k265-do-not-print';

# An IO that answers every request with one canned response, below a real
# WWW::Hetzner::Cloud: the exception is the one WWW::Hetzner raises itself.
package CannedIO {
    use Moo;
    with 'WWW::Hetzner::Role::IO';
    has status  => (is => 'ro', required => 1);
    has content => (is => 'ro', default => '');
    sub call {
        my ($self) = @_;
        return WWW::Hetzner::HTTPResponse->new(
            status  => $self->status,
            content => $self->content,
        );
    }
}

# Run the picker step of `ocp init` on $cloud; return the command object, its
# STDOUT and STDERR, and whether the step returned instead of dying.
sub run_picker {
    my ($cloud) = @_;

    my $init = OCP::Cmd::Init->new(
        _picker      => OCP::Hetzner::Picker->new(token => $TOKEN, _cloud => $cloud),
        _interactive => 1,
    );

    my ($input, $out, $err) = ("\n\n", '', '');
    open my $in,     '<', \$input or die "stdin: $!";
    open my $out_fh, '>', \$out   or die "stdout: $!";
    open my $err_fh, '>', \$err   or die "stderr: $!";
    my $returned;
    {
        local *STDIN  = $in;
        local *STDOUT = $out_fh;
        local *STDERR = $err_fh;
        $returned = eval { $init->_prompt_hetzner_control_plane(undef); 1 };
    }

    return ($init, $out, $err, $returned);
}

sub nothing_asked_nothing_failed {
    my ($init, $out, $err, $returned) = @_;
    ok $returned, 'the step returns -- init does not fail over the catalogue';
    unlike $out, qr/Location:/, 'nothing is asked';
    is $init->_location,    undef, 'the default location stays';
    is $init->_server_type, undef, 'the default server type stays';
    is scalar(() = $err =~ /\n/g), 1, 'STDERR gets exactly one line';
    unlike $err, qr/ at \S+ line \d+/, 'no Perl source location in it';
    unlike $err, qr/\Q$TOKEN\E/, 'and never the token';
}

subtest 'a 401 names what the API answered' => sub {
    # The body Hetzner sends for a token it does not accept.
    my @r = run_picker(WWW::Hetzner::Cloud->new(token => $TOKEN, io => CannedIO->new(
        status  => 401,
        content => '{"error":{"code":"unauthorized","message":"unable to authenticate","details":{}}}',
    )));
    like $r[2], qr/\A\[!!\] Could not read the Hetzner catalogue: Hetzner API error: unable to authenticate — keeping the defaults\n\z/,
        'STDERR says the catalogue could not be read, and why';
    nothing_asked_nothing_failed(@r);

    # No API message in the body: WWW::Hetzner reports the status and the body
    # text. A body that echoes the credential must not carry it to STDERR.
    my @bare = run_picker(WWW::Hetzner::Cloud->new(token => $TOKEN, io => CannedIO->new(
        status  => 401,
        content => "Unauthorized\nBearer $TOKEN\n",
    )));
    like $bare[2], qr/\A\[!!\] Could not read the Hetzner catalogue: Hetzner API error: 401 Unauthorized Bearer \*{8} — keeping the defaults\n\z/,
        'without an API message the status is named, the token masked';
    nothing_asked_nothing_failed(@bare);
};

subtest 'a network error names the connection that failed' => sub {
    # A loopback port nothing listens on: the real LWP transport fails the way
    # it does for an unreachable api.hetzner.cloud, without leaving the host.
    my $sock = IO::Socket::INET->new(Listen => 1, LocalAddr => '127.0.0.1', LocalPort => 0)
        or die "cannot bind a loopback port: $!";
    my $port = $sock->sockport;
    close $sock;

    my @r = run_picker(WWW::Hetzner::Cloud->new(
        token    => $TOKEN,
        base_url => "http://127.0.0.1:$port/v1",
    ));
    like $r[2], qr/\A\[!!\] Could not read the Hetzner catalogue: Hetzner API error: Can't connect to 127\.0\.0\.1:$port\b[^\n]* — keeping the defaults\n\z/,
        'STDERR names the connection that could not be made';
    nothing_asked_nothing_failed(@r);
};

done_testing;

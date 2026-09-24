package OCP::Robocop::KeyInjection;
# ABSTRACT: Hand the robo key to a running robocop over a port-forward

use Moo;
use Carp qw( croak );
use Digest::SHA qw( sha256 );
use Future;
use IO::Async::Listener;
use MIME::Base64 qw( decode_base64 encode_base64 );
use Scalar::Util qw( weaken );

use OCP::TempKeyPair;

#
# robocop.security_level `inject` (k2): the private robo key is never put in a
# Secret and never written to the pod's disk. `ocp inject-key` opens a
# Kubernetes port-forward to the robocop pod and hands the key over this
# protocol; robocop checks it and keeps it in memory. A pod restart loses it,
# by design -- there is no checkpoint, and the admin injects again.
#
# Both ends live in this one module so the wire format has exactly one
# definition.
#
#   request   OCP-INJECT-KEY 1 <length>\n<length bytes of key material>
#   response  OK <fingerprint>\n   |   ERR <reason>\n
#
# after which robocop closes the connection. The fingerprint is the SHA256 form
# `ssh-keygen -l` prints, so the admin can compare it with `ocp keys show`.
#
# The listener binds 127.0.0.1 only: a port-forward enters the pod's network
# namespace and dials localhost, so that is the one way in. Nothing else in
# the cluster can reach the port, and whoever can port-forward into
# ocp-system still cannot plant a key of their own -- robocop only accepts the
# one whose public half it was deployed with.
#

use constant {
        MAGIC         => 'OCP-INJECT-KEY',
        VERSION       => 1,
        PORT          => 9999,
        MAX_HEADER    => 64,
        MAX_KEY_BYTES => 16384,
};

=attr expected_public_key

The robo key's public half (an F<authorized_keys> line) that robocop was
deployed with. When set, only a private key whose public half matches is
accepted. Only the key type and body are compared, not the comment.

=cut

has expected_public_key => ( is => 'ro' );

=attr on_key

Required on the robocop side. Called as C<< $on_key->($material, $fingerprint) >>
for an accepted key, before the C<OK> goes out. If it dies, the injector is
answered with C<ERR> and the message.

=cut

has on_key => ( is => 'ro' );

=attr on_reject

Optional. Called with the reason whenever a request is refused, so robocop can
log attempts that did not deliver a key.

=cut

has on_reject => ( is => 'ro' );

=attr host

Listen address, C<127.0.0.1>.

=attr port

Listen port, C<9999>.

=cut

has host => ( is => 'ro', default => '127.0.0.1' );
has port => ( is => 'ro', default => PORT );

#
# Keys
#

=method fingerprint

        my $fp = OCP::Robocop::KeyInjection->fingerprint($authorized_keys_line);

The C<SHA256:...> fingerprint of a public key, as C<ssh-keygen -l> prints it.
Returns C<undef> for something that is not a public key line.

=cut

sub fingerprint {
    my ( $class, $public ) = @_;
    return unless defined $public;
    my ( undef, $b64 ) = split ' ', $public;
    return unless defined $b64 && length $b64;
    my $blob = decode_base64($b64);
    return unless length $blob;
    ( my $digest = encode_base64( sha256($blob), '' ) ) =~ s/=+\z//;
    return 'SHA256:'.$digest;
}

=method validate_key

        my $fp = OCP::Robocop::KeyInjection->validate_key($material, $expected_public);

Dies (with a message that never quotes key material) unless C<$material> is an
unencrypted OpenSSH private key and, when C<$expected_public> is given, its
public half is that key. Returns the fingerprint.

=cut

sub validate_key {
    my ( $class, $material, $expected ) = @_;

    my $public = OCP::TempKeyPair::public_from_private($material)
        or die "not an OpenSSH private key\n";

    my $cipher = $class->_cipher_of($material) // '';
    die "the key is passphrase-protected (cipher ".$cipher."); robocop needs it unencrypted\n"
        unless $cipher eq 'none';

    my $fp = $class->fingerprint($public);

    if ( defined $expected && length $expected ) {
        my $want = $class->fingerprint($expected)
            // die "robocop's expected public key is not a public key line\n";
        die "the key does not match the robo public key robocop was deployed with"
            ." (expected ".$want.", got ".$fp.")\n"
            unless $fp eq $want;
    }

    return $fp;
}

# The cipher name of an openssh-key-v1 private key: the first string after the
# magic. public_from_private has already vouched for the envelope.
sub _cipher_of {
    my ( $class, $material ) = @_;
    my ($b64) = $material =~
        m{-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END OPENSSH PRIVATE KEY-----}s
        or return;
    my $blob = decode_base64($b64);
    my $pos  = length "openssh-key-v1\0";
    return if $pos + 4 > length $blob;
    my $len = unpack 'N', substr( $blob, $pos, 4 );
    return if $pos + 4 + $len > length $blob;
    return substr( $blob, $pos + 4, $len );
}

#
# Wire format
#

=method encode_request

        my $bytes = OCP::Robocop::KeyInjection->encode_request($material);

=cut

sub encode_request {
    my ( $class, $material ) = @_;
    croak __PACKAGE__.'->encode_request: key material required'
        unless defined $material && length $material;
    return MAGIC.' '.VERSION.' '.length($material)."\n".$material;
}

=method parse_request

        my %r = OCP::Robocop::KeyInjection->parse_request($buffer);

An empty list while more bytes are needed, C<< (key => $material) >> for a
complete request, C<< (error => $reason) >> for one that can never become
valid.

=cut

sub parse_request {
    my ( $class, $buf ) = @_;

    my $nl = index $buf, "\n";
    if ( $nl < 0 ) {
        return ( error => 'request header too long' ) if length $buf > MAX_HEADER;
        return;
    }

    my ( $magic, $version, $len ) = split ' ', substr( $buf, 0, $nl );
    return ( error => 'unknown protocol (expected '.MAGIC.')' )
        unless defined $magic && $magic eq MAGIC;
    return ( error => 'unsupported protocol version' )
        unless defined $version && $version eq VERSION;
    return ( error => 'malformed length' )
        unless defined $len && $len =~ /\A[0-9]{1,9}\z/ && $len > 0;
    return ( error => 'key too large ('.$len.' bytes, at most '.MAX_KEY_BYTES.')' )
        if $len > MAX_KEY_BYTES;

    return if length($buf) - $nl - 1 < $len;
    return ( key => substr( $buf, $nl + 1, $len ) );
}

=method parse_response

        my %r = OCP::Robocop::KeyInjection->parse_response($buffer);

An empty list while the line is incomplete, else C<< (ok => $fingerprint) >> or
C<< (error => $reason) >>.

=cut

sub parse_response {
    my ( $class, $buf ) = @_;
    my $nl = index $buf, "\n";
    return if $nl < 0;
    my $line = substr $buf, 0, $nl;
    return ( ok    => $1 ) if $line =~ /\AOK (\S+)\z/;
    return ( error => $1 ) if $line =~ /\AERR (.*)\z/;
    return ( error => 'unexpected answer from robocop' );
}

#
# robocop side
#

=method handle_request

        my $response = $server->handle_request($buffer);

The whole server decision for one connection's input: C<undef> while more
bytes are needed, else the response line. Calls L</on_key> for an accepted key
and L</on_reject> otherwise.

=cut

sub handle_request {
    my ( $self, $buf ) = @_;

    my %req = $self->parse_request($buf);
    return unless %req;

    my $error = $req{error};
    my $fp;
    unless ( defined $error ) {
        $fp = eval { $self->validate_key( $req{key}, $self->expected_public_key ) };
        $error = $@ unless defined $fp;
    }
    unless ( defined $error ) {
        eval { $self->on_key->( $req{key}, $fp ); 1 } or $error = $@ || 'key rejected';
    }

    if ( defined $error ) {
        chomp $error;
        $error =~ s/[\r\n]+/ /g;
        $self->on_reject->($error) if $self->on_reject;
        return 'ERR '.$error."\n";
    }
    return 'OK '.$fp."\n";
}

=method handle_stream

        $server->handle_stream($stream);

Configures an L<IO::Async::Stream> to read one request, answer it and close.
The caller adds the stream to a loop (the listener does that itself).

=cut

sub handle_stream {
    my ( $self, $stream ) = @_;
    weaken( my $wself = $self );
    my $answered = 0;
    $stream->configure(
        on_read => sub {
            my ( $s, $buffref, $eof ) = @_;
            return 0 if $answered;
            my $resp = $wself ? $wself->handle_request($$buffref) : "ERR robocop is shutting down\n";
            if ( !defined $resp && $eof ) {
                $resp = "ERR connection closed before the request was complete\n";
            }
            return 0 unless defined $resp;
            $$buffref = '';
            $answered = 1;
            $s->write($resp);
            $s->close_when_empty;
            return 0;
        },
    );
    return $stream;
}

=method start

        $server->start($loop)->get;

Adds a listener on L</host>:L</port> to C<$loop>. Returns the listen
L<Future>; the listener is held on the object.

=cut

sub start {
    my ( $self, $loop ) = @_;
    croak __PACKAGE__.'->start: on_key required' unless $self->on_key;

    weaken( my $wself = $self );
    my $listener = IO::Async::Listener->new(
        on_stream => sub {
            my ( $l, $stream ) = @_;
            return unless $wself;
            $wself->handle_stream($stream);
            $l->add_child($stream);
        },
    );
    $loop->add($listener);
    $self->{_listener} = $listener;

    return $listener->listen(
        addr => {
            family   => 'inet',
            socktype => 'stream',
            ip       => $self->host,
            port     => $self->port,
        },
    );
}

#
# CLI side
#

=method send_key

        my $fp = OCP::Robocop::KeyInjection->send_key(
            kube      => $net_async_kubernetes,
            pod       => 'robocop-7c9d...',
            namespace => 'ocp-system',
            key       => $private_material,
            timeout   => 30,            # seconds, default 30
        )->get;

Opens a port-forward to the pod's injection port, sends the key and resolves
to the fingerprint robocop acknowledged. Fails with robocop's reason on
C<ERR>, with the kubelet's message when the port-forward error channel
reports one, and on timeout or an early close. The session is closed in every
case.

=cut

sub send_key {
    my ( $class, %a ) = @_;
    my $kube    = $a{kube} or croak __PACKAGE__.'->send_key: kube required';
    my $pod     = $a{pod}  or croak __PACKAGE__.'->send_key: pod required';
    my $key     = $a{key}  or croak __PACKAGE__.'->send_key: key required';
    my $port    = $a{port}    // PORT;
    my $timeout = $a{timeout} // 30;

    my $loop = $kube->loop;
    my $answer = $loop->new_future;
    my $fail = sub { $answer->fail( $_[0] ) unless $answer->is_ready };

    # Every port-forward channel opens with the port number, two bytes little
    # endian, written by the kubelet before any data. It can arrive as a frame
    # of its own or glued to the first data, so it is stripped by count.
    my %header_left = ( 0 => 2, 1 => 2 );
    my ( $data, $err ) = ( '', '' );

    my $on_frame = sub {
        my ( $ch, $payload ) = @_;
        return unless defined $payload;
        if ( my $skip = $header_left{$ch} ) {
            my $n = $skip < length $payload ? $skip : length $payload;
            substr( $payload, 0, $n, '' );
            $header_left{$ch} -= $n;
        }
        return unless length $payload;
        if ( $ch == 0 ) {
            $data .= $payload;
            my %r = $class->parse_response($data);
            return unless %r;
            return $answer->done( $r{ok} ) if defined $r{ok};
            return $fail->( 'robocop refused the key: '.$r{error}."\n" );
        }
        if ( $ch == 1 ) {
            $err .= $payload;
            return $fail->( 'port-forward to '.$pod.':'.$port.' failed: '.$err."\n" );
        }
    };

    my $session;
    my $f = $kube->port_forward( 'Pod', $pod,
        namespace => $a{namespace},
        ports     => [$port],
        on_frame  => $on_frame,
        on_close  => sub { $fail->( 'the port-forward closed before robocop answered'."\n" ) },
        on_error  => sub { $fail->( 'port-forward error: '.( $_[0] // 'unknown' )."\n" ) },
    )->then( sub {
        ($session) = @_;
        $session->write_channel( 0, $class->encode_request($key) );
        return Future->wait_any(
            $answer,
            $loop->delay_future( after => $timeout )
                ->then_fail( 'timed out after '.$timeout.'s waiting for robocop to answer'."\n" ),
        );
    } );

    return $f->followed_by( sub {
        my ($done) = @_;
        eval { $session->close } if $session;
        return $done;
    } );
}

1;

=head1 SYNOPSIS

        # robocop (security_level inject)
        my $server = OCP::Robocop::KeyInjection->new(
            expected_public_key => $ENV{ROBO_SSH_PUBLIC_KEY},
            on_key              => sub { my ( $material, $fp ) = @_; ... },
        );
        $server->start($loop)->get;

        # ocp inject-key
        my $fp = OCP::Robocop::KeyInjection->send_key(
            kube => $kube, pod => $pod, namespace => 'ocp-system', key => $private,
        )->get;

=head1 DESCRIPTION

The in-memory key delivery behind C<robocop.security_level: inject>. See the
comment at the top of the source for the wire format and why the listener is
bound to loopback.

=head1 SEE ALSO

L<OCP::Robocop::Controller>, L<OCP::Cmd::InjectKey>, L<OCP::TempKeyPair>

=cut

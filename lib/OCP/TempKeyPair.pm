package OCP::TempKeyPair;
# ABSTRACT: A private key in a temp file, with the .pub sibling Rex insists on

use strict;
use warnings;

use File::Temp ();
use MIME::Base64 qw(decode_base64 encode_base64);

# Not imported: this class has its own ->path accessor, and importing
# Path::Tiny's function of that name into the package would clobber it.
use Path::Tiny ();

#
# One job: hand a private key to something that reads keys from disk, and get
# both files removed again afterwards.
#
# It exists because OCP::Rex derives the public half's location from the
# private one and never checks it:
#
#     $ENV{REX_PUBLIC_KEY} = $self->key_file . '.pub';
#
# So every caller that writes a private key to a temp file owes a .pub beside
# it. Three places open-coded that dance and two of them got it wrong --
# OCP::Cmd::Apply::Bootstrap and OCP::Cmd::SSH leaked the public half (karr
# #87), OCP::Node never wrote one at all (karr #93). This is the fourth
# attempt and the last one, because now there is only one.
#
# THE OWNERSHIP RULE, which is the subtle part and the reason this is a class
# and not two lines in a helper sub:
#
#   * The private file belongs to File::Temp. UNLINK => 1 means dropping the
#     object removes the file, and File::Temp keeps its own end-of-process
#     net besides. Unlinking it by hand instead warns loudly ("unlink0: ...
#     is gone already"), so cleanup drops the reference rather than reaching
#     past it.
#   * The .pub has no other owner. Plain unlink, ours to do.
#
# DESTROY runs cleanup, including while Perl unwinds out of a die -- which is
# the case that matters, since the alternative is a readable private key left
# behind in /tmp after a failed run.
#

=synopsis

    use OCP::TempKeyPair;

    # The public half handed in, when the caller has it:
    my $pair = OCP::TempKeyPair->for_private_key($private,
        public => $public);

    # Or left out, when it does not -- see /public_from_private:
    my $pair = OCP::TempKeyPair->for_private_key($material);

    OCP::Rex->new(host => $ip, key_file => $pair->path)->run_task(...);

    # Both files go away when $pair does; cleanup is also explicit.
    undef $pair;

=description

A private SSH key written to a temporary file, plus the C<.pub> sibling that
L<OCP::Rex> points C<REX_PUBLIC_KEY> at, owned as one unit and removed as one
unit.

Callers that already know the public half pass it. Callers that hold nothing
but private key material -- L<OCP::Node>, which is handed a key string and
never a key store -- get it derived from the private key itself.

=cut

#
# Constructor
#

=method for_private_key

    my $pair = OCP::TempKeyPair->for_private_key($material);
    my $pair = OCP::TempKeyPair->for_private_key($material, public => $pub);

Writes C<$material> to a fresh temp file (mode 0600) and its public half to
C<< $pair->path . '.pub' >> (mode 0644), and returns the object that owns
both.

C<public> supplies the public half for callers that have it. Without it the
public half is derived from C<$material> (see L</public_from_private>); when
that is not possible the C<.pub> is written empty rather than skipped, because
the invariant Rex depends on is that the B<path> resolves -- the same
concession L<OCP::ClusterKey> made for a stored key with no public half
recorded.

Empty or undefined C<$material> is not an error here. It is a broken caller,
but this class is not the place that finds out: refusing would turn a node
that fails at the SSH connection with a diagnosable message into one that
dies while building a lazy attribute.

=cut

sub for_private_key {
    my ($class, $private, %opt) = @_;

    my $material = defined $private ? $private : '';

    my $temp = File::Temp->new(SUFFIX => '.key', UNLINK => 1);
    print {$temp} $material;
    close $temp;
    chmod 0600, $temp->filename;

    my $public = (defined $opt{public} && length $opt{public})
        ? $opt{public}
        : public_from_private($private);

    my $pub_path = $temp->filename . '.pub';
    Path::Tiny::path($pub_path)->spew(defined $public ? $public : '');
    chmod 0644, $pub_path;

    return bless {
        path        => $temp->filename,
        public_path => $pub_path,
        temp        => $temp,
    }, $class;
}

=method public_from_private

    my $pub = OCP::TempKeyPair::public_from_private($material);

The public half of an OpenSSH-format private key, as the type and base64 body
of an F<authorized_keys> line (C<"ssh-ed25519 AAAA...\n">, without the
comment), or C<undef> when C<$material> is not a key this can read.

No key exchange and no maths: an C<openssh-key-v1> private key file B<carries
its own public half in cleartext>, ahead of the section a passphrase would
encrypt. Reading it out is a base64 decode and a walk past three header
strings and a count, so this works for a PIN2-protected key as well as a bare
one, and for every key type -- the blob is re-emitted, not interpreted.

Why not C<ssh-keygen -y>, which is the usual answer: L<OCP::Node> is
trigger-neutral, so whatever it needs, robocop needs inside its container.
Shelling out would make F<openssh-client> a runtime dependency of the
controller, declared nowhere, and would fork once per worker install. This
needs L<MIME::Base64> and nothing else.

Returns C<undef> rather than dying on anything it cannot parse -- a PEM
C<BEGIN RSA PRIVATE KEY>, a truncated file, a test fixture that only looks
like a key. The caller writes an empty C<.pub> and carries on; the private
key is what authenticates.

=cut

sub public_from_private {
    my ($material) = @_;

    return undef unless defined $material;

    my ($b64) = $material =~
        m{-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END OPENSSH PRIVATE KEY-----}s
        or return undef;

    my $blob = decode_base64($b64);
    return undef unless index($blob, "openssh-key-v1\0") == 0;

    my $pos  = length "openssh-key-v1\0";
    my $take = sub {
        return undef if $pos + 4 > length $blob;
        my $len = unpack 'N', substr($blob, $pos, 4);
        $pos += 4;
        return undef if $len > length($blob) - $pos;
        my $str = substr($blob, $pos, $len);
        $pos += $len;
        return $str;
    };

    # ciphername, kdfname, kdfoptions -- skipped, they describe the ENCRYPTED
    # section further down and say nothing about the public key.
    for (1 .. 3) {
        defined $take->() or return undef;
    }

    return undef if $pos + 4 > length $blob;
    my $keys = unpack 'N', substr($blob, $pos, 4);
    $pos += 4;
    return undef unless $keys >= 1;

    my $pub = $take->();
    return undef unless defined $pub && length $pub > 4;

    # The wire-format blob leads with its own key type, which is also the
    # first word of the authorized_keys line.
    my $type_len = unpack 'N', substr($pub, 0, 4);
    return undef unless $type_len && 4 + $type_len <= length $pub;
    my $type = substr($pub, 4, $type_len);
    return undef unless $type =~ /\A[A-Za-z0-9._\@-]+\z/;

    # Two fields, no comment. The comment lives in the section a passphrase
    # encrypts -- unreadable for an encrypted key, and nothing authenticates
    # on it either way, so it is dropped rather than conditionally present.
    return "$type " . encode_base64($pub, '') . "\n";
}

#
# Accessors
#

=method path

    my $file = $pair->path;

Path to the private key file, ready to hand to C<< OCP::Rex->new(key_file =>
...) >> or C<< OCP::SSH->new(key_file => ...) >>.

=cut

sub path { $_[0]{path} }

=method public_path

    my $pub = $pair->public_path;

Path to the public half. Always C<< $pair->path . '.pub' >>, which is where
L<OCP::Rex> looks whether or not anything put a file there.

=cut

sub public_path { $_[0]{public_path} }

=method cleanup

    $pair->cleanup;

Removes both files. Idempotent, and called for you from C<DESTROY> --
including while Perl unwinds the stack out of a C<die>.

=cut

sub cleanup {
    my ($self) = @_;

    return unless $self->{temp};

    # The public half first: it has no other owner, plain unlink.
    my $pub = delete $self->{public_path};
    unlink $pub if defined $pub && -e $pub;

    # The private half belongs to the File::Temp object. Dropping the last
    # reference to it is what removes the file; unlinking behind its back
    # would warn on the way out.
    delete $self->{temp};

    $self->{path} = undef;

    return;
}

sub DESTROY {
    my ($self) = @_;
    local ($@, $!, $?);
    eval { $self->cleanup; 1 };
    return;
}

1;

__END__

=seealso

L<OCP::ClusterKey> (which key, and where it comes from), L<OCP::Node>,
L<OCP::Rex>, F<docs/adr/0006-two-tier-ssh-keys.md>.

=cut

package OCP::ClusterKey;
# ABSTRACT: The private SSH key a cluster's machines actually trust

use strict;
use warnings;

use Carp qw(croak);
use File::Temp ();

# Not imported: this class has its own ->path accessor, and importing
# Path::Tiny's function of that name into the package would clobber it.
use Path::Tiny ();

use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

# Whether there is a human who could answer a PIN2 prompt. undef asks the
# terminal, which is the right answer in production; a test that wants to
# drive the prompt path localises this to 1, because under `prove` STDIN is a
# pipe and the honest answer would otherwise be "nobody is there".
our $INTERACTIVE;

#
# Who created the machine decides which key it trusts. That one sentence is
# the whole module, and it is the sentence four call sites got wrong.
#
#   * An ssh-provider machine is pre-existing. The only key on it is the one
#     the operator put into authorized_keys by hand, which is the bootstrap
#     key in .ocp/id_ed25519. Mode does not enter into it — a secure-mode
#     project reaches for the same file, which is why `ocp init` creates it
#     for provider ssh in both modes (karr #85).
#
#   * A Hetzner machine is created by OCP, which uploads the admin public key
#     through the API *before* the server exists. The bootstrap key was never
#     distributed there and `ocp init` does not even create one. Reaching for
#     it is reaching for a file that does not exist, and when it does exist
#     (a leftover, a hand-made key) it is worse: the connection then fails as
#     an SSH auth timeout instead of as "wrong key".
#
#   * --nopassword dev mode has no keys.yaml and therefore no admin key at
#     all. .ocp/id_ed25519 stands in for it on every provider, and
#     OCP::Cmd::Apply uploads its public half exactly where the admin key
#     would have gone.
#
# The admin key lives behind PIN2 (ADR 0006), so the Hetzner branch needs a
# human at a prompt and a temp file for Rex/ssh to read. Getting that temp
# file removed again is the other half of this module's job: it holds a
# private key in /tmp, and both places that open-coded this dance before
# (OCP::Cmd::Apply::Bootstrap, OCP::Cmd::SSH) leaked at least the public half
# and, in setup_ssh_key's case with UNLINK => 0, the private half too.
#
# Why here and not in OCP::Keys: OCP::Keys is the key *store* — it answers
# "decrypt the key called X". This is *selection* policy — "which key does
# this cluster's hardware trust, and how do I hand it to Rex". Those are
# different questions, and only the second one knows about ocp.yaml, the
# provider and the temp file.
#

=synopsis

    use OCP::ClusterKey;

    # In a command, through the caching accessor on OCP::Role::Cmd so that a
    # loop over three components prompts for PIN2 once, not three times:
    my $key = $self->cluster_ssh_key($config);

    OCP::Rex->new(host => $ip, key_file => $key->path)->run_task(...);
    my $material = $key->content;    # for OCP::Node's ssh_key attribute

    # Directly, when there is no command object to hang it on:
    my $key = OCP::ClusterKey->for_config($config);

    # Temp files go away when $key does; cleanup is also explicit.
    undef $key;

=description

Answers one question: which private SSH key file should this process use to
reach the machines of the cluster described by C<$config>?

Three answers, in the order they are decided:

=over 4

=item *

B<Dev mode> (no F<keys.yaml>) — the bootstrap key F<.ocp/id_ed25519>, on
every provider. Nothing is prompted, nothing is written.

=item *

B<Provider C<ssh>> — the bootstrap key, in both modes. A pre-existing
machine trusts what the operator authorised on it by hand.

=item *

B<Secure mode, any other provider> — the admin key from F<keys.yaml>. That
costs a PIN2 prompt (ADR 0006) and a pair of temp files, because Rex reads
its key from disk and expects C<key_file.pub> beside it.

=back

The returned object owns whatever it wrote. When it goes out of scope — a
normal return or a C<die> unwinding the stack — both temp files are unlinked.

=cut

#
# Constructor
#

=method for_config

    my $key = OCP::ClusterKey->for_config($config);
    my $key = OCP::ClusterKey->for_config($config,
        provider => 'ssh',
        reason   => 'ocp update',
    );

Returns an OCP::ClusterKey for the cluster described by C<$config>, or dies
with a message naming what was missing.

C<provider> overrides the provider read from C<control_planes[0]> — pass it
when the machine being reached is not the control plane, as C<ocp destroy>
does for an ssh worker in an otherwise Hetzner cluster. C<reason> is printed
above the PIN2 prompt so the operator knows which command asked.

C<admin_key> takes an already-decrypted key hash (C<< { private =>, public
=>, name => } >>) and skips both the age unlock and the PIN2 prompt. The
deploy path needs this: C<ocp apply> prompts for PIN2 once at the top
because it also has to upload the public half to the provider, and asking a
second time for the same key would be a bug, not extra safety.

C<interactive> overrides the C<< -t STDIN >> check that guards the prompt (as
does C<$OCP::ClusterKey::INTERACTIVE> for a whole dynamic scope). Without a
terminal, this dies instead of prompting — a piped or scheduled run must fail
with a message, not block on a password nobody can see. C<pin2> supplies the
passphrase directly and skips both the check and the prompt.

=cut

=method cache_slot

    my $slot = OCP::ClusterKey::cache_slot($config, %opt);

The identity a caller should memoize a key under: the project it belongs to
plus any provider override. Callers cache because building a key can prompt
for PIN2 and C<ocp update> walks a list of components — but caching on the
command object alone is wrong, because the same object can be handed two
different configs and would then hand back a key for the wrong project.

=cut

sub cache_slot {
    my ($config, %opt) = @_;
    return join "\0", $config->project_dir . '', ($opt{provider} // '');
}

sub for_config {
    my ($class, $config, %opt) = @_;

    croak "for_config: config required" unless $config;

    my $provider = $opt{provider}
        // ($config->control_planes->[0] // {})->{provider}
        // 'hetzner';

    # Same detection as OCP::Cmd::Apply and OCP::Cmd::Apply::Bootstrap: dev
    # mode is the absence of keys.yaml, not a flag anyone passes around.
    my $dev_mode = !-f $config->project_dir->child('keys.yaml');

    return $class->_bootstrap_key($config, $provider, $dev_mode)
        if $dev_mode || $provider eq 'ssh';

    return $class->_admin_key($config, $provider, %opt);
}

# The unencrypted key on disk. Nothing to write, nothing to clean up.
sub _bootstrap_key {
    my ($class, $config, $provider, $dev_mode) = @_;

    my $path = $config->ssh_private_key_path;

    unless (-f $path) {
        my $why = $dev_mode
            ? "dev mode (--nopassword) uses it on every provider"
            : "provider '$provider' machines trust only this key";
        die "ERROR: SSH key '$path' not found — $why.\n"
          . "       Run 'ocp init' to create it.\n";
    }

    return bless {
        path        => "$path",
        public_path => $config->ssh_public_key_path . '',
        origin      => 'bootstrap',
        provider    => $provider,
        temp        => undef,
    }, $class;
}

# The PIN2-protected key from keys.yaml, dropped into a temp file pair.
sub _admin_key {
    my ($class, $config, $provider, %opt) = @_;

    my $admin_key = $opt{admin_key} || _unlock_admin_key($config, $provider, %opt);

    # One owner per file. File::Temp owns the private half — UNLINK => 1
    # means dropping the object removes the file, and File::Temp also has its
    # own end-of-process net. Unlinking it by hand instead warns loudly
    # ("unlink0: ... is gone already"), so cleanup below drops the reference
    # rather than reaching past it. The .pub has no such owner and is ours.
    my $temp = File::Temp->new(SUFFIX => '.key', UNLINK => 1);
    print {$temp} $admin_key->{private};
    close $temp;
    chmod 0600, $temp->filename;

    # OCP::Rex sets REX_PUBLIC_KEY to key_file . '.pub' unconditionally, so
    # the public half has to sit next to the private one or every Rex task
    # over this key points at a path that does not exist.
    my $pub_path = $temp->filename . '.pub';
    Path::Tiny::path($pub_path)->spew($admin_key->{public} // '');
    chmod 0644, $pub_path;

    return bless {
        path        => $temp->filename,
        public_path => $pub_path,
        origin      => 'admin',
        provider    => $provider,
        name        => $admin_key->{name},
        temp        => $temp,
    }, $class;
}

# The interactive half, kept separate so the deploy path can hand in a key it
# already unlocked instead of prompting the operator twice for the same PIN2.
sub _unlock_admin_key {
    my ($config, $provider, %opt) = @_;

    my $reason = $opt{reason};

    # Refuse before asking when there is nobody to ask. OCP::Password reads
    # STDIN with echo off; with STDIN on a pipe or closed, that either blocks
    # forever or reads undef and looks like a wrong PIN2. A cron'd or piped
    # `ocp apply` hanging on an invisible password prompt is worse than a
    # named failure, and the callers that can carry on without the key
    # (OCP::Cmd::Apply::Drift's remedy) turn this back into a skip they can
    # report. Overridable so tests can drive the prompt path deliberately.
    my $interactive = exists $opt{interactive} ? $opt{interactive}
                    : defined $INTERACTIVE     ? $INTERACTIVE
                    :                            -t STDIN;
    unless ($interactive || defined $opt{pin2}) {
        die "ERROR: This cluster's machines trust the admin key (provider "
          . "'$provider',\n"
          . "       secure mode), which is behind PIN2 — and there is no "
          . "terminal to ask on.\n"
          . "       Re-run "
          . ($reason ? "$reason" : "this") . " from an interactive shell.\n";
    }

    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    $secrets->ensure_age_key();

    # Say what is being asked for before asking. A bare "Enter PIN2" in the
    # middle of `ocp update` reads as a bug in a command that never used to
    # want one; this names the reason the key model gives for it.
    print "  This cluster's machines were created by OCP and trust the admin\n";
    print "  key, not .ocp/id_ed25519 (provider '$provider', secure mode).\n";
    print "  " . ($reason ? "$reason needs" : "This step needs")
        . " it to reach them.\n";

    my $pin2 = $opt{pin2}
        // OCP::Password::prompt_password("Enter PIN2 (admin-key for SSH): ");
    die "ERROR: No PIN2 given, cannot decrypt the admin key.\n"
        unless defined $pin2 && length $pin2;

    my $keys = OCP::Keys->new(project_dir => $config->project_dir);
    my $admin_key = $keys->get_admin_key($pin2);
    die "ERROR: Wrong PIN2 or no admin-key found!\n" unless $admin_key;

    return $admin_key;
}

#
# Accessors
#

=method path

    my $file = $key->path;

Path to the private key file, ready to hand to C<< OCP::Rex->new(key_file =>
...) >> or C<< OCP::SSH->new(key_file => ...) >>.

=cut

sub path { $_[0]{path} }

=method public_path

    my $pub = $key->public_path;

Path to the public half. Always C<< $key->path . '.pub' >> for a temporary
admin key; F<.ocp/id_ed25519.pub> for the bootstrap key.

=cut

sub public_path { $_[0]{public_path} }

=method content

    my $material = $key->content;

The private key material itself, for the callers that pass a key by value
rather than by path — C<< OCP::Node->from_cr(ssh_key => ...) >> writes its
own temp file from this.

=cut

sub content { Path::Tiny::path($_[0]{path})->slurp }

=method origin

    if ($key->origin eq 'admin') { ... }

C<'bootstrap'> for F<.ocp/id_ed25519>, C<'admin'> for the PIN2-protected key
out of F<keys.yaml>. Tests assert on this: "secure + hetzner reached the
admin key" is the claim, and a path comparison alone cannot make it.

=cut

sub origin { $_[0]{origin} }

=method is_temporary

    $key->is_temporary or warn "this file is in the project, do not delete it";

True when this object wrote the file it points at and will remove it again.

=cut

sub is_temporary { defined $_[0]{temp} ? 1 : 0 }

=method describe

    print $key->describe, "\n";   # "admin key 'admin-ssh' (provider hetzner)"

One line naming which key was chosen, for the commands that report what they
are about to do.

=cut

sub describe {
    my ($self) = @_;
    return $self->{origin} eq 'admin'
        ? "admin key" . ($self->{name} ? " '$self->{name}'" : '')
            . " (provider $self->{provider}, PIN2)"
        : "bootstrap key .ocp/id_ed25519 (provider $self->{provider})";
}

=method cleanup

    $key->cleanup;

Removes the temp files, if any, and makes the object inert. Idempotent, and
called for you from C<DESTROY> — including while Perl unwinds the stack out
of a C<die>, which is the case that matters: the alternative is a readable
private key left in F</tmp> after a failed run.

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

L<OCP::Keys> (the key store), L<OCP::Secrets>, L<OCP::Role::Cmd/cluster_ssh_key>,
L<OCP::Cmd::Apply::Bootstrap>, F<docs/adr/0006-two-tier-ssh-keys.md>.

=cut

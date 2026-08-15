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
# The MODE decides which key a machine trusts, not who created the machine.
# That is the whole module, and it is a deliberate reversal of what this file
# used to say.
#
# Secure mode has two keys and only two (ADR 0006):
#
#   robo   purpose: automation, age only, no PIN2 — unattended automation
#   admin  purpose: admin, age + PIN2            — everything a human does
#
# So in secure mode the answer is always the admin key, on every provider.
# The providers differ only in who does the distributing: on Hetzner OCP
# uploads the admin public key through the API before the server exists; on
# the ssh provider a human pastes the same public key into authorized_keys,
# which is what `ocp keys show --purpose admin` prints. Same key either way,
# so the same key opens the machine either way.
#
# The bootstrap key .ocp/id_ed25519 survives in exactly one place:
# --nopassword dev mode, which has no keys.yaml and therefore no admin key at
# all. There it stands in on every provider, and OCP::Cmd::Apply uploads its
# public half exactly where the admin key would have gone.
#
# What this cost: an ssh-provider cluster built before this change carries the
# BOOTSTRAP public key in authorized_keys, not the admin one, and nothing here
# falls back to it — a silent fallback would reinstate the third tier through
# the back door. migration_hint below turns that into a diagnosis instead.
#
# The admin key lives behind PIN2, so the secure branch needs a human at a
# prompt and a temp file for Rex/ssh to read. Getting that temp file removed
# again is the other half of this module's job: it holds a private key in
# /tmp, and both places that open-coded this dance before
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

Two answers, decided by the mode alone:

=over 4

=item *

B<Secure mode> (F<keys.yaml> exists) — the admin key from F<keys.yaml>, on
B<every> provider. That costs a PIN2 prompt (ADR 0006) and a pair of temp
files, because Rex reads its key from disk and expects C<key_file.pub> beside
it. The provider decides only who put that public key on the machine: the
Hetzner API before the server existed, or a human with C<ocp keys show
--purpose admin>.

=item *

B<Dev mode> (no F<keys.yaml>) — the bootstrap key F<.ocp/id_ed25519>, on
every provider. Nothing is prompted, nothing is written. This is the only
place the bootstrap key still lives.

=back

There is deliberately no fallback from the admin key to the bootstrap key.
C<provider: ssh> machines built before the two-tier decision trust the
bootstrap key; see C</migration_hint> for how that is reported.

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
does for an ssh worker in an otherwise Hetzner cluster. Since the mode alone
picks the key, this now only changes which provider the messages name; it no
longer changes the answer. C<reason> is printed above the PIN2 prompt so the
operator knows which command asked.

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
    # mode is the absence of keys.yaml, not a flag anyone passes around. It is
    # now the ONLY thing this decision turns on; $provider survives purely as
    # something to name in messages.
    my $dev_mode = !-f $config->project_dir->child('keys.yaml');

    return $class->_bootstrap_key($config, $provider) if $dev_mode;

    return $class->_admin_key($config, $provider, %opt);
}

# The unencrypted key on disk. Nothing to write, nothing to clean up.
sub _bootstrap_key {
    my ($class, $config, $provider) = @_;

    my $path = $config->ssh_private_key_path;

    unless (-f $path) {
        die "ERROR: SSH key '$path' not found — dev mode (--nopassword) uses "
          . "it on every provider.\n"
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
        # Kept for migration_hint alone: a bootstrap key still on disk in a
        # secure-mode project is the signature of a cluster authorised before
        # the two-tier decision.
        bootstrap_path => $config->ssh_private_key_path . '',
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
        die "ERROR: This cluster's machines trust the admin key (secure mode, "
          . "provider '$provider'),\n"
          . "       which is behind PIN2 — and there is no terminal to ask "
          . "on.\n"
          . "       Re-run "
          . ($reason ? "$reason" : "this") . " from an interactive shell.\n";
    }

    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    $secrets->ensure_age_key();

    # Say what is being asked for before asking. A bare "Enter PIN2" in the
    # middle of `ocp update` reads as a bug in a command that never used to
    # want one; this names the reason the key model gives for it.
    print "  In secure mode every machine of this cluster is reached with the\n";
    print "  admin key — they trust the admin public key and nothing else\n";
    print "  (provider '$provider').\n";
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

=method migration_hint

    if (my $hint = $key->migration_hint) {
        die "  [FAIL] SSH not ready: $err\n" . $hint;
    }

The explanation for one specific failure, and the empty string for every other
situation: an SSH connection made with the B<admin> key was refused, while
F<.ocp/id_ed25519> is still sitting in the project.

That combination is almost always a cluster whose C<authorized_keys> were
written before the bootstrap key left secure mode. Its machines carry the
bootstrap public key; this OCP no longer offers it. The text names the two
steps out — C<ocp keys show --purpose admin>, then append to
F</root/.ssh/authorized_keys> on each machine.

There is no automatic fallback to the bootstrap key behind this, on purpose: a
fallback would quietly restore the third key tier that was removed. Callers
append this to their own error message; a caller that cannot fail (C<ocp ssh>
hands the terminal to C<ssh> itself) prints it as a warning.

=cut

sub migration_hint {
    my ($self) = @_;

    return '' unless ($self->{origin} // '') eq 'admin';

    my $bootstrap = $self->{bootstrap_path};
    return '' unless defined $bootstrap && -f $bootstrap;

    return <<"HINT";

  This project still has $bootstrap, and in secure mode nothing uses it
  any more — every machine is reached with the admin key.

  If this cluster was set up before that change, its machines have the
  BOOTSTRAP public key in authorized_keys and have never seen the admin one.
  That is exactly what a refused admin-key login looks like — and nothing
  could have told you sooner: no step verifies in advance which key a machine
  will accept, so this is found out at the connection, not before it.

  To fix it, on each machine of this cluster:

      ocp keys show --purpose admin        # prints the public key
      # then, as root on the machine:
      echo '<that key>' >> /root/.ssh/authorized_keys

  Nothing here falls back to the bootstrap key: the two-tier decision means
  robo (automation) and admin (human), and a third key that silently still
  works would undo it.
HINT
}

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

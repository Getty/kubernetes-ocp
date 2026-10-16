package OCP::ClusterKey;
# ABSTRACT: The private SSH key the CLI reaches a cluster's machines with

use strict;
use warnings;

use Carp qw(croak);

# Not imported: this class has its own ->path accessor, and importing
# Path::Tiny's function of that name into the package would clobber it.
use Path::Tiny ();

use OCP::Keys;
use OCP::Password;
use OCP::Secrets;
use OCP::TempKeyPair;

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
# This module is the CLI's choice, and in secure mode the CLI's answer is
# always the admin key, on every provider. It is not the whole of what a
# machine has to trust: robocop never comes through here -- it holds the robo
# key and joins and tears down workers with it (OCP::Robocop::Controller). So
# a control plane needs the admin public key, and a worker needs the admin
# AND the robo public key, since whether the CLI or robocop drives it decides
# which of the two arrives (k209).
#
# The providers differ only in who does the distributing: on Hetzner OCP
# uploads both public keys through the API before the server exists (the robo
# one since k101); on the ssh provider a human puts them into authorized_keys,
# which is what `ocp keys authorized-keys` prints (`--purpose admin` for a
# control plane). Same keys either way, so the same keys open the machine.
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
# again is not this module's job any more: it belongs to OCP::TempKeyPair,
# which is where the ownership rules live now. Three places open-coded that
# dance before — OCP::Cmd::Apply::Bootstrap and OCP::Cmd::SSH leaked at least
# the public half (and, in setup_ssh_key's case with UNLINK => 0, the private
# half too), OCP::Node never wrote the public half at all (k93).
#
# A third answer since k216, and not a third tier: the OPERATOR key. A
# Leitstand runs `ocp apply` unattended with its own age identity
# (SOPS_AGE_KEY_FILE) and its own SSH key, registered with
# `ocp keys operator add` -- a keys.yaml entry of purpose 'operator' that
# holds the public half and the Leitstand's age recipient, never a private
# half. When this run's identity is such a recipient, the operator key is the
# one the CLI reaches machines with: read from OCP_OPERATOR_KEY, checked
# against the entry, no PIN2. The admin key stays the human's, behind PIN2;
# the operator could not open it anyway (its inner age layer is the project
# key's alone).
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

Answers one question: which private SSH key file should B<the CLI> use to
reach the machines of the cluster described by C<$config>? robocop does not
ask it: it holds the robo key (C<purpose: automation>) and joins and tears
down workers with that. So the key chosen here is one of the keys a machine
must trust, not the only one — in secure mode a worker on the C<ssh> provider
needs the admin B<and> the robo public key (k209); C<ocp keys authorized-keys>
prints both.

Three answers, decided by the mode -- and, in secure mode, by whose age
identity the run decrypts with:

=over 4

=item *

B<Secure mode> (F<keys.yaml> exists) — the admin key from F<keys.yaml>, on
B<every> provider. That costs a PIN2 prompt (ADR 0006) and a pair of temp
files, because Rex reads its key from disk and expects C<key_file.pub> beside
it. The provider decides only who put that public key on the machine: the
Hetzner API before the server existed, or a human with C<ocp keys
authorized-keys --purpose admin>.

=item *

B<Dev mode> (no F<keys.yaml>) — the bootstrap key F<.ocp/id_ed25519>, on
every provider. Nothing is prompted, nothing is written. This is the only
place the bootstrap key still lives.

=item *

B<Operator> (secure mode, k216) — when this run decrypts with
C<SOPS_AGE_KEY_FILE> and that identity's recipient is the C<age> of a
C<purpose: operator> entry in F<keys.yaml> (C<ocp keys operator add>): that
operator's SSH key, whose private half is the file C<OCP_OPERATOR_KEY> names.
Its public half has to be the entry's. No PIN2; the temp file pair is written
as for the admin key. An identity that is another recipient without an
operator entry is refused by name: the admin key opens for the project key
alone.

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
with a message, not block on a password nobody can see. C<--pins-stdin>
(C<$OCP::Password::PINS_STDIN>) counts as a terminal here: the PIN2 is the
next line of STDIN, and a missing one dies by name. C<pin2> supplies the
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

    # k216: whose age identity is this? A key handed in was unlocked by the
    # project key's holder already.
    my ($who, $entry) = $opt{admin_key} ? ('project') : $class->identity_of($config);
    return $class->_operator_key($config, $provider, $entry) if $who eq 'operator';
    die $class->foreign_identity_refusal($config,
        "This cluster's machines are reached with the admin key, whose private\n"
      . "half opens for the project key alone.") if $who eq 'other';

    return $class->_admin_key($config, $provider, %opt);
}

=method identity_of

    my ($who, $entry) = OCP::ClusterKey->identity_of($config);

Who this run's age identity is to the project (k216): C<'project'> -- the
project key, which is the only answer without C<SOPS_AGE_KEY_FILE>, and never
costs a prompt to give --, C<'operator'> with that operator's F<keys.yaml>
entry, or C<'other'>, another recipient of the SOPS files that is no
operator. An identity that cannot be told apart (no private key in
F<keys.yaml> to try it on) counts as the project key: what it then attempts
fails by name in L<OCP::Keys>.

=cut

sub identity_of {
    my ($class, $config) = @_;

    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    return ('project') unless $secrets->sops_age_key_file;

    if (my $entry = $class->operator_entry($config)) {
        return ('operator', $entry);
    }

    my $opens = $secrets->identity_opens_private_keys;
    return ('other') if defined $opens && !$opens;
    return ('project');
}

=method operator_entry

    my $entry = OCP::ClusterKey->operator_entry($config);

The C<purpose: operator> entry of F<keys.yaml> whose C<age> recipient is one
of this run's identities from C<SOPS_AGE_KEY_FILE>, or C<undef>. Without the
variable there is none: F<.ocp/age.key> is the project key.

=cut

sub operator_entry {
    my ($class, $config) = @_;

    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    return undef unless $secrets->sops_age_key_file;

    my $keys = OCP::Keys->new(project_dir => $config->project_dir);
    return undef unless $keys->has_keys_file;

    $secrets->ensure_age_key;
    my %mine = map { $_ => 1 } $secrets->identity_recipients;
    my $all  = $keys->list_keys;

    my ($entry) = grep {
        ($_->{purpose} // '') eq 'operator' && !$_->{deprecated}
        && defined $_->{age} && $mine{ $_->{age} }
    } @$all;
    return $entry;
}

=method foreign_identity_refusal

    die OCP::ClusterKey->foreign_identity_refusal($config, $why);

The message for a run whose age identity (C<SOPS_AGE_KEY_FILE>) is another
recipient of the project but neither its project key nor an operator, with
C<$why> -- the thing that needs the project key -- in front.

=cut

sub foreign_identity_refusal {
    my ($class, $config, $why) = @_;

    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    my $file    = $secrets->sops_age_key_file // '';
    my @mine    = eval { $secrets->identity_recipients };

    return "ERROR: $why\n"
      . "This run decrypts with SOPS_AGE_KEY_FILE ($file):\n"
      . join('', map { "  $_\n" } @mine)
      . "That identity reads the project's SOPS files, but it is not the project key,\n"
      . "and no operator in keys.yaml names it. Run this with the project key (unset\n"
      . "SOPS_AGE_KEY_FILE; PIN1), or register this machine as an operator where the\n"
      . "project key is:\n"
      . "  ocp keys operator add --name NAME --ssh-pubkey FILE --age "
      . ($mine[0] // 'AGE1...') . "\n";
}

# An operator's SSH key (k216): the private half from OCP_OPERATOR_KEY, the
# public half the keys.yaml entry's -- the file must be that key, or the
# machines `ocp keys operator add` put it on would refuse it. Written into a
# temp pair for the same reason as the admin key: Rex wants key.pub beside it.
sub _operator_key {
    my ($class, $config, $provider, $entry) = @_;

    my $name = $entry->{name};
    my $file = $ENV{OCP_OPERATOR_KEY};
    my $who  = "This run decrypts as the operator '$name' (SOPS_AGE_KEY_FILE), so it\n"
             . "       reaches the machines with that operator's SSH key";

    die "ERROR: $who --\n"
      . "       and OCP_OPERATOR_KEY, the path to its private half, is not set.\n"
        unless defined $file && length $file;
    die "ERROR: $who --\n"
      . "       and OCP_OPERATOR_KEY is set to $file, which does not exist.\n"
        unless -f $file;

    my $private = eval { Path::Tiny::path($file)->slurp };
    die "ERROR: $who --\n"
      . "       and OCP_OPERATOR_KEY ($file) cannot be read.\n"
        unless defined $private && length $private;

    my $public = OCP::TempKeyPair::public_from_private($private);
    $public = Path::Tiny::path($file . '.pub')->slurp
        if !defined $public && -f ($file . '.pub');

    my $have = _key_blob($public);
    my $want = _key_blob($entry->{public});
    die "ERROR: $who --\n"
      . "       and the key at OCP_OPERATOR_KEY ($file) is not it.\n"
      . "       keys.yaml has for '$name': " . ($entry->{public} // '?') . "\n"
      . "       the file is:              "
      . (defined $have ? _key_line($public) : 'no OpenSSH private key OCP can read') . "\n"
        unless defined $have && defined $want && $have eq $want;

    my $pair = OCP::TempKeyPair->for_private_key($private, public => $entry->{public});

    return bless {
        path        => $pair->path,
        public_path => $pair->public_path,
        origin      => 'operator',
        provider    => $provider,
        name        => $name,
        temp        => $pair,
    }, $class;
}

# The base64 body of an authorized_keys line, or undef.
sub _key_blob {
    my ($line) = @_;
    return undef unless defined $line;
    my ($blob) = $line =~ m{\A\s*\S+\s+([A-Za-z0-9+/]+=*)(?:\s|\z)};
    return $blob;
}

sub _key_line {
    my ($line) = @_;
    $line =~ s/\s+\z//;
    return $line;
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

    # OCP::Rex sets REX_PUBLIC_KEY to key_file . '.pub' unconditionally, so
    # the public half has to sit next to the private one or every Rex task
    # over this key points at a path that does not exist. Writing that pair
    # and owning it is OCP::TempKeyPair's whole job — it was open-coded here
    # until OCP::Node needed the identical dance for its worker keys and
    # copying it a fourth time was the wrong answer (k93).
    my $pair = OCP::TempKeyPair->for_private_key(
        $admin_key->{private},
        public => $admin_key->{public},
    );

    return bless {
        path        => $pair->path,
        public_path => $pair->public_path,
        origin      => 'admin',
        provider    => $provider,
        name        => $admin_key->{name},
        temp        => $pair,
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
    #
    # --pins-stdin (k166) is someone to ask: the operator put the answer on
    # STDIN up front, and OCP::Password dies naming the PIN if it is missing
    # rather than blocking, which is the failure this guard exists to avoid.
    my $interactive = exists $opt{interactive} ? $opt{interactive}
                    : defined $INTERACTIVE     ? $INTERACTIVE
                    :   $OCP::Password::PINS_STDIN || -t STDIN;
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
    # want one; this names the reason the key model gives for it. It goes
    # where the prompt goes, STDERR (k231: STDOUT is the narrative, and a
    # `> file` must not swallow the reason for a prompt the operator sees);
    # with the PIN2 handed in there is no prompt, and it is narrative.
    #
    # "From the CLI": robocop reaches workers with the robo key, so "the admin
    # key and nothing else", which this said before, was wrong for them (k209).
    my $fh = defined $opt{pin2} ? \*STDOUT : \*STDERR;
    print {$fh} "  In secure mode every machine of this cluster is reached from the\n";
    print {$fh} "  CLI with the admin key (provider '$provider').\n";
    print {$fh} "  " . ($reason ? "$reason needs" : "This step needs")
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
out of F<keys.yaml>, C<'operator'> for an operator's key from
C<OCP_OPERATOR_KEY> (k216). Tests assert on this: "secure + hetzner reached the
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
        die "SSH not ready: $err\n" . $hint;
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
        : $self->{origin} eq 'operator'
        ? "operator key '$self->{name}' (provider $self->{provider}, OCP_OPERATOR_KEY)"
        : "bootstrap key .ocp/id_ed25519 (provider $self->{provider})";
}

=method label

    OCP::SSH->new(key_file => $key->path, key_label => $key->label, ...);
    # "the admin key 'admin-ssh' from keys.yaml"

The key as the operator knows it, for a message about it: the admin key by its
name in F<keys.yaml>, an operator key by its operator's name, the bootstrap
key by its place in the project. L</path>
is no answer to that for the admin key -- it is a temporary copy.

=cut

sub label {
    my ($self) = @_;
    return $self->{origin} eq 'admin'
        ? 'the admin key' . ($self->{name} ? " '$self->{name}'" : '') . ' from keys.yaml'
        : $self->{origin} eq 'operator'
        ? "the operator key '$self->{name}'"
        : 'the bootstrap key .ocp/id_ed25519';
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

    # Both files belong to the OCP::TempKeyPair; it knows which of the two it
    # may unlink itself and which one File::Temp has to be left to remove.
    delete $self->{public_path};
    (delete $self->{temp})->cleanup;

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

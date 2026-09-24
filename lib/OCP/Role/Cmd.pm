package OCP::Role::Cmd;
# ABSTRACT: Base role for OCP commands

use Moo::Role;
use MooX::Options;

use OCP::Choices;
use OCP::Keys;
use OCP::Password;
use OCP::Provider;

# --pins-stdin (k166): every PIN prompt of this run reads the next line of
# STDIN instead of the terminal -- `ocp apply --pins-stdin < <(pass show x)`.
# Declared here so every command has it after its own name, where the
# orchestrating scripts put it; the root options (-v, -c) only parse before
# the command word.
#
# The trigger hands the switch to OCP::Password, where the prompts are. The
# option records that it was given; OCP::Password::$PINS_STDIN is what the
# prompts read (see there for why it is a process-wide switch).
option pins_stdin => (
    is      => 'ro',
    doc     => 'Read PINs from STDIN, one line per prompt in prompt order',
    trigger => sub { $OCP::Password::PINS_STDIN = 1 if $_[1] },
);

# Both spellings of a multi-word option, --pins-stdin and --pins_stdin,
# wherever it stands (k167). MooX::Options (4.103) means to accept both: its
# _options_fix_argv rewrites the dashes. But that loop takes the argument
# after EVERY known option as the option's value, a boolean's included, and
# passes it on without rewriting it -- so `--force --pins-stdin` reached
# Getopt::Long as "pins-stdin" and died "Unknown option", while the same
# option alone, or after one that takes a value, went through.
#
# So the spelling is settled here, before MooX::Options sees the vector: an
# argument is rewritten only when its underscored name IS an option of this
# command, and the value after an option that takes one is left alone. An
# unknown dashed name therefore still reaches Getopt::Long and is refused.
# parse_options, not new_with_options: that is where MooX::Options reads
# @ARGV, and MooX::Cmd reaches it for every command in the chain.
around parse_options => sub {
    my ($orig, $class, @params) = @_;

    local @ARGV = $class->_option_argv_spelled(@ARGV);
    return $class->$orig(@params);
};

sub _option_argv_spelled {
    my ($class, @argv) = @_;

    my %data = $class->_options_data;
    my @spelled;

    while (@argv) {
        my $arg = shift @argv;

        if ($arg eq '--') {
            push @spelled, $arg, @argv;
            last;
        }

        my ($neg, $word, $value) = $arg =~ /\A--(no-)?([^=]+)(=.*)?\z/s;
        unless (defined $word) {
            push @spelled, $arg;
            next;
        }

        (my $name = $word) =~ tr/-/_/;

        # `--no-wait` is a negation only for a negatable option; any other
        # --no-... is left exactly as typed.
        if (defined $neg && $data{$name} && $data{$name}{negatable}) {
            push @spelled, '--no-' . $name . ($value // '');
            next;
        }

        (my $whole = ($neg // '') . $word) =~ tr/-/_/;
        unless ($data{$whole}) {
            push @spelled, $arg;
            next;
        }

        push @spelled, '--' . $whole . ($value // '');

        # The value of `--host x` is data, not an option to spell.
        push @spelled, shift @argv
            if !defined $value && defined $data{$whole}{format} && @argv;
    }

    return @spelled;
}

sub ocp { $_[0]->command_chain->[0] }

# What to say instead of a listing when the cluster has no OCPNodeProvider at
# all: an empty "Available:" line answers nothing. Written once because two
# methods below print it -- provider_choices for the callers that only want
# the listing, provider_cr wrapped in a rejection.
my $NO_PROVIDERS = "No OCPNodeProvider exists in this cluster.\n"
                 . "'ocp apply' writes one per provider in ocp.yaml;"
                 . " 'ocp provider add' adds one by hand.\n";

# A provider is addressed by the NAME of its OCPNodeProvider CR, while
# `ocp init --provider` and spec.type speak provider TYPES. Naming the type
# (`--provider ssh` for the CR `ssh-default` that `ocp apply` writes) is the
# mistake people actually make, and it cost a SPIKE iteration before the
# rejection said anything useful (k89). So every command that rejects a
# provider name does it from here, in the shape `ocp typo` answers in
# (OCP::_resolve_commands): name the word, then say what would have worked.
#
# Deliberately not resolving 'ssh' to 'ssh-default': that would open a second
# namespace next to the CR names, and nothing stops anyone from calling a
# provider 'ssh'. Input we do not understand is refused and explained.
sub provider_crs {
    my ($self, $api, %opt) = @_;

    my $ns = $opt{namespace} // 'ocp-system';

    my $list = eval { $api->list('OCPNodeProvider', namespace => $ns) }
        or return ();

    return sort { $a->{metadata}{name} cmp $b->{metadata}{name} }
           map  { $api->k8s->object_to_struct($_) } @{ $list->items // [] };
}

sub provider_choices {
    my ($self, @providers) = @_;

    return $NO_PROVIDERS unless @providers;

    # Name AND type: the type is what the operator typed, so leaving it out
    # would show the right answer without showing why it is the right answer.
    return OCP::Choices::available(
        map { [ $_->{metadata}{name}, 'type ' . ($_->{spec}{type} // '?') ] }
        @providers
    );
}

sub provider_cr {
    my ($self, $api, $name, %opt) = @_;

    my $ns = $opt{namespace} // 'ocp-system';

    my $cr = eval { $api->get('OCPNodeProvider', name => $name, namespace => $ns) };
    return $api->k8s->object_to_struct($cr) if $cr;

    # The type hint only where it helps: on a cluster without any provider CR
    # the answer is "run ocp apply", and naming the CR that run would create
    # would just say ocp apply twice.
    my @providers = $self->provider_crs($api, %opt);
    my $type_hint = (@providers && OCP::Provider->known_type($name))
        ? "'$name' is a provider type, not a provider name."
          . " 'ocp apply' names its CR '$name-default'.\n"
        : '';

    # provider_choices, not a list: this caller owns both a listing and an
    # empty case, which is the second form OCP::Choices::unknown takes.
    die OCP::Choices::unknown('provider', $name,
        $self->provider_choices(@providers), hint => $type_hint);
}

# Which private key reaches this cluster's machines — see OCP::ClusterKey for
# the answer itself. This is only the caching: on secure mode + a provider OCP
# created the machines for, obtaining it prompts for PIN2, and `ocp update`
# asks once per component. Cached per command object, so the prompt happens on
# the first component and the temp file lives exactly as long as the command
# that needed it.
#
# Deliberately a plain hash slot rather than a Moo attribute: this role is
# consumed by every OCP::Cmd::* class and its constructor surface is part of
# the CLI's contract (MooX::Cmd/MooX::Options both read it). Nothing should be
# able to pass a cluster key in from the command line.
sub cluster_ssh_key {
    my ($self, $config, %opt) = @_;

    require OCP::ClusterKey;

    # Keyed on the project, not just on the object. One command instance can
    # be handed more than one config — the tests do exactly that — and a flat
    # slot would then serve a key built for a different project directory.
    my $slot = OCP::ClusterKey::cache_slot($config, %opt);
    return $self->{_cluster_ssh_key}{$slot}
        //= OCP::ClusterKey->for_config($config, %opt);
}

# The key this command has ALREADY got, or nothing. Never builds one.
#
# For explaining a failure, not for reaching a machine. What a refused SSH
# login probably means is OCP::ClusterKey::migration_hint's answer, and asking
# for it costs a key object — but going through cluster_ssh_key above to get
# one would prompt for PIN2 in the middle of a rollout that never asked for a
# password, purely to decide whether to print a paragraph. That is the wrong
# way round: a diagnosis may not change what the run does.
#
# No key means no diagnosis, which is the honest outcome — a run that never
# obtained a key never offered one to a machine either, so it has nothing to
# say about which key that machine trusts.
sub cluster_ssh_key_if_known {
    my ($self, $config, %opt) = @_;

    require OCP::ClusterKey;

    return $self->{_cluster_ssh_key}{ OCP::ClusterKey::cache_slot($config, %opt) };
}

# A rex prober for OCP::Drift's host-side detection, or undef when no key can be
# had without a prompt. OCP::Drift calls it as $prober->($host, $task, \%params);
# it runs the read-only detection task over SSH and returns OCP::Rex's result.
#
# Non-prompting on purpose. Detection runs on read-only `ocp status` and at the
# top of every `ocp apply`; obtaining a secure-mode cluster key costs a PIN2
# prompt (OCP::ClusterKey), and putting that in front of every status/apply --
# just to look for host residue that is usually not there -- is exactly the cost
# the reconcile path already refuses to pay up front (see
# OCP::Cmd::Apply::Drift::run_remedy, which gets the key late, only once a fix is
# about to run). So this uses only a key already in hand: one this command
# cached earlier, or an on-disk private key for the providers that keep one there
# (ssh/local). When there is none, it returns undef and OCP::Drift skips the SSH
# mode -- the graceful degradation `ocp status` needs when a host is out of reach.
#
# The narration OCP::Rex prints to STDOUT is captured, not emitted: detection
# runs inside the status/drift report, where that would be noise on the payload
# channel. The task's real stdout still comes back in the result hashref (IPC::Run
# collects it over its own pipes, not through Perl's STDOUT).
sub rex_prober {
    my ($self, $config, %opt) = @_;

    require OCP::Rex;

    my $key      = $self->cluster_ssh_key_if_known($config, %opt);
    my $key_file = $key ? $key->path : undef;

    unless (defined $key_file) {
        my $path = $config->ssh_private_key_path;
        $key_file = $path if defined $path && -f $path;
    }
    return undef unless defined $key_file;

    my $verbose = eval { $self->ocp->verbose } || 0;

    return sub {
        my ($host, $task, $params) = @_;
        my $rex = OCP::Rex->new(
            host     => $host,
            key_file => $key_file,
            verbose  => $verbose,
        );

        my $sink = '';
        return do {
            local *STDOUT;
            open STDOUT, '>', \$sink or die "cannot capture rex output: $!\n";
            $rex->run_task($task, %{ $params // {} });
        };
    };
}

# Every retry/poll pause a command makes goes through here — ONE seam,
# reached by method dispatch on $self rather than by a bareword `sleep`
# sitting in whatever file the calling code happens to live in this week.
#
# That distinction is the point (k102): OCP::Cmd::Apply's reconciliation
# steps live across half a dozen Apply::* modules after the phase-8
# extraction (k55), and a test that localised `*OCP::Cmd::Apply::sleep` to
# stub the retry delay had stopped mocking anything the moment those `sleep`
# calls moved into Apply::Network, Apply::CR, and friends — CORE::sleep
# never dispatches through the package that calls it, so the glob it
# replaced was never read. A fixed list of "the modules that sleep today"
# would only survive until the next split. Calling $self->wait_seconds
# instead survives it: every one of those modules already receives $self (the
# OCP::Cmd::Apply instance) as its first argument, so the method resolves to
# whatever "wait_seconds" currently means for that object no matter which
# file defines the caller — and a test only ever has to stub it once, on the
# consuming class ($self's class — flat after Moo::Role composition, so
# stubbing it on OCP::Role::Cmd itself would miss classes that already
# composed the role).
#
# Not only a test seam: OCP::Cmd::Node::Add and OCP::Cmd::DeployImage sleep
# in their own poll loops too (both consume this role), and both already had
# a *different* seam for that (a settable poll interval / _poll_interval
# attribute) rather than mocking sleep directly — this gives them the same
# one-method hook without forcing an attribute onto every command that waits
# for something. It also earns its keep outside of tests: every wait is
# tallied on the object, so a command can report afterwards how much of its
# wall-clock time went to polling rather than doing.
sub wait_seconds {
    my ($self, $seconds) = @_;

    $self->{_wait_seconds_total} += $seconds;
    sleep $seconds;
    return;
}

# Total seconds this command object has spent in wait_seconds so far. Mostly
# for diagnostics (a verbose summary line, a slow-run report) — nothing reads
# it today, but it is the reason wait_seconds is more than a mock point.
sub wait_seconds_total { $_[0]->{_wait_seconds_total} // 0 }

# The PIN2 approval gate for an admin-gated action (secret_approved's Secret
# write, `ocp inject-key`). Unlocking the admin key is both the proof that a
# human holding PIN2 approved AND a key the caller may reuse -- deploy-robocop
# reaches the control plane with it -- so it is RETURNED, not thrown away. A
# wrong or absent PIN2 dies before the caller does anything.
sub require_admin_approval {
    my ($self, $config, $action) = @_;

    print STDERR "  $action is admin-gated and needs PIN2 approval.\n";

    my $pin2 = OCP::Password::prompt_password("Enter PIN2 (admin approval): ");
    die "ERROR: No PIN2 given; $action refused.\n"
        unless defined $pin2 && length $pin2;

    # A wrong PIN2 makes the double-decrypt die ("AES-GCM authentication
    # failed"); catch it so the refusal reads as a PIN2 problem rather than a
    # crypto-internals leak, and so nothing downstream mistakes it for success.
    my $keys  = OCP::Keys->new(project_dir => $config->project_dir);
    my $admin = eval { $keys->get_admin_key($pin2) };
    die "ERROR: Wrong PIN2 or no admin key; $action refused.\n"
        unless $admin;

    return $admin;
}

1;

__END__

=synopsis

    package OCP::Cmd::Something;
    use Moo;
    use MooX::Cmd;
    with 'OCP::Role::Cmd';

    sub execute {
        my $self = shift;
        my $config_path = $self->ocp->config;   # path to ocp.yaml
        my $verbose     = $self->ocp->verbose;  # 0 / 1
    }

=description

A small role consumed by every C<OCP::Cmd::*> class.  Its main job is to
expose the root C<OCP> object so commands can reach the project
configuration without each command having to thread it through.

L<MooX::Cmd> composes commands into a chain (root, sub-command, sub-sub).
The root is always the first element; C<ocp> returns it directly, so
commands at any depth see the same C<OCP> instance.

=opt pins_stdin

    ocp apply --pins-stdin < pins.txt
    ocp inject-key --pins-stdin < <(pass show ocp/mycluster)

Every command takes C<--pins-stdin>, after the command word.  Each PIN prompt
of the run -- PIN1, PIN2, and the new PIN plus its confirmation during
C<ocp init> -- then reads the next line of STDIN instead of the terminal, in
the order the prompts come.  Only the trailing newline is stripped.  The
prompt text still goes to STDERR, so STDOUT carries the same payload as
without the flag.

When STDIN has no line left for a prompt the command dies, naming the PIN it
expected; it never falls back to the terminal.  A secure-mode C<ocp init>
reads four lines (PIN1, PIN1 again, PIN2, PIN2 again); C<ocp init --hetzner>
without a stored token reads the API token as the next line after them, since
that prompt goes through the same hidden-input path.

There is deliberately no way to pass a PIN in argv or the environment, where
C<ps>, F</proc/PID/environ> and shell history would show it.

=method ocp

    my $ocp = $self->ocp;

Returns the first element of the L<MooX::Cmd> C<command_chain>, i.e. the
root C<OCP> object.  Use it to read C<config> (path to C<ocp.yaml>) and
C<verbose>, and to share file/IO helpers (C<dump>, C<dump_file>,
C<load_file>) across commands.

=method cluster_ssh_key

    my $key = $self->cluster_ssh_key($config);
    my $key = $self->cluster_ssh_key($config, provider => 'ssh',
                                              reason   => 'ocp destroy');

The L<OCP::ClusterKey> for this cluster, built once per command object and
reused for every later call.  Dies with a message naming what was missing if
no usable key can be obtained.

The caching is the point: in secure mode on a provider whose machines OCP
created, building this key prompts for PIN2.  C<ocp update> walks a list of
components and would otherwise prompt once per component.  Because the object
is held by the command, its temporary files also live exactly as long as the
command that needed them and are unlinked when it goes away.

=method cluster_ssh_key_if_known

    my $key = $self->cluster_ssh_key_if_known($config);
    print $key->migration_hint if $key;

The L<OCP::ClusterKey> this command has already built, or C<undef>.  Unlike
L</cluster_ssh_key> it never builds one, never prompts and never writes a temp
file.

Use it for diagnosis after something failed — the case it exists for is
L<OCP::ClusterKey/migration_hint>, where the only question is whether to print
an explanation.  Building a key for that would make a message cost a PIN2
prompt in the middle of a run that had not asked for one.  Use
L</cluster_ssh_key> whenever the key is actually going to reach a machine.

=method rex_prober

    my $prober = $self->rex_prober($config);
    OCP::Drift->new(config => $config, api => $api, rex_prober => $prober)->detect;

A coderef for L<OCP::Drift/rex_prober>, or C<undef> when no SSH key can be
obtained without a prompt.  It runs a read-only Rex detection task over SSH and
returns L<OCP::Rex>'s result.

Deliberately non-prompting: detection runs on read-only C<ocp status> and at
the top of every C<ocp apply>, and a secure-mode cluster key costs a PIN2
prompt.  It uses only a key already in hand — one L</cluster_ssh_key_if_known>
already built, or an on-disk private key (C<ssh>/C<local> providers).  With
none, it returns C<undef> and L<OCP::Drift> skips its SSH detection mode, which
is the graceful degradation C<ocp status> needs when a host is unreachable.  The
narration L<OCP::Rex> prints is captured so it does not land on the report's
STDOUT.

=method provider_crs

    my @providers = $self->provider_crs($api);
    my @providers = $self->provider_crs($api, namespace => 'other');

Every C<OCPNodeProvider> CR in the namespace (C<ocp-system> by default) as
plain hashes, sorted by name.  Returns an empty list when the cluster has
none or when the list call fails, so it is safe to call while building an
error message.

=method provider_choices

    die "Multiple providers found, --provider required.\n"
      . $self->provider_choices(@providers);

The C<Available: NAME (type TYPE), ...> line for a list of provider hashes,
newline-terminated.  Given an empty list it returns the bootstrap hint
instead (C<ocp apply> / C<ocp provider add>), so a caller never has to
special-case a cluster without providers.

Both name and type are shown on purpose: C<--provider> takes the CR name,
while C<ocp init --provider> and C<spec.type> take the type, and confusing
the two is the mistake this exists to answer.

The line itself is built by L<OCP::Choices/available>, which is where every
OCP rejection gets its shape; this method only decides what a I<provider>
looks like in one.

=method provider_cr

    my $provider = $self->provider_cr($api, 'ssh-default');

The named C<OCPNodeProvider> as a plain hash.  Dies if there is no such CR,
naming the providers that do exist with their types:

    Unknown provider 'ssh'.
    Available: hetzner-default (type hetzner), ssh-default (type ssh)
    'ssh' is a provider type, not a provider name. 'ocp apply' names its CR 'ssh-default'.

The last line appears only when the rejected name is a provider type and the
cluster has providers at all; without any, the bootstrap hint is the whole
answer.  A type is never resolved to the CR that happens to carry it:
provider names and provider types are separate namespaces and may collide.

=method wait_seconds

    $self->wait_seconds(5);
    $self->wait_seconds($delay) if $attempt < $retries;

Sleeps for the given number of seconds and adds them to
L</wait_seconds_total>.  Every retry/poll pause a command makes should go
through this instead of a bare C<sleep>: it is one method, reached by
dispatch on C<$self>, so it stays reachable no matter which file the caller
ends up living in after the next refactor — unlike C<sleep> itself, which
resolves per-package and silently stops being the C<sleep> a test replaced
the moment the calling code moves to a new module.

=method wait_seconds_total

    my $waited = $self->wait_seconds_total;

Seconds this command object has spent in L</wait_seconds> so far, C<0> if it
never waited.

=seealso

L<MooX::Cmd>, L<OCP>, L<OCP::Choices>, L<OCP::ClusterKey>, L<OCP::Cmd::Apply>,
L<OCP::Cmd::Status>, L<OCP::Cmd::Node::Add>, L<OCP::Cmd::Provider::Rm>

=cut

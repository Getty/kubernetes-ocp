package OCP::Role::Cmd;
# ABSTRACT: Base role for OCP commands

use Moo::Role;
use MooX::Options;
use Carp ();
use Path::Tiny ();
use Scalar::Util ();

use OCP ();
use OCP::Choices;
use OCP::Config ();
use OCP::ErrorLine;
use OCP::Keys;
use OCP::Kubernetes;
use OCP::Password;
use OCP::Provider;
use OCP::Secrets;
use OCP::SSH;

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

# The positional words of a command's $args (k216). MooX::Cmd hands execute
# the command line as typed, options and their values included -- MooX::Options
# parses a protected copy of @ARGV and leaves the vector alone -- so
# `if @$args` is true for any option and `$args->[0]` can be an option. Read
# the way Getopt::Long read it before: an option that takes a value takes the
# next word unless written --opt=value, an unambiguous abbreviation counts as
# the option, and everything after `--` is positional. Getopt has already
# refused anything it did not understand, so nothing here needs to.
sub positional_args {
    my ($self, $args) = @_;

    my %data = $self->_options_data;
    my %takes_value = map { $_ => defined $data{$_}{format} }
                      keys %data, qw( h help usage man );
    my %short_value = map { $data{$_}{short} => defined $data{$_}{format} }
                      grep { defined $data{$_}{short} } keys %data;

    my @words = @{ $args // [] };
    my @positional;

    while (@words) {
        my $arg = shift @words;

        if ($arg eq '--') {
            push @positional, @words;
            last;
        }

        if ($arg =~ /\A--([^=]+)\z/) {
            (my $name = $1) =~ tr/-/_/;
            my @hit = exists $takes_value{$name} ? ($name)
                    : grep { index($_, $name) == 0 } keys %takes_value;
            shift @words if @hit == 1 && $takes_value{ $hit[0] };
            next;
        }
        next if $arg =~ /\A--/;    # --opt=value

        if ($arg =~ /\A-(.)\z/) {
            shift @words if $short_value{$1};
            next;
        }
        next if $arg =~ /\A-./;    # bundled short options, -ovalue

        push @positional, $arg;
    }

    return @positional;
}

sub ocp { $_[0]->command_chain->[0] }

#
# The shape of ocp.yaml, checked once (k400)
#

# The key paths of ocp.yaml this command reads, in OCP::Config::spec_errors'
# syntax; each command that reads any defines it after its options. It may
# read the command's options and the raw config (node add's paths turn on
# --gpu), and never dies on a shape of ocp.yaml: one that is empty or no
# mapping stops with that file's one line, as every reader does (k340).
# Nothing declared, nothing checked.
sub spec_paths { return () }

# What reaching the first control plane reads of ocp.yaml, for the spec_paths
# of each command that reaches it (k401): its address and name as
# OCP::Config::cluster_status reads them -- the entry, its public_ip, else its
# host, a local one's provider, and its name -- and the key to log in with
# (cluster_ssh_key_spec_paths). Node add, update and deploy-robocop listed it
# by hand, status and ssh in variants of their own, so a change to
# cluster_status could leave a declaration behind; t/401 holds what
# cluster_status and cluster_ssh_key read against these.
sub first_control_plane_spec_paths {
    my ($self) = @_;
    return (
        'control_planes', 'control_planes[1]',
        map({ "control_planes[1].$_" } qw( provider public_ip host name )),
        $self->cluster_ssh_key_spec_paths,
    );
}

# What cluster_ssh_key reads of ocp.yaml: ssh:, the bootstrap key's paths in
# dev mode (OCP::ClusterKey). The first control plane's provider it says in
# messages only, where it is a string on a mapping, so it declares nothing
# there (k400).
sub cluster_ssh_key_spec_paths { return ('ssh') }

# Dies with every line of spec_errors at the paths spec_paths declares, in
# validate()'s order, in the one text a command refuses ocp.yaml with; 1 when
# there is none. Destroy's, the machines role's and node add --gpu's own
# frames went into it (k400); ocp apply and ocp keys secure check all of
# validate() in theirs.
sub refuse_spec_errors {
    my ($self, $config) = @_;

    my @paths  = $self->spec_paths($config) or return 1;
    my @errors = $config->spec_errors(@paths) or return 1;

    my $file = $config->file;
    my $s    = @errors == 1 ? '' : 's';
    die "$file has " . scalar(@errors) . " error$s:\n"
      . join('', map { "  - $_\n" } @errors)
      . 'Nothing was done: ' . $self->_command_words . " checks what it reads of $file before it "
      . "asks for a PIN or touches the cluster or a machine. Fix the line$s above and run it "
      . "again.\n";
}

# The command as it is typed: its class's words below OCP::Cmd, lower case,
# spelt as %OCP::COMMAND_ALIASES spells them (deploy-robocop, keys
# authorized-keys) -- the spelling is keyed by the words in front of it.
sub _command_words {
    my ($self) = @_;

    my @words;
    for my $part (split /::/, (ref($self) || $self) =~ s/\AOCP::Cmd:://r) {
        my $word   = lc $part;
        my $prefix = join '', map { "$_ " } @words;
        my ($alias) = grep {
            $OCP::COMMAND_ALIASES{$_} eq $word
              && substr($_, 0, length $prefix) eq $prefix
              && index($_, ' ', length $prefix) < 0
        } sort keys %OCP::COMMAND_ALIASES;
        push @words, defined $alias ? substr($alias, length $prefix) : $word;
    }
    return join ' ', 'ocp', @words;
}

# The check, before the command runs: MooX::Cmd executes the leaf. A command
# built by hand -- in a test -- has no chain and checks nothing; without an
# ocp.yaml the command says its own "not found".
before execute => sub {
    my ($self) = @_;

    my $root = ($self->command_chain // [])->[0] or return;
    my $file = $root->config;
    return unless defined $file && -f $file;
    $self->refuse_spec_errors(OCP::Config->new(file => $file));
};

# What `before execute` wraps in a class that has no execute of its own: a
# modifier needs the method there. Every OCP::Cmd class has its own.
sub execute { Carp::croak(ref($_[0]) . ' has no execute') }

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

# k384, k387: what became of a request to the API server the kubeconfig
# names, as one line naming that server. The wording is
# OCP::ErrorLine::api_error_line's (k398: there, so the renderer in OCP.pm
# can say it too); this adds the server, from the client.
#
# $client is read only for an APIError, which only a built client can give:
# the client itself, or the OCP::Kubernetes that holds it (ocp status).
# Asking an OCP::Kubernetes for its client earlier would run its builder
# again when the build was what died.
sub cluster_api_error {
    my ($self, $client, $err) = @_;
    return unless Scalar::Util::blessed($err)
        && $err->isa('Kubernetes::REST::APIError');
    my $api = $client->can('server') ? $client : $client->api;
    return OCP::ErrorLine::api_error_line($err, $api->server->endpoint);
}

# $call (a sub that talks to the API through $client) and its result; an
# APIError it dies with dies again as the line above (a user error), anything
# else as it came.
sub cluster_api_call {
    my ($self, $client, $call) = @_;
    my $result;
    return $result if eval { $result = $call->(); 1 };
    my $err  = $@;
    my $line = $self->cluster_api_error($client, $err);
    die defined $line ? "$line\n" : $err;
}

# One GET /version, before the first call of a command that built its client
# from the kubeconfig. Every client may read /version, one without credentials
# too, so whatever error comes back here -- no answer, an expired token's 401
# -- is what every call after it would get: it ends the command now, in one
# line, before Kubernetes::REST's discovery for an OCP Kind could warn about
# it with a source location of its own.
sub reach_cluster_api {
    my ($self, $api) = @_;
    $self->cluster_api_call($api, sub {
        $api->check_response(
            $api->io->call($api->prepare_request('GET', '/version')), 'GET /version');
    });
    return $api;
}

# k399 (Part B): the one way a command gets its cluster client. Sixteen files
# built one, each reading kubeconfig.yaml itself and deciding itself whether
# to unlock the key first (k370, k375, k382); only three checked the API
# before their first call (k384).
#
# connect_cluster_api is the inner part, for a kubeconfig in hand -- ocp
# apply's, from bootstrap, in memory. It builds through OCP::Kubernetes, so
# the CRD providers are registered in one place (ADR 0024), and sends
# nothing: right after bootstrap the API may not answer yet, and apply waits
# for it itself. The OCP::Kubernetes stays on the command, for the temp file
# it holds. The server goes to OCP::ErrorLine, process-wide: when execute
# dies, the renderer in OCP.pm holds no command object to ask (MooX::Cmd
# built it), and an APIError that escapes then still names the server -- the
# last one built for, so a rebuild on a new kubeconfig names the new one.
# can('server'): a test's fake client has none, as in cluster_api_error.
sub connect_cluster_api {
    my ($self, $kubeconfig) = @_;

    my $kubernetes = OCP::Kubernetes->new(kubeconfig => $kubeconfig);
    my $api        = $kubernetes->api;
    $self->{_cluster_kubernetes} = $kubernetes;
    $self->{_cluster_api}        = $api;
    OCP::ErrorLine::set_cluster_endpoint($api->server->endpoint) if $api->can('server');
    return $api;
}

# The project's cluster, for every other command: kubeconfig.yaml read,
# connect_cluster_api, one GET /version. Once per command object: a second
# call is the first one's client, no second build and no second PIN1.
#
# The read is the key step. read_kubeconfig unlocks age.key.enc with PIN1 when
# that is where the key comes from (k370) and checks a key already here
# against the project, so it runs outside any eval, in both modes: a key
# problem is no missing cluster (k382). A PIN1 that does not open
# age.key.enc, an empty one, a key this project's files are not bound to, no
# key at all -- each stops the command in OCP::Secrets' words (k375).
#
# optional => 1 is for the commands that go on without the cluster (ocp
# destroy, ocp status): in list context (undef, undef) when there is no
# kubeconfig.yaml -- nothing to say --, (undef, the one line) when the client
# cannot be built or the API does not answer. That client is not kept: a
# second call builds and checks again.
sub cluster_api {
    my ($self, %opt) = @_;

    return $self->{_cluster_api} if $self->{_cluster_api};

    my $project = Path::Tiny::path($self->ocp->config)->parent;
    my $secrets = OCP::Secrets->new(project_dir => $project);

    unless ($secrets->has_kubeconfig) {
        die OCP::Secrets->no_kubeconfig_refusal unless $opt{optional};
        return wantarray ? (undef, undef) : undef;
    }

    my $kubeconfig = $secrets->read_kubeconfig;

    return $self->reach_cluster_api($self->connect_cluster_api($kubeconfig))
        unless $opt{optional};

    my $api = eval { $self->reach_cluster_api($self->connect_cluster_api($kubeconfig)) };
    return $api if $api;

    my $err = $@;
    delete @{$self}{qw( _cluster_api _cluster_kubernetes )};
    my $why = OCP::ErrorLine::user_line($err) // OCP::ErrorLine::one_line($err);
    $why =~ s/\AERROR:\s*//;
    return wantarray ? (undef, $why) : undef;
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
#
# What it reads of ocp.yaml is cluster_ssh_key_spec_paths: a new read there
# goes into that list too (k401).
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
#
# pinned_only => 1 is the dry run's (k374): only a machine whose host key the
# known_hosts file holds already is contacted. OCP::Rex records the key of any
# other on first contact -- OCP::SSH's accept-new, into the project's
# .ocp/known_hosts --, and a dry run writes nothing. So such a machine is
# skipped before any connection, and said. A recorded one is checked against
# its key as on every run; libssh verifies and records nothing. Trusting the
# key into a throwaway file instead would have the dry run read a machine no
# recorded key vouches for, and forget the key again: the first real run
# would trust anew, maybe another one. age_key is the project key a dry run
# holds in memory on a clone (k349), for the robo key.
sub rex_prober {
    my ($self, $config, %opt) = @_;

    require OCP::KnownHosts;
    require OCP::Rex;
    require OCP::ClusterKey;

    my $pinned_only = delete $opt{pinned_only};
    my $age_key     = delete $opt{age_key};

    my $key      = $self->cluster_ssh_key_if_known($config, %opt);
    my $key_file = $key ? $key->path : undef;

    # A Leitstand (operator identity, k216) reaches the machines with its own
    # key, which stands on all of them and needs no PIN2 (k237). Without a key
    # already in hand it comes before the on-disk fallback: that one belongs
    # to a project key's holder. Set but unusable: said once, probe skipped.
    unless (defined $key_file) {
        my ($op, $problem) = OCP::ClusterKey->operator_probe_key($config);
        if ($op) {
            $self->{_operator_probe_key} = $op;    # holds the temp file
            $key_file = $op->path;
        } elsif (defined $problem) {
            print STDERR "[WARN] OCP_OPERATOR_KEY is set but cannot be used for the host probes: $problem\n"
                unless $self->{_operator_probe_warned}++;
        }
    }

    unless (defined $key_file) {
        my $path = $config->ssh_private_key_path;
        $key_file = $path if defined $path && -f $path;
    }

    # Secure mode with no PIN2 asked yet has no key of the kinds above. The
    # robo key needs the age key alone (ADR 0006), so the probe may use it
    # without a prompt (k234). It need not be authorised on a machine (by
    # intent it does not reach control planes): a host that refuses it is
    # skipped and said once -- see host_probe_warning -- not an error.
    my $robo = 0;
    unless (defined $key_file) {
        my $pair = $self->_robo_probe_key($config, $age_key);
        if ($pair) {
            $key_file = $pair->path;
            $robo     = 1;
        }
    }

    delete $self->{_probe_skipped};
    unless (defined $key_file) {
        $self->{_probe_no_key} = 'no SSH key to probe with that needs no PIN2';
        return undef;
    }
    delete $self->{_probe_no_key};

    my $verbose = eval { $self->ocp->verbose } || 0;

    return sub {
        my ($host, $task, $params) = @_;
        my $rex = OCP::Rex->new(
            host     => $host,
            key_file => $key_file,
            verbose  => $verbose,
            quiet    => 1,
        );

        if ($pinned_only
            && !OCP::KnownHosts->new(file => $rex->known_hosts)->knows($host)) {
            $self->{_probe_skipped}{$host} = 'its host key is not in ' . $rex->known_hosts
                . ' yet, and a dry run records none (the first ocp apply or ocp status does)';
            return undef;
        }

        my $sink = '';
        my $result = eval {
            local *STDOUT;
            open STDOUT, '>', \$sink or die "cannot capture rex output: $!\n";
            $rex->run_task($task, %{ $params // {} });
        };
        if (my $err = $@) {
            # A name that does not resolve is said as that, with any key
            # (k236); the robo key's refusal below is only one other reason.
            if (OCP::SSH->name_unresolved("$err")) {
                $self->{_probe_skipped}{$host}
                    = 'the name does not resolve from here (not a key problem)';
                return undef;
            }
            # A host key that no longer matches the recorded one is the
            # machine's identity in question, not the key refused: said as
            # that whatever key was offered (k374). With the robo key it read
            # as "not accepted" below.
            die $err if !$robo || (ref $err && $err->isa('OCP::SSH::HostKeyChanged'));
            $self->{_probe_skipped}{$host} = 'the robo key was not accepted (it is not authorised everywhere; the admin key needs PIN2)';
            return undef;
        }
        return $result;
    };
}

# The robo (automation) key as a key file for the host probes, or undef when
# the project has none (dev mode, no keys.yaml) or it cannot be read without a
# prompt. Held on the command so the temp file lives as long as the command.
# $age_key, when given, is the project key in memory (a dry run on a clone,
# k349/k374); without it, OCP::Keys reads .ocp/age.key.
sub _robo_probe_key {
    my ($self, $config, $age_key) = @_;

    return $self->{_robo_probe_key} if $self->{_robo_probe_key};

    require OCP::Keys;
    require OCP::TempKeyPair;
    my $keys = OCP::Keys->new(project_dir => $config->project_dir, age_key => $age_key);
    return undef unless eval { $keys->has_keys_file };
    my $robo = eval { $keys->get_automation_key } or return undef;
    return undef unless defined $robo->{private} && length $robo->{private};

    return $self->{_robo_probe_key} = OCP::TempKeyPair->for_private_key(
        $robo->{private}, public => $robo->{public});
}

# The one line for host probes that did not run, or '' when all did (k234).
# Hosts the prober skipped -- the robo key refused, a name that does not
# resolve, a dry run's host with no recorded key (k374) --, or -- with no key
# at all -- every machine the probes would have looked at. A skipped probe is
# not drift and not a failure; it only must not read as "no drift".
sub host_probe_warning {
    my ($self, $drift) = @_;

    my $skipped = $self->{_probe_skipped} || {};
    my (@hosts, %reason);
    if (%$skipped) {
        @hosts = sort keys %$skipped;
        $reason{ $skipped->{$_} } = 1 for @hosts;
    }
    elsif (defined $self->{_probe_no_key}) {
        @hosts = $drift->probe_targets;
        $reason{ $self->{_probe_no_key} } = 1;
    }
    return '' unless @hosts;

    return sprintf "  [WARN] host probes skipped on %s: %s\n",
        join(', ', @hosts), join('; ', sort keys %reason);
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
#
# A run under another age identity (SOPS_AGE_KEY_FILE, k216) cannot give it:
# the admin key opens for the project key alone, and an operator (Leitstand)
# runs unattended -- nobody would answer the prompt. Refused by name before
# asking, so an unattended run ends instead of waiting.
sub require_admin_approval {
    my ($self, $config, $action) = @_;

    require OCP::ClusterKey;

    my ($who, $entry) = OCP::ClusterKey->identity_of($config);
    die "ERROR: $action is admin-gated and needs PIN2 approval -- the\n"
      . "       admin key's PIN2, which only the project key's holder can give.\n"
      . "       This run decrypts as the operator '$entry->{name}' (SOPS_AGE_KEY_FILE);\n"
      . "       run it with the project key (PIN1 + PIN2).\n"
        if $who eq 'operator';
    die OCP::ClusterKey->foreign_identity_refusal($config,
        "$action is admin-gated and needs PIN2 approval, from the admin key\n"
      . "whose private half opens for the project key alone.")
        if $who eq 'other';

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

=method positional_args

    my @words = $self->positional_args($args);

The positional words of the C<$args> L<MooX::Cmd> hands to C<execute>, which
is the command line as typed, options included: every option of the command
and the value of each that takes one are left out, as Getopt::Long read them
(C<--opt=value>, abbreviations, short options); everything after C<--> is
positional.

=method spec_paths

    sub spec_paths {
        my ($self, $config) = @_;
        return ('kubernetes', 'network.pod_cidr', ($self->gpu ? 'gpu' : ()));
    }

The key paths of F<ocp.yaml> the command reads, in the syntax of
L<OCP::Config/spec_errors>. A command that reads any defines it after its
options; it may look at its options and at the raw config, and never dies on a
shape of F<ocp.yaml>. The role's own returns nothing: a command that declares
nothing is not checked.

=method first_control_plane_spec_paths

    return ($self->first_control_plane_spec_paths, 'kubernetes');

The key paths reaching the first control plane reads: C<control_planes>, its
first entry and that entry's C<provider>, C<public_ip>, C<host> and C<name>,
as L<OCP::Config/cluster_status> reads them, and
L</cluster_ssh_key_spec_paths>. A command that reaches the first control plane
returns them from its L</spec_paths>.

=method cluster_ssh_key_spec_paths

The key paths L</cluster_ssh_key> reads: C<ssh>, the bootstrap key's paths in
dev mode.

=method refuse_spec_errors

    $self->refuse_spec_errors($config);    # 1, or dies

Dies with every line L<OCP::Config/spec_errors> has at the paths
C<spec_paths> declares, in L<OCP::Config/validate>'s order, or returns 1 when
there is none:

    ocp.yaml has 1 error:
      - gpu.driver: ...
    Nothing was done: ocp node add checks what it reads of ocp.yaml before it asks for a PIN or touches the cluster or a machine. Fix the line above and run it again.

The command words are spelt as they are typed (C<ocp deploy-robocop>). An
F<ocp.yaml> that is empty or no mapping dies with that file's one line
instead. The role runs it before C<execute>, on the F<ocp.yaml> of the root
C<OCP> object, so before the command asks for a PIN, reads the cluster or
touches a machine; without an F<ocp.yaml> it does not run, and the command
says its own "not found". A command built without a C<command_chain> (a
test) is not checked. C<ocp apply> and C<ocp keys secure> check all of
C<validate()> in their own text instead, and declare nothing.

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
prompt.  It uses only a key already in hand, in this order: one
L</cluster_ssh_key_if_known> already built; the operator key of a run under an
operator identity (a Leitstand, C<SOPS_AGE_KEY_FILE>), from C<OCP_OPERATOR_KEY>
via L<OCP::ClusterKey/operator_probe_key>, which needs no PIN2 and stands on
every machine; an on-disk private key (C<ssh>/C<local> providers); the
robo key, which needs the age key alone.  If C<OCP_OPERATOR_KEY> is set but
unusable, a C<[WARN]> on STDERR says why, once, and the probe falls through to
the next key.  With none, it returns C<undef> and L<OCP::Drift> skips its SSH
detection mode, which is the graceful degradation C<ocp status> needs when a
host is unreachable.  The narration L<OCP::Rex> prints is captured so it does
not land on the report's STDOUT.

A host whose key no longer matches the one recorded in known_hosts dies out of
the prober with L<OCP::SSH>'s C<HostKeyChanged>, whatever key was offered;
L<OCP::Drift> says it on STDERR and reports the probe as could not be checked
(an C<error> entry).  Other failures with the robo key are a skip,
named on the C<[WARN] host probes skipped> line.

    my $prober = $self->rex_prober($config,
        pinned_only => 1, age_key => $secrets->age_key);   # ocp apply --dry-run

C<pinned_only> contacts only a machine whose host key the known_hosts file
already holds: the first contact with any other records its key, and a
dry run writes nothing.  Such a machine is skipped, before any connection, and
the skip line says why.  C<age_key> is the project key held in memory
(L<OCP::Secrets/unlock_age_key>), to read the robo key with when
F<.ocp/age.key> is not on disk.

=method require_admin_approval

    my $admin = $self->require_admin_approval($config, 'Injecting the robo key');

The PIN2 approval gate of an admin-gated action (C<secret_approved>'s Secret
write, C<ocp inject-key>). Returns the admin key the PIN2 unlocked; dies on a
wrong or missing PIN2. A run under another age identity
(C<SOPS_AGE_KEY_FILE>: an operator, or another recipient) cannot give the
approval and is refused before any prompt.

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

=method cluster_api

    my $api = $self->cluster_api;
    my ($api, $why) = $self->cluster_api(optional => 1);

The project's cluster client, the one way a command gets it:
F<kubeconfig.yaml> read by L<OCP::Secrets/read_kubeconfig>, the client built
by L</connect_cluster_api>, and one C<GET /version> by L</reach_cluster_api>.
The project is the directory of C<< $self->ocp->config >>.  Built once per
command object: a second call returns the first one's client, with no second
build and no second PIN1 prompt.

Without C<optional> it dies: with L<OCP::Secrets/no_kubeconfig_refusal> when
there is no F<kubeconfig.yaml>, and as reading, building or checking died --
an API that does not answer is the line of L</cluster_api_error>, naming the
server.

With C<< optional => 1 >>, in list context, it answers C<(undef, undef)> when
there is no F<kubeconfig.yaml>, and C<(undef, $line)> when the client cannot
be built or the API does not answer: C<$line> is that failure as one line,
without a newline and without a leading C<ERROR:>.  That client is not kept;
a second call builds and checks again.  For the commands that go on without
the cluster, C<ocp destroy> and C<ocp status>.

A key problem is no missing cluster in either mode: reading
F<kubeconfig.yaml> unlocks F<age.key.enc> with PIN1 when that is where the key
comes from, and checks a key already here against the project.  A PIN1 that
does not open F<age.key.enc>, an empty one, a key this project's files are not
bound to, or no key at all dies in L<OCP::Secrets>' words.

=method connect_cluster_api

    my $api = $self->connect_cluster_api($kubeconfig_yaml);

Builds the client for a kubeconfig in hand, through L<OCP::Kubernetes> (the
CRD providers and OCP's own Kinds registered), keeps it as the command's
client for L</cluster_api>, and tells L<OCP::ErrorLine/set_cluster_endpoint>
its server, so an API error that escapes the command names it.  Sends no
request: C<ocp apply> builds on bootstrap's kubeconfig before the API may
answer.  Each call builds anew; the server named is the last one built for.

=method reach_cluster_api

    my $api = $self->cluster_api;               # checks it already
    $self->reach_cluster_api($self->connect_cluster_api($kubeconfig_yaml));

Sends one C<GET /version> through the client and returns C<$api> when it is
answered.  When it is not -- the API server the kubeconfig names does not
answer (a transport failure, status C<599> in L<Kubernetes::REST>), or answers
with an error status -- it dies with the line of L</cluster_api_error>, a user
error without a Perl source location:

    The cluster API at https://10.0.0.1:6443 could not be reached: Can't connect to 10.0.0.1:6443 (Connection refused)
    The cluster API at https://10.0.0.1:6443 refused the credentials in the kubeconfig (401 Unauthorized)

Every client may read C</version>, so an error there is the one every later
call would get.  L</cluster_api> sends it before a command's first call.

=method cluster_api_call

    my $list = $self->cluster_api_call($api, sub { $api->list('OCPNode', namespace => $ns) });

Runs the sub and returns its result.  A L<Kubernetes::REST::APIError> it dies
with dies again as the line of L</cluster_api_error> (a user error); anything
else dies as it came.  Used by C<ocp node ls> and C<ocp provider ls> around
their calls.

=method cluster_api_error

    my $nodes = eval { $k8s->list_nodes };
    if (my $line = $self->cluster_api_error($k8s, $@)) {
        print STDERR "ERROR: $line\n";
    }

For an error a call already caught: when C<$err> is a
L<Kubernetes::REST::APIError>, one line naming the server
(C<< ->server->endpoint >> of the client), what became of the request, and
why.  The client is a L<Kubernetes::REST>, or an L<OCP::Kubernetes> holding
one.  The words are L<OCP::ErrorLine/api_error_line>'s, with the client's
endpoint.

=over

=item HTTP 599, no answer

C<could not be reached:> and the first line of the transport reason.

=item HTTP 401

C<refused the credentials in the kubeconfig>: a token or client certificate
the API server does not know, or no longer.

=item HTTP 403

C<denied the request>: the credentials are good, RBAC says no.

=item HTTP 500 and up

C<failed>.

=item any other HTTP status

C<answered>; a C<404> too, which is an answer, never "could not be reached".

=back

Behind the words, for an answer: the status in brackets, with the C<reason>
of a Kubernetes C<Status> body in words (C<403 Forbidden>, C<500 Internal
Error>), then the API's C<message> -- or the body, when it is no C<Status>
object -- as one line by L<OCP::ErrorLine/one_line>, left out when it only
repeats the reason:

    The cluster API at https://10.0.0.1:6443 denied the request (403 Forbidden): nodes is forbidden: User "dev" cannot list resource "nodes" ...

For anything that is no APIError it returns nothing and does not touch the
client, so a client whose build died is not built again.  Used by
C<ocp status> and C<ocp health>.

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

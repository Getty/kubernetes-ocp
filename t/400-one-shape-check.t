#!/usr/bin/env perl
# karr k400 (Part C of the one-place-per-concern design): the shape of
# ocp.yaml is checked once, before the command runs. OCP::Role::Cmd's
# `before execute` asks OCP::Config::spec_errors for the key paths the command
# declares it reads (spec_paths) and refuses with all of their lines at once,
# in one text, before a PIN is asked, the cluster asked or a machine touched:
#
#   <file> has <N> error<s>:
#     - <line>
#   Nothing was done: ocp <words> checks what it reads of <file> before it
#   asks for a PIN or touches the cluster or a machine. Fix the line<s> above
#   and run it again.
#
# The claims:
#
#   1. the role: ocp node add --gpu on a gpu: validate() refuses says that
#      text with validate()'s line; without --gpu, or with --nowait, the
#      block holds nothing up; an ocp.yaml that is empty says the file's one
#      line, once; without an ocp.yaml the command says its own "not found"
#   2. the keys commands: a pool's taints that are no list of taints stop
#      ocp keys operator add with validate()'s line before PIN1 (a string was
#      dropped without a word, a list of no taint croaked after PIN1); a
#      control plane whose provider is a list is said nowhere as ARRAY(0x...)
#   3. the sweep, over every leaf command, run as bin/ocp
#      runs it with every way out of this machine a die (@WAYS_OUT):
#      (a) on a valid ocp.yaml: no signal, exit 0 or 1, no Perl text; and,
#          unless the command checks all of validate() (%FULL), every
#          top-level section it reads outside the check is one it declares a
#          path in, or one it reads around on purpose (%READS_AROUND)
#      (b) at every key path of OCPTest::Shapes, with the first shape
#          validate() refuses there: no signal, exit 0 or 1, no Perl text; a
#          refusal in the role's text lists validate()'s lines for the file in
#          its order, as many as it counts; %FULL lists all of them
#   4. the probe the sweep reads with sees a read outside the check, and not
#      one inside it
#   5. update and destroy: ocp update refuses a cilium: or network: it reads
#      before any component runs (it upgraded cert-manager first and then
#      said "Failed to update cilium: ...", k394); ocp destroy is held up by
#      no line in a section it does not read
#   6. status: ocp status refuses a network: it reads before the report, in
#      both forms -- --json as its one JSON error object (k398) -- where it
#      said "Cannot detect drift" under a report half printed (k394); a line
#      in a section it does not declare holds no report up
#   7. the rest: ocp provider add refuses a name that is a list before it
#      writes the provider (it wrote clusterName ARRAY(0x...), k306);
#      ocp deploy-robocop refuses a network.pod_cidr that is a list in its
#      own words; ocp node ls --json says a pool's taints: foo as its one
#      JSON error object, and without --json reads no pool; each command
#      whose reads the sweep does not reach refuses a section it reads, in
#      its words, and not under the option where it does not read it
#
# Network-free and cluster-free: each run is a child whose ways out die, its
# hosts *.invalid.

use strict;
use warnings;
use Test::More;

use Crypt::Age;
use JSON::MaybeXS ();
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Scalar::Util qw( refaddr );
use Tie::Hash ();
use Time::HiRes ();

use lib 'lib';
use lib 't/lib';

use OCP;
use OCP::ClusterKey;
use OCP::Config;
use OCP::Exec;
use OCP::Keys;
use OCP::Kubernetes;
use OCP::Password;
use OCP::Provider;
use OCP::Rex;
use OCP::Role::Cmd;
use OCP::SSH;
use OCP::Secrets;
use OCP::Versions;
use Net::Async::Kubernetes;
use WWW::Hetzner::Cloud;
use OCPTest::Cli qw( run_ocp leaf_commands required_options );
use OCPTest::Shapes qw( shapes at );

delete $ENV{SOPS_AGE_KEY_FILE};
delete $ENV{OCP_OPERATOR_KEY};

my @LEAVES = leaf_commands();

# --- What the sweep covers ----------------------------------------------------

# The commands that check all of validate() before they read, in a frame of
# their own: ocp apply (refuse_invalid_config) and ocp keys secure (its
# switch). They declare nothing.
my %FULL = map { ("OCP::Cmd::$_" => 1) } qw( Apply Keys::Secure );

# The sections a command reads around on purpose, undeclared: it exits 0 with
# a WARNING or a drift entry over a bad value there, and a test pins that.
# Class => [ section, ... ]; each entry is named beside the command's
# spec_paths.
my %READS_AROUND = (
    # The AMD allocation a bad gpu.amd.allocation turns into a WARNING (t/252,
    # t/258, t/379); the cert-manager probe's skip_if a bad nocert turns into
    # a check that could not be made (k332, t/332 claim 1).
    'OCP::Cmd::Status' => [ qw( gpu nocert ) ],
);

# What a command needs after its words to get past its usage line.
my $PUBFILE = path(tempdir(CLEANUP => 1))->child('second.pub');
$PUBFILE->spew("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK400secondkey second\n");
my ($NEW_AGE) = Crypt::Age->generate_keypair;
my %ARGS_OF = (
    'OCP::Cmd::Node::Add'           => [ 'w1' ],
    'OCP::Cmd::Keys::Operator::Add' => [ '--name', 'second', '--ssh-pubkey', "$PUBFILE", '--age', $NEW_AGE ],
    'OCP::Cmd::Keys::Operator::Rm'  => [ 'leitstand' ],
);

# --- The ways out ---------------------------------------------------------------

# Every way a run leaves this machine or waits on a person. In a child each is
# a die naming it, unless the setup hands it an answer: SSH and Rex, every
# process OCP::Exec starts, the providers (Hetzner, the local machine), the
# cluster API (OCP::Kubernetes, the role's builds, robocop's async client),
# the Hetzner API, and the PIN prompts.
my @WAYS_OUT = qw(
    OCP::Rex::run_task
    OCP::SSH::run OCP::SSH::run_script OCP::SSH::interactive OCP::SSH::scp_to OCP::SSH::scp_from
    OCP::Exec::capture_command
    OCP::Provider::for_spec
    OCP::Kubernetes::new
    OCP::Role::Cmd::cluster_api OCP::Role::Cmd::connect_cluster_api
    Net::Async::Kubernetes::new
    WWW::Hetzner::Cloud::new
    OCP::Password::prompt_password OCP::Password::prompt_new_pin OCP::Password::_read_stdin_line
);

# Every named sub of every package, as [ glob name, code ].
sub every_sub {
    my (@subs, %seen);
    my @todo = ('main');
    while (defined(my $pkg = shift @todo)) {
        no strict 'refs';
        my $stash = \%{"${pkg}::"};
        for my $name (keys %$stash) {
            if ($name =~ /\A(.+)::\z/) {
                my $inner = $pkg eq 'main' ? $1 : "${pkg}::$1";
                push @todo, $inner unless $inner eq 'main' || $seen{$inner}++;
                next;
            }
            my $glob = $stash->{$name};
            next unless ref \$glob eq 'GLOB';
            my $code = *{$glob}{CODE} or next;
            push @subs, [ "${pkg}::$name", $code ];
        }
    }
    return @subs;
}

# Each way out with every glob that holds it: the original and its copies --
# an export imported elsewhere, a role's method composed into a class --
# found by identity once, here, so a child replaces them all. A way out its
# class inherits (Net::Async::Kubernetes::new is IO::Async::Notifier's) gets
# a glob of its own there, which method lookup finds first.
my %GLOBS_OF;
{
    no strict 'refs';
    my %way_of;
    for my $way (@WAYS_OUT) {
        my ($pkg, $sub) = $way =~ /\A(.+)::(\w+)\z/;
        $pkg->can($sub) or BAIL_OUT("way out $way: no such sub");
        $way_of{ refaddr \&{$way} } = $way if defined &{$way};
    }
    for my $sub (every_sub()) {
        my $way = $way_of{ refaddr $sub->[1] } or next;
        push @{ $GLOBS_OF{$way} }, $sub->[0];
    }
    $GLOBS_OF{$_} //= [ $_ ] for @WAYS_OUT;
}

# --- The probe --------------------------------------------------------------------

# The spec as a hash that writes each top-level key read to $LOG, once, unless
# the read is the check's own ($IN_CHECK).
package SpecProbe {
    our @ISA = ('Tie::ExtraHash');
    our ($LOG, $IN_CHECK, %SAID);

    sub TIEHASH { my ($class, $spec) = @_; return bless [ $spec ], $class }
    sub FETCH   { _read($_[1]); return $_[0][0]{ $_[1] } }
    sub EXISTS  { _read($_[1]); return exists $_[0][0]{ $_[1] } }

    sub _read { log_line("read $_[0]") unless $IN_CHECK }

    sub log_line {
        my ($line) = @_;
        return if !defined $LOG || $SAID{$line}++;
        open my $fh, '>>', $LOG or die "probe log: $!";
        print {$fh} "$line\n";
        close $fh or die "probe log: $!";
    }
}

package main;

# A child's setup: the alarm, every way out a die (or the answer %answer
# names), and with $log the probe: every Config's spec a SpecProbe, the
# check's own reads marked, and the paths each command declares written down.
# $extra runs last.
sub setup {
    my (%opt) = @_;
    return sub {
        alarm 60;
        $OCP::ClusterKey::INTERACTIVE = 1;
        {
            no strict 'refs';
            no warnings qw( redefine prototype );
            for my $way (keys %GLOBS_OF) {
                my $with = $opt{answer}{$way} // sub { die "sweep: outside ($way)\n" };
                *{$_} = $with for @{ $GLOBS_OF{$way} };
            }
        }
        probe($opt{log}) if defined $opt{log};
        $opt{extra}->() if $opt{extra};
    };
}

sub probe {
    my ($log) = @_;
    $SpecProbe::LOG = $log;
    no strict 'refs';
    no warnings 'redefine';
    my $load = \&OCP::Config::_load_spec;
    *OCP::Config::_load_spec = sub {
        my $spec = $load->(@_);
        tie my %probe, 'SpecProbe', $spec;
        return \%probe;
    };
    for my $class (map { $_->[0] } @LEAVES) {
        my $check = $class->can('refuse_spec_errors') or next;
        my $paths = $class->can('spec_paths');
        *{"${class}::refuse_spec_errors"} = sub {
            local $SpecProbe::IN_CHECK = 1;
            SpecProbe::log_line('check');
            return $check->(@_);
        };
        *{"${class}::spec_paths"} = sub {
            my @p = $paths->(@_);
            SpecProbe::log_line("declared $_") for @p;
            return @p;
        };
    }
}

sub probe_log {
    my ($log) = @_;
    return -f $log ? path($log)->lines_utf8({ chomp => 1 }) : ();
}

# The sections read outside the check that the command neither declares a
# path in nor reads around on purpose.
sub undeclared {
    my ($class, @log) = @_;
    my %ok = map { /\Adeclared ([a-z_]+)/ ? ($1 => 1) : () } @log;
    $ok{$_} = 1 for @{ $READS_AROUND{$class} // [] };
    return sort grep { !$ok{$_} } map { /\Aread (.+)/ ? $1 : () } @log;
}

# --- Projects ---------------------------------------------------------------------

my %BASE = (
    name           => 'k400',
    control_planes => { provider => 'ssh', host => 'cp.k400.invalid' },
    workers        => [ { name => 'w', provider => 'ssh', host => 'w.k400.invalid' } ],
);

my $ROOT = path(tempdir(CLEANUP => 1));

sub project {
    my ($spec) = @_;
    my $dir = path(tempdir(DIR => "$ROOT"));
    OCP->dump_file($dir->child('ocp.yaml')->stringify, $spec) if defined $spec;
    return $dir;
}

sub validate_lines {
    my ($dir) = @_;
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify)->validate;
}

my $HAS_SSH_KEYGEN = system('command -v ssh-keygen >/dev/null 2>&1') == 0;

my $PIN1 = 'pin-one-k400';
my $PIN2 = 'pin-two-k400';
my ($OP_PUB) = Crypt::Age->generate_keypair;
my $OP_SSH = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK400operatorkey leitstand';

# A secure-mode project, t/346's: keys.yaml with the admin (PIN2) and robo
# keys and the operator 'leitstand', the project key behind PIN1 in
# age.key.enc only, the bootstrap key still in .ocp/. No kubeconfig: the
# operator commands go on without the cluster.
sub secure_project {
    my (%spec) = @_;
    my $origin = Path::Tiny->tempdir;
    my $s = OCP::Secrets->new(project_dir => $origin);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);
    $s->generate_ssh_key;
    my $keys = OCP::Keys->new(project_dir => $origin);
    $keys->add_cluster_keys(pin2 => $PIN2);
    $keys->add_public_key(name => 'leitstand', type => 'ssh_ed25519', purpose => 'operator',
        public => $OP_SSH, age => $OP_PUB);
    $s->create_secrets(hetzner_token => 'hz-k400');

    my $dir = project({ %BASE, %spec });
    $_->copy($dir->child($_->basename)) for grep { $_->is_file && $_->basename ne 'ocp.yaml' } $origin->children;
    $dir->child('.ocp')->mkpath;
    $origin->child('.ocp', $_)->copy($dir->child('.ocp', $_)) for qw( id_ed25519 id_ed25519.pub );
    return $dir;
}

# The PIN prompts answered, each written to $file first.
sub answering_pins {
    my ($file) = @_;
    return { 'OCP::Password::prompt_password' => sub {
        path($file)->append("$_[0]\n");
        return $_[0] =~ /PIN1/ ? $PIN1 : $PIN2;
    } };
}

my $PERL_TEXT = qr/internal error| at \S+ line \d+|(?:ARRAY|HASH)\(0x/;

sub role_text {
    my ($words, @lines) = @_;
    my $s = @lines == 1 ? '' : 's';
    return "Error: ocp.yaml has " . scalar(@lines) . " error$s:\n"
      . join('', map { "  - $_\n" } @lines)
      . "Nothing was done: $words checks what it reads of ocp.yaml before it asks for a PIN "
      . "or touches the cluster or a machine. Fix the line$s above and run it again.\n";
}

# --- 1. The role --------------------------------------------------------------------

subtest 'node add: --gpu checks gpu:, in the one text, before anything' => sub {
    my $dir = project({ %BASE, gpu => { driver => 'oprator' } });
    my @lines = validate_lines($dir);
    is scalar(@lines), 1, 'validate() has one line, for gpu.driver' or diag explain \@lines;

    my $r = run_ocp($dir, setup(), qw( node add w1 --gpu ));
    is $r->{err}, role_text('ocp node add', @lines), 'STDERR: the one text, with that line';
    is $r->{exit}, 1, 'exit 1';
    is $r->{out}, '', 'nothing on STDOUT';

    for my $argv ([ qw( node add w1 ) ], [ qw( node add w1 --gpu --nowait ) ]) {
        $r = run_ocp($dir, setup(), @$argv);
        unlike $r->{err}, qr/has \d+ errors?/, "@$argv: gpu: holds nothing up";
        like $r->{err}, qr/sweep: outside/, "@$argv: on to the cluster" or diag $r->{err};
    }
};

subtest 'an empty ocp.yaml: the file\'s one line, once' => sub {
    my $dir = project();
    $dir->child('ocp.yaml')->spew('');
    for my $argv ([ qw( node add w1 ) ],
                  [ qw( keys operator add ), @{ $ARGS_OF{'OCP::Cmd::Keys::Operator::Add'} } ],
                  [ qw( keys operator rm leitstand ) ]) {
        my $r = run_ocp($dir, setup(), @$argv);
        is $r->{err}, "Error: ocp.yaml is empty: it must be a mapping (name, control_planes and "
            . "the other settings)\n", "@$argv: the file's line";
        is $r->{exit}, 1, "@$argv: exit 1";
    }
};

subtest 'no ocp.yaml: the command\'s own words, no check' => sub {
    my $dir = project();
    my $log = $dir->child('probe.log')->stringify;
    my $r = run_ocp($dir, setup(log => $log), qw( node add w1 ));
    is $r->{err}, "Error: Config file 'ocp.yaml' not found. Run 'ocp init' first.\n",
        'node add says it';
    is $r->{exit}, 1, 'exit 1';
    ok !(grep { $_ eq 'check' } probe_log($log)), 'and checks nothing';
};

# --- 2. The keys commands -------------------------------------------------------------

SKIP: {
    skip 'needs ssh-keygen', 2 unless $HAS_SSH_KEYGEN;

    # A string there was dropped without a word (OCP::NodeMeta spec_taints)
    # and the command went on through PIN1 and PIN2 to the machines; a list
    # of one that is no taint croaked after PIN1 (parse_taint).
    subtest 'keys operator add: a pool\'s taints, before PIN1' => sub {
        for my $taints ('foo', [ 'foo' ]) {
            my $what = ref $taints ? 'taints: [ foo ]' : 'taints: foo';
            my $dir = secure_project(workers => [ { name => 'w', provider => 'ssh',
                                                    host => 'w.k400.invalid', taints => $taints } ]);
            my @lines = validate_lines($dir);
            is scalar(@lines), 1, "$what: validate() has one line, for the taints" or diag explain \@lines;

            my $prompts = $dir->child('prompts')->stringify;
            my $r = run_ocp($dir, setup(answer => answering_pins($prompts)),
                qw( keys operator add ), @{ $ARGS_OF{'OCP::Cmd::Keys::Operator::Add'} });
            is $r->{err}, role_text('ocp keys operator add', @lines),
                "$what: STDERR is the one text, with that line";
            is $r->{exit}, 1, "$what: exit 1";
            is $r->{out}, '', "$what: nothing on STDOUT";
            ok !-e $prompts, "$what: no PIN asked";
        }
    };

    subtest 'keys operator add: a control plane\'s provider that is a list' => sub {
        my $dir = secure_project(control_planes => [ { provider => [ 'a' ], host => 'cp.k400.invalid' } ]);
        my $prompts = $dir->child('prompts')->stringify;
        my $r = run_ocp($dir, setup(answer => answering_pins($prompts)),
            qw( keys operator add ), @{ $ARGS_OF{'OCP::Cmd::Keys::Operator::Add'} });
        like $r->{err}, qr/In secure mode every machine/, 'on to where the provider is said'
            or diag $r->{err};
        unlike "$r->{out}$r->{err}", qr/(?:ARRAY|HASH)\(0x/, 'said nowhere as a reference';
    };
}

# --- 3. The sweep ----------------------------------------------------------------------

# The hosts of OCPTest::Shapes, as *.invalid names.
my %INVALID = ('10.9.0.1' => 'w.k400.invalid', '10.42.0.5' => 'w42.k400.invalid',
               'w1.k355.test' => 'w1.k400.invalid');
sub invalid_hosts {
    my ($v) = @_;
    return [ map { invalid_hosts($_) } @$v ] if ref $v eq 'ARRAY';
    return { map { $_ => invalid_hosts($v->{$_}) } keys %$v } if ref $v eq 'HASH';
    return defined $v && !ref $v && exists $INVALID{$v} ? $INVALID{$v} : $v;
}

# Each key path at the first shape validate() refuses there, as
# [ path, shown, spec, [ validate()'s lines ] ].
my @MALFORMED;
for my $at (at()) {
    my ($path, $spec_with) = @$at;
    for my $shape (shapes()) {
        my ($shown, $value) = @$shape;
        my $spec = invalid_hosts({ name => 'k400', %{ $spec_with->($value) } });
        my @lines = validate_lines(project($spec));
        next unless @lines;
        push @MALFORMED, [ $path, $shown, $spec, \@lines ];
        last;
    }
}

sub argv_of {
    my ($class, $words) = @_;
    return (@$words, @{ $ARGS_OF{$class} // [] }, required_options($class),
            $class->can('json') ? '--json' : ());
}

# Is @$sub @$all with lines left out, in its order?
sub in_order {
    my ($sub, $all) = @_;
    my $i = 0;
    for my $line (@$all) { $i++ if $i < @$sub && $line eq $sub->[$i] }
    return $i == @$sub;
}

my $ROLE_TAIL = qr/Nothing was done: ocp [a-z -]+ checks what it reads of \S+ before it asks for a PIN or touches the cluster or a machine\. Fix the lines? above and run it again\./;

# What is wrong with a run of $class on a config validate() has @$lines for.
sub problems {
    my ($class, $r, $lines) = @_;
    my @p;
    push @p, "signal $r->{signal}" if $r->{signal};
    push @p, "exit $r->{exit}" unless $r->{exit} == 0 || $r->{exit} == 1;
    push @p, 'Perl text' if "$r->{out}$r->{err}" =~ $PERL_TEXT;
    my ($n, $listed, $tail) = $r->{err} =~ /^Error: \S+ has (\d+) errors?:\n((?:  - [^\n]*\n)+)(Nothing was [^\n]*)/m
        or return @p;
    my @listed = $listed =~ /^  - (.*)$/mg;
    push @p, "counts $n, lists " . @listed unless $n == @listed;
    if ($FULL{$class}) {
        push @p, 'not all of validate()\'s lines' unless join("\n", @listed) eq join("\n", @$lines);
        push @p, 'not its frame' unless $tail =~ /\ANothing was (?:done|changed): /;
    }
    else {
        push @p, 'not the role\'s text' unless $tail =~ /\A$ROLE_TAIL\z/;
        push @p, 'lines that are not validate()\'s, in its order' unless in_order(\@listed, $lines);
    }
    return @p;
}

subtest 'the sweep: every command on the check' => sub {
    my $started = Time::HiRes::time();
    my @swept = @LEAVES;
    ok @swept >= 25, 'every leaf command (' . @swept . ')';
    ok @MALFORMED > 50, 'the malformed paths (' . @MALFORMED . ')';

    for my $leaf (@swept) {
        my ($class, $words) = @$leaf;
        my @argv = argv_of($class, $words);

        # (a) the valid base
        my $dir = project({ %BASE });
        my $log = $dir->child('probe.log')->stringify;
        my $r   = run_ocp($dir, setup(log => $log), @argv);
        my @p   = problems($class, $r, []);
        my @log = probe_log($log);
        push @p, 'reads, undeclared: ' . join(', ', undeclared($class, @log))
            if !$FULL{$class} && undeclared($class, @log);
        ok !@p, "$class, a valid ocp.yaml" or diag join("\n", @p, "STDERR: $r->{err}", "probe: @log");

        # (b) every malformed path
        for my $case (@MALFORMED) {
            my ($path, $shown, $spec, $lines) = @$case;
            $r = run_ocp(project($spec), setup(), @argv);
            @p = problems($class, $r, $lines);
            ok !@p, "$class, $path: $shown"
                or diag join("\n", @p, "STDERR: $r->{err}", 'validate(): ' . join(' | ', @$lines));
        }
    }
    diag sprintf 'the sweep took %.1f s', Time::HiRes::time() - $started;
};

# --- 4. The probe itself ----------------------------------------------------------------

subtest 'the probe sees a read outside the check, not one inside' => sub {
    my $dir = project({ %BASE });
    my $log = $dir->child('probe.log')->stringify;
    my $r = run_ocp($dir, setup(log => $log, extra => sub {
        no warnings 'redefine';
        *OCP::Cmd::Node::Add::_k8s = sub {
            my $cilium = OCP::Config->new(file => 'ocp.yaml')->spec->{cilium};
            die "probe: read\n";
        };
    }), qw( node add w1 ));
    is $r->{err}, "Error: probe: read\n", 'the run got there' or diag $r->{err};
    my @log = probe_log($log);
    ok((grep { $_ eq 'check' } @log), 'the check ran') or diag explain \@log;
    ok((grep { /\Adeclared / } @log), 'the paths were written down');
    ok((grep { $_ eq 'read cilium' } @log), 'the read after it was');
    is_deeply [ undeclared('OCP::Cmd::Node::Add', @log) ], [ 'cilium' ], 'and is undeclared';
    ok !(grep { $_ eq 'read lbipam' } @log), 'the check\'s own read of lbipam is not';
};

# --- 5. update and destroy --------------------------------------------------------------

# A project ocp update goes on with: status.yaml at an OCP version older than
# any OCP::Versions knows, so every component has an update planned, and
# kubernetes.version pinned in ocp.yaml, so the distribution is skipped (its
# moved pin is a refusal of its own, k165, that would stop the run first).
sub deployed_project {
    my (%spec) = @_;
    my $rke2 = OCP::Versions->get_component_version('rke2');
    my $dir = project({ %BASE, kubernetes => { version => $rke2 }, %spec });
    $dir->child('.ocp')->mkpath;
    $dir->child('.ocp', 'status.yaml')->spew_utf8("ocpVersion: '0.000'\n");
    return $dir;
}

# Each component update would run is written down instead of run.
subtest 'update: cilium: and network: before any component' => sub {
    for my $case ([ cilium => 'foo' ], [ network => 'foo' ]) {
        my ($key, $value) = @$case;
        my $dir = deployed_project($key => $value);
        my @lines = validate_lines($dir);
        is scalar(@lines), 1, "$key: $value: validate() has one line" or diag explain \@lines;

        my $ran = $dir->child('ran')->stringify;
        my $r = run_ocp($dir, setup(extra => sub {
            require OCP::Cmd::Update;
            no warnings 'redefine';
            *OCP::Cmd::Update::_update_component = sub { path($ran)->append("$_[2]{component}\n") };
        }), qw( update ));
        is $r->{err}, role_text('ocp update', @lines), "$key: $value: STDERR is the one text";
        is $r->{exit}, 1, "$key: $value: exit 1";
        is $r->{out}, '', "$key: $value: no plan on STDOUT";
        ok !-e $ran, "$key: $value: no component ran" or diag path($ran)->slurp_utf8;
    }
};

# Destroy is the way out of a cluster: a line it does not read holds no
# teardown up.
subtest 'destroy: cilium: foo holds nothing up' => sub {
    my $dir = project({ %BASE, cilium => 'foo' });
    ok scalar(validate_lines($dir)), 'validate() refuses the file';
    my $r = run_ocp($dir, setup(), qw( destroy ));
    unlike $r->{err}, qr/has \d+ errors?:/, 'no refusal' or diag $r->{err};
    like $r->{err}, qr/sweep: outside/, 'on to the cluster' or diag $r->{err};
};

# --- 6. status and version --------------------------------------------------------------

# Refused up front, not a report that stops where it reads network: (k394).
subtest 'status: network: foo, in both forms, before the report' => sub {
    my $dir = project({ %BASE, network => 'foo' });
    my @lines = validate_lines($dir);
    is scalar(@lines), 1, 'validate() has one line, for network:' or diag explain \@lines;
    my $text = role_text('ocp status', @lines);

    my $r = run_ocp($dir, setup(), qw( status ));
    is $r->{err}, $text, 'STDERR: the one text, with that line';
    is $r->{exit}, 1, 'exit 1';
    is $r->{out}, '', 'no report begun on STDOUT';

    (my $error = $text) =~ s/\AError: //;
    $error =~ s/\n\z//;
    $r = run_ocp($dir, setup(), qw( status --json ));
    my $doc = eval { JSON::MaybeXS->new->decode($r->{out}) };
    is_deeply $doc, { error => $error }, '--json: STDOUT is the one JSON error object'
        or diag "STDOUT: $r->{out}";
    is $r->{err}, $text, '--json: STDERR says it';
    is $r->{exit}, 1, '--json: exit 1';
};

# A section status does not declare -- does not read, or reads around
# (%READS_AROUND) -- holds no report up: each such section of
# OCPTest::Shapes at its first refused shape.
subtest 'status: a line in a section it does not declare' => sub {
    my $config = OCP::Config->new(file => project({ %BASE })->child('ocp.yaml')->stringify);
    my %declared = map { /\A([a-z_]+)/ ? ($1 => 1) : () } OCP::Cmd::Status->spec_paths($config);
    my %seen;
    my @cases = grep {
        my ($section) = $_->[0] =~ /\A([a-z_]+)/;
        !$declared{$section} && !$seen{$section}++;
    } @MALFORMED;
    ok @cases, 'sections status does not declare: ' . join(', ', sort keys %seen);
    for my $case (@cases) {
        my ($path, $shown, $spec) = @$case;
        my $r = run_ocp(project($spec), setup(), qw( status ));
        unlike $r->{err}, qr/has \d+ errors?:/, "$path: $shown: no refusal" or diag $r->{err};
        is $r->{exit}, 0, "$path: $shown: the report, exit 0" or diag $r->{err};
        like $r->{out}, qr/^No cluster deployed yet\./m, "$path: $shown: to its end";
    }
};

# --- 7. the rest ------------------------------------------------------------------------

# A cluster API that writes down each resource it is to ensure, by kind and
# clusterName, instead of sending it.
package WrittenCRs {
    sub new { my ($class, $file) = @_; return bless { file => $file }, $class }
    sub ensure {
        my ($self, $doc) = @_;
        open my $fh, '>>', $self->{file} or die "written: $!";
        print {$fh} "$doc->{kind} " . ($doc->{spec}{clusterName} // '-') . "\n";
        close $fh or die "written: $!";
        return $doc;
    }
}

package main;

# Refused before the provider is written, where it wrote clusterName
# ARRAY(0x...) (k306).
subtest 'provider add: a name that is a list' => sub {
    my $dir = project({ %BASE, name => [ 'a' ] });
    my @lines = validate_lines($dir);
    is scalar(@lines), 1, 'validate() has one line, for the name' or diag explain \@lines;

    my $written = $dir->child('written')->stringify;
    my $r = run_ocp($dir, setup(answer => {
        'OCP::Role::Cmd::cluster_api' => sub { WrittenCRs->new($written) },
    }), qw( provider add --name p --type ssh ));
    is $r->{err}, role_text('ocp provider add', @lines), 'STDERR: the one text, with that line';
    is $r->{exit}, 1, 'exit 1';
    is $r->{out}, '', 'nothing on STDOUT';
    ok !-e $written, 'no provider written'
        or diag path($written)->slurp_utf8;
};

subtest 'deploy-robocop: a network.pod_cidr that is a list' => sub {
    my $dir = project({ %BASE, network => { pod_cidr => [ 'a' ] } });
    my @lines = validate_lines($dir);
    is scalar(@lines), 1, 'validate() has one line, for the pod CIDR' or diag explain \@lines;

    my $r = run_ocp($dir, setup(), qw( deploy-robocop ));
    is $r->{err}, role_text('ocp deploy-robocop', @lines), 'STDERR: the one text, in its words';
    is $r->{exit}, 1, 'exit 1';
    is $r->{out}, '', 'nothing on STDOUT';
};

subtest 'node ls: a pool\'s taints: foo' => sub {
    my $dir = project({ %BASE, workers => [ { %{ $BASE{workers}[0] }, taints => 'foo' } ] });
    my @lines = validate_lines($dir);
    is scalar(@lines), 1, 'validate() has one line, for the taints' or diag explain \@lines;
    my $text = role_text('ocp node ls', @lines);
    (my $error = $text) =~ s/\AError: //;
    $error =~ s/\n\z//;

    my $r = run_ocp($dir, setup(), qw( node ls --json ));
    my $doc = eval { JSON::MaybeXS->new->decode($r->{out}) };
    is_deeply $doc, { error => $error }, '--json: STDOUT is the one JSON error object'
        or diag "STDOUT: $r->{out}";
    is $r->{err}, $text, '--json: STDERR says it';
    is $r->{exit}, 1, '--json: exit 1';

    # The table reads no pool: on to the cluster.
    $r = run_ocp($dir, setup(), qw( node ls ));
    unlike $r->{err}, qr/has \d+ errors?:/, 'without --json: no refusal' or diag $r->{err};
    like $r->{err}, qr/sweep: outside/, 'without --json: on to the cluster' or diag $r->{err};
};

# The commands whose reads the sweep does not reach -- each stops at a way
# out, a missing kubeconfig.yaml or a flag before it reads ocp.yaml -- with a
# value validate() refuses in a section they read: refused in their words;
# and with the option under which they do not read it: not refused.
# [ argv, spec, words (undef: no refusal) ].
my @BEHIND_A_WAY_OUT = (
    [ [qw( deploy-image --tag t )],                    { name => [ 'a' ] },  'ocp deploy-image' ],
    [ [qw( inject-key )],      { robocop => { security_level => [ 'a' ] } }, 'ocp inject-key' ],
    [ [qw( init --nogit )],                      { control_planes => 'foo' }, 'ocp init' ],
    [ [qw( init --nogit --force )],              { control_planes => 'foo' }, undef ],
    [ [qw( kubeconfig --export )],                     { name => [ 'a' ] },  'ocp kubeconfig' ],
    [ [qw( kubeconfig )],                              { name => [ 'a' ] },  undef ],
    [ [qw( ssh --node x )],                            { ssh => 'foo' },     'ocp ssh' ],
    [ [qw( keys authorized-keys )],                    { ssh => 'foo' },     'ocp keys authorized-keys' ],
    [ [qw( keys authorized-keys --purpose operator )], { ssh => 'foo' },     undef ],
    [ [qw( node rm w1 )],                              { ssh => 'foo' },     'ocp node rm' ],
    [ [qw( node rm w1 --keep-machine )],               { ssh => 'foo' },     undef ],
);

subtest 'what the sweep does not reach: refused where read, not where not' => sub {
    for my $case (@BEHIND_A_WAY_OUT) {
        my ($argv, $spec, $words) = @$case;
        my $dir = project({ %BASE, %$spec });
        my @lines = validate_lines($dir);
        my $what = "@$argv";
        is scalar(@lines), 1, "$what: validate() has one line" or diag explain \@lines;
        my $r = run_ocp($dir, setup(), @$argv);
        if (defined $words) {
            is $r->{err}, role_text($words, @lines), "$what: refused, in its words";
            is $r->{exit}, 1, "$what: exit 1";
        }
        else {
            unlike $r->{err}, qr/has \d+ errors?:/, "$what: no refusal" or diag $r->{err};
        }
        unlike "$r->{out}$r->{err}", $PERL_TEXT, "$what: no Perl text" or diag $r->{err};
    }
};

done_testing;

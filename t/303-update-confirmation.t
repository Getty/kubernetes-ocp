#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

BEGIN { $ENV{ANSI_COLORS_DISABLED} = 1 }

use OCP;
use OCP::Cmd::Update;
use OCP::Config;
use OCP::Rex;
use OCP::Versions;

#
# k303: when the version manifest lists manual steps, `ocp update` asked
# "Manual steps required. Continue? [y/N]: " on STDOUT and read <STDIN>
# without looking at what STDIN was. A piped `y` -- a here-string, `yes |`, a
# CI step -- confirmed, Ctrl-D warned "uninitialized value in chomp", and
# /^y/i took "yep" and "yikes" for a yes.
#
# What it must do instead, as `ocp node trust-host` (k293) and `ocp destroy`
# (k301) do:
#
#   * without a terminal, not read STDIN at all: say on STDERR that it needs
#     a person at a terminal, exit 1, and change nothing -- no Rex task, no
#     version stamp. ocp update has no switch that confirms without a
#     terminal (its --force means "even if the versions match"), so the
#     refusal names none;
#   * on a terminal, ask on STDERR (a prompt is not payload) and go on only on
#     y/yes; a "no" or an EOF is an abort, exit 1, nothing changed;
#   * an update without manual steps, and a --dry-run, ask nothing.
#
# The terminal is stood in for by the _interactive attribute: an in-memory
# STDIN is no terminal, so the real `-t STDIN` check is asserted on its own.
# Mock-based: OCP::Rex is replaced by a recorder, no SSH, no cluster.
#

my $CURRENT = $OCP::VERSION;
my %PINS    = %{ OCP::Versions->get_versions($CURRENT)->{components} };

{
    package FakeOcp;
    sub new     { my ($class, %args) = @_; bless {%args}, $class }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# A deployed dev-mode project stamped '0.000', with the bootstrap key dev mode
# reaches the control plane with.
sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(<<'YAML');
name: updatetest
control_planes:
  provider: hetzner
  public_ip: 1.2.3.4
YAML
    $dir->child('kubeconfig.yaml')->spew_utf8("encrypted-placeholder\n");
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nBOOT\n");
    $dir->child('.ocp', 'status.yaml')->spew_utf8(<<'YAML');
ocpVersion: '0.000'
nodes:
  - name: police1
    provider: hetzner
    public_ip: 1.2.3.4
YAML
    return $dir->child('ocp.yaml')->stringify;
}

my $STEP = 'Drain the GPU nodes before the update.';

# The cluster is on '0.000', whose Cilium pin is older than this OCP's, so
# the update runs upgrade_cilium. With %a{steps} (the default) this OCP's
# manifest lists a manual step.
sub with_manifests {
    my ($code, %a) = @_;
    my $steps = exists $a{steps} ? $a{steps} : 1;
    local $OCP::Versions::VERSIONS = {
        %$OCP::Versions::VERSIONS,
        '0.000'  => { components => { %PINS, cilium => '1.0.0' } },
        $CURRENT => {
            %{ $OCP::Versions::VERSIONS->{$CURRENT} },
            ($steps ? (manual_steps => [ $STEP ]) : ()),
        },
    };
    return $code->();
}

# Runs `ocp update` with STDIN fed from $a{stdin} (undef: a closed handle).
# What is left unread on STDIN comes back as {rest}, so "STDIN was not read"
# is an assertion, not an inference.
sub run_update {
    my ($file, %a) = @_;
    my @tasks;

    my $cmd = OCP::Cmd::Update->new(
        command_chain => [ FakeOcp->new(config => $file) ],
        ($a{dry_run} ? (dry_run => 1) : ()),
        (exists $a{interactive} ? (_interactive => $a{interactive}) : ()),
    );

    my ($out, $err) = ('', '');
    my @warnings;
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my ($in, $rest);
    if (defined $a{stdin}) {
        open $in, '<', \$a{stdin} or die;
    } else {
        open $in, '<', \'' or die;
        close $in;
    }
    my @ret = do {
        local *STDIN  = $in;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        local $SIG{__WARN__} = sub { push @warnings, @_ };
        no warnings 'redefine';
        local *OCP::Rex::new      = sub { my ($c, %r) = @_; bless {%r}, $c };
        local *OCP::Rex::run_task = sub { push @tasks, $_[1]; 1 };
        local *OCP::Cmd::Update::_update_via_api = sub { push @tasks, $_[4]; 1 };
        my @r = eval { $cmd->execute([], []) };
        $rest = defined $a{stdin} ? do { local $/; <STDIN> } : undef;
        @r;
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0],
             rest => $rest, tasks => \@tasks, warnings => \@warnings };
}

sub stamped { OCP::Config->new(file => $_[0])->status->{ocpVersion} }

# Nothing ran and the cluster keeps its old stamp.
sub unchanged {
    my ($r, $file) = @_;
    is_deeply $r->{tasks}, [], 'no Rex task ran';
    is stamped($file), '0.000', 'the version stamp is unchanged';
    unlike $r->{out}, qr/Starting updates|updates completed/,
        'no update narrative on STDOUT';
}

my $NO_TERMINAL = qr/^No terminal to confirm on: updating cluster 'updatetest' with manual steps needs a person at a terminal\.$/m;
# Unanchored: on a terminal the answer echoes the newline after the prompt;
# the in-memory STDIN does not, so the abort follows the prompt on its line.
my $ABORTED     = qr/Aborted; nothing was changed\.\n/;
my $PROMPT      = qr/Manual steps required\. Continue\? \[y\/N\] /;

# ------------------------------------------------------- without a terminal

subtest 'a piped y is no confirmation' => sub {
    with_manifests(sub {
        my $file = project();
        my $r = run_update($file, stdin => "y\n", interactive => 0);

        is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
        is $r->{ret}, 1, 'exit 1';
        is $r->{rest}, "y\n", 'STDIN was not read';
        like $r->{err}, $NO_TERMINAL, 'STDERR says a person at a terminal is needed';
        unlike $r->{err}, qr/--/, 'and names no switch: ocp update has none';
        like $r->{err}, $ABORTED, 'and that nothing was changed';
        unlike $r->{err}.$r->{out}, $PROMPT, 'no question nobody can answer';
        like $r->{out}, qr/\Q$STEP\E/, 'the manual steps are still shown';
        unchanged($r, $file);
        is_deeply $r->{warnings}, [], 'no warnings';
    });
};

subtest 'the real check: an in-memory STDIN is no terminal' => sub {
    # No stand-in: the builder's own -t STDIN decides.
    with_manifests(sub {
        my $file = project();
        my $r = run_update($file, stdin => "yes\n");

        is $r->{ret}, 1, 'exit 1';
        is $r->{rest}, "yes\n", 'STDIN was not read';
        like $r->{err}, $NO_TERMINAL, 'refused for want of a terminal';
        unchanged($r, $file);
    });
};

subtest 'a closed STDIN is no terminal either' => sub {
    with_manifests(sub {
        my $file = project();
        my $r = run_update($file, stdin => undef);

        is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
        is $r->{ret}, 1, 'exit 1';
        like $r->{err}, $NO_TERMINAL, 'refused for want of a terminal';
        like $r->{err}, $ABORTED, 'and says nothing was changed';
        unchanged($r, $file);
        is_deeply $r->{warnings}, [], 'no warnings';
    });
};

# ------------------------------------------------------- on a terminal

subtest 'on a terminal, y updates -- the question on STDERR' => sub {
    with_manifests(sub {
        my $file = project();
        my $r = run_update($file, stdin => "y\n", interactive => 1);

        is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
        is $r->{ret}, 0, 'exit 0' or diag "OUT:\n$r->{out}\nERR:\n$r->{err}";
        like   $r->{err}, $PROMPT, 'the question is asked on STDERR';
        unlike $r->{out}, $PROMPT, 'not on the payload channel';
        unlike $r->{err}, $NO_TERMINAL, 'no refusal';
        is $r->{rest} // '', '', 'the answer was read';
        ok( (grep { $_ eq 'upgrade_cilium' } @{ $r->{tasks} }), 'the update ran' );
        is stamped($file), $CURRENT, 'and stamped the new version';
    });
};

subtest 'on a terminal, yes (any case, padded) updates too' => sub {
    with_manifests(sub {
        for my $answer ("YES\n", "  y  \n", "Yes\n") {
            my $file = project();
            my $r = run_update($file, stdin => $answer, interactive => 1);
            (my $shown = $answer) =~ s/\n/\\n/;
            is $r->{ret}, 0, "'$shown': exit 0";
            is stamped($file), $CURRENT, "'$shown': updated";
        }
    });
};

subtest 'on a terminal, n aborts with exit 1 and changes nothing' => sub {
    with_manifests(sub {
        my $file = project();
        my $r = run_update($file, stdin => "n\n", interactive => 1);

        is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
        is $r->{ret}, 1, 'exit 1';
        like $r->{err}, $PROMPT, 'the question was asked';
        like $r->{err}, $ABORTED, 'the abort is said on STDERR';
        unlike $r->{out}, qr/Aborted|cancelled/, 'not on STDOUT';
        is $r->{rest} // '', '', 'the answer was read';
        unchanged($r, $file);
    });
};

subtest 'on a terminal, anything but y/yes is a no' => sub {
    with_manifests(sub {
        for my $answer ("\n", "yep\n", "yikes\n", "no\n", "sure\n") {
            my $file = project();
            my $r = run_update($file, stdin => $answer, interactive => 1);
            (my $shown = $answer) =~ s/\n/\\n/;
            is $r->{ret}, 1, "'$shown': exit 1";
            is_deeply $r->{tasks}, [], "'$shown': nothing ran";
        }
    });
};

subtest 'on a terminal, EOF (Ctrl-D) aborts without a warning' => sub {
    with_manifests(sub {
        my $file = project();
        my $r = run_update($file, stdin => '', interactive => 1);

        is $r->{ret}, 1, 'exit 1';
        like $r->{err}, $ABORTED, 'aborted';
        unchanged($r, $file);
        is_deeply $r->{warnings}, [], 'no "uninitialized value in chomp" warning';
    });
};

# ------------------------------------------------------- nothing to confirm

subtest 'no manual steps: no question, STDIN not read' => sub {
    with_manifests(sub {
        my $file = project();
        my $r = run_update($file, stdin => "n\n", interactive => 0);

        is $r->{ret}, 0, 'exit 0' or diag "OUT:\n$r->{out}\nERR:\n$r->{err}";
        is $r->{rest}, "n\n", 'STDIN was not read';
        unlike $r->{err}.$r->{out}, $PROMPT, 'no question';
        unlike $r->{err}, $NO_TERMINAL, 'no refusal';
        is stamped($file), $CURRENT, 'updated';
    }, steps => 0);
};

subtest '--dry-run with manual steps asks nothing and changes nothing' => sub {
    with_manifests(sub {
        my $file = project();
        my $r = run_update($file, stdin => "y\n", interactive => 0, dry_run => 1);

        is $r->{ret}, 0, 'exit 0';
        is $r->{rest}, "y\n", 'STDIN was not read';
        unlike $r->{err}.$r->{out}, $PROMPT, 'no question';
        unlike $r->{err}, $NO_TERMINAL, 'no refusal';
        like $r->{out}, qr/Dry-run mode/, 'a dry run';
        unchanged($r, $file);
    });
};

done_testing;

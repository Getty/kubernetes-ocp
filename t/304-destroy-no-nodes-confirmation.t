#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Cmd::Destroy;
use OCP::Config;

#
# k304: when `ocp destroy` found no nodes it printed "No nodes to destroy."
# and removed .ocp/status.yaml, .ocp/deployed.yaml and the encrypted
# kubeconfig.yaml at once -- terminal or not, with no question. That cleanup
# came from k78 (state left behind after an out-of-band teardown). But an
# empty node list can also be a stale status.yaml or a read that failed while
# the cluster is alive, and the kubeconfig is the way into it.
#
# What it must do instead, the way the main path does since k301:
#
#   * without a terminal, not read STDIN at all: say on STDERR that removing
#     the local state needs a person at a terminal or --force, exit 1, remove
#     nothing;
#   * on a terminal, ask on STDERR, naming the files, and remove them only on
#     y/yes; a "no" or an EOF is an abort, exit 1, nothing removed;
#   * with --force, never ask and never read STDIN: k78's case is still
#     cleaned up (t/47 and t/107 hold that claim with --force);
#   * --keep_status keeps status.yaml and deployed.yaml as before; the
#     question then names only what is left to remove, the kubeconfig;
#   * nothing to remove: nothing to ask.
#
# The terminal is stood in for by the _interactive attribute: an in-memory
# STDIN is no terminal, so the real `-t STDIN` check is asserted on its own.
#

# ---------------------------------------------------------------- stubs

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# One log for every fake: the no-nodes path must reach neither a provider
# delete nor the robocop scale-down, asked or not.
my @events;

{
    package FakeHetzner;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub list_servers_by_cluster { [] }
    sub delete_server { push @events, [ delete => $_[1] ]; 1 }
}

{
    package FakeList;
    sub new   { my ($c, @i) = @_; bless { items => [@i] }, $c }
    sub items { $_[0]{items} }
}
{
    package FakeK8s;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list { FakeList->new }
    sub patch { push @events, [ patch => $_[1], $_[2] ]; 1 }
}

# k78's shape: a cluster torn down out of band. status.yaml says `nodes: []`,
# the spec names no machine, Hetzner has nothing under the label, the API has
# no OCPNode -- and the three files a teardown removes are still there, unless
# %a says which to leave out.
sub project {
    my (%a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: prod\ncontrol_planes: []\nworkers: []\n");
    $dir->child('.ocp', 'status.yaml')->spew_utf8("nodes: []\n")
        unless $a{no_status};
    $dir->child('.ocp', 'deployed.yaml')->spew_utf8("registry: abc\n")
        unless $a{no_status};
    $dir->child('kubeconfig.yaml')->spew_utf8("sops: encrypted\n")
        unless $a{no_kubeconfig};
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub status_files {
    my ($config) = @_;
    return ($config->status_file, $config->deployed_file);
}
sub kubeconfig { $_[0]->project_dir->child('kubeconfig.yaml') }

# Runs execute with STDIN fed from $a{stdin} (undef: a closed handle). What
# is left unread on STDIN comes back as {rest}, so "STDIN was not read" is an
# assertion, not an inference.
sub run_destroy {
    my ($config, %a) = @_;
    @events = ();

    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        k8s           => FakeK8s->new,
        ($a{force}       ? (force       => 1) : ()),
        ($a{keep_status} ? (keep_status => 1) : ()),
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
    my $fake = FakeHetzner->new;
    my @ret = do {
        local *STDIN  = $in;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        local $SIG{__WARN__} = sub { push @warnings, @_ };
        no warnings 'redefine';
        local *OCP::Provider::for_spec = sub { $fake };
        local *OCP::Secrets::hetzner_token = sub { 'tok' };
        my @r = eval { $cmd->execute([], []) };
        $rest = defined $a{stdin} ? do { local $/; <STDIN> } : undef;
        @r;
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0],
             rest => $rest, events => [@events], warnings => \@warnings };
}

# Every state file still there, nothing announced as removed.
sub kept {
    my ($r, $config) = @_;
    ok -f $_, path($_)->basename.' is kept' for status_files($config), kubeconfig($config);
    unlike $r->{out}, qr/Removed |kubeconfig removed/, 'no removal announced on STDOUT';
}

my $ALL = '.ocp/status.yaml, .ocp/deployed.yaml, kubeconfig.yaml';

my $NO_TERMINAL = qr/^No terminal to confirm on: removing the local state of cluster 'prod' \(\Q$ALL\E\) needs a person at a terminal, or --force\.$/m;
# Unanchored: on a terminal the answer echoes the newline after the prompt;
# the in-memory STDIN does not, so the abort follows the prompt on its line.
my $ABORTED     = qr/Aborted; nothing was removed\.\n/;
my $PROMPT      = qr/Remove the local state of cluster 'prod' \(\Q$ALL\E\)\? \[y\/N\] /;
my $ANY_PROMPT  = qr/Remove the local state|\[y\/N\]/;

# ------------------------------------------------------- without a terminal

subtest 'a piped y removes nothing' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => "y\n", interactive => 0);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 1, 'exit 1';
    is $r->{rest}, "y\n", 'STDIN was not read';
    like $r->{out}, qr/^No nodes to destroy\.$/m, 'says no nodes were found, on STDOUT';
    like $r->{err}, $NO_TERMINAL, 'STDERR names the files and asks for a terminal or --force';
    like $r->{err}, $ABORTED, 'and says nothing was removed';
    unlike $r->{err}.$r->{out}, $ANY_PROMPT, 'no question nobody can answer';
    kept($r, $config);
    is_deeply $r->{events}, [], 'no provider delete, no robocop scale-down';
    is_deeply $r->{warnings}, [], 'no warnings';
};

subtest 'the real check: an in-memory STDIN is no terminal' => sub {
    # No stand-in: the builder's own -t STDIN decides.
    my $config = project();
    my $r = run_destroy($config, stdin => "yes\n");

    is $r->{ret}, 1, 'exit 1';
    is $r->{rest}, "yes\n", 'STDIN was not read';
    like $r->{err}, $NO_TERMINAL, 'refused for want of a terminal';
    kept($r, $config);
};

subtest 'a closed STDIN is no terminal either' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => undef);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 1, 'exit 1';
    like $r->{err}, $NO_TERMINAL, 'refused for want of a terminal';
    like $r->{err}, $ABORTED, 'and says nothing was removed';
    kept($r, $config);
    is_deeply $r->{warnings}, [], 'no warnings';
};

# ------------------------------------------------------- on a terminal

subtest 'on a terminal, y removes the state -- the question names it, on STDERR' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => "y\n", interactive => 1);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    like   $r->{err}, $PROMPT, 'the question names every file, on STDERR';
    unlike $r->{out}, $ANY_PROMPT, 'not on the payload channel';
    unlike $r->{err}, $NO_TERMINAL, 'no refusal';
    is $r->{rest} // '', '', 'the answer was read';
    ok !-f $_, path($_)->basename.' is removed' for status_files($config), kubeconfig($config);
    like $r->{out}, qr/Removed status\.yaml\.\nRemoved deployed\.yaml\.\nEncrypted kubeconfig removed\./,
        'each removal is said on STDOUT, as before';
    is_deeply $r->{events}, [], 'no provider delete, no robocop scale-down';
};

subtest 'on a terminal, yes (any case) removes it too' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => "YES\n", interactive => 1);
    is $r->{ret}, 0, 'exit 0';
    ok !-f kubeconfig($config), 'removed';
};

subtest 'on a terminal, n aborts with exit 1 and removes nothing' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => "n\n", interactive => 1);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 1, 'exit 1';
    like $r->{err}, $PROMPT, 'the question was asked';
    like $r->{err}, $ABORTED, 'the abort is said on STDERR';
    unlike $r->{out}, qr/Aborted/, 'not on STDOUT';
    is $r->{rest} // '', '', 'the answer was read';
    kept($r, $config);
};

subtest 'on a terminal, anything but y/yes is a no' => sub {
    for my $answer ("\n", "yep\n", "no\n", "sure\n") {
        my $config = project();
        my $r = run_destroy($config, stdin => $answer, interactive => 1);
        (my $shown = $answer) =~ s/\n/\\n/;
        is $r->{ret}, 1, "'$shown': exit 1";
        ok -f kubeconfig($config), "'$shown': the kubeconfig is kept";
    }
};

subtest 'on a terminal, EOF (Ctrl-D) aborts without a warning' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => '', interactive => 1);

    is $r->{ret}, 1, 'exit 1';
    like $r->{err}, $ABORTED, 'aborted';
    kept($r, $config);
    is_deeply $r->{warnings}, [], 'no "uninitialized value" warning';
};

# ------------------------------------------------------- --force

subtest '--force removes it without asking: k78 still cleaned up' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => "n\n", interactive => 0, force => 1);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    is $r->{rest}, "n\n", 'STDIN was not read';
    unlike $r->{err}.$r->{out}, $ANY_PROMPT, 'no question';
    unlike $r->{err}, $NO_TERMINAL, 'no refusal';
    ok !-f $_, path($_)->basename.' is removed' for status_files($config), kubeconfig($config);
};

# ------------------------------------------------------- --keep_status

subtest '--keep_status: the question names only the kubeconfig' => sub {
    my $only = qr/Remove the local state of cluster 'prod' \(kubeconfig\.yaml\)\? \[y\/N\] /;

    my $config = project();
    my $r = run_destroy($config, stdin => "y\n", interactive => 1, keep_status => 1);
    is $r->{ret}, 0, 'y: exit 0';
    like $r->{err}, $only, 'the question names the kubeconfig alone';
    ok -f $_, path($_)->basename.' is kept, as --keep_status says' for status_files($config);
    ok !-f kubeconfig($config), 'the kubeconfig is removed, as before';

    $config = project();
    $r = run_destroy($config, stdin => "n\n", interactive => 1, keep_status => 1);
    is $r->{ret}, 1, 'n: exit 1';
    kept($r, $config);

    $config = project();
    $r = run_destroy($config, stdin => "y\n", interactive => 0, keep_status => 1);
    is $r->{ret}, 1, 'no terminal: exit 1';
    like $r->{err}, qr/^No terminal to confirm on: removing the local state of cluster 'prod' \(kubeconfig\.yaml\) needs a person at a terminal, or --force\.$/m,
        'the refusal names the kubeconfig alone';
    kept($r, $config);

    $config = project();
    $r = run_destroy($config, stdin => "n\n", interactive => 0, keep_status => 1, force => 1);
    is $r->{ret}, 0, '--force: exit 0';
    is $r->{rest}, "n\n", 'STDIN was not read';
    ok -f $_, path($_)->basename.' is kept' for status_files($config);
    ok !-f kubeconfig($config), 'the kubeconfig is removed';
};

# ------------------------------------------------------- nothing to remove

subtest 'nothing to remove: nothing to ask' => sub {
    my $config = project(no_status => 1, no_kubeconfig => 1);
    my $r = run_destroy($config, stdin => "n\n", interactive => 0);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    is $r->{rest}, "n\n", 'STDIN was not read';
    is $r->{err}, '', 'nothing on STDERR';
    like $r->{out}, qr/No nodes to destroy\./, 'says no nodes were found';

    # --keep_status leaves only files it keeps: nothing to remove either.
    $config = project(no_kubeconfig => 1);
    $r = run_destroy($config, stdin => "n\n", interactive => 0, keep_status => 1);
    is $r->{ret}, 0, '--keep_status, no kubeconfig: exit 0';
    is $r->{rest}, "n\n", 'STDIN was not read';
    is $r->{err}, '', 'nothing on STDERR';
    ok -f $_, path($_)->basename.' is kept' for status_files($config);
};

done_testing;

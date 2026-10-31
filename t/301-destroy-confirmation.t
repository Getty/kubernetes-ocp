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
# k301: `ocp destroy` asked "Are you sure you want to destroy this cluster?
# [y/N]" on STDOUT and read <STDIN> without looking at what STDIN was. A
# piped `y` -- a here-string, `yes |`, a CI step -- confirmed deleting paid
# servers, and the question landed on the payload channel.
#
# What it must do instead, as `ocp node trust-host` does since k293:
#
#   * without a terminal, not read STDIN at all: say on STDERR that it needs
#     a person at a terminal or --force, exit 1, and delete nothing -- no
#     server, no robocop scale-down, no local state;
#   * on a terminal, ask on STDERR (a prompt is not payload) and go on only
#     on y/yes; a "no" or an EOF is an abort, exit 1, nothing touched;
#   * with --force, never ask and never read STDIN.
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

# One log for every fake, so "nothing happened" covers the provider delete
# and the robocop scale-down alike.
my @events;

{
    package FakeHetzner;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub list_servers_by_cluster { [] }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        push @events, [ delete => $id ];
        return 1;
    }
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
    sub patch {
        my ($self, $kind, $name, %a) = @_;
        push @events, [ patch => $kind, $name ];
        return 1;
    }
}

my $STATUS = <<'YAML';
nodes:
  - name: police1
    provider: hetzner
    providerId: "111"
    public_ip: 1.1.1.1
YAML

# A project with all three files a teardown removes, so "no state is
# touched" is checked on each of them.
sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: prod\n");
    $dir->child('.ocp', 'status.yaml')->spew_utf8($STATUS);
    $dir->child('.ocp', 'deployed.yaml')->spew_utf8("registry: abc\n");
    $dir->child('kubeconfig.yaml')->spew_utf8("sops: encrypted\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub state_files {
    my ($config) = @_;
    return ($config->status_file, $config->deployed_file,
            $config->project_dir->child('kubeconfig.yaml'));
}

# Runs execute with STDIN fed from $a{stdin} (undef: a closed handle). What
# is left unread on STDIN comes back as {rest}, so "STDIN was not read" is an
# assertion, not an inference.
sub run_destroy {
    my ($config, %a) = @_;
    @events = ();

    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        k8s           => FakeK8s->new,
        ($a{force} ? (force => 1) : ()),
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

# Nothing deleted, nothing scaled down, every state file still there.
sub untouched {
    my ($r, $config) = @_;
    is_deeply $r->{events}, [], 'no server deleted, robocop not scaled down';
    ok -f $_, path($_)->basename.' is kept' for state_files($config);
    unlike $r->{out}, qr/Deleting|Cluster destroyed|Removed /,
        'no teardown narrative on STDOUT';
}

my $NO_TERMINAL = qr/^No terminal to confirm on: destroying cluster 'prod' needs a person at a terminal, or --force\.$/m;
# Unanchored: on a terminal the answer echoes the newline after the prompt;
# the in-memory STDIN does not, so the abort follows the prompt on its line.
my $ABORTED     = qr/Aborted; nothing was deleted\.\n/;
my $PROMPT      = qr/Are you sure you want to destroy this cluster\? \[y\/N\] /;

# ------------------------------------------------------- without a terminal

subtest 'a piped y is no confirmation' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => "y\n", interactive => 0);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 1, 'exit 1';
    is $r->{rest}, "y\n", 'STDIN was not read';
    like $r->{err}, $NO_TERMINAL, 'STDERR says a terminal or --force is needed';
    like $r->{err}, $ABORTED, 'and that nothing was deleted';
    unlike $r->{err}.$r->{out}, $PROMPT, 'no question nobody can answer';
    untouched($r, $config);
    is_deeply $r->{warnings}, [], 'no warnings';
};

subtest 'the real check: an in-memory STDIN is no terminal' => sub {
    # No stand-in: the builder's own -t STDIN decides.
    my $config = project();
    my $r = run_destroy($config, stdin => "yes\n");

    is $r->{ret}, 1, 'exit 1';
    is $r->{rest}, "yes\n", 'STDIN was not read';
    like $r->{err}, $NO_TERMINAL, 'refused for want of a terminal';
    untouched($r, $config);
};

subtest 'a closed STDIN is no terminal either' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => undef);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 1, 'exit 1';
    like $r->{err}, $NO_TERMINAL, 'refused for want of a terminal';
    like $r->{err}, $ABORTED, 'and says nothing was deleted';
    untouched($r, $config);
    is_deeply $r->{warnings}, [], 'no warnings';
};

# ------------------------------------------------------- on a terminal

subtest 'on a terminal, y destroys -- the question on STDERR' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => "y\n", interactive => 1);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    like   $r->{err}, $PROMPT, 'the question is asked on STDERR';
    unlike $r->{out}, $PROMPT, 'not on the payload channel';
    unlike $r->{err}, $NO_TERMINAL, 'no refusal';
    is $r->{rest} // '', '', 'the answer was read';
    is_deeply [ grep { $_->[0] eq 'delete' } @{ $r->{events} } ],
        [ [ delete => '111' ] ], 'the server is deleted';
    ok !-f $_, path($_)->basename.' is removed' for state_files($config);
    like $r->{out}, qr/Cluster destroyed\./, 'the run says so on STDOUT';
};

subtest 'on a terminal, yes (any case) destroys too' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => "YES\n", interactive => 1);
    is $r->{ret}, 0, 'exit 0';
    is scalar(grep { $_->[0] eq 'delete' } @{ $r->{events} }), 1,
        'the server is deleted';
};

subtest 'on a terminal, n aborts with exit 1 and touches nothing' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => "n\n", interactive => 1);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 1, 'exit 1';
    like $r->{err}, $PROMPT, 'the question was asked';
    like $r->{err}, $ABORTED, 'the abort is said on STDERR';
    unlike $r->{out}, qr/Aborted/, 'not on STDOUT';
    is $r->{rest} // '', '', 'the answer was read';
    untouched($r, $config);
};

subtest 'on a terminal, anything but y/yes is a no' => sub {
    for my $answer ("\n", "yep\n", "no\n", "sure\n") {
        my $config = project();
        my $r = run_destroy($config, stdin => $answer, interactive => 1);
        (my $shown = $answer) =~ s/\n/\\n/;
        is $r->{ret}, 1, "'$shown': exit 1";
        is_deeply $r->{events}, [], "'$shown': nothing deleted";
    }
};

subtest 'on a terminal, EOF (Ctrl-D) aborts without a warning' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => '', interactive => 1);

    is $r->{ret}, 1, 'exit 1';
    like $r->{err}, $ABORTED, 'aborted';
    untouched($r, $config);
    is_deeply $r->{warnings}, [], 'no "uninitialized value" warning';
};

# ------------------------------------------------------- --force

subtest '--force neither asks nor reads STDIN' => sub {
    my $config = project();
    my $r = run_destroy($config, stdin => "n\n", interactive => 0, force => 1);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    is $r->{rest}, "n\n", 'STDIN was not read';
    unlike $r->{err}.$r->{out}, $PROMPT, 'no question';
    unlike $r->{err}, $NO_TERMINAL, 'no refusal';
    is scalar(grep { $_->[0] eq 'delete' } @{ $r->{events} }), 1,
        'the server is deleted';
};

done_testing;

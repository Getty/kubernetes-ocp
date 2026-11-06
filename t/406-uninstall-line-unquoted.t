#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Moo::Role ();

use Rex::Rancher::Uninstall ();
use OCP::Exec ();
use OCP::Provider;
use OCP::Provider::SSH;
use OCP::Provider::Local;

#
# k406: since Rex::Rancher 0.005 the uninstall line is one command,
# /bin/sh -c '...', with the steps inside single quotes. Nothing in OCP may
# quote it again on the way to the host: an ssh command line is read once
# more by the remote login shell, and an outer '...' around a line with '...'
# in it turns the script into bare words there -- the wrong command, and a
# zsh login shell stops at the first pattern that matches nothing.
#
# OCP::Role::Provider::ExistingHost::delete_server hands the line to the
# provider's run_command (t/50 holds that it is the library's line). These are
# the channels it takes from there:
#
#   ssh    OCP::Provider::SSH::run_command -> OCP::SSH::run -> _build_ssh_cmd,
#          run without a local shell (OCP::Exec, list form). OpenSSH joins the
#          words after the destination with one space and sends that; sshd
#          runs it as `$SHELL -c COMMAND`. So what the remote shell reads is
#          that join, and it has to be the library's line byte for byte.
#   local  OCP::Provider::Local::run_command -> ['sh', '-c', LINE]: one
#          argument to one shell, the same single read as on the remote side.
#
# Each is held twice: with the real uninstall line, by what the channel hands
# on (never run here -- it removes things); and with a harmless line of the
# same shape whose script carries single quotes itself, escaped as a
# single-quoted word must carry them ('\''), run through a real /bin/sh -- for
# ssh standing in for the remote login shell, after OpenSSH's join -- so a
# channel that wraps or re-quotes the line prints something else.
#
# Hetzner deletes through its API and has no shell channel; the last subtest
# holds that every provider type is one or the other, so a new provider that
# runs the line through a channel of its own is noticed here.
#

plan skip_all => 'needs a POSIX /bin/sh' unless -x '/bin/sh';

my $tmp = tempdir(CLEANUP => 1);
local $ENV{OCP_KNOWN_HOSTS} = "$tmp/known_hosts";

my $HOST = '10.0.0.5';
my $DEST = "root\@$HOST";

# A line of the shape uninstall_cmd returns, with single quotes in the script.
my $SCRIPT = q{printf '%s|' 'two words' "it's"};
my $LINE   = "/bin/sh -c '" . ($SCRIPT =~ s/'/'\\''/gr) . "'";
my $WANT   = "two words|it's|";

# What OpenSSH sends for an ssh argv: the words after the destination, joined
# with one space (ssh(1): the command is executed on the remote host).
sub remote_command {
    my ($argv) = @_;
    my ($at) = grep { $argv->[$_] eq $DEST } 0 .. $#$argv;
    return undef unless defined $at;
    return join ' ', @{$argv}[ $at + 1 .. $#$argv ];
}

my $OK = { exit => 0, stdout => '', stderr => '' };

subtest 'ssh: the remote shell reads the uninstall line exactly as the library built it' => sub {
    my $line = Rex::Rancher::Uninstall->uninstall_cmd;
    my @argv;
    no warnings 'redefine';
    local *OCP::SSH::capture_command = sub { push @argv, [ @{ $_[0] } ]; return {%$OK} };

    my $p = OCP::Provider::SSH->new(ssh_key_path => "$tmp/id_ed25519");
    ok eval { $p->delete_server(undef, host => $HOST); 1 }, 'delete_server runs' or diag $@;
    is scalar @argv, 1, 'one ssh call';
    is $argv[0][0], 'ssh', 'through ssh, without a local shell';
    is remote_command($argv[0]), $line,
        'what ssh sends is uninstall_cmd, byte for byte: not wrapped, not quoted again';
};

subtest 'ssh: a line with single quotes inside runs as written on the remote shell' => sub {
    my @argv;
    no warnings 'redefine';
    local *Rex::Rancher::Uninstall::uninstall_cmd = sub { $LINE };
    # The far side of the ssh call: OpenSSH's join, then the login shell.
    local *OCP::SSH::capture_command = sub {
        my ($argv) = @_;
        push @argv, [@$argv];
        my $remote = remote_command($argv);
        return { exit => 255, stdout => '', stderr => "no destination $DEST in the ssh argv\n" }
            unless defined $remote;
        return OCP::Exec::capture_command([ '/bin/sh', '-c', $remote ], timeout => 30);
    };

    my $p = OCP::Provider::SSH->new(ssh_key_path => "$tmp/id_ed25519");
    my $res = eval { $p->delete_server(undef, host => $HOST) };
    ok $res, 'delete_server succeeds' or diag $@;
    is remote_command($argv[0]), $LINE, 'ssh sends the line as given';
    is $res && $res->{stdout}, $WANT, 'the remote shell ran the script inside, its quotes intact';
};

subtest 'local: sh -c gets the uninstall line as one argument, unchanged' => sub {
    my $line = Rex::Rancher::Uninstall->uninstall_cmd;
    my @argv;
    no warnings 'redefine';
    local *OCP::Provider::Local::capture_command = sub { push @argv, [ @{ $_[0] } ]; return {%$OK} };

    ok eval { OCP::Provider::Local->new->delete_server(undef); 1 }, 'delete_server runs' or diag $@;
    is_deeply \@argv, [ [ 'sh', '-c', $line ] ], 'sh -c, then uninstall_cmd as it is';
};

subtest 'local: a line with single quotes inside runs as written' => sub {
    no warnings 'redefine';
    local *Rex::Rancher::Uninstall::uninstall_cmd = sub { $LINE };

    my $res = eval { OCP::Provider::Local->new->delete_server(undef) };
    ok $res, 'delete_server succeeds' or diag $@;
    is $res && $res->{stdout}, $WANT, 'the shell ran the script inside, its quotes intact';
};

subtest 'every provider type is held here: a shell channel above, or none' => sub {
    my %held = map { $_ => 1 } qw( OCP::Provider::SSH OCP::Provider::Local );
    for my $type (OCP::Provider->types) {
        my $p = OCP::Provider->_build({ type => $type, token => 'test-token', cluster_name => 'c' });
        if (Moo::Role::does_role($p, 'OCP::Role::Provider::ExistingHost')) {
            ok $held{ ref $p }, "$type: uninstalls through run_command, held above (" . ref($p) . ')';
        } else {
            ok !$p->can('run_command'), "$type: no shell channel, the line never goes there";
        }
    }
};

done_testing;

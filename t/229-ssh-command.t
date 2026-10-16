#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Cmd::SSH;

#
# k229: `ocp ssh` took no command. `ocp ssh --node crag -- uptime` now runs
# it on the node instead of a shell. ssh is exec'd as before, so the command's
# output is the STDOUT of the process -- the payload -- and its exit status is
# the exit status of ocp; ocp's own framing stays on STDERR.
#

# ------------------------------------------------- what counts as the command
#
# MooX::Cmd hands execute the command line as typed, options and all. These
# are the shapes it hands over (checked against MooX::Cmd/MooX::Options as
# installed): everything after `--` is the command.

sub remote { OCP::Cmd::SSH->new(node => 'crag')->_remote_command([ @_ ]) }

subtest 'the command is everything after --, verbatim' => sub {
    is_deeply [ remote(qw(--node crag -- uptime -p)) ], [qw(uptime -p)],
        'its own options stay its own';
    is_deeply [ remote('--node=crag', '--', 'sh', '-c', 'echo $HOME') ],
        [ 'sh', '-c', 'echo $HOME' ], 'words are not re-split or expanded here';
    is_deeply [ remote(qw(--node crag -- ls -- -x)) ], [qw(ls -- -x)],
        'a second -- belongs to the command';
};

subtest 'no command: the session it always was' => sub {
    is_deeply [ remote(qw(--node crag)) ],    [], 'no --';
    is_deeply [ remote(qw(--node crag --)) ], [], 'an empty one';
    is_deeply [ remote() ],                   [], 'no arguments at all';
};

subtest 'options before the -- are skipped with their values' => sub {
    is_deeply [ remote(qw(--pins-stdin --node crag -- id)) ], ['id'], 'a flag, a valued option';
    is_deeply [ remote(qw(--no crag -- id)) ], ['id'],
        'an abbreviated --node takes its value too, as Getopt reads it';
};

subtest 'a word before the -- is refused, not dropped' => sub {
    ok !eval { remote(qw(--node crag uptime)); 1 }, 'refused';
    like $@, qr/^Unexpected argument 'uptime'\./, 'naming the word';
    like $@, qr/^  ocp ssh --node crag -- uptime$/m, 'and the form that would have worked';
};

# ------------------------------------------------- the ssh command line
#
# The real exec, in a child, with a stand-in `ssh` first on PATH that prints
# its arguments and exits 7: what OCP::SSH->interactive hands ssh, what ends
# up on STDOUT, and the exit status that comes back.

my $bin = path(tempdir(CLEANUP => 1));
$bin->child('ssh')->spew("#!/bin/sh\nfor a in \"\$\@\"; do printf '%s\\n' \"\$a\"; done\nexit 7\n");
$bin->child('ssh')->chmod(0755);
my $kh = path(tempdir(CLEANUP => 1))->child('known_hosts');

sub exec_ssh {
    my (@command) = @_;
    my $code = 'use OCP::SSH; OCP::SSH->new(host => "10.0.0.9", key_file => "/k", '
             . 'known_hosts => $ENV{T_KH})->interactive(@ARGV)';
    local $ENV{PATH} = "$bin:$ENV{PATH}";
    local $ENV{T_KH} = "$kh";
    open my $fh, '-|', $^X, (map { "-I$_" } grep { !ref } @INC), '-e', $code, '--', @command
        or die "cannot run perl: $!";
    my @args = map { chomp; $_ } <$fh>;
    close $fh;
    return { args => \@args, exit => $? >> 8 };
}

subtest 'a command goes after the destination and a --' => sub {
    my $r = exec_ssh(qw(uptime -p));
    my @a = @{ $r->{args} };
    is_deeply [ @a[-4 .. -1] ], [ 'root@10.0.0.9', '--', 'uptime', '-p' ],
        'user@host, then -- so ssh reads none of it as its own, then the command';
    ok scalar(grep { $_ eq 'IdentitiesOnly=yes' } @a), 'with the usual options';
    ok scalar(grep { $_ eq '/k' } @a), 'and the key';
    is $r->{exit}, 7, "ssh's exit status -- the remote command's -- is the process's";
};

subtest 'without a command the session is unchanged' => sub {
    my $r = exec_ssh();
    is $r->{args}[-1], 'root@10.0.0.9', 'the destination is the last word';
    ok !grep({ $_ eq '--' } @{ $r->{args} }), 'no --';
};

done_testing;

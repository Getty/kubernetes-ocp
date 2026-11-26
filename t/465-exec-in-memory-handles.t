#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use OCP::Exec qw( capture_command );

#
# k465: capture_command ran the child through IPC::Open3, which reopens the
# child's STDIN/STDOUT/STDERR *handles* on its pipes. That lands on fds 0/1/2
# only while those handles sit on them; a caller with STDOUT on an in-memory
# handle -- any test capturing output with `open STDOUT, '>', \$buf` -- has no
# fd 1 behind it, so the child wrote to the real fd 1 (prove's TAP stream) and
# {stdout} came back empty. Same for STDIN (the `stdin =>` text never reached
# the child) and STDERR.
#
# The claims, with the real fd 1 caught in a file underneath:
#   1. with STDOUT in memory, the child's stdout is in {stdout}, and neither
#      the in-memory buffer nor fd 1 got any of it;
#   2. with STDERR in memory, the child's stderr is in {stderr};
#   3. with STDIN in memory, the `stdin =>` text is what the child reads;
#   4. with fd 0 closed (a pipe may then get fd 0 itself), stdin, stdout and
#      stderr still reach the child as 0, 1 and 2;
#   5. a command that cannot be executed still dies, naming it and the reason.
#

my $sh = 'echo child-out; echo child-err >&2';

# Run $code with fd 1 on a file; returns (what landed on fd 1, $code's result).
sub on_fd1 {
    my ($code) = @_;
    my $file = path(tempdir(CLEANUP => 1))->child('fd1');
    open my $save, '>&', \*STDOUT or die "dup STDOUT: $!";
    open STDOUT, '>', "$file"     or die "STDOUT to file: $!";
    my $r = eval { $code->() };
    my $died = $@;
    STDOUT->flush;
    open STDOUT, '>&', $save or die "restore STDOUT: $!";
    die $died if $died;
    return ($file->slurp, $r);
}

subtest 'STDOUT in memory: the child stdout is captured, not on fd 1' => sub {
    my $buf = '';
    my ($fd1, $r) = on_fd1(sub {
        local *STDOUT;
        open STDOUT, '>', \$buf or die "in-memory STDOUT: $!";
        capture_command([ 'sh', '-c', $sh ]);
    });
    is $r->{stdout}, "child-out\n", '{stdout} holds what the child printed';
    is $r->{stderr}, "child-err\n", '{stderr} holds what it said on stderr';
    is $r->{exit},   0,             'exit 0';
    is $buf, '',  'nothing in the caller\'s in-memory STDOUT';
    is $fd1, '',  'nothing on the real fd 1';
};

subtest 'STDERR in memory: the child stderr is captured' => sub {
    my $buf = '';
    my $r = do {
        local *STDERR;
        open STDERR, '>', \$buf or die "in-memory STDERR: $!";
        capture_command([ 'sh', '-c', $sh ]);
    };
    is $r->{stderr}, "child-err\n", '{stderr} holds what the child said';
    is $r->{stdout}, "child-out\n", '{stdout} as well';
    is $buf, '', 'nothing in the caller\'s in-memory STDERR';
};

subtest 'STDIN in memory: the stdin text reaches the child' => sub {
    my $pin = "not-for-the-child\n";
    my $r = do {
        local *STDIN;
        open STDIN, '<', \$pin or die "in-memory STDIN: $!";
        capture_command([ 'cat' ], stdin => "script-line\n", timeout => 10);
    };
    is $r->{stdout},    "script-line\n", 'the child read the stdin => text';
    is $r->{timed_out}, 0,               'and saw its end, no timeout';
};

subtest 'fd 0 closed: the pipes still land on 0, 1 and 2' => sub {
    open my $save, '<&', \*STDIN or die "dup STDIN: $!";
    close STDIN;
    my $r = eval {
        capture_command([ 'sh', '-c', 'cat; echo child-err >&2' ],
            stdin => "via-fd-0\n", timeout => 10);
    };
    my $died = $@;
    open STDIN, '<&', $save or die "restore STDIN: $!";
    is $died, '', 'no error';
    is $r->{stdout}, "via-fd-0\n",  'stdin reached the child, stdout came back';
    is $r->{stderr}, "child-err\n", 'stderr came back';
};

subtest 'a command that cannot be executed dies, naming it' => sub {
    my $missing = path(tempdir(CLEANUP => 1))->child('no-such-program')->stringify;
    my $r = eval { capture_command([ $missing, '--flag' ]) };
    like $@, qr/\Qexec of $missing --flag failed: \E\S/,
        'the error names the command and the reason';
    is $r, undef, 'no result';
};

done_testing;

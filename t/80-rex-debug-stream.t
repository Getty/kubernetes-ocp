#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP::Rex;

#
# OCP_REX_DEBUG turns a long rex task from a black box into something an
# operator can watch. On a real bootstrap, install_rke2_server brought up
# Cilium, the CNI briefly cut the network, and OCP::Rex -- which buffered the
# whole task and printed it only at the end -- showed nothing at all: a frozen
# terminal, no clue where it stopped. With OCP_REX_DEBUG set, run_task must
#   (a) pass rex its own -d,
#   (b) stream output live to STDERR while still collecting it for the return,
#   (c) keep the diagnosis on STDERR, never STDOUT (house rule: STDOUT is the
#       payload / apply-progress channel a parser may read).
# And with it unset, the call shape must be exactly what it was (t/27's mock).
#

my $tmp = tempdir(CLEANUP => 1);
my $key = path($tmp)->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub key');

my $rexfile = path($tmp)->child('Rexfile');
$rexfile->spew("# stub\n");
{
    no warnings 'redefine';
    *OCP::Rex::_find_rexfile = sub { $rexfile->stringify };
}

# One mock stands in for IPC::Run's run(). It records the command, and decodes
# which call shape it was handed: the coderef-tee (debug) or the scalar-ref
# buffer (non-debug). In the debug shape it feeds each sink a chunk, exactly as
# IPC::Run would, so we can prove the chunk both streamed and was collected.
my @cmds;
my $shape;
{
    no warnings 'redefine';
    *OCP::Rex::run = sub {
        my @a = @_;
        push @cmds, [ @{ $a[0] } ];
        if (@a >= 6 && $a[2] eq '>' && ref $a[3] eq 'CODE') {
            $shape = 'coderef';
            $a[3]->("STDOUT-CHUNK\n");
            $a[5]->("STDERR-CHUNK\n");
        }
        else {
            $shape = 'scalarref';
            ${ $a[2] } = 'buffered-payload';
            ${ $a[3] } = 'buffered-diag';
        }
        return 1;
    };
}

# Run run_task with STDOUT and STDERR captured into scalars.
sub capture_run_task {
    my ($task, %params) = @_;
    @cmds  = ();
    $shape = undef;
    my ($out, $err) = ('', '');
    my $result;
    {
        open my $ofh, '>', \$out or die "capture STDOUT: $!";
        open my $efh, '>', \$err or die "capture STDERR: $!";
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $result = OCP::Rex->new(host => 'psyduck.example', key_file => $key->stringify)
            ->run_task($task, %params);
    }
    return { result => $result, stdout => $out, stderr => $err, cmd => $cmds[0] };
}

subtest 'without OCP_REX_DEBUG: unchanged call shape, diagnosis on STDERR' => sub {
    delete local $ENV{OCP_REX_DEBUG};

    my $c = capture_run_task('install_cilium');

    is $shape, 'scalarref',
        'non-debug path still calls run(\@cmd, \undef, \$out, \$err) -- t/27 mock stays valid';
    ok !(grep { $_ eq '-d' } @{ $c->{cmd} }), 'no -d appended when OCP_REX_DEBUG is off';
    is $c->{result}{stdout}, 'buffered-payload', 'buffered stdout returned';

    like   $c->{stderr}, qr/--- Rex Output ---/, 'diagnostic banner is on STDERR';
    like   $c->{stderr}, qr/buffered-payload/,   'buffered rex output is on STDERR';
    like   $c->{stderr}, qr/buffered-diag/,      'buffered rex stderr is on STDERR too';
    unlike $c->{stdout}, qr/--- Rex Output ---/, 'diagnostic banner is NOT on STDOUT';
    unlike $c->{stdout}, qr/buffered-payload/,   'rex output does NOT leak onto STDOUT';
    like   $c->{stdout}, qr/Running Rex task: install_cilium/,
        'progress line ("Running Rex task") stays on STDOUT';
};

subtest 'with OCP_REX_DEBUG: -d appended, output streamed live to STDERR and collected' => sub {
    local $ENV{OCP_REX_DEBUG} = 1;

    my $c = capture_run_task('install_rke2_server');

    is $shape, 'coderef', 'debug path calls run() with coderef tee sinks';
    ok((grep { $_ eq '-d' } @{ $c->{cmd} }), '-d is appended to the rex command');
    is $c->{cmd}[-1], 'install_rke2_server', 'the task name is still the final argument';

    # (b) collected for the return value
    like $c->{result}{stdout}, qr/STDOUT-CHUNK/, 'streamed stdout is still collected for the return';
    like $c->{result}{stderr}, qr/STDERR-CHUNK/, 'streamed stderr is still collected for the return';

    # (b) streamed live to STDERR as it arrived
    like $c->{stderr}, qr/STDOUT-CHUNK/, 'rex stdout streamed live to STDERR';
    like $c->{stderr}, qr/STDERR-CHUNK/, 'rex stderr streamed live to STDERR';

    # (c) never on the payload channel
    unlike $c->{stdout}, qr/STDOUT-CHUNK/,       'live output does not land on STDOUT';
    unlike $c->{stdout}, qr/--- Rex Output ---/, 'diagnostic banner is not on STDOUT in debug mode';
    like   $c->{stdout}, qr/Running Rex task: install_rke2_server/,
        'progress line stays on STDOUT';
};

done_testing;

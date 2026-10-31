#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use OCP::Rex;

#
# k343: run_task sets five variables for the rex child -- the key paths, the
# task parameters (a join token among them), the known_hosts file and, since
# k316, PERL5LIB with OCP's lib/ in front -- and has to leave %ENV as it found
# it. It used to put them back only once IPC::Run::run had returned, so a run
# that died instead left all five set: the next run_task, or anything else
# this process starts, inherited the last task's parameters, key paths and
# lib/.
#
# Two ways to die. The real IPC::Run with no rex on PATH: its spawn failure,
# raised in this process before any fork, no network and no rex needed. And a
# stand-in for run that dies as an IPC::Run timeout would, after the child's
# environment was set up -- the stand-in records that environment first, so
# the test knows the variables were changed before it checks they were put
# back.
#

# The fixed 4-argument run shape; OCP_REX_DEBUG would switch to the tee shape.
delete local $ENV{OCP_REX_DEBUG};

my @VARS = qw( REX_PRIVATE_KEY REX_PUBLIC_KEY REX_TASK_PARAMS OCP_KNOWN_HOSTS PERL5LIB );

my $tmp = tempdir(CLEANUP => 1);
my $key = path($tmp)->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub key');

# A host already in known_hosts goes straight to rex, no SSH first (k168).
my $known_hosts = path($tmp)->child('known_hosts');
$known_hosts->spew("psyduck.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr\n");

# A PATH with nothing on it: IPC::Run cannot find rex there.
my $empty_path = path($tmp)->child('empty-path');
$empty_path->mkpath;

# The five as they stand: a variable that is not set has no key at all, so
# "absent" and "set to something" stay apart.
sub env_now {
    return { map { exists $ENV{$_} ? ( $_ => $ENV{$_} ) : () } @VARS };
}

# run_task with a parameter, so REX_TASK_PARAMS is among what it sets.
# Returns what it died with, undef if it did not.
sub run_task_died {
    my $stdout = '';
    local *STDOUT;
    open STDOUT, '>', \$stdout or die "STDOUT: $!";
    my $ok = eval {
        OCP::Rex->new(
            host        => 'psyduck.example',
            key_file    => $key->stringify,
            known_hosts => $known_hosts->stringify,
        )->run_task('prepare_node', token => 'K10c0ffee::server:s3cr3t');
        1;
    };
    return $ok ? undef : $@;
}

# Stands in for IPC::Run::run: records the environment the child would have
# started with, then dies as an IPC::Run timeout does.
sub dying_run {
    my ($seen) = @_;
    return sub {
        %$seen = %{ env_now() };
        die "IPC::Run: timeout on timer #1\n";
    };
}

subtest 'a run that dies puts back the values it found' => sub {
    local @ENV{@VARS} = map { "/outer/$_" } @VARS;
    my $before = env_now();
    my %seen;
    no warnings 'redefine';
    local *OCP::Rex::run = dying_run(\%seen);

    my $died = run_task_died();
    is $died, "IPC::Run: timeout on timer #1\n", 'the die reaches the caller unchanged';

    is $seen{REX_PRIVATE_KEY}, $key->stringify, 'the child got the key path';
    is $seen{REX_PUBLIC_KEY}, "$key.pub", 'and the public key path';
    like $seen{REX_TASK_PARAMS} // '', qr/s3cr3t/, 'the task parameters';
    is $seen{OCP_KNOWN_HOSTS}, $known_hosts->stringify, 'the known_hosts file';
    like $seen{PERL5LIB} // '', qr{\A[^:]+:/outer/PERL5LIB\z}, 'and a PERL5LIB with lib/ in front';

    is $ENV{$_}, $before->{$_}, "$_ is back to what it was" for @VARS;
};

subtest 'a variable that was not set is not set afterwards' => sub {
    delete local @ENV{@VARS};
    my %seen;
    no warnings 'redefine';
    local *OCP::Rex::run = dying_run(\%seen);

    like run_task_died(), qr/timeout on timer/, 'the run died';
    ok exists $seen{$_}, "$_ was set for the child" for @VARS;
    ok !exists $ENV{$_}, "$_ is gone again" for @VARS;
};

subtest 'IPC::Run itself dies: no rex on PATH' => sub {
    local $ENV{PATH} = $empty_path->stringify;
    # Both shapes in one run: two variables set, three not.
    local @ENV{qw( REX_TASK_PARAMS PERL5LIB )} = ( '{"outer":"value"}', '/outer/lib' );
    delete local @ENV{qw( REX_PRIVATE_KEY REX_PUBLIC_KEY OCP_KNOWN_HOSTS )};
    my $before = env_now();

    like run_task_died(), qr/\ACommand 'rex' not found in /, 'IPC::Run could not start rex';
    is_deeply env_now(), $before, '%ENV is as it was: the set ones restored, the others absent';
};

done_testing;

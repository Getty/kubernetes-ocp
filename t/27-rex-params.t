#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS;
use Path::Tiny qw(path);

use OCP::Rex;

#
# Task parameters reach the Rexfile through REX_TASK_PARAMS, never through
# the command line. This went unnoticed for a long time: OCP::Rex encoded the
# JSON but no task ever read the variable, so every parameter silently
# vanished and `upgrade_cilium` died with "version parameter required".
#
# The command line is deliberately kept free of parameters — `install_rke2_agent`
# receives the cluster join token, and arguments are world-readable via `ps`.
#

my $tmp = tempdir(CLEANUP => 1);
my $key = path($tmp)->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub key');

# Capture what run_task hands to IPC::Run instead of executing rex.
my @captured;

{
    no warnings 'redefine';
    *OCP::Rex::run = sub {
        my ($cmd, $in, $out, $err) = @_;
        push @captured, {
            cmd    => [@$cmd],
            params => $ENV{REX_TASK_PARAMS},
        };
        $$out = '';
        $$err = '';
        return 1;
    };
}

# The Rexfile lookup insists on a real file; point it at a stub.
my $rexfile = path($tmp)->child('Rexfile');
$rexfile->spew("# stub\n");
{
    no warnings 'redefine';
    *OCP::Rex::_find_rexfile = sub { $rexfile->stringify };
}

sub run_task_capturing {
    my (%params) = @_;
    my $task = delete $params{_task} // 'upgrade_cilium';
    @captured = ();
    OCP::Rex->new(host => 'psyduck.example', key_file => $key->stringify)
        ->run_task($task, %params);
    return $captured[0];
}

subtest 'parameters travel as JSON in REX_TASK_PARAMS' => sub {
    my $call = run_task_capturing(version => '1.20.0');

    ok defined $call->{params}, 'REX_TASK_PARAMS was set for the child process';

    my $decoded = JSON::MaybeXS->new(utf8 => 1)->decode($call->{params});
    is_deeply $decoded, { version => '1.20.0' }, 'round-trips to the original parameters';
};

subtest 'nested structures survive' => sub {
    my $call = run_task_capturing(
        version => '1.20.0',
        gpu     => { enabled => 1, driver => '580.65.06' },
    );

    my $decoded = JSON::MaybeXS->new(utf8 => 1)->decode($call->{params});
    is_deeply $decoded->{gpu}, { enabled => 1, driver => '580.65.06' },
        'a hashref parameter arrives intact, not flattened to a string';
};

subtest 'secrets stay out of the command line' => sub {
    my $call = run_task_capturing(
        _task => 'install_rke2_agent',
        token => 'K10c0ffee::server:s3cr3t',
    );

    my $cmdline = join ' ', @{ $call->{cmd} };
    unlike $cmdline, qr/s3cr3t/, 'the join token is not visible in `ps` output';
    unlike $cmdline, qr/token/,  'not even the parameter name is passed as an argument';
    is $call->{cmd}[-1], 'install_rke2_agent', 'the task name is the final argument';
};

subtest 'no parameters means no leftover variable' => sub {
    $ENV{REX_TASK_PARAMS} = '{"stale":"from a previous task"}';
    my $call = run_task_capturing(_task => 'install_cilium');

    is $call->{params}, undef,
        'a parameterless task does not inherit the previous task parameters';
};

subtest 'the environment is restored afterwards' => sub {
    local $ENV{REX_TASK_PARAMS} = '{"outer":"value"}';
    run_task_capturing(version => '1.20.0');

    is $ENV{REX_TASK_PARAMS}, '{"outer":"value"}',
        'run_task puts back what it found';
};

#
# The original defect sat in neither half but in the gap between them: OCP::Rex
# encoded the JSON, the Rexfile never read it. Nothing failed loudly, tasks just
# saw empty parameters. So assert the far end of the handover too.
#

subtest 'the Rexfile picks the parameters back up' => sub {
    my $shipped = path(__FILE__)->parent->parent->child('share', 'Rexfile');
    plan skip_all => "share/Rexfile not found at $shipped" unless -f $shipped;

    my $source = $shipped->slurp_utf8;

    like $source, qr/\bREX_TASK_PARAMS\b/,
        'the Rexfile reads the variable OCP::Rex sets';

    my @raw = $source =~ /^\s*my \$params = (shift.*)$/mg;
    is_deeply \@raw, [],
        'no task takes parameters straight off @_ — those never arrive'
        or diag "Tasks bypassing task_params(): @raw";

    my $helpers = () = $source =~ /^\s*my \$params = task_params\(shift\);/mg;
    ok $helpers > 0, "$helpers task(s) go through task_params()";
};

done_testing;

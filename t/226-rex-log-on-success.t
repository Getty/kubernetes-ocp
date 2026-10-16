#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Rex;

#
# k226, lab 2026-10-15/16: every successful `ocp apply` wrote the whole
# "--- Rex Output ---" block -- INFO lines, ANSI colour -- onto STDERR, the
# channel that says something went wrong (ocp-rules "Output channels"). And the
# two warnings worth reading in it, hold_running keeping the installed version
# (k193) and the Rexfile keeping a running server's cluster-cidr (k199), were
# only in that block: the STDOUT narrative never mentioned them.
#
# Claims: a task that worked writes nothing on STDERR unless --verbose asks for
# its log; what it warned about is said on STDOUT, once per message, without
# timestamp or colour; rex runs monochrome.
#

delete local $ENV{OCP_REX_DEBUG};

my $tmp = tempdir(CLEANUP => 1);
my $key = path($tmp)->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub key');
my $rexfile = path($tmp)->child('Rexfile');
$rexfile->spew("# stub\n");
my $known_hosts = path($tmp)->child('known_hosts');
$known_hosts->spew("cp.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr\n");
$ENV{OCP_KNOWN_HOSTS} = $known_hosts->stringify;

# What a re-bootstrap logged on the lab cluster, shortened: the Rexfile's own
# say on stdout, Rex::Logger lines on stderr -- one WARN twice, as rex-rancher
# logs it from both the check and the install, and coloured the way Rex::Logger
# writes it without -m.
my $HOLD = 'rke2 v1.33.4+rke2r1 is running here and options name no version: '
         . 'hold_running holds the installed rke2 v1.33.4+rke2r1 instead';
my $CIDR = 'the server here runs cluster-cidr 10.42.0.0/16, not 10.0.0.0/8; '
         . 'keeping it (a running cluster\'s pod network is not changed by apply)';
my $OUT = "Detected OS: Debian 13\n[WARN] $CIDR\nRKE2 cluster ready\n";
my $ERR = "[2026-10-15 23:01:02] INFO - Running task install_rke2_server on cp.example\n"
        . "\e[33m[2026-10-15 23:01:05] WARN - $HOLD\n\e[0m"
        . "[2026-10-15 23:01:09] WARN - $HOLD\n"
        . "[2026-10-15 23:03:40] INFO - All tasks successful on all hosts\n";

my @cmds;
{
    no warnings 'redefine';
    *OCP::Rex::_find_rexfile = sub { $rexfile->stringify };
    *OCP::Rex::run = sub {
        push @cmds, [ @{ $_[0] } ];
        ${ $_[2] } = $OUT;
        ${ $_[3] } = $ERR;
        return 1;
    };
}

sub run_ok {
    my (%args) = @_;
    my ($out, $err) = ('', '');
    my $result;
    {
        open my $o, '>', \$out or die;
        open my $e, '>', \$err or die;
        local *STDOUT = $o;
        local *STDERR = $e;
        $result = OCP::Rex->new(host => 'cp.example', key_file => "$key", %args)
            ->run_task('install_rke2_server');
    }
    return ($result, $out, $err);
}

subtest 'success without --verbose: nothing on STDERR' => sub {
    my ($r, $out, $err) = run_ok();
    is $err, '', 'STDERR stays empty -- nothing went wrong';
    unlike $out, qr/--- Rex Output ---|INFO -/, 'and the raw log is not moved to STDOUT either';
    like $out, qr/Running Rex task: install_rke2_server/, 'the narrative line is still there';
    is $r->{stdout}, $OUT, 'the caller still gets the output';
};

subtest 'success with --verbose: the log, on STDERR' => sub {
    my (undef, $out, $err) = run_ok(verbose => 1);
    like $err, qr/--- Rex Output ---.*All tasks successful.*--- End Rex Output ---/s,
        '--verbose shows the whole log';
    unlike $out, qr/--- Rex Output ---/, 'never on STDOUT';
};

subtest 'the warnings are in the narrative' => sub {
    my ($r, $out, $err) = run_ok();
    like $out, qr/^  \[WARN\] \Q$HOLD\E$/m, 'hold_running (k193) on STDOUT';
    like $out, qr/^  \[WARN\] \Q$CIDR\E$/m, 'keeping cluster-cidr (k199) on STDOUT';
    is scalar(() = $out =~ /hold_running/g), 1, 'a warning logged twice is said once';
    unlike $out, qr/\e\[|\d{4}-\d\d-\d\d \d\d:/, 'without colour or timestamp';
    is_deeply $r->{warnings}, [ $CIDR, $HOLD ], 'and handed to the caller';
};

subtest 'quiet (probes) prints no warnings either' => sub {
    my (undef, $out, $err) = run_ok(quiet => 1);
    unlike $out, qr/\[WARN\]/, 'a read-only probe stays silent';
    is $err, '', 'on both channels';
};

subtest 'rex runs monochrome' => sub {
    @cmds = ();
    run_ok();
    ok scalar(grep { $_ eq '-m' } @{ $cmds[0] }), 'rex gets -m (no ANSI in its log)';
    is $cmds[0][-1], 'install_rke2_server', 'the task stays the last argument';
};

subtest 'a failure still shows what it showed' => sub {
    no warnings 'redefine';
    local *OCP::Rex::run = sub {
        ${ $_[3] } = "[x] WARN - $HOLD\n[x] ERROR - it broke\n";
        return 0;
    };
    my ($out, $err) = ('', '');
    my $died;
    {
        open my $o, '>', \$out or die;
        open my $e, '>', \$err or die;
        local *STDOUT = $o;
        local *STDERR = $e;
        eval { OCP::Rex->new(host => 'cp.example', key_file => "$key")
            ->run_task('install_rke2_server'); 1 } or $died = $@;
    }
    like $died, qr/it broke/, 'the reason is in the error';
    like $err, qr/^  \[WARN\] \Q$HOLD\E$/m, 'a warning before a failure is diagnosis: STDERR';
    unlike $out, qr/\[WARN\]/, 'not STDOUT';
};

done_testing;

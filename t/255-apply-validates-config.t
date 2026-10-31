#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use FindBin;
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';
use OCP;
use OCP::Config;

#
# k255: OCP::Config::validate had no caller outside t/. At runtime only the
# croaking accessors guarded ocp.yaml, and only where they were read -- a
# typo in gpu.amd.allocation surfaced on the first AMD node, after a control
# plane had been built; one in gpu.driver had no validate() line at all.
#
# The claims here:
#   1. validate() has a gpu.driver line of its own, in the words of the other
#      choice keys; the default and both drivers pass;
#   2. `ocp apply` and `ocp apply --dry-run` call validate() before anything:
#      every error at once on STDERR, one per line, with what to do about
#      them; nothing on STDOUT; exit 1; not a file written in the project
#      (the dev-mode path that would otherwise follow writes .ocp/age.key);
#   3. a valid ocp.yaml passes the gate: the run goes on as before;
#   4. `ocp status` does not gate on it -- it is the read side, and has to
#      show a cluster whose ocp.yaml has a mistake.
#

local @ARGV = ();
my $ocp = OCP->new;
my $bin = "$FindBin::Bin/../bin/ocp";
my $lib = "$FindBin::Bin/../lib";

sub project {
    my ($spec) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({ name => 'k255', %$spec }));
    return $dir;
}

sub validate_errors {
    my ($dir) = @_;
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify, ocp => $ocp)->validate;
}

# `ocp @args` in $dir as a user runs it: (stdout, stderr, exit code).
sub ocp_in {
    my ($dir, @args) = @_;
    my ($out, $err) = map { $dir->parent->child("k255-$$-$_") } qw( out err );
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        open STDIN,  '<', '/dev/null' or die;
        open STDOUT, '>', "$out"      or die;
        open STDERR, '>', "$err"      or die;
        exec $^X, "-I$lib", $bin, @args or die "exec: $!";
    }
    waitpid $pid, 0;
    my $rc = $? >> 8;
    my @r = ($out->slurp_utf8, $err->slurp_utf8, $rc);
    $_->remove for $out, $err;
    return @r;
}

my $ssh = { provider => 'ssh', host => 'cp.k255.test' };

# --- 1. gpu.driver in validate() ---------------------------------------------

subtest 'validate() checks gpu.driver' => sub {
    is_deeply [ validate_errors(project({ control_planes => $ssh, gpu => { driver => 'oprator' } })) ],
        [ "gpu.driver: invalid value 'oprator' (must be host or operator)" ],
        'a typo: one line, the choices named' ;

    is_deeply [ validate_errors(project({ control_planes => $ssh, gpu => { driver => [ 'host' ] } })) ],
        [ 'gpu.driver: invalid value a list (must be host or operator)' ],
        'a list is no driver';

    for my $ok ('host', 'operator') {
        is_deeply [ validate_errors(project({ control_planes => $ssh, gpu => { driver => $ok } })) ], [],
            "'$ok' passes";
    }
    is_deeply [ validate_errors(project({ control_planes => $ssh, gpu => { enabled => 0 } })) ], [],
        'absent (host) passes';
};

# --- 2. apply refuses an invalid ocp.yaml before anything --------------------

my %BAD = (
    control_planes => { %$ssh, node_ip => '10.230.30.52/24' },
    gpu            => { driver => 'oprator', amd => { allocation => 'dpr' } },
);

for my $args ([ 'apply' ], [ 'apply', '--dry-run' ]) {
    subtest "ocp @$args: every error at once, on STDERR, exit 1, nothing done" => sub {
        my $dir  = project(\%BAD);
        my @want = validate_errors($dir);
        is scalar(@want), 3, 'the fixture has three errors' or diag explain \@want;

        my ($out, $err, $rc) = ocp_in($dir, @$args);

        is $rc, 1, 'exit 1';
        is $out, '', 'nothing on STDOUT: no banner, no step' or diag $out;
        like $err, qr/\AError: ocp\.yaml has 3 errors:\n/, 'STDERR opens with the count';
        for my $e (@want) {
            like $err, qr/^  - \Q$e\E$/m, "STDERR lists: $e";
        }
        like $err, qr/^Nothing was done: ocp apply checks ocp\.yaml before it touches a host or the cluster\. Fix the lines above and run it again\.$/m,
            'and says that nothing was done and what to do';
        unlike $err, qr/internal error|line \d+/, 'a refusal, not a Perl error';

        is_deeply [ sort map { $_->basename } $dir->children ], [ 'ocp.yaml' ],
            'no file written in the project (no .ocp/, no age key)';
    };
}

subtest 'one error: said in the singular' => sub {
    my ($out, $err, $rc) = ocp_in(project({ control_planes => $ssh, gpu => { driver => 'oprator' } }), 'apply');
    is $rc, 1, 'exit 1';
    like $err, qr/\AError: ocp\.yaml has 1 error:\n  - gpu\.driver: invalid value 'oprator'/,
        'one error, named';
};

# --- 3. a valid ocp.yaml goes on ---------------------------------------------

subtest 'a valid ocp.yaml passes the gate' => sub {
    my $dir = project({ control_planes => $ssh });
    is_deeply [ validate_errors($dir) ], [], 'the fixture is valid';

    my ($out, $err) = ocp_in($dir, 'apply', '--dry-run');
    like $out, qr/CONTROL PLANE DEPLOYMENT/, 'the run starts';
    unlike $err, qr/ocp\.yaml has \d+ error/, 'and is not refused for its ocp.yaml' or diag $err;
};

# --- 4. ocp status reads on ---------------------------------------------------

subtest 'ocp status does not gate on validate()' => sub {
    my ($out, $err) = ocp_in(project(\%BAD), 'status');
    unlike $err, qr/ocp\.yaml has \d+ error/, 'status is not refused for its ocp.yaml' or diag $err;
};

done_testing;

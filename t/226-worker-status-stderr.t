#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Apply;

#
# k226, lab 2026-10-15/16: the worker status block at the end of `ocp apply`
# printed "[!!] name — Failed (why)" on STDOUT -- the counterpart of what k204
# (6ac9b25) fixed for `ocp node add`. A node that did not come up is
# diagnosis: STDERR. Ready rows are progress and stay on STDOUT. The same rows
# are what the apply counts as unfinished (unready_nodes), so the exit code and
# the STDERR lines name the same nodes.
#

my @results = (
    { name => 'raichu',  phase => 'Ready',   message => '' },
    { name => 'pichu',   phase => 'Failed',  message => 'SSH not ready: key refused' },
    { name => 'pikachu', phase => 'Unknown', message => 'timed out waiting for phase (after 600s)' },
);

sub capture_both {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    {
        local *STDOUT = $o;
        local *STDERR = $e;
        $code->();
    }
    return ($out, $err);
}

my $apply = bless {}, 'OCP::Cmd::Apply';

subtest 'Ready on STDOUT, everything short of Ready on STDERR' => sub {
    my ($out, $err) = capture_both(sub { $apply->_print_worker_status(\@results) });

    like   $out, qr/Worker status:/,           'the block header is narrative';
    like   $out, qr/^    \[ok\] raichu — Ready$/m, 'a Ready worker is progress';
    unlike $out, qr/pichu|pikachu/,            'no failed row on STDOUT';
    like   $err, qr/^    \[!!\] pichu — Failed \(SSH not ready: key refused\)$/m,
        'a Failed worker on STDERR, with its reason';
    like   $err, qr/^    \[\.\.\] pikachu — Unknown \(timed out/m,
        'one still short of Ready when the wait ended, too';
    unlike $err, qr/raichu/,                   'no Ready row on STDERR';
};

subtest 'all Ready: nothing on STDERR' => sub {
    my (undef, $err) = capture_both(sub { $apply->_print_worker_status([ $results[0] ]) });
    is $err, '', 'a clean run writes nothing there';
};

subtest 'the unfinished rows, as the apply names them' => sub {
    is_deeply [ OCP::Cmd::Apply::CR::unready_nodes($apply, \@results) ],
        [ 'worker pichu', 'worker pikachu' ], 'everything short of Ready';
    is_deeply [ OCP::Cmd::Apply::CR::unready_nodes($apply, \@results, 'control plane') ],
        [ 'control plane pichu', 'control plane pikachu' ], 'a joining control plane by its role';
    is_deeply [ OCP::Cmd::Apply::CR::unready_nodes($apply, [ $results[0] ]) ], [],
        'none when all came up';
};

done_testing;

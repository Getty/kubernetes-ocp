#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Apply;

#
# Lab 2026-10-15 (k203), citiai: a reconcile whose ClusterPolicy write was
# refused printed "[!!] GPU Operator setup failed" and "Apply did not
# complete: GPU Operator failed." on STDERR and exited 1 -- and on STDOUT,
# between the two, "CONTROL PLANE DEPLOYED SUCCESSFULLY!". A healthy pod list
# is not a finished apply: the banner has to see the failed components the
# exit code sees.
#

my $clean = { critical => [], warnings => [], starting => [] };

subtest 'a failed component takes the success banner away' => sub {
    my $apply = bless { _failed_components => ['GPU Operator'] }, 'OCP::Cmd::Apply';
    my $text = $apply->_health_banner_text($clean);
    unlike $text, qr/SUCCESSFULLY/, 'no SUCCESSFULLY over a failed component';
    like   $text, qr/INCOMPLETE/,   'the banner says the apply is incomplete';
};

subtest 'without failed components the banner is unchanged' => sub {
    my $apply = bless { _failed_components => [] }, 'OCP::Cmd::Apply';
    like $apply->_health_banner_text($clean), qr/SUCCESSFULLY/, 'clean run';
    my $broken = { critical => [{}], warnings => [], starting => [] };
    my $both = bless { _failed_components => ['GPU Operator'] }, 'OCP::Cmd::Apply';
    like $both->_health_banner_text($broken), qr/NOT HEALTHY/,
        'an unhealthy core still wins over an incomplete apply';
};

subtest 'finish prints the incomplete banner and returns 1' => sub {
    my $apply = bless { _failed_components => ['GPU Operator'] }, 'OCP::Cmd::Apply';
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_check_cluster_health = sub { $clean };
    local *OCP::Cmd::Apply::_stamp_ocp_version    = sub { };
    my $config = bless {}, 'Fake::Config';
    my ($out, $err) = ('', '');
    my $rc;
    {
        open my $o, '>', \$out or die $!;
        open my $e, '>', \$err or die $!;
        local *STDOUT = $o;
        local *STDERR = $e;
        $rc = $apply->_finish_apply(config => $config, api => undef);
    }
    is $rc, 1, 'exit code 1';
    unlike $out, qr/SUCCESSFULLY/, 'STDOUT has no success banner';
    like   $out, qr/INCOMPLETE/,   'STDOUT names the apply incomplete';
    like   $err, qr/Apply did not complete: GPU Operator failed/, 'STDERR as before';
};

done_testing;

package Fake::Config;
sub name { 'citiai' }
sub api_url { 'https://x:6443' }

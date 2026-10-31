#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';
use OCP;
use OCP::Config;
use OCP::Cmd::Init;
use OCP::Robocop::Controller;

#
# k355: the distributions OCP installs are named once, in
# @OCP::Config::DISTRIBUTIONS (k340), the list kubernetes.dist is checked
# against. `ocp init --dist` and robocop's OCP_DISTRIBUTION spelled rke2 and
# k3s out a second and a third time, so the three could drift apart: a
# distribution ocp.yaml takes that ocp init refuses to write, or one ocp apply
# installs and robocop then refuses to start for.
#
# The claim: each takes what the list holds. Each is asked with the list
# changed, so a set spelled out again fails here.
#

my @SHIPPED = @OCP::Config::DISTRIBUTIONS;

# Init's execute up to its option checks. --provider nope ends the run at the
# check after --dist's, before anything is written or asked, whichever way the
# --dist check goes.
sub init_error {
    my ($dist) = @_;
    local $@;
    eval { OCP::Cmd::Init->new(dist => $dist, provider => 'nope')->execute([], []) };
    return $@;
}

subtest 'ocp init --dist takes what the list holds' => sub {
    {
        local @OCP::Config::DISTRIBUTIONS = qw( k3s );
        my $err = init_error('rke2');
        like $err, qr/\AUnknown dist 'rke2'\.\n/, 'a dist the list does not hold is refused';
        like $err, qr/^Available: k3s$/m, '... naming what the list holds';
    }
    {
        local @OCP::Config::DISTRIBUTIONS = (@SHIPPED, 'rke9');
        like init_error('rke9'), qr/\AUnknown provider 'nope'/, 'one it holds passes to the next check';
    }
    like init_error('rke3'), qr/^Available: rke2, k3s$/m, 'as shipped: rke2 and k3s, as before';
};

sub controller_error {
    my ($dist) = @_;
    local $@;
    my $ctrl = eval { OCP::Robocop::Controller->new(
        ssh_key => 'K', server_url => 'U', join_token => 'T',
        distribution => $dist, pod_cidr => '10.42.0.0/16') };
    return $ctrl ? '' : $@;
}

subtest "robocop's OCP_DISTRIBUTION takes what the list holds" => sub {
    {
        local @OCP::Config::DISTRIBUTIONS = qw( k3s );
        my $err = controller_error('rke2');
        like $err, qr/unknown distribution 'rke2' \(OCP_DISTRIBUTION\)/, 'a dist the list does not hold is refused';
        like $err, qr/robocop installs k3s at /, '... naming what the list holds, and nothing else';
    }
    {
        local @OCP::Config::DISTRIBUTIONS = (@SHIPPED, 'rke9');
        is controller_error('rke9'), '', 'one it holds builds a controller';
    }
    is controller_error($_), '', "as shipped: $_ builds a controller" for @SHIPPED;
    like controller_error('rke3'), qr/robocop installs k3s or rke2 at /, 'and rke3 is refused, as before';
};

done_testing;

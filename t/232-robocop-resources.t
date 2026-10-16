#!/usr/bin/env perl
# karr k232 -- robocop's memory has to hold the installs it runs.
#
# Lab 2026-10-16: with limits.memory 256Mi the controller container was
# OOMKilled (exit 137) during every pool-worker join -- each kill aborted the
# Rex install, the next container started it again, the join never finished.
# Measured RSS during one install: controller ~111 MB, reconcile child
# ~120 MB, three Rex processes ~58/97/94 MB. max_reconciles defaults to 2,
# so the limit has to hold the controller plus two of those.
#
# Both deploy paths (`ocp apply`, `ocp deploy-robocop`) apply this file's
# Deployment whole, so its resources are what the cluster gets.

use strict;
use warnings;
use Test::More;
use YAML::XS ();

use lib 'lib';
use OCP::Robocop::Controller;

sub mebibytes {
    my ($q) = @_;
    my %unit = (Ki => 1 / 1024, Mi => 1, Gi => 1024);
    $q =~ /\A(\d+)(Ki|Mi|Gi)\z/ or die "unexpected quantity '$q'";
    return $1 * $unit{$2};
}

my ($d) = grep { ref $_ && ($_->{kind} // '') eq 'Deployment' }
    YAML::XS::LoadFile('share/robocop/deployment.yaml');
my ($ctr) = grep { $_->{name} eq 'controller' } @{ $d->{spec}{template}{spec}{containers} };
my $res = $ctr->{resources};

# ~111 MB controller + 2 x (~120 MB child + ~249 MB Rex), from RSS sums
# (an upper bound: fork shares pages with the parent).
my $installs = OCP::Robocop::Controller->new(ssh_key => 'K', server_url => 'U',
    join_token => 'T', distribution => 'rke2', pod_cidr => '10.42.0.0/16')->max_reconciles;
my $need = 111 + $installs * (120 + 58 + 97 + 94);

cmp_ok mebibytes($res->{limits}{memory}), '>=', $need * 1.15,
    "limits.memory holds the controller and $installs concurrent installs (~$need MB) with headroom";
cmp_ok mebibytes($res->{requests}{memory}), '>=', 111 * 2,
    'requests.memory covers an idle controller (~111 MB) with room for a reconcile';
cmp_ok mebibytes($res->{requests}{memory}), '<=', mebibytes($res->{limits}{memory}),
    'requests do not exceed limits';

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use YAML::XS ();

# k197: the robocop image is amd64 only. The Deployment says so, so an arm64
# control plane leaves the pod Pending with a scheduling reason instead of
# "exec format error" after the pull.

my $file = path(__FILE__)->parent->parent->child('share/robocop/deployment.yaml');
my ($dep) = grep { ($_->{kind} // '') eq 'Deployment' } YAML::XS::Load($file->slurp_raw);
ok $dep, 'the Deployment is there';

my @terms = @{ $dep->{spec}{template}{spec}{affinity}{nodeAffinity}
    {requiredDuringSchedulingIgnoredDuringExecution}{nodeSelectorTerms} };
my ($arch) = grep { $_->{key} eq 'kubernetes.io/arch' } map { @{ $_->{matchExpressions} } } @terms;
ok $arch, 'an arch requirement exists';
is $arch->{operator}, 'In', 'as In';
is_deeply $arch->{values}, ['amd64'], 'amd64';

done_testing;

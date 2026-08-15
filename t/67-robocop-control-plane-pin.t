#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use YAML::XS ();

#
# karr #10 (commit 03dec2e, "Pin robocop to the control-plane node"): robocop
# only ever needs to run where the CP server lives, which is always amd64 in
# this project. Workers may be arm64 (GB10/DGX Spark, karr #25) -- irrelevant
# once robocop can't land there. That commit added a toleration + nodeAffinity
# pair to share/robocop/deployment.yaml with no test of its own.
#
# It matters here specifically because it is the reasoning t/66 leans on to
# drop the old --platform/multi-arch guard from karr #41: "multi-arch is no
# longer architecturally required for robocop" is only true while robocop
# stays pinned to the (always-amd64) control-plane node. Without a test, that
# pin could regress silently and both guards -- the one that used to exist
# and the one that justified removing it -- would be gone at once.
#
# Scope is deliberately narrow: only the two fields commit 03dec2e actually
# added (tolerations, affinity.nodeAffinity). Everything else about the
# Deployment (image, ports, resources, RBAC, ...) is covered elsewhere.
#

my $root       = path(__FILE__)->parent->parent;
my $deployment = $root->child('share/robocop/deployment.yaml');

plan skip_all => 'share/robocop/deployment.yaml not found' unless -f $deployment;

my @docs = YAML::XS::LoadFile($deployment->stringify);
my ($dep) = grep {
    ref $_ eq 'HASH'
        && ($_->{kind} // '') eq 'Deployment'
        && ($_->{metadata}{name} // '') eq 'robocop'
} @docs;

ok $dep, 'share/robocop/deployment.yaml parses and carries a Deployment named robocop'
    or BAIL_OUT('no robocop Deployment to check');

my $pod_spec = $dep->{spec}{template}{spec};

subtest 'tolerates both control-plane taints RKE2 sets on server nodes' => sub {
    my $tolerations = $pod_spec->{tolerations};
    is ref($tolerations), 'ARRAY', 'tolerations is a list'
        or BAIL_OUT('no tolerations to check');

    for my $key (qw(
        node-role.kubernetes.io/control-plane
        node-role.kubernetes.io/master
    )) {
        my ($t) = grep { ($_->{key} // '') eq $key } @$tolerations;
        ok $t, "a toleration for $key is present"
            or diag "tolerations found: "
                . join(', ', map { $_->{key} // '<no key>' } @$tolerations);
        next unless $t;

        # operator: Exists, no value -- matches the taint by key presence
        # only, same value-free convention as nfd-master/gpu-operator in
        # OCP::Cmd::Apply::Workloads. A `value:` here would be a regression:
        # RKE2 sets these taints with no value, so an Equal toleration would
        # never match and robocop would go unschedulable again.
        is $t->{operator}, 'Exists', "$key toleration uses operator: Exists (no value)";
        ok !exists $t->{value}, "$key toleration carries no value field";
        is $t->{effect}, 'NoSchedule', "$key toleration matches the NoSchedule taint";
    }
};

subtest 'requires a control-plane node via nodeAffinity' => sub {
    my $terms = eval {
        $pod_spec->{affinity}{nodeAffinity}
            {requiredDuringSchedulingIgnoredDuringExecution}{nodeSelectorTerms};
    };
    is ref($terms), 'ARRAY', 'requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms is a list'
        or BAIL_OUT('no nodeSelectorTerms to check');

    my @matches = grep {
        my $term = $_;
        grep {
            ($_->{key} // '') eq 'node-role.kubernetes.io/control-plane'
                && ($_->{operator} // '') eq 'Exists'
        } @{ $term->{matchExpressions} // [] };
    } @$terms;

    ok scalar(@matches) >= 1,
        'at least one nodeSelectorTerm requires node-role.kubernetes.io/control-plane (operator: Exists)'
        or diag 'this is the hard requirement -- without it robocop is schedulable anywhere, '
               . 'including an arm64 worker, which is exactly what karr #10 ruled out';
};

done_testing;

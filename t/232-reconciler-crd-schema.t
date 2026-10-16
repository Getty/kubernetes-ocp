#!/usr/bin/env perl
# karr k232 -- the reconciler ids OCP writes into status.reconciler have to
# pass the OCPNode CRD's schema for that field.
#
# Lab 2026-10-16: k232 made robocop's id robocop@<pod name>, the CRD still
# declared `enum: [cli, robocop]`, and the API server answered every robocop
# status write with a 422 FieldValueNotSupported -- the Failed marking too. A
# new worker OCPNode never left Pending (empty phase, a live lease), and
# `ocp apply` timed out waiting for it. No test held the ids against the
# schema; this one does what the API server does with the field: type, enum,
# pattern.

use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Robocop::Controller;

my $crd = YAML::XS::Load(
    path(__FILE__)->parent->parent->child('share/robocop/crds/ocpnode.yaml')->slurp_raw
);
my $version = $crd->{spec}{versions}[0];
my $schema  = $version->{schema}{openAPIV3Schema}{properties}{status}{properties}{reconciler};

# The subset of OpenAPI v3 validation the field uses. A pattern is unanchored
# in the API server (RE2) just like in Perl; the shipped one anchors itself
# (Perl's $ also matches before a final newline, RE2's does not -- no id
# carries one, so the difference does not matter here).
sub admitted {
    my ($v) = @_;
    return 0 unless defined $v && !ref $v;
    return 0 if $schema->{enum}    && !grep { $_ eq $v } @{ $schema->{enum} };
    return 0 if defined $schema->{pattern} && $v !~ /$schema->{pattern}/;
    return 0 if defined $schema->{maxLength} && length($v) > $schema->{maxLength};
    return 1;
}

sub ctrl {
    return OCP::Robocop::Controller->new(ssh_key => 'K', server_url => 'U', join_token => 'T',
        distribution => 'rke2', pod_cidr => '10.42.0.0/16', @_);
}

ok $schema, 'the CRD declares status.reconciler';
is $schema->{type}, 'string', 'as a string';

subtest 'what robocop writes is admitted' => sub {
    {
        local $ENV{POD_NAME} = 'robocop-7b988d647d-dlrmv';
        my $id = ctrl()->reconciler_id;
        is $id, 'robocop@robocop-7b988d647d-dlrmv', 'id from POD_NAME';
        ok admitted($id), "$id (the lab's pod)";
    }
    {
        local $ENV{POD_NAME};
        my $id = ctrl()->reconciler_id;
        ok admitted($id), "$id (hostname fallback, this machine)";
    }
    # The hostname fallback is the pod name in a pod (truncated to 63 chars
    # for long ones), anything a machine is called on the out-of-cluster
    # kubeconfig hatch.
    ok admitted("robocop\@$_"), "robocop\@$_"
        for 'robocop-7d9f-abcde', 'a3f9c2e1b0d4', 'Franks-MacBook.local',
            'build_host-01', 'x' x 63, 'robocop.ocp-system.example';
};

subtest 'what the CLI and older robocops wrote stays admitted' => sub {
    ok admitted($_), $_ for 'cli', 'robocop';
};

subtest 'and nothing else is' => sub {
    ok !admitted($_), "'$_' rejected"
        for '', 'robocop@', 'kubectl', 'cli@host', 'robocop@-x', 'robocop@x-',
            'robocop@a b', 'Robocop';
};

subtest 'the Reconciler printer column still reads the field' => sub {
    my ($col) = grep { $_->{name} eq 'Reconciler' } @{ $version->{additionalPrinterColumns} };
    is $col && $col->{jsonPath}, '.status.reconciler', 'jsonPath';
    is $col && $col->{type}, 'string', 'string column';
};

done_testing;

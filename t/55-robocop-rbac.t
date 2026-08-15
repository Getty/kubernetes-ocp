#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use YAML::XS ();

#
# robocop's ClusterRole against the calls robocop actually makes.
#
# The role granted core `nodes` only get/list/watch/patch/update, while
# OCP::Node::teardown deletes the Node object. Under robocop that call came
# back 403 -- and because it sat in a bare eval whose result nobody looked at,
# teardown returned 1 anyway: the OCPNode CR gone, the Node object left behind
# as NotReady, nothing in the log. The same shape as the api-version defect in
# karr #21, one layer further out (karr #35).
#
# So this file is deliberately not a restatement of the YAML. The verbs
# required on core `nodes` are DERIVED from lib/OCP/Node.pm: every call whose
# argument 0 is 'Node' is mapped to the verb it needs, and an unknown call
# shape fails loudly rather than being skipped. Grant and code can only drift
# apart by making this test red.
#

my $root  = path(__FILE__)->parent->parent;
my $rbac  = $root->child('share/robocop/rbac.yaml');
my $nodes = $root->child('lib/OCP/Node.pm');

plan skip_all => 'share/robocop/rbac.yaml not found' unless -f $rbac;

# Parse it the way OCP::Cmd::DeployRobocop does: multi-document LoadFile, then
# ensure() per document. A manifest this test can read is a manifest deploy can
# apply.
my @docs = YAML::XS::LoadFile($rbac->stringify);

my ($role) = grep {
    ref $_ eq 'HASH'
        && ($_->{kind} // '') eq 'ClusterRole'
        && ($_->{metadata}{name} // '') eq 'robocop'
} @docs;

ok $role, 'share/robocop/rbac.yaml parses and carries a ClusterRole named robocop'
    or BAIL_OUT('no ClusterRole to check');

# rules -> { "apiGroup/resource" => { verb => 1 } }
my %granted;
for my $rule (@{ $role->{rules} // [] }) {
    for my $group (@{ $rule->{apiGroups} // [] }) {
        for my $res (@{ $rule->{resources} // [] }) {
            $granted{"$group/$res"}{$_} = 1 for @{ $rule->{verbs} // [] };
        }
    }
}

sub granted_ok {
    my ($key, $verb, $why) = @_;
    ok $granted{$key} && $granted{$key}{$verb}, "$key: $verb -- $why"
        or diag "granted verbs on $key: "
            . join(', ', sort keys %{ $granted{$key} // {} });
}

subtest 'the verbs OCP::Node needs on core nodes are all granted' => sub {
    # Which method needs which verb. _delete_object is in here because it is
    # the seam teardown deletes through -- the whole point of the ticket is
    # that this call needs a grant the role did not have.
    my %verb_for = (
        get           => 'get',
        list          => 'list',
        patch         => 'patch',
        update        => 'update',
        delete        => 'delete',
        _delete_object => 'delete',
    );

    my $src = $nodes->slurp_utf8;
    my %needed;
    for my $line (split /\n/, $src) {
        next if $line =~ /^\s*#/;
        while ($line =~ /->(\w+)\(\s*'Node'/g) {
            my $method = $1;
            my $verb   = $verb_for{$method};
            ok $verb, "OCP::Node calls ->$method('Node', ...) -- known verb mapping"
                or diag "unmapped call shape: ->$method('Node', ...) "
                      . "-- add it to \%verb_for and grant its verb";
            $needed{$verb} = $method if $verb;
        }
    }

    ok scalar(keys %needed), 'found calls against core Node in lib/OCP/Node.pm';

    for my $verb (sort keys %needed) {
        granted_ok('/nodes', $verb, "OCP::Node calls ->$needed{$verb}('Node', ...)");
    }

    # Stated separately as well: this is the grant the ticket is about, and it
    # must not be reachable only through the derivation above.
    granted_ok('/nodes', 'delete',
        'teardown deletes the Node object after the server is gone');
};

subtest 'the rest of the robocop call path is covered too' => sub {
    # One line per call site found in the robocop path
    # (OCP::Robocop::Controller -> OCP::Node -> OCP::Provider).
    my @required = (
        [ 'ocp.internal/ocpnodes', 'list',   'Controller::list_ocp_nodes' ],
        [ 'ocp.internal/ocpnodes', 'get',    'OCP::Node::_get_cr' ],
        [ 'ocp.internal/ocpnodes', 'update', 'OCP::Node::_put_cr (lease)' ],
        [ 'ocp.internal/ocpnodes', 'delete', 'OCP::Node::teardown' ],
        [ 'ocp.internal/ocpnodes/status', 'patch',
            'OCP::Node::_patch_status via OCP::K8s::patch_status' ],
        [ 'ocp.internal/ocpnodeproviders', 'get',
            'Controller::_on_node_event loads the provider CR' ],
        [ '/secrets', 'get',
            'OCP::Provider::from_cr reads the Hetzner token secret' ],
    );

    granted_ok(@$_) for @required;
};

subtest 'the role stays namespaced to what OCP owns' => sub {
    # A ClusterRole is cluster-wide by definition; the guard that matters is
    # that nobody widens it to a wildcard while fixing a missing verb.
    my @wild = grep { $granted{$_}{'*'} } sort keys %granted;
    is_deeply \@wild, [], 'no resource is granted the * verb'
        or diag "wildcard verbs on: @wild";

    my @all_res = grep { m{/\*$} } sort keys %granted;
    is_deeply \@all_res, [], 'no apiGroup is granted * as a resource'
        or diag "wildcard resources: @all_res";
};

done_testing;

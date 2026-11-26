#!/usr/bin/env perl
# karr k463 -- ocp node rm: a failed OCPNode list is no empty cluster.
#
# `ocp node rm NAME` for a name that is not there lists the OCPNodes there
# are (k103). _node_names took a list that failed for an empty one, and the
# rejection said "No OCPNode exists in this cluster; 'ocp node add' creates
# one." -- on a cluster that may have many, the cause said nowhere. The same
# shape k433 fixed for provider_crs. The claims:
#
#   * the rejection still opens "Unknown node 'NAME'." -- the failure does not
#     replace it
#   * below it, where the listing stands, the failed list in one line:
#     "Could not read the OCPNodes from the cluster API: <cause>", an APIError
#     as the cluster API's line, anything else without its source location
#   * no "No OCPNode exists", no node add hint, no Available: line
#   * a list that worked and is empty still says "No OCPNode exists"
#   * nothing is deleted
#
# Network-free and cluster-free: a fake api answers the reads.

use strict;
use warnings;
use Test::More;

use Kubernetes::REST::APIError;

use lib 'lib';

use OCP;
use OCP::Cmd::Node::Rm;
use OCP::ErrorLine;

# No cluster client was built: the line says "The cluster API", no server.
OCP::ErrorLine::set_cluster_endpoint(undef);

{
    package FakeList;
    sub new   { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]{items} }

    package FakeK8s;
    sub new              { my ($c, %a) = @_; bless { calls => [], %a }, $c }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub get {
        my ($s, $kind, %a) = @_;
        push @{ $s->{calls} }, "get $kind";
        die Kubernetes::REST::APIError->new(code => 404, context => 'get',
            body => '{"kind":"Status","reason":"NotFound","code":404}');
    }
    sub list {
        my ($s, $kind) = @_;
        push @{ $s->{calls} }, "list $kind";
        die $s->{list_error} if $s->{list_error};
        return FakeList->new($s->{nodes} // []);
    }
    sub delete { push @{ $_[0]{calls} }, 'delete'; 1 }
}

sub rm_error {
    my (%fake) = @_;
    my $k8s = FakeK8s->new(%fake);
    eval { OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'crag')->execute([], []) };
    return ($@, $k8s);
}

subtest 'control: a list that worked and is empty is "No OCPNode exists"' => sub {
    my ($err) = rm_error();
    is $err, "Unknown node 'crag'.\nNo OCPNode exists in this cluster; 'ocp node add' creates one.\n",
        'the empty cluster, as before';
};

my @FAILURES = (
    [ 'a 403' => Kubernetes::REST::APIError->new(code => 403, context => 'list',
          body => '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}'),
      'The cluster API denied the request (403 Forbidden)' ],
    [ 'no answer' => Kubernetes::REST::APIError->new(code => 599, context => 'list',
          body => "Can't connect to 10.0.0.1:6443 (Connection refused)\n\nConnection refused at LWP/Protocol/http.pm line 50.\n"),
      "The cluster API could not be reached: Can't connect to 10.0.0.1:6443 (Connection refused)" ],
    [ 'a croak' => "the list broke\n  over two lines at lib/Fake.pm line 7.\n",
      'the list broke over two lines' ],
);

for my $case (@FAILURES) {
    my ($what, $error, $cause) = @$case;
    subtest "$what: the failed list is said, not taken for an empty cluster" => sub {
        my ($err, $k8s) = rm_error(list_error => $error);
        is $err, "Unknown node 'crag'.\nCould not read the OCPNodes from the cluster API: $cause\n",
            'the rejection, then the failed list in one line';
        unlike $err, qr/No OCPNode exists|node add|^Available:/m, 'no empty cluster, no listing';
        ok !grep({ $_ eq 'delete' } @{ $k8s->{calls} }), 'nothing deleted';
    };
}

done_testing;

#!/usr/bin/env perl
# karr k470 -- ocp node rm: only a 404 makes a node unknown.
#
# `ocp node rm NAME` reads the named OCPNode first. Every failed read was
# taken for "there is none": the rejection said "Unknown node 'NAME'." and
# listed the ones there are -- for a node that exists but could not be read
# (an RBAC 403, an apiserver 5xx, an API that does not answer). The claims:
#
#   * a 404 still is "Unknown node 'NAME'." with the listing (control)
#   * any other failed read is said as that: "Could not read OCPNode 'NAME'
#     from the cluster API: <cause>", the cause through
#     OCP::ErrorLine::cause_line -- an APIError as the cluster API's line,
#     anything else without its source location -- then "Nothing was
#     removed."
#   * no "Unknown node", no listing (the OCPNodes are not even listed), and
#     nothing is deleted
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
        die $s->{get_error};
    }
    sub list {
        my ($s, $kind) = @_;
        push @{ $s->{calls} }, "list $kind";
        return FakeList->new([ { metadata => { name => 'worker-1' } } ]);
    }
    sub delete { push @{ $_[0]{calls} }, 'delete'; 1 }
}

sub rm_error {
    my ($get_error) = @_;
    my $k8s = FakeK8s->new(get_error => $get_error);
    eval { OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'crag')->execute([], []) };
    return ($@, $k8s);
}

subtest 'control: a 404 is an unknown node, with the ones there are' => sub {
    my ($err) = rm_error(Kubernetes::REST::APIError->new(code => 404, context => 'get',
        body => '{"kind":"Status","reason":"NotFound","code":404}'));
    is $err, "Unknown node 'crag'.\nAvailable: worker-1\n", 'the rejection, as before';
};

my @FAILURES = (
    [ 'a 403' => Kubernetes::REST::APIError->new(code => 403, context => 'get',
          body => '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}'),
      'The cluster API denied the request (403 Forbidden)' ],
    [ 'a 500' => Kubernetes::REST::APIError->new(code => 500, context => 'get',
          body => '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"InternalError","message":"etcd timed out","code":500}'),
      qr/\AThe cluster API .*\b500\b.*etcd timed out\z/ ],
    [ 'no answer' => Kubernetes::REST::APIError->new(code => 599, context => 'get',
          body => "Can't connect to 10.0.0.1:6443 (Connection refused)\n\nConnection refused at LWP/Protocol/http.pm line 50.\n"),
      "The cluster API could not be reached: Can't connect to 10.0.0.1:6443 (Connection refused)" ],
    [ 'a croak' => "the read broke\n  over two lines at lib/Fake.pm line 7.\n",
      'the read broke over two lines' ],
);

for my $case (@FAILURES) {
    my ($what, $error, $cause) = @$case;
    subtest "$what: the failed read is said, the node is not called unknown" => sub {
        my ($err, $k8s) = rm_error($error);
        my ($first, $second, @rest) = split /\n/, $err;
        my $prefix = "Could not read OCPNode 'crag' from the cluster API: ";
        is substr($first // '', 0, length $prefix), $prefix, 'the failed read, named';
        my $said = substr($first // '', length $prefix);
        ref $cause ? like($said, $cause, 'its cause in one line')
                   : is($said, $cause, 'its cause in one line');
        is $second, 'Nothing was removed.', 'and that nothing was removed';
        is scalar(@rest), 0, 'nothing more' or diag $err;
        unlike $err, qr/Unknown node|Available:|No OCPNode exists| at \S+ line \d+/,
            'no unknown node, no listing, no source location';
        is_deeply $k8s->{calls}, ['get OCPNode'], 'one read, no list, nothing deleted';
    };
}

done_testing;

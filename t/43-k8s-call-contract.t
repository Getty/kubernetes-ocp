use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

use lib 'lib';

use Kubernetes::REST;
use OCP::K8s;

#
# The Kubernetes::REST call contract, pinned.
#
# OCP::Node addressed the API server like this for its whole life:
#
#     $k8s->get('ocp.internal/v1', 'OCPNode', $name, namespace => $ns)
#     $k8s->delete('v1', 'Node', $k8s_name)
#     $k8s->update($plain_hashref)
#
# None of those exist. Kubernetes::REST takes the Kind in argument 0 and
# resolves it through expand_class(); an api-version there is not a
# mis-addressed request but an immediate death. update() calls ->metadata on
# its argument, so a hash dies too. Since _acquire_lease is the first thing
# _provision does, and both teardown deletes sit inside eval blocks, the
# failures were either instant (node straight to phase=Failed) or completely
# silent (teardown reporting success while leaving the Node and the CR
# behind).
#
# The reason this survived is that the test double accepted every signature.
# t/16-node.t no longer has one -- it drives a real Kubernetes::REST over a
# mock transport. This file states the contract that double relies on, so if
# a future Kubernetes::REST changes the rules, the mismatch shows up here as
# a plain statement about the client rather than as a puzzling failure in the
# node tests.
#

package Resp {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { 200 }
    sub content { '{"apiVersion":"ocp.internal/v1","kind":"OCPNode","metadata":{"name":"w1","namespace":"ocp-system"}}' }
    sub headers { {} }
}

package Transport {
    sub new { my ($c, %a) = @_; bless { seen => [], %a }, $c }
    sub call {
        my ($self, $req) = @_;
        my $path = $req->url;
        $path =~ s{^https?://[^/]+}{};
        push @{ $self->{seen} }, { method => $req->method, path => $path };
        return Resp->new;
    }
}

package main;

sub client {
    my $t   = Transport->new;
    my $api = Kubernetes::REST->new(
        server                    => { endpoint => 'https://cluster.invalid:6443' },
        credentials               => { token => 'fake' },
        io                        => $t,
        resource_map_from_cluster => 0,
    );
    OCP::K8s->register($api);
    return ($api, $t);
}

subtest 'an api-version in argument 0 is fatal, not merely wrong' => sub {
    my ($api, $t) = client();

    # These shapes make Kubernetes::REST warn on its way to dying (the stray
    # arguments land in an odd-sized hash assignment). That is part of the
    # evidence, not a problem with the test.
    local $SIG{__WARN__} = sub {};

    ok !eval { $api->get('ocp.internal/v1', 'OCPNode', 'w1', namespace => 'ocp-system'); 1 },
        'get(api_version, Kind, name, ...) dies';
    ok !eval { $api->delete('ocp.internal/v1', 'OCPNode', 'w1', namespace => 'ocp-system'); 1 },
        'delete(api_version, Kind, name, ...) dies';
    ok !eval { $api->delete('v1', 'Node', 'w1'); 1 },
        "delete('v1', 'Node', name) dies -- core group is no more addressable this way";

    is scalar @{ $t->{seen} }, 0,
        'none of them reached the transport: they die before a request is built';
};

subtest 'the Kind-first shapes OCP::Node now uses do reach the right paths' => sub {
    my ($api, $t) = client();

    $api->get('OCPNode', 'w1', namespace => 'ocp-system');
    $api->get('Node', name => 'w1');
    $api->delete('OCPNode', 'w1', namespace => 'ocp-system');
    $api->delete('Node', 'w1');

    is_deeply [ map { "$_->{method} $_->{path}" } @{ $t->{seen} } ], [
        'GET /apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/w1',
        'GET /api/v1/nodes/w1',
        'DELETE /apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/w1',
        'DELETE /api/v1/nodes/w1',
    ], 'namespaced CRD and core Node resolve to their real endpoints';
};

subtest 'update() takes a blessed IO::K8s object, never a hash' => sub {
    my ($api, $t) = client();

    my $struct = {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
        metadata   => { name => 'w1', namespace => 'ocp-system', resourceVersion => '100' },
        spec       => { role => 'worker' },
    };

    my $err = do { local $@; eval { $api->update($struct); 1 }; $@ };
    ok $err, 'update(hashref) dies';
    like $err, qr/unblessed reference/, 'because it calls ->metadata on its argument';

    my $obj = $api->k8s->struct_to_object($api->k8s->expand_class('OCPNode'), $struct);
    ok eval { $api->update($obj); 1 }, 'update(typed object) succeeds';
    is $t->{seen}[0]{method}, 'PUT', 'and issues a PUT';
    is $t->{seen}[0]{path}, '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/w1',
        'to the object it names';
};

subtest 'expand_class resolves the registered CRDs but not an api-version' => sub {
    my ($api) = client();
    is $api->k8s->expand_class('OCPNode'), 'OCP::K8s::OCPNode',
        'OCPNode is registered';
    is $api->k8s->expand_class('OCPNodeProvider'), 'OCP::K8s::OCPNodeProvider',
        'OCPNodeProvider is registered';
    ok !eval { $api->k8s->expand_class('ocp.internal/v1')->can('kind'); 1 },
        'an api-version does not resolve to a usable class';
};

#
# Repo-wide guard. Every other call site in lib/ already had the Kind-first
# form; only OCP::Node drifted. This keeps it that way, including in the
# modules the node path depends on.
#
# The alternation below is deliberately not just the raw Kubernetes::REST
# methods (get/delete/patch/list/ensure): _delete_object is OCP::Node's own
# wrapper around ->k8s->delete($kind, $name, @args) (added alongside it in
# #35, see t/55-robocop-rbac.t), and a literal Kind passed to *it* is just as
# exposed to the api-version-first mistake as a literal passed straight to
# ->delete. Checked repo-wide (grep for `->\w+\(\s*'[A-Z]` outside this
# alternation, filtered to args shaped like a Kind) for other same-shape
# wrappers -- i.e. something that takes a literal Kind and forwards it to a
# raw k8s call -- and _delete_object is the only one; the other hits were
# _report_component('Registry', ...) (a display label), ->new('AES', ...)
# (a cipher name) and ->child('Rexfile', ...) (a path segment), none of which
# go anywhere near Kubernetes::REST.
#
# This list still has to be maintained by hand when the next wrapper like
# this appears -- that is the same brittleness #68 hit in the deployed-hash
# scan, just not fixable the same way: #68's fix worked because "which files"
# has a structural answer (a directory). "Which method names forward a
# literal Kind to a raw k8s call" has no such anchor here without either
# risking false positives (dropping the alternation and keying off the
# Kind-shaped literal alone catches ->scp_to('/local/file'),
# ->_parse_image_ref('ghcr.io/foo/bar:v1.2.3') and similar -- confirmed by
# running that broadened form over lib/) or parsing call graphs, which is
# more than a regex-based repo scan should take on. Fixing it for real is a
# separate ticket, not a guess to bake in here.
#
subtest 'no call site in lib/ passes an api-version as argument 0' => sub {
    my @pm;
    path('lib')->visit(
        sub { my ($p) = @_; push @pm, $p if $p->is_file && "$p" =~ /\.pm$/ },
        { recurse => 1 },
    );
    ok scalar @pm, 'found modules to scan';

    my @bad;
    for my $file (@pm) {
        my @lines = split /\n/, $file->slurp_utf8;
        for my $i (0 .. $#lines) {
            next if $lines[$i] =~ /^\s*#/;
            while ($lines[$i] =~ /->(get|delete|patch|list|ensure|_delete_object)\(\s*'([^']+)'/g) {
                my ($method, $kind) = ($1, $2);
                next unless $kind =~ m{/} || $kind =~ /^v\d+((alpha|beta)\d*)?$/;
                push @bad, sprintf('%s:%d %s(%s)', $file, $i + 1, $method, $kind);
            }
        }
    }
    is_deeply \@bad, [], 'argument 0 is always a Kind'
        or diag "api-version-first calls:\n  " . join("\n  ", @bad);
};

subtest 'OCP::Node writes the CR through one typed seam' => sub {
    my $src = path('lib/OCP/Node.pm')->slurp_utf8;

    my @updates = $src =~ /->update\(/g;
    is scalar @updates, 1,
        'exactly one ->update call, so there is one place that can get the typing wrong';

    my ($put_cr) = $src =~ /^sub _put_cr \{\n(.*?)\n\}$/ms;
    ok defined $put_cr, '_put_cr exists';
    like $put_cr, qr/struct_to_object/,
        'and it converts the struct to a typed object before updating';

    unlike $src, qr/sub _api_version/,
        'the _api_version helper is gone -- there is nothing left to pass as argument 0';
};

subtest 'the reconcile dispatch can reach the agent install' => sub {
    my $src = path('lib/OCP/Node.pm')->slurp_utf8;
    my ($reconcile) = $src =~ /^sub reconcile \{\n(.*?)\n\}$/ms;
    ok defined $reconcile, 'reconcile() found';

    # _provision writes phase=Installing; if that phase does not lead to the
    # install, the agent is never put on the machine.
    like $reconcile, qr/\$p eq 'Installing'\s*\)\s*\{\s*\$self->_install_kubernetes/,
        'Installing dispatches to _install_kubernetes';

    my ($provision) = $src =~ /^sub _provision \{\n(.*?)\n\}$/ms;
    like $provision, qr/phase\s*=>\s*'Installing'/,
        'and that is the phase _provision writes';
};

done_testing;

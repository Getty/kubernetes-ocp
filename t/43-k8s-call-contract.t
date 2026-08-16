use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use JSON::MaybeXS ();

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
        push @{ $self->{seen} }, {
            method       => $req->method,
            path         => $path,
            body         => $req->content,
            content_type => $req->headers->{'Content-Type'},
        };
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

#
# Status writes. Kubernetes::REST had no /status method until 1.107, so
# OCP::K8s carried a hand-built one and preferred a native writer if the client
# ever grew one. It did -- and the flat hash OCP forwarded (kind/name/status)
# is not a shape that method accepts, so the day 1.107 landed on a machine the
# whole node path died with "Invalid arguments to patch_status()" without a
# line changing in this repo. The argument form is therefore part of the
# contract this file pins, not an implementation detail of OCP::K8s.
#
subtest 'patch_status takes the Kind first and the payload under patch' => sub {
    my ($api, $t) = client();

    # As with the api-version-first shapes above, the rejected form warns on
    # its way to dying. That is evidence, not noise.
    local $SIG{__WARN__} = sub {};

    ok !eval { $api->patch_status(kind => 'OCPNode', name => 'w1',
                                  namespace => 'ocp-system',
                                  status    => { phase => 'Ready' }); 1 },
        'the flat kind/name/status form dies -- it is not a supported shape';
    is scalar @{ $t->{seen} }, 0, 'and dies before a request is built';

    $api->patch_status('OCPNode',
        name      => 'w1',
        namespace => 'ocp-system',
        patch     => { status => { phase => 'Ready' } },
    );

    is scalar @{ $t->{seen} }, 1, 'the supported shape issues one request';
    is $t->{seen}[0]{method}, 'PATCH', 'PATCH verb';
    is $t->{seen}[0]{path},
        '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/w1/status',
        'the client appends the /status subresource itself';
    is $t->{seen}[0]{content_type}, 'application/merge-patch+json',
        'and defaults to merge-patch';
    is JSON::MaybeXS::decode_json($t->{seen}[0]{body})->{status}{phase}, 'Ready',
        'the patch payload is sent as given';
};

subtest 'OCP::K8s->patch_status reaches that same endpoint' => sub {
    my ($api, $t) = client();

    OCP::K8s->patch_status($api,
        kind      => 'OCPNode',
        name      => 'w1',
        namespace => 'ocp-system',
        status    => { phase => 'Installing', providerId => 'SRV42' },
    );

    is scalar @{ $t->{seen} }, 1, 'one request';
    is $t->{seen}[0]{path},
        '/apis/ocp.internal/v1/namespaces/ocp-system/ocpnodes/w1/status',
        'OCP\'s flat call form is translated, not forwarded';
    my $sent = JSON::MaybeXS::decode_json($t->{seen}[0]{body});
    is $sent->{status}{phase}, 'Installing', 'phase carried';
    is $sent->{status}{providerId}, 'SRV42', 'and the rest of the status with it';
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
# The list of method names to scan is derived dynamically. Kubernetes::REST's
# own API surface is read at test time from its package symbol table -- any
# public, lowercase method becomes a candidate. That covers every Kind-bearing
# call (get/list/delete/patch/patch_status/watch/...) without naming each one,
# so when Kubernetes::REST grows patch_status - or anything after it - the
# next day the scan knows about it too. The list is then extended with the
# OCP-internal wrappers that forward a literal Kind straight to a raw k8s
# call (today only _delete_object in OCP::Node, added in #35 -- see
# t/55-robocop-rbac.t). New wrappers of that shape are rare enough that a
# static list is fine; the rest of the test sweeps the repo-wide surface
# regardless of which method names appear.
#
# What this used to do (kept here as the cautionary tale): hard-code
# `(get|delete|patch|list|ensure|_delete_object)`. That dropped _delete_object
# silently for every PR that touched it before #35, and would drop the next
# new Kubernetes::REST method (patch_status, update_status, watch, ...) the
# same way. Going purely on Kind-shaped literals - i.e. dropping the
# alternation entirely - was tried and rejected: it catches real
# non-Kubernetes::REST call sites like ->scp_to('/local/file'),
# ->_parse_image_ref('ghcr.io/foo/bar:v1.2.3') and ->new('AES', ...),
# which a static allow-list of strings cannot cure.
#
sub _kubernetes_rest_public_methods {
    # Read Kubernetes::REST.pm at test time and pick out the method names
    # the package author actually wrote -- i.e. every top-level `sub NAME
    # {` definition. That is the authoritative public API surface:
    # anything declared via `has => handles => [...]` or generated by Moo
    # is excluded for free, because none of those produce a `sub NAME {`
    # in the source. We further strip leading-underscore privates
    # (lowercase or otherwise -- the module reserves _ for internals) and
    # API-group accessors like Core/Apps/Networking (capitalised), which
    # take a literal API group as argument 0 rather than a Kind.
    my $src_file = $INC{'Kubernetes/REST.pm'} or die
        "Kubernetes/REST.pm not loaded -- cannot derive its method list";
    open my $fh, '<', $src_file or die "cannot open $src_file: $!";
    my @methods;
    while (my $line = <$fh>) {
        next unless $line =~ /^sub\s+([a-z]\w*)\s*\{/;
        push @methods, $1;
    }
    close $fh;
    return @methods;
}

# OCP-internal wrappers that forward a literal Kind to a raw k8s call. List
# is small and intentional; new entries are a one-line addition whenever a
# same-shape helper is introduced.
my @OCP_KIND_FIRST_WRAPPERS = qw(_delete_object);

subtest 'no call site in lib/ passes an api-version as argument 0' => sub {
    my @pm;
    path('lib')->visit(
        sub { my ($p) = @_; push @pm, $p if $p->is_file && "$p" =~ /\.pm$/ },
        { recurse => 1 },
    );
    ok scalar @pm, 'found modules to scan';

    # The alternation now picks up every public Kubernetes::REST method +
    # each OCP-internal forwarding wrapper. A new method lands in the
    # alternation the moment Kubernetes::REST exposes it -- no test edit
    # required.
    my @methods = (_kubernetes_rest_public_methods(), @OCP_KIND_FIRST_WRAPPERS);
    my $methods_re = join '|', map { quotemeta } @methods;

    my @bad;
    for my $file (@pm) {
        my @lines = split /\n/, $file->slurp_utf8;
        for my $i (0 .. $#lines) {
            next if $lines[$i] =~ /^\s*#/;
            while ($lines[$i] =~ /->($methods_re)\(\s*'([^']+)'/g) {
                my ($method, $kind) = ($1, $2);
                next unless $kind =~ m{/} || $kind =~ /^v\d+((alpha|beta)\d*)?$/;
                push @bad, sprintf('%s:%d %s(%s)', $file, $i + 1, $method, $kind);
            }
        }
    }
    is_deeply \@bad, [], 'argument 0 is always a Kind'
        or diag "api-version-first calls:\n  " . join("\n  ", @bad);
};

#
# Regression for karr #75: the alternation used to be a hand-kept list of
# method names. Demonstrating that the dynamic derivation is in effect --
# i.e. the alternation knows about methods that did NOT exist as literals
# in the old regex. If this fails, something has re-hardcoded the method
# list and silently stopped covering the rest of Kubernetes::REST's API.
#
subtest 'the kind-bearing method list is derived from Kubernetes::REST, not hand-kept' => sub {
    my @methods = _kubernetes_rest_public_methods();
    ok scalar @methods, 'introspection found methods';

    # patch_status and watch are part of Kubernetes::REST's API but were
    # not in the hand-kept alternation before karr #75. If either is
    # missing from the introspection list, the dynamic derivation has
    # regressed to a static allow-list.
    ok( (scalar grep { $_ eq 'patch_status' } @methods),
        'patch_status is covered (it was added to Kubernetes::REST after the original hand-kept list)' );
    ok( (scalar grep { $_ eq 'watch' } @methods),
        'watch is covered' );

    # _delete_object is the one OCP-internal forwarding wrapper at the
    # time of karr #75; the subtest above joins it back in. The full
    # alternation the scan actually used is therefore a superset of the
    # old hand-kept list, which is the whole point of the ticket.
    my @combined = (@methods, @OCP_KIND_FIRST_WRAPPERS);
    for my $old (qw(get delete patch list ensure _delete_object)) {
        ok( (scalar grep { $_ eq $old } @combined),
            "$old still covered (every name the old regex had)" );
    }
    # 6 is the size of the old hand-kept alternation
    # (get|delete|patch|list|ensure|_delete_object). Pinning it as a literal
    # avoids a qw() in scalar context (which returns the trailing element
    # as a string and would warn under `>`, since "_delete_object" is not
    # numeric).
    ok( scalar(@combined) > 6,
        'derived list strictly larger than the old hand-kept one' );

    # The helper being right is not enough on its own: someone could leave
    # the helper in place but stop using it (a half-revert). A direct
    # exercise of the assembled regex on a representative string proves
    # that the alternation the scan actually runs against lib/ is the one
    # built from the helper, not a forgotten literal.
    my $methods_re = join '|', map { quotemeta } @combined;
    like '->patch_status(\'ocp.internal/v1\', \'OCPNode\', \'w1\')',
        qr/->($methods_re)\(\s*'[^']*\/v\d+/,
        'the assembled alternation catches an api-version-shaped literal in patch_status (old hand-kept list did not)';
    like '->watch(\'v1\', \'Pod\', \'w1\')',
        qr/->($methods_re)\(\s*'v\d+/,
        'and the same for watch';
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

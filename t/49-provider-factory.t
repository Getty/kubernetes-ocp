#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# Pure-dispatch test for OCP::Provider. The seam earns its keep only if both
# entry points reach the same _build and the same adapter comes back. We do
# not exercise the adapter itself here — t/12-provider.t and t/46-existing-
# host-role.t own that.

use OCP::Provider;
use OCP::Provider::Hetzner;
use OCP::Provider::SSH;
use OCP::Provider::Local;
use OCP::Role::Provider::ExistingHost;

use MIME::Base64 qw(encode_base64);

# Each test block that needs a fake k8s client uses its own package.
# Defined up here, in main:: scope, so the per-block `package` switch
# inside subtests below does not break `encode_base64` lookups.
package FakeK8sDispatch;
sub get { $_[0]{secret} }

package FakeK8sMissingRef;
sub get { undef }

package FakeK8sShared;
sub get { $_[0]{secret} }

package main;

my $dispatch_k8s = bless {
    secret => { data => { token => encode_base64('tok', '') } },
}, 'FakeK8sDispatch';

my $missing_ref_k8s = bless {}, 'FakeK8sMissingRef';

my $shared_k8s = bless {
    secret => { data => { token => encode_base64('shared-tok', '') } },
}, 'FakeK8sShared';

#
# for_spec: each provider type → matching adapter
#

{
    my $p = OCP::Provider->for_spec(
        { provider => 'hetzner' },
        token        => 'tok',
        cluster_name => 'c',
    );
    isa_ok $p, 'OCP::Provider::Hetzner', 'for_spec(hetzner) -> OCP::Provider::Hetzner';
}

{
    my $p = OCP::Provider->for_spec(
        { provider => 'ssh' },
        ssh_key_path => '/tmp/k',
    );
    isa_ok $p, 'OCP::Provider::SSH', 'for_spec(ssh) -> OCP::Provider::SSH';
}

{
    my $p = OCP::Provider->for_spec({ provider => 'local' });
    isa_ok $p, 'OCP::Provider::Local', 'for_spec(local) -> OCP::Provider::Local';
}

#
# from_cr: each provider type → matching adapter
#

subtest 'from_cr dispatches each type' => sub {
    my %cr_for = (
        hetzner => {
            metadata => { name => 'hz', namespace => 'ocp-system' },
            spec     => {
                type    => 'hetzner',
                hetzner => { tokenSecretRef => { name => 'sec', key => 'token' } },
            },
        },
        ssh => {
            metadata => { name => 's', namespace => 'ocp-system' },
            spec     => { type => 'ssh', ssh => { keyPath => '/k' } },
        },
        local => {
            metadata => { name => 'l', namespace => 'ocp-system' },
            spec     => { type => 'local' },
        },
    );

    my %expected = (
        hetzner => 'OCP::Provider::Hetzner',
        ssh     => 'OCP::Provider::SSH',
        local   => 'OCP::Provider::Local',
    );

    for my $type (qw(hetzner ssh local)) {
        my $p = OCP::Provider->from_cr($cr_for{$type}, k8s => $dispatch_k8s);
        isa_ok $p, $expected{$type}, "from_cr($type) -> $expected{$type}";
    }
};

#
# Default provider is hetzner (spec without provider => hetzner)
#

{
    my $p = OCP::Provider->for_spec({}, token => 'tok', cluster_name => 'c');
    isa_ok $p, 'OCP::Provider::Hetzner', 'for_spec({}) defaults to hetzner';
}

# An empty CR spec also defaults to hetzner — without tokenSecretRef the
# dispatch gets far enough to die with a clear field name. The assertion is
# the error text, not the resulting class.
eval {
    OCP::Provider->from_cr(
        { metadata => { name => 'd' }, spec => {} },
        k8s => $missing_ref_k8s,
    );
};
like($@, qr/tokenSecretRef/,
    'from_cr with empty spec defaults to hetzner (dies on missing ref)');

#
# SSH and Local consume ExistingHost; Hetzner does not.
#
# The role is the seam: any host-based adapter must consume it. The test
# fails the day someone adds a third host-based provider and forgets the
# `with`.
#

ok(OCP::Provider::SSH->DOES('OCP::Role::Provider::ExistingHost'),
    'OCP::Provider::SSH consumes OCP::Role::Provider::ExistingHost');
ok(OCP::Provider::Local->DOES('OCP::Role::Provider::ExistingHost'),
    'OCP::Provider::Local consumes OCP::Role::Provider::ExistingHost');
ok(!OCP::Provider::Hetzner->DOES('OCP::Role::Provider::ExistingHost'),
    'OCP::Provider::Hetzner does NOT consume the host role (it manages hosts, not just uses them)');

#
# Missing provider dies loud: from_cr with no tokenSecretRef on a hetzner CR
#

subtest 'from_cr with missing tokenSecretRef dies with a useful message' => sub {
    my $cr = {
        metadata => { name => 'hz' },
        spec     => { type => 'hetzner', hetzner => {} },  # no tokenSecretRef
    };

    eval { OCP::Provider->from_cr($cr, k8s => $missing_ref_k8s) };
    like $@, qr/tokenSecretRef\.name missing/, 'missing tokenSecretRef.name names the field';
};

#
# Unknown provider type dies loud — both entry points
#

subtest 'for_spec dies loud on unknown type' => sub {
    eval { OCP::Provider->for_spec({ provider => 'aws' }) };
    like $@, qr/Unsupported provider/, 'for_spec unknown dies with one message (single dispatch)';
};

subtest 'from_cr dies loud on unknown type' => sub {
    my $cr = {
        metadata => { name => 'x' },
        spec     => { type => 'aws' },
    };
    eval { OCP::Provider->from_cr($cr, k8s => undef) };
    like $@, qr/Unsupported provider/, 'from_cr unknown dies with the same message';
};

#
# The two entry points produce adapters with the same configuration shape
# when given equivalent inputs. The whole point of the dedup.
#

subtest 'for_spec and from_cr reach the same adapter when given the same args' => sub {
    my $via_spec = OCP::Provider->for_spec(
        { provider => 'hetzner' },
        token        => 'shared-tok',
        cluster_name => 'shared',
    );

    my $via_cr = OCP::Provider->from_cr({
        metadata => { name => 'shared', namespace => 'ocp-system' },
        spec     => {
            type    => 'hetzner',
            hetzner => { tokenSecretRef => { name => 'sec', key => 'token' } },
        },
    }, k8s => $shared_k8s);

    isa_ok $via_spec, 'OCP::Provider::Hetzner', 'spec adapter class';
    isa_ok $via_cr,   'OCP::Provider::Hetzner', 'cr adapter class';
    is $via_spec->token,        $via_cr->token,
        'token identical between the two entry points';
    is $via_spec->cluster_name, $via_cr->cluster_name,
        'cluster_name identical between the two entry points';
};

done_testing;

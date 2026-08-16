#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::MaybeXS ();
use MIME::Base64 qw(encode_base64);
use Path::Tiny qw(path);

use lib 'lib';

#
# The ocp-cluster label a Hetzner server is born with — karr #98.
#
# One value, written by two different code paths, and for a long time they did
# not agree. Bootstrap builds its adapter through OCP::Provider::for_spec and
# passes cluster_name => $config->name, so the control plane came up labelled
# ocp-cluster=<cluster>. Every worker goes through OCP::Provider::from_cr
# instead — `ocp node add` and robocop both — and that took the PROVIDER CR's
# own name, which OCP::Cmd::Apply::CR::ensure_provider_cr writes as
# "<type>-default". So workers came up labelled ocp-cluster=hetzner-default.
#
# Nothing complained. Two things quietly followed, and both cost money:
#
#   * `ocp destroy` lists by ocp-cluster=<cluster>. It never saw those
#     machines. They keep running, keep billing, and the teardown prints
#     "Cluster destroyed."
#   * server_exists matches ocp-cluster=<cluster>/ocp-node=<name>, so a second
#     provisioning pass could not recognise the server it had already created
#     and made a SECOND one.
#
# Both consequences come off the same label, so one assertion covers both: a
# server created through the worker path must carry the same ocp-cluster label
# as one created by bootstrap. This file asserts it across the whole seam —
# the CR that `ocp apply` really writes, read back by the factory the worker
# path really uses, into a create_server call driven by OCP::Node::_provision.
#

#
# The Kubernetes client is a REAL Kubernetes::REST with a recording transport
# under it, for the reason spelled out at the top of t/16-node.t: a
# hand-written double answers signatures the real client refuses, and OCP::Node
# shipped calls no real cluster would have accepted while such a double stayed
# green. Only the HTTP call is faked here.
#

package MockResponse {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
    sub headers { {} }
}

package MockTransport {
    my $JSON = JSON::MaybeXS->new(utf8 => 1, canonical => 1, convert_blessed => 1);

    sub new { my ($c, %a) = @_; bless {%a}, $c }

    sub call {
        my ($self, $req) = @_;
        my $api = $self->{api};

        my $path = $req->url;
        $path =~ s{^https?://[^/]+}{};

        push @{ $api->requests }, {
            method => $req->method,
            path   => $path,
            body   => $req->content,
        };

        my ($status, $struct) = $self->_respond($api, $req->method, $path, $req->content);
        return MockResponse->new(status => $status, content => $JSON->encode($struct));
    }

    sub _respond {
        my ($self, $api, $method, $path, $body) = @_;

        # Writes echo the object back, the way the API server does.
        return (200, $JSON->decode($body)) if $method eq 'PUT' || $method eq 'PATCH';

        if ($path =~ m{/ocpnodes/([^/]+)$}) {
            my $cr = $api->cr;
            return $cr ? (200, $cr) : (404, { message => "ocpnodes \"$1\" not found" });
        }
        if ($path =~ m{/ocpnodeproviders/([^/]+)$}) {
            my $p = $api->provider_cr;
            return $p ? (200, $p) : (404, { message => "ocpnodeproviders \"$1\" not found" });
        }
        # The Hetzner token lives in a Secret, and in the cluster it comes off
        # the same client the CRs do.
        if ($path =~ m{^/api/v1/namespaces/[^/]+/secrets/([^/]+)$}) {
            my $s = $api->secret;
            return $s ? (200, $s) : (404, { message => "secrets \"$1\" not found" });
        }
        return (404, { message => "unexpected path $path" });
    }
}

package StrictK8s {
    use Moo;
    use OCP::K8s;
    extends 'Kubernetes::REST';

    has requests    => (is => 'ro', default => sub { [] });
    has cr          => (is => 'rw');
    has provider_cr => (is => 'rw');
    has secret      => (is => 'rw');

    sub build {
        my (%args) = @_;
        my $transport = MockTransport->new;
        my $self = StrictK8s->new(
            server                    => { endpoint => 'https://cluster.invalid:6443' },
            credentials               => { token => 'fake-token' },
            resource_map_from_cluster => 0,
            io                        => $transport,
            %args,
        );
        $transport->{api} = $self;
        OCP::K8s->register($self);
        return $self;
    }
}

# Only the cloud client under OCP::Provider::Hetzner is faked, so the adapter
# itself — including the labels it builds — runs for real.
package FakeHzServer {
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub id   { $_[0]{id} }
    sub name { $_[0]{name} }
    sub ipv4 { $_[0]{ipv4} }
}

package FakeHzServers {
    sub new { my ($c, %a) = @_; bless { created => [], queries => [], %a }, $c }
    sub list_by_label {
        my ($self, $selector) = @_;
        push @{ $self->{queries} }, $selector;
        return $self->{existing} // [];
    }
    sub create {
        my ($self, %params) = @_;
        push @{ $self->{created} }, \%params;
        return FakeHzServer->new(id => 'SRV-' . scalar @{ $self->{created} });
    }
    sub wait_for_status {
        my ($self, $id) = @_;
        return FakeHzServer->new(id => $id, ipv4 => '203.0.113.7');
    }
}

package FakeHzCloud {
    sub new     { my ($c, %a) = @_; bless { servers => FakeHzServers->new(%a) }, $c }
    sub servers { $_[0]{servers} }
}

# `ocp apply` reads the token off OCP::Secrets; ensure_provider_cr only ever
# asks for hetzner_token.
package FakeSecrets {
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub hetzner_token { $_[0]{token} }
}

# Records what ensure_provider_cr writes. It is the writer end of the seam and
# the only thing that can supply the cluster name, so the CR it produces — not
# a fixture typed out here — is what the reader end gets fed below.
package RecordingApi {
    sub new { my ($c) = @_; bless { ensured => [] }, $c }
    sub ensure {
        my ($self, $doc) = @_;
        push @{ $self->{ensured} }, $doc;
        return $doc;
    }
    sub for_kind {
        my ($self, $kind) = @_;
        my ($doc) = grep { $_->{kind} eq $kind } @{ $self->{ensured} };
        return $doc;
    }
}

package main;

use OCP::Cmd::Apply::CR;
use OCP::Config;
use OCP::Node;
use OCP::Provider;
use OCP::Provider::Hetzner;

my $CLUSTER = 'cortex';

# A real project on disk: the cluster name has exactly one source, and both
# ends of the seam have to reach the same one.
my $tmp = Path::Tiny->tempdir;
$tmp->child('.ocp')->mkpath;
$tmp->child('ocp.yaml')->spew(<<"YAML");
name: $CLUSTER
control_planes:
  - provider: hetzner
    location: fsn1
workers:
  - name: pool-a
    provider: hetzner
    nodes: 1
YAML

my $config = OCP::Config->new(file => $tmp->child('ocp.yaml')->stringify);
is $config->name, $CLUSTER, 'config carries the cluster name the labels must match';

#
# Writer end: the provider CR `ocp apply` writes carries the cluster name.
#
# $self is unused by ensure_provider_cr (it is a plain package function that
# only reads $api/$config/$secrets), so undef is honest here — the day it
# starts needing the command object this line fails loudly.
#

my $rec = RecordingApi->new;
OCP::Cmd::Apply::CR::ensure_provider_cr(
    undef, $rec, 'hetzner', 'ocp-system', $config, FakeSecrets->new(token => 'hz-tok'),
);

my $provider_cr = $rec->for_kind('OCPNodeProvider');
ok $provider_cr, 'ensure_provider_cr wrote an OCPNodeProvider';
is $provider_cr->{metadata}{name}, 'hetzner-default',
    'and named it after the TYPE, not the cluster — which is the whole trap';
is $provider_cr->{spec}{clusterName}, $CLUSTER,
    'spec.clusterName carries the real cluster name';
isnt $provider_cr->{spec}{clusterName}, $provider_cr->{metadata}{name},
    'the two differ, so a reader taking metadata.name gets it wrong';

my $secret_cr = $rec->for_kind('Secret');
ok $secret_cr, 'and the token Secret the CR points at';

#
# THE assertion: worker path and bootstrap path label a server identically.
#

# Bootstrap: OCP::Cmd::Apply::Bootstrap builds its adapter with
# cluster_name => $config->name and also passes cluster => $config->name to
# create_server. Both agree, so what lands on the machine is $config->name.
sub bootstrap_label {
    my $cloud = FakeHzCloud->new;
    my $prov  = OCP::Provider->for_spec(
        { provider => 'hetzner' },
        token        => 'hz-tok',
        cluster_name => $config->name,
    );
    # `cloud` is a lazy attribute; handing one in replaces the builder.
    $prov = OCP::Provider::Hetzner->new(
        token        => $prov->token,
        cluster_name => $prov->cluster_name,
        cloud        => $cloud,
    );
    $prov->create_server(
        name     => 'cp1',
        cluster  => $config->name,
        node     => 'cp1',
        role     => 'control-plane',
        ssh_keys => [ $config->admin_ssh_key_name ],
    );
    return $cloud->servers->{created}[0]{labels}{'ocp-cluster'};
}

# Worker: the CR above, read back by the factory OCP::Node uses, then driven
# through _provision — the call shape robocop and `ocp node add` produce.
sub worker_provision {
    my $k8s = StrictK8s::build();
    $k8s->secret({
        apiVersion => 'v1',
        kind       => 'Secret',
        metadata   => { name => $secret_cr->{metadata}{name}, namespace => 'ocp-system' },
        data       => { token => encode_base64('hz-tok', '') },
    });
    $k8s->cr({
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => 'pool-a-1', namespace => 'ocp-system' },
        spec       => { role => 'worker', providerRef => 'hetzner-default' },
    });
    $k8s->provider_cr($provider_cr);

    # The CR is READ BACK through the client rather than handed over as the
    # hash `ocp apply` built. That is the whole in-cluster path: robocop gets
    # a typed OCP::K8s::OCPNodeProvider off the API and converts it with
    # object_to_struct, and a field that did not survive that round trip would
    # be invisible exactly where nobody can hand one in. `spec` is declared as
    # a free-form pass-through on the class, and this is what proves it.
    my $fetched = $k8s->k8s->object_to_struct(
        $k8s->get('OCPNodeProvider', 'hetzner-default', namespace => 'ocp-system')
    );
    is $fetched->{spec}{clusterName}, $CLUSTER,
        'clusterName survives the typed round trip robocop reads through';

    my $provider = OCP::Provider->from_cr($fetched, k8s => $k8s);
    my $cloud    = FakeHzCloud->new;
    $provider    = OCP::Provider::Hetzner->new(
        token        => $provider->token,
        cluster_name => $provider->cluster_name,
        ssh_key_name => $provider->ssh_key_name,
        cloud        => $cloud,
    );

    my $node = OCP::Node->from_cr($k8s->cr,
        k8s           => $k8s,
        provider      => $provider,
        reconciler_id => 'robocop',
    );
    $node->_provision;

    return $cloud->servers;
}

my $boot_label = bootstrap_label();
is $boot_label, $CLUSTER, 'bootstrap labels its server with the cluster name';

my $worker_servers = worker_provision();
my $sent = $worker_servers->{created}[0];
ok $sent, 'the worker path created a server';

is $sent->{labels}{'ocp-cluster'}, $boot_label,
    'a server from _provision carries the SAME ocp-cluster label as one from bootstrap';
is $sent->{labels}{'ocp-cluster'}, $CLUSTER,
    'and that label is the cluster name';
isnt $sent->{labels}{'ocp-cluster'}, 'hetzner-default',
    'not the provider CR name — that server would survive `ocp destroy` and keep billing';
is $sent->{labels}{'ocp-node'}, 'pool-a-1', 'the node label is still the node name';

# Consequence 2 falls out of the same value: the idempotency probe has to look
# under the label the machine actually wears, or it never finds it and builds a
# second one next to the first.
my ($probe) = @{ $worker_servers->{queries} };
is $probe, "ocp-cluster=$CLUSTER,ocp-node=pool-a-1",
    'server_exists probes the label the server is created with';

#
# The refusal, on the other side of the same decision.
#
# A provider CR written before spec.clusterName existed has none, and there is
# no second source to fall back to: metadata.name is "<type>-default", the
# namespace is ocp-system in every cluster there is, and an empty cluster_name
# makes create_server skip its idempotency check AND label the machine
# ocp-cluster= — matched by no selector at all. Refusing is the only answer
# that does not leave a running, billed, unfindable server behind.
#

subtest 'a provider CR from before the field refuses rather than mislabelling' => sub {
    my $k8s = StrictK8s::build();
    $k8s->secret({
        apiVersion => 'v1', kind => 'Secret',
        metadata   => { name => 'hetzner-api-token-hetzner', namespace => 'ocp-system' },
        data       => { token => encode_base64('hz-tok', '') },
    });

    my %old_cr = %$provider_cr;
    delete $old_cr{spec}{clusterName};   # what an upgraded cluster still has stored

    my $prov = eval { OCP::Provider->from_cr(\%old_cr, k8s => $k8s) };
    ok !$prov, 'no adapter is built';
    like $@, qr/spec\.clusterName/, 'the message names the field';
    like $@, qr/billed/,            'and says what it would have cost';
};

#
# The machines already out there.
#
# The fix stops new ones appearing; it cannot relabel a server that is already
# running under ocp-cluster=hetzner-default. Those are unreachable for every
# selector `ocp destroy` uses, so the teardown would delete the control plane,
# print "Cluster destroyed." and leave the workers billing. They have to be
# NAMED — and only named: the label is generic by construction, so a match can
# belong to a different OCP cluster in the same Hetzner project.
#

package MislabelledProvider {
    sub new { my ($c, %a) = @_; bless { deleted => [], asked => [], %a }, $c }
    sub list_servers_by_cluster {
        my ($self, $label) = @_;
        push @{ $self->{asked} }, $label;
        return $self->{by_label}{$label} // [];
    }
    sub delete_server {
        my ($self, $id) = @_;
        push @{ $self->{deleted} }, $id;
    }
}

package main;

use OCP::Cmd::Destroy;

sub capture_stdout_of {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die "capture: $!";
    my $old = select $fh;
    eval { $code->() };
    my $err = $@;
    select $old;
    close $fh;
    die $err if $err;
    return $out;
}

subtest 'destroy names the servers left behind under the old label' => sub {
    my $destroy = OCP::Cmd::Destroy->new(command_chain => []);

    my $prov = MislabelledProvider->new(by_label => {
        'hetzner-default' => [
            FakeHzServer->new(id => 4711, name => 'pool-a-1', ipv4 => '203.0.113.7'),
            FakeHzServer->new(id => 4712, name => 'pool-a-2', ipv4 => '203.0.113.8'),
        ],
    });

    my $out = capture_stdout_of(sub {
        $destroy->_report_mislabelled_servers($config, $prov);
    });

    is_deeply $prov->{asked}, ['hetzner-default'],
        'it looks under exactly the provider-CR name `ocp apply` writes';
    like $out, qr/ocp-cluster=hetzner-default/, 'the label is spelled out';
    like $out, qr/pool-a-1.*4711.*203\.0\.113\.7/, 'each server is named with its id and address';
    like $out, qr/pool-a-2/,                       'all of them, not just the first';
    like $out, qr/NOT deleted/,                    'and it says they were not removed';
    like $out, qr/hcloud server list -l ocp-cluster=hetzner-default/,
        'the operator gets the selector that finds them';

    is_deeply $prov->{deleted}, [],
        'nothing is deleted — a generic label can point at another cluster entirely';
};

subtest 'a clean project says nothing' => sub {
    my $destroy = OCP::Cmd::Destroy->new(command_chain => []);
    my $prov    = MislabelledProvider->new(by_label => {});

    my $out = capture_stdout_of(sub {
        $destroy->_report_mislabelled_servers($config, $prov);
    });
    is $out, '', 'no output when the stale label matches nothing';

    # And no Hetzner provider at all (no token) must not make the teardown die.
    my $quiet = capture_stdout_of(sub {
        $destroy->_report_mislabelled_servers($config, undef);
    });
    is $quiet, '', 'without a Hetzner client the check is simply skipped';
};

done_testing;

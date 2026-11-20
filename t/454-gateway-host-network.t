#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use Path::Tiny qw(path);
use File::Temp qw(tempdir);
use IO::K8s;

use lib 'lib';

use OCP;
use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Network;

#
# k454: under gateway: { mode: host_network } the Cilium Gateway gets no
# LoadBalancer address -- Envoy listens on 80/443 of the nodes the selector
# picks. The apply path:
#
#   1. gateway_nodes picks the Nodes whose labels hold every pair of the
#      selector, with their InternalIP, sorted by name
#   2. setup_cilium_gateway applies and waits as before, then says on STDOUT
#      which nodes Envoy listens on; none labelled yet is no error (on a first
#      apply the Gateway comes before the workers); a Node list that fails is
#      said on STDERR and fails nothing. Under load_balancer (and without a
#      config) no Node is listed and nothing more is said
#   3. setup_lb_ipam no longer reads the Gateway for an address in host mode;
#      under load_balancer it still does
#   4. Rex::Rancher::Cilium, the real one, merges the values over its own
#      gatewayAPI.enabled and keeps both
#
# Network-free: fake API objects, OCP::Config on temp files.
#

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $code->() };
        $died = $@;
    }
    return ($rv, $out, $err, $died);
}

my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

sub config_for {
    my ($spec) = @_;
    my $name = 'c' . int(rand(1_000_000));
    my $f = path($tmpdir)->child("$name.yaml");
    $ocp->dump_file($f->stringify, { name => $name, %$spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

my $local = { control_planes => [{ provider => 'local' }] };
my $SEL   = { 'ocp.io/gateway' => 'true' };
my $HOST  = config_for({ %$local, gateway => { mode => 'host_network', node_selector => $SEL } });
my $LB    = config_for($local);

sub node {
    my ($name, $labels, $ip) = @_;
    return IO::K8s->new->struct_to_object('IO::K8s::Api::Core::V1::Node', {
        metadata => { name => $name, ($labels ? (labels => $labels) : ()) },
        ($ip ? (status => { addresses => [
            { type => 'Hostname',   address => $name },
            { type => 'InternalIP', address => $ip },
        ] }) : ()),
    });
}

my @NODES = (
    node('police1', { 'node-role.kubernetes.io/control-plane' => 'true' }, '10.200.0.2'),
    node('w2', { 'ocp.io/gateway' => 'true', 'ocp.io/pool' => 'gw' }, '10.200.0.4'),
    node('w1', { 'ocp.io/gateway' => 'true' }, '10.200.0.3'),
    node('w3', { 'ocp.io/gateway' => 'false' }, '10.200.0.5'),
    node('w4', undef, '10.200.0.6'),
);

# --- 1. which nodes ----------------------------------------------------------

subtest 'gateway_nodes: every pair of the selector, with the InternalIP' => sub {
    is_deeply OCP::Cmd::Apply::Network::gateway_nodes(\@NODES, $SEL),
        [ { name => 'w1', address => '10.200.0.3' }, { name => 'w2', address => '10.200.0.4' } ],
        'the two labelled true, sorted by name; not the one labelled false, nor the unlabelled';
    is_deeply OCP::Cmd::Apply::Network::gateway_nodes(\@NODES, { %$SEL, 'ocp.io/pool' => 'gw' }),
        [ { name => 'w2', address => '10.200.0.4' } ], 'all of the pairs, not one of them';
    is_deeply OCP::Cmd::Apply::Network::gateway_nodes([ node('w9', $SEL) ], $SEL),
        [ { name => 'w9', address => undef } ], 'a node without addresses yet: its name';
    is_deeply OCP::Cmd::Apply::Network::gateway_nodes([], $SEL), [], 'no nodes: none';
};

# --- 2. setup_cilium_gateway --------------------------------------------------

our $GW_PATH = '/apis/gateway.networking.k8s.io/v1/namespaces/kube-system/gateways/cilium-gateway';

{
    package FakeResponse;
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}
{
    package FakeList;
    sub new   { my ($c, @items) = @_; bless { items => [ @items ] }, $c }
    sub items { $_[0]{items} }
}
{
    # The Gateway accepted, generation 1, on every read; list('Node') answers
    # from $self->{nodes}, or dies with $self->{list_error}. Reads recorded.
    package FakeApi;
    sub new { my ($c, %o) = @_; bless { %o, gets => [], lists => 0 }, $c }
    sub _request {
        my ($self, $method, $path) = @_;
        push @{ $self->{gets} }, $path;
        die "unexpected $method $path\n" unless $method eq 'GET';
        if ($path eq $main::GW_PATH) {
            return FakeResponse->new(200, JSON::PP->new->encode({
                metadata => { name => 'cilium-gateway', namespace => 'kube-system', generation => 1 },
                status   => { conditions => [ { type => 'Accepted', status => 'True', observedGeneration => 1 } ] },
            }));
        }
        return FakeResponse->new(200, '{"kind":"List","items":[]}')
            if $path eq '/apis/cilium.io/v2/ciliumloadbalancerippools';
        die "unexpected GET $path\n";
    }
    sub list {
        my ($self, $kind) = @_;
        die "unexpected list $kind\n" unless $kind eq 'Node';
        $self->{lists}++;
        die $self->{list_error} if $self->{list_error};
        return FakeList->new(@{ $self->{nodes} // [] });
    }
}
{
    package FakeOCP;
    sub new     { bless {}, shift }
    sub verbose { 0 }
}

sub apply_with {
    my ($api) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    $apply->{_k8s_api} = $api;
    return $apply;
}

sub run_gateway {
    my ($config, %api) = @_;
    my $api = FakeApi->new(%api);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_server_side_apply = sub { 1 };
    local *OCP::Cmd::Apply::wait_seconds       = sub { };
    my ($rv, $out, $err, $died) = capture { apply_with($api)->_setup_cilium_gateway($config) };
    return { outcome => $rv, out => $out, err => $err, died => $died, lists => $api->{lists} };
}

my $UP_TO_DATE = "      Cilium Gateway already deployed (up to date)\n";

subtest 'host_network: the nodes Envoy listens on' => sub {
    my $r = run_gateway($HOST, nodes => \@NODES);
    is $r->{died}, '', 'ran' or return diag $r->{died};
    is $r->{outcome}, 'unchanged', 'the outcome as before';
    is $r->{out}, $UP_TO_DATE
        . "      Gateway host network: Envoy listens on 80/443 of w1 (10.200.0.3), w2 (10.200.0.4)\n",
        'named, with the address an edge proxy forwards to';
    is $r->{err}, '', 'nothing on STDERR';
    is $r->{lists}, 1, 'the Nodes listed once';
};

subtest 'host_network, none labelled yet: said, and no error' => sub {
    my $r = run_gateway($HOST, nodes => [ grep { $_->metadata->name =~ /^(police1|w4)$/ } @NODES ]);
    is $r->{died}, '', 'ran' or return diag $r->{died};
    is $r->{outcome}, 'unchanged', 'the outcome as before';
    is $r->{out}, $UP_TO_DATE
        . "      Gateway host network: no node carries ocp.io/gateway=true yet -- Envoy listens on "
        . "80/443 of each node that does, once it joins\n", 'says which label it waits for';
    is $r->{err}, '', 'nothing on STDERR: a first apply has no workers yet';
};

subtest 'host_network, the Node list fails: said on STDERR, the step stands' => sub {
    my $r = run_gateway($HOST, list_error => "Kubernetes API error: 503 Service Unavailable\n");
    is $r->{died}, '', 'the Gateway step does not fail over the report' or return diag $r->{died};
    is $r->{outcome}, 'unchanged', 'its outcome';
    is $r->{out}, $UP_TO_DATE, 'nothing more on STDOUT';
    is $r->{err}, '  [!!] Gateway host network: the nodes were not read, so which of them carry '
        . "ocp.io/gateway=true is unknown: could not read Nodes (for the Gateway host network): "
        . "Kubernetes API error: 503 Service Unavailable\n", 'the cause on STDERR';
};

subtest 'load_balancer, or no config: no Node listed, nothing more said' => sub {
    for my $case ([ 'load_balancer', $LB ], [ 'no config', undef ]) {
        my $r = run_gateway($case->[1], nodes => \@NODES);
        is $r->{died}, '', "$case->[0]: ran" or next;
        is $r->{out}, $UP_TO_DATE, "$case->[0]: as before";
        is $r->{lists}, 0, "$case->[0]: no Node listed";
    }
};

# --- 3. setup_lb_ipam ---------------------------------------------------------

sub run_lb_ipam {
    my ($config) = @_;
    my $api = FakeApi->new;
    my @applied;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_server_side_apply_all = sub { shift; shift; push @applied, @_; 1 };
    local *OCP::Cmd::Apply::wait_seconds           = sub { };
    my ($rv, $out, $err, $died) = capture {
        OCP::Cmd::Apply::Network::setup_lb_ipam(apply_with($api), '10.0.0.1', $config);
    };
    return { out => $out, died => $died, applied => \@applied,
             gateway_reads => scalar grep { $_ eq $GW_PATH } @{ $api->{gets} } };
}

subtest 'setup_lb_ipam: no Gateway address looked for in host mode' => sub {
    my $r = run_lb_ipam($HOST);
    is $r->{died}, '', 'ran' or return diag $r->{died};
    is scalar @{ $r->{applied} }, 2, 'the pool and the L2 policy, as before';
    is $r->{gateway_reads}, 0, 'the Gateway is not read for an address';

    $r = run_lb_ipam($LB);
    is $r->{died}, '', 'load_balancer: ran' or return diag $r->{died};
    is $r->{gateway_reads}, 1, 'load_balancer: read for its address, as before';
};

# --- 4. the library -----------------------------------------------------------

subtest 'Rex::Rancher::Cilium merges the values over its own gatewayAPI.enabled' => sub {
    require Rex::Rancher::Cilium;
    require Rex::Rancher::Distribution;
    my $helm = Rex::Rancher::Cilium->can('_helm_values')
        or plan skip_all => 'Rex::Rancher::Cilium has no _helm_values any more';
    my $values = $helm->(Rex::Rancher::Distribution->new_for('rke2'), 1, $HOST->cilium_helm_values,
                         undef, '10.42.0.0/16', 'cluster-pool');
    ok $values->{gatewayAPI}{enabled}, 'gatewayAPI.enabled, the library\'s';
    ok $values->{gatewayAPI}{hostNetwork}{enabled}, 'gatewayAPI.hostNetwork.enabled, OCP\'s';
    is_deeply $values->{gatewayAPI}{hostNetwork}{nodes}, { matchLabels => $SEL }, 'its nodes';
    ok $values->{envoy}{securityContext}{capabilities}{keepCapNetBindService}, 'keepCapNetBindService';
    is_deeply $values->{envoy}{securityContext}{capabilities}{envoy},
        [qw( NET_ADMIN SYS_ADMIN NET_BIND_SERVICE )], 'the capability list';
    like Rex::Rancher::Cilium::_helm_values_yaml($values),
        qr/hostNetwork:\n\s+enabled: true\n/, 'and the YAML Helm reads says true';
};

done_testing;

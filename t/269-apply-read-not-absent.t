#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::PP ();
use Kubernetes::REST::APIError;
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::K8s;
use OCP::Cmd::Apply::Network;
use OCP::Cmd::Apply::Registry;
use OCP::Cmd::Apply::Workloads;

#
# k269: the apply path's two read helpers, OCP::Cmd::Apply::K8s
# resource_exists and crd_get, read every failed read as "not there". Only a
# 404 says that. An RBAC denial, an apiserver 5xx, a TLS error says nothing
# about the object: those die with their cause, and each caller decides
# whether its step fails on it or a poll reads again and says it at the end.
# The AMD GPU stack's callers are pinned in t/251.
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

# What Kubernetes::REST dies with for an HTTP error status (as in t/25).
sub api_error {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(
        code    => $code,
        context => 'get',
        body    => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}),
    );
}
my @REFUSALS = ([403, 'Forbidden'], [500, 'InternalError']);

{
    package FakeResponse;
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}
{
    # get() answers from { "Kind/namespace/name" => object | error };
    # _request() from { path => [ response, ... ] }, the last one repeating.
    package ReadApi;
    sub new { my ($c, %a) = @_; bless { objects => {}, responses => {}, reads => [], %a }, $c }
    sub get {
        my ($self, $kind, $name, %o) = @_;
        my $key = join '/', $kind, $o{namespace} // '-', $name;
        my $answer = $self->{objects}{$key} // die "404 $key not found\n";
        die $answer if ref $answer && ref $answer ne 'HASH';
        return $answer;
    }
    sub _request {
        my ($self, $method, $path) = @_;
        push @{ $self->{reads} }, $path;
        my $queue = $self->{responses}{$path} or return FakeResponse->new(404, '{}');
        my $answer = @$queue > 1 ? shift @$queue : $queue->[0];
        die $answer unless ref $answer;
        return FakeResponse->new(@$answer);
    }
}

subtest 'resource_exists: only a 404 is absent' => sub {
    my $api = ReadApi->new(objects => {
        'Deployment/ocp-system/ocp-cache' => { kind => 'Deployment' },
        'Deployment/ocp-system/apierror'  => api_error(404, 'NotFound'),
    });
    ok OCP::Cmd::Apply::K8s::resource_exists({}, $api, 'Deployment', 'ocp-cache', namespace => 'ocp-system'),
        'an object: there';
    ok !OCP::Cmd::Apply::K8s::resource_exists({}, $api, 'Deployment', 'gone', namespace => 'ocp-system'),
        'a 404 (the plain death): absent';
    ok !OCP::Cmd::Apply::K8s::resource_exists({}, $api, 'Deployment', 'apierror', namespace => 'ocp-system'),
        'a 404 (the APIError): absent';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $api->{objects}{'Deployment/ocp-system/ocp-cache'} = api_error($code, $reason);
        $api->{objects}{'Namespace/-/ocp-system'}          = api_error($code, $reason);
        my $rv = eval { OCP::Cmd::Apply::K8s::resource_exists({}, $api, 'Deployment', 'ocp-cache',
            namespace => 'ocp-system') };
        like $@, qr{\Acould not read Deployment ocp-system/ocp-cache: Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "$code: dies, naming the object and the cause";
        ok !defined $rv, "$code: no answer";
        eval { OCP::Cmd::Apply::K8s::resource_exists({}, $api, 'Namespace', 'ocp-system') };
        like $@, qr{\Acould not read Namespace ocp-system: Kubernetes API error \(get\): $code }, "$code: cluster-scoped";
    }

    no warnings 'redefine';
    local *ReadApi::get = sub { die "Can't connect to 10.0.0.1:6443 (Connection refused)\n" };
    eval { OCP::Cmd::Apply::K8s::resource_exists({}, $api, 'Deployment', 'ocp-cache', namespace => 'ocp-system') };
    like $@, qr{\Acould not read Deployment ocp-system/ocp-cache: Can't connect}, 'a transport error: dies too';

    my $apply = OCP::Cmd::Apply->new(command_chain => [ bless {}, 'FakeOCP' ]);
    eval { $apply->_resource_exists($api, 'Deployment', 'ocp-cache', namespace => 'ocp-system') };
    like $@, qr{\Acould not read Deployment}, 'the Apply forwarder passes the death on';
};

subtest 'crd_get: undef only for a 404' => sub {
    my $path = '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';
    my $api  = ReadApi->new;

    is OCP::Cmd::Apply::K8s::crd_get({}, $api, $path), undef, '404: undef';

    $api->{responses}{$path} = [ [ 200, '{"kind":"ClusterPolicy","status":{"state":"ready"}}' ] ];
    is_deeply OCP::Cmd::Apply::K8s::crd_get({}, $api, $path),
        { kind => 'ClusterPolicy', status => { state => 'ready' } }, '200: the object';

    for my $code (403, 500) {
        $api->{responses}{$path} = [ [ $code, "{\"reason\":\"refused\",\n \"code\":$code}" ] ];
        my $rv = eval { OCP::Cmd::Apply::K8s::crd_get({}, $api, $path) };
        is $@, qq{GET $path failed: HTTP $code {"reason":"refused", "code":$code}\n}, "$code: dies with status and body";
        ok !defined $rv, "$code: no answer";
    }

    $api->{responses}{$path} = [ [ 200, '<html>proxy</html>' ] ];
    eval { OCP::Cmd::Apply::K8s::crd_get({}, $api, $path) };
    like $@, qr{\AGET \Q$path\E: the answer is no JSON: }, '200 that is no JSON: dies, not absent';

    $api->{responses}{$path} = [ "SSL connect attempt failed\n" ];
    eval { OCP::Cmd::Apply::K8s::crd_get({}, $api, $path) };
    is $@, "GET $path failed: SSL connect attempt failed\n", 'a transport error: dies with it';

    my $apply = OCP::Cmd::Apply->new(command_chain => [ bless {}, 'FakeOCP' ]);
    $api->{responses}{$path} = [ [ 403, 'forbidden' ] ];
    eval { $apply->_crd_get($api, $path) };
    like $@, qr{\AGET \Q$path\E failed: HTTP 403 forbidden}, 'the Apply forwarder passes the death on';
};

#
# The callers. A step that asks once dies, and its step reports it; a poll
# reads again and names the last failed read when it gives up.
#

{
    package FakeOCP;
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub dump      { my ($self, @r) = @_; return join '', map { YAML::XS::Dump($_) } @r }
    sub load_file { my ($self, $f) = @_; -f "$f" ? YAML::XS::LoadFile("$f") : undef }
    sub dump_file { my ($self, $f, $d) = @_; YAML::XS::DumpFile("$f", $d) }
}
{
    package FakeConfig;
    sub new {
        my ($class, %arg) = @_;
        my $dir = Path::Tiny::path(main::tempdir(CLEANUP => 1));
        $dir->child('.ocp')->mkpath;
        bless { dir => $dir, %arg }, $class;
    }
    sub distribution          { 'k3s' }
    sub gpu_driver            { 'host' }
    sub gpu_toolkit           { 1 }
    sub gpu_enabled           { 1 }
    sub has_external_cache    { 0 }
    sub has_external_upstream { 0 }
    sub deployed_file         { $_[0]{dir}->child('.ocp', 'deployed.yaml')->stringify }
}

sub new_apply {
    my ($api) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    $apply->{_k8s_api} = $api;
    return $apply;
}

subtest 'Registry: an unreadable registry is neither running nor gone' => sub {
    my $api = ReadApi->new(objects => { 'Namespace/-/ocp-system' => { kind => 'Namespace' } });
    my $apply = new_apply($api);
    is OCP::Cmd::Apply::Registry::running($apply, FakeConfig->new), 0, '404 on ocp-cache: not running';
    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $api->{objects}{'Deployment/ocp-system/ocp-cache'} = api_error($code, $reason);
        my $rv = eval { OCP::Cmd::Apply::Registry::running($apply, FakeConfig->new) };
        like $@, qr{\Acould not read Deployment ocp-system/ocp-cache: Kubernetes API error \(get\): $code },
            "$code: dies with the cause, so setup reports it instead of redeploying";
        ok !defined $rv, "$code: no verdict";
    }
};

{
    # One node with NFD's NVIDIA label; the operator not deployed yet (404).
    package GpuNodeList;
    sub new   { bless {}, shift }
    sub items { [ bless {}, 'GpuNode' ] }
    package GpuNode;
    sub metadata { bless {}, 'GpuNodeMeta' }
    package GpuNodeMeta;
    sub name { 'crag' }
    package GpuApi;
    our @ISA = ('ReadApi');
    sub list { GpuNodeList->new }
}

my $CP_PATH = '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';

# setup_gpu_operator up to its ClusterPolicy state wait, whose reads are
# answered by @answers (the last repeating).
sub gpu_setup {
    my (@answers) = @_;
    my $api = GpuApi->new(responses => { $CP_PATH => [ @answers ] });
    my $apply = new_apply($api);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::K8s::server_side_apply = sub { 1 };
    local *OCP::Cmd::Apply::_poll_deployment_ready = sub { 1 };
    local *OCP::Cmd::Apply::wait_seconds = sub { };
    my ($rv, $out, $err, $died) = capture { OCP::Cmd::Apply::Workloads::setup_gpu_operator($apply, FakeConfig->new) };
    return { outcome => $rv, out => $out, err => $err, died => $died,
             reads => scalar grep { $_ eq $CP_PATH } @{ $api->{reads} } };
}

subtest 'GPU Operator: the ClusterPolicy state wait reads again, then says why it could not' => sub {
    for my $code (403, 500) {
        my $res = gpu_setup([ $code, 'refused' ]);
        is $res->{died}, '', "$code: the deploy is not failed by a state it could not read";
        is $res->{outcome}, 'deployed', "$code: deployed";
        is $res->{reads}, 12, "$code: read for the whole wait";
        is $res->{err}, "  [WARN] ClusterPolicy state unknown: could not read ClusterPolicy gpu-cluster-policy:"
            . " GET $CP_PATH failed: HTTP $code refused\n", "$code: the cause, on STDERR";
        unlike $res->{out}, qr/may still be reconciling/, "$code: not called a state it never saw";
    }

    my $res = gpu_setup([ 404, '{}' ]);
    is $res->{outcome}, 'deployed', '404: deployed';
    like $res->{out}, qr/ClusterPolicy state: unknown \(may still be reconciling\)/, '404: still reconciling';
    is $res->{err}, '', '404: nothing on STDERR';

    $res = gpu_setup([ 500, 'blip' ], [ 200, '{"status":{"state":"ready"}}' ]);
    like $res->{out}, qr/ClusterPolicy state: ready/, 'a 500 once, then ready: ready';
    is $res->{err}, '', 'and nothing on STDERR';
};

my $GW_PATH = '/apis/gateway.networking.k8s.io/v1/namespaces/kube-system/gateways/cilium-gateway';

sub gateway_setup {
    my (@answers) = @_;
    my $api = ReadApi->new(responses => { $GW_PATH => [ @answers ] });
    my $apply = new_apply($api);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_server_side_apply = sub { 1 };
    local *OCP::Cmd::Apply::wait_seconds = sub { };
    my ($rv, $out, $err, $died) = capture { OCP::Cmd::Apply::Network::setup_cilium_gateway($apply, FakeConfig->new); 1 };
    return { ok => $rv, out => $out, died => $died,
             reads => scalar grep { $_ eq $GW_PATH } @{ $api->{reads} } };
}

subtest 'Cilium Gateway: the Accepted wait reads again, then dies with the last read failure' => sub {
    for my $code (403, 500) {
        my $res = gateway_setup([ $code, 'refused' ]);
        is $res->{reads}, 30, "$code: read for the whole wait";
        is $res->{died}, "Gateway 'cilium-gateway' did not become Accepted within 60s;"
            . " the last read failed: GET $GW_PATH failed: HTTP $code refused\n", "$code: the death names the cause";
    }

    my $res = gateway_setup([ 404, '{}' ]);
    is $res->{died}, "Gateway 'cilium-gateway' did not become Accepted within 60s\n", '404: no read failure to name';

    $res = gateway_setup([ 500, 'blip' ],
        [ 200, '{"status":{"conditions":[{"type":"Accepted","status":"True"}]}}' ]);
    ok $res->{ok}, 'a 500 once, then Accepted: done';
    like $res->{out}, qr/Gateway is accepted/, 'said';
};

done_testing;

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
    # crag has its GPU allocatable, so the wait after the rollout (k273,
    # pinned in t/273) is over at once.
    sub get {
        my ($self, $kind, @rest) = @_;
        return { metadata => { name => 'crag' }, status => { allocatable => { 'nvidia.com/gpu' => '1' } } }
            if $kind eq 'Node' && "@rest" eq 'name crag';
        return $self->SUPER::get($kind, @rest);
    }
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
    my $applied = 0;
    local *OCP::Cmd::Apply::_server_side_apply = sub { $applied++; 1 };
    local *OCP::Cmd::Apply::wait_seconds = sub { };
    my ($rv, $out, $err, $died) = capture { OCP::Cmd::Apply::Network::setup_cilium_gateway($apply, FakeConfig->new); 1 };
    return { ok => $rv, out => $out, died => $died, applied => $applied,
             reads => scalar grep { $_ eq $GW_PATH } @{ $api->{reads} } };
}

# Since k300 the Gateway is read before the apply and once after it, to tell
# created from updated from up to date; the Accepted wait comes after that.
my $GW_THERE = [ 200, '{"metadata":{"generation":1}}' ];

subtest 'Cilium Gateway: a read before the apply that fails dies with its cause' => sub {
    for my $code (403, 500) {
        my $res = gateway_setup([ $code, 'refused' ]);
        is $res->{died}, "GET $GW_PATH failed: HTTP $code refused\n", "$code: the death names the cause";
        is $res->{reads}, 1, "$code: not polled";
        is $res->{applied}, 0, "$code: and not applied as if there were none";
        unlike $res->{out}, qr/Creating Cilium Gateway/, "$code: not called missing";
    }
};

subtest 'Cilium Gateway: the Accepted wait reads again, then dies with the last read failure' => sub {
    for my $code (403, 500) {
        my $res = gateway_setup($GW_THERE, $GW_THERE, [ $code, 'refused' ]);
        is $res->{reads}, 2 + 30, "$code: read for the whole wait";
        is $res->{died}, "Gateway 'cilium-gateway' did not become Accepted within 60s;"
            . " the last read failed: GET $GW_PATH failed: HTTP $code refused\n", "$code: the death names the cause";
    }

    my $res = gateway_setup([ 404, '{}' ]);
    is $res->{died}, "Gateway 'cilium-gateway' did not become Accepted within 60s\n", '404: no read failure to name';

    $res = gateway_setup($GW_THERE, $GW_THERE, [ 500, 'blip' ],
        [ 200, '{"status":{"conditions":[{"type":"Accepted","status":"True"}]}}' ]);
    ok $res->{ok}, 'a 500 once, then Accepted: done';
    like $res->{out}, qr/Gateway is accepted/, 'said';
};

#
# k277: the reads k269 did not reach, the same rule. A read asked once dies
# with its cause (its step says it on STDERR); a poll reads again and names
# its last failed read when it gives up. Only a 404 is absent.
#

subtest 'k277 read_or_absent: the object, undef for a 404, a death for the rest' => sub {
    my $read = \&OCP::Cmd::Apply::K8s::read_or_absent;
    is_deeply $read->('ConfigMap kube-system/coredns', sub { { kind => 'ConfigMap' } }),
        { kind => 'ConfigMap' }, 'read: the object';
    is $read->('ConfigMap kube-system/coredns', sub { die api_error(404, 'NotFound') }), undef,
        '404 (the APIError): undef';
    is $read->('ConfigMap kube-system/coredns', sub { die "404 ConfigMap/coredns not found\n" }), undef,
        '404 (the plain death): undef';
    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        my $rv = eval { $read->('ConfigMap kube-system/coredns', sub { die api_error($code, $reason) }) };
        like $@, qr{\Acould not read ConfigMap kube-system/coredns: Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "$code: dies, naming what and why";
        ok !defined $rv, "$code: no answer";
    }
};

subtest 'k277 GPU Operator: a Node list that fails is not "no GPU nodes"' => sub {
    no warnings 'redefine';
    local *GpuApi::list = sub { die api_error(404, 'NotFound') };
    my $none = gpu_setup([ 200, '{"status":{"state":"ready"}}' ]);
    is $none->{died}, '', '404: no death';
    is $none->{outcome}, 'skipped', '404: no GPU nodes, skipped';
    like $none->{out}, qr/No GPU nodes detected/, '404: said so';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        local *GpuApi::list = sub { die api_error($code, $reason) };
        my $res = gpu_setup([ 200, '{"status":{"state":"ready"}}' ]);
        like $res->{died},
            qr{\Acould not read Nodes labelled feature\.node\.kubernetes\.io/pci-0300_10de\.present=true: Kubernetes API error \(get\): $code .*"reason":"$reason"},
            "$code: dies with the cause, so the step is [!!] instead of skipped";
        unlike $res->{out}, qr/No GPU nodes detected/, "$code: not called no GPU nodes";
        ok !defined $res->{outcome}, "$code: no verdict";
    }
};

{
    package PollStatus;
    sub new { my ($c, $n) = @_; bless { n => $n }, $c }
    sub availableReplicas { $_[0]{n} }
    package PollDeployment;
    sub new { my ($c, $n) = @_; bless { s => PollStatus->new($n) }, $c }
    sub status { $_[0]{s} }
    # get() answers from a queue, the last answer repeating: a number is the
    # Deployment's availableReplicas, anything else is what the read dies with.
    package PollApi;
    sub new { my ($c, @a) = @_; bless { answers => [ @a ], gets => 0 }, $c }
    sub get {
        my ($self, $kind, $name, %o) = @_;
        $self->{gets}++;
        my $q = $self->{answers};
        my $answer = @$q > 1 ? shift @$q : $q->[0];
        die $answer unless !ref $answer && $answer =~ /\A[0-9]+\z/;
        return PollDeployment->new($answer);
    }
}

sub poll {
    my (@answers) = @_;
    my $api = PollApi->new(@answers);
    my $waited = 0;
    my $apply = new_apply($api);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::wait_seconds = sub { $waited += $_[1] };
    my ($rv, $out, $err, $died) = capture {
        OCP::Cmd::Apply::K8s::poll_deployment_ready($apply, $api, 'ocp-cache', 'ocp-system', 20)
    };
    return { ready => $rv, died => $died, gets => $api->{gets}, waited => $waited };
}

subtest 'k277 poll_deployment_ready: names the last failed read when it gives up' => sub {
    my $r = poll(1);
    is $r->{ready}, 1, 'an available replica: ready';
    is $r->{died}, '', 'and no death';

    $r = poll(0);
    is $r->{ready}, 0, 'never available: not ready';
    is $r->{died}, '', 'and no death: the caller says "not ready" in its words';

    $r = poll(api_error(404, 'NotFound'));
    is $r->{ready}, 0, '404 throughout: not ready, the Deployment is not there';
    is $r->{died}, '', '404 throughout: no death';
    is $r->{gets}, 4, '404 throughout: read for the whole wait';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = poll(api_error($code, $reason));
        like $r->{died},
            qr{\ADeployment ocp-system/ocp-cache not ready within 20s; the last read failed: Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "$code throughout: dies with the cause, not \"not ready\"";
        is $r->{gets}, 4, "$code throughout: read for the whole wait";

        $r = poll(api_error($code, $reason), 1);
        is $r->{ready}, 1, "$code once, then available: ready";
        is $r->{died}, '', "$code once, then available: no death";

        $r = poll(api_error($code, $reason), 0);
        is $r->{ready}, 0, "$code once, then read and not available: not ready";
        is $r->{died}, '', "$code once, then read: the last read did not fail, no death";
    }
};

{
    package DnsCm;
    sub new  { my ($c, $d) = @_; bless { data => $d }, $c }
    sub data { $_[0]{data} }
    # ReadApi dies with any object that is no plain hash; a ConfigMap here
    # is one (configure_registry_dns calls ->data on it).
    package DnsApi;
    our @ISA = ('ReadApi');
    sub get {
        my ($self, $kind, $name, %o) = @_;
        my $answer = $self->{objects}{ join '/', $kind, $o{namespace} // '-', $name };
        return $answer if ref $answer eq 'DnsCm';
        return $self->SUPER::get($kind, $name, %o);
    }
}

sub registry_dns {
    my (%objects) = @_;
    my $api = DnsApi->new(objects => { %objects });
    my $apply = new_apply($api);
    my @applied;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_server_side_apply = sub { push @applied, $_[2]; 1 };
    my ($rv, $out, $err, $died) = capture {
        OCP::Cmd::Apply::Network::configure_registry_dns($apply, '10.230.30.155')
    };
    return { patched => $rv, out => $out, died => $died, applied => \@applied };
}

subtest 'k277 registry.local DNS: a CoreDNS ConfigMap that cannot be read is not "up to date"' => sub {
    my ($first, $second) = @OCP::Cmd::Apply::Network::COREDNS_CONFIGMAPS;
    my $cm = DnsCm->new({ Corefile => ".:53 {\n    forward . /etc/resolv.conf\n}\n" });

    my $r = registry_dns("ConfigMap/kube-system/$second" => $cm);
    is $r->{died}, '', "404 on $first: no death";
    is $r->{patched}, 1, "404 on $first: the next name is read and patched";
    is $r->{applied}[0]{metadata}{name}, $second, "404 on $first: $second written";

    $r = registry_dns();
    is $r->{died}, '', '404 on both: no death';
    is $r->{patched}, 0, '404 on both: nothing to patch';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = registry_dns("ConfigMap/kube-system/$first"  => api_error($code, $reason),
                          "ConfigMap/kube-system/$second" => $cm);
        like $r->{died},
            qr{\Acould not read ConfigMap kube-system/$first: Kubernetes API error \(get\): $code .*"reason":"$reason"},
            "$code on $first: dies with the cause";
        ok !defined $r->{patched}, "$code on $first: no verdict, so not \"up to date\"";
        is scalar @{ $r->{applied} }, 0, "$code on $first: and $second is not written over it";
    }
};

my $POOL_PATH = '/apis/cilium.io/v2/ciliumloadbalancerippools';

# setup_lb_ipam on a single-node cluster up to the pool apply; the pool API's
# reads are answered by @answers (the last repeating).
sub lb_wait {
    my (@answers) = @_;
    my $api = ReadApi->new(responses => { $POOL_PATH => [ @answers ] });
    my $apply = new_apply($api);
    my ($applied, $waited) = (0, 0);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_server_side_apply_all = sub { $applied++; 1 };
    local *OCP::Cmd::Apply::wait_seconds          = sub { $waited += $_[1] };
    local *OCP::Cmd::Apply::Network::lb_ipam_resources = sub {
        [ { kind => 'CiliumLoadBalancerIPPool', spec => { blocks => [ { cidr => '10.230.30.155/32' } ] } } ]
    };
    my ($rv, $out, $err, $died) = capture {
        OCP::Cmd::Apply::Network::setup_lb_ipam($apply, '10.230.30.155', FakeConfig->new); 1
    };
    return { ok => $rv, died => $died, applied => $applied, waited => $waited,
             reads => scalar grep { $_ eq $POOL_PATH } @{ $api->{reads} } };
}

subtest 'k277 LB-IPAM: the pool API wait names its last failed read' => sub {
    my $r = lb_wait([ 200, '{"kind":"CiliumLoadBalancerIPPoolList","items":[]}' ]);
    is $r->{died}, '', 'served: no death';
    is $r->{applied}, 1, 'served: the pool applied';

    $r = lb_wait([ 404, '{}' ]);
    is $r->{died}, "CiliumLoadBalancerIPPool API (cilium.io/v2) not served after 300s\n",
        '404 throughout: not served, as before';
    is $r->{reads}, 30, '404 throughout: read for the whole wait';
    is $r->{applied}, 0, '404 throughout: nothing applied';

    for my $code (403, 500) {
        $r = lb_wait([ $code, 'refused' ]);
        is $r->{died}, "CiliumLoadBalancerIPPool API (cilium.io/v2) not served after 300s;"
            . " the last read failed: GET $POOL_PATH failed: HTTP $code refused\n",
            "$code throughout: the cause, not only \"not served\"";
        is $r->{reads}, 30, "$code throughout: read for the whole wait";

        $r = lb_wait([ $code, 'refused' ], [ 404, '{}' ]);
        is $r->{died}, "CiliumLoadBalancerIPPool API (cilium.io/v2) not served after 300s\n",
            "$code once, then 404: the last read did not fail";

        $r = lb_wait([ $code, 'refused' ], [ 200, '{"items":[]}' ]);
        is $r->{died}, '', "$code once, then served: no death";
        is $r->{applied}, 1, "$code once, then served: the pool applied";
    }
};

subtest 'k277 GPU Operator: a running operator without its ClusterPolicy is not up to date' => sub {
    my $config = FakeConfig->new;
    my $api    = GpuApi->new(responses => { $CP_PATH => [ [ 404, '{}' ] ] });
    my $apply  = new_apply($api);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::K8s::server_side_apply = sub { 1 };
    local *OCP::Cmd::Apply::_poll_deployment_ready = sub { 1 };
    local *OCP::Cmd::Apply::wait_seconds           = sub { };
    # The CRDs are compared elsewhere (t/228-gpu-crd-drift.t): as shipped here.
    local *OCP::Drift::gpu_crds_differing          = sub { () };
    my $run = sub { [ capture { OCP::Cmd::Apply::Workloads::setup_gpu_operator($apply, $config) } ] };

    my $r = $run->();
    is $r->[0], 'deployed', 'premise: the first run deploys and records its hash' or diag $r->[3];

    $api->{objects}{'Namespace/-/gpu-operator'}            = { kind => 'Namespace' };
    $api->{objects}{'Deployment/gpu-operator/gpu-operator'} = { kind => 'Deployment' };
    my ($cp) = grep { ref $_ eq 'HASH' && ($_->{kind} // '') eq 'ClusterPolicy' }
        YAML::XS::Load(OCP::Cmd::Apply::Workloads::generate_gpu_operator_manifest($apply, $config));
    $api->{responses}{$CP_PATH} = [ [ 200, JSON::PP->new->encode($cp) ] ];
    $r = $run->();
    is $r->[0], 'unchanged', 'control: running, the ClusterPolicy as applied: up to date' or diag $r->[1], $r->[3];

    $api->{responses}{$CP_PATH} = [ [ 404, '{}' ] ];
    $r = $run->();
    is $r->[3], '', '404: no death';
    is $r->[0], 'updated', '404: re-applied, not up to date';
    like $r->[1], qr/^ {6}ClusterPolicy is not on the cluster \(or has no spec\), re-applying$/m, '404: said';
    unlike $r->[1], qr/already deployed \(up to date\)/, '404: not called up to date';

    $api->{responses}{$CP_PATH} = [ [ 403, 'refused' ] ];
    $r = $run->();
    is $r->[3], "GET $CP_PATH failed: HTTP 403 refused\n", '403: dies with the cause, as since k269';
};

done_testing;

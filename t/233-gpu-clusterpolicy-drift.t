#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Apply::Workloads;
use OCP::Cmd::Apply::Drift;

#
# Lab 2026-10-16 round 6, note 24: the runc pin taken out of the ClusterPolicy
# with kubectl patch was no drift -- dry-run said nothing, apply called the
# operator up to date. Note 27: dry-run did not announce a gpu.toolkit
# switch. Only what OCP sets is compared; the apiserver's defaults are not
# drift.
#

my $want = {
    apiVersion => 'nvidia.com/v1', kind => 'ClusterPolicy',
    metadata => { name => 'gpu-cluster-policy' },
    spec => {
        cdi     => { enabled => JSON::PP::true },
        toolkit => { enabled => JSON::PP::true, version => 'v1.19.1',
                     env => [ { name => 'CONTAINERD_SOCKET', value => '/run/k3s/containerd/containerd.sock' },
                              { name => 'NVIDIA_CONTAINER_RUNTIME_RUNTIMES', value => 'runc,crun' } ] },
        daemonsets => {},
    },
};
my $MANIFEST = YAML::XS::Dump({ kind => 'Namespace', metadata => { name => 'gpu-operator' } }, $want);

# What the apiserver hands back: the same, plus CRD defaults and status.
sub live {
    my $cp = JSON::PP::decode_json(JSON::PP::encode_json($want));
    $cp->{spec}{daemonsets}{updateStrategy} = 'RollingUpdate';
    $cp->{spec}{toolkit}{installDir} = '/usr/local/nvidia';
    $cp->{status} = { state => 'ready' };
    $_[0]->($cp) if $_[0];
    return $cp;
}

{
    package FakeApply;
    sub new { my ($c, %o) = @_; bless { %o }, $c }
    sub _crd_get { $_[0]{cp} }
    sub _k8s_api { 'API' }
    sub _resource_exists { $_[0]{running} // 1 }
}
{
    package FakeConfig;
    sub new { my ($c, %o) = @_; bless { toolkit => 1, %o }, $c }
    sub gpu_enabled { 1 }
    sub gpu_toolkit { $_[0]{toolkit} }
}

sub diffs {
    my ($cp) = @_;
    return [ OCP::Cmd::Apply::Workloads::cluster_policy_differences(
        FakeApply->new(cp => $cp), FakeConfig->new, 'API', $MANIFEST) ];
}

is_deeply diffs(live()), [], 'as applied, plus the apiserver\'s defaults: no drift';
is_deeply diffs(live(sub { pop @{ $_[0]{spec}{toolkit}{env} } })), ['spec.toolkit.env'],
    'the runc pin patched out: spec.toolkit.env';
is_deeply diffs(live(sub { $_[0]{spec}{toolkit}{version} = 'v1.18.0' })), ['spec.toolkit.version'],
    'another toolkit version';
is_deeply diffs(live(sub { $_[0]{spec}{cdi}{enabled} = JSON::PP::false })), ['spec.cdi.enabled'],
    'a boolean flipped';
is_deeply diffs(live(sub { delete $_[0]{spec}{toolkit} })), ['spec.toolkit'], 'a section gone';
# k277: asked only while the operator runs, which has nothing to run its
# operands by without one: no ClusterPolicy (a 404) differs as a whole.
is_deeply diffs(undef), ['spec'], 'no ClusterPolicy while the operator runs: the whole spec differs';

{
    open my $fh, '<', 'lib/OCP/Cmd/Apply/Workloads.pm' or die;
    my $src = do { local $/; <$fh> };
    like $src, qr/cluster_policy_differences\(\$self, \$config, \$api, \$manifest\).*?!\@cp_differ/s,
        'apply re-applies on a differing ClusterPolicy instead of calling it up to date';
}

subtest 'dry-run says both' => sub {
    no warnings 'redefine';
    local *OCP::Cmd::Apply::Workloads::generate_gpu_operator_manifest = sub { $MANIFEST };
    my $out = '';
    my @r;
    {
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        @r = OCP::Cmd::Apply::Drift::gpu_dry_run(
            FakeApply->new(cp => live(sub { pop @{ $_[0]{spec}{toolkit}{env} } })),
            FakeConfig->new(toolkit => 0));
    }
    is_deeply [ map { "$_->{kind} $_->{path}" } @r ], ['spec spec.toolkit.env'], 'one action';
    like $out, qr/\[drift\] GPU Operator ClusterPolicy differs from the spec at spec\.toolkit\.env/, 'named';
    like $out, qr/\[WARN\] gpu\.toolkit changed \(true -> false\)/, 'the toolkit switch is announced';

    $out = '';
    {
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        @r = OCP::Cmd::Apply::Drift::gpu_dry_run(FakeApply->new(cp => live(), running => 0), FakeConfig->new);
    }
    is_deeply \@r, [], 'no operator running: nothing';
    is $out, '', 'and silent';
};

subtest 'quiet: the same finding, said nowhere (k234)' => sub {
    no warnings 'redefine';
    local *OCP::Cmd::Apply::Workloads::generate_gpu_operator_manifest = sub { $MANIFEST };
    my $out = '';
    my @r;
    {
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        @r = OCP::Cmd::Apply::Drift::gpu_dry_run(
            FakeApply->new(cp => live(sub { pop @{ $_[0]{spec}{toolkit}{env} } })),
            FakeConfig->new(toolkit => 0), quiet => 1);
    }
    is_deeply [ map { "$_->{kind} $_->{path}" } @r ], ['spec spec.toolkit.env'],
        'found, so "No drift detected" can be held back';
    is $out, '', 'and nothing printed';
};

#
# k276: gpu_dry_run makes three reads -- the operator's Deployment, the
# ClusterPolicy for its differences, the ClusterPolicy again for the
# gpu.toolkit warning -- and each one took a failed read for a false answer:
# no operator, no differences, no ClusterPolicy. Since k269 the helpers die on
# anything but a 404. Here, through those very helpers, a 404 stays the answer
# it is and a 403 is "could not be checked", with its cause on STDERR once.
#

use Kubernetes::REST::APIError;
use OCP::Cmd::Apply::K8s;

my $CP_PATH = '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';

{
    # The apply object with the real read helpers of OCP::Cmd::Apply::K8s.
    package ReadApply;
    sub new { my ($c, %o) = @_; bless { %o }, $c }
    sub _k8s_api { $_[0]{api} }
    sub _resource_exists { my $self = shift; OCP::Cmd::Apply::K8s::resource_exists($self, @_) }
    sub _crd_get         { my $self = shift; OCP::Cmd::Apply::K8s::crd_get($self, @_) }
}
{
    # get(): the operator Deployment, or the error it dies with. _request():
    # the ClusterPolicy GETs, one [status, body] per call in order, then 404s.
    package ReadApi;
    sub new { my ($c, %o) = @_; bless { deployment => { kind => 'Deployment' }, cp => [], gets => 0, %o }, $c }
    sub get {
        my ($self) = @_;
        die $self->{deployment} unless ref $self->{deployment} eq 'HASH';
        return $self->{deployment};
    }
    sub _request {
        my ($self, $method, $path) = @_;
        die "unexpected $method $path\n" unless $method eq 'GET' && $path eq $CP_PATH;
        $self->{gets}++;
        return ReadResponse->new(@{ shift @{ $self->{cp} } // [404, '{}'] });
    }
}
{
    package ReadResponse;
    sub new     { my ($c, $status, $body) = @_; bless { status => $status, body => $body }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{body} }
}

# What Kubernetes::REST dies with for an HTTP error status (as in t/269).
sub api_error {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(code => $code, context => 'get',
        body => qq({"kind":"Status","status":"Failure","reason":"$reason","code":$code}));
}
my $DENIED  = qq({"kind":"Status","status":"Failure","reason":"Forbidden","code":403});
my $MISSING = qq({"kind":"Status","status":"Failure","reason":"NotFound","code":404});
my $LIVE    = JSON::PP::encode_json(live());

sub read_dry {
    my (%a) = @_;
    my $api = ReadApi->new(%{ $a{api} // {} });
    my ($out, $err) = ('', '');
    my @r;
    {
        no warnings 'redefine';
        local *OCP::Cmd::Apply::Workloads::generate_gpu_operator_manifest = sub { $MANIFEST };
        open my $o, '>', \$out or die;
        open my $e, '>', \$err or die;
        local *STDOUT = $o;
        local *STDERR = $e;
        @r = OCP::Cmd::Apply::Drift::gpu_dry_run(ReadApply->new(api => $api),
            FakeConfig->new(toolkit => 0), %{ $a{opt} // {} });
    }
    return { found => \@r, out => $out, err => $err, gets => $api->{gets} };
}
sub kinds { [ map { $_->{kind} } @{ $_[0]{found} } ] }
sub count { my ($text, $re) = @_; scalar(() = $text =~ /$re/g) }

subtest 'k276: the operator Deployment -- a 404 is no operator, a 403 is not known' => sub {
    my $none = read_dry(api => { deployment => api_error(404, 'NotFound') });
    is_deeply $none->{found}, [], '404: nothing found';
    is $none->{out} . $none->{err}, '', '404: nothing said';
    is $none->{gets}, 0, '404: no ClusterPolicy asked for';

    my $denied = read_dry(api => { deployment => api_error(403, 'Forbidden') });
    is_deeply kinds($denied), ['error'], '403: one error entry, not "no operator"';
    is $denied->{found}[0]{label}, 'GPU Operator', '403: named';
    like $denied->{out},
        qr{^  \[drift\] could not be checked: GPU Operator: could not read Deployment gpu-operator/gpu-operator: Kubernetes API error \(get\): 403 }m,
        '403: could not be checked, with the cause';
    like $denied->{err}, qr{^  \[!!\] GPU Operator not checked: could not read Deployment gpu-operator/gpu-operator: .*"Forbidden"}m,
        '403: the cause on STDERR';
    is count($denied->{err}, qr/Forbidden/), 1, '403: once';
    is $denied->{gets}, 0, '403: nothing read past it';

    my $quiet = read_dry(api => { deployment => api_error(403, 'Forbidden') }, opt => { quiet => 1 });
    is_deeply kinds($quiet), ['error'], 'quiet 403: the same entry';
    is $quiet->{out} . $quiet->{err}, '', 'quiet 403: said nowhere, the caller says it';
};

# k277 replaces k276's claim for the 404: with the operator running, a
# ClusterPolicy that is not there is a difference (the whole spec), not none.
subtest 'k276/k277: the ClusterPolicy -- a 404 is missing, a 403 is not known' => sub {
    my $none = read_dry(api => { cp => [ [404, $MISSING] ] });
    is_deeply [ map { "$_->{kind} $_->{path}" } @{ $none->{found} } ], ['spec spec'],
        '404: one finding, the whole spec';
    is $none->{out}, "  [drift] GPU Operator ClusterPolicy is not on the cluster (or has no spec)\n"
                   . "          would re-apply the GPU Operator manifest\n",
        '404: said as missing, with the remedy';
    is $none->{err}, '', '404: nothing on STDERR, it is an answer';

    my $denied = read_dry(api => { cp => [ [403, $DENIED] ] });
    is_deeply kinds($denied), ['error'], '403: one error entry, not "no differences"';
    is $denied->{found}[0]{label}, 'GPU Operator ClusterPolicy', '403: named';
    like $denied->{out},
        qr{^  \[drift\] could not be checked: GPU Operator ClusterPolicy: GET \Q$CP_PATH\E failed: HTTP 403 }m,
        '403: could not be checked, with the cause';
    like $denied->{err}, qr{^  \[!!\] GPU Operator ClusterPolicy not checked: GET \Q$CP_PATH\E failed: HTTP 403 }m,
        '403: the cause on STDERR';
    is count($denied->{err}, qr/Forbidden/), 1, '403: once';
    is $denied->{gets}, 1, '403: not asked again for the gpu.toolkit warning';
    unlike $denied->{out}, qr/differs from the spec/, '403: no difference claimed';

    my $quiet = read_dry(api => { cp => [ [403, $DENIED] ] }, opt => { quiet => 1 });
    is_deeply kinds($quiet), ['error'], 'quiet 403: the same entry';
    is $quiet->{out} . $quiet->{err}, '', 'quiet 403: said nowhere';
};

subtest 'k276: the gpu.toolkit read -- a 404 is no ClusterPolicy, a 403 is not known' => sub {
    # gpu.toolkit is false here and the live ClusterPolicy has the toolkit on:
    # the warning is due whenever the second read sees it.
    my $read = read_dry(api => { cp => [ [200, $LIVE], [200, $LIVE] ] });
    is_deeply $read->{found}, [], 'control: nothing differs';
    like $read->{out}, qr/\[WARN\] gpu\.toolkit changed \(true -> false\)/,
        'control: the second read decides the warning';

    my $none = read_dry(api => { cp => [ [200, $LIVE], [404, $MISSING] ] });
    is_deeply $none->{found}, [], '404: nothing found';
    is $none->{out} . $none->{err}, '', '404: no ClusterPolicy, nothing to warn about';

    my $denied = read_dry(api => { cp => [ [200, $LIVE], [403, $DENIED] ] });
    is_deeply kinds($denied), ['error'], '403: one error entry, not "no ClusterPolicy"';
    is $denied->{found}[0]{label}, 'gpu.toolkit switch', '403: named';
    like $denied->{out},
        qr{^  \[drift\] could not be checked: gpu\.toolkit switch: GET \Q$CP_PATH\E failed: HTTP 403 }m,
        '403: could not be checked, with the cause';
    like $denied->{err}, qr{^  \[!!\] gpu\.toolkit switch not checked: GET \Q$CP_PATH\E failed: HTTP 403 }m,
        '403: the cause on STDERR';
    is count($denied->{err}, qr/Forbidden/), 1, '403: once';
    unlike $denied->{out}, qr/\[WARN\]/, '403: no warning made up';

    my $both = read_dry(api => { cp => [
        [200, JSON::PP::encode_json(live(sub { pop @{ $_[0]{spec}{toolkit}{env} } }))], [403, $DENIED] ] });
    is_deeply kinds($both), ['spec', 'error'], 'a difference and a failed warning read: both kept';
};


done_testing;

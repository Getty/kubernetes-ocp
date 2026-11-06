#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Cwd ();
use File::Temp ();
use JSON::MaybeXS qw( decode_json );
use JSON::PP ();
use Kubernetes::REST::APIError;
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Apply::K8s;
use OCP::Cmd::Apply::Workloads;
use OCP::Cmd::Status;
use OCP::Config;
use OCP::Drift;
use OCP::Kubernetes;
use OCP::Secrets;
use OCP::Versions;

#
# k313: what `ocp apply` closes was decided in three places -- ocp status's
# "N of M can be reconciled automatically" (and --json's fixable), the dry
# run's "N difference(s) a real run would act on" with its "would re-apply"
# lines, and the real run -- and the first two did not ask what the third
# does. The GPU step (setup_gpu_operator) skips a cluster under gpu.enabled:
# false, and one without a node NFD labelled NVIDIA, and leaves the GPU
# Operator there as it is. Status still counted a GPU Operator off its pin
# there as drift ocp apply closes, the dry run counted it as an action, and
# the dry run promised to re-apply its manifest for a ClusterPolicy that
# differs where no NVIDIA node is. The real run then skipped, and the next
# ocp status said the same again.
#
# The rule is one now (OCP::Drift apply_closes), and the GPU Operator probe
# asks the GPU step's own question -- gpu.enabled, then the NVIDIA nodes, as
# that step reads them -- when it finds the image off its pin.
#
# The claims, each for a GPU Operator off its pin and a ClusterPolicy that
# differs, against one cluster as the three read it:
#   1. gpu.enabled: false -- status counts nothing more and --json says not
#      fixable, naming why; the dry run reports it only, promises no
#      re-apply and counts no action; the real run skips and writes nothing.
#   2. gpu.enabled: true but no node NFD labelled NVIDIA -- the same.
#   3. gpu.enabled: true and a node NFD labelled NVIDIA -- the control: all
#      three say ocp apply closes it, and the real run does.
#   4. the Node list refused -- no verdict: status says it could not be
#      checked and counts it nowhere, the dry run counts it with what could
#      not be checked, the real run dies with the cause. At the pin the probe
#      asks nothing, and under gpu.enabled: false nothing either (the step
#      does not list the nodes there).
#

# Rex puts getcwd/lib first in @INC; the OCP::Drift under test is this tree's.
is Cwd::realpath($INC{'OCP/Drift.pm'}), Cwd::realpath('lib/OCP/Drift.pm'),
    "OCP::Drift is this tree's lib/";

my $NVIDIA_LABEL = 'feature.node.kubernetes.io/pci-0302_10de.present';
my $CP_PATH      = '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';
my $PIN          = OCP::Versions->get_component_version('gpu_operator');
my $IMAGE        = 'nvcr.io/nvidia/gpu-operator:';

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my (@rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        local $SIG{__WARN__} = sub { print STDERR @_ };
        @rv = eval { $code->() };
        $died = $@;
    }
    return { rv => \@rv, out => $out, err => $err, died => $died };
}

{
    package FakeOcp;
    sub new       { my ($c, %a) = @_; bless { %a }, $c }
    sub config    { $_[0]{config} }
    sub verbose   { 0 }
    sub load_file { my ($self, $f) = @_; -f "$f" ? YAML::XS::LoadFile("$f") : undef }
    sub dump_file { my ($self, $f, $d) = @_; YAML::XS::DumpFile("$f", $d) }
    sub dump      { my $self = shift; YAML::XS::Dump(@_) }
}
{
    package WlList;
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
    # A Node as setup_nfd and setup_gpu_operator read one: methods.
    package WlNode;
    sub new      { my ($c, %a) = @_; bless { %a }, $c }
    sub metadata { $_[0] }
    sub name     { $_[0]{name} }
    sub labels   { $_[0]{labels} }
    # nfd-worker as setup_nfd's wait reads it, and as the NFD DaemonSet probe
    # reads it: the spec as applied.
    package WlDaemonSet;
    sub new                    { bless { object => $_[1] }, $_[0] }
    sub spec                   { $_[0]{object}{spec} }
    sub status                 { $_[0] }
    sub numberReady            { 1 }
    sub desiredNumberScheduled { 1 }
    package WlResponse;
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}
{
    # A cluster with one node, crag, that NFD has labelled -- NVIDIA while
    # {nvidia} is true, AMD CPU only otherwise. {refuse_list}: an error the
    # Node lists by an NVIDIA label die with. What a server-side apply (a
    # PATCH) writes is what get() and the raw GETs read back. Every PATCH is
    # recorded.
    package WlApi;
    sub new { bless { objects => {}, paths => {}, patches => [], nvidia => 1 }, shift }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub expand_class     { undef }
    sub labels {
        my ($self) = @_;
        return {
            'feature.node.kubernetes.io/cpu-model.vendor_id' => 'AMD',
            ($self->{nvidia} ? ($NVIDIA_LABEL => 'true') : ()),
        };
    }
    sub key {
        my ($kind, $namespace, $name) = @_;
        return join '/', $kind, $namespace // '-', $name;
    }
    sub list {
        my ($self, $kind, %a) = @_;
        die "unexpected list $kind\n" unless $kind eq 'Node';
        my ($k, $v) = split /=/, $a{labelSelector} // '', 2;
        die $self->{refuse_list} if $self->{refuse_list} && defined $k && $k =~ /_10de\.present\z/;
        my $labels = $self->labels;
        return WlList->new([]) if defined $k && ($labels->{$k} // '') ne ($v // '');
        return WlList->new([ WlNode->new(name => 'crag', labels => $labels) ]);
    }
    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : undef;
        my %a = @rest;
        $name //= $a{name};
        return { metadata => { name => 'crag', labels => $self->labels },
                 status   => { allocatable => { 'nvidia.com/gpu' => '1' }, capacity => { 'nvidia.com/gpu' => '1' } } }
            if $kind eq 'Node' && $name eq 'crag';
        my $key = key($kind, $a{namespace}, $name);
        my $obj = $self->{objects}{$key} or die "404 $key not found\n";
        return $kind eq 'DaemonSet' && $name eq 'nfd-worker' ? WlDaemonSet->new($obj) : $obj;
    }
    sub _request {
        my ($self, $method, $path, $body, %o) = @_;
        if ($method eq 'PATCH') {
            my $obj = JSON::PP::decode_json(JSON::PP::encode_json($body));
            push @{ $self->{patches} }, { kind => $obj->{kind}, name => $obj->{metadata}{name} };
            $obj->{status} = { state => 'ready' } if $obj->{kind} eq 'ClusterPolicy';
            $self->{objects}{ key($obj->{kind}, $obj->{metadata}{namespace}, $obj->{metadata}{name}) } = $obj;
            $self->{paths}{$path} = $obj;
            return WlResponse->new(200, '{}');
        }
        die "unexpected $method $path\n" unless $method eq 'GET';
        my $obj = $self->{paths}{$path}
            or return WlResponse->new(404, '{"kind":"Status","status":"Failure","reason":"NotFound","code":404}');
        return WlResponse->new(200, JSON::PP::encode_json($obj));
    }
}
# What ocp status builds: OCP::Kubernetes over the cluster above, one control
# plane node, no GPU block.
{
    package FakeK8s;
    sub new               { bless { api => $_[1] }, $_[0] }
    sub api               { $_[0]{api} }
    sub list_nodes        { [ { metadata => { name => 'crag' } } ] }
    sub gpu_nodes         { [] }
    sub node_name         { $_[1]{metadata}{name} }
    sub node_ready        { 1 }
    sub node_roles        { 'control-plane' }
    sub node_version      { 'v1.32.1+k3s1' }
    sub node_internal_ip  { '10.0.0.1' }
    sub node_gpu_count    { 0 }
    sub node_gpu_capacity { undef }
}
{ package FakeSecrets; sub new { bless {}, $_[0] } sub has_kubeconfig { 1 } sub read_kubeconfig { "apiVersion: v1\n" } }

sub project {
    my $dir = path(File::Temp::tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew(<<'YAML');
name: nvlab
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: crag.ocp.invalid
nocert: true
gpu:
  enabled: true
YAML
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n");
    return $dir;
}
sub config_for { OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify) }
sub gpu_disabled {
    my ($dir) = @_;
    $dir->child('ocp.yaml')->edit_raw(sub { s/^  enabled: true$/  enabled: false/m or die "no gpu.enabled\n" });
}

sub new_apply {
    my ($api, %o) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ], %o);
    $apply->{_k8s_api} = $api;
    return $apply;
}

# The real run's step: { rv, out, err, died, patches }.
sub run_step {
    my ($api, $dir, $step) = @_;
    my $apply = new_apply($api);
    my $config = config_for($dir);
    $api->{patches} = [];
    my $r = do {
        no warnings 'redefine';
        local *OCP::Cmd::Apply::_poll_deployment_ready = sub { 1 };
        local *OCP::Cmd::Apply::wait_seconds           = sub { };
        capture { $step->($apply, $config) };
    };
    $r->{patches} = $api->{patches};
    return $r;
}
sub gpu_step { run_step(@_, \&OCP::Cmd::Apply::Workloads::setup_gpu_operator) }

# The GPU Operator probe's entries, as the detector status builds finds them.
sub probe_entries {
    my ($api, $dir) = @_;
    my $r = capture { OCP::Drift->new(config => config_for($dir), api => $api)->component_drift };
    die "component_drift died: $r->{died}" if $r->{died};
    return [ grep { ($_->{label} // '') eq 'GPU Operator' } @{ $r->{rv} } ];
}

# `ocp status` against the cluster, text or --json: { rc, out, err, count,
# found, json }. count is N of "N of M can be reconciled automatically", 0
# without that line; found is M, the findings (entries not of kind error).
sub status_of {
    my ($api, $dir, %o) = @_;
    my $cmd = OCP::Cmd::Status->new(
        ($o{json} ? (json => 1) : ()),
        command_chain => [ FakeOcp->new(config => $dir->child('ocp.yaml')->stringify) ],
    );
    my $r = do {
        no warnings 'redefine';
        local *OCP::Secrets::new                   = sub { FakeSecrets->new };
        local *OCP::Kubernetes::new                = sub { FakeK8s->new($api) };
        local *OCP::Cmd::Status::reach_cluster_api = sub { $_[1] };
        local *OCP::Cmd::Status::rex_prober        = sub { undef };
        capture { $cmd->execute([], []) };
    };
    $r->{rc} = $r->{rv}[0];
    if ($o{json}) {
        $r->{json} = eval { decode_json($r->{out}) } // {};
        my @drift  = @{ $r->{json}{drift} // [] };
        $r->{count} = grep { $_->{fixable} } @drift;
        $r->{found} = grep { $_->{kind} ne 'error' } @drift;
    }
    else {
        my ($n, $m) = $r->{out} =~ /^(\d+) of (\d+) can be reconciled automatically: run 'ocp apply'\.$/m;
        $r->{count} = $n // 0;
    }
    return $r;
}
sub json_entry {
    my ($r, $re) = @_;
    my ($e) = grep { $_->{component} eq 'gpu_operator' && $_->{message} =~ $re } @{ $r->{json}{drift} // [] };
    return $e;
}

# `ocp apply --dry-run` on the cluster: its output, the writes it made, and
# its three counts.
sub dry_run {
    my ($api, $dir) = @_;
    my $apply = new_apply($api, dry_run => 1);
    $api->{patches} = [];
    my $r = do {
        no warnings 'redefine';
        local *OCP::Cmd::Apply::rex_prober = sub { undef };
        capture { OCP::Cmd::Apply::Drift::dry_run_report($apply, config_for($dir), '10.0.0.1') };
    };
    $r->{patches} = $api->{patches};
    ($r->{actions})     = $r->{out} =~ /^  (\d+) difference\(s\) a real run would act on\.$/m;
    ($r->{report_only}) = $r->{out} =~ /^  (\d+) more reported only/m;
    ($r->{unknown})     = $r->{out} =~ /^  (\d+) more could not be checked/m;
    $r->{$_} //= 0 for qw( report_only unknown );
    return $r;
}

# A cluster where ocp apply deployed NFD and the GPU Operator at its pin.
sub deployed {
    my $api = WlApi->new;
    my $dir = project();
    for my $step (\&OCP::Cmd::Apply::Workloads::setup_nfd, \&OCP::Cmd::Apply::Workloads::setup_gpu_operator) {
        my $r = run_step($api, $dir, $step);
        die "the first deploy failed: $r->{died}" if $r->{died};
        die "the first deploy was '@{ $r->{rv} }'\n" unless "@{ $r->{rv} }" eq 'deployed';
    }
    return ($api, $dir);
}

sub off_pin {
    my ($api) = @_;
    $api->{objects}{'Deployment/gpu-operator/gpu-operator'}{spec}{template}{spec}{containers}[0]{image}
        = $IMAGE . 'v0.0.1';
}
sub image_of {
    $_[0]{objects}{'Deployment/gpu-operator/gpu-operator'}{spec}{template}{spec}{containers}[0]{image};
}
# A ClusterPolicy edited in the cluster: the driver switched the other way.
sub cluster_policy_edited {
    my ($api) = @_;
    my $cp = $api->{paths}{$CP_PATH} or die "no ClusterPolicy at $CP_PATH\n";
    $cp->{spec}{driver}{enabled} = $cp->{spec}{driver}{enabled} ? JSON::PP::false : JSON::PP::true;
}

my $FOUND = qr/^GPU Operator runs v0\.0\.1, expected \Q$PIN\E\z/;
my $LINE  = "  [drift] GPU Operator runs v0.0.1, expected $PIN";

# Where the GPU step skips: the cluster as it, and the three, see it.
my %SKIPS = (
    'gpu.enabled: false' => {
        turn => sub { gpu_disabled($_[1]) },
        why  => qr/^gpu\.enabled is false, so ocp apply leaves the GPU Operator as it is;/,
        says => qr/gpu\.enabled is false/,
    },
    'no node NFD labelled NVIDIA' => {
        turn => sub { $_[0]{nvidia} = 0 },
        why  => qr/^No node carries an NFD NVIDIA label \(pci-0300_10de or pci-0302_10de\), so ocp apply leaves the GPU Operator as it is\.\z/,
        says => qr/No GPU nodes detected/,
    },
);

for my $case (sort keys %SKIPS) {
    my $s = $SKIPS{$case};

    subtest "$case: a GPU Operator off its pin -- status, the dry run and the real run agree" => sub {
        my ($api, $dir) = deployed();
        $s->{turn}->($api, $dir);
        my $text0 = status_of($api, $dir);
        my $json0 = status_of($api, $dir, json => 1);
        my $dry0  = dry_run($api, $dir);
        is_deeply probe_entries($api, $dir), [], 'at its pin, the probe finds nothing';

        off_pin($api);

        my ($entry, @more) = @{ probe_entries($api, $dir) };
        is scalar @more, 0, 'the probe: one entry';
        like $entry && $entry->{message}, $FOUND, 'the probe names the image';
        ok $entry && !$entry->{self_healing}, 'the probe: not self_healing here';
        like $entry && $entry->{manual_step}, $s->{why}, 'the probe: says why ocp apply leaves it';

        my $text = status_of($api, $dir);
        is $text->{died}, '', 'status: ran';
        like $text->{out}, qr/^\Q$LINE\E\n {10}\S/m, 'status: names it, and why under it';
        is $text->{count}, $text0->{count}, 'status: no more to reconcile automatically';

        my $json = status_of($api, $dir, json => 1);
        my $e = json_entry($json, $FOUND);
        ok $e, 'status --json: the entry';
        ok $e && !$e->{fixable}, 'status --json: not fixable';
        like $e && $e->{manual_step}, $s->{why}, 'status --json: with the why';
        is $json->{count}, $json0->{count}, 'status --json: no more fixable';
        is $json->{found}, $json0->{found} + 1, 'status --json: one more finding';

        my $dry = dry_run($api, $dir);
        is $dry->{died}, '', 'the dry run: ran';
        is_deeply $dry->{patches}, [], 'the dry run: writes nothing';
        like $dry->{out}, qr/^\Q$LINE\E\n {10}report only, a real run leaves it as it is$/m,
            'the dry run: names it, report only';
        unlike $dry->{out}, qr/would re-apply the GPU Operator manifest/, 'the dry run: promises no re-apply';
        is $dry->{actions}, $dry0->{actions}, 'the dry run: no more differences a real run acts on';
        is $dry->{report_only}, $dry0->{report_only} + 1, 'the dry run: one more reported only';

        my $res = gpu_step($api, $dir);
        is $res->{died}, '', 'the real run: does not die';
        is_deeply $res->{rv}, ['skipped'], 'the real run: skips the GPU step';
        like $res->{out}, $s->{says}, 'the real run: and says why';
        is_deeply $res->{patches}, [], 'the real run: applies nothing';
        is image_of($api), $IMAGE . 'v0.0.1', 'the real run: leaves the image';
        like +(probe_entries($api, $dir)->[0] // {})->{message}, $FOUND, 'so the next status names it again';
    };

    subtest "$case: a ClusterPolicy that differs -- the dry run and the real run agree" => sub {
        my ($api, $dir) = deployed();
        $s->{turn}->($api, $dir);
        my $dry0 = dry_run($api, $dir);
        cluster_policy_edited($api);

        my $dry = dry_run($api, $dir);
        is $dry->{died}, '', 'the dry run: ran';
        unlike $dry->{out}, qr/ClusterPolicy differs/, 'the dry run: names no ClusterPolicy difference';
        unlike $dry->{out}, qr/would re-apply the GPU Operator manifest/, 'the dry run: promises no re-apply';
        is $dry->{actions}, $dry0->{actions}, 'the dry run: no more differences a real run acts on';
        is $dry->{unknown}, $dry0->{unknown}, 'the dry run: nothing more that could not be checked';

        my $res = gpu_step($api, $dir);
        is_deeply $res->{rv}, ['skipped'], 'the real run: skips the GPU step';
        is_deeply $res->{patches}, [], 'the real run: applies nothing';
    };
}

#### 3: the control -- gpu.enabled and a node NFD labelled NVIDIA

subtest 'an NVIDIA node and gpu.enabled: a GPU Operator off its pin is closed, by all three' => sub {
    my ($api, $dir) = deployed();
    my $text0 = status_of($api, $dir);
    my $dry0  = dry_run($api, $dir);
    off_pin($api);

    my ($entry) = @{ probe_entries($api, $dir) };
    ok $entry && $entry->{self_healing}, 'the probe: self_healing';
    ok $entry && !defined $entry->{manual_step}, 'the probe: no manual step';

    my $text = status_of($api, $dir);
    like $text->{out}, qr/^\Q$LINE\E$/m, 'status: names it';
    is $text->{count}, $text0->{count} + 1, 'status: one more to reconcile automatically';
    my $e = json_entry(status_of($api, $dir, json => 1), $FOUND);
    ok $e && $e->{fixable}, 'status --json: fixable';

    my $dry = dry_run($api, $dir);
    like $dry->{out}, qr/^\Q$LINE\E\n {10}would re-apply the GPU Operator manifest$/m,
        'the dry run: would re-apply it';
    is $dry->{actions}, $dry0->{actions} + 1, 'the dry run: one more difference a real run acts on';

    my $res = gpu_step($api, $dir);
    is_deeply $res->{rv}, [ 'updated', "ran v0.0.1, expected $PIN" ], 'the real run: re-applies it';
    is image_of($api), $IMAGE . $PIN, 'the real run: back at its pin';
};

subtest 'an NVIDIA node and gpu.enabled: a ClusterPolicy that differs is closed, by both' => sub {
    my ($api, $dir) = deployed();
    my $dry0 = dry_run($api, $dir);
    cluster_policy_edited($api);

    my $dry = dry_run($api, $dir);
    like $dry->{out},
        qr/^  \[drift\] GPU Operator ClusterPolicy differs from the spec at spec\.driver\.enabled\n {10}would re-apply the GPU Operator manifest$/m,
        'the dry run: names it, and would re-apply';
    is $dry->{actions}, $dry0->{actions} + 1, 'the dry run: one more difference a real run acts on';

    my $res = gpu_step($api, $dir);
    is $res->{rv}[0], 'updated', 'the real run: re-applies it';
    ok +(grep { $_->{kind} eq 'ClusterPolicy' } @{ $res->{patches} }), 'the real run: the ClusterPolicy applied';
};

#### 4: the Node list refused

my $REFUSED = Kubernetes::REST::APIError->new(code => 403, context => 'list',
    body => '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}');

subtest 'the Node list refused: no verdict, in all three' => sub {
    my ($api, $dir) = deployed();
    $api->{refuse_list} = $REFUSED;
    my $json0 = status_of($api, $dir, json => 1);
    my $dry0  = dry_run($api, $dir);
    is_deeply probe_entries($api, $dir), [], 'at its pin, the probe asks nothing and finds nothing';

    off_pin($api);

    my ($entry, @more) = @{ probe_entries($api, $dir) };
    is scalar @more, 0, 'the probe: one entry';
    is $entry && $entry->{kind}, 'error', 'the probe: a check it could not make';
    like $entry && $entry->{message},
        qr/^GPU Operator runs v0\.0\.1, expected \Q$PIN\E; whether ocp apply re-applies it is unknown: .*403/,
        'the probe: what it found, and what it could not tell, with the cause';

    my $text = status_of($api, $dir);
    like $text->{out}, qr/^  \[drift\] could not be checked: GPU Operator runs v0\.0\.1, expected \Q$PIN\E; whether/m,
        'status: could not be checked';
    my $json = status_of($api, $dir, json => 1);
    my $e = json_entry($json, qr/^GPU Operator runs v0\.0\.1/);
    ok $e && !$e->{fixable}, 'status --json: not fixable';
    is $json->{count}, $json0->{count}, 'status --json: no more fixable';
    is $json->{found}, $json0->{found}, 'status --json: and no more findings';

    my $dry = dry_run($api, $dir);
    is $dry->{actions}, $dry0->{actions}, 'the dry run: no more differences a real run acts on';
    is $dry->{unknown}, $dry0->{unknown} + 1, 'the dry run: one more that could not be checked';

    my $res = gpu_step($api, $dir);
    like $res->{died}, qr{^could not read Nodes labelled feature\.node\.kubernetes\.io/pci-0300_10de\.present=true: .*403}s,
        'the real run: dies with the cause';
    is_deeply $res->{patches}, [], 'the real run: applies nothing';
};

subtest 'the Node list refused under gpu.enabled: false: not read, by any of the three' => sub {
    my ($api, $dir) = deployed();
    $api->{refuse_list} = $REFUSED;
    gpu_disabled($dir);
    off_pin($api);

    my ($entry) = @{ probe_entries($api, $dir) };
    is $entry && $entry->{kind}, 'version', 'the probe: a finding, not a check it could not make';
    like $entry && $entry->{manual_step}, qr/^gpu\.enabled is false/, 'the probe: report only, and why';

    my $res = gpu_step($api, $dir);
    is $res->{died}, '', 'the real run: does not die';
    is_deeply $res->{rv}, ['skipped'], 'the real run: skips before it lists a node';
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS qw(decode_json);
use JSON::PP ();
use Path::Tiny qw(path);
use Scalar::Util qw(blessed);
use YAML::XS ();

use lib 'lib';

use IO::K8s;
use Kubernetes::REST::APIError;
use OCP;
use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Apply::Workloads;
use OCP::Cmd::Status;
use OCP::Drift;
use OCP::Kubernetes;

#
# k359: gpu.amd.integrated and gpu.toolkit are install-time settings. A node
# takes them when its install task runs: police1 once, in the apply that
# builds the cluster (every later apply takes the reconcile path, which
# installs nothing on it), a joined worker or police2+ never again while it
# is Ready -- it is only verified. A changed value reached no node that had
# joined, and nothing said so. The maintainer's answer (2026-11-06): docs,
# apply and status say it, and name the re-join; nothing is re-installed.
#
# The claims:
#   1. the warning names the nodes that joined before, the re-join of a
#      worker in the commands that exist (`ocp node rm NAME`, then `ocp apply`
#      or `ocp node add NAME`), and that a control plane has none -- each only
#      for the kind of node it names; turning integrated off says the driver
#      stays; no node, no warning
#   2. ocp apply's reconcile path compares ocp.yaml's gpu.amd.integrated with
#      the OCPNodeProvider CR, the record of the value the nodes joined under,
#      before it writes it: a change is a [WARN] on STDERR, counted for WITH
#      WARNINGS, naming the Ready OCPNodes that did not join with --gpu; the
#      same value, no CR yet, no joined node, gpu.enabled false (either side)
#      and a local provider are silent; a CR without the field reads as false;
#      a read that fails is a [WARN] with its cause, never a death
#   3. it is called before the provider write, on the reconcile path and in
#      its dry run
#   4. the gpu.toolkit warning of the GPU step names the NVIDIA nodes with the
#      re-join for their kind, on STDERR (it was on STDOUT), and is counted
#   5. ocp status: the Spec section shows both values and that a joined node
#      takes a change only when joined again, a control plane never; --json
#      has them as spec.gpu; not under gpu.enabled false, not before the
#      cluster is deployed
#
# Network-free: fake APIs, real OCP::Config over temp ocp.yaml files.
#

note 'OCP::Cmd::Apply::CR from ' . $INC{'OCP/Cmd/Apply/CR.pm'};

my $ocp = OCP->new;
my $tmp = tempdir(CLEANUP => 1);
my $n   = 0;

# A project: ocp.yaml from $spec (merged over an ssh control plane), and a
# kubeconfig.yaml unless deployed => 0.
sub project {
    my (%o) = @_;
    my $dir = path($tmp)->child('p' . ++$n);
    $dir->child('.ocp')->mkpath;
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k359',
        kubernetes     => { version => 'v1.36.4+rke2r1' },
        control_planes => [ { provider => $o{cp_provider} // 'ssh', host => '10.230.30.52' } ],
        %{ $o{spec} // {} },
    });
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n") if $o{deployed} // 1;
    return $dir->child('ocp.yaml')->stringify;
}

sub config_with { OCP::Config->new(file => project(@_)) }

sub api_error {
    my ($code) = @_;
    my $reason = $code == 404 ? 'NotFound' : 'Forbidden';
    return Kubernetes::REST::APIError->new(code => $code, context => 'get',
        body => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}));
}

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $o;
        local *STDERR = $e;
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, out => $out, err => $err, died => $died };
}

#### 1. the warning's text

subtest 'install_time_warning: the nodes, and the re-join for their kind' => sub {
    my $w = sub { OCP::Cmd::Apply::CR::install_time_warning(@_) };

    my $both = $w->(setting => 'gpu.amd.integrated', was => 0, now => 1,
        nodes => [ [ 'police1', 1 ], [ 'worker-1', 0 ] ]);
    like $both, qr/\A  \[WARN\] gpu\.amd\.integrated changed \(false -> true\), and it is set at a node's install:\n/,
        'the setting, the change, and why it matters';
    like $both, qr/the nodes that joined before keep the old value \(police1, worker-1\)\.\n/,
        'the nodes that joined before, by name';
    like $both, qr/A worker takes it when it is joined again: `ocp node rm NAME`, then\n {9}`ocp apply` \(a worker ocp\.yaml lists\) or `ocp node add NAME` with its\n {9}flags again \(a worker added by hand\)\.\n/,
        'a worker: ocp node rm, then ocp apply or ocp node add';
    like $both, qr/A control plane cannot be joined again with ocp: it keeps the old value\.\n/,
        'a control plane: no re-join, said so';
    unlike $both, qr/amdgpu driver/, 'turned on: nothing about a driver left behind';
    is_deeply [ sort { $a cmp $b } keys %{{ map { $_ => 1 } $both =~ /`(ocp [^`]+)`/g }} ],
        [ 'ocp apply', 'ocp node add NAME', 'ocp node rm NAME' ],
        'only commands that exist are named';
    is scalar(() = $both =~ /^  \S/mg), 1, 'one [WARN], its other lines indented under it';

    my $cp_only = $w->(setting => 'gpu.amd.integrated', was => 1, now => 0, nodes => [ [ 'police1', 1 ] ]);
    unlike $cp_only, qr/A worker takes it/, 'only a control plane joined: no worker re-join';
    like $cp_only, qr/A control plane cannot be joined again/, '... the control plane sentence';
    like $cp_only, qr/Turning it off uninstalls nothing: the amdgpu driver stays on the machine\.\n\z/,
        'turned off: the driver stays';

    my $workers = $w->(setting => 'gpu.toolkit', was => 1, now => 0, what => 'GPU nodes',
        nodes => [ [ 'gpu-1', 0 ] ]);
    like $workers, qr/\(true -> false\)/, 'gpu.toolkit, true -> false';
    like $workers, qr/the GPU nodes that joined before keep the old value \(gpu-1\)/, 'its own noun';
    unlike $workers, qr/control plane/, 'only workers: no control plane sentence';
    unlike $workers, qr/amdgpu/, 'gpu.toolkit off: nothing about the amdgpu driver';

    is $w->(setting => 'gpu.amd.integrated', was => 0, now => 1, nodes => []), undef,
        'no node joined before: no warning';

    my $unknown = $w->(setting => 'gpu.toolkit', was => 0, now => 1);
    like $unknown, qr/keep the old value\.\n/, 'no node list at hand: no names';
    like $unknown, qr/A worker takes it/,              '... and both re-joins said:';
    like $unknown, qr/A control plane cannot be joined/, '... the worker\'s and the control plane\'s';
};

#### 2. ocp apply: gpu.amd.integrated against the OCPNodeProvider CR

{
    package FakeList;
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}
{
    # OCPNodeProviders by name (a hash, or what the get dies with), the
    # OCPNodes as one list (or what the list dies with). Records every read.
    package CrApi;
    sub new { my ($c, %a) = @_; bless { providers => {}, ocpnodes => [], reads => [], %a }, $c }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : { @rest }->{name};
        push @{ $self->{reads} }, "get $kind $name";
        my $cr = $self->{providers}{$name} // main::api_error(404);
        die $cr if Scalar::Util::blessed($cr);
        return $cr;
    }
    sub list {
        my ($self, $kind) = @_;
        push @{ $self->{reads} }, "list $kind";
        die $self->{ocpnodes} unless ref $self->{ocpnodes} eq 'ARRAY';
        return FakeList->new($self->{ocpnodes});
    }
}

sub provider_cr { my (%gpu) = @_; return { metadata => { name => 'ssh-default' }, spec => { type => 'ssh', gpu => { %gpu } } } }
sub integrated  { return amd => { integrated => $_[0] ? JSON::PP::true : JSON::PP::false } }

sub ocpnode {
    my ($name, %o) = @_;
    return { metadata => { name => $name },
             spec     => { role => $o{role} // 'worker', ($o{gpu} ? (gpu => JSON::PP::true) : ()) },
             status   => { phase => $o{phase} // 'Ready' } };
}

my @JOINED = (
    ocpnode('police1', role => 'control-plane'),
    ocpnode('worker-1'),
    ocpnode('gpu-1', gpu => 1),           # --gpu: integrated set up whatever the setting
    ocpnode('worker-2', phase => 'Pending'),
);

sub check {
    my (%o) = @_;
    my $api   = CrApi->new(%{ $o{api} // {} });
    my $apply = {};
    my $r = capture { OCP::Cmd::Apply::CR::warn_install_time_changes($apply, $api, $o{config}) };
    return { %$r, reads => $api->{reads}, warnings => $apply->{_apply_warnings} // [] };
}

my $ON  = { gpu => { amd => { integrated => JSON::PP::true } } };
my $OFF = { gpu => { amd => { integrated => JSON::PP::false } } };

subtest 'apply: a changed gpu.amd.integrated is said, on STDERR, with the nodes it does not reach' => sub {
    my $r = check(config => config_with(spec => $ON),
        api => { providers => { 'ssh-default' => provider_cr(enabled => JSON::PP::true, integrated(0)) },
                 ocpnodes  => [ @JOINED ] });
    is $r->{died}, '', 'no death';
    is $r->{rv}, 1, 'it warned';
    like $r->{err}, qr/\A  \[WARN\] gpu\.amd\.integrated changed \(false -> true\)/, 'the [WARN], on STDERR';
    like $r->{err}, qr/keep the old value \(police1, worker-1\)\./,
        'the Ready nodes without --gpu, by name: not the --gpu one, not the Pending one';
    like $r->{err}, qr/A worker takes it when it is joined again/, 'a worker among them: its re-join';
    like $r->{err}, qr/A control plane cannot be joined again/, 'police1 among them: no re-join for it';
    is $r->{out}, '', 'nothing on STDOUT';
    is_deeply $r->{warnings}, [ 'gpu.amd.integrated' ], 'counted: the banner reads WITH WARNINGS';
    is_deeply $r->{reads}, [ 'get OCPNodeProvider ssh-default', 'list OCPNode' ],
        'the CR, then the OCPNodes';

    my $off = check(config => config_with(spec => $OFF),
        api => { providers => { 'ssh-default' => provider_cr(integrated(1)) }, ocpnodes => [ @JOINED ] });
    like $off->{err}, qr/\(true -> false\)/, 'true -> false too';
    like $off->{err}, qr/the amdgpu driver stays on the machine/, '... and the driver stays';
};

subtest 'apply: nothing to say, nothing said' => sub {
    my %cases = (
        'the same value' => [ $ON, { providers => { 'ssh-default' => provider_cr(integrated(1)) },
                                     ocpnodes => [ @JOINED ] } ],
        'no CR yet (404): a cluster being built' => [ $ON, { ocpnodes => [ @JOINED ] } ],
        'a CR an older ocp wrote, without the field, under false' => [ $OFF,
            { providers => { 'ssh-default' => provider_cr(enabled => JSON::PP::true) }, ocpnodes => [ @JOINED ] } ],
        'the CR under gpu.enabled false: nobody joined with GPU detection' => [ $ON,
            { providers => { 'ssh-default' => provider_cr(enabled => JSON::PP::false, integrated(0)) },
              ocpnodes => [ @JOINED ] } ],
        'no Ready node but the --gpu one' => [ $ON,
            { providers => { 'ssh-default' => provider_cr(integrated(0)) },
              ocpnodes => [ ocpnode('gpu-1', gpu => 1), ocpnode('worker-2', phase => 'Failed') ] } ],
    );
    for my $what (sort keys %cases) {
        my ($spec, $api) = @{ $cases{$what} };
        my $r = check(config => config_with(spec => $spec), api => $api);
        is $r->{died}, '', "$what: no death";
        is $r->{out} . $r->{err}, '', "$what: silent";
        is_deeply $r->{warnings}, [], "$what: not counted";
    }

    my $old = check(config => config_with(spec => $ON),
        api => { providers => { 'ssh-default' => provider_cr(enabled => JSON::PP::true) }, ocpnodes => [ @JOINED ] });
    like $old->{err}, qr/\(false -> true\)/, 'a CR without the field reads as false: switched on, said';

    my $disabled = check(config => config_with(spec => { gpu => { enabled => JSON::PP::false,
        amd => { integrated => JSON::PP::true } } }),
        api => { providers => { 'ssh-default' => provider_cr(integrated(0)) }, ocpnodes => [ @JOINED ] });
    is $disabled->{out} . $disabled->{err}, '', 'gpu.enabled false in ocp.yaml: silent';
    is_deeply $disabled->{reads}, [], '... and nothing read';

    my $local = check(config => config_with(cp_provider => 'local', spec => $ON),
        api => { providers => { 'local-default' => provider_cr(integrated(0)) }, ocpnodes => [ @JOINED ] });
    is_deeply $local->{reads}, [], 'a local control plane alone: no OCPNodeProvider to read (apply writes none)';
    is $local->{out} . $local->{err}, '', '... and nothing said';
};

subtest 'apply: a read that fails is said with its cause, and stops nothing' => sub {
    for my $case ([ 'the CR' => { providers => { 'ssh-default' => api_error(403) }, ocpnodes => [ @JOINED ] } ],
                  [ 'the OCPNodes' => { providers => { 'ssh-default' => provider_cr(integrated(0)) },
                                        ocpnodes => api_error(403) } ]) {
        my ($what, $api) = @$case;
        my $r = check(config => config_with(spec => $ON), api => $api);
        is $r->{died}, '', "$what, 403: no death";
        like $r->{err}, qr/\A  \[WARN\] gpu\.amd\.integrated not compared with the cluster's: .*403.*\n\z/,
            "$what, 403: a [WARN] with the cause, in one line";
        unlike $r->{err}, qr/ at \S+ line \d+/, "$what, 403: no Perl location";
        is $r->{out}, '', "$what, 403: nothing on STDOUT";
        is_deeply $r->{warnings}, [ 'gpu.amd.integrated' ], "$what, 403: counted";
    }
};

#### 3. where it runs

subtest 'the reconcile path compares before it writes the CR; its dry run says it too' => sub {
    my $src = path('lib/OCP/Cmd/Apply/Drift.pm')->slurp_utf8;
    like $src, qr/Checking node CRs.*?\$self->_ensure_crds\(\$api\);\s*(?:#[^\n]*\n\s*)*OCP::Cmd::Apply::CR::warn_install_time_changes\(\$self, \$api, \$config\);\s*\$self->_ensure_providers\(/s,
        'reconcile: right before _ensure_providers, which records ocp.yaml\'s value';
    like $src, qr/sub dry_run_report \{.*?OCP::Cmd::Apply::CR::warn_install_time_changes\(\$self, \$self->_k8s_api, \$config\);.*?^\}/ms,
        'the dry run of the reconcile path';
};

#### 4. gpu.toolkit: the GPU step's warning

{
    package NodeItem;
    sub new      { my ($c, $name, %labels) = @_; bless { name => $name, labels => { %labels } }, $c }
    sub metadata { $_[0] }
    sub name     { $_[0]{name} }
    sub labels   { $_[0]{labels} }
}
{
    package FakeResponse;
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}
{
    # A running GPU Operator whose ClusterPolicy has the toolkit off, and two
    # NVIDIA nodes NFD labelled, each with its GPU allocatable.
    package NvApi;
    my $NFD = 'feature.node.kubernetes.io/pci-0302_10de.present';
    sub new { bless { nodes => [ NodeItem->new('otho', 'node-role.kubernetes.io/control-plane' => 'true'),
                                 NodeItem->new('crag') ] }, shift }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub ensure           { $_[1] }
    sub list {
        my ($self, $kind, %a) = @_;
        return FakeList->new([]) unless $kind eq 'Node' && ($a{labelSelector} // '') eq "$NFD=true";
        return FakeList->new($self->{nodes});
    }
    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : { @rest }->{name};
        return { metadata => { name => $name }, status => { allocatable => { 'nvidia.com/gpu' => '1' },
                                                             capacity    => { 'nvidia.com/gpu' => '1' } } }
            if $kind eq 'Node';
        return { kind => $kind } if $kind eq 'Namespace' || $kind eq 'Deployment';
        die main::api_error(404);
    }
    sub _request {
        my ($self, $method, $path) = @_;
        return FakeResponse->new(200, '{"spec":{"toolkit":{"enabled":false}},"status":{"state":"ready"}}')
            if $path eq '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';
        return FakeResponse->new(404, '{}');
    }
}
{
    package FakeOCP;
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub config    { undef }
}

subtest 'apply: the gpu.toolkit switch names the NVIDIA nodes, on STDERR, counted' => sub {
    my $config = config_with(spec => { gpu => { toolkit => JSON::PP::true } });
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    $apply->{_k8s_api} = NvApi->new;
    my $r = do {
        no warnings 'redefine';
        local *OCP::Cmd::Apply::K8s::server_side_apply = sub { 1 };
        local *OCP::Cmd::Apply::_poll_deployment_ready = sub { 1 };
        local *OCP::Cmd::Apply::wait_seconds           = sub { 1 };
        local *OCP::Drift::gpu_crds_differing                         = sub { () };
        local *OCP::Cmd::Apply::Workloads::cluster_policy_differences = sub { () };
        local *OCP::Cmd::Apply::Workloads::generate_gpu_operator_manifest = sub { "---\n" };
        local *OCP::Cmd::Apply::_save_deployed_hash = sub { 1 };
        local *OCP::Cmd::Apply::_load_deployed_hashes = sub { {} };
        capture { OCP::Cmd::Apply::Workloads::setup_gpu_operator($apply, $config) };
    };
    is $r->{died}, '', 'the step ran' or diag $r->{died};
    like $r->{err}, qr/^  \[WARN\] gpu\.toolkit changed \(false -> true\), and it is set at a node's install:\n {9}the GPU nodes that joined before keep the old value \((?:crag, otho|otho, crag)\)\./m,
        'the switch, with the NVIDIA nodes by name, on STDERR';
    like $r->{err}, qr/A worker takes it when it is joined again/, 'crag, a worker: its re-join';
    like $r->{err}, qr/A control plane cannot be joined again/, 'otho, a control plane: none';
    unlike $r->{out}, qr/\[WARN\]/, 'not on STDOUT any more';
    is_deeply $apply->{_apply_warnings} // [], [ 'gpu.toolkit' ], 'counted: WITH WARNINGS';
};

#### 5. ocp status

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }
{ package Local::FakeSecrets; sub new { bless {}, $_[0] } sub has_kubeconfig { 1 } sub read_kubeconfig { "apiVersion: v1\nkind: Config\n" } }
{
    package Local::StatusApi;
    sub new  { my ($c, %a) = @_; bless { %a }, $c }
    sub list {
        my ($self, $kind) = @_;
        return FakeList->new($self->{nodes}) if $kind eq 'Node';
        die "unexpected list $kind\n";
    }
    sub get { die "unexpected get $_[1]\n" }
}

my $IO = IO::K8s->new;
sub k8s_node {
    my ($name) = @_;
    return $IO->struct_to_object('Node', {
        metadata => { name => $name },
        status   => {
            conditions => [ { type => 'Ready', status => 'True' } ],
            addresses  => [ { type => 'InternalIP', address => '10.0.0.1' } ],
            nodeInfo   => {
                kubeletVersion => 'v1.36.4+rke2r1', kubeProxyVersion => 'v1.36.4+rke2r1',
                architecture => 'amd64', bootID => 'b', containerRuntimeVersion => 'containerd://2.3.4',
                kernelVersion => '7.0.0', machineID => 'm', operatingSystem => 'linux',
                osImage => 'Ubuntu 24.04.5 LTS', systemUUID => 'u',
            },
        },
    });
}

sub status_of {
    my ($cfg, %o) = @_;
    my $k8s = OCP::Kubernetes->new(api => Local::StatusApi->new(nodes => [ k8s_node('police1') ]));
    my $cmd = OCP::Cmd::Status->new(($o{json} ? (json => 1) : ()),
        command_chain => [ Local::FakeOCP->new(config => $cfg) ]);
    no warnings 'redefine';
    local *OCP::Secrets::new                   = sub { Local::FakeSecrets->new };
    local *OCP::Cmd::Status::reach_cluster_api = sub { $_[1] };
    local *OCP::Kubernetes::new                = sub { $k8s };
    local *OCP::Drift::detect                  = sub { [] };
    local *OCP::Cmd::Status::rex_prober        = sub { undef };
    return capture { $cmd->execute([], []) };
}

my $SET = { gpu => { toolkit => JSON::PP::false, amd => { integrated => JSON::PP::true } } };

subtest 'status: the Spec section says the values, and that they are set at install' => sub {
    my $r = status_of(project(spec => $SET));
    is $r->{rv}, 0, 'exit 0';
    like $r->{out}, qr/^=== Spec ===\n(?:.*\n)*?GPU, set at install: toolkit false, amd\.integrated true\n  a joined worker takes a change only when joined again, a control plane never\n\n=== Status ===$/m,
        'in the Spec section, as ocp.yaml has them, with what a change reaches';
    is $r->{err}, '', 'nothing on STDERR: it is the report';

    my $default = status_of(project());
    like $default->{out}, qr/^GPU, set at install: toolkit true, amd\.integrated false$/m, 'the defaults, without a gpu: block';

    my $off = status_of(project(spec => { gpu => { enabled => JSON::PP::false } }));
    unlike $off->{out}, qr/set at install/, 'gpu.enabled false: no node gets either, nothing said';

    my $fresh = status_of(project(spec => $SET, deployed => 0));
    like $fresh->{out}, qr/No cluster deployed yet/, 'not deployed';
    unlike $fresh->{out}, qr/set at install/, '... no node has joined: nothing said';
};

subtest 'status --json: spec.gpu, under the same rule' => sub {
    my $r = status_of(project(spec => $SET), json => 1);
    my $d = eval { decode_json($r->{out}) } or return fail 'STDOUT is JSON: ' . $r->{out};
    is_deeply $d->{spec}{gpu}, { toolkit => JSON::MaybeXS::false(), amd_integrated => JSON::MaybeXS::true() },
        'toolkit and amd_integrated, as ocp.yaml has them';
    ok JSON::MaybeXS::is_bool($d->{spec}{gpu}{$_}), "$_ is a JSON boolean" for qw( toolkit amd_integrated );

    for my $case ([ 'gpu.enabled false' => project(spec => { gpu => { enabled => JSON::PP::false } }) ],
                  [ 'not deployed'      => project(spec => $SET, deployed => 0) ]) {
        my ($what, $cfg) = @$case;
        my $o = decode_json(status_of($cfg, json => 1)->{out});
        ok !exists $o->{spec}{gpu}, "$what: no spec.gpu";
    }
};

done_testing;

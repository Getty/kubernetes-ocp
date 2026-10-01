#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use Path::Tiny qw(path);
use File::Temp qw(tempdir);

use lib 'lib';

#
# k223: with gpu.toolkit: false the GPU Operator runs no toolkit DaemonSet
# (ClusterPolicy toolkit.enabled=false, so it is in the CitiAI lab for the
# GB10), and with it goes the only thing that wrote CDI specs. Live on GB10
# "brain" (2026-10-01, nvidia-cdi-refresh disabled) /run/cdi was empty after a
# reboot, the operator validator died on management.nvidia.com/gpu=all and the
# node never got nvidia.com/gpu. Rex::GPU::NVIDIA::generate_cdi_specs (rex-gpu
# k76) writes what does not resolve -- but the Rexfile never called it, and
# gpu.toolkit reached the ClusterPolicy and no machine.
#
# This file holds the channel: gpu.toolkit travels like gpu.enabled /
# gpu.driver (k31) and system: (k217) -- onto the OCPNodeProvider CR as
# spec.gpu.toolkit, back off it with OCP::Provider->gpu_flags_from_cr, through
# all three callers of OCP::Node->from_cr into the join's install task, and
# from the bootstrap straight through OCP::Rex. Absent means toolkit true, the
# behaviour before. What the Rexfile does with it is t/44-gpu-detect.t.
#

use OCP::Provider;
use OCP::Node;
use OCP::Config;
use OCP::Rex;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Node::Add;
use OCP::Robocop::Controller;

sub project {
    my ($extra) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(
        "name: k223\ncontrol_planes:\n  provider: ssh\n  host: cp.example\n$extra");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my $NO_TOOLKIT = "gpu:\n  toolkit: false\n";

sub quiet (&) {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die;
    my $old = select $fh;
    my @r = eval { $code->() };
    my $err = $@;
    select $old;
    die $err if $err;
    return wantarray ? @r : $r[0];
}

{
    package RecordingApi;
    sub new    { bless { ensured => [] }, shift }
    sub ensure { push @{ $_[0]{ensured} }, $_[1]; $_[1] }
}

sub provider_cr_for {
    my ($config) = @_;
    my $api = RecordingApi->new;
    quiet { OCP::Cmd::Apply::CR::ensure_provider_cr(undef, $api, 'ssh', 'ocp-system', $config, undef) };
    my ($cr) = grep { $_->{kind} eq 'OCPNodeProvider' } @{ $api->{ensured} };
    return $cr;
}

#
# 1. ocp apply writes spec.gpu.toolkit.
#
subtest 'ensure_provider_cr copies gpu.toolkit onto the provider CR' => sub {
    my $cr = provider_cr_for(project($NO_TOOLKIT));
    ok $cr, 'a provider CR was written' or return;
    ok exists $cr->{spec}{gpu}{toolkit}, 'spec.gpu.toolkit is there' or return;
    ok JSON::PP::is_bool($cr->{spec}{gpu}{toolkit}), 'as a JSON boolean (CRD type: boolean)';
    ok !$cr->{spec}{gpu}{toolkit}, 'false, as ocp.yaml says';

    $cr = provider_cr_for(project(''));
    ok JSON::PP::is_bool($cr->{spec}{gpu}{toolkit}) && $cr->{spec}{gpu}{toolkit},
        'without a gpu: block: true, the same default the ClusterPolicy gets';
};

#
# 2. The CRD declares it (else the API server prunes it).
#
subtest 'the OCPNodeProvider CRD declares spec.gpu.toolkit' => sub {
    require YAML::XS;
    my $crd = YAML::XS::LoadFile('share/robocop/crds/ocpnodeprovider.yaml');
    my $gpu = $crd->{spec}{versions}[0]{schema}{openAPIV3Schema}{properties}{spec}{properties}{gpu};
    is $gpu->{properties}{toolkit}{type}, 'boolean', 'toolkit: boolean';
    ok !exists $gpu->{properties}{toolkit}{default},
        'no schema default: a CR written before the field must read as absent';
};

#
# 3. The parse.
#
subtest 'gpu_flags_from_cr reads gpu_toolkit' => sub {
    my %f = OCP::Provider->gpu_flags_from_cr({ spec => { gpu => {
        enabled => JSON::PP::true, driver => 'host', toolkit => JSON::PP::false } } });
    is_deeply \%f, { gpu_enabled => 1, gpu_driver => 'host', gpu_toolkit => 0 },
        'toolkit as 0/1 next to the other two';
    %f = OCP::Provider->gpu_flags_from_cr({ spec => { gpu => { toolkit => JSON::PP::true } } });
    is $f{gpu_toolkit}, 1, 'true is 1';
    %f = OCP::Provider->gpu_flags_from_cr({ spec => { gpu => { enabled => JSON::PP::true } } });
    ok !exists $f{gpu_toolkit}, 'a CR predating the field gives no gpu_toolkit';
};

#
# 4. OCP::Node hands it to the install task.
#
{
    package FakeRex;
    our @calls;
    sub new      { bless {}, shift }
    sub run_task { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 }
}
{
    package FakeSSH;
    sub new          { bless {}, shift }
    sub wait_for_ssh { 1 }
}
{
    package FakeProvider;
    sub new              { bless {}, shift }
    sub create_server    { { id => 'S1', ip => '1.2.3.4' } }
    sub wait_for_running { $_[1] }
}
{
    package Anything;
    sub new { bless {}, shift }
}

sub install_params {
    my (%flags) = @_;
    no warnings 'redefine', 'once';
    local *OCP::Versions::get_component_version = sub { 'v9.9.9' };
    local *OCP::K8s::patch_status = sub { return };
    @FakeRex::calls = ();
    my $node = OCP::Node->from_cr({
            apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => 'w1', namespace => 'ocp-system', resourceVersion => '1' },
            spec     => { role => 'worker', providerRef => 'ssh-default' },
            status   => { phase => 'Installing', publicIP => '1.2.3.4' },
        },
        k8s => Anything->new, provider => FakeProvider->new,
        ssh_key => 'KEY', server_url => 'https://cp:9345', join_token => 'TOKEN',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
        %flags,
    );
    $node->_install_kubernetes;
    return $FakeRex::calls[0][1];
}

subtest 'OCP::Node passes gpu_toolkit to the join' => sub {
    my $p = install_params(gpu_toolkit => 0);
    ok $p, 'the install task ran' or return;
    ok exists $p->{gpu_toolkit} && $p->{gpu_toolkit} eq '0', 'toolkit false reaches the task as 0';

    $p = install_params(gpu_toolkit => 1);
    is $p->{gpu_toolkit}, 1, 'toolkit true as 1';

    $p = install_params();
    ok !exists $p->{gpu_toolkit}, 'nothing passed: the Rexfile default (toolkit true) decides';
};

#
# 5. Every from_cr caller reads it off the provider CR.
#
my $PROVIDER = {
    apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
    metadata   => { name => 'ssh-default', namespace => 'ocp-system' },
    spec       => { type => 'ssh', gpu => {
        enabled => JSON::PP::true, driver => 'host', toolkit => JSON::PP::false } },
};
{
    package FakeApi;
    sub new  { bless {}, shift }
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }
    sub patch_status { 1 }
    sub patch { 1 }
    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? $rest[0] : {@rest}->{name};
        return { metadata => { name => $name, namespace => 'ocp-system' },
                 spec => { role => 'worker', providerRef => 'ssh-default' }, status => {} }
            if $kind eq 'OCPNode';
        return $PROVIDER if $kind eq 'OCPNodeProvider';
        return undef;
    }
}
{
    package FakeNode;
    sub reconcile_until_ready { 1 }
    sub reconcile { 1 }
    sub phase { 'Ready' }
    sub name  { 'w1' }
    sub cr    { { status => {} } }
}
{
    package FakeOcp;
    sub new     { bless {}, shift }
    sub verbose { 0 }
}
{
    package FakeSecrets;
    sub new             { bless {}, shift }
    sub read_kubeconfig { undef }
}

sub from_cr_deps (&) {
    my ($run) = @_;
    my @deps;
    no warnings 'redefine';
    local *OCP::Node::from_cr     = sub { my ($c, $cr, %d) = @_; push @deps, \%d; bless {}, 'FakeNode' };
    local *OCP::Provider::from_cr = sub { bless {}, 'FakeProvider' };
    local *OCP::SSH::new = sub { bless {}, $_[0] };
    local *OCP::SSH::run = sub { { stdout => "K10::token\n", stderr => '', exit => 0 } };
    my ($out, $err) = ('', '');
    {
        open my $ofh, '>', \$out or die;
        open my $efh, '>', \$err or die;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $run->();
    }
    return @deps;
}

sub has_toolkit_off {
    my ($d, $what) = @_;
    ok exists $d->{gpu_toolkit}, "$what: gpu_toolkit handed to OCP::Node" or return;
    is $d->{gpu_toolkit}, 0, "$what: as 0";
}

subtest 'ocp apply (CLI path)' => sub {
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    my @deps = from_cr_deps {
        OCP::Cmd::Apply::CR::cli_reconcile_workers($apply, FakeApi->new, project(''),
            [ 'worker-1' ],
            { ssh_key_path => '/nonexistent', cp_ip => '1.2.3.4', secrets => FakeSecrets->new });
    };
    ok @deps, 'a node was built' or return;
    has_toolkit_off($deps[0], 'apply');
};

subtest 'ocp node add (CLI path)' => sub {
    {
        package FakeAddConfig;
        sub new            { bless {}, shift }
        sub cluster_status { {} }
        sub distribution   { 'rke2' }
        sub pod_cidr       { '10.42.0.0/16' }
    }
    my $add = OCP::Cmd::Node::Add->new(k8s => FakeApi->new, name => 'worker-9');
    my @deps = from_cr_deps {
        $add->_cli_reconcile({ metadata => { name => 'worker-9', namespace => 'ocp-system' },
                               spec => { role => 'worker', providerRef => 'ssh-default' } },
            FakeApi->new, FakeAddConfig->new, FakeSecrets->new);
    };
    ok @deps, 'a node was built' or return;
    has_toolkit_off($deps[0], 'node add');
};

subtest 'robocop' => sub {
    my $ctrl = OCP::Robocop::Controller->new(
        ssh_key => 'K', server_url => 'U', join_token => 'T',
        distribution => 'rke2', pod_cidr => '10.42.0.0/16', kube => FakeApi->new,
    );
    my @deps = from_cr_deps {
        $ctrl->_on_node_event({ apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => 'w1', namespace => 'ocp-system', resourceVersion => '1',
                          finalizers => [ OCP::Node::TEARDOWN_FINALIZER ] },
            spec => { role => 'worker', providerRef => 'ssh-default' },
            status => { phase => 'Pending' } });
    };
    ok @deps, 'a node was built' or return;
    has_toolkit_off($deps[0], 'robocop');
};

#
# 6. The control plane: bootstrap -> OCP::Rex -> install task.
#
subtest 'OCP::Rex passes gpu_toolkit to the install tasks' => sub {
    my $tmp = path(tempdir(CLEANUP => 1));
    my $key = $tmp->child('id'); $key->spew('k'); path("$key.pub")->spew('k');

    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 };
    local *OCP::Rex::fetch_kubeconfig_ssh   = sub { "apiVersion: v1\n" };
    local *OCP::Rex::_existing_server_token = sub { undef };

    my $rex = OCP::Rex->new(host => '127.0.0.1', key_file => $key->stringify);
    for my $case ([ [ gpu_toolkit => 0 ], 0 ], [ [ gpu_toolkit => 1 ], 1 ], [ [], 1 ]) {
        my ($in, $want) = @$case;
        my $label = @$in ? "gpu_toolkit => $in->[1]" : 'nothing passed';

        @calls = ();
        $rex->install_server(distribution => 'rke2', version => 'v1', @$in);
        my ($server) = grep { $_->[0] eq 'install_rke2_server' } @calls;
        is $server->[1]{gpu_toolkit}, $want, "install_server, $label: gpu_toolkit $want";

        @calls = ();
        $rex->install_agent(distribution => 'rke2', server => 'https://cp:9345', token => 't', @$in);
        my ($agent) = grep { $_->[0] eq 'install_rke2_agent' } @calls;
        is $agent->[1]{gpu_toolkit}, $want, "install_agent, $label: gpu_toolkit $want";
    }
};

subtest 'the bootstrap hands install_server the configured gpu.toolkit' => sub {
    my $boot = path('lib/OCP/Cmd/Apply/Bootstrap.pm')->slurp_utf8;
    my ($call) = $boot =~ /(\$rex->install_server\(.*?\);)/s;
    like $call, qr/gpu_toolkit\s*=>\s*\$config->gpu_toolkit/, 'gpu_toolkit => $config->gpu_toolkit';
};

done_testing;

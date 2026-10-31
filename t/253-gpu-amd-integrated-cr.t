#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use Path::Tiny qw(path);
use File::Temp qw(tempdir);

use lib 'lib';

#
# k253: gpu.amd.integrated cluster-wide. The Rexfile sets up an integrated AMD
# GPU (a Ryzen iGPU or APU) only when its gpu_amd_integrated parameter is true
# (k249), and OCP::Node passes it for a node joined with `ocp node add --gpu`
# or under its gpu_amd_integrated attribute (k250, t/250). Nothing set that
# attribute and the bootstrap passed nothing, so ocp.yaml's
# gpu.amd.integrated: true reached no node -- while install_amd's skip line
# told the user to set it.
#
# This file holds the channel, the one gpu.toolkit takes (k223, t/223): onto
# the OCPNodeProvider CR as spec.gpu.amd.integrated, back off it with
# OCP::Provider->gpu_flags_from_cr, through all three callers of
# OCP::Node->from_cr into the join's install task, and from the bootstrap
# straight through OCP::Rex. Absent means false, the k250 default, and a CR an
# older ocp wrote without the field reads as absent, not as an error. What the
# Rexfile does with the parameter is t/249.
#

use OCP;
use OCP::Provider;
use OCP::Node;
use OCP::Config;
use OCP::Rex;
use OCP::Secrets;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Node::Add;
use OCP::Robocop::Controller;

sub project {
    my ($extra) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    $dir->child('ocp.yaml')->spew_utf8(
        "name: k253\ncontrol_planes:\n  provider: ssh\n  host: cp.example\n$extra");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my $INTEGRATED     = "gpu:\n  amd:\n    integrated: true\n";
my $NOT_INTEGRATED = "gpu:\n  amd:\n    integrated: false\n";

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
# 1. ocp apply writes spec.gpu.amd.integrated.
#
subtest 'ensure_provider_cr copies gpu.amd.integrated onto the provider CR' => sub {
    my $cr = provider_cr_for(project($INTEGRATED));
    ok $cr, 'a provider CR was written' or return;
    my $amd = $cr->{spec}{gpu}{amd};
    ok ref $amd eq 'HASH' && exists $amd->{integrated}, 'spec.gpu.amd.integrated is there' or return;
    ok JSON::PP::is_bool($amd->{integrated}), 'as a JSON boolean (CRD type: boolean)';
    ok $amd->{integrated}, 'true, as ocp.yaml says';
    is_deeply [ sort keys %$amd ], [ 'integrated' ],
        'only integrated: the other gpu.amd keys shape the cluster stack, not a node install';
    ok exists $cr->{spec}{gpu}{$_}, "spec.gpu.$_ is still written next to it"
        for qw( enabled driver toolkit );

    for my $case ([ 'gpu.amd.integrated: false' => $NOT_INTEGRATED ], [ 'no gpu: block' => '' ]) {
        my ($what, $yaml) = @$case;
        my $off = provider_cr_for(project($yaml))->{spec}{gpu}{amd};
        ok ref $off eq 'HASH' && JSON::PP::is_bool($off->{integrated}) && !$off->{integrated},
            "$what: written as false, the k250 default";
    }
};

#
# 2. The CRD declares it (else the API server prunes it).
#
subtest 'the OCPNodeProvider CRD declares spec.gpu.amd.integrated' => sub {
    require YAML::XS;
    my $crd = YAML::XS::LoadFile('share/robocop/crds/ocpnodeprovider.yaml');
    my $gpu = $crd->{spec}{versions}[0]{schema}{openAPIV3Schema}{properties}{spec}{properties}{gpu};
    my $amd = $gpu->{properties}{amd};
    is $amd->{type}, 'object', 'spec.gpu.amd: object' or return;
    ok !exists $amd->{default}, 'with no schema default';
    is $amd->{properties}{integrated}{type}, 'boolean', 'spec.gpu.amd.integrated: boolean';
    ok !exists $amd->{properties}{integrated}{default},
        'no schema default: a CR written before the field must read as absent';
};

#
# 3. The parse, and the round trip apply -> robocop.
#
subtest 'gpu_flags_from_cr reads gpu_amd_integrated' => sub {
    my %f = OCP::Provider->gpu_flags_from_cr({ spec => { gpu => {
        enabled => JSON::PP::true, driver => 'host', toolkit => JSON::PP::true,
        amd => { integrated => JSON::PP::true } } } });
    is_deeply \%f, { gpu_enabled => 1, gpu_driver => 'host', gpu_toolkit => 1, gpu_amd_integrated => 1 },
        'integrated as 0/1 next to the other three';

    %f = OCP::Provider->gpu_flags_from_cr({ spec => { gpu => { amd => { integrated => JSON::PP::false } } } });
    ok exists $f{gpu_amd_integrated} && $f{gpu_amd_integrated} eq '0', 'false is 0';

    for my $case (
        [ 'a CR from before the field'  => { gpu => { enabled => JSON::PP::true, driver => 'host',
                                                       toolkit => JSON::PP::true } } ],
        [ 'spec.gpu.amd without it'     => { gpu => { amd => {} } } ],
        [ 'no spec.gpu at all'          => { type => 'ssh' } ],
    ) {
        my ($what, $spec) = @$case;
        my %flags = eval { OCP::Provider->gpu_flags_from_cr({ spec => $spec }) };
        is $@, '', "$what: read without an error";
        ok !exists $flags{gpu_amd_integrated}, "$what: no gpu_amd_integrated";
    }

    %f = OCP::Provider->gpu_flags_from_cr(provider_cr_for(project($INTEGRATED)));
    is $f{gpu_amd_integrated}, 1, 'what ocp apply writes, gpu_flags_from_cr reads back';
};

#
# 4. OCP::Node hands it to the install task -- worker and control plane.
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

sub install_call {
    my ($role, %flags) = @_;
    no warnings 'redefine', 'once';
    local *OCP::Versions::get_component_version = sub { 'v9.9.9' };
    local *OCP::K8s::patch_status = sub { return };
    @FakeRex::calls = ();
    my $node = OCP::Node->from_cr({
            apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => 'n1', namespace => 'ocp-system', resourceVersion => '1' },
            spec     => { role => $role, providerRef => 'ssh-default' },
            status   => { phase => 'Installing', publicIP => '1.2.3.4' },
        },
        k8s => Anything->new, provider => FakeProvider->new,
        ssh_key => 'KEY', server_url => 'https://cp:9345', join_token => 'TOKEN',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
        %flags,
    );
    $node->_install_kubernetes;
    return $FakeRex::calls[0];
}

subtest 'the provider CR\'s gpu.amd.integrated reaches the join of a node without --gpu' => sub {
    my %on  = OCP::Provider->gpu_flags_from_cr(provider_cr_for(project($INTEGRATED)));
    my %off = OCP::Provider->gpu_flags_from_cr(provider_cr_for(project('')));
    my %old = OCP::Provider->gpu_flags_from_cr({ spec => { gpu => {
        enabled => JSON::PP::true, driver => 'host', toolkit => JSON::PP::true } } });

    for my $c ([ worker => 'install_rke2_agent' ], [ 'control-plane' => 'install_rke2_server' ]) {
        my ($role, $task) = @$c;
        my $call = install_call($role, %on);
        ok $call, "$role: the install task ran" or next;
        is $call->[0], $task, "$role: $task";
        is $call->[1]{gpu_amd_integrated}, 1, "$role: gpu.amd.integrated: true opens the gate";

        $call = install_call($role, %off);
        ok !exists $call->[1]{gpu_amd_integrated}, "$role: gpu.amd.integrated: false passes nothing";

        $call = install_call($role, %old);
        ok !exists $call->[1]{gpu_amd_integrated},
            "$role: a CR from before the field passes nothing -- the Rexfile default (0) decides";
    }
};

#
# 5. Every from_cr caller reads it off the provider CR.
#
our $AMD_INTEGRATED = 1;
sub provider {
    return {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
        metadata   => { name => 'ssh-default', namespace => 'ocp-system' },
        spec       => { type => 'ssh', gpu => {
            enabled => JSON::PP::true, driver => 'host', toolkit => JSON::PP::false,
            ($AMD_INTEGRATED ? (amd => { integrated => JSON::PP::true }) : ()) } },
    };
}
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
        return main::provider() if $kind eq 'OCPNodeProvider';
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
    sub lease_conflict { undef }
    sub host_key_mismatch { undef }
}
{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}
{
    package FakeSecrets;
    sub new             { bless {}, shift }
    sub read_kubeconfig { undef }
}
{
    package FakeAddConfig;
    sub new            { bless {}, shift }
    sub cluster_status { {} }
    sub distribution   { 'rke2' }
    sub pod_cidr       { '10.42.0.0/16' }
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

my %CALLER = (
    'ocp apply (CLI path)' => sub {
        my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
        from_cr_deps {
            OCP::Cmd::Apply::CR::cli_reconcile_workers($apply, FakeApi->new, project(''),
                [ 'worker-1' ],
                { ssh_key_path => '/nonexistent', cp_ip => '1.2.3.4', secrets => FakeSecrets->new });
        };
    },
    'ocp node add (CLI path)' => sub {
        my $add = OCP::Cmd::Node::Add->new(k8s => FakeApi->new, name => 'worker-9');
        from_cr_deps {
            $add->_cli_reconcile({ metadata => { name => 'worker-9', namespace => 'ocp-system' },
                                   spec => { role => 'worker', providerRef => 'ssh-default' } },
                FakeApi->new, FakeAddConfig->new, FakeSecrets->new);
        };
    },
    'robocop' => sub {
        my $ctrl = OCP::Robocop::Controller->new(
            ssh_key => 'K', server_url => 'U', join_token => 'T',
            distribution => 'rke2', pod_cidr => '10.42.0.0/16', kube => FakeApi->new,
        );
        from_cr_deps {
            $ctrl->_on_node_event({ apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
                metadata => { name => 'w1', namespace => 'ocp-system', resourceVersion => '1',
                              finalizers => [ OCP::Node::TEARDOWN_FINALIZER ] },
                spec => { role => 'worker', providerRef => 'ssh-default' },
                status => { phase => 'Pending' } });
        };
    },
);

for my $what (sort keys %CALLER) {
    subtest $what => sub {
        local $AMD_INTEGRATED = 1;
        my @deps = $CALLER{$what}->();
        ok @deps, 'a node was built' or return;
        is $deps[0]{gpu_amd_integrated}, 1, 'gpu_amd_integrated 1 handed to OCP::Node';
        is $deps[0]{gpu_toolkit}, 0, 'next to gpu_toolkit, which it took before (k223)';

        local $AMD_INTEGRATED = 0;
        @deps = $CALLER{$what}->();
        ok @deps, 'a provider CR from before the field: a node was still built' or return;
        ok !exists $deps[0]{gpu_amd_integrated}, 'and no gpu_amd_integrated handed to it';
    };
}

#
# 6. The control plane: bootstrap -> OCP::Rex -> install task.
#
subtest 'OCP::Rex passes gpu_amd_integrated to the install tasks' => sub {
    my $tmp = path(tempdir(CLEANUP => 1));
    my $key = $tmp->child('id'); $key->spew('k'); path("$key.pub")->spew('k');

    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 };
    local *OCP::Rex::fetch_kubeconfig_ssh   = sub { "apiVersion: v1\n" };
    local *OCP::Rex::_existing_server_token = sub { undef };

    my $rex = OCP::Rex->new(host => '127.0.0.1', key_file => $key->stringify);
    for my $case ([ [ gpu_amd_integrated => 1 ], 1 ], [ [ gpu_amd_integrated => 0 ], 0 ], [ [], 0 ]) {
        my ($in, $want) = @$case;
        my $label = @$in ? "gpu_amd_integrated => $in->[1]" : 'nothing passed';

        @calls = ();
        $rex->install_server(distribution => 'rke2', version => 'v1', @$in);
        my ($server) = grep { $_->[0] eq 'install_rke2_server' } @calls;
        ok $server && exists $server->[1]{gpu_amd_integrated}, "install_server, $label: passed on";
        is $server->[1]{gpu_amd_integrated}, $want, "install_server, $label: gpu_amd_integrated $want";

        @calls = ();
        $rex->install_agent(distribution => 'rke2', server => 'https://cp:9345', token => 't', @$in);
        my ($agent) = grep { $_->[0] eq 'install_rke2_agent' } @calls;
        ok $agent && exists $agent->[1]{gpu_amd_integrated}, "install_agent, $label: passed on";
        is $agent->[1]{gpu_amd_integrated}, $want, "install_agent, $label: gpu_amd_integrated $want";
    }
};

# The bootstrap with every machine-touching layer faked, as t/185 runs it.
{
    package FakeProv;
    sub new { bless {}, $_[0] }
    sub upload_ssh_key     { }
    sub server_exists      { { ip => 'cp.example', newly_created => 0 } }
    sub create_server      { { ip => 'cp.example', newly_created => 0 } }
    sub wait_for_running   { $_[1] }
    sub advertised_host    { my ($s, %o) = @_; $o{host} }
    sub cleanup_on_failure { }
}
{ package FakeCond;     sub new { bless { t => $_[1], s => $_[2] }, $_[0] } sub type { $_[0]{t} } sub status { $_[0]{s} } }
{ package FakeStatus;   sub conditions { [ FakeCond->new('Ready', 'True') ] } }
{ package FakeNodeObj;  sub status { bless {}, 'FakeStatus' } }
{ package FakeNodeList; sub items { [ bless {}, 'FakeNodeObj' ] } }
{
    package FakeBootApi;
    sub _request { 1 }
    sub list     { bless {}, 'FakeNodeList' }
}

sub bootstrap_server_opts {
    my ($config) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new(config => $config) ]);
    my %server_opts;
    my $err = '';
    quiet {
        eval {
            no warnings 'redefine';
            local *OCP::Provider::for_spec       = sub { FakeProv->new };
            local *OCP::Cmd::Apply::_k8s_api     = sub { bless {}, 'FakeBootApi' };
            local *OCP::Secrets::save_kubeconfig = sub { 1 };
            local *OCP::Secrets::ensure_age_key  = sub { 1 };
            local *OCP::SSH::new                 = sub { bless {}, 'OCP::SSH' };
            local *OCP::SSH::wait_for_ssh        = sub { 1 };
            local *OCP::SSH::run                 = sub { { stdout => 'Ready' } };
            local *OCP::Rex::new                 = sub { bless {}, 'OCP::Rex' };
            local *OCP::Rex::install_server      = sub { shift; %server_opts = @_; { kubeconfig => "apiVersion: v1\n" } };
            OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
                $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
                admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
            );
            1;
        } or $err = $@;
    };
    return ($err, \%server_opts);
}

subtest 'the bootstrap hands install_server the configured gpu.amd.integrated' => sub {
    my ($err, $opts) = bootstrap_server_opts(project($INTEGRATED));
    is $err, '', 'bootstrap ran to completion' or return;
    is $opts->{gpu_amd_integrated}, 1, 'gpu.amd.integrated: true reaches police1\'s install';

    ($err, $opts) = bootstrap_server_opts(project(''));
    is $err, '', 'bootstrap ran to completion without a gpu: block' or return;
    ok !$opts->{gpu_amd_integrated}, 'without it: false, the k250 default';
};

done_testing;

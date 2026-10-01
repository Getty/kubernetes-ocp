#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use Path::Tiny qw(path);
use File::Temp qw(tempdir);

use lib 'lib';

#
# k217: ocp.yaml's system: block (timezone, locale, ntp) reached the control
# plane's prepare_node and no other machine. OCP::Node built a worker's join
# parameters without them, so the Rexfile fell back to UTC / en_US.UTF-8: live
# on ocpt (2026-10-01) the control plane came up Europe/Berlin + de_DE.UTF-8
# and its worker was switched to UTC / en_US.
#
# The channel is the one k31 built for gpu.enabled / gpu.driver, for the same
# reason: robocop never sees ocp.yaml. `ocp apply` copies the three values onto
# the OCPNodeProvider CR (spec.system), OCP::Provider->system_flags_from_cr
# reads them back, and all three callers of OCP::Node->from_cr -- robocop, the
# apply CLI path, `ocp node add` -- hand them to OCP::Node, which passes them to
# the install task. A provider CR that predates the field passes nothing and
# the Rexfile's defaults stay in charge, as before.
#

use OCP::Provider;
use OCP::Node;
use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Node::Add;
use OCP::Robocop::Controller;

sub project {
    my ($system) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(
        "name: k217\ncontrol_planes:\n  provider: ssh\n  host: cp.example\n$system");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my $BERLIN = "system:\n  timezone: Europe/Berlin\n  locale: de_DE.UTF-8\n  ntp: false\n";

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

#
# 1. ocp apply writes spec.system.
#
subtest 'ensure_provider_cr copies ocp.yaml system: onto the provider CR' => sub {
    my $api = RecordingApi->new;
    quiet { OCP::Cmd::Apply::CR::ensure_provider_cr(undef, $api, 'ssh', 'ocp-system', project($BERLIN), undef) };
    my ($cr) = grep { $_->{kind} eq 'OCPNodeProvider' } @{ $api->{ensured} };
    ok $cr, 'a provider CR was written' or return;
    is $cr->{spec}{system}{timezone}, 'Europe/Berlin', 'timezone';
    is $cr->{spec}{system}{locale},   'de_DE.UTF-8',   'locale';
    ok JSON::PP::is_bool($cr->{spec}{system}{ntp}), 'ntp is a JSON boolean (CRD type: boolean)';
    ok !$cr->{spec}{system}{ntp}, 'ntp false';

    $api = RecordingApi->new;
    quiet { OCP::Cmd::Apply::CR::ensure_provider_cr(undef, $api, 'ssh', 'ocp-system', project(''), undef) };
    ($cr) = grep { $_->{kind} eq 'OCPNodeProvider' } @{ $api->{ensured} };
    is_deeply [ @{ $cr->{spec}{system} }{qw(timezone locale)} ], [ 'UTC', 'en_US.UTF-8' ],
        'without a system: block, the same defaults the control plane gets';
    ok $cr->{spec}{system}{ntp}, 'ntp defaults to true';
};

#
# 2. The CRD declares it (else the API server prunes it).
#
subtest 'the OCPNodeProvider CRD declares spec.system' => sub {
    require YAML::XS;
    my $crd = YAML::XS::LoadFile('share/robocop/crds/ocpnodeprovider.yaml');
    my $sys = $crd->{spec}{versions}[0]{schema}{openAPIV3Schema}{properties}{spec}{properties}{system};
    ok $sys, 'spec.system exists' or return;
    is $sys->{properties}{timezone}{type}, 'string',  'timezone: string';
    is $sys->{properties}{locale}{type},   'string',  'locale: string';
    is $sys->{properties}{ntp}{type},      'boolean', 'ntp: boolean';
};

#
# 3. The parse.
#
subtest 'system_flags_from_cr' => sub {
    my %f = OCP::Provider->system_flags_from_cr({ spec => { system => {
        timezone => 'Europe/Berlin', locale => 'de_DE.UTF-8', ntp => JSON::PP::false } } });
    is_deeply \%f, { timezone => 'Europe/Berlin', locale => 'de_DE.UTF-8', ntp => 0 },
        'values through, ntp as 0/1';
    my %none = OCP::Provider->system_flags_from_cr({ spec => { type => 'ssh' } });
    is_deeply \%none, {}, 'a CR predating the field gives nothing';
};

#
# 4. OCP::Node hands them to the install task.
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

subtest 'OCP::Node passes timezone/locale/ntp to the join' => sub {
    my $p = install_params(timezone => 'Europe/Berlin', locale => 'de_DE.UTF-8', ntp => 0);
    ok $p, 'the install task ran' or return;
    is $p->{timezone}, 'Europe/Berlin', 'timezone';
    is $p->{locale},   'de_DE.UTF-8',   'locale';
    is $p->{ntp},      0,               'ntp';

    $p = install_params();
    ok !exists $p->{timezone} && !exists $p->{locale},
        'nothing passed: the Rexfile defaults decide, as before';
    is $p->{ntp}, 1, 'ntp stays on by default';
};

#
# 5. Every from_cr caller reads them off the provider CR.
#
my $PROVIDER = {
    apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
    metadata   => { name => 'ssh-default', namespace => 'ocp-system' },
    spec       => { type => 'ssh', system => {
        timezone => 'Europe/Berlin', locale => 'de_DE.UTF-8', ntp => JSON::PP::true } },
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

sub has_system {
    my ($d, $what) = @_;
    is $d->{timezone}, 'Europe/Berlin', "$what: timezone";
    is $d->{locale},   'de_DE.UTF-8',   "$what: locale";
    is $d->{ntp},      1,               "$what: ntp";
}

subtest 'ocp apply (CLI path)' => sub {
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    my @deps = from_cr_deps {
        OCP::Cmd::Apply::CR::cli_reconcile_workers($apply, FakeApi->new, project(''),
            [ 'worker-1' ],
            { ssh_key_path => '/nonexistent', cp_ip => '1.2.3.4', secrets => FakeSecrets->new });
    };
    ok @deps, 'a node was built' or return;
    has_system($deps[0], 'apply');
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
    has_system($deps[0], 'node add');
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
    has_system($deps[0], 'robocop');
};

done_testing;

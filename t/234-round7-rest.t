#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::ClusterKey;
use OCP::Config;
use OCP::Drift;
use OCP::Rex;

#
# k234, rest of lab round 7 (2026-10-16):
#   29 robocop from before SIGTERM handling is retired with a short grace
#   32 the legacy-template probe covers the workers OCP can reach
#   33 secure mode without PIN2: the probes use the robo key, or say they skipped
# (28, 30, 31, 34 run through the reconcile harness in t/38; 35 in t/54; 36 in t/230.)
#

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeResp { sub new { bless { status => $_[1] }, $_[0] } sub status { $_[0]{status} } }
package FakeApi {
    sub new  { my ($c, %a) = @_; bless { %a, requests => [] }, $c }
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }
    sub list {
        my ($s, $kind) = @_;
        return FakeList->new($kind eq 'Pod' ? $s->{pods} : $s->{ocpnodes});
    }
    sub _request {
        my ($s, $method, $path, $body, %o) = @_;
        push @{ $s->{requests} }, { method => $method, path => $path, %o };
        return FakeResp->new($s->{status} // 200);
    }
}
package main;

sub config_for {
    my ($yaml) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew($yaml);
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my $CFG = "name: lab\ncontrol_planes:\n  provider: ssh\n  host: cp.lab.example\n";

sub capture {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    { local *STDOUT = $o; local *STDERR = $e; $code->(); }
    return ($out, $err);
}

subtest '29: the Deployment template carries the SIGTERM annotation' => sub {
    my @docs = YAML::XS::LoadFile('share/robocop/deployment.yaml');
    my ($dep) = grep { ($_->{kind} // '') eq 'Deployment' } @docs;
    is $dep->{spec}{template}{metadata}{annotations}{'ocp.internal/robocop-sigterm'}, '1',
        'on the pod template, where the pods inherit it';
};

subtest '29: pods without the annotation are deleted with a 30 s grace period' => sub {
    my $api = FakeApi->new(pods => [
        { metadata => { name => 'robocop-old' } },
        { metadata => { name => 'robocop-old2', annotations => { other => 'x' } } },
        { metadata => { name => 'robocop-new', annotations => { 'ocp.internal/robocop-sigterm' => '1' } } },
    ]);
    my ($out, $err) = capture(sub { OCP::Cmd::Apply::CR::retire_unannotated_robocop_pods(undef, $api) });
    is_deeply [ map { $_->{path} } @{ $api->{requests} } ],
        [ '/api/v1/namespaces/ocp-system/pods/robocop-old', '/api/v1/namespaces/ocp-system/pods/robocop-old2' ],
        'exactly the pods without the annotation';
    is $_->{method}, 'DELETE', 'DELETE' for @{ $api->{requests} };
    is $_->{parameters}{gracePeriodSeconds}, 30, 'grace period 30 s' for @{ $api->{requests} };
    like $out, qr/^  \[\.\.\] robocop pod robocop-old predates SIGTERM handling; deleted with a 30 s grace period/m,
        'one line on STDOUT per pod';
    is $err, '', 'nothing on STDERR';

    my $done = FakeApi->new(pods => [
        { metadata => { name => 'robocop-new', annotations => { 'ocp.internal/robocop-sigterm' => '1' } } } ]);
    ($out) = capture(sub { OCP::Cmd::Apply::CR::retire_unannotated_robocop_pods(undef, $done) });
    is scalar @{ $done->{requests} }, 0, 'once the transition is over it touches nothing';
    is $out, '', 'and says nothing';

    my $gone = FakeApi->new(pods => [ { metadata => { name => 'p' } } ], status => 404);
    ($out) = capture(sub { OCP::Cmd::Apply::CR::retire_unannotated_robocop_pods(undef, $gone) });
    unlike $out, qr/WARN/, 'a pod that is gone already is fine';

    my $bad = FakeApi->new(pods => [ { metadata => { name => 'p' } } ], status => 403);
    ($out) = capture(sub { OCP::Cmd::Apply::CR::retire_unannotated_robocop_pods(undef, $bad) });
    like $out, qr/\[WARN\] could not delete robocop pod p/, 'a refusal is a [WARN], not a failed apply';
};

subtest '29: apply and deploy-robocop both do it' => sub {
    like path('lib/OCP/Cmd/Apply/CR.pm')->slurp_utf8,
        qr/sub ensure_robocop \{.*?retire_unannotated_robocop_pods\(\$self, \$api\)/s, 'ensure_robocop (apply)';
    like path('lib/OCP/Cmd/DeployRobocop.pm')->slurp_utf8,
        qr/retire_unannotated_robocop_pods\(\$self, \$api\)/, 'deploy-robocop';
};

subtest '32: the legacy-template probe names workers, not only control planes' => sub {
    my $node = sub {
        my ($name, $role, $ref, %st) = @_;
        return { metadata => { name => $name },
                 spec => { role => $role, providerRef => $ref, host => "$name.host" },
                 status => { %st } };
    };
    my $api = FakeApi->new(ocpnodes => [
        $node->('w-ssh',   'worker',        'ssh-default',     publicIP => '10.0.0.5'),
        $node->('w-local', 'worker',        'local-default'),
        $node->('w-hz',    'worker',        'hetzner-default', publicIP => '10.0.0.7'),
        $node->('cp',      'control-plane', 'ssh-default',     publicIP => '10.0.0.9'),
        $node->('w-dup',   'worker',        'ssh-default',     publicIP => '10.0.0.5'),
    ]);
    my @seen;
    my $drift = OCP::Drift->new(
        config     => config_for($CFG),
        api        => $api,
        rex_prober => sub { push @seen, [ @_[0, 1] ]; return { stdout => '' } },
    );
    $drift->rex_probe_drift;
    is_deeply [ map { $_->[0] } @seen ],
        [ 'cp.lab.example', '10.0.0.5', 'w-local.host' ],
        'CP, then ssh/local workers by publicIP else host; no Hetzner, no CP OCPNode, no duplicate';
    is $_->[1], 'detect_legacy_containerd_template', 'the read-only detection task' for @seen;

    my @cp_only;
    OCP::Drift->new(config => config_for($CFG), rex_prober => sub { push @cp_only, $_[0]; {} })
        ->rex_probe_drift;
    is_deeply \@cp_only, ['cp.lab.example'], 'without an API only the control planes can be named';

    my @all = OCP::Drift->new(config => config_for($CFG), api => $api, rex_prober => sub { {} })->probe_targets;
    is_deeply \@all, [ 'cp.lab.example', '10.0.0.5', 'w-local.host' ], 'probe_targets names the same machines';

    my @hit;
    my $found = OCP::Drift->new(config => config_for($CFG), api => $api,
        rex_prober => sub { return { stdout => $_[0] eq '10.0.0.5' ? "$OCP::Drift::REX_DRIFT_MARKER\n" : '' } });
    @hit = $found->rex_probe_drift;
    is_deeply [ map { $_->{host} } @hit ], ['10.0.0.5'], 'a worker with the template is a finding';
    is $hit[0]{remedy}{host}, '10.0.0.5', 'whose remedy runs on that worker';
};

# A command object with the role's rex_prober, and a robo key we control.
sub probe_cmd {
    my (%o) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => []);
    my $config = config_for($CFG);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_robo_probe_key = sub { $o{robo} };
    $apply->{_robo_probe_key} = $o{robo};
    if ($o{admin}) {
        $apply->{_cluster_ssh_key}{ OCP::ClusterKey::cache_slot($config) } = $o{admin};
    }
    return ($apply, $config);
}
{ package FakeKey; sub new { bless { path => $_[1] }, $_[0] } sub path { $_[0]{path} } }

subtest '33: secure mode without PIN2 probes with the robo key' => sub {
    my @keys_used;
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub {
        my ($rex, $task) = @_;
        push @keys_used, $rex->key_file;
        die "Rex task '$task' failed: Permission denied (publickey)\n" if $rex->host eq 'cp.lab.example';
        return { stdout => '' };
    };
    my ($apply, $config) = probe_cmd(robo => FakeKey->new('/tmp/robo.key'));
    local $ENV{HOME} = tempdir(CLEANUP => 1);
    my $prober = $apply->rex_prober($config);
    ok $prober, 'a prober exists although no PIN2 was asked';

    my $ok = $prober->('w1.host', 'detect_legacy_containerd_template', {});
    ok $ok, 'a host that accepts the robo key is probed';
    my $refused = eval { $prober->('cp.lab.example', 'detect_legacy_containerd_template', {}) };
    is $@, '', 'a host that refuses it is no exception';
    ok !$refused, 'and gives no result';
    is_deeply \@keys_used, [ '/tmp/robo.key', '/tmp/robo.key' ], 'the robo key was the one offered';

    my $drift = OCP::Drift->new(config => $config, rex_prober => $prober);
    is $apply->host_probe_warning($drift),
        "  [WARN] host probes skipped on cp.lab.example: the robo key was not accepted"
        . " (it is not authorised everywhere; the admin key needs PIN2)\n",
        'one [WARN] line naming the host';
};

subtest '33: a known admin key beats the robo key and its failures stay failures' => sub {
    my $used;
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub { $used = $_[0]->key_file; die "boom\n" };
    my ($apply, $config) = probe_cmd(robo => FakeKey->new('/tmp/robo.key'), admin => FakeKey->new('/tmp/admin.key'));
    my $prober = $apply->rex_prober($config);
    eval { $prober->('h', 't', {}) };
    is $@, "boom\n", 'the error propagates (OCP::Drift carps it, as before)';
    is $used, '/tmp/admin.key', 'admin key used';
    is $apply->host_probe_warning(OCP::Drift->new(config => $config)), '', 'no warning';
};

subtest '33: no usable key at all: one [WARN] naming the machines, no error' => sub {
    my ($apply, $config) = probe_cmd();
    local $ENV{HOME} = tempdir(CLEANUP => 1);
    my $prober = $apply->rex_prober($config);
    ok !$prober, 'no prober';
    my $drift = OCP::Drift->new(config => $config);
    is $apply->host_probe_warning($drift),
        "  [WARN] host probes skipped on cp.lab.example: no SSH key to probe with that needs no PIN2\n",
        'one line';
};

subtest '33: the robo key needs a keys.yaml; none is no key' => sub {
    my $apply  = OCP::Cmd::Apply->new(command_chain => []);
    my $config = config_for($CFG);
    ok !$apply->_robo_probe_key($config), 'dev mode (no keys.yaml): undef';
};

done_testing;

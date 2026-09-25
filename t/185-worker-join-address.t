#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 't/lib';
use OCPTest::Rexfile;

use OCP;
use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;

no warnings 'once';   # the stub package is filled by a string eval

#
# k185: a k3s worker joined via the control plane's HOSTNAME and hung forever.
#
# Live (ocpt): the CP had `host: ocpt-cp.vm` and `public_ip: 10.5.10.20` in
# ocp.yaml. The worker got K3S_URL=https://ocpt-cp.vm:6443, a name it could not
# use, and k3s-agent looped on "failed to get CA certs". The port was right --
# OCP::Config::join_url already knew k3s from RKE2 -- the ADDRESS was not: the
# first apply (bootstrap) handed every downstream step the provider's advertised
# host, which for the ssh provider is `host`, while the reconcile path (second
# apply, `ocp node add`, deploy-robocop) used public_ip // host. So which address
# a worker joined via depended on which apply brought it up, not on the
# distribution. And because the k3s installer ran `systemctl restart k3s-agent`
# -- a Type=notify unit that only returns once the agent has joined -- the Rex
# task, `ocp apply` and the OCPNode (stuck in Installing) waited with it, over
# 20 minutes and without a line of output.
#
# The claims here:
#   1. one answer to "the address workers join": public_ip when ocp.yaml pins
#      one, else the advertised host -- and bootstrap hands exactly that
#      downstream, so the join URL no longer depends on which apply ran;
#   2. neither agent task blocks on its unit's start: the unit is started
#      without waiting and the task waits for it itself, bounded;
#   3. an agent that never comes up fails the task, loudly, by name, with the
#      join URL and the unit's last journal lines.
#
# Network-free: bootstrap runs with every machine-touching layer faked (t/101),
# the Rexfile runs against recorders (t/lib/OCPTest/Rexfile.pm).
# Whether a real k3s agent now joins is a live question, NOT claimed here.
#

# --- 1a. the helper ------------------------------------------------------------

sub project {
    my ($yaml) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8($yaml);
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my $PINNED = <<'YAML';
name: ocpt
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: ocpt-cp.vm
  public_ip: 10.5.10.20
YAML

my $HOST_ONLY = <<'YAML';
name: ocpt
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: ocpt-cp.vm
YAML

subtest 'join_host: a pinned public_ip wins over the advertised host' => sub {
    my $config = project($PINNED);
    is $config->join_host('ocpt-cp.vm'), '10.5.10.20', 'public_ip, not the hostname';
    is $config->join_url($config->join_host('ocpt-cp.vm')), 'https://10.5.10.20:6443',
        'k3s joins via public_ip on 6443';
};

subtest 'join_host: no public_ip -> the advertised host, unchanged' => sub {
    my $config = project($HOST_ONLY);
    is $config->join_host('ocpt-cp.vm'), 'ocpt-cp.vm', 'the host the provider advertised';
    is $config->join_host('198.51.100.9'), '198.51.100.9',
        'a fresh Hetzner CP: whatever the provider handed back';
};

subtest 'join_host: an empty public_ip is no pin' => sub {
    my $config = project($PINNED =~ s/public_ip: 10\.5\.10\.20/public_ip: ''/r);
    is $config->join_host('ocpt-cp.vm'), 'ocpt-cp.vm', 'falls back to the advertised host';
};

# --- 1b. bootstrap hands that address downstream ------------------------------

package FakeOcp {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# An ssh-provider-shaped provider: the machine exists, SSH is reached at `host`
# and that is also what it advertises (OCP::Role::Provider::ExistingHost).
package FakeProv {
    sub new { bless { advertised => [] }, $_[0] }
    sub upload_ssh_key   { }
    sub server_exists    { { ip => 'ocpt-cp.vm', newly_created => 0 } }
    sub create_server    { { ip => 'ocpt-cp.vm', newly_created => 0 } }
    sub wait_for_running { $_[1] }
    sub advertised_host  { my ($s, %o) = @_; push @{ $s->{advertised} }, $o{host}; $o{host} }
    sub cleanup_on_failure { }
}

package FakeCond   { sub new { bless { t => $_[1], s => $_[2] }, $_[0] } sub type { $_[0]{t} } sub status { $_[0]{s} } }
package FakeStatus { sub conditions { [ FakeCond->new('Ready', 'True') ] } }
package FakeNodeObj { sub status { bless {}, 'FakeStatus' } }
package FakeNodeList { sub items { [ bless {}, 'FakeNodeObj' ] } }
package FakeApi {
    sub _request { 1 }
    sub list     { bless {}, 'FakeNodeList' }
}

package main;

sub run_bootstrap {
    my ($config) = @_;
    my $prov  = FakeProv->new;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    my %server_opts;

    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $old = select $fh;
    my $r = eval {
        no warnings 'redefine';
        local *OCP::Provider::for_spec         = sub { $prov };
        local *OCP::Cmd::Apply::_k8s_api       = sub { bless {}, 'FakeApi' };
        local *OCP::Secrets::save_kubeconfig   = sub { 1 };
        local *OCP::Secrets::ensure_age_key    = sub { 1 };
        local *OCP::SSH::new                   = sub { bless {}, 'OCP::SSH' };
        local *OCP::SSH::wait_for_ssh          = sub { 1 };
        local *OCP::SSH::run                   = sub { { stdout => 'Ready' } };
        local *OCP::Rex::new                   = sub { bless {}, 'OCP::Rex' };
        local *OCP::Rex::install_server        = sub { shift; %server_opts = @_; { kubeconfig => "apiVersion: v1\n" } };
        OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
            $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
            # dev mode (no keys.yaml): the bootstrap key on disk is used
            admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
        );
    };
    my $err = $@;
    select $old;
    return { r => $r, err => $err, out => $out, prov => $prov, server_opts => \%server_opts };
}

subtest 'bootstrap: cp_ip is the pinned public_ip, not the ssh host' => sub {
    my $res = run_bootstrap(project($PINNED));
    is $res->{err}, '', 'bootstrap ran to completion' or return diag $res->{out};
    is $res->{r}{cp_ip}, '10.5.10.20',
        'the worker join URL, robocop Secret, LB-IPAM and registry DNS get public_ip';
};

subtest 'bootstrap: no public_ip -> cp_ip stays the advertised host' => sub {
    my $res = run_bootstrap(project($HOST_ONLY));
    is $res->{err}, '', 'bootstrap ran to completion' or return diag $res->{out};
    is $res->{r}{cp_ip}, 'ocpt-cp.vm', 'unchanged where nothing else is known (k138)';
};

# --- 2 + 3. the Rexfile agent tasks -------------------------------------------
#
# Since k155 both agent tasks go through Rex::Rancher::Agent::install_agent,
# which starts the unit with --no-block (k3s: installer with
# INSTALL_K3S_SKIP_START, then restart --no-block) and waits at most 10
# minutes, dying with the unit's state and journal. Those guarantees are held
# against the real library in t/155-rex-libraries.t, and since Rex::Rancher
# 0.003 (rex-rancher k44) so is the join address in its error; here: that both
# tasks use it, and that its error reaches the caller as it is.

for my $t ([ install_k3s_agent => 'k3s' ], [ install_rke2_agent => 'rke2' ]) {
    my ($task, $dist) = @$t;
    subtest "$task joins through Rex::Rancher::Agent::install_agent" => sub {
        OCPTest::Rexfile->reset;
        OCPTest::Rexfile->run_task($task,
            { server => 'https://10.5.10.20:6443', token => 'K10tok', node_name => 'w1', version => 'v1' });
        my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Agent::install_agent');
        ok $o, 'install_agent called' or return;
        is $o->{distribution}, $dist, 'distribution';
        is $o->{server}, 'https://10.5.10.20:6443', 'the join URL as given';
        is $o->{node_name}, 'w1', 'node name';
        ok !(grep { /systemctl (?:start|restart) (?:k3s|rke2)-agent\b/ } OCPTest::Rexfile->commands),
            'no blocking start of a Type=notify unit of its own';
    };

    subtest "$task: a join that never comes up fails with the library's message" => sub {
        OCPTest::Rexfile->reset;
        my $msg = "$dist-agent.service did not become active within 600s (last state: activating)\n"
          . "It joins the cluster via https://ocpt-cp.vm:6443 -- check that this node can reach that address\n"
          . "--- journalctl -u $dist-agent.service -n 50 ---\nlevel=error msg=\"failed to get CA certs\"\n";
        local $OCPTest::Rexfile::LIB_DIE{'Rex::Rancher::Agent::install_agent'} = $msg;
        my $ok = eval {
            OCPTest::Rexfile->run_task($task, { server => 'https://ocpt-cp.vm:6443', token => 'K10tok' });
            1;
        };
        my $err = $@;
        ok !$ok, 'dies';
        like $err, qr/$dist-agent/, 'names the unit (the library\'s message)';
        like $err, qr/activating/, 'says the state it was stuck in';
        like $err, qr/failed to get CA certs/, 'carries the journal';
        like $err, qr{via https://ocpt-cp\.vm:6443 -- check that this node can reach that address},
            'and names the join URL (rex-rancher k44)';
        is $err, $msg, 'exactly as the library said it: OCP adds nothing, no second hint';
    };

    subtest "$task refuses to start without server or token" => sub {
        OCPTest::Rexfile->reset;
        ok !eval { OCPTest::Rexfile->run_task($task, { token => 't' }); 1 }, 'no server: dies';
        ok !eval { OCPTest::Rexfile->run_task($task, { server => 'https://x:6443' }); 1 }, 'no token: dies';
        is scalar(OCPTest::Rexfile->calls('do_task')), 0, 'before the node is touched';
    };
}

done_testing;

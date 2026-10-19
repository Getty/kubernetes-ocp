#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Node::Add;
use OCP::Config;
use OCP::Drift;
use OCP::K8s;
use OCP::Node;
use OCP::SSH;

#
# k236 (lab round 8, notes 40-41): a worker added by host NAME that does not
# resolve was blamed on the key ("the robo key was not accepted"), and nothing
# said that robocop resolves the name inside the cluster, not on the CLI host.
# Every message below is pinned on its own:
#   1 the recogniser (OCP::SSH->name_unresolved)
#   2 wait_for_ssh / learn_host_key stop at once on it
#   3 the host-probe warning tells a name from a key
#   4 status.message of a node (Rex task failure, teardown)
#   5 `ocp node add --host NAME` with robocop: the hint, and when it is silent
# No network, no DNS: the lookups are seams, OCP::SSH::run and OCP::Rex are faked.
#

# ---------------------------------------------------------------------------
# 1 recogniser
# ---------------------------------------------------------------------------

subtest '1: name_unresolved recognises resolver failures, not refused keys' => sub {
    for my $text (
        "ssh: Could not resolve hostname crag.lab: Name or service not known\n",
        "ssh: Could not resolve hostname crag.lab: Temporary failure in name resolution\n",
        "Rex task 'x' failed: Failed to resolve hostname crag.lab (Name or service not known)\n",
    ) {
        (my $short = $text) =~ s/\n//;
        ok( OCP::SSH->name_unresolved($text), "matches: $short" );
    }
    for my $text (
        "root\@h: Permission denied (publickey).\n",
        "ssh: connect to host x port 22: Connection refused\n",
        '', undef,
    ) {
        ok !OCP::SSH->name_unresolved($text), 'no match: ' . ($text // 'undef') =~ s/\n//r;
    }
    like( OCP::SSH->unresolved_message('crag.lab'), qr/Name 'crag\.lab' does not resolve/, 'the shared message names the host' );
};

# ---------------------------------------------------------------------------
# 2 OCP::SSH
# ---------------------------------------------------------------------------

subtest '2: wait_for_ssh says "does not resolve" at once, not key or timeout' => sub {
    my $ssh = OCP::SSH->new(host => 'crag.lab', user => 'root', key_file => '/p/id');
    my $runs = 0;
    no warnings 'redefine';
    local *OCP::SSH::run = sub {
        $runs++;
        return { exit => 255, stdout => '',
                 stderr => "ssh: Could not resolve hostname crag.lab: Name or service not known\n" };
    };
    ok !eval { $ssh->wait_for_ssh(120, 2); 1 }, 'dies';
    like $@, qr/does not resolve/, 'says the name does not resolve';
    like $@, qr/crag\.lab/, 'names it';
    unlike $@, qr/key rejected|not reachable/, 'neither key nor timeout text';
    is $runs, 1, 'one probe, no waiting out the budget';
};

subtest '2: learn_host_key says "does not resolve" too' => sub {
    my $ssh = OCP::SSH->new(host => 'crag.lab', user => 'root', key_file => '/p/id');
    no warnings 'redefine';
    local *OCP::SSH::run = sub {
        return { exit => 255, stdout => '',
                 stderr => "ssh: Could not resolve hostname crag.lab: Temporary failure in name resolution\n" };
    };
    ok !eval { $ssh->learn_host_key; 1 }, 'dies';
    like $@, qr/does not resolve/, 'says so';
    unlike $@, qr/Cannot reach/, 'not the generic text';
};

# ---------------------------------------------------------------------------
# 3 host-probe warning
# ---------------------------------------------------------------------------

{ package FakeKey; sub new { bless { path => $_[1] }, $_[0] } sub path { $_[0]{path} } }

my $dir = tempdir(CLEANUP => 1);
path($dir, 'ocp.yaml')->spew_utf8("name: lab\ncontrol_planes:\n  provider: ssh\n  nodes: 1\n");

sub probe_cmd {
    my $apply  = OCP::Cmd::Apply->new(command_chain => []);
    my $config = OCP::Config->new(file => "$dir/ocp.yaml");
    my $robo   = FakeKey->new('/tmp/robo.key');
    $apply->{_robo_probe_key} = $robo;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_robo_probe_key = sub { $robo };
    local $ENV{HOME} = tempdir(CLEANUP => 1);
    my $prober = $apply->rex_prober($config);
    return ($apply, $config, $prober);
}

subtest '3: probe warning names an unresolvable name, not the key' => sub {
    my ($apply, $config, $prober) = probe_cmd();
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub {
        die "Rex task 'x' failed: Failed to resolve hostname crag.lab (Name or service not known)\n";
    };
    my $res = eval { $prober->('crag.lab', 'detect_legacy_containerd_template', {}) };
    is $@, '', 'no exception';
    ok !$res, 'no result';
    my $warn = $apply->host_probe_warning(OCP::Drift->new(config => $config));
    like $warn, qr/host probes skipped on crag\.lab/, 'names the host';
    like $warn, qr/does not resolve/, 'says the name does not resolve';
    unlike $warn, qr/robo key was not accepted/, 'does not blame the key';
};

subtest '3: a refused robo key still says so' => sub {
    my ($apply, $config, $prober) = probe_cmd();
    no warnings 'redefine';
    local *OCP::Rex::run_task = sub { die "Rex task 'x' failed: Permission denied (publickey)\n" };
    eval { $prober->('cp.lab', 'detect_legacy_containerd_template', {}) };
    is $@, '', 'no exception';
    my $warn = $apply->host_probe_warning(OCP::Drift->new(config => $config));
    like $warn, qr/the robo key was not accepted/, 'key text kept';
    unlike $warn, qr/does not resolve/, 'no DNS text';
};

# ---------------------------------------------------------------------------
# 4 OCP::Node status.message
# ---------------------------------------------------------------------------

my @patches;
{
    no warnings 'redefine';
    *OCP::K8s::patch_status = sub { my ($c, $api, %a) = @_; push @patches, $a{status}; 1 };
}
our $REX_ERR;
{
    package FakeSSH;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub wait_for_ssh { 1 }
    sub run { +{ exit => 0 } }
    package FakeRex;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub run_task { die $main::REX_ERR }
    package FakeProvider;
    sub new { bless {}, shift }
    sub delete_server { die $main::REX_ERR }
}
sub last_patch { my %m; for my $p (@patches) { $m{$_} = $p->{$_} for keys %$p } \%m }

subtest '4: a Rex task that cannot resolve the name: status.message says so' => sub {
    @patches = ();
    local $REX_ERR = "Rex task 'install_rke2_agent' failed: Failed to resolve hostname crag.lab (Name or service not known)\n";
    my $n = OCP::Node->from_cr({
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => 'crag.lab' },
        status   => { phase => 'Installing', publicIP => 'crag.lab' },
    }, k8s => 'x', ssh_key => 'K', server_url => 'https://cp:9345', join_token => 'T',
       ssh_class => 'FakeSSH', rex_class => 'FakeRex');
    {
        no warnings 'redefine';
        local *OCP::Node::_seed_known_hosts = sub { '/dev/null' };
        local *OCP::Node::_pin_host_keys    = sub { 1 };
        $n->_install_kubernetes;
    }
    my $p = last_patch();
    is $p->{phase}, 'Failed', 'Failed';
    like $p->{message}, qr/Name 'crag\.lab' does not resolve/, 'message says the name does not resolve';
    unlike $p->{message}, qr/Rex task failed/, 'not the raw Rex wrapper';
};

subtest '4: a teardown that cannot resolve the name: status.message says so' => sub {
    @patches = ();
    local $REX_ERR = "ssh: Could not resolve hostname crag.lab: Name or service not known\n";
    my $n = OCP::Node->from_cr({
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => 'crag.lab' },
        status   => { phase => 'Ready', publicIP => 'crag.lab', providerId => 'SRV1' },
    }, k8s => 'x', provider => FakeProvider->new);
    {
        no warnings 'redefine';
        local *OCP::Node::_acquire_lease = sub { 1 };
        local *OCP::Node::_release_lease = sub { 1 };
        local *OCP::Node::_cordon        = sub { 0 };
        local *OCP::Node::_seed_known_hosts = sub { '/dev/null' };
        ok !eval { $n->teardown; 1 }, 'teardown dies';
    }
    my $p = last_patch();
    is $p->{phase}, 'Failed', 'Failed';
    like $p->{message}, qr/Teardown failed: Name 'crag\.lab' does not resolve/, 'message says so';
    like $p->{message}, qr/ocp node rm w1/, 'and keeps the way out';
};

# ---------------------------------------------------------------------------
# 5 ocp node add --host NAME
# ---------------------------------------------------------------------------

{ package FakeList; sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
{ package FakeIO;   sub new { bless {}, $_[0] } sub object_to_struct { $_[1] } }
{
    package FakeK8s;
    my $io = FakeIO->new;
    sub new { my ($c, %a) = @_; bless { %a, calls => [] }, $c }
    sub k8s { $io }
    sub list { my ($s, $kind) = @_; FakeList->new($kind eq 'OCPNodeProvider' ? $s->{providers} : []) }
    sub get {
        my ($s, $kind, %a) = @_;
        push @{ $s->{calls} }, [ get => $kind ];
        return $s->{providers}[0] if $kind eq 'OCPNodeProvider';
        return $s->{robocop_ready}
            ? { metadata => { name => 'robocop' }, status => { readyReplicas => 1 } } : undef
            if $kind eq 'Deployment';
        return undef;
    }
    sub ensure { my ($s, $o) = @_; push @{ $s->{calls} }, [ ensure => $o ]; $o }
}
my $ssh_provider = {
    metadata => { name => 'ssh-a', namespace => 'ocp-system', annotations => {} },
    spec     => { type => 'ssh' },
};

# Runs `node add --nowait` and returns (stdout, stderr). Lookup seams are set per call.
sub add_host {
    my (%o) = @_;
    my $k8s = FakeK8s->new(providers => [$ssh_provider], robocop_ready => $o{robocop});
    my $hosts = path(tempdir(CLEANUP => 1), 'hosts');
    $hosts->spew_utf8($o{hosts_file} // "127.0.0.1 localhost\n");
    my $add = OCP::Cmd::Node::Add->new(k8s => $k8s, name => 'w1', host => $o{host}, nowait => 1);
    my ($out, $err, $died) = ('', '', '');
    {
        no warnings 'redefine';
        local *OCP::Cmd::Node::Add::_resolves_here   = sub { $o{resolves} ? 1 : 0 };
        local *OCP::Cmd::Node::Add::_etc_hosts_file  = sub { "$hosts" };
        local *OCP::Cmd::Node::Add::_ssh_keys_note   = sub { '' };
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        eval { $add->execute([], []); 1 } or $died = $@;
    }
    return ($out, $err, $k8s, $died);
}

subtest '5: a name that does not resolve here: hint on STDERR with robocop' => sub {
    my ($out, $err) = add_host(host => 'crag.lab', robocop => 1, resolves => 0);
    like $err, qr/robocop resolves it inside the cluster/, 'the hint is given';
    like $err, qr/crag\.lab/, 'names the host';
    like $err, qr/does not resolve from this machine either/, 'says it does not resolve here';
    is $out, "w1\n", 'STDOUT stays the node name';
};

subtest '5: a name only /etc/hosts knows: hint says so' => sub {
    my ($out, $err) = add_host(host => 'crag.lab', robocop => 1, resolves => 1,
        hosts_file => "127.0.0.1 localhost\n10.0.0.9 crag.lab crag # lab\n");
    like $err, qr/resolves through \/etc\/hosts or similar, which no pod sees/, 'hint names /etc/hosts';
    is $out, "w1\n", 'STDOUT stays the node name';
};

subtest '5: a name resolving here but not in /etc/hosts: not checkable' => sub {
    my (undef, $err) = add_host(host => 'crag.lab', robocop => 1, resolves => 1);
    like $err, qr/cannot be checked from here/, 'hint says it cannot be checked';
    unlike $err, qr/\/etc\/hosts/, 'and does not claim /etc/hosts';
};

subtest '5: no hint for an IP address or without robocop' => sub {
    my (undef, $err_ip) = add_host(host => '10.0.0.9', robocop => 1, resolves => 0);
    unlike $err_ip, qr/inside the cluster/, 'IPv4: nothing to say';
    my (undef, $err_v6) = add_host(host => 'fd00::9', robocop => 1, resolves => 0);
    unlike $err_v6, qr/inside the cluster/, 'IPv6: nothing to say';
    # k238: without robocop nothing resolves the name but this machine, so the
    # call now aborts in the preflight (before ensure; t/238 pins the details).
    # What stays pinned here: the cluster hint is not printed without robocop.
    my (undef, $err_nr, $k8s_nr, $died) = add_host(host => 'crag.lab', robocop => 0, resolves => 0);
    like $died, qr/does not resolve.*on this machine/s, 'robocop not ready: aborts, name unresolved on this machine';
    unlike $err_nr, qr/inside the cluster/, 'robocop not ready: no cluster hint';
    unlike $died, qr/inside the cluster/, 'robocop not ready: no cluster hint in the error either';
    ok !(grep { $_->[0] eq 'ensure' } @{ $k8s_nr->{calls} }), 'ensure never called';
};

done_testing;

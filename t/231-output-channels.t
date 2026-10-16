#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Config;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Health;
use OCP::Node;
use OCP::Rex;

#
# k231, rest of k226 (lab 2026-10-16): what still went to the wrong channel or
# left the exit at 0. House rule: STDOUT is the narrative, STDERR is everything
# that went wrong, a run that worked writes nothing on STDERR, the exit is
# non-zero when something is not in order.
#
# N18 a Failed worker OCPNode outside ocp.yaml: named on STDOUT, not counted.
# N19 a pool host that already belongs to another OCPNode: counted.
# N22 a Rex warning in the successful CLI join path: [WARN] on STDOUT.
# 4b  Health.pm critical pods, 4c robocop's key label, 4d the PIN2 explanation.
#

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeK8s  { sub new { bless {}, shift } sub object_to_struct { $_[1] } }
package FakeApi  {
    sub new  { my ($c, @n) = @_; bless { nodes => \@n }, $c }
    sub k8s  { FakeK8s->new }
    sub list { FakeList->new($_[0]{nodes}) }
}
package main;

sub config_with {
    my (@nodes) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({ name => 'lab',
        control_planes => { provider => 'ssh', host => 'cp.lab.example' },
        (@nodes ? (workers => [ { name => 'lab', provider => 'ssh', nodes => \@nodes } ]) : ()) }));
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub ocpnode {
    my ($name, $host, $phase, $role) = @_;
    return { metadata => { name => $name },
             spec     => { host => $host, role => $role // 'worker' },
             status   => { phase => $phase // 'Ready' } };
}

sub capture_both {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    {
        local *STDOUT = $o;
        local *STDERR = $e;
        local $SIG{__WARN__} = sub { print STDERR @_ };
        $code->();
    }
    return ($out, $err);
}

subtest 'N18: a Failed worker outside ocp.yaml is named on STDOUT, not counted' => sub {
    my $api = FakeApi->new(
        ocpnode('lab-1',  '10.230.30.52',  'Ready'),
        ocpnode('ghost',  '10.230.30.254', 'Failed'),
        ocpnode('listed', '10.230.30.53',  'Failed'),
        ocpnode('other',  '10.230.30.99',  'Ready'),
        ocpnode('cp2',    '10.230.30.7',   'Failed', 'control-plane'),
    );
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my @warned;
    my ($out, $err) = capture_both(sub {
        @warned = OCP::Cmd::Apply::CR::warn_unlisted_failed_ocpnodes(
            $apply, $api, config_with('10.230.30.52', '10.230.30.53'));
    });
    is_deeply \@warned, ['ghost'], 'only the Failed worker the spec does not list (by host)';
    is $out, "  [WARN] OCPNode ghost is Failed and not in ocp.yaml (ocp node rm ghost)\n",
        'one WARN line on STDOUT, with the way out';
    is $err, '', 'nothing on STDERR';
    ok !$apply->{_failed_components}, 'and it does not count for the exit';

    # No workers in ocp.yaml at all: the same node is still not invisible.
    ($out) = capture_both(sub {
        OCP::Cmd::Apply::CR::warn_unlisted_failed_ocpnodes($apply, $api, config_with());
    });
    like $out, qr/OCPNode ghost is Failed and not in ocp.yaml/, 'also with an empty worker list';
};

subtest 'N19: a pool host owned by another OCPNode counts, the line stays on STDERR' => sub {
    my $api = FakeApi->new(ocpnode('otho-lab', '10.230.30.52'));
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my @missing;
    my ($out, $err) = capture_both(sub {
        @missing = OCP::Cmd::Apply::CR::missing_worker_ocpnodes(
            $apply, $api, config_with('10.230.30.52'));
    });
    is scalar @missing, 0, 'not provisioned again';
    like $err, qr/\[!!\] worker 10-230-30-52 .* is already OCPNode\/otho-lab/, 'said on STDERR';
    is $out, '', 'nothing on STDOUT';
    is_deeply $apply->{_failed_components}, ['worker 10-230-30-52'], 'counted for the exit';
};

subtest 'N22: a Rex warning in the successful join reaches the STDOUT narrative' => sub {
    my $tmp = tempdir(CLEANUP => 1);
    my $rexfile = path($tmp)->child('Rexfile');
    $rexfile->spew("# stub\n");
    my $kh = path($tmp)->child('known_hosts');
    $kh->spew("w.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr\n");
    local $ENV{OCP_KNOWN_HOSTS} = $kh->stringify;
    delete local $ENV{OCP_REX_DEBUG};

    my $WARN = 'crun not found, the nvidia runtime falls back to runc';
    no warnings 'redefine';
    local *OCP::Rex::_find_rexfile = sub { $rexfile->stringify };
    local *OCP::Rex::run = sub {
        ${ $_[2] } = "RKE2 agent ready\n";
        ${ $_[3] } = "[2026-10-16 10:00:00] INFO - Running task\n"
                   . "[2026-10-16 10:00:05] WARN - $WARN\n";
        return 1;
    };
    local *OCP::Versions::get_component_version = sub { 'v9.9.9' };
    local *OCP::K8s::patch_status = sub { return };
    {
        package AnySSH; sub new { bless {}, shift } sub wait_for_ssh { 1 }
        package AnyProv; sub new { bless {}, shift } sub create_server { { id => 'S1', ip => '10.0.0.5' } }
                         sub wait_for_running { $_[1] }
        package AnyK8s; sub new { bless {}, shift }
    }
    my $node = OCP::Node->from_cr({
            apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => 'w1', namespace => 'ocp-system', resourceVersion => '1' },
            spec     => { role => 'worker', providerRef => 'ssh-default', host => 'w.example' },
            status   => { phase => 'Installing', publicIP => 'w.example' },
        },
        k8s => AnyK8s->new, provider => AnyProv->new, ssh_key => 'KEY',
        server_url => 'https://cp:9345', join_token => 'TOKEN',
        ssh_class => 'AnySSH', rex_class => 'OCP::Rex',
    );
    my ($out, $err) = capture_both(sub { $node->_install_kubernetes });
    is $err, '', 'a join that worked writes nothing on STDERR';
    like $out, qr/^  \[WARN\] \Q$WARN\E$/m, 'the warning is a [WARN] line in the narrative';
};

subtest '4b: critical pods are [!!] on STDERR' => sub {
    my $health = { critical => [ { namespace => 'kube-system', name => 'cilium-x', reason => 'CrashLoop' } ],
                   warnings => [ { namespace => 'a', name => 'b', reason => 'slow' } ], starting => [] };
    my ($out, $err) = capture_both(sub { OCP::Cmd::Apply::Health::print(undef, $health) });
    like   $err, qr{^  \[!!\] kube-system/cilium-x — CrashLoop$}m, 'on STDERR';
    unlike $out, qr/\[!!\]/, 'not on STDOUT';
    like   $out, qr{\[WARN\] a/b}, 'warnings stay narrative';
};

subtest 'source claims: Bootstrap, Init, ClusterKey, robocop label' => sub {
    my $boot = path('lib/OCP/Cmd/Apply/Bootstrap.pm')->slurp_utf8;
    like $boot, qr/print STDERR "  \[!!\] Installation failed, cleaning up/, 'Bootstrap [!!] on STDERR';
    my $init = path('lib/OCP/Cmd/Init.pm')->slurp_utf8;
    unlike $init, qr/^\s*print "\[!!\]/m, 'no [!!] on STDOUT in Init';
    my $ck = path('lib/OCP/ClusterKey.pm')->slurp_utf8;
    unlike $ck, qr/^\s*print "  In secure mode every machine|^\s*print "  \(provider|^\s*print "  " \. \(\$reason/m,
        'the PIN2 explanation is not on STDOUT';
    like $ck, qr/my \$fh = defined \$opt\{pin2\} \? \\\*STDOUT : \\\*STDERR;\s*print \{\$fh\} "  In secure mode every machine/,
        'it goes with the prompt on STDERR (STDOUT only when the PIN2 is handed in, no prompt)';
    my $rc = path('lib/OCP/Robocop/Controller.pm')->slurp_utf8;
    is scalar(() = $rc =~ /ssh_key_label => 'the robo key'/g), 2, 'both from_cr sites label the robo key';
};

done_testing;

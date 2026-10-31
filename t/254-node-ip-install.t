#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';
use lib 't/lib';
use OCPTest::Rexfile;
use OCP::Rex;

#
# k254: OCP set no node-ip, so a multi-homed host registered the address of
# its default route. Live (2026-10-31): synapse, joined by 10.230.30.50,
# registered 192.168.0.165 -- unreachable from the control plane, Cilium's
# tunnel broken in one direction, the node Ready all the same.
#
# The install half (infra lane). Claims:
#   1. the OCPNode CRD carries spec.nodeIP (asked for) and status.nodeIP (what
#      OCP handed the installer), strings without a schema default -- the CRD
#      prunes what it does not declare, and a default would be read as asked;
#   2. OCP::Rex install_server/install_agent hand node_ip on as the task
#      parameter of that name, and only when it is set;
#   3. the Rexfile hands it to Rex::Rancher's preflight and install, server and
#      agent, RKE2 and k3s, only when it is set;
#   4. node_ip is only ever what the operator asked for, so a Rex::Rancher
#      without node_ip support (rex-rancher k100; 0.004 ignores an option it
#      does not know) is a refusal: the task dies naming the address, the
#      library and the fix, before it reads or changes anything on the host --
#      a node Ready on the wrong address is what was asked to be avoided. No
#      node_ip, no refusal;
#   5. that refusal is the failed task's reason through OCP::Rex (what robocop
#      writes into the Failed OCPNode), and the library's own warning for a
#      re-run that changes the node-ip reaches the operator like every task
#      warning.
#

no warnings 'once';   # the sandbox package is filled by a string eval

my $IP   = '10.230.30.50';
my $DUAL = '10.230.30.50,fd00:30::50';

# Rex::Rancher's capability, switched per test: the Rexfile asks
# Rex::Rancher::Distribution->can('node_addresses') and nothing else of it.
sub with_node_ip_support {
    my ($code) = @_;
    no warnings 'redefine';
    local *Rex::Rancher::Distribution::node_addresses = sub { die "the Rexfile only asks can()\n" };
    return $code->();
}
sub without_node_ip_support {
    my ($code) = @_;
    local *Rex::Rancher::Distribution::node_addresses;
    return $code->();
}

# Runs an install task in the sandbox; returns (STDOUT, STDERR).
sub install_task {
    my ($task, %params) = @_;
    OCPTest::Rexfile->reset;
    my $err = '';
    my $out;
    {
        local *STDERR;
        open STDERR, '>', \$err or die "cannot capture STDERR: $!";
        $out = OCPTest::Rexfile->run_task($task, {
            token => 't',
            ($task =~ /_agent\z/ ? (server => 'https://203.0.113.1:9345') : ()),
            %params,
        });
    }
    return ($out, $err);
}

# The two library calls an install task makes, by role.
sub lib_calls_for {
    my ($task) = @_;
    my $side = $task =~ /_agent\z/ ? 'Agent::%s_agent' : 'Server::%s_server';
    return map { 'Rex::Rancher::' . sprintf($side, $_) } qw( preflight install );
}

my @TASKS = map { ("install_${_}_server", "install_${_}_agent") } qw( rke2 k3s );

# --- 1. the CRD -------------------------------------------------------------

subtest 'the OCPNode CRD declares spec.nodeIP and status.nodeIP' => sub {
    # Loaded as OCP::Cmd::Apply::CR::ensure_crds loads it before the
    # Server-Side Apply.
    my @docs = YAML::XS::LoadFile('share/robocop/crds/ocpnode.yaml');
    is scalar(grep { ref $_ eq 'HASH' && $_->{kind} } @docs), 1, 'one document, as before';
    my $props = $docs[0]{spec}{versions}[0]{schema}{openAPIV3Schema}{properties};

    my $spec = $props->{spec}{properties}{nodeIP};
    ok $spec, 'spec.nodeIP is declared' or return;
    is $spec->{type}, 'string', 'a string';
    ok !exists $spec->{default}, 'without a schema default: absent stays absent';
    like $spec->{description}, qr/one IP, or "v4,v6"/, 'its description names the two forms';
    ok !(grep { $_ eq 'nodeIP' } @{ $props->{spec}{required} // [] }), 'not required';

    my $status = $props->{status}{properties}{nodeIP};
    ok $status, 'status.nodeIP is declared' or return;
    is $status->{type}, 'string', 'a string';
    ok !exists $status->{default}, 'without a schema default';
};

# --- 2. OCP::Rex -------------------------------------------------------------

my $tmp = tempdir(CLEANUP => 1);
my $key = path($tmp)->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub key');
my $known_hosts = path($tmp)->child('known_hosts');
$known_hosts->spew('');
our $STUB_REXFILE = path($tmp)->child('Rexfile');
$STUB_REXFILE->spew("# stub\n");

sub rex { OCP::Rex->new(host => '203.0.113.9', key_file => "$key", known_hosts => "$known_hosts") }

# The parameters of each task OCP::Rex runs, by task.
sub ocp_rex_tasks {
    my ($method, %opts) = @_;
    my %tasks;
    no warnings 'redefine';
    local *OCP::Rex::fetch_kubeconfig_ssh   = sub { "stub-kubeconfig\n" };
    local *OCP::Rex::_existing_server_token = sub { undef };
    local *OCP::Rex::run_task = sub {
        my ($self, $task, %params) = @_;
        $tasks{$task} = \%params;
        return { stdout => '', stderr => '', exit => 0, warnings => [], steps => [] };
    };
    rex()->$method(%opts);
    return \%tasks;
}

my %AGENT = (server => 'https://203.0.113.1:9345', token => 't');

subtest 'OCP::Rex: node_ip reaches the install task when set' => sub {
    for my $dist (qw( rke2 k3s )) {
        my $t = ocp_rex_tasks('install_server', distribution => $dist, node_ip => $IP);
        is $t->{"install_${dist}_server"}{node_ip}, $IP, "$dist: install_server";
        ok !exists $t->{install_cilium}{node_ip}, "$dist: and not install_cilium, which has no use for it";

        $t = ocp_rex_tasks('install_agent', distribution => $dist, %AGENT, node_ip => $DUAL);
        is $t->{"install_${dist}_agent"}{node_ip}, $DUAL, "$dist: install_agent, dual-stack as given";
    }
};

subtest 'OCP::Rex: no node_ip parameter when none is set' => sub {
    for my $unset ([], [ node_ip => undef ], [ node_ip => '' ]) {
        my $how = @$unset ? 'node_ip => ' . (defined $unset->[1] ? "''" : 'undef') : 'no node_ip';
        my $t = ocp_rex_tasks('install_server', distribution => 'rke2', @$unset);
        ok $t->{install_rke2_server}, "$how: the server task ran" or next;
        ok !exists $t->{install_rke2_server}{node_ip}, "$how: install_server passes none";

        $t = ocp_rex_tasks('install_agent', distribution => 'rke2', %AGENT, @$unset);
        ok !exists $t->{install_rke2_agent}{node_ip}, "$how: install_agent passes none";
    }
};

# --- 3. the Rexfile, with a Rex::Rancher that has node_ip --------------------

subtest 'Rexfile: node_ip reaches preflight and install, server and agent' => sub {
    with_node_ip_support(sub {
        ok(Rex::Rancher::Distribution->can('node_addresses'), 'the library has node_ip support');
        for my $task (@TASKS) {
            for my $ip ($IP, $DUAL) {
                my (undef, $err) = install_task($task, node_ip => $ip);
                for my $fn (lib_calls_for($task)) {
                    my $o = OCPTest::Rexfile->lib_opts($fn);
                    ok $o, "$task: $fn called" or next;
                    is $o->{node_ip}, $ip, "$task: $fn gets node_ip $ip";
                }
                unlike $err, qr/node-ip/, "$task: nothing said about it";
            }
        }
    });
};

subtest 'Rexfile: no node_ip option when none is set' => sub {
    with_node_ip_support(sub {
        for my $task (@TASKS) {
            for my $unset ([], [ node_ip => '' ], [ node_ip => [] ]) {
                my (undef, $err) = install_task($task, @$unset);
                for my $fn (lib_calls_for($task)) {
                    my $o = OCPTest::Rexfile->lib_opts($fn);
                    ok $o, "$task: $fn called" or next;
                    ok !exists $o->{node_ip}, "$task: $fn gets no node_ip ("
                        . (@$unset ? 'empty' : 'absent') . ')';
                }
                is $err, '', "$task: and nothing on STDERR";
            }
        }
    });
};

# --- 4. a Rex::Rancher without it --------------------------------------------

my $REFUSAL;

subtest 'Rexfile: a Rex::Rancher without node_ip support refuses the node_ip' => sub {
    without_node_ip_support(sub {
        ok(!Rex::Rancher::Distribution->can('node_addresses'), 'the library has no node_ip support');
        for my $task (@TASKS) {
            for my $ip ($IP, [ $IP ]) {
                my $as = ref $ip ? 'as a list' : 'as a string';
                my ($out, $err);
                ok !eval { ($out, $err) = install_task($task, node_ip => $ip); 1 },
                    "$task: dies ($as)" or next;
                my $died = $@;
                is scalar @OCPTest::Rexfile::CALLS, 0,
                    "$task: before anything on the host is read or changed, or a library is called";
                like $died, qr/^node_ip \Q$IP\E cannot be set: this image's Rex::Rancher \S+ has no node_ip support \(rex-rancher k100\)/,
                    "$task: naming the address and the library";
                like $died, qr/Nothing was changed on the host\./, "$task: saying nothing happened";
                like $died, qr/Fix: an OCP\/robocop image whose Rex::Rancher supports node_ip, or leave node_ip out\n\z/,
                    "$task: and the two ways out";
                unlike $died, qr/\n./, "$task: one line, as Rex logs it in one ERROR line";
                $REFUSAL //= $died;
            }
        }

        my ($out, $err);
        ok eval { ($out, $err) = install_task('install_rke2_agent'); 1 },
            'without a node_ip the old library installs as before' or diag $@;
        ok(OCPTest::Rexfile->lib_opts('Rex::Rancher::Agent::install_agent'), 'the install runs');
        is $err, '', 'and nothing is said about it';
    });
};

# --- 5. where it surfaces ----------------------------------------------------

# rex itself replaced: its stdout/stderr as given, exit as given.
sub rex_run_with {
    my ($stderr, $ok) = @_;
    my ($out, $err) = ('', '');
    my $died;
    {
        no warnings 'redefine';
        local *OCP::Rex::_ensure_host_key = sub { };
        local *OCP::Rex::_find_rexfile    = sub { "$STUB_REXFILE" };
        local *OCP::Rex::run = sub { ${ $_[2] } = "RKE2 agent joined cluster\n"; ${ $_[3] } = $stderr; $ok };
        delete local $ENV{OCP_REX_DEBUG};
        open my $o, '>', \$out or die;
        open my $e, '>', \$err or die;
        local *STDOUT = $o;
        local *STDERR = $e;
        eval { rex()->run_task('install_rke2_agent'); 1 } or $died = $@;
    }
    return ($out, $err, $died);
}

subtest 'the refusal is the failed task\'s reason through OCP::Rex' => sub {
    ok $REFUSAL, 'the Rexfile\'s refusal from above' or return;
    chomp(my $refusal = $REFUSAL);

    # A task's die, as Rex logs it (t/201): a header, the message, the header.
    my $log = "[2026-10-31 02:00:01] INFO - Running task install_rke2_agent on 203.0.113.9\n"
            . "[2026-10-31 02:00:01] ERROR - Error executing task:\n"
            . "[2026-10-31 02:00:01] ERROR - $refusal\n"
            . "[2026-10-31 02:00:01] ERROR - $refusal\n"
            . "[2026-10-31 02:00:02] ERROR - Error executing task:\n";
    my ($out, $err, $died) = rex_run_with($log, 0);
    is $died, "Rex task 'install_rke2_agent' failed: $refusal\n",
        'the error is the refusal, once -- what robocop writes into the Failed OCPNode';
};

subtest 'a re-run that changes the node-ip: the library\'s warning reaches the operator' => sub {
    # Rex::Rancher (k100) on a re-run whose node_ip differs from config.yaml's:
    # a Rex::Logger warning, on rex's STDERR, as -m writes it.
    my $changed = "node-ip changes from 192.168.0.165 to $IP in /etc/rancher/rke2/config.yaml: "
        . 'a node that already registered takes it when rke2-agent restarts. With Cilium, '
        . 'restart its agent pod on this node then as well, or its CiliumNode keeps the old address';
    my $log = "[2026-10-31 02:00:01] INFO - Running task install_rke2_agent on 203.0.113.9\n"
            . "[2026-10-31 02:00:09] WARN - $changed\n";

    my ($out, $err, $died) = rex_run_with($log, 1);
    ok !$died, 'a task that worked' or diag $died;
    like $out, qr/^  \[WARN\] \Q$changed\E$/m, 'a [WARN] in the narrative';
    is $err, '', 'and, as for every task that worked (k226), nothing on STDERR';

    ($out, $err, $died) = rex_run_with($log . "[2026-10-31 02:00:10] ERROR - agent did not start\n", 0);
    like $died, qr/agent did not start/, 'a task that failed dies with its reason';
    like $err, qr/^  \[WARN\] \Q$changed\E$/m, 'and its warnings are on STDERR, with the diagnosis';
    unlike $out, qr/\[WARN\]/, 'not on STDOUT';
};

done_testing;

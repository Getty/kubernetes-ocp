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
use OCP::Rex;
use OCP::Node;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Node::Add;

no warnings 'once';   # the stub packages are filled by a string eval

#
# k196, part 1: what the Rexfile still did itself, or kept without a caller,
# now that Rex::Rancher and Rex::GPU carry the install.
#
# The claims:
#   1. the Rexfile declares the tasks OCP runs and no others: the on-node
#      kubectl tasks nothing called (untaint_control_plane, get_<dist>_kubeconfig,
#      get_<dist>_token) are gone, and with them OCP::Rex's get_kubeconfig and
#      get_token, the only route to two of them;
#   2. a server install waits for the Kubernetes API through
#      Rex::Rancher::K8s::wait_for_api, from this machine, with the node's admin
#      kubeconfig pointed at the address Rex reaches the node on -- the route
#      install_cilium takes right after -- and never through kubectl on the
#      node. The library returns false on a timeout instead of dying, so the
#      task dies itself, naming the address this machine has to reach;
#   3. an agent install hands Rex::Rancher the cluster's kubeconfig when it has
#      one, so the library checks the agent's version against the control
#      plane before the host is touched. `ocp apply` and `ocp node add` have
#      one (the project's kubeconfig.yaml) and pass it; OCP::Node gives it to
#      workers only, as a file on the machine Rex runs on. robocop has none.
#
# Network-free: the Rexfile runs against recorders (t/lib/OCPTest/Rexfile.pm),
# the CLI callers against fakes. Whether the library's check refuses a real
# too-new agent is held against the real library in t/155-rex-libraries.t.
#

my $HOST = $OCPTest::Rexfile::SERVER;

# --- 1. no task without a caller ---------------------------------------------

subtest 'the Rexfile declares the tasks OCP runs, and no others' => sub {
    my %runs = (
        # OCP::Rex::install_server (bootstrap); install_rke2_server also
        # OCP::Node, for a control plane joining police1
        install_rke2_server => 1, install_k3s_server => 1,
        # OCP::Node, for workers
        install_rke2_agent  => 1, install_k3s_agent  => 1,
        # OCP::Rex::install_server, after the server
        install_cilium      => 1,
        # OCP::Drift's remedies and `ocp update`
        upgrade_cilium      => 1, update_gateway_api => 1, upgrade_cert_manager => 1,
        # OCP::Drift's read-only probe and its remedy (also run by prepare_node)
        detect_legacy_containerd_template  => 1,
        cleanup_legacy_containerd_template => 1,
        # do_task inside the install tasks
        prepare_node => 1, detect_gpu => 1, install_nvidia => 1,
    );
    is_deeply [ OCPTest::Rexfile->task_names ], [ sort keys %runs ],
        'every declared task has a caller';

    ok !OCP::Rex->can($_), "OCP::Rex has no $_" for qw( get_kubeconfig get_token );
    ok(OCP::Rex->can('fetch_kubeconfig_ssh'),
        'the kubeconfig still comes off the node over SSH');
};

# --- 2. the API wait ---------------------------------------------------------

my @SERVERS = (
    [ 'rke2 server'      => install_rke2_server => '/etc/rancher/rke2/rke2.yaml', {} ],
    [ 'k3s server'       => install_k3s_server  => '/etc/rancher/k3s/k3s.yaml',   {} ],
    [ 'rke2 server join' => install_rke2_server => '/etc/rancher/rke2/rke2.yaml',
        { server => 'https://10.0.0.1:9345' } ],
);

for my $case (@SERVERS) {
    my ($label, $task, $node_kc, $extra) = @$case;

    subtest "$label: waits for the API through the library, from here" => sub {
        OCPTest::Rexfile->reset;
        my ($seen, $mode);
        local $OCPTest::Rexfile::LIB_CODE{'Rex::Rancher::K8s::wait_for_api'} = sub {
            my (%o) = @_;
            $seen = -r $o{kubeconfig} ? path($o{kubeconfig})->slurp : undef;
            $mode = -e $o{kubeconfig} ? (stat $o{kubeconfig})[2] & 07777 : undef;
            return 1;
        };
        OCPTest::Rexfile->run_task($task, { token => 't', %$extra });

        my @waits = OCPTest::Rexfile->calls('Rex::Rancher::K8s::wait_for_api');
        is scalar @waits, 1, 'wait_for_api, once' or return;
        my $install = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::Rancher::Server::install_server' });
        my $wait    = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::Rancher::K8s::wait_for_api' });
        ok $install >= 0 && $wait > $install, 'after the server install';

        my %o = @{ $waits[0]{args} };
        ok defined $seen, 'handed a kubeconfig file on this machine' or return;
        is $mode, 0600, 'readable by nobody else';
        ok !-e $o{kubeconfig}, 'gone once the task is done';
        ok((grep { $_ eq "cat $node_kc" } OCPTest::Rexfile->commands), "read off the node ($node_kc)");
        like $seen, qr{server: https://\Q$HOST\E:6443}, 'pointed at the address Rex reaches the node on';
        like $seen, qr/insecure-skip-tls-verify: true/, 'as every kubeconfig OCP uses';
    };

    subtest "$label: an API that does not answer fails the task" => sub {
        OCPTest::Rexfile->reset;
        local $OCPTest::Rexfile::LIB_CODE{'Rex::Rancher::K8s::wait_for_api'} = sub { 0 };
        my $out;
        ok !eval { $out = OCPTest::Rexfile->run_task($task, { token => 't', %$extra }); 1 },
            'dies although the library only returned false';
        like $@, qr/did not answer within 5 minutes/, 'saying so';
        like $@, qr/\Q$HOST\E:6443/, 'naming the address';
        like $@, qr/this machine/, 'and where it was asked from';
    };
}

subtest 'a node without its admin kubeconfig is not waited on' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = sub { $_[0] =~ /^cat / ? ('', 1) : ('', 0) };
    ok !eval { OCPTest::Rexfile->run_task('install_rke2_server', { token => 't' }); 1 }, 'dies';
    like $@, qr{Cannot read /etc/rancher/rke2/rke2\.yaml on the node}, 'naming the file';
    is scalar(OCPTest::Rexfile->calls('Rex::Rancher::K8s::wait_for_api')), 0, 'before any wait';
};

subtest 'no install task runs kubectl on the node' => sub {
    for my $task (qw( install_rke2_server install_k3s_server install_rke2_agent install_k3s_agent )) {
        OCPTest::Rexfile->reset;
        OCPTest::Rexfile->run_task($task, { token => 't', server => 'https://10.0.0.1:9345' });
        my @kubectl = grep { /kubectl/ } OCPTest::Rexfile->commands;
        is_deeply \@kubectl, [], "$task: none" or diag explain \@kubectl;
    }
};

# --- 3. the agent's version check ----------------------------------------------

for my $t ([ install_rke2_agent => 'rke2' ], [ install_k3s_agent => 'k3s' ]) {
    my ($task, $dist) = @$t;
    my %join = (server => 'https://10.0.0.1:9345', token => 't');

    subtest "$task: the cluster's kubeconfig reaches install_agent" => sub {
        OCPTest::Rexfile->reset;
        OCPTest::Rexfile->run_task($task, { %join, kubeconfig => '/tmp/ocp-kubeconfig-x.yaml' });
        my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Agent::install_agent');
        is $o->{kubeconfig}, '/tmp/ocp-kubeconfig-x.yaml',
            'as given: the library checks the agent against the control plane with it';

        for my $none (undef, '') {
            OCPTest::Rexfile->reset;
            OCPTest::Rexfile->run_task($task, { %join, kubeconfig => $none });
            ok !exists OCPTest::Rexfile->lib_opts('Rex::Rancher::Agent::install_agent')->{kubeconfig},
                'none (' . (defined $none ? "''" : 'undef') . '): no kubeconfig, the join goes without the check';
        }
    };
}

# The CLI callers of OCP::Node, which are the ones that have a kubeconfig.

my $KC = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://1.2.3.4:6443\n    insecure-skip-tls-verify: true\n";

{
    package FakeSecrets;
    sub new             { my ($c, $kc) = @_; bless { kc => $kc }, $c }
    sub read_kubeconfig { $_[0]{kc} }
}
{
    package FakeOcp;
    sub new     { bless {}, shift }
    sub verbose { 0 }
}
{
    package FakeApi;
    sub new  { bless {}, shift }
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }
    sub get {
        my ($self, $kind, @rest) = @_;
        return {
            metadata => { name => $rest[0], namespace => 'ocp-system' },
            spec     => { role => 'worker', providerRef => 'ssh-default' },
            status   => {},
        } if $kind eq 'OCPNode';
        return {
            metadata => { name => 'ssh-default', namespace => 'ocp-system' },
            spec     => { type => 'ssh' },
        } if $kind eq 'OCPNodeProvider';
        return undef;
    }
}
{
    package FakeNode;
    sub reconcile_until_ready { 1 }
    sub phase { 'Ready' }
}

sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: k196\ncontrol_planes:\n  provider: ssh\n  host: 1.2.3.4\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# The %deps OCP::Node->from_cr is built with, one hash per node.
sub node_deps (&) {
    my ($run) = @_;
    my @deps;
    no warnings 'redefine';
    local *OCP::Node::from_cr = sub { my ($c, $cr, %d) = @_; push @deps, \%d; bless {}, 'FakeNode' };
    local *OCP::Provider::from_cr = sub { bless {}, 'FakeProvider' };
    local *OCP::SSH::new = sub { bless {}, $_[0] };
    local *OCP::SSH::run = sub { { stdout => "K10::token\n", stderr => '', exit => 0 } };
    my $out = '';
    {
        local *STDOUT;
        open STDOUT, '>', \$out or die $!;
        $run->();
    }
    return @deps;
}

subtest 'ocp apply hands every node it drives the project kubeconfig' => sub {
    my $config = project();
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);

    my @deps = node_deps {
        OCP::Cmd::Apply::CR::cli_reconcile_workers($apply, FakeApi->new, $config,
            [ 'worker-1', 'worker-2' ],
            { ssh_key_path => '/nonexistent', cp_ip => '1.2.3.4', secrets => FakeSecrets->new($KC) });
    };
    is scalar @deps, 2, 'two nodes driven' or return;
    is $_->{kubeconfig}, $KC, 'the kubeconfig.yaml content' for @deps;

    @deps = node_deps {
        OCP::Cmd::Apply::CR::cli_reconcile_workers($apply, FakeApi->new, $config,
            [ 'worker-1' ],
            { ssh_key_path => '/nonexistent', cp_ip => '1.2.3.4', secrets => FakeSecrets->new(undef) });
    };
    ok !exists $deps[0]{kubeconfig}, 'a project without one hands none';
};

{
    package FakeAddConfig;
    sub new            { bless {}, shift }
    sub cluster_status { {} }
    sub distribution   { 'rke2' }
    sub pod_cidr       { '10.42.0.0/16' }
}

subtest 'ocp node add hands the node the project kubeconfig' => sub {
    my $add = OCP::Cmd::Node::Add->new(k8s => FakeApi->new, name => 'worker-9');
    my $cr  = {
        metadata => { name => 'worker-9', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'ssh-default' },
    };

    my @deps = node_deps {
        $add->_cli_reconcile($cr, FakeApi->new, FakeAddConfig->new, FakeSecrets->new($KC));
    };
    is scalar @deps, 1, 'one node driven' or return;
    is $deps[0]{kubeconfig}, $KC, 'the kubeconfig.yaml content';
};

done_testing;

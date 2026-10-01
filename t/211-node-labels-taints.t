#!/usr/bin/env perl
# karr k211 -- an OCPNode's spec.labels and spec.taints reach the Node.
#
# The CRD declared both and nothing read them. Now:
#   - ocp.yaml worker pools (labels:, taints:) and `ocp node add --label
#     --taint` write them onto the OCPNode;
#   - the install hands the labels the kubelet may set itself to the join
#     (Rex::Rancher's node_labels);
#   - OCP::Node converges the Kubernetes Node to both through the API once it
#     is registered, and again on every look at a Ready node -- removing only
#     what it set itself (ocp.internal/managed-* annotations).
#
# No cluster: the k8s client and Rex are recorders.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS ();
use Path::Tiny qw(path);

use lib 'lib';
use lib 't/lib';
use OCPTest::Rexfile;
use OCP;
use OCP::Config;
use OCP::NodeMeta;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Node::Add;

my $M = 'OCP::NodeMeta';

# --- syntax --------------------------------------------------------------------

subtest 'taints: kubectl syntax into the CRD shape' => sub {
    is_deeply $M->parse_taint('nvidia.com/gpu=present:NoSchedule'),
        { key => 'nvidia.com/gpu', value => 'present', effect => 'NoSchedule' }, 'key=value:Effect';
    is_deeply $M->parse_taint('dedicated:NoExecute'),
        { key => 'dedicated', effect => 'NoExecute' }, 'key:Effect';
    is_deeply $M->parse_taint('dedicated=:PreferNoSchedule'),
        { key => 'dedicated', effect => 'PreferNoSchedule' }, 'an empty value is none';
    like $M->taint_error('gpu=yes'), qr/expected key=value:Effect/, 'no effect';
    like $M->taint_error('gpu=yes:Never'), qr/effect must be NoSchedule, PreferNoSchedule, NoExecute/,
        'unknown effect';
    like $M->taint_error('-bad=x:NoSchedule'), qr/'-bad' is not a valid key/, 'bad key';
    like $M->taint_error('k=a b:NoSchedule'), qr/'a b' is not a valid value/, 'bad value';
    ok !defined $M->taint_error('a.b/c=d:NoSchedule'), 'a good one has no error';
    ok !eval { $M->parse_taint('nope'); 1 }, 'parse_taint croaks on a bad one';
};

subtest 'labels: key=value and the mapping form' => sub {
    is_deeply { $M->parse_label('ai.citilan.de/node-class=rtx3090') },
        { 'ai.citilan.de/node-class' => 'rtx3090' }, 'key=value';
    is_deeply { $M->parse_label('flag=') }, { flag => '' }, 'an empty value is a value';
    like $M->label_error('novalue'), qr/expected key=value/, 'no =';
    like $M->label_error('UPPER.Case/x=y'), qr/not a valid key/, 'prefix must be a DNS subdomain';
    like $M->label_error('k=' . ('x' x 64)), qr/not a valid value/, 'value over 63 chars';

    is_deeply [ $M->label_errors('w', { 'ai.citilan.de/node-class' => 'gb10' }) ], [], 'a good mapping';
    like join("\n", $M->label_errors('w', { a => JSON::MaybeXS::true })),
        qr/w\.a: value must be a string \(quote true/, 'an unquoted YAML boolean';
    like join("\n", $M->label_errors('w', ['a=b'])), qr/must be a mapping/, 'a list';
};

subtest 'join labels: only what the kubelet may set itself' => sub {
    is_deeply $M->join_labels({
        'ai.citilan.de/node-class'        => 'rtx3090',
        'node-role.kubernetes.io/gpu'     => '',
        'node.kubernetes.io/pool'         => 'a',
        'kubelet.kubernetes.io/x'         => 'b',
        'topology.kubernetes.io/zone'     => 'lab',
        'example.k8s.io/thing'            => 'c',
        plain                             => 'd',
    }), [ 'ai.citilan.de/node-class=rtx3090', 'kubelet.kubernetes.io/x=b',
          'node.kubernetes.io/pool=a', 'plain=d', 'topology.kubernetes.io/zone=lab' ],
        'node-role.kubernetes.io and *.k8s.io stay out of the registration';
    is_deeply $M->join_labels(undef), [], 'none';
};

# --- convergence -----------------------------------------------------------------

sub node {
    my (%o) = @_;
    return {
        metadata => { name => 'crag', resourceVersion => '7',
                      labels => $o{labels} // { 'kubernetes.io/hostname' => 'crag' },
                      ($o{annotations} ? (annotations => $o{annotations}) : ()) },
        spec     => { ($o{taints} ? (taints => $o{taints}) : ()) },
    };
}

my $GPU_TAINT = { key => 'nvidia.com/gpu', value => 'present', effect => 'NoSchedule' };

subtest 'a fresh Node gets labels, taints and the bookkeeping' => sub {
    my $p = $M->converge_patch(node(taints => [ { key => 'node.kubernetes.io/not-ready', effect => 'NoSchedule' } ]),
        { 'ai.citilan.de/node-class' => 'rtx3090' }, [ $GPU_TAINT ]);
    is $p->{metadata}{resourceVersion}, '7', 'conditional on the resourceVersion';
    is_deeply $p->{metadata}{labels}, { 'ai.citilan.de/node-class' => 'rtx3090' }, 'the label';
    is_deeply $p->{spec}{taints},
        [ { key => 'node.kubernetes.io/not-ready', effect => 'NoSchedule' }, $GPU_TAINT ],
        'the taint, next to the node controller\'s';
    is $p->{metadata}{annotations}{'ocp.internal/managed-labels'}, '["ai.citilan.de/node-class"]',
        'managed labels recorded';
    is $p->{metadata}{annotations}{'ocp.internal/managed-taints'}, '["nvidia.com/gpu:NoSchedule"]',
        'managed taints recorded';
};

subtest 'a Node that already matches: no patch' => sub {
    my $n = node(
        labels      => { 'ai.citilan.de/node-class' => 'rtx3090' },
        taints      => [ $GPU_TAINT ],
        annotations => { 'ocp.internal/managed-labels' => '["ai.citilan.de/node-class"]',
                         'ocp.internal/managed-taints' => '["nvidia.com/gpu:NoSchedule"]' },
    );
    is $M->converge_patch($n, { 'ai.citilan.de/node-class' => 'rtx3090' }, [ $GPU_TAINT ]), undef,
        'idempotent';
    is $M->converge_patch(node(), undef, undef), undef, 'nothing wanted, nothing managed: no patch';
};

subtest 'what OCP set and the spec dropped goes; what others set stays' => sub {
    my $n = node(
        labels      => { 'ai.citilan.de/node-class' => 'rtx3090', 'team' => 'ml', 'kubernetes.io/hostname' => 'crag' },
        taints      => [ $GPU_TAINT, { key => 'manual', effect => 'NoExecute' } ],
        annotations => { 'ocp.internal/managed-labels' => '["ai.citilan.de/node-class"]',
                         'ocp.internal/managed-taints' => '["nvidia.com/gpu:NoSchedule"]' },
    );
    my $p = $M->converge_patch($n, {}, []);
    is_deeply $p->{metadata}{labels}, { 'ai.citilan.de/node-class' => undef },
        'the managed label is removed (null in the merge patch), team stays';
    is_deeply $p->{spec}{taints}, [ { key => 'manual', effect => 'NoExecute' } ],
        'the managed taint goes, the manual one stays';
    is_deeply $p->{metadata}{annotations},
        { 'ocp.internal/managed-labels' => undef, 'ocp.internal/managed-taints' => undef },
        'and the bookkeeping is cleared';
};

subtest 'a changed value replaces the old one' => sub {
    my $n = node(
        labels      => { 'ai.citilan.de/node-class' => 'general' },
        taints      => [ { key => 'nvidia.com/gpu', value => 'old', effect => 'NoSchedule' } ],
        annotations => { 'ocp.internal/managed-labels' => '["ai.citilan.de/node-class"]',
                         'ocp.internal/managed-taints' => '["nvidia.com/gpu:NoSchedule"]' },
    );
    my $p = $M->converge_patch($n, { 'ai.citilan.de/node-class' => 'rtx3090' }, [ $GPU_TAINT ]);
    is_deeply $p->{metadata}{labels}, { 'ai.citilan.de/node-class' => 'rtx3090' }, 'label value';
    is_deeply $p->{spec}{taints}, [ $GPU_TAINT ], 'taint value, same key and effect';
    ok !exists $p->{metadata}{annotations}, 'bookkeeping unchanged';
};

# --- where the spec comes from -------------------------------------------------

my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

sub config_for {
    my ($spec) = @_;
    my $name = 'c' . int(rand(1_000_000));
    my $f = path($tmpdir)->child("$name.yaml");
    $ocp->dump_file($f->stringify, { name => $name, control_planes => [{ provider => 'local' }], %$spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

subtest 'ocp.yaml worker pools carry labels and taints onto their OCPNodes' => sub {
    my $config = config_for({ workers => [
        { name => 'gpu', provider => 'ssh', host => 'crag.lan',
          labels => { 'ai.citilan.de/node-class' => 'rtx3090' },
          taints => [ 'nvidia.com/gpu=present:NoSchedule' ] },
        { name => 'plain', provider => 'hetzner', nodes => 1 },
    ] });
    is_deeply [ grep { /worker pool/ } $config->validate ], [], 'valid';
    my ($gpu, $plain) = OCP::Cmd::Apply::CR::worker_ocpnodes($config);
    is_deeply $gpu->{spec}{labels}, { 'ai.citilan.de/node-class' => 'rtx3090' }, 'labels';
    is_deeply $gpu->{spec}{taints}, [ $GPU_TAINT ], 'taints, parsed';
    ok !exists $plain->{spec}{labels} && !exists $plain->{spec}{taints}, 'a pool without: neither key';
};

subtest 'ocp.yaml: malformed labels and taints are reported' => sub {
    my @e = grep { /worker pool/ } config_for({ workers => [
        { name => 'gpu', provider => 'ssh', host => 'h',
          labels => { 'ai.citilan.de/l2' => JSON::MaybeXS::true, '-x' => 'y' },
          taints => [ 'gpu', 'k=v:Sometimes' ] },
        { name => 'two', provider => 'ssh', host => 'h', taints => 'k=v:NoSchedule' },
    ] })->validate;
    my $e = join "\n", @e;
    like $e, qr/worker pool 'gpu': labels\.ai\.citilan\.de\/l2: value must be a string/, 'boolean value';
    like $e, qr/worker pool 'gpu': labels: '-x' is not a valid label key/, 'bad key';
    like $e, qr/worker pool 'gpu': taint 'gpu': expected key=value:Effect/, 'taint without effect';
    like $e, qr/worker pool 'gpu': taint 'k=v:Sometimes': effect must be/, 'unknown effect';
    like $e, qr/worker pool 'two': taints must be a list/, 'taints as a string';
};

subtest 'ocp node add --label --taint' => sub {
    my $cr = OCP::Cmd::Node::Add->new(name => 'crag-gpu', role => 'worker', host => 'h',
        label => [ 'ai.citilan.de/node-class=rtx3090', 'team=ml' ],
        taint => [ 'nvidia.com/gpu=present:NoSchedule' ])->_build_cr('ssh-default');
    is_deeply $cr->{spec}{labels}, { 'ai.citilan.de/node-class' => 'rtx3090', team => 'ml' }, 'labels';
    is_deeply $cr->{spec}{taints}, [ $GPU_TAINT ], 'taints';

    my $bare = OCP::Cmd::Node::Add->new(name => 'w', role => 'worker')->_build_cr('p');
    ok !exists $bare->{spec}{labels} && !exists $bare->{spec}{taints}, 'neither flag: neither key';

    for my $case ([ label => 'nokey', qr/^--label: label 'nokey': expected key=value\n\z/ ],
                  [ taint => 'k=v',   qr/^--taint: taint 'k=v': expected key=value:Effect/ ]) {
        my ($opt, $val, $re) = @$case;
        my $cmd = OCP::Cmd::Node::Add->new(name => 'w', role => 'worker', $opt => [ $val ]);
        no warnings 'redefine';
        local *OCP::Cmd::Node::Add::_k8s = sub { die "the API was asked\n" };
        ok !eval { $cmd->execute([], []); 1 }, "--$opt $val dies";
        like $@, $re, '... before the API is asked, with the reason';
    }
};

# --- OCP::Node: join and convergence ---------------------------------------------

package FakeProvider { sub new { bless {}, shift } }
package FakeSSH { sub new { bless {}, shift } sub wait_for_ssh { 1 } }
package FakeRex {
    our @calls;
    sub new { bless {}, shift }
    sub run_task { my ($s, $task, %p) = @_; push @calls, [ $task, \%p ]; 1 }
}

package FakeK8s {
    sub new { my ($c, %a) = @_; bless { patches => [], conflicts => 0, %a }, $c }
    sub get {
        my ($s, $kind, %a) = @_;
        return $s->{node};
    }
    sub patch {
        my ($s, $kind, %a) = @_;
        push @{ $s->{patches} }, \%a;
        die "Kubernetes API error (patch Node): 409 Conflict\n" if $s->{conflicts}-- > 0;
        return 1;
    }
}

package main;

sub load_ocp_node {
    require OCP::Versions;
    require OCP::Node;
    no warnings 'redefine', 'once';
    *OCP::Versions::get_component_version = sub { 'v9.9.9' };
    *OCP::K8s::patch_status               = sub { return; };
}
load_ocp_node();

sub ocpnode {
    my (%o) = @_;
    return {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
        metadata   => { name => 'crag', namespace => 'ocp-system', resourceVersion => '1' },
        spec       => { role => 'worker', providerRef => 'ssh-default',
                        labels => { 'ai.citilan.de/node-class' => 'rtx3090',
                                    'node-role.kubernetes.io/gpu' => '' },
                        taints => [ $GPU_TAINT ] },
        status     => { phase => $o{phase} // 'Installing', publicIP => '10.0.0.9' },
    };
}

sub ocp_node {
    my ($k8s, %o) = @_;
    return OCP::Node->from_cr(ocpnode(%o),
        k8s => $k8s, provider => FakeProvider->new, ssh_key => 'KEY',
        server_url => 'https://cp:9345', join_token => 'T',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex');
}

subtest 'the install hands the kubelet-settable labels to the join' => sub {
    @FakeRex::calls = ();
    ocp_node(FakeK8s->new)->_install_kubernetes;
    is_deeply $FakeRex::calls[0][1]{node_labels}, [ 'ai.citilan.de/node-class=rtx3090' ],
        'node_labels, without node-role.kubernetes.io';
};

my $READY_NODE = {
    metadata => { name => 'crag', resourceVersion => '42', labels => {} },
    spec     => {},
    status   => { conditions => [ { type => 'Ready', status => 'True' } ] },
};

subtest 'Joining: the registered Node is converged' => sub {
    my $k8s = FakeK8s->new(node => $READY_NODE);
    ok ocp_node($k8s, phase => 'Joining')->_wait_ready, 'Ready';
    is scalar @{ $k8s->{patches} }, 1, 'one patch';
    my $p = $k8s->{patches}[0];
    is $p->{type}, 'merge', 'a JSON merge patch';
    is $p->{name}, 'crag', 'on the Node';
    is_deeply $p->{patch}{metadata}{labels},
        { 'ai.citilan.de/node-class' => 'rtx3090', 'node-role.kubernetes.io/gpu' => '' },
        'every label, the restricted one included';
    is_deeply $p->{patch}{spec}{taints}, [ $GPU_TAINT ], 'the taint';
};

subtest 'Ready: converged again; a 409 reads the Node again and retries' => sub {
    my $k8s = FakeK8s->new(node => $READY_NODE, conflicts => 1);
    ok ocp_node($k8s, phase => 'Ready')->_verify, 'still Ready';
    is scalar @{ $k8s->{patches} }, 2, 'patched twice: the conflict, then the retry';
};

subtest 'a failing patch warns and leaves the node Ready' => sub {
    my $k8s = FakeK8s->new(node => $READY_NODE, conflicts => 99);
    my @w;
    local $SIG{__WARN__} = sub { push @w, @_ };
    ok ocp_node($k8s, phase => 'Ready')->_verify, 'Ready all the same';
    like "@w", qr{labels/taints of Node/crag not applied}, 'and says so';
};

# --- the Rexfile passes node_labels to the library ------------------------------

subtest 'Rexfile: node_labels into install_agent and install_server' => sub {
    my $agent  = { OCPTest::Rexfile->helper('_agent_opts')->('rke2',
        { server => 's', token => 't', node_labels => [ 'a=b' ] }) };
    is_deeply $agent->{node_labels}, [ 'a=b' ], 'agent';
    my $server = { OCPTest::Rexfile->helper('_server_opts')->('rke2',
        { token => 't', node_labels => [ 'a=b' ] }, []) };
    is_deeply $server->{node_labels}, [ 'a=b' ], 'server';
    my $none = { OCPTest::Rexfile->helper('_agent_opts')->('rke2', { server => 's', token => 't' }) };
    ok !exists $none->{node_labels}, 'none given: none passed';
};

done_testing;

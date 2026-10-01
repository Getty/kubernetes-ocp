#!/usr/bin/env perl
# karr k208 -- a worker without a per-node GPU flag follows gpu.enabled.
#
# The OCPNode CRD declared spec.gpu with `default: false`. `ocp node add`
# without --gpu leaves the field out, and so does `ocp apply` for the workers
# in ocp.yaml -- but the API server stamps the schema default into the stored
# CR, so OCP::Node read an explicit "no GPU on this node" and handed gpu => 0
# to Rex, even on a cluster with gpu.enabled: true. Live: crag (RTX 3090)
# joined without driver or toolkit.
#
# This file walks the whole path: the CR the CLI writes, the defaulting the
# API server applies from the shipped CRD schema, and the install parameters
# OCP::Node builds from the result. Absent spec.gpu means "inherit"; an
# explicit spec.gpu stays a per-node decision, and gpu.enabled: false stays
# the cluster kill switch.

use strict;
use warnings;
use Test::More;
use JSON::PP ();
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Node::Add;
use OCP::Cmd::Apply::CR;

package FakeProvider {
    sub new              { my ($c, %a) = @_; bless {%a}, $c }
    sub create_server    { { id => 'S1', ip => '1.2.3.4' } }
    sub delete_server    { 1 }
    sub wait_for_running { $_[1]{ip} = '9.9.9.9'; return $_[1] }
}

package FakeSSH {
    sub new          { my ($c, %a) = @_; bless {%a}, $c }
    sub wait_for_ssh { 1 }
}

package FakeRex {
    our @_instances;
    sub new { my ($c, %a) = @_; my $s = bless { %a, calls => [] }, $c; push @_instances, $s; $s }
    sub run_task {
        my ($s, $task, %p) = @_;
        push @{$s->{calls}}, [$task, \%p];
        return 1;
    }
}

package _Anything { sub new { bless {}, shift } }

package main;

my $crd = YAML::XS::Load(
    path(__FILE__)->parent->parent->child('share/robocop/crds/ocpnode.yaml')->slurp_raw
);
my $spec_schema = $crd->{spec}{versions}[0]{schema}{openAPIV3Schema}{properties}{spec};

# What the API server does on create for a structural schema: every property
# the object leaves out and the schema carries a `default:` for is filled in,
# recursively. Enough of it for the flat OCPNode spec.
sub apply_schema_defaults {
    my ($schema, $obj) = @_;
    my $props = $schema->{properties} or return $obj;
    for my $k (keys %$props) {
        if (!exists $obj->{$k}) {
            $obj->{$k} = $props->{$k}{default} if exists $props->{$k}{default};
        } elsif (ref $obj->{$k} eq 'HASH') {
            apply_schema_defaults($props->{$k}, $obj->{$k});
        }
    }
    return $obj;
}

sub load_ocp_node {
    return 1 if $OCP::Node::LOADED_208;
    eval { require OCP::Versions; require OCP::Node; 1 }
        or plan skip_all => 'load chain incomplete on this host: '.$@;
    no warnings 'redefine', 'once';
    *OCP::Versions::get_component_version = sub { 'v9.9.9' };
    *OCP::K8s::patch_status               = sub { return; };
    $OCP::Node::LOADED_208 = 1;
    return 1;
}

# The install parameters OCP::Node hands to Rex for a stored CR spec, with the
# cluster-wide gpu flags the OCPNodeProvider CR carries.
sub install_params {
    my ($spec, %gpu_flags) = @_;
    load_ocp_node();
    @FakeRex::_instances = ();
    my $cr = {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => 'crag-gpu', namespace => 'ocp-system', resourceVersion => '1' },
        spec       => $spec,
        status     => { phase => 'Installing', publicIP => '10.230.30.250' },
    };
    my $node = OCP::Node->from_cr($cr,
        k8s        => _Anything->new,
        provider   => FakeProvider->new,
        ssh_key    => 'KEY',
        server_url => 'https://cp:9345',
        join_token => 'TOKEN',
        ssh_class  => 'FakeSSH',
        rex_class  => 'FakeRex',
        %gpu_flags,
    );
    $node->_install_kubernetes;
    return $FakeRex::_instances[0]{calls}[0][1];
}

# What OCP::Rex makes of the parameter: absent means its `// 1` default.
sub rex_gpu { my ($p) = @_; return ($p->{gpu} // 1) ? 1 : 0 }

subtest 'the OCPNode CRD carries no default for spec.gpu' => sub {
    ok exists $spec_schema->{properties}{gpu}, 'spec.gpu is declared';
    is $spec_schema->{properties}{gpu}{type}, 'boolean', 'as a boolean';
    ok !exists $spec_schema->{properties}{gpu}{default},
        'no schema default -- an absent flag stays absent in the stored CR';
};

subtest 'ocp node add without --gpu on a gpu.enabled: true cluster' => sub {
    my $cr = OCP::Cmd::Node::Add->new(name => 'crag-gpu', role => 'worker',
                                      host => '10.230.30.250')->_build_cr('ssh-default');
    ok !exists $cr->{spec}{gpu}, 'the CLI leaves spec.gpu out';

    my $stored = apply_schema_defaults($spec_schema, { %{ $cr->{spec} } });
    ok !exists $stored->{gpu}, 'the API server adds nothing';

    my $p = install_params($stored, gpu_enabled => 1, gpu_driver => 'host');
    is rex_gpu($p), 1, 'Rex runs GPU detection -- gpu.enabled decides';
    is $p->{gpu_driver}, 'host', 'with the cluster driver';
};

subtest 'workers from ocp.yaml on a gpu.enabled: true cluster' => sub {
    my $config = bless { workers => [ { name => 'gpu', provider => 'ssh', host => 'crag.lan' } ] },
                       'FakeConfig208';
    { no strict 'refs'; *{'FakeConfig208::workers'} = sub { $_[0]{workers} } }
    my ($cr) = OCP::Cmd::Apply::CR::worker_ocpnodes($config);
    my $stored = apply_schema_defaults($spec_schema, { %{ $cr->{spec} } });
    ok !exists $stored->{gpu}, 'no spec.gpu after defaulting';
    is rex_gpu(install_params($stored, gpu_enabled => 1)), 1, 'GPU detection runs';
};

subtest 'gpu.enabled: false still switches every node off' => sub {
    my $stored = apply_schema_defaults($spec_schema, { role => 'worker', providerRef => 'p' });
    is rex_gpu(install_params($stored, gpu_enabled => 0)), 0, 'absent flag: off';
    is rex_gpu(install_params({ role => 'worker', providerRef => 'p', gpu => JSON::PP::true },
                              gpu_enabled => 0)), 0,
        'even spec.gpu: true: off -- the kill switch wins';
};

subtest 'an explicit per-node flag still decides' => sub {
    is rex_gpu(install_params({ role => 'worker', providerRef => 'p', gpu => JSON::PP::false },
                              gpu_enabled => 1)), 0,
        'spec.gpu: false opts this node out on a GPU cluster';
    is rex_gpu(install_params({ role => 'worker', providerRef => 'p', gpu => JSON::PP::true },
                              gpu_enabled => 1)), 1,
        'spec.gpu: true keeps it on';
};

done_testing;

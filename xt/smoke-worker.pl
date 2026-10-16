#!/usr/bin/env perl
#
# Helper for the worker step of xt/smoke.sh (k29). The shell script drives
# the cluster; everything that needs real parsing lives here, so t/ can test
# it without a cluster (t/229-smoke-worker.t) and smoke.sh does not grow its
# own half-JSON, half-YAML handling in sed.
#
#   smoke-worker.pl config   OCP_YAML --mode ssh|hetzner [--host H] [--pool P]
#                            [--server-type T] [--location L]
#       Adds one worker pool to the ocp.yaml `ocp init` wrote. Prints the
#       pool name.
#   smoke-worker.pl pick     --pool P            (`ocp node ls --json` on STDIN)
#       Prints name, phase, kubernetesNodeName and host of the pool's node,
#       tab separated, empty field for null. Exit 1 when the pool has no node.
#   smoke-worker.pl pod      --node K8S_NODE [--image I]
#       Prints a Pod manifest (JSON, which kubectl takes as it is) pinned to
#       the Kubernetes node by kubernetes.io/hostname.
#   smoke-worker.pl hcloud-count --cluster NAME  (token in $HETZNER_API_TOKEN)
#       Prints how many servers carry the label ocp-cluster=NAME at Hetzner.
#
# Runs inside the OCP image (YAML::XS, JSON::MaybeXS, WWW::Hetzner are there);
# `config`, `pick` and `pod` run anywhere those two modules load.
#
use strict;
use warnings;
use Getopt::Long qw(GetOptionsFromArray);
use JSON::MaybeXS ();
use YAML::XS ();

# The pool every smoke worker lives in. One name, so `pick` finds it again
# without asking anyone what the node was called.
use constant POOL => 'smoke-workers';

# registry.k8s.io/pause is already on every node (kubelet needs it for each
# pod sandbox), so the test pod starts without pulling anything.
use constant POD_IMAGE => 'registry.k8s.io/pause:3.10';

sub add_worker_pool {
    my ($file, %o) = @_;
    my $mode = $o{mode} // '';
    die "mode must be ssh or hetzner, got '$mode'\n" unless $mode =~ /\A(?:ssh|hetzner)\z/;
    my $pool = $o{pool} // POOL;

    my $spec = YAML::XS::LoadFile($file);
    die "$file has no cluster name -- not an ocp.yaml\n" unless $spec->{name};
    die "pool '$pool' is already in $file\n"
        if grep { ($_->{name} // '') eq $pool } @{ $spec->{workers} // [] };

    my %entry = (name => $pool, provider => $mode);
    if ($mode eq 'ssh') {
        die "an ssh worker needs a host\n" unless length($o{host} // '');
        $entry{nodes} = [ $o{host} ];
    } else {
        $entry{nodes}       = 1;
        $entry{server_type} = $o{server_type} if length($o{server_type} // '');
        $entry{location}    = $o{location}    if length($o{location}    // '');
    }
    push @{ $spec->{workers} }, \%entry;

    YAML::XS::DumpFile($file, $spec);
    return $pool;
}

sub pick_node {
    my ($json, $pool) = @_;
    $pool //= POOL;
    my $rows = JSON::MaybeXS->new->decode($json);
    for my $row (@$rows) {
        next unless ($row->{pool} // '') eq $pool;
        return [ map { $row->{$_} // '' } qw(name phase kubernetesNodeName host) ];
    }
    return undef;
}

sub pod_manifest {
    my ($node, $image) = @_;
    die "pod: the Kubernetes node name is required\n" unless length($node // '');
    return {
        apiVersion => 'v1',
        kind       => 'Pod',
        metadata   => { name => 'smoke-worker-pod', namespace => 'default' },
        spec       => {
            nodeSelector  => { 'kubernetes.io/hostname' => $node },
            tolerations   => [ { operator => 'Exists' } ],
            containers    => [ { name => 'pause', image => $image // POD_IMAGE } ],
            restartPolicy => 'Never',
        },
    };
}

sub hcloud_count {
    my ($cluster) = @_;
    my $token = $ENV{HETZNER_API_TOKEN}
        or die "hcloud-count: HETZNER_API_TOKEN is not set\n";
    require OCP::Provider::Hetzner;
    my $servers = OCP::Provider::Hetzner->new(token => $token, cluster_name => $cluster)
        ->list_servers_by_cluster($cluster);
    return scalar @{ $servers // [] };
}

sub main {
    my ($cmd, @args) = @_;
    $cmd //= '';
    my %o;
    if ($cmd eq 'config') {
        my $file = shift @args or die "config: ocp.yaml path required\n";
        GetOptionsFromArray(\@args, \%o, qw(mode=s host=s pool=s server-type=s location=s))
            or die "config: bad options\n";
        $o{server_type} = delete $o{'server-type'};
        print add_worker_pool($file, %o), "\n";
    }
    elsif ($cmd eq 'pick') {
        GetOptionsFromArray(\@args, \%o, qw(pool=s)) or die "pick: bad options\n";
        my $json = do { local $/; <STDIN> };
        my $row  = pick_node($json, $o{pool}) or return 1;
        print join("\t", @$row), "\n";
    }
    elsif ($cmd eq 'pod') {
        GetOptionsFromArray(\@args, \%o, qw(node=s image=s)) or die "pod: bad options\n";
        print JSON::MaybeXS->new(canonical => 1)->encode(pod_manifest($o{node}, $o{image})), "\n";
    }
    elsif ($cmd eq 'hcloud-count') {
        GetOptionsFromArray(\@args, \%o, qw(cluster=s)) or die "hcloud-count: bad options\n";
        die "hcloud-count: --cluster required\n" unless $o{cluster};
        print hcloud_count($o{cluster}), "\n";
    }
    else {
        die "usage: smoke-worker.pl config|pick|pod|hcloud-count ...\n";
    }
    return 0;
}

exit main(@ARGV) unless caller;

1;

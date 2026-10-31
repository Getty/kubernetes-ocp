#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';
use OCP;
use OCP::Config;

#
# k299: validate() refused a network.pod_cidr that contains a node address
# (k182; control_planes[].node_ip since k279), but never held the same
# addresses against the service network -- RKE2's and K3s's built-in
# service-cidr 10.43.0.0/16, which ocp.yaml has no key for and OCP never
# changes ($OCP::Config::SERVICE_CIDR). An address in there can be handed to
# a Service as its ClusterIP, and routing to the node breaks as badly as
# inside the pod network.
#
# The claims here:
#   1. every address the pod-CIDR check holds against network.pod_cidr is
#      held against the service network too: a control plane's host,
#      public_ip, private_ip and node_ip (its IPv4 part), a worker pool's
#      host and its nodes' hosts, the LB pool;
#   2. in the words of the pod-CIDR line, with "default" in it, as the
#      pod-CIDR line has when network.pod_cidr is not set -- and what to do,
#      since there is no key to move it;
#   3. what the pod-CIDR check leaves out, this one leaves out: a host name
#      (not resolved), a node_ip refused for its syntax, one node_ip shared
#      by nodes: N;
#   4. it does not depend on the pod CIDR being valid.
#

my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

sub config_for {
    my ($spec) = @_;
    my $f = path($tmpdir)->child('c' . int(rand(1_000_000)) . '.yaml');
    $ocp->dump_file($f->stringify, { name => 'k299', %$spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

sub service_errors { grep { /service network/ && !/^network\.pod_cidr/ } config_for(@_)->validate }

my $HINT = ' -- ocp.yaml has no key to move it; use an address outside it';
sub line { "the service network (default 10.43.0.0/16) overlaps $_[0]$HINT" }

my $ssh = sub { +{ provider => 'ssh', host => $_[0], @_[1 .. $#_] } };

is $OCP::Config::SERVICE_CIDR, '10.43.0.0/16', 'the service network is the RKE2/K3s default';

# --- 1 + 2. every address, in the pod-CIDR words ------------------------------

subtest 'a control plane address inside the service network' => sub {
    is_deeply [ service_errors({ control_planes => $ssh->('10.43.0.5') }) ],
        [ line('control_planes[1].host 10.43.0.5') ], 'host' ;

    is_deeply [ service_errors({ control_planes => [ $ssh->('otho.lab'),
                                                     $ssh->('crag.lab', public_ip => '10.43.1.2') ] }) ],
        [ line('control_planes[2].public_ip 10.43.1.2') ], 'public_ip, the right entry';

    is_deeply [ service_errors({ control_planes => $ssh->('otho.lab', private_ip => '10.43.255.254') }) ],
        [ line('control_planes[1].private_ip 10.43.255.254') ], 'private_ip, at the top of the range';

    is_deeply [ service_errors({ control_planes => $ssh->('otho.lab', node_ip => '10.43.0.9') }) ],
        [ line('control_planes[1].node_ip 10.43.0.9') ], 'node_ip';

    is_deeply [ service_errors({ control_planes => $ssh->('otho.lab', node_ip => 'fd00::9,10.43.0.9') }) ],
        [ line('control_planes[1].node_ip 10.43.0.9') ], 'node_ip dual-stack: its IPv4 part';
};

subtest 'a worker pool address inside the service network' => sub {
    is_deeply [ service_errors({ control_planes => $ssh->('otho.lab'),
                                 workers => [ { name => 'w', provider => 'ssh', host => '10.43.7.7' } ] }) ],
        [ line("worker pool 'w' host 10.43.7.7") ], 'the pool host';

    is_deeply [ service_errors({ control_planes => $ssh->('otho.lab'),
                                 workers => [ { name => 'w', provider => 'ssh',
                                                nodes => [ '10.5.0.1', { host => '10.43.7.8' } ] } ] }) ],
        [ line("worker pool 'w' host 10.43.7.8") ], 'a host in its nodes list';
};

subtest 'the LB pool inside the service network' => sub {
    is_deeply [ service_errors({ control_planes => $ssh->('otho.lab'),
                                 network => { lb_pool => { cidr => '10.43.200.0/28' } } }) ],
        [ line('network.lb_pool 10.43.200.0/28') ], 'cidr';

    is_deeply [ service_errors({ control_planes => $ssh->('otho.lab'),
                                 network => { lb_pool => { cidr => '10.0.0.0/8' } } }) ],
        [ line('network.lb_pool 10.0.0.0/8') ], 'a cidr around it';

    is_deeply [ service_errors({ control_planes => $ssh->('otho.lab'),
                                 network => { lb_pool => { start => '10.43.0.240', stop => '10.43.0.249' } } }) ],
        [ line('network.lb_pool.start 10.43.0.240'), line('network.lb_pool.stop 10.43.0.249') ],
        'start and stop';
};

subtest 'in the words of the pod-CIDR line' => sub {
    my @all = config_for({ control_planes => [ $ssh->('otho.lab', node_ip => '10.42.0.5'),
                                               $ssh->('crag.lab', node_ip => '10.43.0.5') ] })->validate;
    my ($pod)     = grep { /^network\.pod_cidr/ } @all;
    my ($service) = grep { /^the service network/ } @all;
    like $pod,     qr/^network\.pod_cidr \(default 10\.42\.0\.0\/16\) overlaps control_planes\[1\]\.node_ip 10\.42\.0\.5 -- /,
        'the pod-CIDR line';
    like $service, qr/^the service network \(default 10\.43\.0\.0\/16\) overlaps control_planes\[2\]\.node_ip 10\.43\.0\.5 -- /,
        'the service line: "(default ...) overlaps <key> <address> -- <what to do>"';
    is scalar(@all), 2, 'and nothing else' or diag explain \@all;
};

# --- 3. what it leaves out ----------------------------------------------------

subtest 'what is not a node address here, is not one there' => sub {
    is_deeply [ service_errors({ control_planes => $ssh->('10.43.x.lab') }) ], [], 'a host name is not resolved';
    is_deeply [ service_errors({ control_planes => $ssh->('10.44.0.1') }) ], [], 'next to it: nothing';
    is_deeply [ service_errors({ control_planes => $ssh->('10.42.255.255') }) ], [], 'below it: nothing';
    is_deeply [ service_errors({ control_planes => $ssh->('otho.lab', node_ip => 'fd00::43') }) ], [],
        'IPv6 only: no IPv6 service network to overlap';
    # Refused for the space; its IPv4 part alone would be counted.
    is_deeply [ service_errors({ control_planes => $ssh->('otho.lab', node_ip => '10.43.0.5, fd00::1') }) ], [],
        'a node_ip refused for its syntax is not counted here';
    is_deeply [ service_errors({ control_planes => { %{ $ssh->('otho.lab', node_ip => '10.43.0.5') }, nodes => 3 } }) ],
        [], 'nodes: 3 sharing one node_ip: refused once for that, not here';
};

# --- 4. independent of the pod CIDR -------------------------------------------

subtest 'checked when the pod CIDR is invalid too' => sub {
    is_deeply [ service_errors({ control_planes => $ssh->('10.43.0.5'), network => { pod_cidr => 'foo' } }) ],
        [ line('control_planes[1].host 10.43.0.5') ], 'pod_cidr: foo';
    is_deeply [ service_errors({ control_planes => $ssh->('10.43.0.5'), network => { pod_cidr => '172.20.0.0/16' } }) ],
        [ line('control_planes[1].host 10.43.0.5') ], 'a pod_cidr of its own';
};

done_testing;

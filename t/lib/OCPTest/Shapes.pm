package OCPTest::Shapes;
# ABSTRACT: The YAML shapes and the ocp.yaml key paths t/296 sweeps validate() over

use strict;
use warnings;
use Exporter 'import';
use JSON::PP ();

our @EXPORT_OK = qw( shapes at );

# Moved out of t/296-validate-malformed-shapes.t (k400) as they stood there, so
# that t/306 (spec_errors at every path) and t/400 (every command on every
# malformed path) sweep the very shapes and paths validate() is swept over.
#
#   shapes()  ([ shown, value ], ...): a scalar, a number, both booleans, null,
#             the empty list, a list, a list of a mapping, the empty mapping, a
#             mapping
#   at()      ([ path, sub { spec } ], ...): each key validate() reads, top level
#             and below; the sub puts its argument at that path of a spec that
#             is valid around it (a local control plane, an ssh pool), without
#             a name

my @SHAPES = (
    [ "'foo'" => 'foo' ], [ '7' => 7 ], [ 'true' => JSON::PP::true ], [ 'false' => JSON::PP::false ],
    [ 'null' => undef ], [ '[]' => [] ], [ "['foo']" => [ 'foo' ] ], [ '[{}]' => [ {} ] ],
    [ '{}' => {} ], [ '{foo: bar}' => { foo => 'bar' } ],
);

my $cp = sub { +{ provider => 'local', @_ } };
my $wp = sub { +{ name => 'w', provider => 'ssh', host => '10.9.0.1', @_ } };
my @AT = (
    [ 'name'                      => sub { +{ control_planes => $cp->(), name => $_[0] } } ],
    [ 'control_planes'            => sub { +{ control_planes => $_[0] } } ],
    [ 'control_planes[1]'         => sub { +{ control_planes => [ $_[0] ] } } ],
    [ 'control_planes[2]'         => sub { +{ control_planes => [ $cp->(), $_[0] ] } } ],
    [ 'control_planes.nodes'      => sub { +{ control_planes => $cp->(nodes => $_[0]) } } ],
    # the eighth of a list that holds one too many (k315)
    [ 'control_planes[8]'         => sub { +{ control_planes => [ (map { $cp->() } 1 .. 7), $_[0] ] } } ],
    (map { my $k = $_;
        [ "control_planes.$k"     => sub { +{ control_planes => $cp->($k => $_[0]) } } ],
        [ "control_planes[1].$k"  => sub { +{ control_planes => [ $cp->($k => $_[0]) ] } } ],
     } qw( provider host public_ip private_ip node_ip server_type location image )),
    [ 'workers'                   => sub { +{ control_planes => $cp->(), workers => $_[0] } } ],
    [ 'workers[1]'                => sub { +{ control_planes => $cp->(), workers => [ $_[0] ] } } ],
    (map { my $k = $_;
        [ "workers[1].$k"         => sub { +{ control_planes => $cp->(), workers => [ $wp->($k => $_[0]) ] } } ],
     } qw( name provider host nodes labels taints node_ip server_type location image )),
    [ 'workers[1].nodes[1]'       => sub { +{ control_planes => $cp->(), workers => [ $wp->(nodes => [ $_[0] ]) ] } } ],
    # k315: an entry's host, and the nodes of a pool that counts its machines
    [ 'workers[1].nodes[1].host'  => sub { +{ control_planes => $cp->(), workers => [ $wp->(nodes => [ { host => $_[0] } ]) ] } } ],
    # k322: an ssh pool with nodes and no host
    [ 'workers[1].nodes, no host' => sub { +{ control_planes => $cp->(), workers => [ {
                                     name => 'w', provider => 'ssh', nodes => $_[0] } ] } } ],
    [ 'workers[1].nodes, hetzner' => sub { +{ control_planes => $cp->(), workers => [ {
                                     name => 'w', provider => 'hetzner', server_type => 'cx22', nodes => $_[0] } ] } } ],
    # a host in the pod CIDR, so the pool is named in that line too (k305)
    [ 'workers[1].name, host 10.42.0.5' => sub { +{ control_planes => $cp->(),
                                     workers => [ $wp->(name => $_[0], host => '10.42.0.5') ] } } ],
    # k331: a pool that takes no host
    [ 'workers[1].host, hetzner'  => sub { +{ control_planes => $cp->(), workers => [ {
                                     name => 'w', provider => 'hetzner', server_type => 'cx22', host => $_[0] } ] } } ],
    [ 'workers[1].host, local'    => sub { +{ control_planes => $cp->(), workers => [ {
                                     name => 'w', provider => 'local', host => $_[0] } ] } } ],
    [ 'network'                   => sub { +{ control_planes => $cp->(), network => $_[0] } } ],
    (map { my $k = $_;
        [ "network.$k"            => sub { +{ control_planes => $cp->(), network => { $k => $_[0] } } } ],
     } qw( pod_cidr lb_pool l2 )),
    (map { my $k = $_;
        [ "network.lb_pool.$k"    => sub { +{ control_planes => $cp->(), network => { lb_pool => { $k => $_[0] } } } } ],
     } qw( cidr start stop )),
    (map { my $k = $_;
        [ "network.l2.$k"         => sub { +{ control_planes => $cp->(), network => { l2 => { $k => $_[0] } } } } ],
     } qw( node_selector interfaces )),
    [ 'cilium'                    => sub { +{ control_planes => $cp->(), cilium => $_[0] } } ],
    (map { my $k = $_;
        [ "cilium.$k"             => sub { +{ control_planes => $cp->(), cilium => { $k => $_[0] } } } ],
     } qw( devices helm_values )),
    [ 'gpu'                       => sub { +{ control_planes => $cp->(), gpu => $_[0] } } ],
    (map { my $k = $_;
        [ "gpu.$k"                => sub { +{ control_planes => $cp->(), gpu => { $k => $_[0] } } } ],
     } qw( enabled driver toolkit amd enable )),    # enable: no key of gpu's (k331)
    (map { my $k = $_;
        [ "gpu.amd.$k"            => sub { +{ control_planes => $cp->(), gpu => { amd => { $k => $_[0] } } } } ],
     } qw( allocation resource_naming labeller metrics integrated alocation )),
    [ 'robocop'                   => sub { +{ control_planes => $cp->(), robocop => $_[0] } } ],
    (map { my $k = $_;
        [ "robocop.$k"            => sub { +{ control_planes => $cp->(), robocop => { $k => $_[0] } } } ],
     } qw( enabled security_level image enable )),    # enable: no key of robocop's (k315)
    # the other switches (k320)
    (map { my $k = $_;
        [ $k                      => sub { +{ control_planes => $cp->(), $k => $_[0] } } ],
     } qw( lbipam nocert system )),
    [ 'system.ntp'                => sub { +{ control_planes => $cp->(), system => { ntp => $_[0] } } } ],
    (map { my $k = $_;
        [ "system.$k"             => sub { +{ control_planes => $cp->(), system => { $k => $_[0] } } } ],
     } qw( timezone locale time_zone )),    # time_zone: no key of system's (k331)
    # k340
    [ 'kubernetes'                => sub { +{ control_planes => $cp->(), kubernetes => $_[0] } } ],
    (map { my $k = $_;
        [ "kubernetes.$k"         => sub { +{ control_planes => $cp->(), kubernetes => { $k => $_[0] } } } ],
     } qw( dist version distribution )),    # distribution: no key of kubernetes' (k355)
    [ 'ssh'                       => sub { +{ control_planes => $cp->(), ssh => $_[0] } } ],
    (map { my $k = $_;
        [ "ssh.$k"                => sub { +{ control_planes => $cp->(), ssh => { $k => $_[0] } } } ],
     } qw( private_key public_key )),
    # k347: the keys read that no line checks, and keys nothing reads
    (map { my $k = $_;
        [ "control_planes.$k"     => sub { +{ control_planes => $cp->($k => $_[0]) } } ],
        [ "control_planes[1].$k"  => sub { +{ control_planes => [ $cp->($k => $_[0]) ] } } ],
     } qw( name service count nodez )),
    [ 'control_planes[1].nodes'   => sub { +{ control_planes => [ $cp->(nodes => $_[0]) ] } } ],
    (map { my $k = $_;
        [ "workers[1].$k"         => sub { +{ control_planes => $cp->(), workers => [ $wp->($k => $_[0]) ] } } ],
        [ "workers[1].$k, hetzner" => sub { +{ control_planes => $cp->(), workers => [ {
                                     name => 'w', provider => 'hetzner', server_type => 'cx22', $k => $_[0] } ] } } ],
     } qw( count nodez )),
    # k355: a key of an ssh pool's machine that nothing reads
    [ 'workers[1].nodes[1].name'  => sub { +{ control_planes => $cp->(), workers => [ {
                                     name => 'w', provider => 'ssh', nodes => [ { host => 'w1.k355.test', name => $_[0] } ] } ] } } ],
);

sub shapes { return @SHAPES }
sub at     { return @AT }

1;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Health;
use OCP::Cmd::Apply::Network;

#
# k462: on a control plane known only by a loopback address, LB-IPAM looks
# for the node's InternalIP; when there is none it builds the pool on
# 127.0.0.1 and says so. That line went to STDOUT, labelled "WARNING:", and
# the banner still read SUCCESSFULLY. It is a warning of the run (a pool no
# one outside reaches): a [WARN] on STDERR, counted in {_apply_warnings}, so
# the banner reads WITH WARNINGS -- as the other [WARN]s of ocp apply since
# k415. A node with another address says nothing of it.
#

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, out => $out, err => $err, died => $died };
}

{
    package Addr;
    sub new     { my ($c, $t, $a) = @_; bless { t => $t, a => $a }, $c }
    sub type    { $_[0]{t} }
    sub address { $_[0]{a} }
    package Status;
    sub new       { my ($c, @a) = @_; bless { a => [ @a ] }, $c }
    sub addresses { $_[0]{a} }
    package Node;
    sub new    { my ($c, @a) = @_; bless { s => Status->new(@a) }, $c }
    sub status { $_[0]{s} }
    package List;
    sub new   { my ($c, @n) = @_; bless { n => [ @n ] }, $c }
    sub items { $_[0]{n} }

    package Resp;
    sub new     { my ($c, $s, $b) = @_; bless { status => $s, content => $b }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }

    # list('Node') answers the nodes; the LB-IPAM API is served.
    package Api;
    sub new      { my ($c, @n) = @_; bless { n => [ @n ] }, $c }
    sub list     { List->new(@{ $_[0]{n} }) }
    sub _request { Resp->new(200, '{"items":[]}') }

    package OcpStub;
    sub new     { bless {}, shift }
    sub verbose { 0 }
}

sub lb_ipam {
    my (@addrs) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ OcpStub->new ]);
    $apply->{_k8s_api} = Api->new(Node->new(@addrs));
    my $pool_ip;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_server_side_apply_all = sub { 1 };
    local *OCP::Cmd::Apply::wait_seconds           = sub { };
    local *OCP::Cmd::Apply::_crd_get               = sub { { items => [] } };
    local *OCP::Cmd::Apply::Network::lb_ipam_resources = sub {
        $pool_ip = $_[0];
        [ { kind => 'CiliumLoadBalancerIPPool', spec => { blocks => [ { cidr => "$_[0]/32" } ] } } ]
    };
    my $r = capture { OCP::Cmd::Apply::Network::setup_lb_ipam($apply, '127.0.0.1', undef); 1 };
    $r->{pool_ip} = $pool_ip;
    $r->{apply}   = $apply;
    return $r;
}

my $HEALTHY = { critical => [], warnings => [] };
my $LINE    = "      [WARN] Only loopback IP available, LB-IPAM may not work externally\n";

subtest 'only loopback: a [WARN] on STDERR, counted' => sub {
    my $r = lb_ipam(Addr->new(InternalIP => '127.0.0.1'));
    is $r->{died}, '', 'no death' or return diag $r->{died};
    is $r->{pool_ip}, '127.0.0.1', 'the pool on it, as before';
    is $r->{err}, $LINE, 'on STDERR, in the house label, once';
    unlike $r->{out}, qr/loopback|WARN/, 'nothing of it on STDOUT';
    is_deeply $r->{apply}{_apply_warnings}, [ 'LB-IPAM loopback' ], 'counted in {_apply_warnings}';
    is OCP::Cmd::Apply::Health::banner_text($r->{apply}, $HEALTHY), 'CONTROL PLANE DEPLOYED — WITH WARNINGS',
        'the banner reads WITH WARNINGS';
};

subtest 'another address: used, nothing warned' => sub {
    my $r = lb_ipam(Addr->new(InternalIP => '127.0.0.1'), Addr->new(InternalIP => '10.0.0.7'));
    is $r->{died}, '', 'no death' or return diag $r->{died};
    is $r->{pool_ip}, '10.0.0.7', 'the pool on the InternalIP';
    like $r->{out}, qr/Using node IP 10\.0\.0\.7 \(instead of 127\.0\.0\.1\)/, 'said on STDOUT, as before';
    is $r->{err}, '', 'nothing on STDERR';
    ok !@{ $r->{apply}{_apply_warnings} // [] }, 'nothing counted';
    is OCP::Cmd::Apply::Health::banner_text($r->{apply}, $HEALTHY), 'CONTROL PLANE DEPLOYED SUCCESSFULLY!',
        'the banner as before';
};

done_testing;

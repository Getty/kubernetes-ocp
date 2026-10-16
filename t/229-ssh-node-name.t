#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Config;
use OCP::Kubernetes;
use OCP::Secrets;
use OCP::Cmd::SSH;

#
# k229, lab 2026-10-15/16: `ocp ssh --node crag` answered "Could not resolve
# hostname crag". crag was a worker with an OCPNode and an address; a name
# that is neither a control plane of ocp.yaml nor police*/cp* went straight
# to ssh as a hostname. Now the node of exactly that name is asked first --
# the OCPNode, then the Kubernetes Node -- and only then is the argument a
# hostname. police*/cp* keep their substring lookup.
#

{
    package FakeIO;
    sub new              { bless {}, $_[0] }
    sub object_to_struct { $_[1] }
}

{
    package FakeList;
    sub new   { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]{items} }
}

# Kubernetes::REST as far as OCP::Cmd::SSH uses it: get() dies with the
# status in the message, like the real client; `fail` answers every call
# with it.
{
    package FakeAPI;
    sub new {
        my ($c, %a) = @_;
        bless { ocpnodes => {}, nodes => {}, calls => [], resource_map => {}, %a }, $c;
    }
    sub k8s          { FakeIO->new }
    sub resource_map { $_[0]{resource_map} }
    sub get {
        my ($self, $kind, %args) = @_;
        push @{ $self->{calls} }, [ get => $kind, $args{name} ];
        die "$self->{fail}\n" if $self->{fail};
        my $from = $kind eq 'OCPNode' ? $self->{ocpnodes} : $self->{nodes};
        return $from->{ $args{name} } // die "404 Not Found: $kind $args{name}\n";
    }
    sub list {
        my ($self, $kind) = @_;
        push @{ $self->{calls} }, [ list => $kind ];
        die "$self->{fail}\n" if $self->{fail};
        my $from = $kind eq 'OCPNode' ? $self->{ocpnodes} : $self->{nodes};
        return FakeList->new([ map { $from->{$_} } sort keys %$from ]);
    }
}

sub ocpnode {
    my ($name, %o) = @_;
    return { metadata => { name => $name, namespace => 'ocp-system' },
             spec => { role => 'worker', %{ $o{spec} // {} } },
             status => $o{status} // {} };
}

sub k8s_node {
    my ($name, %addr) = @_;
    return { metadata => { name => $name },
             status => { addresses => [
                 map { { type => $_, address => $addr{$_} } } sort keys %addr ] } };
}

sub config {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({ name => 't',
        control_planes => { provider => 'hetzner' } }));
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    return ($config, OCP::Secrets->new(project_dir => $config->project_dir));
}

# Resolve $name against $api, with STDOUT and STDERR captured.
sub resolve {
    my ($api, $name) = @_;
    my ($config, $secrets) = config();
    no warnings 'redefine';
    local *OCP::Cmd::SSH::_kubernetes = sub { OCP::Kubernetes->new(api => $api) };

    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my $got = do {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        eval { OCP::Cmd::SSH->new(node => $name)->_resolve_target_host($config, $secrets, $name) };
    };
    return { host => $got, died => $@, out => $out, err => $err };
}

subtest 'a worker is found by its OCPNode name' => sub {
    my $api = FakeAPI->new(ocpnodes => {
        crag => ocpnode('crag', spec => { host => 'crag.lab' },
                                status => { phase => 'Failed', publicIP => '10.230.30.54' }) });
    my $r = resolve($api, 'crag');
    is $r->{host}, '10.230.30.54',
        'at status.publicIP -- the address OCP installed it over, not "crag" as a hostname';
    is $r->{out}, '', 'nothing of ocp on STDOUT, which is the session\'s';
};

subtest 'an OCPNode without publicIP is found at spec.host' => sub {
    my $api = FakeAPI->new(ocpnodes => {
        crag => ocpnode('crag', spec => { host => 'crag.lab' }, status => { phase => 'Installing' }) });
    is resolve($api, 'crag')->{host}, 'crag.lab',
        'the order OCP::Node::_resolve_host uses: publicIP, then spec.host';
};

subtest 'a Kubernetes node is matched by its exact name only' => sub {
    my $api = FakeAPI->new(nodes => {
        crag     => k8s_node('crag',   InternalIP => '10.0.0.4', ExternalIP => '198.51.100.4'),
        'crag-2' => k8s_node('crag-2', ExternalIP => '198.51.100.5'),
    });
    is resolve($api, 'crag')->{host}, '198.51.100.4', 'ExternalIP before InternalIP';

    my $only_longer = FakeAPI->new(nodes => {
        'crag-2' => k8s_node('crag-2', ExternalIP => '198.51.100.5') });
    is resolve($only_longer, 'crag')->{host}, 'crag',
        'crag-2 is not crag: no substring match, the name goes on as a hostname';
};

subtest 'a name nothing in the cluster has is still tried as a hostname' => sub {
    is resolve(FakeAPI->new, 'raichu.vm')->{host}, 'raichu.vm',
        'the IP/hostname fallback is still there, after the lookup';
};

subtest 'an OCPNode with no address yet is refused, not dialled as a hostname' => sub {
    my $api = FakeAPI->new(ocpnodes => {
        w9 => ocpnode('w9', status => { phase => 'Pending' }) });
    my $r = resolve($api, 'w9');
    is $r->{host}, undef, 'nothing to connect to';
    like $r->{died}, qr/^OCPNode 'w9' has no address yet \(phase Pending/,
        'it says what is missing, with the phase';
    unlike $r->{died}, qr/Unknown node/, 'and does not call a real node unknown';
    like $r->{died}, qr/--node <ip>/, 'and what to do instead';
};

subtest 'a cluster API that does not answer is said, and the hostname is tried' => sub {
    my $r = resolve(FakeAPI->new(fail => '500 Internal Server Error'), 'crag');
    is $r->{host}, 'crag', 'falls back to the hostname path';
    like $r->{err}, qr/Could not look up node 'crag' in the cluster API: 500/,
        'and says on STDERR why it did';
    is $r->{out}, '', 'STDOUT stays clean';
};

subtest 'an IP is not looked up' => sub {
    my $api = FakeAPI->new;
    is resolve($api, '10.0.0.7')->{host}, '10.0.0.7', 'returned as is';
    is resolve($api, '2a01:4f8::7')->{host}, '2a01:4f8::7', 'IPv6 too';
    is_deeply $api->{calls}, [], 'without a call to the API';
};

subtest 'police1 keeps its substring lookup' => sub {
    my $api = FakeAPI->new(
        nodes    => { 'ocpt-police1' => k8s_node('ocpt-police1', ExternalIP => '198.51.100.1') },
        ocpnodes => { police1 => ocpnode('police1', status => { publicIP => '192.0.2.1' }) },
    );
    my $r = resolve($api, 'police1');
    is $r->{host}, '198.51.100.1', 'the Kubernetes node whose name contains it, as before';
    ok !grep({ $_->[0] eq 'get' } @{ $api->{calls} }),
        'and the exact-name lookup is not asked when that found one';
    like $r->{err}, qr/Looking up control plane IP/, 'the progress note, on STDERR';
};

subtest 'a cp* name the substring lookup misses is still found by its exact name' => sub {
    my $api = FakeAPI->new(ocpnodes => {
        'cpu-1' => ocpnode('cpu-1', status => { publicIP => '192.0.2.9' }) });
    is resolve($api, 'cpu-1')->{host}, '192.0.2.9',
        'a worker called cpu-1 is reachable although its name starts with cp';
};

subtest 'the names offered for a typo include OCPNodes that have an address' => sub {
    my ($config, $secrets) = config();
    my $api = FakeAPI->new(
        nodes    => { 'cp-lab' => k8s_node('cp-lab', ExternalIP => '1.1.1.1') },
        ocpnodes => {
            'cp-lab' => ocpnode('cp-lab', status => { publicIP => '1.1.1.1' }),
            crag     => ocpnode('crag', spec => { host => '10.0.0.9' }),
            w9       => ocpnode('w9', status => { phase => 'Pending' }),
        },
    );
    no warnings 'redefine';
    local *OCP::Cmd::SSH::_kubernetes = sub { OCP::Kubernetes->new(api => $api) };

    is_deeply [ OCP::Cmd::SSH->new(node => 'x')->_node_names($secrets) ],
        [ 'cp-lab', 'crag' ],
        'crag, which has a host, is something ocp ssh reaches; w9 has no address and is left out';
};

done_testing;

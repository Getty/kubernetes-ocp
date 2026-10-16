#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Config;
use OCP::Node;
use OCP::Cmd::Apply::Bootstrap;

#
# k229 point 1 (lab 2026-10-15): control_planes.host: 10.230.30.212 renamed the
# machine agent-lab-2 to 10-230-30-212. The dashed form of an IP (k218, k211)
# names the Kubernetes Node and the OCPNode, which need a stable DNS-safe name;
# it is no name of the machine's, so the install leaves the hostname alone.
# A FQDN or short name keeps setting it, and the Node name does not change.
#

sub identity {
    my ($host) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({ name => 'lab',
        control_planes => { provider => 'ssh', host => $host } }));
    return OCP::Cmd::Apply::Bootstrap::cp_identity(
        OCP::Config->new(file => $dir->child('ocp.yaml')->stringify));
}

subtest 'is_address' => sub {
    ok  OCP::Cmd::Apply::Bootstrap::is_address('10.230.30.212'), 'IPv4';
    ok  OCP::Cmd::Apply::Bootstrap::is_address('2a01:4f8::20'),  'IPv6';
    ok !OCP::Cmd::Apply::Bootstrap::is_address('agent-lab-2.ai.citilan.de'), 'FQDN';
    ok !OCP::Cmd::Apply::Bootstrap::is_address('crag'), 'short name';
    ok !OCP::Cmd::Apply::Bootstrap::is_address(undef), 'undef';
};

subtest 'control plane on an IP: Node name dashed, hostname untouched' => sub {
    my $id = identity('10.230.30.212');
    is $id->{name}, '10-230-30-212', 'the Node/OCPNode name stays the k218 form';
    ok !$id->{set_hostname}, 'the machine hostname is not set';

    $id = identity('2a01:4f8::20');
    ok !$id->{set_hostname}, 'IPv6 alike';
};

subtest 'control plane on a name: hostname set as before' => sub {
    my $id = identity('cp1.lab.example');
    is $id->{hostname}, 'cp1', 'short name';
    ok $id->{set_hostname}, 'set';
    ok identity('cortex')->{set_hostname}, 'a short name too';
};

subtest 'the bootstrap gates hostname and domain on set_hostname' => sub {
    my $boot = path('lib/OCP/Cmd/Apply/Bootstrap.pm')->slurp_utf8;
    my ($call) = $boot =~ /(\$rex->install_server\(.*?\);)/s;
    like $call, qr/node_name\s*=>\s*\$cp_name\b/, 'node_name is the CP name, unconditionally';
    like $call, qr/hostname\s*=>\s*\$cp_id->\{set_hostname\}\s*\?/, 'hostname only with set_hostname';
    like $call, qr/domain\s*=>\s*\$cp_id->\{set_hostname\}\s*\?/,   'domain likewise';
};

#
# Workers: the OCPNode name is the dashed IP when a pool lists the host by IP
# (k211); `ocp node add NAME --host IP` gives a name of the operator's choosing,
# which still becomes the hostname.
#
{
    package FakeRex;
    our @calls;
    sub new      { bless {}, shift }
    sub run_task { my ($s, $task, %p) = @_; push @calls, [$task, \%p]; 1 }
}
{
    package FakeSSH;
    sub new          { bless {}, shift }
    sub wait_for_ssh { 1 }
}
{
    package FakeProvider;
    sub new              { bless {}, shift }
    sub create_server    { { id => 'S1', ip => '10.230.30.250' } }
    sub wait_for_running { $_[1] }
}
{
    package Anything;
    sub new { bless {}, shift }
}

sub worker_params {
    my ($name, $host) = @_;
    no warnings 'redefine', 'once';
    local *OCP::Versions::get_component_version = sub { 'v9.9.9' };
    local *OCP::K8s::patch_status = sub { return };
    @FakeRex::calls = ();
    my $node = OCP::Node->from_cr({
            apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => $name, namespace => 'ocp-system', resourceVersion => '1' },
            spec     => { role => 'worker', providerRef => 'ssh-default', host => $host },
            status   => { phase => 'Installing', publicIP => $host },
        },
        k8s => Anything->new, provider => FakeProvider->new,
        ssh_key => 'KEY', server_url => 'https://cp:9345', join_token => 'TOKEN',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
    );
    $node->_install_kubernetes;
    return $FakeRex::calls[0][1];
}

subtest 'worker named after its IP: hostname untouched' => sub {
    my $p = worker_params('10-230-30-250', '10.230.30.250');
    ok $p, 'the install task ran' or return;
    is $p->{node_name}, '10-230-30-250', 'node_name is the OCPNode name';
    ok !exists $p->{hostname}, 'no hostname for the machine';
};

subtest 'worker with a name of its own: hostname set as before' => sub {
    my $p = worker_params('crag', '10.230.30.250');
    is $p->{node_name}, 'crag', 'node_name';
    is $p->{hostname},  'crag', 'a chosen name still becomes the hostname';

    $p = worker_params('otho-lab', 'otho-lab.ai.citilan.de');
    is $p->{hostname}, 'otho-lab', 'FQDN host as before';
};

done_testing;

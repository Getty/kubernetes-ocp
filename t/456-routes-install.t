#!/usr/bin/env perl
# karr k456: routes: reach the install task with via resolved -- ocp apply's
# bootstrap for police1, OCP::Node for every node robocop (or ocp apply)
# installs.
#
# The claims:
#
#   1. gateway_of_range is the first address of a network's ip_range (the
#      network address plus one), whatever address inside it is written, and
#      undef for anything that is no IPv4 CIDR
#   2. OCP::Provider::Hetzner network_gateway reads the existing network's
#      ip_range (name looked up, id taken), resolve_routes turns via: gateway
#      into it -- the network looked up once, only when a route names
#      gateway -- and leaves an address as it is; a network that is not
#      there, a gateway without a network, and an ip_range that is none die;
#      nothing on the network is written
#   3. OCP::Rex install_server and install_agent hand routes on as the task
#      parameter of that name, an empty list too, and no parameter without a
#      list
#   4. the bootstrap resolves police1's routes before create_server -- a
#      route that cannot be resolved orders no server -- and hands them to
#      install_server; on Hetzner an empty list when ocp.yaml lists none
#   5. OCP::Node resolves spec.routes through its provider and hands them to
#      the install task (an empty list for none); a resolution that dies fails
#      the node with 'spec.routes: <why>' before the Rex run; a provider
#      without resolve_routes (ssh, local) hands no routes parameter
#
# Network-free: the cloud, the provider, SSH and Rex are stand-ins.

use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Config;
use OCP::K8s;
use OCP::KnownHosts;
use OCP::Node;
use OCP::Provider::Hetzner;
use OCP::Rex;
use OCP::Secrets;
use OCP::SSH;
use OCP::Versions;

no warnings 'once';

# ---------------------------------------------------------------- 1

subtest 'gateway_of_range: the first address of the network' => sub {
    my $g = \&OCP::Provider::Hetzner::gateway_of_range;
    is $g->('10.200.0.0/16'),  '10.200.0.1',  'cai-live: 10.200.0.0/16';
    is $g->('10.0.0.0/8'),     '10.0.0.1',    'a /8';
    is $g->('172.16.4.0/22'),  '172.16.4.1',  'a /22';
    is $g->('10.200.7.9/16'),  '10.200.0.1',  'host bits written: still the network address plus one';
    is $g->($_), undef, "'" . ($_ // 'undef') . "': none" for (undef, '', '10.200.0.0', 'fd00::/64', '10.200.0.0/31');
};

# ---------------------------------------------------------------- 2

package FakeEntity {
    sub new { my ($class, %a) = @_; return bless {%a}, $class }
    sub id       { $_[0]{id} }
    sub name     { $_[0]{name} }
    sub ip_range { $_[0]{ip_range} }
}
package FakeCtl {
    sub new { my ($class, %a) = @_; return bless { items => [], calls => [], %a }, $class }
    sub calls { @{ $_[0]{calls} } }
    sub list_all {
        my ($self, %q) = @_;
        push @{ $self->{calls} }, [ list_all => %q ];
        return [ grep { !defined $q{name} || $_->name eq $q{name} } @{ $self->{items} } ];
    }
    sub get {
        my ($self, $id) = @_;
        push @{ $self->{calls} }, [ get => $id ];
        my ($hit) = grep { $_->id eq $id } @{ $self->{items} };
        die "Hetzner API error: not_found\n" unless $hit;
        return $hit;
    }
}
package FakeCloud {
    sub new { my ($class, %a) = @_; return bless {%a}, $class }
    sub networks { $_[0]{networks} }
}
package main;

sub hetzner {
    my $cloud = FakeCloud->new(networks => FakeCtl->new(items => [
        FakeEntity->new(id => 4242, name => 'cai-live', ip_range => '10.200.0.0/16'),
        FakeEntity->new(id => 4243, name => 'odd',      ip_range => undef),
    ]));
    my $prov = OCP::Provider::Hetzner->new(token => 't0k3n', cluster_name => 'hz',
        ssh_key_name => 'ocp-hz-admin', cloud => $cloud);
    return ($prov, $cloud);
}

subtest 'the Hetzner provider resolves via: gateway' => sub {
    my ($prov, $cloud) = hetzner();
    is $prov->network_gateway('cai-live'), '10.200.0.1', 'by name';
    is $prov->network_gateway(4242),       '10.200.0.1', 'by id';

    ($prov, $cloud) = hetzner();
    my $r = $prov->resolve_routes([ { to => '10.230.30.0/24', via => 'gateway' },
                                    { to => '10.230.31.0/24', via => '10.200.0.9' },
                                    { to => '10.230.32.0/24', via => 'gateway' } ],
                                  network => 'cai-live', server => 'hz-w-1');
    is_deeply $r, [ { to => '10.230.30.0/24', via => '10.200.0.1' },
                    { to => '10.230.31.0/24', via => '10.200.0.9' },
                    { to => '10.230.32.0/24', via => '10.200.0.1' } ], 'gateway resolved, an address kept';
    is scalar(grep { $_->[0] eq 'list_all' } $cloud->networks->calls), 1, 'the network looked up once';

    ($prov, $cloud) = hetzner();
    is_deeply $prov->resolve_routes([ { to => '10.230.31.0/24', via => '10.200.0.9' } ], server => 'x'),
        [ { to => '10.230.31.0/24', via => '10.200.0.9' } ], 'no gateway: no network needed';
    is_deeply [ $cloud->networks->calls ], [], '... and none looked up';
    is_deeply $prov->resolve_routes(undef), [], 'no routes: an empty list';
    is_deeply $prov->resolve_routes([]),    [], 'an empty list: an empty list';

    eval { $prov->resolve_routes([ { to => '10.230.30.0/24', via => 'gateway' } ], server => 'hz-w-1') };
    like $@, qr/\AHetzner server 'hz-w-1': a route via gateway needs the network whose gateway it is/,
        'gateway without a network dies, naming the server';
    eval { $prov->resolve_routes([ { to => '10.230.30.0/24', via => 'gateway' } ],
        network => 'cai-gone', server => 'hz-w-1') };
    like $@, qr/there is no Hetzner network 'cai-gone' in this project/, 'a network that is not there dies';
    eval { $prov->network_gateway('odd', 'hz-w-1') };
    like $@, qr/\AHetzner network 'odd' reports no IPv4 ip_range/, 'an ip_range that is none dies';
    is_deeply [ grep { $_->[0] !~ /\A(?:get|list_all)\z/ } $cloud->networks->calls ], [],
        'nothing written on a network, ever';
};

# ---------------------------------------------------------------- 3

my $tmp = tempdir(CLEANUP => 1);
my $key = path($tmp)->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub key');

sub rex_tasks {
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
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $old = select $fh;
    OCP::Rex->new(host => '203.0.113.9', key_file => "$key")->$method(%opts);
    select $old;
    return \%tasks;
}

subtest 'OCP::Rex hands routes to the install task' => sub {
    my @R = ({ to => '10.230.30.0/24', via => '10.200.0.1' });
    my %AGENT = (server => 'https://10.200.0.2:9345', token => 't');
    for my $dist (qw( rke2 k3s )) {
        my $t = rex_tasks(install_server => distribution => $dist, routes => \@R);
        is_deeply $t->{"install_${dist}_server"}{routes}, \@R, "$dist server: routes";
        ok !exists $t->{install_cilium}{routes}, "$dist: not to install_cilium";
        $t = rex_tasks(install_agent => distribution => $dist, %AGENT, routes => \@R);
        is_deeply $t->{"install_${dist}_agent"}{routes}, \@R, "$dist agent: routes";
    }
    my $t = rex_tasks(install_agent => %AGENT, routes => []);
    is_deeply $t->{install_rke2_agent}{routes}, [], 'an empty list is handed on: it removes';
    $t = rex_tasks(install_agent => %AGENT);
    ok !exists $t->{install_rke2_agent}{routes}, 'no list, no parameter';
    $t = rex_tasks(install_server => ());
    ok !exists $t->{install_rke2_server}{routes}, 'no list, no parameter (server)';
};

# ---------------------------------------------------------------- 4

package FakeOcp { sub new { bless {}, shift } sub verbose { 0 } }

package RouteProv {
    our (@ORDER, $FAIL);
    sub new            { bless {}, shift }
    sub upload_ssh_key { }
    sub resolve_routes {
        my ($self, $routes, %o) = @_;
        push @ORDER, [ resolve_routes => $routes, \%o ];
        die $FAIL if $FAIL;
        return [ map { +{ to => $_->{to}, via => $_->{via} eq 'gateway' ? '10.200.0.1' : $_->{via} } }
                 @{ $routes // [] } ];
    }
    sub create_server  { push @ORDER, [ 'create_server' ]; +{ id => 7, ip => '10.200.0.2', newly_created => 0 } }
    sub cleanup_on_failure { }
}

package main;

our %INSTALL;

sub project {
    my ($spec) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({ name => 'hz', %$spec }));
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub bootstrap {
    my ($config, $prov_class) = @_;
    (@RouteProv::ORDER, %INSTALL) = ();
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $old = select $fh;
    eval {
        no warnings 'redefine';
        open local *STDERR, '>', \my $stderr or die $!;
        local *OCP::Provider::for_spec      = sub { ($prov_class // 'RouteProv')->new };
        local *OCP::Secrets::ensure_age_key = sub { 1 };
        local *OCP::SSH::new          = sub { my ($c, %a) = @_; bless {%a}, $c };
        local *OCP::SSH::wait_for_ssh = sub { 1 };
        local *OCP::Rex::new          = sub { my ($c, %a) = @_; bless {%a}, $c };
        local *OCP::Rex::install_server = sub { my ($s, %a) = @_; %INSTALL = %a; die "stop at the install\n" };
        OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
            $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
            admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
        );
    };
    my $died = $@;
    select $old;
    return $died;
}

my %CP = (provider => 'hetzner', server_type => 'cpx22', location => 'fsn1', network => 'cai-live');

subtest 'the bootstrap resolves police1\'s routes first and installs with them' => sub {
    my $config = project({ control_planes => { %CP, address => 'private',
        routes => [ { to => '10.230.30.0/24', via => 'gateway' } ] } });
    is_deeply [ $config->validate ], [], 'a valid ocp.yaml';
    is bootstrap($config), "stop at the install\n", 'ran to the install';
    is $RouteProv::ORDER[0][0], 'resolve_routes', 'resolved before the server is ordered';
    is $RouteProv::ORDER[1][0], 'create_server', '... then created';
    is $RouteProv::ORDER[0][2]{network}, 'cai-live', "with police1's network";
    is_deeply $INSTALL{routes}, [ { to => '10.230.30.0/24', via => '10.200.0.1' } ],
        'install_server gets them, via resolved';

    bootstrap(project({ control_planes => { %CP } }));
    is_deeply $INSTALL{routes}, [], 'no routes: an empty list, so earlier ones are removed';

    local $RouteProv::FAIL = "there is no Hetzner network 'cai-live'\n";
    like bootstrap($config), qr/no Hetzner network/, 'a gateway that cannot be resolved stops the run';
    ok !grep({ $_->[0] eq 'create_server' } @RouteProv::ORDER), '... before a server is ordered';
};

package PlainProv {
    sub new            { bless {}, shift }
    sub upload_ssh_key { }
    sub create_server  { +{ id => 7, ip => '10.200.0.2', newly_created => 0 } }
}
package main;

subtest 'a provider without resolve_routes hands none' => sub {
    bootstrap(project({ control_planes => { %CP } }), 'PlainProv');
    ok !exists $INSTALL{routes}, 'no routes parameter: the node is left alone';
};

# ---------------------------------------------------------------- 5

my @patches;
{
    no warnings 'redefine';
    *OCP::K8s::patch_status = sub { my ($c, $api, %a) = @_; push @patches, $a{status}; 1 };
    *OCP::KnownHosts::scan  = sub { () };
}
{
    package FakeRex;
    our @calls;
    sub new      { bless {}, shift }
    sub run_task { my ($s, $task, %p) = @_; push @calls, [ $task, \%p ]; 1 }
}
{ package FakeSSH; sub new { bless {}, shift } sub wait_for_ssh { 1 } }
{ package FakeIO;  sub new { bless {}, shift } sub object_to_struct { $_[1] } }
{
    package FakeK8s;
    sub new { bless {}, shift }
    sub k8s { FakeIO->new }
    sub get { die "404\n" }
}

sub install_node {
    my (%o) = @_;
    @patches = (); @FakeRex::calls = (); @RouteProv::ORDER = ();
    my $node = OCP::Node->from_cr({
            apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
            metadata => { name => 'w-1', namespace => 'ocp-system', resourceVersion => '1' },
            spec     => { role => 'worker', providerRef => 'hetzner-default', network => 'cai-live',
                          (exists $o{routes} ? (routes => $o{routes}) : ()) },
            status   => { phase => 'Installing', publicIP => '10.200.0.3' },
        },
        k8s => FakeK8s->new, ssh_key => 'KEY',
        provider => $o{provider} // RouteProv->new,
        server_url => 'https://10.200.0.2:9345', join_token => 'TOKEN', distribution => 'rke2',
        ssh_class => 'FakeSSH', rex_class => 'FakeRex',
    );
    $node->_install_kubernetes;
    return $FakeRex::calls[0];
}

subtest 'OCP::Node resolves spec.routes through its provider' => sub {
    my $call = install_node(routes => [ { to => '10.230.30.0/24', via => 'gateway' } ]);
    ok $call, 'the install ran' or return;
    is_deeply $call->[1]{routes}, [ { to => '10.230.30.0/24', via => '10.200.0.1' } ], 'routes, via resolved';
    is $RouteProv::ORDER[0][2]{network}, 'cai-live', 'through spec.network';
    is $RouteProv::ORDER[0][2]{server},  'w-1',      'naming the node';

    $call = install_node();
    is_deeply $call->[1]{routes}, [], 'no spec.routes: an empty list';

    $call = install_node(routes => [ { to => '10.230.30.0/24', via => 'gateway' } ], provider => PlainProv->new);
    ok !exists $call->[1]{routes}, 'a provider without resolve_routes: no parameter';

    local $RouteProv::FAIL = "there is no Hetzner network 'cai-live'\n";
    $call = install_node(routes => [ { to => '10.230.30.0/24', via => 'gateway' } ]);
    ok !$call, 'no Rex run';
    is $patches[-1]{phase}, 'Failed', 'the node fails';
    is $patches[-1]{message}, "spec.routes: there is no Hetzner network 'cai-live'\n", 'saying why';
};

done_testing;

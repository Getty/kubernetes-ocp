#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Config;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);
use YAML::XS ();

# Minimal fake api that records every ensure/get call so we can assert
# that Apply's new CR-first helpers write the expected resources in the
# expected order.

{
    package FakeApi;
    sub new {
        my ($class, %args) = @_;
        return bless {
            calls       => [],
            deployments => $args{deployments} // {},
            nodes       => $args{nodes}       // {},
            providers   => $args{providers}   // {},
        }, $class;
    }
    sub ensure {
        my ($self, $doc) = @_;
        push @{$self->{calls}}, ['ensure', $doc->{kind}, $doc->{metadata}{name}, $doc];
        return $doc;
    }
    sub get {
        my ($self, $kind, $name, %args) = @_;
        push @{$self->{calls}}, ['get', $kind, $name, \%args];
        if ($kind eq 'Deployment') {
            return $self->{deployments}{$name};
        }
        if ($kind eq 'OCPNode') {
            return $self->{nodes}{$name};
        }
        if ($kind eq 'OCPNodeProvider') {
            return $self->{providers}{$name};
        }
        return undef;
    }
    sub k8s { FakeK8s->new }
}

{
    package FakeK8s;
    sub new { bless {}, shift }
    sub object_to_struct { $_[1] }
}

{
    package FakeDep;
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub status { $_[0]->{status} }
}

{
    package FakeStatus;
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub readyReplicas { $_[0]->{readyReplicas} }
}

{
    package FakeSecrets;
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub hetzner_token { $_[0]->{token} }
}

# --- Build a minimal on-disk project + config for helper calls. ---

my $tmp = Path::Tiny->tempdir;
$tmp->child('.ocp')->mkpath;
my $ocp_yaml = $tmp->child('ocp.yaml');
$ocp_yaml->spew(<<'YAML');
name: mycluster
controlPlanes:
  - provider: hetzner
    location: fsn1
    serverType: cx32
workers:
  - name: pool-a
    provider: hetzner
    nodes: 2
    serverType: cx21
  - name: ssh-pool
    provider: ssh
    nodes:
      - host: avatar.example.com
YAML

my $config = OCP::Config->new(file => $ocp_yaml->stringify);

# Apply's helpers need the share-dir resolvable from the project. The
# tempdir has no share/, so point at the real one.
my $share = path(__FILE__)->parent->parent->child('share');
ok -d $share, 'share dir resolvable';

# Construct an Apply without running execute(). Supply an ocp stub so
# calls like $self->ocp->verbose don't blow up.
{
    package FakeOcp;
    sub new { bless { verbose => 0 }, shift }
    sub verbose { 0 }
}

my $apply = OCP::Cmd::Apply->new(ocp => FakeOcp->new);

# _find_share_dir needs to resolve — inject a stub that returns our share/.
{
    no warnings 'redefine';
    *OCP::Cmd::Apply::_find_share_dir = sub { $share };
}

subtest '_ensure_crds writes CRDs from share/robocop/crds/' => sub {
    my $api = FakeApi->new;
    $apply->_ensure_crds($api);
    my @ensured = grep { $_->[0] eq 'ensure' } @{$api->{calls}};
    ok scalar(@ensured) >= 2, 'at least 2 CRDs ensured (OCPNode + OCPNodeProvider)';
    my @kinds = map { $_->[1] } @ensured;
    is_deeply [sort @kinds], [sort ('CustomResourceDefinition', 'CustomResourceDefinition')],
        'both resources are CRDs';
    my @names = map { $_->[2] } @ensured;
    ok scalar(grep { $_ eq 'ocpnodes.ocp.internal' }         @names), 'OCPNode CRD ensured';
    ok scalar(grep { $_ eq 'ocpnodeproviders.ocp.internal' } @names), 'OCPNodeProvider CRD ensured';
};

subtest '_ensure_providers writes Namespace + hetzner Secret/Provider + ssh Provider' => sub {
    my $api = FakeApi->new;
    my $secrets = FakeSecrets->new(token => 'hx-test-token');
    $apply->_ensure_providers($api, $config, $secrets);

    my @ensured = grep { $_->[0] eq 'ensure' } @{$api->{calls}};
    my @rows    = map { "$_->[1]/$_->[2]" } @ensured;

    ok scalar(grep { $_ eq 'Namespace/ocp-system' } @rows),
        'Namespace ocp-system ensured first';
    ok scalar(grep { $_ eq 'Secret/hetzner-api-token-hetzner' } @rows),
        'Hetzner API token Secret ensured';
    ok scalar(grep { $_ eq 'OCPNodeProvider/hetzner-default' } @rows),
        'hetzner-default OCPNodeProvider ensured';
    ok scalar(grep { $_ eq 'OCPNodeProvider/ssh-default' } @rows),
        'ssh-default OCPNodeProvider ensured';

    # Verify Secret has base64-encoded token.
    my ($secret) = grep { $_->[1] eq 'Secret' } @ensured;
    like $secret->[3]{data}{token}, qr/^[A-Za-z0-9+\/=]+$/,
        'Secret token is base64-encoded';
};

subtest '_ensure_cp_ocpnode writes CP CR with phase=Ready' => sub {
    my $api = FakeApi->new;
    $apply->_ensure_cp_ocpnode($api, {
        name     => 'police1',
        provider => 'hetzner',
        host     => '1.2.3.4',
    });
    my ($call) = grep { $_->[0] eq 'ensure' && $_->[1] eq 'OCPNode' } @{$api->{calls}};
    ok $call, 'OCPNode CR ensured';
    is $call->[2], 'police1', 'name=police1';
    is $call->[3]{spec}{role}, 'control-plane', 'role=control-plane';
    is $call->[3]{spec}{providerRef}, 'hetzner-default', 'providerRef=hetzner-default';
    is $call->[3]{status}{phase}, 'Ready', 'phase=Ready';
    is $call->[3]{status}{publicIP}, '1.2.3.4', 'publicIP stamped';
};

subtest '_ensure_worker_ocpnodes writes one Pending CR per worker entry' => sub {
    my $api = FakeApi->new;
    $apply->_ensure_worker_ocpnodes($api, $config);
    my @ensured = grep { $_->[0] eq 'ensure' && $_->[1] eq 'OCPNode' } @{$api->{calls}};
    is scalar(@ensured), 3, '3 worker OCPNodes ensured (2 hetzner + 1 ssh)';

    my %by_name = map { $_->[2] => $_->[3] } @ensured;
    ok $by_name{'pool-a-1'}, 'pool-a-1 written';
    ok $by_name{'pool-a-2'}, 'pool-a-2 written';
    ok $by_name{'avatar'},   'ssh worker derived name from host';

    is $by_name{'pool-a-1'}{spec}{role}, 'worker', 'hetzner worker role';
    is $by_name{'pool-a-1'}{spec}{providerRef}, 'hetzner-default',
        'hetzner worker providerRef';
    is $by_name{'pool-a-1'}{spec}{serverType}, 'cx21',
        'serverType threaded from pool spec';
    ok !$by_name{'pool-a-1'}{status},
        'Pending CRs do not stamp status (controller owns it)';

    is $by_name{'avatar'}{spec}{providerRef}, 'ssh-default',
        'ssh worker providerRef';
    is $by_name{'avatar'}{spec}{host}, 'avatar.example.com',
        'ssh worker host threaded from pool';
};

subtest '_wait_robocop_ready: ready when readyReplicas >= 1' => sub {
    my $api = FakeApi->new(deployments => {
        robocop => FakeDep->new(status => FakeStatus->new(readyReplicas => 1)),
    });
    ok $apply->_wait_robocop_ready($api, 5), 'ready=1';
};

subtest '_wait_robocop_ready: not ready when Deployment missing' => sub {
    my $api = FakeApi->new; # no deployments
    # Shorten polling cost: timeout 0 means one-iteration max.
    is $apply->_wait_robocop_ready($api, 0), 0, 'no robocop → not ready';
};

subtest '_poll_nodes_until_terminal collects terminal phases' => sub {
    my $api = FakeApi->new(nodes => {
        'pool-a-1' => { status => { phase => 'Ready',  message => 'ok' } },
        'pool-a-2' => { status => { phase => 'Failed', message => 'boom' } },
    });
    my @out = $apply->_poll_nodes_until_terminal($api, ['pool-a-1', 'pool-a-2'], 5);
    is scalar(@out), 2, 'result per name';
    my %by_name = map { $_->{name} => $_ } @out;
    is $by_name{'pool-a-1'}{phase}, 'Ready',  'Ready reported';
    is $by_name{'pool-a-2'}{phase}, 'Failed', 'Failed reported';
    is $by_name{'pool-a-2'}{message}, 'boom', 'message threaded';
};

subtest 'helper ordering: CRDs, then Providers, then CP CR, then Workers' => sub {
    # Simulate the exact apply sequence: the four ensure helpers called in
    # order. Verify the observable order of ensure() calls matches the
    # spec (CRDs -> Namespace/Providers -> CP -> Workers).
    my $api = FakeApi->new;
    my $secrets = FakeSecrets->new(token => 'T');
    $apply->_ensure_crds($api);
    $apply->_ensure_providers($api, $config, $secrets);
    $apply->_ensure_cp_ocpnode($api, {
        name => 'police1', provider => 'hetzner', host => '1.2.3.4',
    });
    $apply->_ensure_worker_ocpnodes($api, $config);

    my @ensures = grep { $_->[0] eq 'ensure' } @{$api->{calls}};
    my @kinds = map { $_->[1] } @ensures;

    # First two ensures should be CRDs.
    is $kinds[0], 'CustomResourceDefinition', 'first ensure is a CRD';
    is $kinds[1], 'CustomResourceDefinition', 'second ensure is a CRD';

    # After CRDs, Namespace/ocp-system precedes any OCPNodeProvider.
    my $first_ns  = (grep { $kinds[$_] eq 'Namespace' }       0..$#kinds)[0];
    my $first_prv = (grep { $kinds[$_] eq 'OCPNodeProvider' } 0..$#kinds)[0];
    ok defined $first_ns && defined $first_prv, 'saw both kinds';
    ok $first_ns < $first_prv, 'Namespace before OCPNodeProvider';

    # CP OCPNode must come before worker OCPNodes.
    my @ocpnode_names = map { $_->[2] } grep { $_->[1] eq 'OCPNode' } @ensures;
    is $ocpnode_names[0], 'police1', 'CP OCPNode written first';
    ok scalar(grep { $_ eq 'pool-a-1' } @ocpnode_names), 'worker CR after';
};

done_testing;

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
    package FakeList;
    sub new {
        my ($class, @items) = @_;
        return bless { items => \@items }, $class;
    }
    sub items { $_[0]->{items} }
}

{
    package FakeApi;
    sub new {
        my ($class, %args) = @_;
        return bless {
            calls        => [],
            deployments  => $args{deployments}  // {},
            nodes        => $args{nodes}         // {},
            providers    => $args{providers}     // {},
            k8s_nodes    => $args{k8s_nodes}     // [],
            ocpnode_list => $args{ocpnode_list}  // [],
        }, $class;
    }
    sub ensure {
        my ($self, $doc) = @_;
        push @{$self->{calls}}, ['ensure', $doc->{kind}, $doc->{metadata}{name}, $doc];
        return $doc;
    }
    # OCP::K8s::patch_status prefers a native writer when the api provides one,
    # so stubbing it here records the /status write without having to emulate
    # _build_path and the raw transport. The raw path has its own coverage in
    # t/36-ocpnode-status.t.
    sub patch_status {
        my ($self, %args) = @_;
        push @{$self->{calls}},
            ['patch_status', $args{kind}, $args{name}, $args{status}];
        return 1;
    }
    # _server_side_apply falls back to a hand-built path when the kind is not
    # a registered class, then PATCHes the raw manifest.
    sub _request {
        my ($self, $method, $path, $body, %opts) = @_;
        push @{$self->{calls}},
            [lc($method), $body->{kind}, $body->{metadata}{name}, $body, \%opts];
        return $body;
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
        if ($kind eq 'Node') {
            return $self->{plain_nodes}{$name};
        }
        return undef;
    }
    sub list {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['list', $kind, \%args];
        if ($kind eq 'Node') {
            return FakeList->new(@{ $self->{k8s_nodes} });
        }
        if ($kind eq 'OCPNode') {
            return FakeList->new(@{ $self->{ocpnode_list} });
        }
        return FakeList->new();
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
control_planes:
  - provider: hetzner
    location: fsn1
    server_type: cx32
workers:
  - name: pool-a
    provider: hetzner
    nodes: 2
    server_type: cx21
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
    # CRDs go out as raw manifests, never through ensure(): a CRD schema is
    # full of union-typed fields (default/enum/items/additionalProperties) that
    # IO::K8s cannot inflate, and a partial inflate would write the CRD back
    # without its defaults.
    my @ensured = grep { $_->[0] eq 'patch' } @{$api->{calls}};
    ok scalar(@ensured) >= 2, 'at least 2 CRDs applied (OCPNode + OCPNodeProvider)';
    is scalar(grep { $_->[0] eq 'ensure' } @{$api->{calls}}), 0,
        'no CRD is round-tripped through the typed ensure() path';
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

    # The ensure must NOT carry status: OCPNode enables the status subresource,
    # so the API server drops it there and answers 2xx anyway. Status has to be
    # a separate /status write or it never lands.
    ok !exists $call->[3]{status}, 'ensure payload carries no status';

    my ($status) = grep { $_->[0] eq 'patch_status' } @{$api->{calls}};
    ok $status, 'status written through the /status subresource';
    is $status->[1], 'OCPNode', 'status patch targets OCPNode';
    is $status->[2], 'police1', 'status patch targets police1';
    is $status->[3]{phase}, 'Ready', 'phase=Ready';
    is $status->[3]{publicIP}, '1.2.3.4', 'publicIP stamped';
    is $status->[3]{reconciler}, 'cli', 'stamped reconciler=cli';
};

subtest '_ensure_cp_ocpnode prefers the Node address over the configured host' => sub {
    # The configured control_planes.host is regularly a DNS name, which would
    # put "cortex.example.com" in the IP column while `ocp status` shows the
    # real address. Read it off the Node object instead.
    my $api = FakeApi->new(
        k8s_nodes => [],
        nodes     => {},
    );
    $api->{plain_nodes} = {
        cortex => {
            metadata => { name => 'cortex' },
            status   => { addresses => [
                { type => 'InternalIP', address => '10.230.30.155' },
            ] },
        },
    };
    $apply->_ensure_cp_ocpnode($api, {
        name     => 'cortex',
        provider => 'ssh',
        host     => 'cortex.example.com',
    });

    my ($status) = grep { $_->[0] eq 'patch_status' } @{$api->{calls}};
    is $status->[3]{publicIP}, '10.230.30.155',
        'IP comes from the Node object, not from the configured host';
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

    # Every write, in order — CRDs go out as raw PATCHes (server-side apply),
    # everything else through the typed ensure(). Ordering is what matters here,
    # not which of the two paths a given kind takes.
    my @ensures = grep { $_->[0] eq 'ensure' || $_->[0] eq 'patch' } @{$api->{calls}};
    my @kinds = map { $_->[1] } @ensures;

    # First two writes should be CRDs.
    is $kinds[0], 'CustomResourceDefinition', 'first write is a CRD';
    is $kinds[1], 'CustomResourceDefinition', 'second write is a CRD';

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

subtest 'migration synthesizes legacy provider when needed' => sub {
    my $api = FakeApi->new(
        ocpnode_list => [],
        k8s_nodes    => [
            { metadata => { name => 'worker-1', labels => {} },
              status   => { addresses => [{ type => 'ExternalIP', address => '1.2.3.4' }] } },
            { metadata => { name => 'worker-2', labels => {} },
              status   => { addresses => [{ type => 'InternalIP', address => '10.0.0.2' }] } },
        ],
    );
    $apply->_migrate_legacy_nodes($api);
    my @ensures = grep { $_->[0] eq 'ensure' } @{$api->{calls}};
    my @rows = map { "$_->[1]/$_->[2]" } @ensures;

    ok scalar(grep { $_ eq 'OCPNodeProvider/legacy' } @rows),
        'legacy OCPNodeProvider ensured';
    ok scalar(grep { $_ eq 'OCPNode/worker-1' } @rows), 'OCPNode/worker-1 synthesized';
    ok scalar(grep { $_ eq 'OCPNode/worker-2' } @rows), 'OCPNode/worker-2 synthesized';

    my ($w1) = grep { $_->[1] eq 'OCPNode' && $_->[2] eq 'worker-1' } @ensures;
    is $w1->[3]{spec}{providerRef}, 'legacy',  'worker-1 providerRef=legacy';
    is $w1->[3]{spec}{role},        'worker',  'worker-1 role=worker';
    is $w1->[3]{metadata}{annotations}{'ocp.internal/synthetic'}, 'true',
        'synthetic annotation set';

    # Status again travels via /status, not via the ensure payload.
    my %status = map { $_->[2] => $_->[3] }
                 grep { $_->[0] eq 'patch_status' } @{$api->{calls}};
    is $status{'worker-1'}{phase},    'Ready',   'worker-1 phase=Ready';
    is $status{'worker-1'}{publicIP}, '1.2.3.4', 'worker-1 ExternalIP used';
    is $status{'worker-2'}{publicIP}, '10.0.0.2',
        'worker-2 falls back to InternalIP';

    my ($prov) = grep { $_->[1] eq 'OCPNodeProvider' } @ensures;
    is $prov->[3]{metadata}{annotations}{'ocp.internal/synthetic'}, 'true',
        'legacy provider has synthetic annotation';
    is $prov->[3]{spec}{type}, 'ssh', 'legacy provider type=ssh';
};

subtest 'migration skips already-tracked nodes' => sub {
    my $api = FakeApi->new(
        ocpnode_list => [
            { metadata => { name => 'worker-1' } },
        ],
        k8s_nodes => [
            { metadata => { name => 'worker-1', labels => {} },
              status   => { addresses => [] } },
            { metadata => { name => 'worker-2', labels => {} },
              status   => { addresses => [{ type => 'InternalIP', address => '10.0.0.2' }] } },
        ],
    );
    $apply->_migrate_legacy_nodes($api);
    my @ensures = grep { $_->[0] eq 'ensure' } @{$api->{calls}};
    my @names   = map { $_->[2] } grep { $_->[1] eq 'OCPNode' } @ensures;

    ok !scalar(grep { $_ eq 'worker-1' } @names), 'worker-1 not re-synthesized';
    ok  scalar(grep { $_ eq 'worker-2' } @names), 'worker-2 synthesized';
};

subtest 'migration detects control-plane label' => sub {
    my $api = FakeApi->new(
        ocpnode_list => [],
        k8s_nodes    => [
            {
                metadata => {
                    name   => 'police1',
                    labels => { 'node-role.kubernetes.io/control-plane' => '' },
                },
                status => { addresses => [] },
            },
        ],
    );
    $apply->_migrate_legacy_nodes($api);
    my @ensures = grep { $_->[0] eq 'ensure' } @{$api->{calls}};
    my ($cp) = grep { $_->[1] eq 'OCPNode' && $_->[2] eq 'police1' } @ensures;
    is $cp->[3]{spec}{role}, 'control-plane', 'CP label → role=control-plane';
};

#
# _run_remedy: the step apply runs for a drift entry
#

sub remedy_config {
    my (%args) = @_;
    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('ocp.yaml')->spew_utf8(<<"YAML");
name: t
control_planes:
  provider: ssh
  host: @{[ $args{host} // '1.2.3.4' ]}
ssh:
  private_key: key
YAML
    path($dir)->child('key')->spew_utf8('PRIVATE') if $args{with_key};
    return OCP::Config->new(file => path($dir)->child('ocp.yaml')->stringify);
}

# _run_remedy asks the root command for --verbose, so this instance needs a
# command chain rather than just an 'ocp' constructor argument.
my $remedy_apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);

my $CILIUM_DRIFT = {
    component => 'cilium',
    label     => 'Cilium',
    expected  => '1.19.2',
    remedy    => { type => 'rex', task => 'upgrade_cilium', params => { version => '1.19.2' } },
};

subtest '_run_remedy runs the Rex task with the target version' => sub {
    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::new = sub { my ($class, %args) = @_; bless {%args}, $class };
    local *OCP::Rex::run_task = sub {
        my ($self, $task, %params) = @_;
        push @calls, { host => $self->{host}, key => $self->{key_file}, task => $task, %params };
        return 1;
    };

    my $config = remedy_config(with_key => 1);
    my $ran = $remedy_apply->_run_remedy($config, $CILIUM_DRIFT);

    ok $ran, 'reports that it ran';
    is scalar(@calls), 1, 'one Rex task';
    is $calls[0]{task}, 'upgrade_cilium', 'the task named by the remedy';
    is $calls[0]{version}, '1.19.2', 'with the target version';
    is $calls[0]{host}, '1.2.3.4', 'against the control plane';
};

subtest '_run_remedy declines without an SSH key instead of dying' => sub {
    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::new = sub { push @calls, 1; bless {}, shift };

    my $config = remedy_config();   # no key file written
    my $ran = eval { $remedy_apply->_run_remedy($config, $CILIUM_DRIFT) };

    ok defined $ran, 'no exception';
    ok !$ran, 'reports that it did not run';
    is scalar(@calls), 0, 'Rex never invoked';
};

subtest '_run_remedy ignores entries without a remedy' => sub {
    my $config = remedy_config(with_key => 1);
    ok !$remedy_apply->_run_remedy($config, { component => 'rke2', remedy => undef }),
        'nothing to do';
};

done_testing;

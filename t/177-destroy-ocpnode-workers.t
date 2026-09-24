#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Cmd::Destroy;
use OCP::Config;

#
# k177: `ocp destroy --force` on an ssh-provider cluster whose worker robocop
# had installed from an OCPNode tore down the control plane only -- "Cluster
# destroyed." -- and rke2-agent kept running on the worker.
#
# The node list came from .ocp/status.yaml, which records control planes
# only. The Hetzner label search and the ocp.yaml fallback ran only when that
# list was EMPTY, and the fallback only knew worker pools written as
# `nodes: [...]`, not the `host:` form.
#
# What `ocp destroy` must do instead:
#
#   * while the cluster API answers, read every OCPNode (all roles) and merge
#     them with status.yaml and the spec, one entry per machine;
#   * tear the workers down BEFORE the control planes (and stop robocop
#     first, so nothing re-provisions what is being deleted);
#   * ssh workers through the same uninstall path as ssh control planes,
#     Hetzner workers through delete_server with their address (so the host
#     key goes too, k168);
#   * with no API, still find `host:`-form worker pools in ocp.yaml.
#

# ---------------------------------------------------------------- stubs

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# One event log shared by every fake, so ORDER (robocop stopped before any
# delete, workers before control planes) is assertable, not just the set.
my @events;

{
    package FakeProvider;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub list_servers_by_cluster { [] }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        push @events, [ delete => $self->{type}, $id, $opts{host} ];
        return { stdout => '', stderr => '', exit => 0 };
    }
    sub resolve_host {
        my ($self, %opts) = @_;
        return '127.0.0.1' if $self->{type} eq 'local';
        my $host = $opts{host};
        die "SSH provider requires 'host'\n"
            unless defined $host && length $host;
        return $host;
    }
}

{
    package FakeKey;
    sub new            { bless {}, shift }
    sub path           { '/nonexistent/admin-key' }
    sub migration_hint { "hint\n" }
}

# Kubernetes::REST stand-in: list() answers from fixed fixtures, patch() is
# logged, and object_to_struct is the identity -- the items are plain hashes.
{
    package FakeList;
    sub new   { my ($c, @i) = @_; bless { items => [@i] }, $c }
    sub items { $_[0]{items} }
}
{
    package FakeK8s;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list {
        my ($self, $kind) = @_;
        die "connection refused\n" if $self->{down};
        return FakeList->new(@{ $self->{$kind} // [] });
    }
    sub patch {
        my ($self, $kind, $name, %a) = @_;
        push @events, [ patch => $kind, $name, $a{patch} ];
        return 1;
    }
}

sub ocpnode {
    my ($name, %a) = @_;
    return {
        metadata => { name => $name, namespace => 'ocp-system' },
        spec     => {
            role        => $a{role} // 'worker',
            providerRef => $a{ref},
            ($a{host} ? (host => $a{host}) : ()),
        },
        status   => {
            phase => 'Ready',
            ($a{id} ? (providerId => $a{id}) : ()),
            ($a{ip} ? (publicIP   => $a{ip}) : ()),
        },
    };
}

sub provider_cr {
    my ($name, $type) = @_;
    return { metadata => { name => $name }, spec => { type => $type } };
}

sub project {
    my (%a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8($a{yaml});
    $dir->child('.ocp', 'status.yaml')->spew_utf8($a{status}) if $a{status};
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub run_destroy {
    my ($config, %a) = @_;
    @events = ();

    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        force         => 1,
        ($a{k8s} ? (k8s => $a{k8s}) : ()),
    );

    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my @ret = do {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        no warnings 'redefine';
        local *OCP::Provider::for_spec = sub {
            my ($class, $spec) = @_;
            return FakeProvider->new(type => $spec->{provider});
        };
        local *OCP::Secrets::hetzner_token = sub { $a{token} };
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { FakeKey->new };
        eval { $cmd->execute([], []) };
    };
    my $ex = $@;
    return { out => $out, err => $err, ex => $ex, ret => $ret[0],
             events => [@events] };
}

sub deletes { grep { $_->[0] eq 'delete' } @{ $_[0]{events} } }

my $STATUS_SSH_CP = <<'YAML';
nodes:
  - name: ocpt
    provider: ssh
    public_ip: ocpt.lan
YAML

my $YAML_SSH = <<'YAML';
name: ocpt
control_planes:
  provider: ssh
  host: ocpt.lan
YAML

# -------------------------------------------------------------- the live bug

subtest 'OCPNode workers are torn down, before the control plane' => sub {
    my $config = project(yaml => $YAML_SSH, status => $STATUS_SSH_CP);
    my $k8s = FakeK8s->new(
        OCPNodeProvider => [ provider_cr('ssh-default',     'ssh'),
                             provider_cr('hetzner-default', 'hetzner') ],
        OCPNode => [
            ocpnode('ocpt-w', ref => 'ssh-default', host => 'ocpt-w.lan'),
            ocpnode('hw-1',   ref => 'hetzner-default', id => '999',
                              ip  => '5.5.5.5'),
            # the control plane's own OCPNode: the same machine as status.yaml
            ocpnode('ocpt', role => 'control-plane', ref => 'ssh-default',
                            host => 'ocpt.lan'),
        ],
    );

    my $r = run_destroy($config, k8s => $k8s, token => 'tok');
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';

    my @d = deletes($r);
    is_deeply [ map { [ @$_[1..3] ] } @d ], [
        [ 'ssh',     undef, 'ocpt-w.lan' ],
        [ 'hetzner', '999', '5.5.5.5'    ],
        [ 'ssh',     undef, 'ocpt.lan'   ],
    ], 'ssh worker uninstalled, Hetzner worker deleted with its address,'
     . ' control plane last and only once';

    like $r->{out}, qr/ocpt-w/, 'the worker is on the announced list';

    my ($stop_idx) = grep { $r->{events}[$_][0] eq 'patch' } 0 .. $#{ $r->{events} };
    ok defined $stop_idx, 'robocop was patched';
    is $stop_idx, 0, 'robocop is stopped before anything is deleted';
    is_deeply $r->{events}[$stop_idx], [ patch => 'Deployment', 'robocop',
        { spec => { replicas => 0 } } ], 'scaled to zero replicas';

    ok !-f $config->status_file, 'status.yaml removed on a clean teardown';
};

subtest 'a spec host-form worker already known as an OCPNode is uninstalled once' => sub {
    my $config = project(status => $STATUS_SSH_CP, yaml => $YAML_SSH . <<'YAML');
workers:
  - name: pool
    provider: ssh
    host: ocpt-w.lan
YAML
    my $k8s = FakeK8s->new(
        OCPNodeProvider => [ provider_cr('ssh-default', 'ssh') ],
        OCPNode => [ ocpnode('ocpt-w', ref => 'ssh-default', host => 'ocpt-w.lan') ],
    );

    my $r = run_destroy($config, k8s => $k8s);
    is_deeply [ map { $_->[3] } deletes($r) ], [ 'ocpt-w.lan', 'ocpt.lan' ],
        'deduplicated by name/host, worker first';
};

# ------------------------------------------------------------ no cluster API

subtest 'API unreachable: host-form worker pools from ocp.yaml are found' => sub {
    my $config = project(status => $STATUS_SSH_CP, yaml => $YAML_SSH . <<'YAML');
workers:
  - name: pool
    provider: ssh
    host: ocpt-w.lan
  - name: listed
    provider: ssh
    nodes:
      - w2.lan
  - name: cloud
    provider: hetzner
    nodes: 2
YAML

    my $r = run_destroy($config, k8s => FakeK8s->new(down => 1));
    is $r->{ex}, '', 'ran without dying (a count-form pool is no host list)'
        or diag $r->{ex};
    is_deeply [ map { $_->[3] } deletes($r) ],
        [ 'ocpt-w.lan', 'w2.lan', 'ocpt.lan' ],
        'both spec worker forms uninstalled, then the control plane';
    like $r->{err}, qr/OCPNode/, 'the unreachable API is reported on STDERR';
    unlike $r->{out}, qr/connection refused/, 'diagnosis stays off STDOUT';
    ok !(grep { $_->[0] eq 'patch' } @{ $r->{events} }),
        'a down API is not asked a second time (no robocop patch)';
    is $r->{ret}, 0, 'still a clean teardown: nothing paid was left behind';
};

subtest 'no kubeconfig at all: the teardown still runs from status + spec' => sub {
    my $config = project(status => $STATUS_SSH_CP, yaml => $YAML_SSH);
    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is_deeply [ map { $_->[3] } deletes($r) ], [ 'ocpt.lan' ], 'control plane only';
    is $r->{ret}, 0, 'exit 0';
};

done_testing;

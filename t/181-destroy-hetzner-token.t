#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use MIME::Base64 qw(encode_base64);
use Path::Tiny qw(path);

use OCP;
use OCP::Cmd::Destroy;
use OCP::Config;

#
# k181: a Hetzner node with a providerId was skipped WITHOUT A WORD when
# `ocp destroy` had no local Hetzner token -- a fresh checkout whose
# secrets.yaml lacks it, or a worker brought up through a provider CR of its
# own with a different token. The paid server kept running and the run said
# "Cluster destroyed.".
#
# What `ocp destroy` does instead:
#
#   * each Hetzner node is deleted with the token of the OCPNodeProvider it
#     names (the token that created it), read from that CR's Secret while the
#     API still answers; a node without one (a control plane from status.yaml,
#     a label-search find) uses the local token, else the hetzner-default CR's;
#   * the label search runs under every distinct token it has, not only the
#     local one;
#   * a Hetzner server no token reaches is found BEFORE anything is deleted:
#     the teardown refuses, lists name/id/ip on STDERR and exits 1. Deleting
#     the rest first would take down the control plane and with it the
#     OCPNode and the Secret -- the only records of the survivor and the
#     only key that could still delete it.
#
# Real OCP::Provider::for_spec and from_cr run (Secret lookup included);
# only _build is replaced, so nothing is constructed that could reach an API.
#

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

my @events;
our %LABELLED;   # token => [ servers ] the label search answers with

{
    package FakeServer;
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub name { $_[0]{name} }
    sub id   { $_[0]{id} }
    sub ipv4 { $_[0]{ip} }
}
{
    package FakeHetzner;
    sub new   { my ($c, %a) = @_; bless {%a}, $c }
    sub token { $_[0]{token} }
    sub list_servers_by_cluster {
        my ($self, $cluster) = @_;
        return [] unless $cluster eq 'prod';
        return $main::LABELLED{ $self->{token} } // [];
    }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        push @events, [ delete => 'hetzner', $id, $self->{token} ];
        return;
    }
}
{
    package FakeHost;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub resolve_host { my ($self, %o) = @_; $o{host} or die "no host\n" }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        push @events, [ delete => $self->{type}, $opts{host} ];
        return { stdout => '', stderr => '', exit => 0 };
    }
}
{
    package FakeKey;
    sub new            { bless {}, shift }
    sub path           { '/nonexistent/admin-key' }
    sub migration_hint { "hint\n" }
}
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
    sub get {
        my ($self, $kind, %a) = @_;
        my $s = $self->{Secret}{ $a{name} }
            or die "404 secrets \"$a{name}\" not found\n";
        return $s;
    }
    sub patch {
        my ($self, $kind, $name) = @_;
        push @events, [ patch => $kind, $name ];
        return 1;
    }
}

sub secret {
    my ($token) = @_;
    return { data => { token => encode_base64($token, '') } };
}

sub hetzner_cr {
    my ($name, %a) = @_;
    return {
        metadata => { name => $name, namespace => 'ocp-system' },
        spec     => {
            type => 'hetzner',
            (exists $a{cluster} ? ($a{cluster} ? (clusterName => $a{cluster}) : ())
                                : (clusterName => 'prod')),
            hetzner => { tokenSecretRef => { name => "tok-$name", key => 'token' } },
        },
    };
}

sub ocpnode {
    my ($name, %a) = @_;
    return {
        metadata => { name => $name, namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => $a{ref} },
        status   => { phase => 'Ready', providerId => $a{id}, publicIP => $a{ip} },
    };
}

my $STATUS_HCP = <<'YAML';
nodes:
  - name: police1
    provider: hetzner
    providerId: "111"
    public_ip: 1.1.1.1
YAML

sub project {
    my (%a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8($a{yaml} // <<'YAML');
name: prod
control_planes:
  provider: hetzner
  location: fsn1
  server_type: cx32
  nodes: 1
YAML
    $dir->child('.ocp', 'status.yaml')->spew_utf8($a{status} // $STATUS_HCP);
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
        local *OCP::Provider::_build = sub {
            my ($class, $args) = @_;
            return $args->{type} eq 'hetzner'
                ? FakeHetzner->new(token => $args->{token},
                                   cluster => $args->{cluster_name})
                : FakeHost->new(type => $args->{type});
        };
        local *OCP::Secrets::hetzner_token = sub { $a{token} };
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { FakeKey->new };
        eval { $cmd->execute([], []) };
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0],
             events => [@events] };
}

sub deleted {
    my ($r) = @_;
    return { map { ($_->[2] => $_->[3]) }
             grep { $_->[0] eq 'delete' && $_->[1] eq 'hetzner' } @{ $r->{events} } };
}

# ------------------------------------------------------------------ the bug

subtest 'no local token: the provider CR\'s Secret deletes the servers' => sub {
    my $config = project();
    my $k8s = FakeK8s->new(
        OCPNodeProvider => [ hetzner_cr('hetzner-default') ],
        Secret          => { 'tok-hetzner-default' => secret('cr-token') },
        OCPNode         => [ ocpnode('hw-1', ref => 'hetzner-default',
                                     id => '999', ip => '9.9.9.9') ],
    );
    my $r = run_destroy($config, k8s => $k8s);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is_deeply deleted($r), { 999 => 'cr-token', 111 => 'cr-token' },
        'the worker and the control plane are both deleted, with the CR token';
    is $r->{ret}, 0, 'exit 0' or diag $r->{err};
    ok !-f $config->status_file, 'a clean teardown removes status.yaml';
};

subtest 'each node is deleted with the token of its own provider' => sub {
    my $config = project();
    my $k8s = FakeK8s->new(
        OCPNodeProvider => [ hetzner_cr('hetzner-default'), hetzner_cr('hz-other') ],
        Secret          => { 'tok-hetzner-default' => secret('tok-a'),
                             'tok-hz-other'        => secret('tok-b') },
        OCPNode         => [
            ocpnode('hw-a', ref => 'hetzner-default', id => '201', ip => '2.0.0.1'),
            ocpnode('hw-b', ref => 'hz-other',        id => '202', ip => '2.0.0.2'),
        ],
    );
    my $r = run_destroy($config, k8s => $k8s, token => 'local-tok');

    is_deeply deleted($r),
        { 201 => 'tok-a', 202 => 'tok-b', 111 => 'local-tok' },
        'workers with their provider\'s token, the control plane with the local one';
    is $r->{ret}, 0, 'exit 0';
};

subtest 'the label search runs under the CR token too' => sub {
    my $config = project();
    local %LABELLED = ('cr-token' => [
        FakeServer->new(name => 'orphan', id => '555', ip => '5.5.5.5') ]);
    my $k8s = FakeK8s->new(
        OCPNodeProvider => [ hetzner_cr('hetzner-default') ],
        Secret          => { 'tok-hetzner-default' => secret('cr-token') },
    );
    my $r = run_destroy($config, k8s => $k8s);

    is_deeply deleted($r), { 555 => 'cr-token', 111 => 'cr-token' },
        'the orphan found under the CR token is deleted';
};

subtest 'a CR from before k98 (no clusterName) still deletes' => sub {
    my $config = project();
    my $k8s = FakeK8s->new(
        OCPNodeProvider => [ hetzner_cr('hetzner-default', cluster => undef) ],
        Secret          => { 'tok-hetzner-default' => secret('old-token') },
    );
    my $r = run_destroy($config, k8s => $k8s);
    is_deeply deleted($r), { 111 => 'old-token' }, 'deleted with its token';
    is $r->{ret}, 0, 'exit 0';
};

# ----------------------------------------------------- no token reaches it

subtest 'no token anywhere: refuse before deleting anything, name the servers' => sub {
    my $config = project(
        yaml   => <<'YAML',
name: prod
control_planes:
  provider: ssh
  host: cp.lan
YAML
        status => <<'YAML',
nodes:
  - name: cp
    provider: ssh
    public_ip: cp.lan
YAML
    );
    my $k8s = FakeK8s->new(
        OCPNodeProvider => [ hetzner_cr('hz-other') ],   # its Secret is gone
        OCPNode         => [ ocpnode('hw-b', ref => 'hz-other',
                                     id => '202', ip => '2.0.0.2') ],
    );
    my $r = run_destroy($config, k8s => $k8s);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 1, 'exit 1';
    is_deeply $r->{events}, [],
        'nothing deleted, robocop not stopped: the API still holds the record';
    like $r->{err}, qr/hw-b.*202.*2\.0\.0\.2/, 'name, id and address on STDERR';
    like $r->{err}, qr/not found/, 'with the reason the Secret could not be read';
    like $r->{err}, qr/token/i, 'and what is missing';
    unlike $r->{out}, qr/Cluster destroyed/, 'no success line';
    ok -f $config->status_file, 'status.yaml untouched';
};

subtest 'no token and no API: the status.yaml server is named, not skipped' => sub {
    my $config = project();
    my $r = run_destroy($config, k8s => FakeK8s->new(down => 1));

    is $r->{ret}, 1, 'exit 1';
    is_deeply deleted($r), {}, 'nothing deleted';
    like $r->{err}, qr/police1.*111.*1\.1\.1\.1/, 'name, id and address on STDERR';
    ok -f $config->status_file, 'status.yaml kept';
};

subtest 'with the local token nothing changes' => sub {
    my $config = project();
    my $r = run_destroy($config, token => 'local-tok');
    is_deeply deleted($r), { 111 => 'local-tok' }, 'deleted';
    is $r->{ret}, 0, 'exit 0';
    is $r->{err}, '', 'no STDERR';
};

done_testing;

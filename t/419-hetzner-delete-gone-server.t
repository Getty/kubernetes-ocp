#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS qw(encode_json);
use Path::Tiny qw(path);

use lib 'lib';

use WWW::Hetzner::Error;
use WWW::Hetzner::HTTPResponse;
use WWW::Hetzner::LWPIO;

use OCP;
use OCP::Cmd::Destroy;
use OCP::Config;
use OCP::K8s;
use OCP::KnownHosts;
use OCP::Node;
use OCP::Provider::Hetzner;

#
# k419: a server Hetzner no longer has -- deleted by hand in the console, or
# by an earlier teardown that died after the delete -- answers the delete with
# 404 not_found. That failed every teardown path: robocop and `ocp node rm`
# (OCP::Node->teardown) set the OCPNode to Failed and kept it, `ocp destroy`
# warned and exited 1, and every rerun failed the same way. The server is
# gone, which is what the delete was for: the Hetzner adapter now counts that
# answer as deleted, read from the WWW::Hetzner::Error object (status 404,
# code not_found), not from the message text.
#
# Only the wire is fake: the client is the real WWW::Hetzner::Cloud the
# adapter builds, and every error is the one WWW::Hetzner raises from the
# answer below.
#

no warnings 'once';

my $TOKEN = 'hzTOKEN-k419-0123456789';

our %ROUTES;    # "METHOD /path" => [ status, body ]
our @SENT;

sub wire {
    my ($io, $req) = @_;
    (my $path = $req->url) =~ s{\Ahttps://api\.hetzner\.cloud/v1}{};
    ($path) = split /\?/, $path;
    my $key = $req->method . " $path";
    push @SENT, $key;
    my ($status, $body) = @{ $ROUTES{$key} // [ 401, { error => { code => 'unauthorized', message => 'unable to authenticate' } } ] };
    return WWW::Hetzner::HTTPResponse->new(status => $status, content => encode_json($body));
}

my $GONE = [ 404, { error => { code => 'not_found', message => "server with ID '111' not found" } } ];

my $tmp = path(tempdir(CLEANUP => 1));
$ENV{OCP_KNOWN_HOSTS} = $tmp->child('known_hosts')->stringify;

sub known_hosts_with {
    my ($host) = @_;
    path($ENV{OCP_KNOWN_HOSTS})->spew("$host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr\n");
}

# ---------------------------------------------------------------- the adapter

subtest 'the adapter: what WWW::Hetzner raises for a gone server is the error object' => sub {
    no warnings 'redefine';
    local *WWW::Hetzner::LWPIO::call = \&wire;
    local %ROUTES = ('DELETE /servers/111' => $GONE);
    my $prov = OCP::Provider::Hetzner->new(token => $TOKEN, cluster_name => 'lab');
    my $err = do { eval { $prov->cloud->servers->delete(111) }; $@ };
    isa_ok $err, 'WWW::Hetzner::Error', 'the raw client error';
    is $err->status, 404, 'status 404';
    is $err->code, 'not_found', 'code not_found';
};

subtest 'the adapter: a server Hetzner reports as not found counts as deleted' => sub {
    no warnings 'redefine';
    local *WWW::Hetzner::LWPIO::call = \&wire;
    local %ROUTES = ('DELETE /servers/111' => $GONE);
    local @SENT;
    known_hosts_with('1.1.1.1');
    my $prov = OCP::Provider::Hetzner->new(token => $TOKEN, cluster_name => 'lab');
    ok eval { $prov->delete_server(111, host => '1.1.1.1'); 1 }, 'delete_server returns'
        or diag $@;
    is_deeply \@SENT, ['DELETE /servers/111'], 'the delete went out, once';
    ok !OCP::KnownHosts->new->knows('1.1.1.1'), 'and the gone machine\'s host key left known_hosts';
};

subtest 'the adapter: every other refusal still dies, masked' => sub {
    no warnings 'redefine';
    local *WWW::Hetzner::LWPIO::call = \&wire;
    my $prov = OCP::Provider::Hetzner->new(token => $TOKEN, cluster_name => 'lab');
    for my $case (
        [ 'unauthorized',              [ 401, { error => { code => 'unauthorized', message => "Bearer $TOKEN refused" } } ] ],
        [ 'locked',                    [ 423, { error => { code => 'locked', message => 'server is locked' } } ] ],
        [ '404 without not_found',     [ 404, { error => { code => 'something_else', message => 'nope' } } ] ],
        [ '404 with no code (a proxy)', [ 404, 'Not Found' ] ],
    ) {
        my ($what, $answer) = @$case;
        local %ROUTES = ('DELETE /servers/111' => $answer);
        my $err = do { eval { $prov->delete_server(111) }; $@ };
        ok length $err, "$what: dies";
        ok !ref $err, "$what: as the adapter's masked line, not the raw object";
        unlike $err, qr/\Q$TOKEN\E/, "$what: without the token";
    }
};

# ---------------------------------------------------------------- OCP::Node

# robocop's teardown of a deleted OCPNode and `ocp node rm` are both
# OCP::Node->teardown; the cluster side is stubbed, the provider is real.
subtest 'OCP::Node teardown (robocop, ocp node rm): a gone server is torn down, not Failed' => sub {
    my @patches;
    my @deleted;
    no warnings 'redefine';
    local *WWW::Hetzner::LWPIO::call = \&wire;
    local %ROUTES = ('DELETE /servers/111' => $GONE);
    local *OCP::K8s::patch_status       = sub { my ($c, $api, %a) = @_; push @patches, $a{status}; 1 };
    local *OCP::Node::_acquire_lease    = sub { 1 };
    local *OCP::Node::_release_lease    = sub { 1 };
    local *OCP::Node::_cordon           = sub { 0 };
    local *OCP::Node::_seed_known_hosts = sub { $ENV{OCP_KNOWN_HOSTS} };
    local *OCP::Node::_release_finalizer = sub { 1 };
    local *OCP::Node::_delete_object    = sub { my ($self, $kind, $name) = @_; push @deleted, "$kind/$name"; 1 };

    my $n = OCP::Node->from_cr({
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'hetzner-fsn1' },
        status   => { phase => 'Ready', publicIP => '1.1.1.1', providerId => '111' },
    }, k8s => 'x', provider => OCP::Provider::Hetzner->new(token => $TOKEN, cluster_name => 'lab'));

    my $ok = eval { $n->teardown };
    ok $ok, 'teardown succeeds' or diag $@;
    ok !(grep { ($_->{phase} // '') eq 'Failed' } @patches), 'no Failed phase written';
    ok !$n->machine_cleanup_failed, 'the machine is not reported as left behind';
    is_deeply \@deleted, [ 'Node/w1', 'OCPNode/w1' ], 'the Node and the OCPNode go';
};

# ---------------------------------------------------------------- ocp destroy

sub project {
    my ($status) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(<<'YAML');
name: lab
control_planes:
  provider: hetzner
  server_type: cx42
  location: nbg1
  nodes: 1
YAML
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    $dir->child('.ocp', 'status.yaml')->spew_utf8($status);
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

subtest 'ocp destroy: a gone server is deleted, no warning, exit 0' => sub {
    my $config = project(<<'YAML');
nodes:
  - name: police1
    provider: hetzner
    providerId: "111"
    public_ip: 1.1.1.1
YAML
    my ($out, $err, $code) = ('', '');
    local @SENT;
    local %ROUTES = (
        'DELETE /servers/111' => $GONE,
        'GET /servers'        => [ 200, { servers => [], meta => { pagination => { page => 1, per_page => 50, next_page => undef, last_page => 1, total_entries => 0 } } } ],
    );
    {
        local @ARGV = ('-c', $config->file, 'destroy', '--force');
        local $ENV{HETZNER_API_TOKEN} = $TOKEN;
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        local *STDERR;
        open STDERR, '>', \$err or die;
        local $SIG{__WARN__} = sub { print STDERR @_ };
        no warnings 'redefine';
        local *WWW::Hetzner::LWPIO::call = \&wire;
        local *OCP::Cmd::Destroy::_cluster_api = sub { undef };
        $code = OCP->run_cli;
    }
    ok scalar(grep { $_ eq 'DELETE /servers/111' } @SENT), 'the delete went out';
    unlike $err, qr/Warning: Hetzner API error/, 'no warning for the gone server';
    unlike $err, qr/police1/, 'police1 is not named as left behind';
    is $code, 0, 'exit 0' or diag "STDOUT:\n$out\nSTDERR:\n$err";
};

done_testing;

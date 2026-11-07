#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use IO::Socket::INET ();
use JSON::MaybeXS ();
use POSIX ();
use Path::Tiny qw( path );

use lib 'lib';

use Kubernetes::REST ();
use Kubernetes::REST::APIError ();
use Kubernetes::REST::HTTPResponse ();
use OCP;
use OCP::Cmd::Health;
use OCP::Secrets;

#
# k387: k384 made an API that does not answer one line. An API that answers
# with an error -- 401 for a token that is wrong or expired, 403 for one RBAC
# does not let through, 500 for an API server in trouble -- still reached
# OCP.pm as Kubernetes::REST's error text, its source location in it, so
# ocp node ls, ocp health and ocp provider ls said "This is an internal
# error", and ocp status printed it as it came under "Cannot connect to
# cluster API". The claims, from bin/ocp against a local API server that
# answers with the error, for each of the four commands:
#   1. STDERR is one line naming the server the kubeconfig names, what the
#      answer means (credentials refused, request denied, the API failed),
#      the status and the API's own message;
#   2. the exit code is 1;
#   3. no output carries a Perl source location or "internal error" -- nor
#      Kubernetes::REST's discovery warning, which carries one;
#   4. ocp status keeps on STDOUT what it shows without the API, and --json
#      keeps STDOUT pure JSON (status, health and node ls: their object, the
#      line as its error; node ls's has nothing else -- k388).
# 401 is answered to every request, /version included, as a token the API
# server does not know is; 403 and 500 only to the resources, after /version
# and discovery were answered, as RBAC and a failing etcd do.
# Then the OCP::Role::Cmd methods behind it, status by status.
#

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};
delete local @ENV{qw( http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY )};

#### A local API server that answers with an error

my @servers;
END { kill 'TERM', @servers if @servers }

# $answer->($path) gives the status and the JSON body for one request. The
# server runs in a child until the test ends; each connection is one request.
sub fake_api {
    my ($answer) = @_;
    my $listen = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Listen    => 16,
        Proto     => 'tcp',
    ) or BAIL_OUT("cannot listen on a local port: $!");
    my $pid = fork // BAIL_OUT("fork: $!");
    unless ($pid) {
        alarm 900;
        my $json = JSON::MaybeXS->new(canonical => 1);
        while (my $c = $listen->accept) {
            local $/ = "\r\n";
            my $request = <$c>;
            next unless defined $request;
            while (my $h = <$c>) { last if $h eq "\r\n" }
            my (undef, $target) = split ' ', $request;
            (my $p = $target // '/') =~ s/\?.*//s;
            my ($code, $doc) = $answer->($p);
            my $body = $json->encode($doc);
            print {$c} "HTTP/1.1 $code Fake\r\n",
                "Content-Type: application/json\r\n",
                'Content-Length: ', length($body), "\r\n",
                "Connection: close\r\n\r\n", $body;
            close $c;
        }
        POSIX::_exit(0);
    }
    push @servers, $pid;
    return 'http://127.0.0.1:' . $listen->sockport;
}

sub status_doc {
    my ($code, $reason, $message) = @_;
    return { kind => 'Status', apiVersion => 'v1', metadata => {},
             status => 'Failure', reason => $reason, message => $message,
             code => $code };
}

# The last segment of a resource path, the plural the API server names.
sub plural_of { (split m{/}, $_[0])[-1] }

my %reached = (
    '/version' => [ 200, { major => '1', minor => '36', gitVersion => 'v1.36.4+rke2r1' } ],
    '/api'     => [ 200, { kind => 'APIGroupDiscoveryList',
                           apiVersion => 'apidiscovery.k8s.io/v2', items => [] } ],
);
$reached{'/apis'} = $reached{'/api'};

# Every request refused, /version included: a token the API server does not
# know.
my $s401 = fake_api(sub {
    return (401, status_doc(401, 'Unauthorized', 'Unauthorized'));
});

# /version and discovery answered, every resource denied: RBAC.
my $s403 = fake_api(sub {
    my ($p) = @_;
    return @{ $reached{$p} } if $reached{$p};
    my $plural = plural_of($p);
    return (403, status_doc(403, 'Forbidden',
        qq{$plural is forbidden: User "k387" cannot list resource "$plural"}));
});

# /version and discovery answered, every resource failing: etcd in trouble.
my $s500 = fake_api(sub {
    my ($p) = @_;
    return @{ $reached{$p} } if $reached{$p};
    return (500, status_doc(500, 'InternalError',
        'Internal error occurred: etcdserver: request timed out'));
});

#### From bin/ocp

# A deployed project as the machine that made it has it: the project key in
# .ocp/ (nothing to unlock, no PIN asked), kubeconfig.yaml encrypted to it,
# naming $server, and an ocp.yaml.
sub project {
    my ($server) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->save_kubeconfig(join "\n",
        'apiVersion: v1', 'kind: Config', 'current-context: k387',
        'clusters:', '- name: k387', '  cluster:', "    server: $server",
        'users:', '- name: k387', '  user:', '    token: k387-token',
        'contexts:', '- name: k387', '  context:', '    cluster: k387', '    user: k387', '');
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k387',
        control_planes => { provider => 'ssh', host => 'cp.k387.invalid' },
    });
    return $dir;
}

my $bin = path('bin/ocp')->absolute;
my $lib = path('lib')->absolute;

# bin/ocp in the project dir, STDIN empty and --pins-stdin, so a prompt that
# should not come ends the run instead of waiting.
sub run_ocp {
    my ($dir, @argv) = @_;
    my ($in, $out, $err) = map { Path::Tiny->tempfile } 1 .. 3;
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        open STDIN,  '<', "$in"  or die;
        open STDOUT, '>', "$out" or die;
        open STDERR, '>', "$err" or die;
        alarm 120;
        exec $^X, "-I$lib", "$bin", @argv, '--pins-stdin' or die "exec: $!";
    }
    waitpid $pid, 0;
    return ($?, $out->slurp_utf8, $err->slurp_utf8);
}

my $perl_text = qr/ at \S+ line \d+|internal error/;

sub json_of {
    my ($text) = @_;
    my $doc = eval { JSON::MaybeXS->new->decode($text) };
    ok ref $doc eq 'HASH', 'STDOUT: one JSON object, nothing else'
        or diag "STDOUT:\n$text";
    return $doc // {};
}

# Each command: its argv, the resource it asks for first, the label its
# STDERR line carries, and what is left on STDOUT.
my @commands = (
    [ ['status'], 'nodes', 'ERROR', sub {
          my ($o, $line) = @_;
          like $o, qr/^Cluster: k387$/m,             'STDOUT: the spec summary';
          like $o, qr/^Control Planes: 1 \(ssh\)$/m, 'STDOUT: the control planes from ocp.yaml';
          like $o, qr/^=== Status ===\nCluster exists \(kubeconfig\.yaml found\)$/m,
              'STDOUT: the status section says what it found';
          like $o, qr/\nKubeconfig available\. Export with: ocp kubeconfig -e\n\z/,
              'STDOUT: the kubeconfig hint closes the report';
          unlike $o, qr/cluster API|ERROR/, 'STDOUT: not the error';
      } ],
    [ ['status', '--json'], 'nodes', 'ERROR', sub {
          my ($o, $line) = @_;
          my $doc = json_of($o);
          is $doc->{cluster}, 'k387', 'JSON: the cluster from ocp.yaml';
          ok $doc->{deployed}, 'JSON: deployed';
          is_deeply $doc->{nodes}, [], 'JSON: no nodes';
          is $doc->{error}, $line, 'JSON: error is the line, as on STDERR';
      } ],
    [ ['node', 'ls'], 'ocpnodes', 'Error', sub {
          is $_[0], '', 'STDOUT: nothing';
      } ],
    [ ['node', 'ls', '--json'], 'ocpnodes', 'Error', sub {
          my ($o, $line) = @_;
          is_deeply json_of($o), { error => $line },
              'JSON: the line as its error, nothing else (k388)';
      } ],
    [ ['health'], 'pods', 'Error', sub {
          is $_[0], '', 'STDOUT: nothing';
      } ],
    [ ['health', '--json'], 'pods', 'Error', sub {
          my ($o, $line) = @_;
          my $doc = json_of($o);
          is $doc->{error}, $line, 'JSON: error is the line, as on STDERR';
          ok exists $doc->{healthy} && !$doc->{healthy}, 'JSON: not healthy';
          is_deeply $doc->{pods}, [], 'JSON: no pods';
      } ],
    [ ['provider', 'ls'], 'ocpnodeproviders', 'Error', sub {
          is $_[0], '', 'STDOUT: nothing';
      } ],
);

my @codes = (
    [ 401, $s401, sub { "The cluster API at $s401 refused the credentials in the kubeconfig (401 Unauthorized)" } ],
    [ 403, $s403, sub { qq{The cluster API at $s403 denied the request (403 Forbidden): $_[0] is forbidden: User "k387" cannot list resource "$_[0]"} } ],
    [ 500, $s500, sub { "The cluster API at $s500 failed (500 Internal Error): Internal error occurred: etcdserver: request timed out" } ],
);

for my $c (@codes) {
    my ($code, $server, $line_for) = @$c;
    my $dir = project($server);
    for my $cmd (@commands) {
        my ($argv, $plural, $label, $check) = @$cmd;
        my $line = $line_for->($plural);
        my ($st, $o, $e) = (0, '', '');
        subtest "ocp @$argv, the API answers $code" => sub {
            ($st, $o, $e) = run_ocp($dir, @$argv);
            is $st & 127, 0, 'no signal (alarm)';
            is $st >> 8, 1, 'exit 1';
            is $e, "$label: $line\n", 'STDERR: one line, the server, the status and the message';
            $check->($o, $line);
            unlike $e, $perl_text, 'STDERR: no Perl source location, no "internal error"';
            unlike $o, $perl_text, 'STDOUT: no Perl source location, no "internal error"';
            unlike "$o$e", qr/k387-token/, 'the token is not shown';
        } or diag "ocp @$argv ($code): exit=" . ($st >> 8) . "\n--- STDOUT:\n$o--- STDERR:\n$e";
    }
}

#### k388: ocp node ls --json, the Nodes after the OCPNodes

# ocp node ls --json lists the OCPNodes, then the Kubernetes Nodes. An API that
# lets the first through and denies the second -- RBAC that may list the OCP
# Kinds but not Nodes -- ends in the object too, its line naming the Nodes. An
# API that answers both with nothing is [] and exit 0: "no nodes", which a
# reader of --json could tell from "could not ask" by the exit code alone
# before.

# The core group as discovery serves it, with the Nodes in it: the client node
# ls builds from the kubeconfig resolves a Kind from discovery, and an empty
# one leaves Node unknown to it.
my $core = { kind => 'APIGroupDiscoveryList', apiVersion => 'apidiscovery.k8s.io/v2',
             items => [ { metadata => {}, versions => [ { version => 'v1', resources => [
                 { resource => 'nodes', scope => 'Cluster',
                   responseKind => { group => '', version => 'v1', kind => 'Node' } },
             ] } ] } ] };

# /version and discovery answered, the resources named here as an empty
# list, every other one denied.
sub lists_api {
    my (%empty) = @_;
    return fake_api(sub {
        my ($p) = @_;
        return (200, $core) if $p eq '/api';
        return @{ $reached{$p} } if $reached{$p};
        my $plural = plural_of($p);
        return (200, { kind => $empty{$plural}[0], apiVersion => $empty{$plural}[1],
                       metadata => {}, items => [] })
            if $empty{$plural};
        return (403, status_doc(403, 'Forbidden',
            qq{$plural is forbidden: User "k387" cannot list resource "$plural"}));
    });
}

my $s403n = lists_api(ocpnodes => [ 'OCPNodeList', 'ocp.internal/v1' ]);
my $s200  = lists_api(ocpnodes => [ 'OCPNodeList', 'ocp.internal/v1' ],
                      nodes    => [ 'NodeList', 'v1' ]);

{
    my $line = qq{The cluster API at $s403n denied the request (403 Forbidden): }
             . qq{nodes is forbidden: User "k387" cannot list resource "nodes"};
    my ($st, $o, $e) = (0, '', '');
    subtest 'ocp node ls --json, the OCPNodes listed and the Nodes denied' => sub {
        ($st, $o, $e) = run_ocp(project($s403n), 'node', 'ls', '--json');
        is $st & 127, 0, 'no signal (alarm)';
        is $st >> 8, 1, 'exit 1';
        is $e, "Error: $line\n", 'STDERR: the line for the Nodes';
        is_deeply json_of($o), { error => $line }, 'JSON: the object, not an empty list';
        unlike "$o$e", $perl_text, 'no Perl source location, no "internal error"';
    } or diag "exit=" . ($st >> 8) . "\n--- STDOUT:\n$o--- STDERR:\n$e";
}

{
    my ($st, $o, $e) = (0, '', '');
    subtest 'ocp node ls --json, a cluster without OCPNodes: [] and exit 0' => sub {
        ($st, $o, $e) = run_ocp(project($s200), 'node', 'ls', '--json');
        is $st & 127, 0, 'no signal (alarm)';
        is $st >> 8, 0, 'exit 0';
        is $e, '', 'STDERR: nothing';
        my $doc = eval { JSON::MaybeXS->new->decode($o) };
        is_deeply $doc, [], 'JSON: an empty list';
    } or diag "exit=" . ($st >> 8) . "\n--- STDOUT:\n$o--- STDERR:\n$e";
}

#### OCP::Role::Cmd: the line for each status

{
    # The transport of a Kubernetes::REST client: answers every request with
    # one response, and keeps the requests.
    package Local::IO;
    sub new  { bless { res => $_[1], calls => [] }, $_[0] }
    sub call { push @{ $_[0]{calls} }, $_[1]; $_[0]{res} }
}

my $cmd = OCP::Cmd::Health->new;
my $at  = 'The cluster API at https://10.9.8.7:6443';

sub client {
    my ($res) = @_;
    return Kubernetes::REST->new(
        server      => { endpoint => 'https://10.9.8.7:6443' },
        credentials => { token => 't' },
        io          => Local::IO->new($res),
    );
}

sub status_json { JSON::MaybeXS->new(canonical => 1)->encode(status_doc(@_)) }

subtest 'cluster_api_error: one line per status' => sub {
    my $api = client(undef);
    my @cases = (
        [ 401, status_json(401, 'Unauthorized', 'Unauthorized'),
          "$at refused the credentials in the kubeconfig (401 Unauthorized)",
          '401: the credentials, the API message only repeating the status is left out' ],
        [ 403, status_json(403, 'Forbidden', 'nodes is forbidden: User "u" cannot list resource "nodes"'),
          qq{$at denied the request (403 Forbidden): nodes is forbidden: User "u" cannot list resource "nodes"},
          '403: denied, and the API says what and for whom' ],
        [ 500, status_json(500, 'InternalError', 'Internal error occurred: etcd'),
          "$at failed (500 Internal Error): Internal error occurred: etcd",
          '500: failed, the reason in words' ],
        [ 503, 'service unavailable',
          "$at failed (503): service unavailable",
          '503 without a Status body: the body is the message' ],
        [ 502, '',
          "$at failed (502)",
          '502 without a body: the status alone' ],
        [ 404, "404 page not found\n",
          "$at answered (404): 404 page not found",
          '404: an answer, not "could not be reached"' ],
        [ 404, status_json(404, 'NotFound', 'the server could not find the requested resource'),
          "$at answered (404 Not Found): the server could not find the requested resource",
          '404 with a Status body' ],
        [ 422, status_json(422, 'Invalid', "Node \"x\" is invalid:\n  spec: bad"),
          qq{$at answered (422 Invalid): Node "x" is invalid: spec: bad},
          'a message over lines is one line' ],
        [ 599, "Can't connect to 10.9.8.7:6443 (Connection refused)\n\n"
             . "Connection refused at /usr/share/perl5/LWP/Protocol/http.pm line 49.\n",
          "$at could not be reached: Can't connect to 10.9.8.7:6443 (Connection refused)",
          '599: could not be reached, the first line of the reason: "Connection refused" once' ],
        [ 599, "read timeout at /usr/share/perl5/LWP/Protocol/http.pm line 389.\n",
          "$at could not be reached: read timeout",
          '599 in one line: without its location' ],
    );
    for my $c (@cases) {
        my ($code, $body, $want, $name) = @$c;
        my $err = Kubernetes::REST::APIError->new(code => $code, body => $body, context => 'list Node');
        is $cmd->cluster_api_error($api, $err), $want, $name;
    }

    ok !defined $cmd->cluster_api_error($api, "connection refused\n"), 'a string: nothing';
    ok !defined $cmd->cluster_api_error($api, bless({}, 'Local::Other')), 'another object: nothing';
};

subtest 'reach_cluster_api: GET /version, any error status ends the command with its line' => sub {
    my $ok = client(Kubernetes::REST::HTTPResponse->new(status => 200, content => '{"gitVersion":"v1.36.4"}'));
    is eval { $cmd->reach_cluster_api($ok) }, $ok, '200: the client comes back';
    is $@, '', '200: nothing dies';
    my @calls = @{ $ok->io->{calls} };
    is scalar @calls, 1, 'one request';
    is $calls[0]->method, 'GET', 'a GET';
    is $calls[0]->url, 'https://10.9.8.7:6443/version', 'of /version';

    for my $c ([ 401, status_json(401, 'Unauthorized', 'Unauthorized'),
                 "$at refused the credentials in the kubeconfig (401 Unauthorized)" ],
               [ 403, status_json(403, 'Forbidden', 'forbidden: User "u" cannot get path "/version"'),
                 qq{$at denied the request (403 Forbidden): forbidden: User "u" cannot get path "/version"} ],
               [ 404, "404 page not found\n", "$at answered (404): 404 page not found" ],
               [ 500, status_json(500, 'InternalError', 'boom'), "$at failed (500 Internal Error): boom" ]) {
        my ($code, $body, $want) = @$c;
        my $api = client(Kubernetes::REST::HTTPResponse->new(status => $code, content => $body));
        ok !eval { $cmd->reach_cluster_api($api); 1 }, "$code: dies";
        is $@, "$want\n", "$code: with the line, a user error";
    }
};

subtest 'cluster_api_call: an API error is the line, anything else passes as it came' => sub {
    my $api = client(undef);
    is $cmd->cluster_api_call($api, sub { 'listed' }), 'listed', 'the call\'s result';
    is $cmd->cluster_api_call($api, sub { 0 }), 0, 'a false result too';

    my $err = Kubernetes::REST::APIError->new(code => 403,
        body => status_json(403, 'Forbidden', 'pods is forbidden'), context => 'list Pod');
    ok !eval { $cmd->cluster_api_call($api, sub { die $err }); 1 }, 'an API error: dies';
    is $@, "$at denied the request (403 Forbidden): pods is forbidden\n", 'with the line';

    ok !eval { $cmd->cluster_api_call($api, sub { die "no such Kind\n" }); 1 }, 'a string: dies';
    is $@, "no such Kind\n", 'as it came';
    my $other = bless {}, 'Local::Other';
    ok !eval { $cmd->cluster_api_call($api, sub { die $other }); 1 }, 'another object: dies';
    is $@, $other, 'the same object';
};

done_testing;

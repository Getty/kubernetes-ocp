#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use IO::Socket::INET ();
use JSON::MaybeXS ();
use Path::Tiny qw( path );

use lib 'lib';

use Kubernetes::REST ();
use Kubernetes::REST::APIError ();
use Kubernetes::REST::HTTPResponse ();
use OCP;
use OCP::Cmd::Health;
use OCP::Secrets;

#
# k384: when the Kubernetes API cannot be reached, ocp status, ocp node ls,
# ocp health and ocp provider ls ended in Kubernetes::REST's transport error
# as it came: LWP's text with its own " at FILE line N." inside, the client's
# behind it, and a discovery warning before it for the OCP Kinds. Where the
# error reached OCP.pm, the location made it "This is an internal error. Run
# again with --verbose". An API that does not answer is the most ordinary
# operational failure there is. The claims, from bin/ocp, for each command:
#   1. STDERR says, in one line, that the cluster API at the server the
#      kubeconfig names could not be reached, and why (the transport reason,
#      said once: LWP says it twice, k387);
#   2. the exit code is 1;
#   3. no output carries a Perl source location or "internal error";
#   4. ocp status keeps on STDOUT what it can show without the API: the spec
#      summary from ocp.yaml, that the cluster exists, the kubeconfig hint;
#   5. --json keeps STDOUT pure JSON: status, health and node ls print an
#      object with the error in it (node ls: that and nothing else, where it
#      lists an array -- k388); STDERR says it as without --json;
#   6. a kubeconfig no client can be built from is not "could not be
#      reached": ocp status reports it as before.
# And of the OCP::Role::Cmd methods that say it: only a transport failure
# (status 599) is "could not be reached"; an answer from the API server, an
# error status included, is not (the lines for those: t/387).
#

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

#### OCP::Role::Cmd: reach_cluster_api and cluster_api_error

{
    # The transport of a Kubernetes::REST client: answers every request with
    # one response, and keeps the requests.
    package Local::IO;
    sub new  { bless { res => $_[1], calls => [] }, $_[0] }
    sub call { push @{ $_[0]{calls} }, $_[1]; $_[0]{res} }

    # What OCP::Kubernetes is to ocp status: an api accessor whose builder
    # dies when there is no client to give.
    package Local::Holder;
    sub new { bless { api => $_[1] }, $_[0] }
    sub api { $_[0]{api} // die "kubeconfig: no current-context\n" }
}

sub client {
    my ($res) = @_;
    return Kubernetes::REST->new(
        server      => { endpoint => 'https://10.9.8.7:6443' },
        credentials => { token => 't' },
        io          => Local::IO->new($res),
    );
}

my $cmd = OCP::Cmd::Health->new;
my $lwp = "Can't connect to 10.9.8.7:6443 (Connection refused)\n\n"
        . "Connection refused at /usr/share/perl5/LWP/Protocol/http.pm line 49.";
my $said = 'The cluster API at https://10.9.8.7:6443 could not be reached: '
         . "Can't connect to 10.9.8.7:6443 (Connection refused)";

subtest 'reach_cluster_api: a transport failure dies with the line' => sub {
    my $api = client(Kubernetes::REST::HTTPResponse->new(status => 599, content => $lwp));
    ok !eval { $cmd->reach_cluster_api($api); 1 }, '599: dies';
    is $@, "$said\n", '599: the server and the reason, one line, a user error';
    my @calls = @{ $api->io->{calls} };
    is scalar @calls, 1, 'one request';
    is $calls[0]->method . ' ' . $calls[0]->url, 'GET https://10.9.8.7:6443/version', 'GET /version';

    my $ok = client(Kubernetes::REST::HTTPResponse->new(status => 200, content => '{}'));
    is eval { $cmd->reach_cluster_api($ok) }, $ok, '200: the client comes back';
    is $@, '', '200: nothing dies';

    for my $status (401, 403, 404, 500, 503) {
        my $answered = client(Kubernetes::REST::HTTPResponse->new(status => $status, content => 'x'));
        ok !eval { $cmd->reach_cluster_api($answered); 1 }, "$status: dies";
        like $@, qr/\AThe cluster API at https:\/\/10\.9\.8\.7:6443 [^\n]*\($status\): x\n\z/,
            "$status: an answer, with its status";
        unlike $@, qr/could not be reached/, "$status: not \"could not be reached\"";
    }
};

subtest 'cluster_api_error: the line for a caught 599' => sub {
    my $api = client(undef);
    my $err = Kubernetes::REST::APIError->new(code => 599, body => $lwp, context => 'list Node');
    is $cmd->cluster_api_error($api, $err), $said, '599: the line';

    my $forbidden = Kubernetes::REST::APIError->new(code => 403, body => '{}', context => 'list Node');
    unlike $cmd->cluster_api_error($api, $forbidden), qr/could not be reached/,
        '403: the API answered, not "could not be reached"';
    ok !defined $cmd->cluster_api_error($api, "connection refused\n"), 'a string: nothing';
    is eval { $cmd->cluster_api_error(undef, "connection refused\n") }, undef,
        'nothing, without asking the client';
    is $@, '', 'and nothing dies';

    # ocp status hands over its OCP::Kubernetes: the client is asked of it
    # only for an APIError, so a client whose build died is not built again.
    my $holder = Local::Holder->new($api);
    is $cmd->cluster_api_error($holder, $err), $said, 'an OCP::Kubernetes: its client names the server';
    my $broken = Local::Holder->new(undef);
    is eval { $cmd->cluster_api_error($broken, "kubeconfig: no current-context\n") }, undef,
        'a build that died: nothing';
    is $@, '', 'and the builder is not run again';
};

#### From bin/ocp

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};

# A local port nothing listens on: bound and never listening, held for the
# whole test, so no other process can take it and every connect is refused.
my $closed = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Proto     => 'tcp',
) or BAIL_OUT("cannot bind a local port: $!");
my $port   = $closed->sockport;
my $server = "https://127.0.0.1:$port";

# A deployed project as the machine that made it has it: the project key in
# .ocp/ (nothing to unlock, no PIN asked), kubeconfig.yaml encrypted to it,
# naming the closed port, and an ocp.yaml.
sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->save_kubeconfig(join "\n",
        'apiVersion: v1', 'kind: Config', 'current-context: k384',
        'clusters:', '- name: k384', '  cluster:', "    server: $server",
        '    insecure-skip-tls-verify: true',
        'users:', '- name: k384', '  user:', '    token: t',
        'contexts:', '- name: k384', '  context:', '    cluster: k384', '    user: k384', '');
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k384',
        control_planes => { provider => 'ssh', host => 'cp.k384.invalid' },
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

# The one line, without its label: the server from the kubeconfig, then the
# transport reason.
my $unreachable = qr/The cluster API at \Q$server\E could not be reached: [^\n]*Connection refused[^\n]*/;
my $perl_text   = qr/ at \S+ line \d+|internal error/;

sub json_of {
    my ($text) = @_;
    my $doc = eval { JSON::MaybeXS->new->decode($text) };
    ok ref $doc eq 'HASH', 'STDOUT: one JSON object, nothing else'
        or diag "STDOUT:\n$text";
    return $doc // {};
}

my @commands = (
    [ ['status'], sub {
          my ($o, $e) = @_;
          like $e, qr/\AERROR: $unreachable\n\z/, 'STDERR: the API and why, one line, nothing else';
          like $o, qr/^Cluster: k384$/m,         'STDOUT: the spec summary';
          like $o, qr/^=== Spec ===$/m,          'STDOUT: the spec section';
          like $o, qr/^Control Planes: 1 \(ssh\)$/m, 'STDOUT: the control planes from ocp.yaml';
          like $o, qr/^=== Status ===\nCluster exists \(kubeconfig\.yaml found\)$/m,
              'STDOUT: the status section says what it found';
          like $o, qr/\nKubeconfig available\. Export with: ocp kubeconfig -e\n\z/,
              'STDOUT: the kubeconfig hint closes the report';
          unlike $o, qr/could not be reached|Connection refused|ERROR/,
              'STDOUT: neither the error nor its cause';
      } ],
    [ ['status', '--json'], sub {
          my ($o, $e) = @_;
          like $e, qr/\AERROR: $unreachable\n\z/, 'STDERR: the API and why, one line, nothing else';
          my $doc = json_of($o);
          is $doc->{cluster}, 'k384', 'JSON: the cluster from ocp.yaml';
          is $doc->{spec}{control_planes}{provider}, 'ssh', 'JSON: the spec from ocp.yaml';
          ok $doc->{deployed}, 'JSON: deployed';
          is_deeply $doc->{nodes}, [], 'JSON: no nodes';
          like $doc->{error} // '', qr/\A$unreachable\z/, 'JSON: error says it, as on STDERR';
      } ],
    [ ['node', 'ls'], sub {
          my ($o, $e) = @_;
          like $e, qr/\AError: $unreachable\n\z/, 'STDERR: the API and why, one line, nothing else';
          is $o, '', 'STDOUT: nothing';
      } ],
    [ ['node', 'ls', '--json'], sub {
          my ($o, $e) = @_;
          like $e, qr/\AError: $unreachable\n\z/, 'STDERR: the API and why, one line, as without --json';
          my $doc = json_of($o);
          like $doc->{error} // '', qr/\A$unreachable\z/, 'JSON: error says it, as on STDERR';
          is_deeply [ sort keys %$doc ], ['error'], 'JSON: the error and nothing else (k388)';
      } ],
    [ ['health'], sub {
          my ($o, $e) = @_;
          like $e, qr/\AError: $unreachable\n\z/, 'STDERR: the API and why, one line, nothing else';
          is $o, '', 'STDOUT: nothing';
      } ],
    [ ['health', '--json'], sub {
          my ($o, $e) = @_;
          like $e, qr/\AERROR: $unreachable\n\z/, 'STDERR: the API and why, one line, nothing else';
          my $doc = json_of($o);
          like $doc->{error} // '', qr/\A$unreachable\z/, 'JSON: error says it, as on STDERR';
          ok exists $doc->{healthy} && !$doc->{healthy}, 'JSON: not healthy';
          is_deeply $doc->{pods}, [], 'JSON: no pods';
      } ],
    [ ['provider', 'ls'], sub {
          my ($o, $e) = @_;
          like $e, qr/\AError: $unreachable\n\z/, 'STDERR: the API and why, one line, nothing else';
          is $o, '', 'STDOUT: nothing';
      } ],
);

my $dir = project();

for my $c (@commands) {
    my ($argv, $check) = @$c;
    my ($st, $o, $e);
    subtest "ocp @$argv, the API refuses every connection" => sub {
        ($st, $o, $e) = run_ocp($dir, @$argv);
        is $st & 127, 0, 'no signal (alarm)';
        is $st >> 8, 1, 'exit 1';
        $check->($o, $e);
        unlike $e, $perl_text, 'STDERR: no Perl source location, no "internal error"';
        unlike $o, $perl_text, 'STDOUT: no Perl source location, no "internal error"';
        unlike $e, qr/PIN/, 'no PIN asked: the key is in .ocp/';
        is scalar(() = $e =~ /Connection refused/g), 1, 'STDERR: the reason said once';
    } or diag "ocp @$argv: exit=" . ($st >> 8) . "\n--- STDOUT:\n$o--- STDERR:\n$e";
}

# Nothing to ask with: without an ocp.yaml, ocp node ls --json still answers
# with the object (k388), and STDERR says it as without --json.
{
    my $empty = path(tempdir(CLEANUP => 1));
    my $why   = "Config file 'ocp.yaml' not found. Run 'ocp init' first.";
    my ($st, $o, $e);
    subtest 'ocp node ls --json, no ocp.yaml: the object, the message as its error' => sub {
        ($st, $o, $e) = run_ocp($empty, 'node', 'ls', '--json');
        is $st & 127, 0, 'no signal (alarm)';
        is $st >> 8, 1, 'exit 1';
        is $e, "Error: $why\n", 'STDERR: as without --json';
        is_deeply json_of($o), { error => $why }, 'JSON: the message as its error, nothing else';
    } or diag "exit=" . ($st >> 8) . "\n--- STDOUT:\n$o--- STDERR:\n$e";
}

# A kubeconfig no client can be built from is not an API that could not be
# reached, and ocp status reports it as before: building the client is not
# tried a second time on the way to the message.
{
    my $bad = project();
    OCP::Secrets->new(project_dir => $bad, ocp => $ocp)
        ->save_kubeconfig("apiVersion: v1\nkind: Config\n");
    my ($st, $o, $e);
    subtest 'ocp status, a kubeconfig without contexts: reported as before' => sub {
        ($st, $o, $e) = run_ocp($bad, 'status');
        is $st & 127, 0, 'no signal (alarm)';
        is $st >> 8, 1, 'exit 1';
        like $e, qr/\AWARNING: Cannot connect to cluster API\nError: [^\n]*(?i:kubeconfig)/,
            'STDERR: the build error, as before';
        unlike $e, qr/could not be reached|internal error/, 'not called unreachable, not internal';
        like $o, qr/\nKubeconfig available\. Export with: ocp kubeconfig -e\n\z/,
            'STDOUT: the report still ends on the kubeconfig hint';
    } or diag "exit=" . ($st >> 8) . "\n--- STDOUT:\n$o--- STDERR:\n$e";
}

done_testing;

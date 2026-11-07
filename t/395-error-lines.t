#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Cwd ();
use File::Temp qw( tempdir );
use IO::Socket::INET ();
use JSON::MaybeXS ();
use POSIX ();
use Path::Tiny qw( path );

use lib 'lib';
use lib 't/lib';

use Kubernetes::REST ();
use Kubernetes::REST::APIError ();
use OCP;
use OCP::Cmd::Health;
use OCP::Cmd::Node::Ls;
use OCP::Cmd::Status;
use OCP::Config;
use OCP::Drift;
use OCP::ErrorLine;
use OCP::K8s;
use OCP::Secrets;
use OCPTest::Cli qw( run_ocp );

#
# k395: what was left of raw errors in one-line places after k387 and k399.
# The claims, one subtest each:
#   1. one_line says a 599 -- an API that does not answer -- with its
#      transport reason once: Kubernetes::REST's body for it is LWP's text,
#      which says the reason again below its first line, with LWP's own
#      source location. Only the first line stands for the body, as
#      api_error_line says a 599; a plain refusal of several lines is still
#      folded whole.
#   2. the error field of ocp status --json, ocp health --json and ocp node
#      ls --json is one line without an ERROR:/Error: label, the same in all
#      three for the same refusal (OCP::Secrets' no_kubeconfig_refusal, a
#      label and indented lines of its own); each one's STDERR is what the
#      command says without --json -- health --json said "ERROR: ERROR:"
#      there, where ocp health says "Error:".
#   3. ocp node ls --json against an API whose discovery answers without the
#      Kind Node is one line naming the server, not "This is an internal
#      error" with Kubernetes::REST's croak and its location.
#   4. the drift table: the message of an error entry for a failed read --
#      distribution_drift's Node list, _unknown_drift's every probe -- is
#      the API error's one line, never Kubernetes::REST's text with its
#      " at FILE line N."; anything else is one line without a location too.
#   5. OCP::Cmd::Apply loads File::Temp only if it uses it (it loaded it and
#      used nothing of it).
#

local @ARGV = ();
delete local @ENV{qw( http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY )};

my $LOCATION = qr/ at \S+ line \d+/;

sub api_err { Kubernetes::REST::APIError->new(@_) }

# What Kubernetes::REST throws for a refused connection: LWP's text as the
# body -- the reason, a blank line, the reason again with LWP's location --
# and the caller's location croak adds.
my $lwp_body = "Can't connect to 10.0.0.1:6443 (Connection refused)\n\n"
             . "Connection refused at /usr/share/perl5/LWP/Protocol/http.pm line 49.";
my $e599 = api_err(code => 599, context => 'patch OCPNode', body => $lwp_body,
    _location => ' at lib/OCP/Cmd/Apply/CR.pm line 396.');

#### 1: one_line and a 599

subtest 'one_line: a 599 says its transport reason once' => sub {
    my $line = OCP::ErrorLine::one_line($e599);
    is $line, "Kubernetes API error (patch OCPNode): 599 Can't connect to 10.0.0.1:6443 (Connection refused)",
        "Kubernetes::REST's words, the body's first line";
    unlike $line, $LOCATION, 'no source location';
    is scalar(() = $line =~ /Connection refused/g), 1, 'the reason said once';
    is OCP::ErrorLine::one_line($e599, mask => '10.0.0.1:6443'),
        'Kubernetes API error (patch OCPNode): 599 Can\'t connect to ******** (Connection refused)',
        'the mask still applies';

    # The same, from a real Kubernetes::REST against a port nothing listens on.
    my $port = do {
        my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                      Listen => 1, Proto => 'tcp')
            or BAIL_OUT("cannot listen on a local port: $!");
        my $p = $s->sockport;
        close $s;
        $p;
    };
    my $api = Kubernetes::REST->new(server => { endpoint => "http://127.0.0.1:$port" },
                                    credentials => { token => 'k395-token-0000' });
    my $err = do { local $@; eval { $api->get('Pod', 'x', namespace => 'default') }; $@ };
    ok ref $err && $err->isa('Kubernetes::REST::APIError') && $err->code == 599,
        'Kubernetes::REST: a 599' or diag "$err";
    my $real = OCP::ErrorLine::one_line($err);
    unlike $real, qr/\n/, 'a real one: one line';
    unlike $real, $LOCATION, 'a real one: no source location';
    is scalar(() = $real =~ /Connection refused/g), 1, 'a real one: the reason said once'
        or diag "body:\n" . $err->body;

    # Not an APIError: a refusal of several lines is folded whole, as before.
    is OCP::ErrorLine::one_line("ERROR: first line.\n       second line.\n\nthird at lib/X.pm line 3.\n"),
        'ERROR: first line. second line. third', 'a plain refusal: every line, folded';
    is OCP::ErrorLine::one_line(api_err(code => 599, body => '', _location => ' at x line 1.')),
        'Kubernetes API error (): 599', 'a 599 without a body: what is there';
};

#### 2: the --json error fields

# The refusal as one line without its label, built from its lines here
# rather than by the code under test (as t/391 builds it).
my $refusal = OCP::Secrets->no_kubeconfig_refusal;
(my $refusal_line = join ' ', map { s/\A\s+//r } split /\n/, $refusal) =~ s/\AERROR: //;

# A project with an ocp.yaml, and a kubeconfig.yaml unless kubeconfig => 0.
sub project {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew(join "\n",
        'name: k395', 'control_planes:', '  provider: ssh', '  host: cp.k395.invalid', '');
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n")
        unless defined $o{kubeconfig} && !$o{kubeconfig};
    return $dir;
}

# kubeconfig.yaml goes after cluster_exists saw it, right as $class's
# cluster_api is called: the real cluster_api then finds none (t/391's race).
sub gone_on_cluster_api {
    my ($class) = @_;
    return sub {
        no strict 'refs';
        no warnings 'redefine';
        # Loaded above: a stub taken here would resolve to the override.
        defined &{"${class}::cluster_api"} or die "$class has no cluster_api\n";
        my $real = \&{"${class}::cluster_api"};
        *{"${class}::cluster_api"} = sub {
            path('kubeconfig.yaml')->remove;
            goto &$real;
        };
    };
}

sub one_document {
    my ($text) = @_;
    my $doc = eval { JSON::MaybeXS->new->decode($text) };
    ok ref $doc eq 'HASH', 'STDOUT: exactly one JSON object' or diag "STDOUT:\n$text";
    return $doc // {};
}

subtest '--json error fields: one line, no label, in status, health and node ls' => sub {
    my %case = (
        status => [ gone_on_cluster_api('OCP::Cmd::Status'), 1 ],
        health => [ gone_on_cluster_api('OCP::Cmd::Health'), 1 ],
        node   => [ undef, 0 ],          # node ls: no kubeconfig.yaml at all
    );
    my %field;
    for my $cmd (sort keys %case) {
        my ($setup, $kubeconfig) = @{ $case{$cmd} };
        my @words = $cmd eq 'node' ? ('node', 'ls') : ($cmd);
        my $json = run_ocp(project(kubeconfig => $kubeconfig), $setup, @words, '--json');
        my $text = run_ocp(project(kubeconfig => $kubeconfig), $setup, @words);
        my $what = "ocp @words --json";

        is $json->{signal}, 0, "$what: no signal";
        is $json->{exit}, 1, "$what: exit 1";
        my $error = one_document($json->{out})->{error} // '';
        is $error, $refusal_line, "$what: error is the refusal, as one line";
        unlike $error, qr/\n/, "$what: error: one line";
        unlike $error, qr/\A(?:ERROR|Error|error):/, "$what: error: no label";
        unlike $error, qr/ERROR:/, "$what: error: no ERROR: anywhere in it";
        $field{$cmd} = $error;

        is $json->{err}, $text->{err}, "$what: STDERR is what ocp @words says without --json";
        unlike $json->{err}, qr/(?:ERROR|Error): (?:ERROR|Error):/, "$what: STDERR: one label, not two";
        unlike $json->{err} . $json->{out}, qr/internal error|$LOCATION/i,
            "$what: no internal error, no source location";
    }
    is $field{health}, $field{status}, 'health --json: the field status --json has';
    is $field{node},   $field{status}, 'node ls --json: the field status --json has';

    # The labels as each command says the refusal: status prints its text
    # form's lines, health and node ls stop and OCP.pm's renderer says it.
    my $s = run_ocp(project(), gone_on_cluster_api('OCP::Cmd::Status'), 'status', '--json');
    is $s->{err}, $refusal, "status --json: STDERR is OCP::Secrets' refusal, as the text form prints it";
    my $h = run_ocp(project(), gone_on_cluster_api('OCP::Cmd::Health'), 'health', '--json');
    like $h->{err}, qr/\AError: This project has no kubeconfig\.yaml/, 'health --json: the renderer\'s Error: label';
    my $n = run_ocp(project(kubeconfig => 0), undef, 'node', 'ls', '--json');
    like $n->{err}, qr/\AError: This project has no kubeconfig\.yaml/, 'node ls --json: the renderer\'s Error: label';
    is_deeply [ sort keys %{ one_document($n->{out}) } ], ['error'], 'node ls --json: the error and nothing else';
    my $hd = one_document($h->{out});
    ok exists $hd->{healthy} && !$hd->{healthy}, 'health --json: still its own object, not healthy';
    is_deeply $hd->{pods}, [], 'health --json: no pods';
};

#### 3: node ls --json, a discovery without Node

my @servers;
END { kill 'TERM', @servers if @servers }

# An API server that answers /version, a discovery that lists nothing, and
# an empty OCPNode list; anything else (the Nodes) an empty list too. The
# client reads the discovery for the OCPNodes, and Node is then not in it.
sub discovery_without_node {
    my $listen = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                       Listen => 16, Proto => 'tcp')
        or BAIL_OUT("cannot listen on a local port: $!");
    my $pid = fork // BAIL_OUT("fork: $!");
    unless ($pid) {
        alarm 300;
        my $json = JSON::MaybeXS->new(canonical => 1);
        while (my $c = $listen->accept) {
            local $/ = "\r\n";
            my $request = <$c>;
            next unless defined $request;
            while (my $h = <$c>) { last if $h eq "\r\n" }
            my (undef, $target) = split ' ', $request;
            (my $p = $target // '/') =~ s/\?.*//s;
            my $doc = $p eq '/version'               ? { major => '1', minor => '36' }
                    : ($p eq '/api' || $p eq '/apis') ? { kind => 'APIGroupDiscoveryList',
                                                          apiVersion => 'apidiscovery.k8s.io/v2', items => [] }
                    :                                   { kind => 'List', apiVersion => 'v1',
                                                          metadata => {}, items => [] };
            my $body = $json->encode($doc);
            print {$c} "HTTP/1.1 200 OK\r\n",
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

subtest 'node ls --json, a discovery without Node: one line, not an internal error' => sub {
    my $server = discovery_without_node();
    my $client = sub {
        no warnings 'redefine';
        *OCP::Cmd::Node::Ls::_k8s = sub {
            my ($self) = @_;
            my $api = Kubernetes::REST->new(server => { endpoint => $server },
                                            credentials => { token => 'k395-token-1111' });
            OCP::K8s->register($api);
            return $self->k8s($api);
        };
    };
    my $line = "The cluster API at $server does not list the Kind Node in its discovery,"
             . ' so the Nodes cannot be read.';

    my $r = run_ocp(project(), $client, 'node', 'ls', '--json');
    is $r->{signal}, 0, 'no signal';
    is $r->{exit}, 1, 'exit 1';
    is_deeply one_document($r->{out}), { error => $line }, 'JSON: the line as its error';
    is $r->{err}, "Error: $line\n", 'STDERR: the one line';
    unlike $r->{err} . $r->{out}, qr/internal error|$LOCATION|unknown resource/i,
        "no internal error, no source location, not Kubernetes::REST's croak";

    # The table lists no Node: nothing to refuse there.
    $r = run_ocp(project(), $client, 'node', 'ls');
    is $r->{exit}, 0, 'node ls (the table): exit 0';
    is $r->{err}, '', 'node ls (the table): nothing on STDERR';
};

#### 4: the drift table

subtest 'drift error entries: the API error as its line, no source location' => sub {
    OCP::ErrorLine::set_cluster_endpoint(undef);
    my $dir = project();
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    my $dist = $config->distribution;

    my $e500 = api_err(code => 500, context => 'list Node',
        body => '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"InternalError",'
              . '"message":"etcdserver: request timed out","code":500}',
        _location => ' at lib/OCP/Drift.pm line 950.');

    my @warn;
    local $SIG{__WARN__} = sub { push @warn, $_[0] };

    my ($d) = OCP::Drift->new(config => $config, api => Local::Api->new(die => $e500))->distribution_drift;
    is $d->{kind}, 'error', 'distribution_drift: an error entry';
    is $d->{message}, "$dist kubelet versions: could not list Nodes: "
        . 'The cluster API failed (500 Internal Error): etcdserver: request timed out',
        "distribution_drift: the message holds the API error's line";

    my %probe = (in => 'component_drift', op => 'get', object => 'ConfigMap kube-system/k395',
                 component => 'k395', label => 'K395', expected => undef);
    my $drift = OCP::Drift->new(config => $config, api => Local::Api->new);

    my $u599 = $drift->_unknown_drift($e599, %probe);
    is $u599->{message}, 'K395: could not read ConfigMap kube-system/k395, drift unknown: '
        . "The cluster API could not be reached: Can't connect to 10.0.0.1:6443 (Connection refused)",
        '_unknown_drift, a 599: the line, the reason once';

    my $u500 = $drift->_unknown_drift($e500, %probe);
    like $u500->{message}, qr/drift unknown: The cluster API failed \(500 Internal Error\): etcdserver: request timed out\z/,
        '_unknown_drift, a 500: the line';

    my $plain = $drift->_unknown_drift("boom\n  and why at lib/OCP/Whatever.pm line 7.\n", %probe);
    is $plain->{message}, 'K395: could not read ConfigMap kube-system/k395, drift unknown: boom and why',
        '_unknown_drift, not an APIError: one line, no location';

    for my $e ($d, $u599, $u500, $plain) {
        unlike $e->{message}, $LOCATION, "no source location: $e->{message}";
        unlike $e->{message}, qr/\n/, 'one line';
    }

    # STDERR said those lines already (k399); the entries now say the same.
    is $warn[0], "OCP::Drift::distribution_drift: list('Node') failed: "
        . "The cluster API failed (500 Internal Error): etcdserver: request timed out\n",
        'distribution_drift: STDERR says the line the entry holds';
    is $warn[1], 'OCP::Drift::component_drift: get ConfigMap kube-system/k395 failed: '
        . "The cluster API could not be reached: Can't connect to 10.0.0.1:6443 (Connection refused)\n",
        '_unknown_drift, a 599: STDERR says the line the entry holds';
};

#### 5: Apply.pm loads File::Temp only to use it

subtest 'OCP::Cmd::Apply: File::Temp loaded exactly when used' => sub {
    my ($code) = split /^__END__$/m, path('lib/OCP/Cmd/Apply.pm')->slurp_utf8, 2;
    $code =~ s/^\s*#.*$//mg;
    my $loads = $code =~ /^\s*use\s+File::Temp\b/m ? 1 : 0;
    my $uses  = $code =~ /File::Temp(?:::|->)|\btemp(?:file|dir)\s*\(/ ? 1 : 0;
    is $loads, $uses, 'use File::Temp, if and only if Apply.pm calls it'
        or diag "loads: $loads, uses: $uses";
};

{
    package Local::Api;
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub list { my ($s) = @_; die $s->{die} if $s->{die}; return { items => [] } }
    sub get  { my ($s) = @_; die $s->{die} if $s->{die}; return undef }
}

like $INC{'OCP/ErrorLine.pm'}, qr{\Alib/}, 'OCP::ErrorLine came from ./lib';
diag 'OCP::ErrorLine from ' . Cwd::abs_path($INC{'OCP/ErrorLine.pm'});
ok !exists $INC{'Rex.pm'}, 'Rex was not loaded: nothing put another lib/ first in @INC';

done_testing;

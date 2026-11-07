#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Kubernetes::REST::APIError;
use Path::Tiny ();
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Apply::K8s;
use OCP::Robocop::Manifest;

#
# k403: a cluster read that failed kept its Perl source location on the way
# to the terminal.
#
#   1. OCP::Cmd::Apply::K8s read_or_absent, read_or_why and crd_get flattened
#      the error into "could not read X: $reason" with the reason as it came
#      -- Kubernetes::REST's APIError with the caller's " at FILE line N.",
#      a 599 with LWP's text, which says its reason twice and carries LWP's
#      own location. The cause is now OCP::ErrorLine::one_line of the error
#      object: one line, no location, a 599 said once. 404 is still the one
#      answer that means absent, and the words around the cause are the same.
#   2. Through them, the two [WARN]s of OCP::Cmd::Apply::CR that print those
#      words: robocop's image not compared, robocop not seen ready.
#   3. The [!!] lines of OCP::Cmd::Apply::Drift that printed the raw
#      exception: the remedy that failed, Registry, GPU Operator,
#      cert-manager, Cilium Gateway, "Could not list OCPNodes" and
#      "Could not check worker labels/taints" -- in the reconcile and in the
#      dry run.
#   4. OCP.pm's renderer: a user error that wraps an inner croak with
#      "$@\n" ends in "line N.\n\n", and read as internal. Internal is what
#      ends in Perl's location and the one newline after it; what is said
#      carries no location, the inner one included.
#

# Rex (through OCP::Rex) puts getcwd/lib first in @INC: the modules under
# test must come from this tree's lib/, whichever spelling %INC has.
for my $m (qw( OCP.pm OCP/Cmd/Apply/K8s.pm OCP/Cmd/Apply/CR.pm OCP/Cmd/Apply/Drift.pm )) {
    is Path::Tiny::path($INC{$m})->realpath->stringify, Path::Tiny::path("lib/$m")->realpath->stringify,
        "$m: from the tree under test" or BAIL_OUT("$m loaded from $INC{$m}");
}

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, out => $out, err => $err, died => $died };
}

my $LOCATION = qr/ at \S+ line \d+/;

# Kubernetes::REST throws its APIError from inside the client; croak's
# location is the line that called it. Thrower stands in for the client.
{
    package Thrower;
    sub api_error { Kubernetes::REST::APIError->throw(@_) }
}

# The error as Kubernetes::REST dies with it, location and all.
sub thrown {
    my (%a) = @_;
    my $e = do { local $@; eval { Thrower::api_error(context => 'get Deployment', %a) }; $@ };
    return $e;
}

my $B403 = '{"kind":"Status","apiVersion":"v1","status":"Failure",'
         . '"message":"deployments.apps \"robocop\" is forbidden","reason":"Forbidden","code":403}';

# LWP's text for a refused connection, as Kubernetes::REST's LWPIO hands it on
# in a 599: the reason, a blank line, the reason again with LWP's location.
my $LWP = "Can't connect to 10.0.0.1:6443 (Connection refused)\n\n"
        . "Connection refused at /usr/share/perl5/LWP/Protocol/http.pm line 50.";

my $E403  = thrown(code => 403, body => $B403);
my $E599  = thrown(code => 599, body => $LWP);
my $CROAK = do { local $@; eval { die 'the client broke' }; $@ };   # no newline: Perl's location

like "$E403",  qr/$LOCATION\.\n\z/, 'the 403 carries a location, as Kubernetes::REST throws it';
like "$E599",  qr/$LOCATION/,       'the 599 too, LWP\'s inside it';
like "$CROAK", qr/$LOCATION\.\n\z/, 'the croak too';

# What one_line makes of each: the words the read helpers now say.
my %SAID = (
    403   => "Kubernetes API error (get Deployment): 403 $B403",
    599   => "Kubernetes API error (get Deployment): 599 Can't connect to 10.0.0.1:6443 (Connection refused)",
    croak => 'the client broke',
);
my %ERR = (403 => $E403, 599 => $E599, croak => $CROAK);

# --- 1. the read helpers ------------------------------------------------------

my $WHAT = 'Deployment ocp-system/robocop';

subtest 'read_or_absent: the cause in one line, without a location; a 404 still absent' => sub {
    for my $k (sort keys %ERR) {
        my $rv = eval { OCP::Cmd::Apply::K8s::read_or_absent($WHAT, sub { die $ERR{$k} }) };
        is $@, "could not read $WHAT: $SAID{$k}\n", "$k: its words, the cause said once, no location";
        ok !defined $rv, "$k: no answer";
    }
    my $gone = thrown(code => 404, body => '{"kind":"Status","reason":"NotFound","code":404}');
    my $ok = eval { is OCP::Cmd::Apply::K8s::read_or_absent($WHAT, sub { die $gone }), undef,
        '404: absent, as before'; 1 };
    ok $ok, '404: no death';
    is_deeply OCP::Cmd::Apply::K8s::read_or_absent($WHAT, sub { { kind => 'Deployment' } }),
        { kind => 'Deployment' }, 'an object: the object';
};

subtest 'read_or_why: the why in one line, without a location; a 404 still "not found"' => sub {
    for my $k (sort keys %ERR) {
        my ($obj, $why) = OCP::Cmd::Apply::K8s::read_or_why($WHAT, sub { die $ERR{$k} });
        ok !defined $obj, "$k: no object";
        is $why, "could not read $WHAT: $SAID{$k}", "$k: its words, the cause said once, no location";
    }
    my $gone = thrown(code => 404, body => '{"kind":"Status","reason":"NotFound","code":404}');
    my (undef, $why) = OCP::Cmd::Apply::K8s::read_or_why($WHAT, sub { die $gone });
    is $why, "$WHAT not found", '404: not found, as before';
};

{
    package Resp;
    sub new     { my ($c, $s, $b) = @_; bless { status => $s, content => $b }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }

    # _request answers from { path => response | error to die with }.
    package RawApi;
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub _request {
        my ($self, $method, $path) = @_;
        my $a = $self->{$path} // Resp->new(404, '{}');
        die $a unless ref $a eq 'Resp';
        return $a;
    }
}

subtest 'crd_get: every death in one line, without a location' => sub {
    my $path = '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';

    eval { OCP::Cmd::Apply::K8s::crd_get({}, RawApi->new($path => $CROAK), $path) };
    is $@, "GET $path failed: the client broke\n", 'a request that died: its reason, no location';

    eval { OCP::Cmd::Apply::K8s::crd_get({}, RawApi->new($path => Resp->new(599, $LWP)), $path) };
    like $@, qr/\AGET \Q$path\E failed: HTTP 599 Can't connect to 10\.0\.0\.1:6443 \(Connection refused\)/,
        'a 599: LWP\'s reason';
    unlike $@, $LOCATION, 'a 599: without LWP\'s location';
    like $@, qr/\A[^\n]*\n\z/, 'a 599: one line';

    eval { OCP::Cmd::Apply::K8s::crd_get({}, RawApi->new($path => Resp->new(200, '<html>proxy</html>')), $path) };
    like $@, qr/\AGET \Q$path\E: the answer is no JSON: \S/, 'no JSON: said so, with the parser\'s why';
    unlike $@, $LOCATION, 'no JSON: without the parser\'s location';
    like $@, qr/\A[^\n]*\n\z/, 'no JSON: one line';

    is OCP::Cmd::Apply::K8s::crd_get({}, RawApi->new, $path), undef, '404: undef, as before';
};

# --- 2. the CR [WARN]s that print those words -----------------------------------

my @KEEP;
sub config_for {
    my ($spec) = @_;
    my $dir = Path::Tiny->tempdir;
    push @KEEP, $dir;
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({
        name           => 'k403',
        control_planes => { provider => 'ssh', host => 'police1.k403.test' },
        %{ $spec // {} },
    }));
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

{
    package GetApi;
    sub new              { my ($c, $e) = @_; bless { e => $e }, $c }
    sub get              { die $_[0]{e} }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }

    package FakeSelf;
    sub new          { bless {}, shift }
    sub wait_seconds { }
}

subtest 'CR: robocop\'s image not compared -- the [WARN] carries no location' => sub {
    my $config = config_for();
    my $want   = OCP::Robocop::Manifest->image($config);
    my $doc    = { kind => 'Deployment', metadata => { name => 'robocop', namespace => 'ocp-system' } };
    for my $k (sort keys %ERR) {
        my $r = capture { OCP::Cmd::Apply::CR::_say_robocop_image_change(
            FakeSelf->new, GetApi->new($ERR{$k}), $config, $doc); 1 };
        is $r->{died}, '', "$k: no death";
        is $r->{err}, "  [WARN] robocop image $want, not compared with the running one: "
            . "could not read Deployment ocp-system/robocop: $SAID{$k}\n",
            "$k: one line on STDERR, the cause without its location";
        unlike $r->{out}, $LOCATION, "$k: none on STDOUT either";
    }
};

subtest 'CR: robocop not seen ready -- the [WARN] carries no location' => sub {
    for my $k (sort keys %ERR) {
        my $r = capture { OCP::Cmd::Apply::CR::wait_robocop_ready(FakeSelf->new, GetApi->new($ERR{$k}), 0) };
        is $r->{rv}, 0, "$k: not ready";
        is $r->{err}, "  [WARN] robocop not seen ready: could not read Deployment ocp-system/robocop: $SAID{$k}\n",
            "$k: one line on STDERR, the cause without its location";
    }
};

# --- 3. the [!!] lines of OCP::Cmd::Apply::Drift --------------------------------

{
    package FakeOcp;
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub load_file { undef }
    sub dump_file { 1 }

    package FakeDrift;
    our @ENTRIES;
    sub detect { [ @ENTRIES ] }
}

# A user error that wraps an inner croak: its location stands in the middle.
my $WRAPPED = "the step gave up: $CROAK\n";

my $WORKERS = { workers => [ { name => 'pool', provider => 'ssh', nodes => [ 'w1.k403.test' ] } ] };

# Every cluster step stubbed: the ones a case names die with its error, the
# others do nothing. Returns what reached STDOUT and STDERR.
sub run_drift {
    my (%o) = @_;
    my $config = config_for($WORKERS);
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ], dry_run => $o{dry_run} ? 1 : 0);
    $apply->{_k8s_api} = bless {}, 'NoApi';
    my %die = %{ $o{die} // {} };
    my $step = sub {
        my ($name, $ok) = @_;
        return sub { die $die{$name} if exists $die{$name}; return $ok };
    };

    no warnings qw( redefine once );
    local @FakeDrift::ENTRIES = @{ $o{drift} // [] };
    local *OCP::Secrets::read_kubeconfig          = sub { "apiVersion: v1\n" };
    local *OCP::Drift::new                        = sub { bless {}, 'FakeDrift' };
    local *OCP::Cmd::Apply::_k8s_api              = sub { $_[0]{_k8s_api} };
    local *OCP::Cmd::Apply::rex_prober            = sub { undef };
    local *OCP::Cmd::Apply::host_probe_warning    = sub { '' };
    local *OCP::Cmd::Apply::Drift::gpu_dry_run    = sub { () };
    local *OCP::Cmd::Apply::_run_remedy           = sub { die $die{ $_[2]{remedy}{task} } };
    local *OCP::Cmd::Apply::_setup_registry       = $step->('registry', 'unchanged');
    local *OCP::Cmd::Apply::_configure_registry_dns = sub { 0 };
    local *OCP::Cmd::Apply::_setup_nfd            = sub { 'unchanged' };
    local *OCP::Cmd::Apply::_setup_gpu_operator   = $step->('gpu', 'skipped');
    local *OCP::Cmd::Apply::AMDGPU::step          = sub { { changed => 0, failed => [] } };
    local *OCP::Cmd::Apply::AMDGPU::dry_run       = sub { () };
    local *OCP::Cmd::Apply::_load_deployed_hashes = sub { {} };
    local *OCP::Cmd::Apply::_resource_exists      = $step->('cert-manager', 1);
    local *OCP::Cmd::Apply::_setup_cilium_gateway = $step->('gateway', 'unchanged');
    local *OCP::Cmd::Apply::_setup_lb_ipam        = sub { 1 };
    local *OCP::Cmd::Apply::_ensure_crds          = sub { 1 };
    local *OCP::Cmd::Apply::_ensure_providers     = sub { 1 };
    local *OCP::Cmd::Apply::_migrate_legacy_nodes = sub { 1 };
    local *OCP::Cmd::Apply::_ensure_cp_ocpnode    = sub { 1 };
    local *OCP::Cmd::Apply::CR::warn_install_time_changes   = sub { 0 };
    local *OCP::Cmd::Apply::CR::missing_worker_ocpnodes     = $step->('list', ());
    local *OCP::Cmd::Apply::CR::sync_worker_meta            = $step->('meta', { patched => [], failed => [] });
    local *OCP::Cmd::Apply::CR::warn_unlisted_failed_ocpnodes = sub { };

    return capture { OCP::Cmd::Apply::Drift::reconcile_components($apply, $config); 1 };
}

my @DRIFT = (
    { component => 'cilium', label => 'Cilium', message => 'Cilium 1.0 != 1.1', expected => '1.1',
      remedy => { type => 'rex', task => 'upgrade_cilium' } },
    { component => 'cert_manager', label => 'cert-manager', message => 'cert-manager 1.0 != 1.1',
      expected => '1.1', remedy => { type => 'api', task => 'upgrade_cert_manager' } },
);

# Each step dies with one kind of error; each [!!] says it in one line.
my %STEP = (
    upgrade_cilium       => [ $E403,    "  [!!] upgrade_cilium failed: $SAID{403}\n" ],
    upgrade_cert_manager => [ $E599,    "  [!!] cert-manager update via the cluster API failed: $SAID{599}\n" ],
    registry             => [ $CROAK,   "  [!!] Registry setup failed: $SAID{croak}\n" ],
    gpu                  => [ $E599,    "  [!!] GPU Operator setup failed: $SAID{599}\n" ],
    'cert-manager'       => [ $E403,    "  [!!] cert-manager setup failed: $SAID{403}\n" ],
    gateway              => [ $WRAPPED, "  [!!] Cilium Gateway setup failed: the step gave up: $SAID{croak}\n" ],
    list                 => [ $E403,    "  [!!] Could not list OCPNodes, workers were not checked: $SAID{403}\n" ],
    meta                 => [ $CROAK,   "  [!!] Could not check worker labels/taints: $SAID{croak}\n" ],
);

subtest 'reconcile: every [!!] says its cause in one line, without a location' => sub {
    my $r = run_drift(drift => \@DRIFT, die => { map { $_ => $STEP{$_}[0] } keys %STEP });
    is $r->{died}, '', 'the reconcile ran to its end' or diag $r->{died};
    for my $name (sort keys %STEP) {
        my $line = $STEP{$name}[1];
        like $r->{err}, qr/^\Q$line\E/m, "$name: the [!!] line, the cause without its location";
    }
    unlike $r->{err}, $LOCATION, 'no Perl source location anywhere on STDERR';
    unlike $r->{out}, $LOCATION, 'nor on STDOUT';
    is scalar(() = $r->{err} =~ /^  \[!!\] /mg), scalar(keys %STEP), 'one [!!] line per failure, no more';
    unlike $r->{err}, qr/\n\n/, 'no blank line after any';
};

subtest 'dry run: the two [!!] of the worker checks, without a location' => sub {
    my $r = run_drift(dry_run => 1, die => { list => $E599, meta => $WRAPPED });
    is $r->{died}, '', 'the dry run ran to its end' or diag $r->{died};
    my $list = "  [!!] Could not list OCPNodes, workers were not checked: $SAID{599}\n";
    my $meta = "  [!!] Could not check worker labels/taints: the step gave up: $SAID{croak}\n";
    like $r->{err}, qr/^\Q$list\E/m, 'the OCPNode list: one line, said once, no location';
    like $r->{err}, qr/^\Q$meta\E/m, 'labels/taints: one line, the inner location gone too';
    unlike $r->{err}, $LOCATION, 'no Perl source location anywhere on STDERR';
};

# --- 4. the renderer: user error or internal -----------------------------------

sub report {
    my ($err) = @_;
    my $r = capture { OCP::_report_error($err, 0, 0) };
    return $r->{err};
}

subtest 'OCP.pm: a user error wrapping an inner croak is a user error, said without the location' => sub {
    my $wrapped = "Could not reach the thing: $CROAK\n";
    like $wrapped, qr/line \d+\.\n\n\z/, 'it ends in "line N.\n\n"';
    my ($msg, $internal) = OCP::_clean_message($wrapped);
    is $internal, 0, 'not an internal error: it was raised with a newline of its own';
    is $msg, 'Could not reach the thing: the client broke', 'said without the inner location';
    is report($wrapped), "Error: Could not reach the thing: the client broke\n",
        'run_cli\'s renderer: one Error line, no internal-error hint';

    my $block = "ERROR: Refused.\n\n  $CROAK  the second line\n";
    ($msg, $internal) = OCP::_clean_message($block);
    is $internal, 0, 'a refusal of several lines with a location inside: a user error';
    is $msg, "Refused.\n\n  the client broke\n  the second line", 'its lines kept, the location gone';
};

subtest 'OCP.pm: what ends in Perl\'s location is internal, as before' => sub {
    my ($msg, $internal) = OCP::_clean_message($CROAK);
    is $internal, 1, 'a die without a newline: internal';
    is $msg, 'the client broke', 'said without its location';
    like report($CROAK), qr/\AError: the client broke\n\nThis is an internal error\./, 'with the hint';

    my $inner = do { local $@; eval { die "outer: $CROAK" }; $@ };
    ($msg, $internal) = OCP::_clean_message($inner);
    is $internal, 1, 'a croak that wraps a croak: internal';
    is $msg, 'outer: the client broke', 'said without either location';
};

subtest 'OCP.pm: Perl\'s location after a line read from a filehandle is seen too' => sub {
    open my $fh, '<', \"PIN1\n" or die;
    my $pin  = <$fh>;
    my $died = do { local $@; eval { die 'boom' }; $@ };
    close $fh;
    like $died, qr/ line \d+, <\$fh> line 1\.\n\z/, 'Perl puts the filehandle into the location';
    my ($msg, $internal) = OCP::_clean_message($died);
    is $internal, 1, 'internal';
    is $msg, 'boom', 'said without any of it';
};

done_testing;

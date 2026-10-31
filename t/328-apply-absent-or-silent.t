#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Kubernetes::REST::APIError;
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Deploy;
use OCP::Cmd::Apply::Network;
use OCP::Cmd::Apply::Workloads;

#
# k328: three more places of the k269/k277/k319 class, after k319 -- only a
# 404 is absent, any other failure is reported with its cause, and a step
# that has nothing to show for itself does not say "up to date" or nothing:
#
# - robocop_step read the robocop Deployment as `eval { get } ? 1 : 0`: a
#   403 or a 500 was "no Deployment", and the step went on to roll out and
#   called it a change. The dry run says such a read leaves a real run
#   incomplete (k319); now the real run fails the step with the cause.
# - configure_registry_dns on a Corefile with no server block for the root
#   zone: corefile_with_host leaves it as it is (t/39), and unchanged read
#   as "up to date". Now it dies saying so; the step says it on STDERR.
# - setup_nfd's nfd-worker wait ran out without a word when no pod got
#   ready (k319 covered a failed read). Now it says why on STDERR.
#

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

# What Kubernetes::REST dies with for an HTTP error status (as in t/25).
sub api_error {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(
        code    => $code,
        context => 'get',
        body    => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}),
    );
}
my @REFUSALS = ([403, 'Forbidden'], [500, 'InternalError']);

# The next answer of a queue, the last one repeating.
sub next_answer { my ($q) = @_; @$q > 1 ? shift @$q : $q->[0] }

{
    package FakeOCP;
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub load_file { my ($self, $f) = @_; -f "$f" ? YAML::XS::LoadFile("$f") : undef }
    sub dump_file { my ($self, $f, $d) = @_; YAML::XS::DumpFile("$f", $d) }
    sub dump      { my $self = shift; YAML::XS::Dump(@_) }
}

sub new_apply {
    my ($api) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    $apply->{_k8s_api} = $api;
    return $apply;
}

#
# robocop_step
#

{
    package RobocopConfig;
    sub new { bless {}, shift }
    sub robocop_security_level { 'secret' }
    # get('Deployment', 'robocop') answers from {deployment}: 1 for one that
    # is there, or what the read dies with.
    package RobocopApi;
    sub new { my ($c, %a) = @_; bless { gets => 0, %a }, $c }
    sub get {
        my ($self, $kind, $name, %o) = @_;
        die "unexpected get $kind/$name\n" unless $kind eq 'Deployment' && $name eq 'robocop'
            && ($o{namespace} // '') eq 'ocp-system';
        $self->{gets}++;
        my $answer = $self->{deployment};
        die $answer if ref $answer;
        return bless {}, 'RobocopDeployment';
    }
}

# robocop_step with the Deployment read answering $deployment and the
# credentials write answering $secret ('written' or 'current'); records
# what the step wrote.
sub robocop {
    my ($deployment, $secret) = @_;
    my $api = RobocopApi->new(deployment => $deployment);
    my @wrote;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_ensure_robocop_credentials = sub { push @wrote, 'Secret'; $secret // 'current' };
    local *OCP::Cmd::Apply::_ensure_robocop             = sub { push @wrote, 'Deployment'; 1 };
    local *OCP::Cmd::Apply::_wait_robocop_ready         = sub { 1 };
    my $r = capture { OCP::Cmd::Apply::Deploy::robocop_step(new_apply($api), $api, RobocopConfig->new,
        { cp_ip => '10.0.0.1', secrets => undef }) };
    $r->{wrote} = \@wrote;
    $r->{gets}  = $api->{gets};
    return $r;
}

subtest 'k328 robocop_step: a Deployment that cannot be read is not "no Deployment"' => sub {
    my $r = robocop(1);
    is $r->{died}, '', 'control: no death';
    is_deeply $r->{rv}, { state => 'ready', changed => 0 }, 'control: there, Secret current: ready, no change';
    is_deeply $r->{wrote}, [qw( Secret Deployment )], 'control: the Secret and the Deployment made sure of';
    is $r->{err}, '', 'control: nothing on STDERR';

    $r = robocop(1, 'written');
    is_deeply $r->{rv}, { state => 'ready', changed => 1 }, 'there, Secret written: a change';

    $r = robocop(api_error(404, 'NotFound'));
    is $r->{died}, '', '404: no death';
    is_deeply $r->{rv}, { state => 'ready', changed => 1 }, '404: rolled out, a change';
    is_deeply $r->{wrote}, [qw( Secret Deployment )], '404: the Secret and the Deployment written';
    is $r->{err}, '', '404: nothing on STDERR';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = robocop(api_error($code, $reason));
        is $r->{died}, '', "$code: no death, the step reports it";
        is_deeply $r->{rv}, { state => 'failed', changed => 0 },
            "$code: the step failed -- which the callers count -- not a rollout called a change";
        like $r->{err},
            qr{\A  \[!!\] robocop deploy failed: could not read Deployment ocp-system/robocop: Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "$code: the cause, on STDERR";
        unlike $r->{out}, qr/could not read|\[ok\] robocop ready/, "$code: not on STDOUT, and no ready";
        is_deeply $r->{wrote}, [], "$code: nothing written after a read that failed";
        is $r->{gets}, 1, "$code: read once";
    }
};

#
# configure_registry_dns
#

{
    package DnsCm;
    sub new  { my ($c, $d) = @_; bless { data => $d }, $c }
    sub data { $_[0]{data} }
    # get('ConfigMap', 'coredns') answers with {cm}; the other name is a 404.
    package DnsApi;
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub get {
        my ($self, $kind, $name) = @_;
        return $self->{cm} if $kind eq 'ConfigMap' && $name eq 'coredns' && $self->{cm};
        die "404 $kind/$name not found\n";
    }
}

my $ROOT = <<'COREFILE';
.:53 {
    errors
    hosts /etc/coredns/NodeHosts {
        ttl 60
        reload 15s
        fallthrough
    }
    kubernetes cluster.local in-addr.arpa ip6.arpa
    forward . /etc/resolv.conf
}
COREFILE

my $NO_ROOT = <<'COREFILE';
cluster.local:53 {
    errors
    kubernetes cluster.local in-addr.arpa ip6.arpa
}
COREFILE

my $NO_PLACE = 'ConfigMap kube-system/coredns: its Corefile has no server block for the root zone (.), '
             . "so registry.local has no place in it\n";

sub registry_dns {
    my ($data) = @_;
    my $api = DnsApi->new(cm => DnsCm->new($data));
    my @applied;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_server_side_apply = sub { push @applied, $_[2]; 1 };
    my $r = capture { OCP::Cmd::Apply::Network::configure_registry_dns(new_apply($api), '10.230.30.155') };
    $r->{applied} = \@applied;
    return $r;
}

subtest 'k328 registry.local DNS: no root server block is no record in place' => sub {
    my $r = registry_dns({ Corefile => $ROOT });
    is $r->{died}, '', 'control: a root block, no record: no death';
    is $r->{rv}, 1, 'control: patched';
    like $r->{applied}[0]{data}{Corefile}, qr/^\s+10\.230\.30\.155 registry\.local$/m, 'control: the record written';

    $r = registry_dns({ Corefile => $r->{applied}[0]{data}{Corefile} });
    is $r->{died}, '', 'control: the record in place: no death';
    is $r->{rv}, 0, 'control: up to date';
    is scalar @{ $r->{applied} }, 0, 'control: nothing written';

    # k348 names the missing key instead of an empty Corefile's missing root
    # block; the drift probe says the same now.
    my $NO_KEY = "ConfigMap kube-system/coredns has no Corefile key, so registry.local has no place in it\n";
    for my $case ([ 'only a cluster.local block' => { Corefile => $NO_ROOT }, $NO_PLACE ],
                  [ 'an empty Corefile'          => { Corefile => '' },       $NO_PLACE ],
                  [ 'no Corefile key'            => {},                       $NO_KEY ]) {
        my ($what, $data, $death) = @$case;
        $r = registry_dns($data);
        is $r->{died}, $death, "$what: dies saying there is no place for the record";
        ok !defined $r->{rv}, "$what: no verdict, so not \"up to date\"";
        is scalar @{ $r->{applied} }, 0, "$what: nothing written";
    }
};

subtest 'k328 corefile_has_root_block' => sub {
    my $has = \&OCP::Cmd::Apply::Network::corefile_has_root_block;
    is $has->($ROOT), 1, '.:53';
    is $has->(". {\n    forward . /etc/resolv.conf\n}\n"), 1, '.';
    is $has->("dns://.:53 {\n    forward . /etc/resolv.conf\n}\n"), 1, 'dns://.:53';
    is $has->($NO_ROOT . $ROOT), 1, 'a root block after another one';
    is $has->($NO_ROOT), 0, 'only cluster.local:53';
    is $has->(''), 0, 'empty';
    is $has->("# nothing to patch here\n"), 0, 'a comment';
    is $has->("registry.local:53 {\n    hosts {\n        10.0.0.5 registry.local\n    }\n}\n"), 0,
        'a server block of its own for the name is not the root zone';
};

#
# setup_nfd: the nfd-worker wait
#

{
    package NfdStatus;
    sub new                    { my ($c, %a) = @_; bless { %a }, $c }
    sub numberReady            { $_[0]{ready} }
    sub desiredNumberScheduled { $_[0]{desired} }
    package NfdDaemonSet;
    sub new    { my ($c, $s) = @_; bless { s => $s }, $c }
    sub status { $_[0]{s} }
    package NfdMeta;
    sub new    { bless {}, shift }
    sub labels { +{ 'feature.node.kubernetes.io/cpu' => 'true' } }
    package NfdNode;
    sub new      { bless {}, shift }
    sub metadata { NfdMeta->new }
    package NfdList;
    sub new   { bless {}, shift }
    sub items { [ NfdNode->new ] }
    # get('DaemonSet') answers from {ds}, a queue, the last answer repeating:
    # [ ready, desired ], 'nostatus' for a DaemonSet without a status yet, or
    # what the read dies with. Every other get is a 404: NFD is not deployed
    # yet. The Nodes carry NFD's labels.
    package NfdApi;
    sub new { my ($c, %a) = @_; bless { reads => 0, %a }, $c }
    sub get {
        my ($self, $kind, $name) = @_;
        die "404 $kind/$name not found\n" unless $kind eq 'DaemonSet';
        $self->{reads}++;
        my $answer = main::next_answer($self->{ds});
        return NfdDaemonSet->new(undef) if !ref $answer && $answer eq 'nostatus';
        die $answer unless ref $answer eq 'ARRAY';
        return NfdDaemonSet->new(NfdStatus->new(ready => $answer->[0], desired => $answer->[1]));
    }
    sub list { NfdList->new }
}

{
    package NfdConfig;
    sub new {
        my $dir = Path::Tiny::path(main::tempdir(CLEANUP => 1));
        $dir->child('.ocp')->mkpath;
        bless { dir => $dir }, shift;
    }
    sub has_external_cache    { 0 }
    sub has_external_upstream { 0 }
    sub deployed_file         { $_[0]{dir}->child('.ocp', 'deployed.yaml')->stringify }
}

sub nfd {
    my (@ds) = @_;
    my $api = NfdApi->new(ds => [ @ds ]);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_apply_yaml_file       = sub { 1 };
    local *OCP::Cmd::Apply::_apply_yaml_string     = sub { 1 };
    local *OCP::Cmd::Apply::_poll_deployment_ready = sub { 1 };
    local *OCP::Cmd::Apply::wait_seconds           = sub { };
    my $r = capture { OCP::Cmd::Apply::Workloads::setup_nfd(new_apply($api), NfdConfig->new) };
    $r->{reads} = $api->{reads};
    return $r;
}

my $NOT_SEEN = '  [WARN] nfd-worker not seen ready within 120s';

subtest 'k328 NFD: the nfd-worker wait says why it ran out' => sub {
    my $r = nfd([ 1, 1 ]);
    is $r->{died}, '', 'control: no death';
    is $r->{rv}, 'deployed', 'control: deployed';
    like $r->{out}, qr/NFD worker running on 1 node\(s\)/, 'control: the worker seen';
    is $r->{err}, '', 'control: nothing on STDERR';

    $r = nfd([ 0, 2 ]);
    is $r->{rv}, 'deployed', 'no pod ready: the label wait decides, as before';
    is $r->{reads}, 12, 'no pod ready: read for the whole wait';
    is $r->{err}, "$NOT_SEEN: 0 of 2 pod(s) ready\n", 'no pod ready: said on STDERR, with the count';
    unlike $r->{out}, qr/not seen ready|pod\(s\) ready/, 'no pod ready: not on STDOUT';

    $r = nfd([ 0, 0 ]);
    is $r->{err}, "$NOT_SEEN: 0 of 0 pod(s) ready\n", 'a DaemonSet no node takes: 0 of 0';

    $r = nfd([ undef, undef ]);
    is $r->{err}, "$NOT_SEEN: 0 of 0 pod(s) ready\n", 'counts not set yet: 0 of 0';

    $r = nfd('nostatus');
    is $r->{err}, "$NOT_SEEN: the DaemonSet reports no status yet\n", 'no status: said so';

    $r = nfd(api_error(404, 'NotFound'));
    is $r->{rv}, 'deployed', '404 throughout: the label wait decides';
    is $r->{err}, "$NOT_SEEN: DaemonSet node-feature-discovery/nfd-worker not found\n",
        '404 throughout: said on STDERR, not a read that failed';

    $r = nfd([ 0, 1 ], [ 1, 1 ]);
    like $r->{out}, qr/NFD worker running on 1 node\(s\)/, 'none ready, then one: seen';
    is $r->{err}, '', 'none ready, then one: nothing on STDERR';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = nfd([ 0, 1 ], api_error($code, $reason));
        like $r->{err},
            qr{\A\Q$NOT_SEEN\E; the last read failed: could not read DaemonSet node-feature-discovery/nfd-worker: Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "none ready, then $code: the failed read, as k319 says it";

        $r = nfd(api_error($code, $reason), [ 0, 3 ]);
        is $r->{err}, "$NOT_SEEN: 0 of 3 pod(s) ready\n", "$code, then none ready: the last read decides";
    }
};

done_testing;

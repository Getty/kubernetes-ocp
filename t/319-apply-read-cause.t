#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Kubernetes::REST::APIError;
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Config;
use OCP::Secrets;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::Registry;
use OCP::Cmd::Apply::Workloads;

#
# k319: more apply reads of the k269/k277 class -- a read that failed was
# taken for "not there", or a wait ran out without saying why. Only a 404 is
# absent; any other failure is no verdict on the object. A read asked once
# dies with its cause (its step reports it); a wait reads again and names its
# last failed read when it runs out. The reconcile's robocop dry run is
# pinned in t/38, registry.local DNS with no CoreDNS ConfigMap in t/269.
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
{
    package FakeConfig;
    sub new {
        my ($class, %arg) = @_;
        my $dir = Path::Tiny::path(main::tempdir(CLEANUP => 1));
        $dir->child('.ocp')->mkpath;
        bless { dir => $dir, %arg }, $class;
    }
    sub has_external_cache    { 0 }
    sub has_external_upstream { 0 }
    sub deployed_file         { $_[0]{dir}->child('.ocp', 'deployed.yaml')->stringify }
}

sub new_apply {
    my ($api) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    $apply->{_k8s_api} = $api;
    return $apply;
}

#
# Registry: the switch to Recreate reads each registry Deployment first. A
# read that failed was "not there" -- no patch -- and the apply after it then
# failed on a 422 that named the strategy, not the read.
#

{
    package RecreateDeployment;
    sub new     { my ($c, $type) = @_; bless { type => $type }, $c }
    sub TO_JSON { +{ spec => { strategy => { type => $_[0]{type} } } } }
    # get() answers from { name => strategy type | what it dies with }; a
    # name not listed is a 404.
    package RecreateApi;
    sub new { my ($c, %a) = @_; bless { live => {}, patched => [], %a }, $c }
    sub get {
        my ($self, $kind, $name, %o) = @_;
        my $answer = $self->{live}{$name} // die "404 Deployment/$name not found\n";
        die $answer if ref $answer;
        return RecreateDeployment->new($answer);
    }
    sub patch { my ($self, $kind, $name) = @_; push @{ $self->{patched} }, $name; 1 }
}

sub recreate {
    my (%live) = @_;
    my $api = RecreateApi->new(live => { %live });
    my $r = capture { OCP::Cmd::Apply::Registry::switch_to_recreate(new_apply($api), $api, FakeConfig->new); 1 };
    $r->{patched} = $api->{patched};
    return $r;
}

subtest 'k319 Registry: a Deployment that cannot be read is not "not there"' => sub {
    my $r = recreate('ocp-cache' => 'RollingUpdate', 'ocp-registry' => 'Recreate');
    is $r->{died}, '', 'control: no death';
    is_deeply $r->{patched}, ['ocp-cache'], 'control: the RollingUpdate one is switched';

    $r = recreate();
    is $r->{died}, '', '404 on both: no death';
    is_deeply $r->{patched}, [], '404 on both: nothing to switch, the apply creates them';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = recreate('ocp-cache' => api_error($code, $reason), 'ocp-registry' => 'RollingUpdate');
        like $r->{died},
            qr{\Acould not read Deployment ocp-system/ocp-cache: Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "$code: dies with the cause, so the registry step reports it";
        is_deeply $r->{patched}, [], "$code: and nothing after it is patched as if all were well";
    }
};

#
# NFD: after the rollout, a wait for an nfd-worker pod (which goes on to the
# label wait whatever it saw) and a wait for NFD's labels (which dies when
# none come). Both read every failure as "not yet" and said nothing of it.
# Since k328 the nfd-worker wait says on STDERR why it ran out in every case,
# a failed read here; the rest of it is t/328.
#

{
    package NfdDaemonSet;
    sub new         { my ($c, $n) = @_; bless { n => $n }, $c }
    sub status      { $_[0] }
    sub numberReady { $_[0]{n} }
    sub desiredNumberScheduled { 1 }
    package NfdMeta;
    sub new    { my ($c, $l) = @_; bless { l => $l }, $c }
    sub labels { $_[0]{l} }
    package NfdNode;
    sub new      { my ($c, $l) = @_; bless { m => NfdMeta->new($l) }, $c }
    sub metadata { $_[0]{m} }
    package NfdList;
    sub new   { my ($c, @n) = @_; bless { n => [ @n ] }, $c }
    sub items { $_[0]{n} }
    # get('DaemonSet') answers from {ds}: a number of ready pods, or what the
    # read dies with. list('Node') from {nodes}: a hash of labels, or a death.
    # Each a queue, the last answer repeating. Every other get is a 404: NFD
    # is not deployed yet.
    package NfdApi;
    sub new { my ($c, %a) = @_; bless { ds => [ 1 ], nodes => [ { 'feature.node.kubernetes.io/cpu' => 'true' } ],
                                         ds_reads => 0, node_reads => 0, %a }, $c }
    sub get {
        my ($self, $kind, $name) = @_;
        die "404 $kind/$name not found\n" unless $kind eq 'DaemonSet';
        $self->{ds_reads}++;
        my $answer = main::next_answer($self->{ds});
        die $answer if ref $answer;
        return NfdDaemonSet->new($answer);
    }
    sub list {
        my ($self) = @_;
        $self->{node_reads}++;
        my $answer = main::next_answer($self->{nodes});
        die $answer unless ref $answer eq 'HASH';
        return NfdList->new(NfdNode->new($answer));
    }
}

sub nfd {
    my (%queues) = @_;
    my $api = NfdApi->new(%queues);
    my $apply = new_apply($api);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_apply_yaml_file       = sub { 1 };
    local *OCP::Cmd::Apply::_apply_yaml_string     = sub { 1 };
    local *OCP::Cmd::Apply::_poll_deployment_ready = sub { 1 };
    local *OCP::Cmd::Apply::wait_seconds           = sub { };
    my $r = capture { OCP::Cmd::Apply::Workloads::setup_nfd($apply, FakeConfig->new) };
    $r->{ds_reads}   = $api->{ds_reads};
    $r->{node_reads} = $api->{node_reads};
    return $r;
}

my $DS = 'DaemonSet node-feature-discovery/nfd-worker';

subtest 'k319 NFD: the nfd-worker wait names its last failed read' => sub {
    my $r = nfd();
    is $r->{died}, '', 'control: no death';
    is $r->{rv}, 'deployed', 'control: deployed';
    like $r->{out}, qr/NFD worker running on 1 node\(s\)/, 'control: the worker seen';
    is $r->{err}, '', 'control: nothing on STDERR';

    for my $quiet ([ '404' => api_error(404, 'NotFound') ], [ 'no pod ready' => 0 ]) {
        my ($what, $answer) = @$quiet;
        $r = nfd(ds => [ $answer ]);
        is $r->{rv}, 'deployed', "$what throughout: the label wait decides, as before";
        is $r->{ds_reads}, 12, "$what throughout: read for the whole wait";
        unlike $r->{err}, qr/read failed|could not read/, "$what throughout: no read failed, none named";
    }

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = nfd(ds => [ api_error($code, $reason) ]);
        is $r->{rv}, 'deployed', "$code throughout: the label wait still decides";
        is $r->{ds_reads}, 12, "$code throughout: read for the whole wait";
        like $r->{err},
            qr{\A  \[WARN\] nfd-worker not seen ready within 120s; the last read failed: could not read \Q$DS\E: Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "$code throughout: the cause, on STDERR";
        unlike $r->{out}, qr/could not read/, "$code throughout: not on STDOUT";

        $r = nfd(ds => [ api_error($code, $reason), 1 ]);
        like $r->{out}, qr/NFD worker running on 1 node\(s\)/, "$code once, then ready: the worker seen";
        is $r->{err}, '', "$code once, then ready: nothing on STDERR";

        $r = nfd(ds => [ api_error($code, $reason), 0 ]);
        unlike $r->{err}, qr/read failed|could not read/, "$code once, then read and not ready: the last read did not fail";
    }
};

subtest 'k319 NFD: the label wait dies with its last failed read' => sub {
    my $r = nfd(nodes => [ {} ]);
    is $r->{died}, "NFD labels not detected on any node after 120s\n", 'no labels throughout: as before';
    is $r->{node_reads}, 12, 'no labels throughout: read for the whole wait';

    $r = nfd(nodes => [ api_error(404, 'NotFound') ]);
    is $r->{died}, "NFD labels not detected on any node after 120s\n", '404 throughout: nothing listed, no read failure to name';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = nfd(nodes => [ api_error($code, $reason) ]);
        like $r->{died},
            qr{\ANFD labels not detected on any node after 120s; the last read failed: could not read Nodes: Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "$code throughout: the death names the cause";
        is $r->{node_reads}, 12, "$code throughout: read for the whole wait";

        $r = nfd(nodes => [ api_error($code, $reason), { 'feature.node.kubernetes.io/cpu' => 'true' } ]);
        is $r->{died}, '', "$code once, then labelled: no death";
        like $r->{out}, qr/NFD labels detected on nodes/, "$code once, then labelled: said";

        $r = nfd(nodes => [ api_error($code, $reason), {} ]);
        is $r->{died}, "NFD labels not detected on any node after 120s\n",
            "$code once, then read without labels: the last read did not fail";
    }
};

#
# Bootstrap: the wait for police1 to turn Ready lists the Nodes every 10s for
# 600s (and asked over SSH after that until k327). A list that failed was
# "status unknown" and its cause was nowhere -- the very API every step after
# it needs. Since k327 a Node not seen Ready is one line on STDERR, which
# names the failed read here -- an [!!] since k336, which made it a failed
# component; the rest of it is t/327.
#

{
    package BootOcp;
    sub new { bless {}, shift } sub verbose { 0 }
    package BootProv;
    sub new                { bless {}, shift }
    sub upload_ssh_key     { }
    sub create_server      { { ip => 'otho.lab', newly_created => 0 } }
    sub wait_for_running   { $_[1] }
    sub advertised_host    { my ($s, %o) = @_; $o{host} }
    sub cleanup_on_failure { }
    package BootCond;
    sub new { bless { s => $_[1] }, $_[0] } sub type { 'Ready' } sub status { $_[0]{s} }
    sub reason { undef } sub message { undef }
    package BootStatus;
    sub new { bless { s => $_[1] }, $_[0] } sub conditions { [ BootCond->new($_[0]{s}) ] }
    package BootNode;
    sub new { bless { s => $_[1] }, $_[0] } sub status { BootStatus->new($_[0]{s}) }
    package BootIO;
    sub new { bless {}, shift } sub object_to_struct { +{ metadata => { name => 'otho' } } }
    # list('Node') answers from {nodes}: a Ready condition status ('True',
    # 'False'), or what the list dies with; the last answer repeating.
    package BootApi;
    sub new      { my ($c, @a) = @_; bless { nodes => [ @a ], lists => 0 }, $c }
    sub _request { 1 }
    sub k8s      { BootIO->new }
    sub list {
        my ($self) = @_;
        $self->{lists}++;
        my $answer = main::next_answer($self->{nodes});
        die $answer if ref $answer;
        return NfdList->new(BootNode->new($answer));
    }
}

sub boot_config {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: amdlab\ncontrol_planes:\n  provider: ssh\n  host: otho.lab\n");
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub bootstrap {
    my (@answers) = @_;
    my $api    = BootApi->new(@answers);
    my $config = boot_config();
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ BootOcp->new ]);
    my @ssh_runs;
    no warnings 'redefine';
    local *OCP::Provider::for_spec       = sub { BootProv->new };
    local *OCP::Cmd::Apply::_k8s_api     = sub { $api };
    local *OCP::Secrets::save_kubeconfig = sub { 1 };
    local *OCP::Secrets::ensure_age_key  = sub { 1 };
    local *OCP::SSH::new                 = sub { bless {}, 'OCP::SSH' };
    local *OCP::SSH::wait_for_ssh        = sub { 1 };
    local *OCP::SSH::run                 = sub { push @ssh_runs, $_[1]; { stdout => "otho   NotReady\n" } };
    local *OCP::Rex::new                 = sub { bless {}, 'OCP::Rex' };
    local *OCP::Rex::install_server      = sub { { kubeconfig => "apiVersion: v1\n" } };
    local *OCP::Cmd::Apply::wait_seconds = sub { };
    my $r = capture { OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
        $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
        admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
    ) };
    $r->{lists}    = $api->{lists};
    $r->{ssh_runs} = scalar @ssh_runs;
    return $r;
}

subtest 'k319 Bootstrap: the node-Ready wait names its last failed Node list' => sub {
    my $r = bootstrap('True');
    is $r->{died}, '', 'control: bootstrap ran' or return diag $r->{died};
    like $r->{out}, qr/\[ok\] Node is Ready after ~10s/, 'control: Ready at once';
    is $r->{err}, '', 'control: nothing on STDERR';

    for my $quiet ([ 'not Ready' => 'False' ], [ '404' => api_error(404, 'NotFound') ]) {
        my ($what, $answer) = @$quiet;
        $r = bootstrap($answer);
        is $r->{died}, '', "$what throughout: the bootstrap goes on, as before";
        is $r->{lists}, 60, "$what throughout: listed for the whole wait";
        is $r->{ssh_runs}, 0, "$what throughout: not asked over SSH (k327)";
        like $r->{err}, qr/\A  \[!!\] Node otho not seen Ready within 600s: /, "$what throughout: said on STDERR (k327)";
        unlike $r->{err}, qr/read failed|could not read/, "$what throughout: no list failed, none named";
    }

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = bootstrap(api_error($code, $reason));
        is $r->{died}, '', "$code throughout: the bootstrap goes on, as before";
        is $r->{lists}, 60, "$code throughout: listed for the whole wait";
        like $r->{err},
            qr{\A  \[!!\] Node otho not seen Ready within 600s; the last read failed: could not read Nodes: Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "$code throughout: the cause, on STDERR";
        unlike $r->{out}, qr/could not read/, "$code throughout: not on STDOUT";

        $r = bootstrap(api_error($code, $reason), 'True');
        like $r->{out}, qr/\[ok\] Node is Ready after ~20s/, "$code once, then Ready: Ready";
        is $r->{err}, '', "$code once, then Ready: nothing on STDERR";

        $r = bootstrap(api_error($code, $reason), 'False');
        unlike $r->{err}, qr/read failed|could not read/, "$code once, then read and not Ready: the last read did not fail";
    }
};

done_testing;

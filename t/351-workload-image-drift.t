#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp ();
use JSON::PP ();
use Kubernetes::REST::APIError;
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Apply::K8s;
use OCP::Cmd::Apply::Workloads;
use OCP::Cmd::Status;
use OCP::Config;
use OCP::Drift;
use OCP::Versions;

#
# k351: NFD (Deployment node-feature-discovery/nfd-master) or the GPU Operator
# (Deployment gpu-operator/gpu-operator) runs another image than its pin while
# .ocp/deployed.yaml still holds the hash OCP deployed it with -- changed
# outside OCP (kubectl set image, an edit). The OCP::Drift probe reads that
# image and names it as drift a real run closes (self_healing), and ocp status
# counts it so. setup_nfd and setup_gpu_operator judged by the hash and
# presence alone: up to date, nothing applied, and the next ocp status named
# the same drift again. The k350 bug, for the two workloads OCP writes itself.
#
# Their deploy is a server-side apply of the whole manifest with force
# (fieldManager ocp): it takes the image back from whichever manager set it,
# so a re-apply restores the pin and both probes stay self_healing.
#
# The claims:
#   1. ocp status, the dry run and the real run say the same about it: the
#      probe's entry is one status counts as fixable, the dry run names it
#      and the re-apply of its manifest, the real run re-applies it -- the
#      Deployment back at the pin, the record as it was -- and says why, and
#      the probe finds nothing afterwards.
#   2. the step reads the image as the probe does: a tag the probe takes for
#      the pin (with or without the leading v), an image without a tag and
#      what the probe does not read (the args) are left as they are, and none
#      of the three names them.
#   3. a Deployment whose image cannot be read is no verdict: the step dies
#      with the cause and applies nothing it could not see.
#
# k369: the NFD manifest pins a second workload, the DaemonSet
# node-feature-discovery/nfd-worker, and no probe read it: a hand-changed
# worker image was drift nowhere -- not in ocp status, not in the dry run --
# and setup_nfd called NFD up to date. It is the NFD DaemonSet probe now (one
# component, two objects, as the AMD device plugin and its labeller), and
# setup_nfd asks it as it asks the Deployment. The three claims above hold
# for the DaemonSet as for the Deployments (nfd_worker below), and
#   4. an nfd-worker that is not there is the same in all three: status names
#      it missing and fixable, the dry run counts it, the real run restores it.
#

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my (@rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        @rv = eval { $code->() };
        $died = $@;
    }
    return { rv => \@rv, out => $out, err => $err, died => $died };
}

# What Kubernetes::REST dies with for an HTTP error status (as in t/269).
sub api_error {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(code => $code, context => 'get',
        body => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}));
}
my @REFUSALS = ([403, 'Forbidden'], [500, 'InternalError']);

{
    package FakeOcp;
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub load_file { my ($self, $f) = @_; -f "$f" ? YAML::XS::LoadFile("$f") : undef }
    sub dump_file { my ($self, $f, $d) = @_; YAML::XS::DumpFile("$f", $d) }
    sub dump      { my $self = shift; YAML::XS::Dump(@_) }
}
{
    package WlList;
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
    # A Node as setup_nfd and setup_gpu_operator read one: methods.
    package WlNode;
    sub new      { my ($c, %a) = @_; bless { %a }, $c }
    sub metadata { $_[0] }
    sub name     { $_[0]{name} }
    sub labels   { $_[0]{labels} }
    # nfd-worker as setup_nfd's wait reads it (one pod, ready), and as the
    # NFD DaemonSet probe reads it: the spec as applied (k369).
    package WlDaemonSet;
    sub new                    { bless { object => $_[1] }, $_[0] }
    sub spec                   { $_[0]{object}{spec} }
    sub status                 { $_[0] }
    sub numberReady            { 1 }
    sub desiredNumberScheduled { 1 }
    package WlResponse;
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}
{
    # A cluster with one NVIDIA node, crag, that NFD has labelled. What a
    # server-side apply (a PATCH) writes is what get() and the raw GETs read
    # back -- a server-side apply with force is the applied object, whoever set
    # a field before. Every PATCH is recorded with its parameters.
    package WlApi;
    my %LABELS = (
        'feature.node.kubernetes.io/cpu-model.vendor_id'    => 'AMD',
        'feature.node.kubernetes.io/pci-0302_10de.present' => 'true',
    );
    sub new { bless { objects => {}, paths => {}, patches => [], refuse => {} }, shift }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub expand_class     { undef }
    sub key {
        my ($kind, $namespace, $name) = @_;
        return join '/', $kind, $namespace // '-', $name;
    }
    sub list {
        my ($self, $kind, %a) = @_;
        die "unexpected list $kind\n" unless $kind eq 'Node';
        my ($k, $v) = split /=/, $a{labelSelector} // '', 2;
        return WlList->new([]) if defined $k && ($LABELS{$k} // '') ne ($v // '');
        return WlList->new([ WlNode->new(name => 'crag', labels => { %LABELS }) ]);
    }
    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : undef;
        my %a = @rest;
        $name //= $a{name};
        my $key = key($kind, $a{namespace}, $name);
        # { key => { after => N, error => E } }: the reads after the N-th die E.
        if (my $r = $self->{refuse}{$key}) { die $r->{error} if $r->{seen}++ >= $r->{after} }
        return { metadata => { name => 'crag', labels => { %LABELS } },
                 status   => { allocatable => { 'nvidia.com/gpu' => '1' }, capacity => { 'nvidia.com/gpu' => '1' } } }
            if $kind eq 'Node' && $name eq 'crag';
        my $obj = $self->{objects}{$key} or die "404 $key not found\n";
        return $kind eq 'DaemonSet' && $name eq 'nfd-worker' ? WlDaemonSet->new($obj) : $obj;
    }
    sub _request {
        my ($self, $method, $path, $body, %o) = @_;
        if ($method eq 'PATCH') {
            my $obj = JSON::PP::decode_json(JSON::PP::encode_json($body));
            push @{ $self->{patches} }, { kind => $obj->{kind}, name => $obj->{metadata}{name},
                                          params => $o{parameters}, object => $obj };
            $obj->{status} = { state => 'ready' } if $obj->{kind} eq 'ClusterPolicy';
            $self->{objects}{ key($obj->{kind}, $obj->{metadata}{namespace}, $obj->{metadata}{name}) } = $obj;
            $self->{paths}{$path} = $obj;
            return WlResponse->new(200, '{}');
        }
        die "unexpected $method $path\n" unless $method eq 'GET';
        my $obj = $self->{paths}{$path}
            or return WlResponse->new(404, '{"kind":"Status","status":"Failure","reason":"NotFound","code":404}');
        return WlResponse->new(200, JSON::PP::encode_json($obj));
    }
}

# The workloads: their step, probe label and component (the key, unless
# named), object and the image their manifest writes before the pin. NFD's
# two are one component, applied by one step (k369).
my %WL = (
    nfd => {
        step   => \&OCP::Cmd::Apply::Workloads::setup_nfd,
        label  => 'NFD',
        kind   => 'Deployment',
        key    => 'Deployment/node-feature-discovery/nfd-master',
        name   => 'nfd-master',
        image  => 'registry.k8s.io/nfd/node-feature-discovery:',
        record => 'nfd',
    },
    nfd_worker => {
        step      => \&OCP::Cmd::Apply::Workloads::setup_nfd,
        label     => 'NFD DaemonSet',
        component => 'nfd',
        kind      => 'DaemonSet',
        key       => 'DaemonSet/node-feature-discovery/nfd-worker',
        name      => 'nfd-worker',
        image     => 'registry.k8s.io/nfd/node-feature-discovery:',
        record    => 'nfd',
    },
    gpu_operator => {
        step   => \&OCP::Cmd::Apply::Workloads::setup_gpu_operator,
        label  => 'GPU Operator',
        kind   => 'Deployment',
        key    => 'Deployment/gpu-operator/gpu-operator',
        name   => 'gpu-operator',
        image  => 'nvcr.io/nvidia/gpu-operator:',
        record => 'gpu-operator',
    },
);
$WL{$_}{pin} = OCP::Versions->get_component_version($WL{$_}{component} // $_) for keys %WL;

sub project {
    my $dir = path(File::Temp::tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew(<<'YAML');
name: nvlab
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: crag.ocp.invalid
nocert: true
gpu:
  enabled: true
YAML
    return $dir;
}
sub config_for { OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify) }

sub new_apply {
    my ($api, %o) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ], %o);
    $apply->{_k8s_api} = $api;
    return $apply;
}

# One run of $c's step against $api, in list context unless scalar => 1:
# { rv, out, err, died, patches, record } -- what it wrote, the record after.
sub run_step {
    my ($api, $dir, $c, %o) = @_;
    my $apply = new_apply($api);
    my $config = config_for($dir);
    $api->{patches} = [];
    my $r = do {
        no warnings 'redefine';
        local *OCP::Cmd::Apply::_poll_deployment_ready = sub { 1 };
        local *OCP::Cmd::Apply::wait_seconds           = sub { };
        $o{scalar}
            ? capture { scalar $WL{$c}{step}->($apply, $config) }
            : capture { $WL{$c}{step}->($apply, $config) };
    };
    $r->{patches} = $api->{patches};
    my $file = $dir->child('.ocp', 'deployed.yaml');
    $r->{record}  = -f $file ? YAML::XS::LoadFile("$file") : {};
    return $r;
}

# What ocp status reads off the cluster for $c: the probe's entries, by label.
sub status_of {
    my ($api, $dir, $c) = @_;
    my $detector = OCP::Drift->new(config => config_for($dir), api => $api);
    return [ grep { ($_->{label} // '') eq $WL{$c}{label} } $detector->component_drift ];
}

# The dry run (ocp apply --dry-run on a cluster that exists): its output, and
# the writes it made -- there must be none.
sub dry_run {
    my ($api, $dir) = @_;
    my $apply = new_apply($api, dry_run => 1);
    $api->{patches} = [];
    my $r = do {
        no warnings 'redefine';
        # No host probes: the detector's SSH mode is not what this is about.
        local *OCP::Cmd::Apply::rex_prober = sub { undef };
        capture { OCP::Cmd::Apply::Drift::dry_run_report($apply, config_for($dir), '10.0.0.1') };
    };
    $r->{patches} = $api->{patches};
    ($r->{actions}) = $r->{out} =~ /^  (\d+) difference\(s\) a real run would act on\.$/m;
    return $r;
}

# A cluster where $c's step has deployed it, at its pin.
sub deployed {
    my ($c) = @_;
    my $api = WlApi->new;
    my $dir = project();
    run_step($api, $dir, 'nfd') if $c eq 'gpu_operator';    # NFD's CRDs and labels, as in apply
    my $first = run_step($api, $dir, $c);
    die "the first deploy of $c failed: $first->{died}" if $first->{died};
    die "the first deploy of $c was '@{ $first->{rv} }'\n" unless "@{ $first->{rv} }" eq 'deployed';
    return ($api, $dir, $first);
}

sub set_container {
    my ($api, $c, %field) = @_;
    my $container = $api->{objects}{ $WL{$c}{key} }{spec}{template}{spec}{containers}[0];
    @{$container}{ keys %field } = values %field;
}
sub image_of {
    my ($api, $c) = @_;
    return $api->{objects}{ $WL{$c}{key} }{spec}{template}{spec}{containers}[0]{image};
}

subtest 'k351: an image changed outside OCP -- status, the dry run and the real run agree' => sub {
    for my $c (qw( nfd nfd_worker gpu_operator )) {
        my ($label, $pin) = @{ $WL{$c} }{qw( label pin )};
        my ($api, $dir, $first) = deployed($c);
        is image_of($api, $c), $WL{$c}{image} . $pin, "$c: deployed at its pin";
        is_deeply status_of($api, $dir, $c), [], "$c: as OCP deployed it, the probe finds nothing";
        my $before = dry_run($api, $dir);

        set_container($api, $c, image => $WL{$c}{image} . 'v0.0.1');

        my ($entry, @more) = @{ status_of($api, $dir, $c) };
        is scalar @more, 0, "$c: one entry";
        is $entry && $entry->{message}, "$label runs v0.0.1, expected $pin", "$c: status names the image";
        ok $entry && OCP::Cmd::Status->_drift_fixable($entry), "$c: and counts it as drift ocp apply closes";

        my $dry = dry_run($api, $dir);
        is_deeply $dry->{patches}, [], "$c: the dry run writes nothing";
        like $dry->{out}, qr/^  \[drift\] \Q$label\E runs v0\.0\.1, expected \Q$pin\E\n {10}would re-apply the \Q$label\E manifest$/m,
            "$c: the dry run names it, and what a real run does about it";
        is $dry->{actions}, $before->{actions} + 1, "$c: one more difference a real run acts on";

        my $res = run_step($api, $dir, $c);
        is $res->{died}, '', "$c: the real run does not die";
        is_deeply $res->{rv}, [ 'updated', "ran v0.0.1, expected $pin" ],
            "$c: the real run re-applies it, and says why";
        my ($patch) = grep { $_->{kind} eq $WL{$c}{kind} && $_->{name} eq $WL{$c}{name} } @{ $res->{patches} };
        ok $patch, "$c: the $WL{$c}{kind} applied";
        is_deeply $patch && $patch->{params}, { fieldManager => 'ocp', force => 'true' },
            "$c: by a server-side apply with force, which takes the image back";
        is image_of($api, $c), $WL{$c}{image} . $pin, "$c: back at its pin";
        is_deeply $res->{record}, $first->{record}, "$c: the record as it was: the manifest did not move";
        is_deeply status_of($api, $dir, $c), [], "$c: then the probe finds nothing";

        my $again = run_step($api, $dir, $c);
        is_deeply $again->{rv}, ['unchanged'], "$c: the next run calls it up to date";
        is_deeply $again->{patches}, [], "$c: and applies nothing";

        # The step's callers that ask for one value get the outcome, as before.
        set_container($api, $c, image => $WL{$c}{image} . 'v0.0.1');
        is_deeply run_step($api, $dir, $c, scalar => 1)->{rv}, ['updated'], "$c: in scalar context, the outcome";
    }
};

subtest 'k351: what the probe does not call drift, the step leaves -- all three agree' => sub {
    for my $c (qw( nfd nfd_worker gpu_operator )) {
        (my $bare = $WL{$c}{pin}) =~ s/\Av//;
        my %case = (
            'the pin without its leading v' => [ image => $WL{$c}{image} . $bare ],
            'an image without a tag'        => [ image => ($WL{$c}{image} =~ s/:\z//r) . '@sha256:' . ('a' x 64) ],
            'args the probe does not read'  => [ args => [ '-v=5' ] ],
        );
        for my $what (sort keys %case) {
            my ($api, $dir) = deployed($c);
            my $before = dry_run($api, $dir);
            set_container($api, $c, @{ $case{$what} });
            is_deeply status_of($api, $dir, $c), [], "$c, $what: status names nothing";
            my $dry = dry_run($api, $dir);
            unlike $dry->{out}, qr/\Q$WL{$c}{label}\E (?:runs|manifest)/, "$c, $what: nor does the dry run";
            is $dry->{actions}, $before->{actions}, "$c, $what: no more differences";
            my $res = run_step($api, $dir, $c);
            is_deeply $res->{rv}, ['unchanged'], "$c, $what: the real run calls it up to date";
            is_deeply $res->{patches}, [], "$c, $what: and applies nothing";
        }
    }
};

subtest 'k351: a workload whose image cannot be read is no verdict' => sub {
    for my $c (qw( nfd nfd_worker gpu_operator )) {
        for my $refusal (@REFUSALS) {
            my ($code, $reason) = @$refusal;
            my ($api, $dir, $first) = deployed($c);
            set_container($api, $c, image => $WL{$c}{image} . 'v0.0.1');
            # Readable for the presence check, refused on the read after it.
            $api->{refuse}{ $WL{$c}{key} } = { after => 1, error => api_error($code, $reason) };
            my $res = run_step($api, $dir, $c);
            (my $where = $WL{$c}{key}) =~ s{\A\w+/}{};
            like $res->{died}, qr{\Acould not read \Q$WL{$c}{kind}\E \Q$where\E: Kubernetes API error \(get\): $code .*"reason":"$reason"}s,
                "$c, $code: the step dies with the cause";
            is_deeply $res->{patches}, [], "$c, $code: and applies nothing it could not see";
            is_deeply $res->{record}, $first->{record}, "$c, $code: the record as it was";
        }
    }
};

subtest 'k369: an nfd-worker that is not there -- status, the dry run and the real run agree' => sub {
    my $pin = $WL{nfd_worker}{pin};
    my ($api, $dir, $first) = deployed('nfd_worker');
    my $before = dry_run($api, $dir);
    delete $api->{objects}{ $WL{nfd_worker}{key} };

    my ($entry, @more) = @{ status_of($api, $dir, 'nfd_worker') };
    is scalar @more, 0, 'one entry';
    is $entry && $entry->{kind}, 'missing', 'status: missing';
    is $entry && $entry->{message}, "NFD DaemonSet is not deployed (expected $pin)", 'status names it';
    ok $entry && OCP::Cmd::Status->_drift_fixable($entry), 'and counts it as drift ocp apply closes';

    my $dry = dry_run($api, $dir);
    is_deeply $dry->{patches}, [], 'the dry run writes nothing';
    like $dry->{out}, qr/^  \[drift\] NFD DaemonSet is not deployed \(expected \Q$pin\E\)$/m, 'the dry run names it';
    is $dry->{actions}, $before->{actions} + 1, 'one more difference a real run acts on';

    my $res = run_step($api, $dir, 'nfd_worker');
    is $res->{died}, '', 'the real run does not die';
    is_deeply $res->{rv}, ['restored'], 'the real run restores it';
    ok +(grep { $_->{kind} eq 'DaemonSet' && $_->{name} eq 'nfd-worker' } @{ $res->{patches} }),
        'the DaemonSet applied';
    is image_of($api, 'nfd_worker'), $WL{nfd_worker}{image} . $pin, 'at its pin';
    is_deeply $res->{record}, $first->{record}, 'the record as it was';
    is_deeply status_of($api, $dir, 'nfd_worker'), [], 'then the probe finds nothing';
};

# The dry run's "would re-apply" is the promise of setup_nfd and
# setup_gpu_operator, and only theirs: the other probes' steps (Cilium's
# remedy, the AMD GPU step with its own dry run) close a version drift their
# own way, and a missing workload is deployed, not re-applied.
subtest 'k351: the dry run says re-apply only for the steps that do' => sub {
    my $config = config_for(project());
    for my $probe (@OCP::Drift::COMPONENT_PROBES) {
        my $c     = $probe->{component};
        my $mine  = $c eq 'nfd' || $c eq 'gpu_operator';
        my %entry = (component => $c, label => $probe->{label}, message => 'x');
        is !!OCP::Cmd::Apply::Workloads::reapplies({ %entry, kind => 'version' }, $config), !!$mine,
            "$c, another version: " . ($mine ? 'would re-apply' : 'nothing about a manifest');
        ok !OCP::Cmd::Apply::Workloads::reapplies({ %entry, kind => 'missing' }, $config),
            "$c, missing: nothing about a manifest";
    }
};

# gpu.enabled: false after the operator was deployed: setup_gpu_operator
# skips and leaves it, so the dry run does not promise to re-apply it. The
# probe still names the image (it reads the Deployment wherever it is).
subtest 'k351: no re-apply promised for a GPU Operator the step skips' => sub {
    my ($api, $dir) = deployed('gpu_operator');
    set_container($api, 'gpu_operator', image => $WL{gpu_operator}{image} . 'v0.0.1');
    $dir->child('ocp.yaml')->edit_raw(sub { s/^  enabled: true$/  enabled: false/m or die "no gpu.enabled\n" });
    my $dry = dry_run($api, $dir);
    like $dry->{out}, qr/^  \[drift\] GPU Operator runs v0\.0\.1, expected \Q$WL{gpu_operator}{pin}\E$/m,
        'the dry run names the image';
    unlike $dry->{out}, qr/would re-apply the GPU Operator manifest/, 'and promises no re-apply';
    my $res = run_step($api, $dir, 'gpu_operator');
    is_deeply $res->{rv}, ['skipped'], 'the real run skips the step';
    is_deeply $res->{patches}, [], 'and applies nothing';
};

done_testing;

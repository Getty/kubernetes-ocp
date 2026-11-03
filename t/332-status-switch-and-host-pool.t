#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use JSON::MaybeXS qw( decode_json );
use JSON::PP ();
use YAML::XS ();
use IO::K8s;

use lib 'lib';

use OCP;
use OCP::Cmd::Status;
use OCP::Config;
use OCP::Drift;
use OCP::Kubernetes;
use OCP::Versions;

#
# k332, two claims about `ocp status`:
#
#   1. A switch OCP::Config refuses (k320) blanks no drift report. Of the
#      switches, the drift check reads one: nocert, the cert-manager probe's
#      skip_if. Its accessor croaks with validate()'s line, detect died on it,
#      and status had "Cannot detect drift: nocert: ..." where the report
#      should be, exit 1. Now the probe that reads it is a check that could
#      not be made -- kind error, drift unknown, the line as its cause, said
#      once on STDERR -- and every other check runs; both forms list it the
#      way they list any check that could not be made (k262, k267). The rule
#      is skip_if's, not nocert's: whichever switch a probe names is read so.
#      The other switches (gpu.*, lbipam, system.ntp) are read by neither
#      status nor the drift check, and stand in their way not at all.
#   2. An ssh pool names its machines with host: (one) or a nodes: list
#      (k322). Status counted nodes: only, and a host-only pool read
#      "Workers (w): 0 (ssh)" where ocp apply makes it one worker.
#
# Network-free: the drift check is the real OCP::Drift against a fake api.
#

#### harness

{
    package Local::FakeApi;
    sub new { my ($class, %args) = @_; bless { objects => {}, %args }, $class }

    sub get {
        my ($self, $kind, %args) = @_;
        my $key = join '/', $kind, $args{namespace} // '', $args{name} // '';
        return $self->{objects}{$key}
            // die "Kubernetes API error (get $kind): 404 $kind $args{name} not found\n";
    }

    sub list { { items => [] } }

    # OCP's own CRDs as this ocp ships them (k291); anything else is a 404,
    # the GPU Operator's CRDs included.
    my %OCP_CRDS = map { $_->{metadata}{name} => $_ }
        map { YAML::XS::LoadFile("$_") }
        Path::Tiny::path(__FILE__)->parent->parent->child(qw(share robocop crds))->children(qr/\.yaml$/);
    sub _request {
        my ($self, $method, $path) = @_;
        (my $name = $path) =~ s{.*/}{};
        return Local::FakeResponse->new(200, JSON::PP->new->canonical->utf8->encode($OCP_CRDS{$name}))
            if $path =~ m{/customresourcedefinitions/} && $OCP_CRDS{$name};
        return Local::FakeResponse->new(404, '{"kind":"Status","code":404}');
    }
}
{
    package Local::FakeResponse;
    sub new     { my ($class, $status, $content) = @_; bless { status => $status, content => $content }, $class }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}
{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }
{ package Local::FakeSecrets; sub new { bless {}, $_[0] } sub has_kubeconfig { 1 } sub read_kubeconfig { "apiVersion: v1\n" } }
{
    package Local::FakeK8s;
    sub new { bless { api => $_[1] }, $_[0] }
    sub list_nodes { [ { metadata => { name => 'police1' } } ] }
    sub api { $_[0]{api} }
    sub gpu_nodes { [] }
    sub node_name { $_[1]{metadata}{name} }
    sub node_ready { 1 }
    sub node_roles { 'control-plane' }
    sub node_version { 'v1.32.1+rke2r1' }
    sub node_internal_ip { '10.0.0.10' }
    sub node_gpu_count { 0 }
    sub node_gpu_capacity { undef }
}

sub deployment {
    my ($image) = @_;
    return { spec => { template => { spec => { containers => [ { image => $image } ] } } } };
}

sub gateway_bundle {
    return IO::K8s->new->struct_to_object('CustomResourceDefinition', {
        apiVersion => 'apiextensions.k8s.io/v1',
        kind       => 'CustomResourceDefinition',
        metadata   => {
            name        => 'gateways.gateway.networking.k8s.io',
            annotations => {
                'gateway.networking.k8s.io/bundle-version' => OCP::Versions->get_component_version('gateway_api'),
                'gateway.networking.k8s.io/channel'        => 'standard',
            },
        },
        spec => {
            group    => 'gateway.networking.k8s.io',
            scope    => 'Namespaced',
            names    => { kind => 'Gateway', plural => 'gateways' },
            versions => [],
        },
    });
}

my %PIN = map { $_ => OCP::Versions->get_component_version($_) } qw( cilium cert_manager nfd );

# A cluster at every pin but Cilium's: one finding, the rest clean -- so a
# report that came through whole says exactly this, and no more.
sub cluster_api {
    return Local::FakeApi->new(objects => {
        'Deployment/kube-system/cilium-operator' => deployment('quay.io/cilium/operator-generic:v1.17.0'),
        'Deployment/cert-manager/cert-manager'   => deployment("quay.io/jetstack/cert-manager-controller:$PIN{cert_manager}"),
        'Deployment/node-feature-discovery/nfd-master'
            => deployment("registry.k8s.io/nfd/node-feature-discovery:$PIN{nfd}"),
        'CustomResourceDefinition//gateways.gateway.networking.k8s.io' => gateway_bundle(),
    });
}

my $CILIUM = "Cilium runs v1.17.0, expected $PIN{cilium}";

my $BASE = <<'YAML';
name: k332
kubernetes:
  version: v1.32.1+rke2r1
control_planes:
  provider: hetzner
  server_type: cx32
  location: fsn1
YAML

# The ocp.yaml lines that set $path to $typed: 'gpu.amd.labeller', 'off' is
# gpu:, amd: and labeller: off below it (t/296's helper).
sub yaml_at {
    my ($path, $typed) = @_;
    my @keys = split /\./, $path;
    my $leaf = pop @keys;
    my $text = '';
    $text .= ('  ' x $_) . "$keys[$_]:\n" for 0 .. $#keys;
    return $text . ('  ' x @keys) . "$leaf: $typed\n";
}

my $tmp = tempdir(CLEANUP => 1);
my $n = 0;

# The ocp.yaml $text in a project of its own; deployed unless told otherwise.
sub project {
    my ($text, %opt) = @_;
    my $dir = path($tmp)->child('p' . ++$n);
    $dir->mkpath;
    $dir->child('ocp.yaml')->spew_utf8($text);
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n") unless $opt{undeployed};
    return $dir->child('ocp.yaml')->stringify;
}

sub config_for { OCP::Config->new(file => project($_[0], undeployed => 1)) }

# (exit, STDOUT, STDERR) of one `ocp status` against cluster_api().
sub run_status {
    my ($cfg, %opt) = @_;
    my $cmd = OCP::Cmd::Status->new(
        ($opt{json} ? (json => 1) : ()),
        command_chain => [Local::FakeOCP->new(config => $cfg)],
    );
    my $api = cluster_api();
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my $rc;
    {
        no warnings 'redefine';
        local *OCP::Secrets::new            = sub { Local::FakeSecrets->new };
        local *OCP::Cmd::Status::reach_cluster_api = sub { $_[1] };
        local *OCP::Kubernetes::new         = sub { Local::FakeK8s->new($api) };
        local *OCP::Cmd::Status::rex_prober = sub { undef };
        local *STDOUT = $o;
        local *STDERR = $e;
        $rc = $cmd->execute([], []);
    }
    return ($rc, $out, $err);
}

# The drift section's lines.
sub drift_section {
    my ($out) = @_;
    my ($section) = $out =~ /\n=== Drift ===\n(.*?)\n\n/s;
    return defined $section ? [ split /\n/, $section ] : [];
}

# validate()'s line for nocert: no (k320), and the entry the drift check
# makes of it.
my $NOCERT_LINE = "nocert: must be true or false, not 'no'; write nocert: false";
my $NOCERT_MESSAGE = "cert-manager: ocp.yaml does not say whether to check it, drift unknown: $NOCERT_LINE";

#### 1. the drift check reads a refused switch as a check it could not make

subtest 'OCP::Drift: a refused nocert is the cert-manager check, unknown; the rest runs' => sub {
    is_deeply [ config_for($BASE . "nocert: no\n")->validate ], [ $NOCERT_LINE ],
        'the fixture: validate() refuses nocert: no with this line';

    my @warned;
    local $SIG{__WARN__} = sub { push @warned, $_[0] };
    my $drift = eval { OCP::Drift->new(config => config_for($BASE . "nocert: no\n"), api => cluster_api())->detect };
    is $@, '', 'detect does not die on it';

    my @cert = grep { $_->{component} eq 'cert_manager' } @{ $drift // [] };
    is scalar @cert, 1, 'one cert-manager entry';
    is $cert[0]{kind}, 'error', '... of kind error: drift unknown, not none';
    is $cert[0]{message}, $NOCERT_MESSAGE, '... validate()\'s line its cause, without a Perl location';
    is $cert[0]{remedy}, undef, '... and nothing for ocp apply to run';

    is_deeply [ map { $_->{message} } grep { $_->{component} ne 'cert_manager' } @{ $drift // [] } ],
        [ $CILIUM ], 'every other check ran: the Cilium finding, and nothing else';

    is scalar(@warned), 1, 'STDERR: one line';
    like $warned[0] // '', qr/^OCP::Drift::component_drift: cert-manager not checked: \Q$NOCERT_LINE\E at /,
        '... the line, once, with what it costs';
};

subtest 'OCP::Drift: a nocert it can read still decides' => sub {
    my @warned;
    local $SIG{__WARN__} = sub { push @warned, $_[0] };
    for my $case ([ 'true', 0 ], [ 'false', 0 ], [ '1', 0 ]) {
        my ($typed) = @$case;
        my $drift = OCP::Drift->new(config => config_for($BASE . "nocert: $typed\n"), api => cluster_api())->detect;
        is_deeply [ map { $_->{message} } @$drift ], [ $CILIUM ], "nocert: $typed -- the Cilium finding alone";
    }
    is_deeply \@warned, [], 'and nothing on STDERR';
};

# Each switch OCP::Config has and the accessor that reads it (t/296's table).
# A probe that names it in skip_if gets the same: the rule is skip_if's.
my %SWITCH = (
    'gpu.enabled'        => 'gpu_enabled',
    'gpu.toolkit'        => 'gpu_toolkit',
    'gpu.amd.labeller'   => 'gpu_amd_labeller',
    'gpu.amd.metrics'    => 'gpu_amd_metrics',
    'gpu.amd.integrated' => 'gpu_amd_integrated',
    'lbipam'             => 'lbipam',
    'nocert'             => 'no_cert',
    'system.ntp'         => 'ntp_enabled',
);

subtest 'OCP::Drift: any switch a probe names in skip_if is read the same way' => sub {
    is_deeply [ sort keys %SWITCH ], [ sort keys %OCP::Config::SWITCH_DEFAULTS ],
        'every switch OCP::Config has is swept here';

    for my $path (sort keys %SWITCH) {
        my ($key) = $path =~ /([^.]+)\z/;
        local @OCP::Drift::COMPONENT_PROBES = ({
            component => 'cilium', label => 'Probe', kind => 'Deployment',
            name => 'cilium-operator', namespace => 'kube-system', skip_if => $SWITCH{$path},
        });
        my @warned;
        local $SIG{__WARN__} = sub { push @warned, $_[0] };
        my $config = config_for($BASE . yaml_at($path, 'off'));
        my @drift = eval { OCP::Drift->new(config => $config, api => cluster_api())->component_drift };
        is $@, '', "$path: off -- component_drift does not die";
        is_deeply [ map { [ @{$_}{qw( kind message )} ] } @drift ],
            [ [ error => "Probe: ocp.yaml does not say whether to check it, drift unknown: "
                . "$path: must be true or false, not 'off'; write $key: false" ] ],
            "$path: off -- the probe is a check that could not be made, the line its cause";
        is scalar(@warned), 1, "$path: off -- said once";
    }
};

# k363: the cause is said by OCP::ErrorLine::one_line. The hand-made strip took
# one location off the very end only, so a refusal with one in the middle --
# validate()'s lines joined with '; ', a die that wraps another -- kept it, and
# its newline, in the drift entry and on STDERR.
subtest 'OCP::Drift: a refusal with a location inside is said as one line, without it' => sub {
    local @OCP::Drift::COMPONENT_PROBES = ({
        component => 'cilium', label => 'Probe', kind => 'Deployment',
        name => 'cilium-operator', namespace => 'kube-system', skip_if => 'no_cert',
    });
    no warnings 'redefine';
    local *OCP::Config::no_cert = sub {
        die "nocert: cannot read it: Not a HASH reference at lib/OCP/Config.pm line 9.\n"
          . "write nocert: false\n";
    };
    my @warned;
    local $SIG{__WARN__} = sub { push @warned, $_[0] };
    my @drift = eval { OCP::Drift->new(config => config_for($BASE), api => cluster_api())->component_drift };
    is $@, '', 'component_drift does not die';
    my $line = 'nocert: cannot read it: Not a HASH reference write nocert: false';
    is_deeply [ map { [ @{$_}{qw( kind message )} ] } @drift ],
        [ [ error => "Probe: ocp.yaml does not say whether to check it, drift unknown: $line" ] ],
        'the drift entry: the cause as one line, the location in the middle gone';
    is scalar(@warned), 1, 'said once';
    like $warned[0] // '', qr/^OCP::Drift::component_drift: Probe not checked: \Q$line\E at /,
        '... the same line, then the carp location only';
};

#### 1. ocp status, both forms

subtest 'ocp status: nocert: no gives its line and the rest of the drift report' => sub {
    my ($rc, $out, $err) = run_status(project($BASE . "nocert: no\n"));

    is $rc, 0, 'exit 0, as for any check that could not be made';
    my @err = split /\n/, $err;
    is scalar(@err), 1, 'STDERR: one line';
    like $err[0] // '', qr/cert-manager not checked: \Q$NOCERT_LINE\E/, '... validate()\'s line';
    unlike $err, qr/Cannot detect drift/, '... and drift detection did not die';

    like $out, qr/^police1\s+Ready\s+control-plane\s/m, 'STDOUT: the node table';
    is_deeply drift_section($out), [
        "  [drift] $CILIUM",
        "  [drift] could not be checked: $NOCERT_MESSAGE",
    ], 'STDOUT: the drift section, whole, the cert-manager check as could not be checked';
    like $out, qr/^1 of 1 can be reconciled automatically: run 'ocp apply'\.$/m,
        'STDOUT: the count is of the drift found';
    like $out, qr/\nKubeconfig: ocp kubeconfig -e\n\z/, 'STDOUT: the report ends as a good run does';
};

subtest 'ocp status --json: nocert: no -- the object, whole and parseable' => sub {
    my ($rc, $out, $err) = run_status(project($BASE . "nocert: no\n"), json => 1);

    is $rc, 0, 'exit 0';
    my @err = split /\n/, $err;
    is scalar(@err), 1, 'STDERR: one line';
    like $err[0] // '', qr/cert-manager not checked: \Q$NOCERT_LINE\E/, '... validate()\'s line';

    my $d = eval { decode_json($out) };
    ok $d, 'STDOUT is one JSON document' or return diag $out;
    ok !exists $d->{error}, 'no error: drift detection completed';
    is_deeply [ map { [ @{$_}{qw( component kind message )}, $_->{fixable} ? 1 : 0 ] } @{ $d->{drift} } ], [
        [ cert_manager => error   => $NOCERT_MESSAGE, 0 ],
        [ cilium       => version => $CILIUM,         1 ],
    ], 'drift: the cert-manager check as kind error, not fixable, and the Cilium finding';
};

subtest 'ocp status: the switches it does not read stand in its way not at all' => sub {
    for my $path (grep { $_ ne 'nocert' } sort keys %SWITCH) {
        my ($rc, $out, $err) = run_status(project($BASE . yaml_at($path, 'off')));
        is $rc, 0, "$path: off -- exit 0";
        is $err, '', "$path: off -- STDERR empty";
        is_deeply drift_section($out), [ "  [drift] $CILIUM" ], "$path: off -- the drift report, whole";
    }
};

#### 2. an ssh pool counts the machines it names

my @POOLS = (
    [ 'ssh, host: only'      => "    provider: ssh\n    host: 10.0.0.21\n"                        => 1 ],
    [ 'ssh, nodes: a list'   => "    provider: ssh\n    nodes: [ 10.0.0.21, { host: 10.0.0.22 } ]\n" => 2 ],
    [ 'ssh, nodes: []'       => "    provider: ssh\n    nodes: []\n"                              => 0 ],
    [ 'ssh, a host of 0'     => "    provider: ssh\n    host: 0\n"                                => 0 ],
    [ 'ssh, neither'         => "    provider: ssh\n"                                             => 0 ],
    [ 'hetzner, nodes: 3'    => "    provider: hetzner\n    server_type: cx23\n    nodes: 3\n"     => 3 ],
    # host: is an ssh pool's: ocp apply does not read it on any other.
    [ 'hetzner, nodes: 3 and a host: beside it'
        => "    provider: hetzner\n    server_type: cx23\n    nodes: 3\n    host: 10.0.0.23\n"   => 3 ],
);

subtest 'the spec summary counts the machines an ssh pool names, both forms' => sub {
    for my $case (@POOLS) {
        my ($what, $pool, $count) = @$case;
        my $cfg = project($BASE . "workers:\n  - name: w\n$pool", undeployed => 1);
        my ($provider) = $pool =~ /provider: (\w+)/;

        my (undef, $out) = run_status($cfg);
        like $out, qr/^Workers \(w\): \Q$count\E \(\Q$provider\E\)$/m, "$what: text says $count";

        my (undef, $json) = run_status($cfg, json => 1);
        is_deeply decode_json($json)->{spec}{workers}, [ { name => 'w', provider => $provider, nodes => $count } ],
            "$what: --json says $count";
    }
};

done_testing;

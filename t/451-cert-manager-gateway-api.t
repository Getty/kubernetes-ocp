#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);
use File::Temp qw(tempdir);
use YAML::XS ();

use lib 'lib';
use IO::K8s;
use OCP::Config;
use OCP::Drift;
use OCP::Versions;
use OCP::Cmd::Apply::Network;
use OCP::Cmd::Apply::K8s;
use OCP::Cmd::Apply::Drift;

#
# k451: the ACME ClusterIssuers OCP writes (acme_issuer) solve HTTP-01 through
# a gatewayHTTPRoute on cilium-gateway. cert-manager answers that solver only
# with --enable-gateway-api, which its release manifest does not set: the
# issuers read Ready and every order hangs at the challenge. A hand patch of
# the Deployment was taken away again by the next ocp apply/update.
#
# The claims here:
#   1. apply_cert_manager server-side applies the release manifest with
#      --enable-gateway-api on the cert-manager-controller container -- the
#      other args kept, an =false replaced, never twice;
#   2. a manifest without that Deployment or container dies instead of being
#      applied as it came;
#   3. the drift check reports a running controller without the flag, with
#      the cert-manager API remedy at the pin -- the one ocp apply runs, which
#      re-applies the manifest and so closes it; with the flag, under nocert,
#      or without the Deployment (the cert-manager probe's 'missing') there is
#      no entry, and a failed read is drift unknown;
#   4. what the writer applies, the reader reads as on.
#
# Network-free: the download, the apply and the API are stubs.
#

my $tmpdir = tempdir(CLEANUP => 1);

sub config_for {
    my ($extra) = @_;
    my $f = path($tmpdir)->child('c' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8("name: t\ncontrol_planes:\n  provider: local\n" . ($extra // ''));
    return OCP::Config->new(file => $f->stringify);
}

# The release manifest, cut down to the objects that matter here; the
# controller's args are the upstream ones.
sub manifest {
    my (@args) = @_;
    @args = ('--v=2', '--cluster-resource-namespace=$(POD_NAMESPACE)',
             '--leader-election-namespace=kube-system') unless @args;
    my $args = join '', map { "            - '$_'\n" } @args;
    return <<"YAML";
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-manager-webhook
  namespace: cert-manager
spec:
  template:
    spec:
      containers:
        - name: cert-manager-webhook
          args:
            - --v=2
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-manager
  namespace: cert-manager
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: cert-manager
  template:
    spec:
      containers:
        - name: cert-manager-controller
          image: quay.io/jetstack/cert-manager-controller:v1.21.2
          args:
$args
YAML
}

# Runs apply_cert_manager against $content and returns what it applied.
sub applied_from {
    my ($content) = @_;
    my @applied;
    no warnings 'redefine';
    local *HTTP::Tiny::get = sub { { success => 1, content => $content } };
    local *OCP::Cmd::Apply::K8s::server_side_apply = sub { push @applied, $_[2] };
    OCP::Cmd::Apply::Network::apply_cert_manager(bless({}, 'FakeCmd'), 'v1.21.2', {});
    return @applied;
}

sub controller_args {
    my ($resource) = @_;
    my ($c) = grep { $_->{name} eq 'cert-manager-controller' }
        @{ $resource->{spec}{template}{spec}{containers} };
    return $c->{args};
}

sub the_deployment {
    my ($d) = grep { $_->{kind} eq 'Deployment' && $_->{metadata}{name} eq 'cert-manager' } @_;
    return $d;
}

# --- 1. the writer -----------------------------------------------------------

subtest 'the controller is applied with --enable-gateway-api' => sub {
    my @applied = applied_from(manifest());
    is scalar @applied, 3, 'every object of the manifest is applied';
    is_deeply controller_args(the_deployment(@applied)),
        [ '--v=2', '--cluster-resource-namespace=$(POD_NAMESPACE)',
          '--leader-election-namespace=kube-system', '--enable-gateway-api' ],
        'the flag is added, the upstream args kept in order';
    my ($webhook) = grep { $_->{metadata}{name} eq 'cert-manager-webhook' } @applied;
    is_deeply $webhook->{spec}{template}{spec}{containers}[0]{args}, ['--v=2'],
        'the webhook is left as it came';
};

subtest 'never twice, and an =false does not stay beside it' => sub {
    is_deeply controller_args(the_deployment(applied_from(manifest('--v=2', '--enable-gateway-api')))),
        [ '--v=2', '--enable-gateway-api' ], 'already there: once';
    is_deeply controller_args(the_deployment(applied_from(manifest('--enable-gateway-api=false', '--v=2')))),
        [ '--v=2', '--enable-gateway-api' ], '=false replaced';
    # A neighbouring flag that only starts the same is not the flag.
    is_deeply controller_args(the_deployment(applied_from(manifest('--enable-gateway-api-foo')))),
        [ '--enable-gateway-api-foo', '--enable-gateway-api' ], 'a longer flag is kept';
};

# --- 2. a manifest the flag cannot go into ----------------------------------

subtest 'a manifest without the controller dies, nothing applied' => sub {
    my $no_deploy = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: cert-manager\n";
    my @applied;
    ok !eval { @applied = applied_from($no_deploy); 1 }, 'no Deployment: dies';
    like $@, qr{no Deployment cert-manager/cert-manager; cannot set --enable-gateway-api},
        'and says what it could not do';
    is scalar @applied, 0, 'before applying anything';

    (my $renamed = manifest()) =~ s/name: cert-manager-controller/name: controller/;
    ok !eval { applied_from($renamed); 1 }, 'no cert-manager-controller container: dies';
    like $@, qr/has no cert-manager-controller container/, 'and says so';
};

# --- 3. the drift check -----------------------------------------------------

package FakeApi {
    sub new { my ($class, %o) = @_; bless { calls => 0, %o }, $class }
    sub get {
        my ($self, $kind, %a) = @_;
        $self->{calls}++;
        die $self->{die} if $self->{die};
        my $obj = $self->{objects}{ join '/', $kind, $a{namespace} // '', $a{name} // '' };
        die "Kubernetes API error (get $kind): 404 $kind not found\n" unless $obj;
        return $obj;
    }
    # What detect's other probes ask: no Nodes, and no CRDs (a 404).
    sub list     { +{ items => [] } }
    sub _request { FakeResponse->new }
}

package FakeResponse {
    sub new     { bless {}, shift }
    sub status  { 404 }
    sub content { '{"kind":"Status","code":404}' }
}

# A running Deployment as the client hands it back: a typed object.
sub running {
    my (@args) = @_;
    my $struct = (grep { $_->{kind} eq 'Deployment' && $_->{metadata}{name} eq 'cert-manager' }
        YAML::XS::Load(manifest(@args)))[0];
    return IO::K8s->new->struct_to_object('Deployment', $struct);
}

sub probe {
    my ($api, $extra) = @_;
    return OCP::Drift->new(config => config_for($extra), api => $api)
        ->cert_manager_gateway_api_drift;
}

my $KEY = 'Deployment/cert-manager/cert-manager';

subtest 'a controller without the flag is drift that ocp apply closes' => sub {
    my @d = probe(FakeApi->new(objects => { $KEY => running() }));
    is scalar @d, 1, 'one entry' or return;
    my $e = $d[0];
    is $e->{kind}, 'spec', 'spec kind';
    is $e->{component}, 'cert_manager', 'component';
    is $e->{label}, 'cert-manager Gateway API', 'label';
    is $e->{expected}, 'enabled', 'expected';
    is $e->{actual}, 'disabled', 'actual';
    like $e->{message}, qr/runs without --enable-gateway-api/, 'says what is missing';
    like $e->{message}, qr/HTTP-01/, 'and what it breaks';
    is $e->{remedy}{type}, 'api', 'an API remedy';
    is $e->{remedy}{task}, 'upgrade_cert_manager', 'the cert-manager one';
    is $e->{remedy}{params}{version}, OCP::Versions->get_component_version('cert_manager'),
        'at the pin';
};

subtest 'ocp apply runs that remedy' => sub {
    my ($e) = probe(FakeApi->new(objects => { $KEY => running() }));
    my @ran;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::Network::upgrade_cert_manager = sub { push @ran, $_[2]; 1 };
    my $self = bless {}, 'FakeCmd';
    ok OCP::Cmd::Apply::Drift::run_remedy($self, config_for(), $e), 'run';
    is_deeply \@ran, [ OCP::Versions->get_component_version('cert_manager') ],
        'upgrade_cert_manager at the pin';
};

subtest 'no entry where there is nothing to report' => sub {
    is_deeply [ probe(FakeApi->new(objects => { $KEY => running('--v=2', '--enable-gateway-api') })) ],
        [], 'the flag set';
    is_deeply [ probe(FakeApi->new(objects => { $KEY => running('--enable-gateway-api=true') })) ],
        [], '=true';
    my @d = probe(FakeApi->new(objects => { $KEY => running('--enable-gateway-api', '--enable-gateway-api=false') }));
    is scalar @d, 1, 'the last one wins: =false after it is off';
    is_deeply [ probe(FakeApi->new(objects => {})) ], [],
        'no Deployment: the cert-manager probe reports it missing, not this one';

    my $api = FakeApi->new(objects => { $KEY => running() });
    is_deeply [ probe($api, "nocert: true\n") ], [], 'nocert: true';
    is $api->{calls}, 0, 'without asking the cluster';
    is_deeply [ probe(FakeApi->new(objects => { $KEY => running() }), "nocert: no\n") ], [],
        'a nocert OCP::Config refuses is component_drift\'s error entry, not a second one';
};

subtest 'a failed read is drift unknown' => sub {
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, @_ };
    my @d = probe(FakeApi->new(die => "Kubernetes API error (get Deployment): 403 forbidden\n"));
    is scalar @d, 1, 'one entry' or return;
    is $d[0]{kind}, 'error', 'an error entry';
    is $d[0]{label}, 'cert-manager Gateway API', 'named';
    ok !$d[0]{remedy}, 'no remedy';
    like "@warn", qr/cert_manager_gateway_api_drift/, 'the cause said on stderr';
};

subtest 'detect asks it' => sub {
    my $d = OCP::Drift->new(config => config_for(), api => FakeApi->new(objects => { $KEY => running() }))
        ->detect;
    ok((grep { ($_->{label} // '') eq 'cert-manager Gateway API' } @$d), 'entry in detect()');
};

# --- 4. writer and reader agree ---------------------------------------------

subtest 'what apply writes, the drift check reads as on' => sub {
    my $applied = the_deployment(applied_from(manifest()));
    is OCP::Drift::cert_manager_gateway_api_on($applied), 1, 'as a hash';
    is OCP::Drift::cert_manager_gateway_api_on(IO::K8s->new->struct_to_object('Deployment', $applied)),
        1, 'as the typed object the API returns';
    is OCP::Drift::cert_manager_gateway_api_on(running()), 0, 'the manifest as it came: off';
    is OCP::Drift::cert_manager_gateway_api_on({ spec => {} }), undef, 'no container: not compared';
};

package FakeCmd { sub _k8s_api { {} } }

done_testing;

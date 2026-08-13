#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();

use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Destroy;

#
# .ocp/deployed.yaml records the manifest hash of every component OCP rolled
# out, and a component whose hash is unchanged is skipped (ADR 0008). What the
# file never was is evidence: it says what OCP did, not what the cluster has.
#
# `ocp destroy` removed .ocp/status.yaml and the encrypted kubeconfig but left
# deployed.yaml behind, so the next apply — against a cluster built from
# scratch, on a different distribution even — compared against the components
# of a cluster that no longer existed:
#
#   [..] Setting up OCP registry (pull-through cache + local)...
#       Registry already deployed (up to date)
#   [ok] OCP registry ready
#   [ok] CoreDNS configured for registry.local -> 10.230.30.155
#
# ocp-system was empty. CoreDNS was pointed at a registry that did not exist.
# Nothing failed: a component that is never deployed produces no broken pods
# for the health gate (ADR 0017) to find, it produces no pods at all.
#
# That only the registry went missing was luck — cert-manager, NFD and the GPU
# operator carry distribution-dependent values whose hash changed with the
# k3s -> rke2 switch. On the same distribution, destroy + apply would have
# skipped everything.
#
# Two claims are nailed down here:
#   1. destroy takes the local cluster state with it, all of it.
#   2. "up to date" is never said without asking the cluster first.
#

my $REGISTRY_MANIFEST_HASH;   # filled in by the first subtest

package FakeOcp {
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub dump      { my ($s, @r) = @_; join '', map { YAML::XS::Dump($_) } @r }
    sub load_file { my ($s, $f) = @_; YAML::XS::LoadFile("$f") }
    sub dump_file { my ($s, $f, $d) = @_; YAML::XS::DumpFile("$f", $d) }
    sub config    { $_[0]{config} }
}

# Only what _setup_registry asks of a config.
package FakeConfig {
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub project_dir          { $_[0]{dir} }
    sub deployed_file        { $_[0]{dir}->child('.ocp', 'deployed.yaml')->stringify }
    sub has_external_cache   { $_[0]{external_cache} }
    sub has_external_upstream { $_[0]{external_upstream} }
    sub registry_cache       { 'cache.example:5000' }
    sub registry_upstream    { 'upstream.example:5000' }
    sub registry_name        { 'registry.local' }
}

# A cluster that has exactly the objects it was told it has. The real client
# throws on a 404, which is what _resource_exists reads as "not there".
package FakeApi {
    sub new { my ($c, %a) = @_; bless { have => $a{have} // {}, %a }, $c }
    sub get {
        my ($self, $kind, $name, %opts) = @_;
        my $key = join '/', $kind, ($opts{namespace} // '-'), $name;
        die "404 $key not found\n" unless $self->{have}{$key};
        return bless { kind => $kind, name => $name }, 'FakeObject';
    }
}

package main;

my @applied;
{
    no warnings 'redefine';
    *OCP::Cmd::Apply::_apply_yaml_string  = sub { push @applied, $_[2]; 1 };
    *OCP::Cmd::Apply::_poll_deployment_ready = sub { 1 };
}

sub capture_stdout (&) {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $rc;
    {
        local *STDOUT = $fh;
        $rc = $code->();
    }
    return ($out, $rc);
}

# A registry the cluster really has: namespace plus both deployments.
my %FULL_REGISTRY = (
    'Namespace/-/ocp-system'               => 1,
    'Deployment/ocp-system/ocp-cache'      => 1,
    'Deployment/ocp-system/ocp-registry'   => 1,
);

sub setup_registry {
    my (%opt) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    my $config = FakeConfig->new(dir => $dir, %{ $opt{config} // {} });

    if (my $hashes = $opt{deployed}) {
        $dir->child('.ocp')->mkpath;
        YAML::XS::DumpFile($config->deployed_file, $hashes);
    }

    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    $apply->{_k8s_api} = FakeApi->new(have => $opt{have} // {});

    @applied = ();
    my ($out, $outcome) = capture_stdout { $apply->_setup_registry($config) };

    return {
        out     => $out,
        outcome => $outcome,
        applied => [@applied],
        hashes  => -f $config->deployed_file
            ? YAML::XS::LoadFile($config->deployed_file) : {},
    };
}

subtest 'a cluster with no registry gets one' => sub {
    my $r = setup_registry();

    is $r->{outcome}, 'deployed', 'reported as a first deployment';
    is scalar @{ $r->{applied} }, 1, 'the manifest was applied';
    ok $r->{hashes}{registry}, 'and the hash was recorded';

    $REGISTRY_MANIFEST_HASH = $r->{hashes}{registry};
};

subtest 'a registry that is recorded AND present is left alone' => sub {
    my $r = setup_registry(
        deployed => { registry => $REGISTRY_MANIFEST_HASH },
        have     => { %FULL_REGISTRY },
    );

    is $r->{outcome}, 'unchanged', 'nothing to do';
    is scalar @{ $r->{applied} }, 0, 'nothing applied';
    like $r->{out}, qr/up to date/, 'and it may say so, because it asked';
};

#
# The regression itself.
#
subtest 'a matching hash over an empty cluster is not "up to date"' => sub {
    # Exactly the state destroy used to leave behind: the record of the old
    # cluster, and a new cluster that has nothing.
    my $r = setup_registry(
        deployed => { registry => $REGISTRY_MANIFEST_HASH },
        have     => {},
    );

    unlike $r->{out}, qr/already deployed|up to date/,
        'the claim that broke cortex is not made';
    is scalar @{ $r->{applied} }, 1,
        'the registry is deployed instead of skipped';
    is $r->{outcome}, 'restored',
        'and the caller is told the cluster had lost it';
};

subtest 'half a registry is not a registry' => sub {
    # A hand-deleted Deployment is the same fault as a destroyed cluster, only
    # smaller: the namespace still exists and the record still matches.
    for my $gone ('Deployment/ocp-system/ocp-cache', 'Deployment/ocp-system/ocp-registry') {
        my %have = %FULL_REGISTRY;
        delete $have{$gone};

        my $r = setup_registry(
            deployed => { registry => $REGISTRY_MANIFEST_HASH },
            have     => \%have,
        );

        is $r->{outcome}, 'restored', "$gone missing is noticed";
        is scalar @{ $r->{applied} }, 1, "and put back";
    }
};

subtest 'nothing is expected that this configuration never deploys' => sub {
    # With an external cache and an external upstream OCP deploys the
    # namespace and nothing else. Demanding the deployments anyway would make
    # the registry redeploy on every single run.
    my $r = setup_registry(
        config   => { external_cache => 1, external_upstream => 1 },
        have     => { 'Namespace/-/ocp-system' => 1 },
    );
    is $r->{outcome}, 'deployed', 'first run deploys';

    my $again = setup_registry(
        config   => { external_cache => 1, external_upstream => 1 },
        deployed => { registry => $r->{hashes}{registry} },
        have     => { 'Namespace/-/ocp-system' => 1 },
    );
    is $again->{outcome}, 'unchanged',
        'and the next run is quiet without either deployment existing';
    is scalar @{ $again->{applied} }, 0, 'nothing reapplied';
};

subtest 'reconcile reports what happened, not what the file suggested' => sub {
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);

    my %expected = (
        unchanged => qr/up to date/,
        deployed  => qr/was missing/,
        restored  => qr/gone from the cluster/,
        updated   => qr/manifest changed/,
    );

    for my $outcome (sort keys %expected) {
        my ($out, $counted) = capture_stdout {
            $apply->_report_component('Registry', $outcome);
        };
        like $out, $expected{$outcome}, "$outcome is named in the output";
        is $counted, ($outcome eq 'unchanged' ? 0 : 1),
            "$outcome counts as " . ($outcome eq 'unchanged' ? 'no change' : 'a change');
    }

    # A component put back on the cluster is a change, and the summary line at
    # the end of reconcile has to include it — "All N components up to date"
    # over a redeployed registry is the same lie in a different place.
    my ($out) = capture_stdout { $apply->_report_component('Registry', 'restored') };
    like $out, qr/\[ok\]/, 'still an ok line, not a warning';
};

#
# The invariant behind all of it, so the next hash-gated component cannot
# repeat the mistake: whoever reads the hashes also asks the cluster.
#

subtest 'no component trusts the hash file on its own' => sub {
    my $src = path('lib/OCP/Cmd/Apply.pm')->slurp_utf8;

    my @subs = $src =~ /^sub (\w+) \{\n(.*?)\n\}$/msg;
    my %body;
    while (my ($name, $body) = splice @subs, 0, 2) { $body{$name} = $body }

    my @readers = grep {
        $body{$_} =~ /_load_deployed_hashes/
            && !/^_(?:load|save)_deployed_hash(?:es)?$/
    } sort keys %body;

    ok scalar @readers, 'found the subs that consult the hash record'
        or diag 'nothing reads _load_deployed_hashes any more — check this test';

    for my $name (@readers) {
        like $body{$name}, qr/_resource_exists|_registry_running/,
            "$name asks the cluster before believing the record";
    }
};

#
# destroy: the record dies with the cluster it describes (ADR 0004).
#

subtest 'the deployed-hash path has one definition' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);

    is $config->deployed_file, $dir->child('.ocp', 'deployed.yaml')->stringify,
        'OCP::Config names the file';

    my $apply_src = path('lib/OCP/Cmd/Apply.pm')->slurp_utf8;
    unlike $apply_src, qr/'deployed\.yaml'/,
        'apply does not spell the path a second time';

    my $destroy_src = path('lib/OCP/Cmd/Destroy.pm')->slurp_utf8;
    unlike $destroy_src, qr/'deployed\.yaml'/,
        'neither does destroy';
};

subtest 'destroy removes the local cluster state' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew(<<'YAML');
name: cortex
kubernetes:
  dist: rke2
control_planes:
  provider: ssh
workers: []
YAML

    $dir->child('.ocp')->mkpath;
    my $status   = path($dir->child('.ocp', 'status.yaml'));
    my $deployed = path($dir->child('.ocp', 'deployed.yaml'));
    my $kubeconfig = $dir->child('kubeconfig.yaml');
    $status->spew("nodes: []\n");
    $deployed->spew("registry: deadbeef\nnfd: cafebabe\n");
    $kubeconfig->spew("encrypted\n");

    my $destroy = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new_with_config($dir->child('ocp.yaml')->stringify) ],
        force         => 1,
    );

    my ($out) = capture_stdout { $destroy->execute([], []) };

    ok !-f $status,     'status.yaml is gone';
    ok !-f $deployed,
        'deployed.yaml is gone — otherwise the next apply skips what is missing';
    ok !-f $kubeconfig, 'the encrypted kubeconfig is gone';
};

subtest '--keep-status keeps all of it, not half' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew(<<'YAML');
name: cortex
kubernetes:
  dist: rke2
control_planes:
  provider: ssh
workers: []
YAML

    $dir->child('.ocp')->mkpath;
    my $status   = path($dir->child('.ocp', 'status.yaml'));
    my $deployed = path($dir->child('.ocp', 'deployed.yaml'));
    $status->spew("nodes: []\n");
    $deployed->spew("registry: deadbeef\n");

    my $destroy = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new_with_config($dir->child('ocp.yaml')->stringify) ],
        force         => 1,
        keep_status   => 1,
    );

    capture_stdout { $destroy->execute([], []) };

    ok -f $status,   'status.yaml kept';
    ok -f $deployed, 'deployed.yaml kept with it — one switch, one meaning';
};

done_testing;

sub FakeOcp::new_with_config {
    my ($class, $config) = @_;
    my $self = FakeOcp->new;
    $self->{config} = $config;
    return $self;
}

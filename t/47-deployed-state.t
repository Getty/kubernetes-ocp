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
    sub gpu_enabled          { $_[0]{gpu_enabled} // 1 }
}

# A cluster NFD found no NVIDIA card on.
package NoGpuList { sub new { bless {}, shift } sub items { [] } }
package NoGpuApi  { sub new { bless {}, shift } sub list { NoGpuList->new } }

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

    # The whole vocabulary, and what each word costs the summary line.
    # 'skipped' is the GPU operator's fifth answer: no NVIDIA card, or
    # gpu.enabled: false. It is not a change — a cluster with no GPU that
    # reported "1 component updated" on every single run would be the same
    # kind of untruth as "up to date" over a component that was just put back.
    my %expected = (
        unchanged => [qr/up to date/,             0],
        deployed  => [qr/was missing/,            1],
        restored  => [qr/gone from the cluster/,  1],
        updated   => [qr/manifest changed/,       1],
        skipped   => [qr/skipped/,                0],
    );

    for my $outcome (sort keys %expected) {
        my ($re, $counts) = @{ $expected{$outcome} };
        my ($out, $counted) = capture_stdout {
            $apply->_report_component('Registry', $outcome);
        };
        like $out, $re, "$outcome is named in the output";
        is $counted, $counts,
            "$outcome counts as " . ($counts ? 'a change' : 'no change');
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
    # A directory scan, not a hardcoded pair of files: the Phase 8 extraction
    # (#55) moved the Registry/NFD/GPU-operator hash readers out of Apply.pm
    # into Apply/Registry.pm and Apply/Workloads.pm, and this subtest kept
    # looking only at Apply.pm + Apply/Drift.pm -- it kept reporting a pass
    # for coverage it no longer had (#68). Whatever module the next extraction
    # lands a component in gets picked up here automatically.
    my @files = (
        path('lib/OCP/Cmd/Apply.pm'),
        path('lib/OCP/Cmd/Apply')->children(qr/\.pm$/),
    );

    # DeployedHash.pm defines the hash mechanism itself (load/save/
    # report_component) -- it has no cluster to ask, only the file it reads
    # and writes; every real component reaches it through the
    # $self->_load_deployed_hashes($config) accessor, never by calling load()
    # directly. Named exception, not a silent filter: if this module ever
    # grows a sub that forms an "up to date" verdict on its own, that sub
    # needs the same _resource_exists scrutiny as everywhere else and this
    # exclusion should go.
    @files = grep { $_->basename ne 'DeployedHash.pm' } @files;

    ok scalar(@files) > 2,
        'scanning more than the two files #68 found the blind spot in';

    # Per-file: name -> body, and per-file: which subs read the hash record.
    # Kept scoped to one file at a time, not merged into one global map --
    # Registry.pm's setup() delegates the cluster question to a sibling
    # running() rather than asking directly, and that indirection is resolved
    # by walking calls to *other subs in the same file*, not by hardcoding
    # "running" as a magic name (that would be exactly the brittle, file-list
    # style fix #68 is about). Resolving across files would let two unrelated
    # modules' same-named helpers shadow each other.
    my (@readers, %asks_cluster);

    for my $file (@files) {
        my $src = $file->slurp_utf8;
        my @subs = $src =~ /^sub (\w+) \{\n(.*?)\n\}$/msg;
        my %body;
        while (my ($name, $sub_body) = splice @subs, 0, 2) { $body{$name} = $sub_body }

        my @file_readers = grep {
            $body{$_} =~ /_load_deployed_hashes/
                && !/^_(?:load|save)_deployed_hash(?:es)?$/
        } sort keys %body;

        for my $name (@file_readers) {
            my $key = "$file:$name";
            push @readers, $key;

            my (%seen, $found);
            my @stack = ($name);
            while (@stack && !$found) {
                my $n = pop @stack;
                next if $seen{$n}++;
                next unless $body{$n};
                if ($body{$n} =~ /_resource_exists|_registry_running/) {
                    $found = 1;
                    last;
                }
                push @stack, $body{$n} =~ /(?:->)?(\w+)\s*\(/g;
            }
            $asks_cluster{$key} = $found;
        }
    }

    ok scalar @readers, 'found the subs that consult the hash record'
        or diag 'nothing reads _load_deployed_hashes any more — check this test';

    for my $key (@readers) {
        ok $asks_cluster{$key},
            "$key asks the cluster before believing the record";
    }
};

#
# The GPU operator answers in the same vocabulary, including the word the
# other components have no use for.
#

subtest 'a cluster the GPU operator has no business on says so' => sub {
    my $dir = path(tempdir(CLEANUP => 1));

    my $off = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    my ($out, $outcome) = capture_stdout {
        $off->_setup_gpu_operator(FakeConfig->new(dir => $dir, gpu_enabled => 0));
    };
    is $outcome, 'skipped', 'gpu.enabled: false is a skip, not an unchanged';
    like $out, qr/gpu\.enabled is false/, 'and the reason is on the record';
    unlike $out, qr/\[ok\]/,
        'the verdict line belongs to the reporter, so the step does not print one';

    my $bare = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    $bare->{_k8s_api} = NoGpuApi->new;
    my ($out2, $outcome2) = capture_stdout {
        $bare->_setup_gpu_operator(FakeConfig->new(dir => $dir));
    };
    is $outcome2, 'skipped', 'no NVIDIA card is the same answer';
    like $out2, qr/No GPU nodes detected/, 'with its own reason';

    # What the reconcile block used to infer from "no gpu-operator key in the
    # file afterwards" is now simply what the step said.
    my ($reported, $counted) = capture_stdout {
        $off->_report_component('GPU Operator', 'skipped');
    };
    like $reported, qr/\[ok\] GPU Operator skipped/, 'reported as a skip';
    is $counted, 0, 'and counted as no change';
};

subtest 'reconcile forms no verdict of its own' => sub {
    my $reconcile_src = path('lib/OCP/Cmd/Apply/Drift.pm')->slurp_utf8;
    my ($reconcile) = $reconcile_src =~ /^sub reconcile_components \{\n(.*?)\n\}$/ms;
    ok defined $reconcile, 'reconcile_components found';

    # The GPU block used to read the hash file before and after the deploy
    # step and diff the two. That is a second judge with strictly less
    # evidence than the step itself: an operator gone from the cluster and
    # rolled out again at an unchanged hash looked identical to one that was
    # never touched, and got reported as "up to date".
    my @reads = $reconcile =~ /(_load_deployed_hashes)/g;
    is scalar @reads, 1,
        'the hash file is read once in reconcile, by the cert-manager block';

    unlike $reconcile, qr/deployed_after/,
        'no before/after comparison of the record is left';

    # cert-manager keeps its own $was_missing, and it is the harmless kind:
    # derived from _resource_exists, i.e. from the cluster, not from the file.
    like $reconcile, qr/my \$was_missing = !\$cm_running/,
        'cert-managers verdict comes from what the cluster answered';

    for my $label ('Registry', 'NFD', 'GPU Operator') {
        like $reconcile, qr/_report_component\('\Q$label\E'/,
            "$label is reported from what the deploy step returned";
    }
};

#
# karr #69: cert-manager's reconcile gate used to test presence, not
# equality, against OCP::Versions->get_component_version('cert_manager').
# A version bump in OCP::Versions would never be reconciled on this path --
# the gate read "entry exists, deployment is running" and skipped. Asserted
# directly: a recorded version that does not match the canonical one must
# trigger _apply_cert_manager; a matching version must not.
#

package CertManagerGate::Api {
    sub new { my ($c, %a) = @_; bless { have => $a{have} // {}, %a }, $c }
    sub get { die "404 unexpected get\n" }
    sub list {
        my ($s, $kind) = @_;
        return $kind eq 'Node' ? { items => [] } : { items => [] };
    }
    sub expand_class { undef }
    sub _request { bless {}, 'NoopResponse' }
}
package NoopResponse { sub new { bless {}, shift } sub status { 200 } sub content { '{}' } }

package CertManagerGate::Ocp {
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub load_file { my ($s, $f) = @_; YAML::XS::LoadFile("$f") }
    sub dump_file { my ($s, $f, $d) = @_; YAML::XS::DumpFile("$f", $d) }
    sub dump      { '' }
    sub config    { $_[0]{config} }
}

package main;

sub reconcile_cert_manager {
    my (%opt) = @_;

    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew(<<'YAML');
name: cortex
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: cortex.ocp.invalid
lbipam: true
YAML
    $dir->child('.ocp')->mkpath;

    if (my $hashes = $opt{deployed}) {
        YAML::XS::DumpFile($dir->child('.ocp', 'deployed.yaml'), $hashes);
    }

    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);

    my @applied_cert;
    my @waited;
    my @saved;
    my @exists_calls;

    {
        no warnings 'redefine';
        no strict 'refs';

        *OCP::Secrets::read_kubeconfig = sub { "apiVersion: v1\nkind: Config\n" };

        *OCP::Cmd::Apply::_k8s_api = sub { $_[0]{_k8s_api} };
        *OCP::Cmd::Apply::_resource_exists = sub {
            my ($s, $api, $kind, $name, %o) = @_;
            push @exists_calls, "$kind/$o{namespace}/$name";
            return $opt{cm_running} ? 1 : 0;
        };
        *OCP::Cmd::Apply::_apply_cert_manager = sub {
            push @applied_cert, 1;
            return 1;
        };
        *OCP::Cmd::Apply::_wait_cert_manager_and_create_issuers = sub {
            push @waited, 1;
            return 1;
        };
        *OCP::Cmd::Apply::_save_deployed_hash = sub {
            push @saved, { component => $_[2], value => $_[3] };
            return 1;
        };

        # Stub every other piece the reconcile path touches. None of them
        # should fire for the cert-manager block; if any does, the test sees
        # it in @touched below and the assert is loosened for that reason.
        *OCP::Cmd::Apply::_setup_registry             = sub { 'unchanged' };
        *OCP::Cmd::Apply::_configure_registry_dns     = sub { 0 };
        *OCP::Cmd::Apply::_setup_nfd                  = sub { 'unchanged' };
        *OCP::Cmd::Apply::_setup_gpu_operator         = sub { 'skipped' };
        *OCP::Cmd::Apply::_setup_cilium_gateway       = sub { 1 };
        *OCP::Cmd::Apply::_setup_lb_ipam              = sub { 1 };
        *OCP::Cmd::Apply::_ensure_crds                = sub { 1 };
        *OCP::Cmd::Apply::_ensure_providers           = sub { 1 };
        *OCP::Cmd::Apply::_migrate_legacy_nodes       = sub { 1 };
        *OCP::Cmd::Apply::_ensure_cp_ocpnode          = sub { 1 };
        *OCP::Cmd::Apply::_run_remedy                 = sub { 0 };
        *OCP::Cmd::Apply::_stamp_ocp_version          = sub { 1 };
    }

    my $apply = OCP::Cmd::Apply->new(command_chain => [ bless {}, 'CertManagerGate::Ocp' ]);
    $apply->{_k8s_api} = CertManagerGate::Api->new;

    my ($out) = capture_stdout { $apply->_reconcile_components($config) };

    return {
        out           => $out,
        applied_cert  => [ @applied_cert ],
        waited        => [ @waited ],
        saved         => [ @saved ],
    };
}

subtest 'reconcile gates cert-manager on version equality, not presence (karr #69)' => sub {

    # Recorded equals canonical -> skipped. A version that already matches
    # OCP::Versions must not be rolled out again on every reconcile.
    my $canonical = OCP::Versions->get_component_version('cert_manager');
    my $match = reconcile_cert_manager(
        deployed  => { certmanager => $canonical },
        cm_running => 1,
    );
    is scalar @{ $match->{applied_cert} }, 0,
        'matching recorded version -> nothing to apply';
    is scalar @{ $match->{saved} }, 0,
        'and the hash is not rewritten';
    like $match->{out}, qr/cert-manager up to date/,
        'and the printout says so';

    # Recorded older than canonical -> redeployed. This is the case the
    # presence-only gate let slip: the entry was there, the deployment was
    # running, and a newer OCP::Versions was silently skipped.
    my $stale = reconcile_cert_manager(
        deployed  => { certmanager => 'v0.0.0-older' },
        cm_running => 1,
    );
    is scalar @{ $stale->{applied_cert} }, 1,
        'stale recorded version -> cert-manager is re-applied';
    is scalar @{ $stale->{waited} }, 1,
        'and the wait + issuers step runs with it';
    is scalar @{ $stale->{saved} }, 1,
        'and the canonical version overwrites the stale hash';
    is $stale->{saved}[0]{component}, 'certmanager',
        'saved under the same key the gate consults';
    is $stale->{saved}[0]{value}, $canonical,
        'the saved value is the live OCP::Versions value, not the old one';
    like $stale->{out}, qr/Updating cert-manager/,
        'and the printout says it was an update';

    # No record at all -> deployed. The original gate caught this through
    # the !$cm_running branch; the new gate additionally catches stale
    # records, which is what the ticket was about.
    my $fresh = reconcile_cert_manager(
        deployed  => {},
        cm_running => 1,
    );
    is scalar @{ $fresh->{applied_cert} }, 1,
        'no recorded version -> cert-manager is still re-applied';
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

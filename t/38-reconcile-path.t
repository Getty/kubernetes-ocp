#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Cmd::Apply;

#
# `ocp apply` has two paths: a fresh deploy, and a reconcile for a cluster that
# already has a kubeconfig. The health gate was built into the fresh-deploy
# path only, and the reconcile path returned before reaching it — so applying
# over an existing cluster printed component results and exited 0 without ever
# looking at the cluster:
#
#   [ok] Cluster already exists (kubeconfig.yaml found)
#        Checking components...
#     [ok] No drift detected
#     ...
#     1 component(s) updated, 5 checked.
#   <exit 0>
#
# The reconcile path was also missing every step that repairs cluster state it
# does not own. registry.local had been dropped from the Corefile by k3s' addon
# manager, and the "self-healing on the next apply" that ticket #19 assumes
# never happened, because _configure_registry_dns lived only in the deploy
# path. Same for the control-plane OCPNode: a cluster bootstrapped by an older
# OCP kept a CR with no status, so `ocp node ls` showed Pending forever.
#
# The invariant these tests defend: there is ONE health gate, ONE banner and
# ONE exit code, and no path may reach a return without passing them.
#

my $src = path('lib/OCP/Cmd/Apply.pm')->slurp_utf8;
my $drift_src = path('lib/OCP/Cmd/Apply/Drift.pm')->slurp_utf8;
my $health_src = path('lib/OCP/Cmd/Apply/Health.pm')->slurp_utf8;

subtest 'the health gate has exactly one call site' => sub {
    # If _check_cluster_health is called from more than one place, the paths
    # can drift apart again — which is precisely how this bug happened.
    # The call site moved to OCP::Cmd::Apply::Health::finish during the
    # Phase 10 dispatcher extraction, so we grep both files.
    my @calls = ($src . $health_src) =~ /\$self->(_check_cluster_health)\b/g;
    is scalar @calls, 1,
        '_check_cluster_health is invoked from a single place';

    my ($finish) = $health_src =~ /^sub finish \{\n(.*?)\n\}$/ms;
    ok defined $finish, 'finish exists in Health.pm';
    like $finish, qr/_check_cluster_health/,
        'and that place is finish';
    like $finish, qr/_health_is_fatal/, 'finish decides the exit code';
    like $finish, qr/_banner/,          'finish prints the banner';
};

subtest 'both apply paths return through the shared finisher' => sub {
    my ($execute) = $src =~ /^sub execute \{\n(.*?)\n\}$/ms;
    ok defined $execute, 'execute() found';

    my @finishes = $execute =~ /return \$self->(_finish_apply)\b/g;
    is scalar @finishes, 2,
        'execute returns through _finish_apply twice: reconcile and fresh deploy';

    # The reconcile branch specifically — the one that used to slip past.
    my ($branch) = $execute =~ /if \(\$config->cluster_exists\) \{(.*?)\n    \}/ms;
    ok defined $branch, 'cluster_exists branch found';
    like $branch, qr/_reconcile_components/, 'it reconciles components';
    like $branch, qr/return \$self->_finish_apply/,
        'and it returns through the gate instead of returning early';
    unlike $branch, qr/^\s*return\s*;/m,
        'no bare early return that would skip the gate';
};

subtest 'the banner is not printed anywhere but the finisher' => sub {
    my ($reconcile) = $drift_src =~ /^sub reconcile_components \{\n(.*?)\n\}$/ms;
    ok defined $reconcile, 'reconcile_components found in Drift.pm';
    unlike $reconcile, qr/DEPLOYED|_banner/,
        'reconcile does not claim success on its own';
};

#
# What the reconcile path must now actually do.
#

subtest 'reconcile repairs the things it does not own' => sub {
    my ($reconcile) = $drift_src =~ /^sub reconcile_components \{\n(.*?)\n\}$/ms;

    # #19 assumes this heals on the next apply; that is only true if the
    # reconcile path runs it.
    like $reconcile, qr/_configure_registry_dns/,
        'registry.local DNS is reconciled';

    # A pre-existing cluster otherwise keeps an OCPNode with no status.
    like $reconcile, qr/_ensure_cp_ocpnode/, 'control-plane OCPNode is ensured';
    like $reconcile, qr/_ensure_crds/,       'CRDs are ensured';
    like $reconcile, qr/_ensure_providers/,  'provider CRs are ensured';

    like $reconcile, qr/_setup_cilium_gateway/, 'Cilium Gateway is reconciled';
    like $reconcile, qr/_setup_lb_ipam/,        'LB-IPAM is reconciled';
};

subtest 'reconcile stays out of bootstrap and provisioning' => sub {
    my ($reconcile) = $drift_src =~ /^sub reconcile_components \{\n(.*?)\n\}$/ms;

    # Reconcile is the cheap, frequently-run path. Creating servers and
    # waiting on them is a one-time bootstrap step, not convergence.
    unlike $reconcile, qr/_drive_workers|_ensure_worker_ocpnodes/,
        'no worker provisioning';
    unlike $reconcile, qr/install_server|_ensure_robocop/,
        'no control-plane install, no robocop rollout';
    unlike $reconcile, qr/reconcile_until_ready/, 'no long wait loops';
};

#
# The shared finisher itself: one verdict, whoever calls it.
#

package FakeList {
    sub new   { my ($c, $i) = @_; bless { items => $i }, $c }
    sub items { $_[0]{items} }
}
package HealthApi {
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }
    sub list { FakeList->new($_[0]{pods} // []) }
}
package FakeConfig {
    sub new     { bless {}, shift }
    sub name    { 'cortex' }
    sub api_url { "https://$_[1]:6443" }
}

package main;

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

# _stamp_ocp_version writes to the project dir; stub it out.
{
    no warnings 'redefine';
    *OCP::Cmd::Apply::_stamp_ocp_version = sub { 1 };
}

my $healthy_pod = {
    metadata => { name => 'coredns', namespace => 'kube-system' },
    status   => { phase => 'Running',
                  containerStatuses => [{ ready => 1, state => { running => {} } }] },
};
my $broken_pod = {
    metadata => { name => 'coredns', namespace => 'kube-system' },
    status   => { phase => 'Running', containerStatuses => [{
        ready => 0, restartCount => 5,
        state => { waiting => { reason => 'CrashLoopBackOff' } },
    }] },
};

subtest 'the finisher gives the same verdict to whichever path calls it' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';

    # Called the way the fresh-deploy path calls it (with a step number)...
    my ($deploy_out, $deploy_rc) = capture_stdout {
        $apply->_finish_apply(
            config => FakeConfig->new, api => HealthApi->new(pods => [$broken_pod]),
            step => 5, cp_name => 'cortex', cp_ip => '10.230.30.155',
        );
    };

    # ...and the way the reconcile path calls it (without one).
    my ($rec_out, $rec_rc) = capture_stdout {
        $apply->_finish_apply(
            config => FakeConfig->new, api => HealthApi->new(pods => [$broken_pod]),
            cp_name => 'cortex', cp_ip => '10.230.30.155',
        );
    };

    is $deploy_rc, 1, 'fresh deploy exits non-zero over a broken core';
    is $rec_rc,    1, 'reconcile exits non-zero over the same broken core';
    like $deploy_out, qr/NOT HEALTHY/, 'deploy banner says so';
    like $rec_out,    qr/NOT HEALTHY/, 'reconcile banner says the same';
    unlike $rec_out,  qr/SUCCESSFULLY/,
        'reconcile can no longer report success over a crash-looping CoreDNS';

    like $deploy_out, qr/Step 5: Verify cluster health/, 'numbered when given a step';
    like $rec_out,    qr/Verifying cluster health/, 'unnumbered otherwise';
};

subtest 'a healthy cluster still succeeds on both paths' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';
    for my $label ('deploy', 'reconcile') {
        my ($out, $rc) = capture_stdout {
            $apply->_finish_apply(
                config => FakeConfig->new, api => HealthApi->new(pods => [$healthy_pod]),
                cp_name => 'cortex', cp_ip => '10.230.30.155',
                ($label eq 'deploy' ? (step => 5) : ()),
            );
        };
        is $rc, 0, "$label exits 0 on a healthy cluster";
        like $out, qr/SUCCESSFULLY/, "$label prints the success banner";
    }
};

subtest 'a health check that cannot run does not fail the apply' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my $api = bless {}, 'ExplodingApi';
    {
        no strict 'refs';
        no warnings 'once';
        *ExplodingApi::list = sub { die "connection refused\n" };
        *ExplodingApi::k8s  = sub { $_[0] };
    }
    my ($out, $rc) = capture_stdout {
        $apply->_finish_apply(config => FakeConfig->new, api => $api);
    };
    is $rc, 0, 'a broken check is not itself a deploy failure';
    like $out, qr/\[WARN\] could not verify cluster health/, 'and says so';
};

#
# Both paths must address the same control plane, or reconcile would write the
# status of a node that does not exist.
#

package CpConfig {
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub name           { $_[0]{name} }
    sub control_planes { $_[0]{cps} }
}

package main;

subtest 'control-plane identity is one rule, shared by both paths' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';

    my $ssh = $apply->_cp_identity(CpConfig->new(
        name => 'cortex',
        cps  => [{ provider => 'ssh', host => 'cortex.ai.citilan.de' }],
    ));
    is $ssh->{name}, 'cortex', 'ssh cluster is named after the first host label';
    is $ssh->{domain}, 'ai.citilan.de', 'domain split off';
    is $ssh->{provider}, 'ssh', 'provider carried';

    my $bare = $apply->_cp_identity(CpConfig->new(
        name => 'c', cps => [{ provider => 'ssh', host => 'nodots' }],
    ));
    is $bare->{name}, 'nodots', 'host without a dot is used whole';

    my $htz = $apply->_cp_identity(CpConfig->new(
        name => 'prod', cps => [{ provider => 'hetzner' }],
    ));
    is $htz->{name}, 'police1', 'hetzner keeps RoboCop naming';
    is $htz->{hostname}, 'prod-police1', 'hostname prefixed with the cluster name';
};

#
# _configure_registry_dns reports whether it changed anything, which is what
# lets reconcile print "up to date" instead of claiming an update every run.
#

package CoreDnsCm {
    sub new  { my ($c, $d) = @_; bless { data => $d }, $c }
    sub data { $_[0]{data} }
}
package DnsApi {
    sub new  { my ($c, %a) = @_; bless { applied => [], %a }, $c }
    sub get  { $_[0]{cm} }
    sub expand_class { undef }
    sub _request {
        my ($self, $method, $path, $body) = @_;
        push @{$self->{applied}}, $body;
        return DnsResponse->new;
    }
}
package DnsResponse {
    sub new     { bless {}, shift }
    sub status  { 200 }
    sub content { '{}' }
}

package main;

subtest 'registry DNS reconcile is idempotent and reports honestly' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';

    my $corefile = <<'COREFILE';
.:53 {
    errors
    hosts /etc/coredns/NodeHosts {
        ttl 60
        reload 15s
        fallthrough
    }
    forward . /etc/resolv.conf
}
COREFILE

    # First run: the record is missing (k3s reset the Corefile) -> repaired.
    my $api = DnsApi->new(cm => CoreDnsCm->new({ Corefile => $corefile }));
    $apply->{_k8s_api} = $api;
    my ($out, $changed) = capture_stdout {
        $apply->_configure_registry_dns('10.230.30.155');
    };
    ok $changed, 'a Corefile without the record is patched';
    is scalar @{$api->{applied}}, 1, 'one apply issued';
    my $patched = $api->{applied}[0]{data}{Corefile};
    like $patched, qr/10\.230\.30\.155 registry\.local/, 'record added';

    # Second run over the result: nothing to do, nothing claimed.
    my $api2 = DnsApi->new(cm => CoreDnsCm->new({ Corefile => $patched }));
    $apply->{_k8s_api} = $api2;
    my ($out2, $changed2) = capture_stdout {
        $apply->_configure_registry_dns('10.230.30.155');
    };
    ok !$changed2, 'a Corefile that already has the record is left alone';
    is scalar @{$api2->{applied}}, 0, 'no apply issued on the second run';
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use FindBin;
use Path::Tiny qw( path );

use lib 'lib';
use lib 't/lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Kubeconfig;
use OCP::Config;
use OCP::Secrets;
use OCPTest::Cli qw( run_ocp );

#
# k444: `ocp apply` on the reconcile path, when it finds no kubeconfig.yaml,
# printed OCP::Secrets' refusal on STDERR and returned false. The dispatcher
# passes no verdict on a false return, so apply ended with exit 0 and no
# banner, while ocp update, ocp kubeconfig and ocp inject-key die with the
# same refusal and end with exit 1. Decided (hub, 2026-11-07): exit 1 like
# them. The refusal is an error.
#
# The branch is reached when kubeconfig.yaml goes between the dispatcher's
# cluster_exists, which sends apply down the reconcile path, and
# reconcile_components' read of it. Without the file at all, apply takes the
# fresh-deploy path instead. So the file goes the moment read_kubeconfig is
# called -- t/395's race, one call lower, so the dispatcher, its forwarder and
# reconcile_components all run as they are. ocp kubeconfig has the same
# race (cluster_exists, then read_kubeconfig) and dies on it: it is the model.
#
# The claims, for a real run and a dry run, from OCP->run_cli as bin/ocp runs
# it:
#   1. exit 1, as ocp kubeconfig in the same race;
#   2. STDERR is the refusal as the renderer says an error -- "Error: " and
#      OCP::Secrets' words without their own "ERROR:" -- and nothing else:
#      what ocp kubeconfig says in the same race, line for line;
#   3. nothing of it on STDOUT, no Perl source location, no "internal error";
#   4. nothing after it: STDOUT ends with the reconcile path's opening lines,
#      so no drift check and no banner, and no cluster API is built.
# Claims 3 and 4 held before; 1 and 2 are the change.
# Controls: with kubeconfig.yaml left in place the same fixture reads it and
# goes on to the cluster API, stopped there by the test (the race takes the
# file away, nothing else); the modules come from this tree's lib.
#
# Network-free and cluster-free: a dev-mode project in a temp dir, an ssh
# control plane with a .test name, no PIN to ask, STDIN empty; the cluster
# API is never built (a die stands in for it).
#

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};
delete local $ENV{HETZNER_API_TOKEN};

my $OCP_YAML = <<'YAML';
name: k444
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: cp.k444.test
YAML

# The refusal's words, taken from OCP::Secrets: the renderer takes off the
# leading "ERROR: " and the trailing newline and puts "Error: " in front.
my $REFUSAL = OCP::Secrets->no_kubeconfig_refusal;
(my $SAID = $REFUSAL) =~ s/\AERROR: //;
$SAID =~ s/\s+\z//;
my @LINES = map { s/\A\s+//r } split /\n/, $SAID;

my $LOCATION = qr/ at \S+ line \d+/;
my $STOP     = 'k444 stop: the cluster API would be built here';

# A dev-mode project whose cluster is up: ocp.yaml, the age key in .ocp/,
# kubeconfig.yaml encrypted to it, the control plane recorded in
# .ocp/status.yaml.
sub deployed_project {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8($OCP_YAML);
    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    $config->set_status(nodes => [
        { name => 'police1', role => 'control-plane', public_ip => '192.0.2.44' },
    ]);
    $config->save_status;
    return $dir;
}

# In the child: the cluster API is never built. Should a run get that far,
# it stops there with $STOP.
sub stop_at_cluster_api {
    no warnings 'redefine';
    *OCP::Cmd::Apply::_k8s_api = sub { die "$STOP\n" };
}

# In the child: kubeconfig.yaml goes the moment read_kubeconfig is called,
# after cluster_exists saw it; the real read_kubeconfig then finds none.
sub gone_on_read {
    my ($dir) = @_;
    return sub {
        no warnings 'redefine';
        # Loaded above: a reference taken here is the real method.
        my $real = \&OCP::Secrets::read_kubeconfig;
        *OCP::Secrets::read_kubeconfig = sub {
            $dir->child('kubeconfig.yaml')->remove;
            goto &$real;
        };
        stop_at_cluster_api();
    };
}

subtest 'the modules under test come from this tree' => sub {
    my $lib = path("$FindBin::Bin/../lib")->realpath;
    for my $file (qw( OCP.pm OCP/Cmd/Apply.pm OCP/Cmd/Apply/Drift.pm OCP/Secrets.pm )) {
        my $from = path($INC{$file})->realpath;
        ok $lib->subsumes($from), "$file from $lib" or diag "loaded from $from";
    }
};

subtest 'ocp kubeconfig, the same race: exit 1, the refusal as an error (the model)' => sub {
    my $dir = deployed_project();
    my $r = run_ocp($dir, gone_on_read($dir), 'kubeconfig');
    is $r->{signal}, 0, 'no signal';
    ok !-e $dir->child('kubeconfig.yaml'), 'premise: kubeconfig.yaml was gone when it was read';
    is $r->{exit}, 1, 'exit 1';
    is $r->{err}, "Error: $SAID\n", 'STDERR: "Error: " and the refusal\'s words' or diag $r->{err};
    is $r->{out}, '', 'nothing on STDOUT';
};

my $model = do {
    my $dir = deployed_project();
    run_ocp($dir, gone_on_read($dir), 'kubeconfig');
};

for my $dry (0, 1) {
    my @argv = ('apply', $dry ? '--dry-run' : ());
    my $run  = "ocp @argv";

    subtest "$run, kubeconfig.yaml in place: read, then on to the cluster API (the fixture is sound)" => sub {
        my $dir = deployed_project();
        my $r = run_ocp($dir, \&stop_at_cluster_api, @argv);
        is $r->{signal}, 0, 'no signal';
        like $r->{out}, qr/^\[ok\] Cluster already exists \(kubeconfig\.yaml found\)$/m,
            'the reconcile path';
        is $r->{err}, "Error: $STOP\n", 'read it, and stopped where the cluster API is built'
            or diag $r->{err};
        ok -e $dir->child('kubeconfig.yaml'), 'kubeconfig.yaml is still there';
    };

    subtest "$run, kubeconfig.yaml gone when reconcile reads it: exit 1, the refusal as an error" => sub {
        my $dir = deployed_project();
        my $r = run_ocp($dir, gone_on_read($dir), @argv);
        my ($out, $err) = @{$r}{qw( out err )};

        is $r->{signal}, 0, 'no signal';
        like $out, qr/^\[ok\] Cluster already exists \(kubeconfig\.yaml found\)$/m,
            'premise: apply took the reconcile path';
        ok !-e $dir->child('kubeconfig.yaml'), 'premise: kubeconfig.yaml was gone when it was read';

        # 3 and 4: held before the change.
        like $err, qr/\Q$_\E/, "STDERR has the refusal's line: $_" for @LINES;
        unlike $out, qr/\Q$_\E/, "STDOUT has none of it: $_" for @LINES;
        unlike $out, qr/^(?:Error|ERROR):/m, 'STDOUT: no error label';
        unlike $err . $out, $LOCATION, 'no Perl source location';
        unlike $err . $out, qr/internal error/i, 'not called an internal error';
        unlike $err, qr/\Q$STOP\E/, 'no cluster API built';
        like $out, qr/^\[ok\] Cluster already exists \(kubeconfig\.yaml found\)\n     Checking components\.\.\.\n\n\z/m,
            'nothing after it: no drift check, no banner' or diag $out;

        # 1 and 2: the change.
        is $r->{exit}, 1, 'exit 1';
        is $r->{exit}, $model->{exit}, 'the exit code of ocp kubeconfig in the same race';
        is $err, "Error: $SAID\n", 'STDERR: the refusal as the renderer says an error, nothing else'
            or diag $err;
        is $err, $model->{err}, 'STDERR: what ocp kubeconfig says in the same race';
    };
}

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

use OCP::Versions;

use lib 't/lib';
use OCPTest::Rexfile;

#
# Three places answer "which distribution version?" — the installer
# (OCP::Cmd::Apply), the worker join (OCP::Node) and the drift check
# (OCP::Drift). They must agree.
#
# They did not: Apply fell back to '', which makes the Rex task resolve the
# distribution's *stable* channel, while Drift and Node fell back to
# OCP::Versions, which tracks *latest*. A fresh cluster came up on stable and
# was immediately reported as drifted against OCP's own manifest, and workers
# joined one minor ahead of the apiserver.
#

my %source = (
    'lib/OCP/Cmd/Apply/Bootstrap.pm' => qr/\$config->version\s*\n?\s*\|\|\s*OCP::Versions->get_component_version/,
    'lib/OCP/Drift.pm'     => qr/\$config->version\s*\|\|\s*OCP::Versions->get_component_version/,
    'lib/OCP/Node.pm'      => qr/OCP::Versions->get_component_version\(/,
);

for my $file (sort keys %source) {
    my $path = path(__FILE__)->parent->parent->child($file);
    ok -f $path, "$file exists" or next;

    my $src = $path->slurp_utf8;
    like $src, $source{$file},
        "$file resolves the distribution version from OCP::Versions";
}

subtest 'the installer never falls back to an empty version' => sub {
    my $src = path(__FILE__)->parent->parent->child('lib/OCP/Cmd/Apply.pm')->slurp_utf8;

    unlike $src, qr/my \$version = \$config->version \|\| '';/,
        "an empty fallback would silently hand the choice to the stable channel";
};

#
# Same defect, second component: the Rexfile carries CILIUM_VERSION /
# CILIUM_CLI_VERSION constants as a fallback for hand-runs, and those drifted
# behind OCP::Versions. install_cilium ignored the manifest entirely, so a
# freshly bootstrapped cluster came up on the older Cilium and OCP::Drift
# reported it against OCP's own manifest on the very next status call.
#

subtest 'install_cilium is handed the versions from the manifest' => sub {
    my $src = path(__FILE__)->parent->parent->child('lib/OCP/Rex.pm')->slurp_utf8;

    like $src, qr/run_task\(\s*'install_cilium'.*?get_component_version\('cilium'\)/s,
        'the Cilium version comes from OCP::Versions';
    like $src, qr/run_task\(\s*'install_cilium'.*?get_component_version\('cilium_cli'\)/s,
        'the Cilium CLI version comes from OCP::Versions';
    like $src, qr/run_task\(\s*'install_cilium'.*?distribution\s*=>/s,
        'the distribution is passed too — it decides the kubectl path for k3s';
};

subtest 'the Rexfile reads Cilium versions from task_params, not from constants' => sub {
    my $rexfile = path(__FILE__)->parent->parent->child('share/Rexfile');
    plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

    my $src = $rexfile->slurp_utf8;

    # ADR 0014: every pin lives in OCP::Versions exactly once. The Rexfile
    # used to carry CILIUM_VERSION / CILIUM_CLI_VERSION / GATEWAY_API_VERSION
    # constants as a hand-run fallback, and they drifted behind the manifest.
    my @cst = $src =~ /^\s*use constant \s+ (CILIUM|CILIUM_CLI|GATEWAY_API)_VERSION \b/gmx;
    is_deeply \@cst, [],
        'no Cilium version constants remain in the Rexfile (every pin lives in OCP::Versions)'
        or diag "Constants still present: @cst";

    like $src, qr/my \$version = \$params->\{version\} \/\/ \$ENV\{OCP_CILIUM_VERSION\}/,
        'install_cilium takes Cilium from task_params, with an ENV fallback for hand-runs';
    like $src, qr/my \$cli_version = \$params->\{cli_version\} \/\/ \$ENV\{OCP_CILIUM_CLI_VERSION\}/,
        'the Cilium CLI version has the same shape';
    unlike $src, qr/run 'cilium install --version ' \. CILIUM_VERSION/,
        'the install command no longer hardcodes any constant';
};

#
# Gateway API is version-locked to Cilium and was pinned at v1.2.0 in the
# Rexfile while Cilium moved to 1.20, which requires the v1.6.1 bundle. The
# mismatch is silent in the install log: the CRDs apply fine, then the Cilium
# operator refuses to start its Gateway controller and every Gateway sits at
# Accepted=Unknown.
#

subtest 'Gateway API travels with Cilium' => sub {
    my $gw = OCP::Versions->get_component_version('gateway_api');
    ok defined $gw && length $gw, "gateway_api is pinned in the manifest ($gw)";
    like $gw, qr/^v\d+\.\d+\.\d+$/, 'looks like a Gateway API release tag';

    my $src = path(__FILE__)->parent->parent->child('lib/OCP/Rex.pm')->slurp_utf8;
    like $src, qr/gateway_api_version.*?get_component_version\('gateway_api'\)/s,
        'the version is passed to install_cilium from the manifest';

    my $rexfile = path(__FILE__)->parent->parent->child('share/Rexfile');
    return unless -f $rexfile;
    my $rex = $rexfile->slurp_utf8;

    unlike $rex, qr{gateway-api/releases/download/v\d+\.\d+\.\d+/},
        'the CRD URLs no longer hardcode a version';
    # Since k155 install_cilium hands it to Rex::Rancher::Cilium, which builds
    # the bundle URL from it (t/90, t/155); since Rex::Rancher 0.003
    # update_gateway_api does the same through ensure_gateway_api_crds -- held
    # by what the task hands the library in t/93-update-gateway-api.t.
    like $rex, qr/gateway_api_version\s*=>\s*\$gateway_api_version/s,
        'install_cilium hands the passed version to the CRD apply';
    # One channel only, standard -- since Gateway API v1.5 it carries the
    # TLSRoute v1 Cilium 1.20 requires, and experimental over standard is
    # refused by the bundle's safe-upgrades policy. See t/90 (k157).
};

subtest 'every bundled ingress controller is disabled' => sub {
    # RKE2 v1.36 added Traefik; its helm-install job crashes on a
    # Cilium-owned cluster and leaves two pods in CrashLoopBackOff. Since k155
    # the list is Rex::Rancher::Server's default for rke2 (held against the
    # real library in t/155-rex-libraries.t); OCP must leave that default in
    # charge rather than hand over a list of its own.
    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_rke2_server', { token => 't' });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    ok $o && !exists $o->{disable}, 'install_rke2_server leaves the disable list to the library default';
};

subtest 'the manifest actually carries a version per distribution' => sub {
    for my $dist (qw( rke2 k3s )) {
        my $v = OCP::Versions->get_component_version($dist);
        ok defined $v && length $v, "$dist has a pinned version ($v)";
        like $v, qr/^v\d+\.\d+\.\d+\+/, "$dist version looks like a release tag";
    }
};

#
# The port an agent registers on is not the apiserver port. RKE2 listens for
# joins on 9345, k3s serves joins and API from 6443. Both call sites hardcoded
# 9345, so a k3s worker was always pointed at a port nothing listens on, and
# the closing banner of `ocp apply` advertised the join port as the API
# endpoint.
#

subtest 'the join URL follows the distribution' => sub {
    require File::Temp;
    require OCP;
    require OCP::Config;

    my $tmpdir = File::Temp::tempdir(CLEANUP => 1);
    my $ocp    = OCP->new;

    my %port = (rke2 => 9345, k3s => 6443);

    for my $dist (qw( rke2 k3s )) {
        my $file = path($tmpdir)->child("$dist.yaml");
        $ocp->dump_file($file->stringify, {
            name       => 't',
            kubernetes => { dist => $dist },
        });

        my $config = OCP::Config->new(file => $file->stringify, ocp => $ocp);

        is $config->supervisor_port, $port{$dist},
            "$dist agents register on $port{$dist}";
        is $config->join_url('cp-1'), "https://cp-1:$port{$dist}",
            "$dist join URL";
        is $config->api_url('cp-1'), 'https://cp-1:6443',
            "$dist apiserver is on 6443 either way";
    }
};

subtest 'no call site hardcodes the join port any more' => sub {
    my $root = path(__FILE__)->parent->parent;

    for my $file (qw( lib/OCP/Cmd/Apply.pm lib/OCP/Cmd/Node/Add.pm )) {
        my $src = $root->child($file)->slurp_utf8;
        unlike $src, qr{"https://\$cp_ip:9345"},
            "$file asks OCP::Config for the join URL";
    }
};

done_testing;

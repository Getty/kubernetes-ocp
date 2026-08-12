#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

use OCP::Versions;

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
    'lib/OCP/Cmd/Apply.pm' => qr/\$config->version\s*\n?\s*\|\|\s*OCP::Versions->get_component_version/,
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

subtest 'the Rexfile treats its Cilium constants as fallbacks' => sub {
    my $rexfile = path(__FILE__)->parent->parent->child('share/Rexfile');
    plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

    my $src = $rexfile->slurp_utf8;

    like $src, qr/my \$cilium_version_target = \$params->\{version\} \|\| CILIUM_VERSION;/,
        'install_cilium prefers the passed version';
    like $src, qr/my \$cli_version = \$params->\{cli_version\} \|\| CILIUM_CLI_VERSION;/,
        'install_cilium prefers the passed CLI version';
    unlike $src, qr/run 'cilium install --version ' \. CILIUM_VERSION/,
        'the install command no longer hardcodes the constant';
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
    like $rex, qr/\$gateway_api_version.*standard-install\.yaml/,
        'standard channel uses the passed version';
    like $rex, qr/\$gateway_api_version.*experimental-install\.yaml/,
        'experimental channel too — TLSRoute only exists there, and Cilium requires it';
};

subtest 'every bundled ingress controller is disabled' => sub {
    my $rexfile = path(__FILE__)->parent->parent->child('share/Rexfile');
    plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

    my $rex = $rexfile->slurp_utf8;

    # RKE2 v1.36 added Traefik; its helm-install job crashes on a
    # Cilium-owned cluster and leaves two pods in CrashLoopBackOff.
    for my $chart (qw( rke2-ingress-nginx rke2-traefik rke2-traefik-crd )) {
        like $rex, qr/^\s*\Q$chart\E$/m, "$chart is disabled in the RKE2 config";
    }
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

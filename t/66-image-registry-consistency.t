#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# karr #41, following on from #10: for months the robocop manifests pointed
# at ghcr.io/getty/ocp while the (now-deleted) CI publish workflow pushed
# raudssus/ocp, and nothing ever compared the two -- the mismatch was only
# visible once someone actually pulled the image. #10 fixed the drift and
# consolidated everything on raudssus/ocp; this file is the missing
# comparison that would have caught it, kept alive as a standing guard.
#
# There is no CI publish workflow any more (.github/workflows/docker-publish.yml
# was deleted along with CI auto-publish -- see #10's history and the #41
# addendum). The place that now actually builds and pushes the image is
# share/bin/ocp-build-image, and the name every other Make target defers to
# is the Makefile's IMAGE variable. So the comparison this file makes is:
# every image reference under share/ agrees with the Makefile's IMAGE
# variable, and with ocp-build-image's own default.
#
# Two code-side carriers of the same string get the same treatment, per
# maintainer decision on #41: OCP::Cmd::DeployImage's $DEFAULT_REPO (what
# `ocp deploy-image` rolls onto the cluster when nobody overrides --repo)
# and xt/smoke.sh's default IMAGE. Both would drift silently the same way
# the manifests did in #10 -- they're read once at the top of their files
# and nothing else in the codebase would notice a registry rename.
#
# README.md deliberately stays OUT of this comparison. Its prose gets
# reworded/restructured for reasons that have nothing to do with the image
# repo (examples, quoting style, alias suggestions), and a guard that fires
# on every unrelated doc edit trains people to ignore it. If the repo ever
# moves, README.md needs a manual pass regardless of what this test says.
#
# What this deliberately does NOT check: an architecture guard. The image is
# built for the architecture of the machine that builds it, so there is no
# platform list here for a guard to compare against. #41 originally proposed
# one aimed at the CI workflow, which no longer exists, and robocop has been
# pinned to the (always-amd64) control-plane node via nodeSelector/toleration
# since #10 (commit 03dec2e). See karr #41's addendum for the maintainer's
# call on this.
#

my $root = path(__FILE__)->parent->parent->absolute;

my $deployment   = $root->child('share/robocop/deployment.yaml');
my $dev_overlay  = $root->child('share/robocop/overlays/dev/kustomization.yaml');
my $makefile     = $root->child('Makefile');
my $build_image  = $root->child('share/bin/ocp-build-image');
my $deploy_image = $root->child('lib/OCP/Cmd/DeployImage.pm');
my $smoke        = $root->child('xt/smoke.sh');

plan skip_all => 'share/robocop or Makefile not found'
    unless -f $deployment && -f $dev_overlay && -f $makefile;

# repo, no tag: "raudssus/ocp:latest" -> "raudssus/ocp"
sub _repo_only {
    my $ref = shift;
    $ref =~ s/:[^:\/]+$//;
    return $ref;
}

my ($deployment_image) = $deployment->slurp_utf8 =~ /^\s*image:\s*(\S+)\s*$/m;
ok defined $deployment_image, 'share/robocop/deployment.yaml has an image: line'
    or diag 'could not find "image: <ref>" in share/robocop/deployment.yaml';
my $deployment_repo = defined($deployment_image) ? _repo_only($deployment_image) : undef;

# The dev overlay doesn't set the image it runs -- it rewrites it, via
# kustomize's `images:` transformer, to a local registry placeholder
# (REGISTRY_HOST_PLACEHOLDER/ocp) for local iteration. That transformer
# matches by the `name:` field, which therefore has to equal the base
# Deployment's image repo, or it silently no-ops: kustomize does not error
# on an unmatched image name, it just leaves the base image alone, and the
# dev overlay quietly deploys the public raudssus/ocp image instead of the
# local one. That silent-no-op failure mode is exactly the shape of bug #10
# was about, just in the opposite direction (dev tooling instead of prod).
my ($overlay_match_name) = $dev_overlay->slurp_utf8
    =~ /^images:\s*\n-\s*name:\s*(\S+)\s*$/m;
ok defined $overlay_match_name,
    'share/robocop/overlays/dev/kustomization.yaml has an images: transformer with a name:'
    or diag 'could not find "images:\n- name: <ref>" in the dev overlay kustomization';

my ($makefile_image) = $makefile->slurp_utf8 =~ /^IMAGE\s*\?=\s*(\S+)\s*$/m;
ok defined $makefile_image, 'Makefile defines IMAGE ?= <repo>'
    or diag 'could not find "IMAGE ?= <repo>" in the Makefile';

my $build_image_repo;
if (-f $build_image) {
    ($build_image_repo) = $build_image->slurp_utf8
        =~ /REPO="\$\{OCP_IMAGE_REPO:-([^}]+)\}"/;
    ok defined $build_image_repo,
        'share/bin/ocp-build-image defines a default REPO'
        or diag 'could not find REPO="${OCP_IMAGE_REPO:-<repo>}" in share/bin/ocp-build-image';
} else {
    fail 'share/bin/ocp-build-image not found -- image-building script moved?';
}

my $deploy_image_repo;
if (-f $deploy_image) {
    ($deploy_image_repo) = $deploy_image->slurp_utf8
        =~ /^our\s+\$DEFAULT_REPO\s*=\s*'([^']+)'/m;
    ok defined $deploy_image_repo,
        'OCP::Cmd::DeployImage defines $DEFAULT_REPO'
        or diag q{could not find "our $DEFAULT_REPO = '<repo>'" in lib/OCP/Cmd/DeployImage.pm};
} else {
    fail 'lib/OCP/Cmd/DeployImage.pm not found -- deploy-image command moved?';
}

my $smoke_repo;
if (-f $smoke) {
    my ($smoke_image) = $smoke->slurp_utf8
        =~ /IMAGE="\$\{SMOKE_IMAGE:-([^}]+)\}"/;
    ok defined $smoke_image, 'xt/smoke.sh defines a default IMAGE'
        or diag 'could not find IMAGE="${SMOKE_IMAGE:-<ref>}" in xt/smoke.sh';
    $smoke_repo = defined($smoke_image) ? _repo_only($smoke_image) : undef;
} else {
    fail 'xt/smoke.sh not found -- smoke harness moved?';
}

subtest 'every image reference under share/, the Makefile, and the two code-side defaults agrees on one repo' => sub {
    plan skip_all => 'one or more image references could not be extracted -- see failures above'
        unless defined $deployment_repo
            && defined $overlay_match_name
            && defined $makefile_image
            && defined $build_image_repo
            && defined $deploy_image_repo
            && defined $smoke_repo;

    is $deployment_repo, $makefile_image,
        'share/robocop/deployment.yaml image repo matches the Makefile IMAGE variable'
        or diag "deployment.yaml: $deployment_repo vs Makefile IMAGE: $makefile_image -- "
               . 'karr #41/#10: these drifting apart is exactly the bug #10 fixed.';

    is $overlay_match_name, $makefile_image,
        'the dev overlay images: transformer name: matches the Makefile IMAGE variable '
        . '(otherwise the transformer silently fails to match and the dev overlay '
        . 'deploys the public image instead of the local one)'
        or diag "dev overlay images.name: $overlay_match_name vs Makefile IMAGE: $makefile_image";

    is $build_image_repo, $makefile_image,
        'share/bin/ocp-build-image default REPO matches the Makefile IMAGE variable '
        . '(this is the script that actually builds and pushes the image)'
        or diag "ocp-build-image REPO: $build_image_repo vs Makefile IMAGE: $makefile_image";

    is $deploy_image_repo, $makefile_image,
        'OCP::Cmd::DeployImage $DEFAULT_REPO matches the Makefile IMAGE variable '
        . '(what `ocp deploy-image` rolls out when nobody passes --repo)'
        or diag "DeployImage.pm \$DEFAULT_REPO: $deploy_image_repo vs Makefile IMAGE: $makefile_image";

    is $smoke_repo, $makefile_image,
        'xt/smoke.sh default IMAGE repo matches the Makefile IMAGE variable'
        or diag "smoke.sh IMAGE: $smoke_repo vs Makefile IMAGE: $makefile_image";
};

done_testing;

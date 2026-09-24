#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

use lib 't/lib';
use OCPTest::Rexfile;

#
# Every artifact OCP has downloaded by hand onto a node is named after the
# node's architecture. The RKE2 install task once did not know that: it asked
# for rke2.linux-amd64.tar.gz on every host, so bootstrapping an aarch64
# machine (a DGX Spark) got a 404 from GitHub, a zero-byte tarball, and a
# "download failed" that named the size but never the reason.
#
# Since k155 the downloads are Rex::Rancher's: the RKE2 release tarball (with
# install_method artifact, checksum-verified) and the Cilium CLI, both named by
# the node's GOARCH. That mapping is held against the real library in
# t/155-rex-libraries.t. Here: the RKE2 server install still takes the
# artifact path, which is the one that downloads for the node, and the Rexfile
# carries no amd64 literal of its own.
#

my $root = path(__FILE__)->parent->parent;
(my $code = OCPTest::Rexfile->rexfile->slurp_utf8) =~ s/^\s*#.*\n//mg;

subtest 'no amd64 literal is left in the Rexfile' => sub {
    unlike $code, qr/amd64/, 'no hardcoded amd64 anywhere';
    unlike $code, qr/cilium-linux-|rke2\.linux-/, 'no artifact names of its own';
};

subtest 'a pinned RKE2 server installs from the release artifact for the node' => sub {
    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_rke2_server', { token => 't', version => 'v1.36.4+rke2r1' });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    is $o->{install_method}, 'artifact', 'artifact: downloaded on the node, for its uname -m';
    is $o->{version}, 'v1.36.4+rke2r1', 'with the pinned version it needs';

    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task('install_rke2_server', { token => 't' });
    $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    is $o->{install_method}, 'script', 'no pin (a hand-run): the install script, latest stable';
};

#
# A DGX Spark arrives with a vendor driver matched to its kernel and its
# silicon. install_nvidia once ran apt at it unconditionally, which on Ubuntu
# meant pulling nvidia-driver-535 over a working Blackwell driver. On Ubuntu
# the check is OCP's own (rex-gpu k69); elsewhere Rex::GPU's install_driver
# makes the same check (nvidia-smi lists a GPU and libcuda is in the linker
# cache) before it installs anything.
#
subtest 'an existing working driver is respected, not overwritten (Ubuntu)' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::OS = 'Ubuntu';
    local $OCPTest::Rexfile::RUN = sub {
        my ($cmd) = @_;
        return ("GPU 0: NVIDIA GB10 (UUID: GPU-1)\n", 0) if $cmd =~ /^nvidia-smi -L/;
        return ("\tlibcuda.so (libc6,AArch64) => /usr/lib/aarch64-linux-gnu/libcuda.so\n", 0)
            if $cmd =~ /libcuda/;
        return ('', 0);
    };
    my $out = OCPTest::Rexfile->run_task('install_nvidia');
    like $out, qr/skipping driver install/i, 'says so instead of silently doing nothing';
    ok !(grep { /ubuntu-drivers install/ } OCPTest::Rexfile->commands), 'no ubuntu-drivers install';
    is scalar(OCPTest::Rexfile->calls('pkg')), 0, 'no package installed';
    is scalar(OCPTest::Rexfile->calls('Rex::GPU::NVIDIA::install_driver')), 0,
        'and Rex::GPU\'s driver install is not asked either';
};

subtest 'the image ships a kubectl that runs on the image' => sub {
    my $dockerfile = $root->child('Dockerfile');
    plan skip_all => 'Dockerfile not found' unless -f $dockerfile;

    my $df = $dockerfile->slurp_utf8;

    unlike $df, qr{release/bin/linux/amd64/kubectl|/bin/linux/amd64/kubectl},
        'the kubectl download is not pinned to amd64';
    like $df, qr/dpkg --print-architecture/,
        'it resolves the architecture of the image being built';
};

done_testing;

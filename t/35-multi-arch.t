#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# Every artifact OCP downloads by hand onto a node is named after the node's
# architecture. The RKE2 install task did not know that: it asked for
# rke2.linux-amd64.tar.gz on every host, so bootstrapping an aarch64 machine
# (a DGX Spark) got a 404 from GitHub, a zero-byte tarball, and a "download
# failed" that named the size but never the reason.
#
# The mapping already existed — twice, inlined in the two Cilium tasks. This
# suite pins the single helper they now share, and keeps the amd64 literals
# from growing back.
#

my $root    = path(__FILE__)->parent->parent;
my $rexfile = $root->child('share/Rexfile');

plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

my $src = $rexfile->slurp_utf8;

#
# The helper itself, executed rather than pattern-matched: extract the sub out
# of the Rexfile and run it against a stubbed `uname -m`. The Rexfile cannot be
# loaded whole (it is a Rex script, not a module), but this one sub is
# self-contained and its mapping is the whole point.
#
my ($node_arch_src) = $src =~ /^(sub _node_arch \{.*?^\})/ms;

ok $node_arch_src, 'share/Rexfile defines a _node_arch helper';

my $uname_output;
{
    no strict 'refs';
    # Predeclare before the eval so `run "uname -m"` compiles as a call.
    *{'RexArchProbe::run'} = sub { return $uname_output };
}
eval "package RexArchProbe; $node_arch_src; 1"
    or die "could not load _node_arch out of the Rexfile: $@";

sub node_arch_for {
    $uname_output = shift;
    return RexArchProbe::_node_arch();
}

subtest 'uname -m maps to the Go architecture the release artifacts use' => sub {
    is node_arch_for("x86_64\n"),  'amd64', 'x86_64 is amd64';
    is node_arch_for("aarch64\n"), 'arm64', 'aarch64 is arm64 — the DGX Spark case';
    is node_arch_for("arm64\n"),   'arm64', 'arm64 passes through';
    is node_arch_for("amd64\n"),   'amd64', 'amd64 passes through';

    is node_arch_for("x86_64"), 'amd64',
        'a missing trailing newline is not a different architecture';

    is node_arch_for("riscv64\n"), 'riscv64',
        'an unmapped machine keeps its own name so the failing URL names it';
};

subtest 'the RKE2 install downloads for the node, not for amd64' => sub {
    my ($task) = $src =~ /task "install_rke2_server", sub \{(.*?)\n\};/s;
    ok $task, 'found the install_rke2_server task';

    like $task, qr/my \$arch = _node_arch\(\);/,
        'the task asks the node for its architecture';
    like $task, qr/my \$tarball_name\s*=\s*"rke2\.linux-\$arch\.tar\.gz";/,
        'the tarball name carries that architecture';
    like $task, qr/my \$checksum_name\s*=\s*"sha256sum-\$arch\.txt";/,
        'so does the checksum file';

    unlike $task, qr/rke2\.linux-amd64\.tar\.gz/,
        'no hardcoded amd64 tarball is left';
    unlike $task, qr/sha256sum-amd64\.txt/,
        'no hardcoded amd64 checksum is left';

    # The size check and the INSTALL_RKE2_ARTIFACT_PATH handoff read the same
    # file the download wrote. A stale amd64 path there is a silent 0 bytes.
    like $task, qr/wc -c < \/tmp\/rke2-artifacts\/\$tarball_name/,
        'the size check inspects the file that was actually downloaded';
};

subtest 'the Cilium tasks share the helper instead of re-inlining it' => sub {
    my $inlined = () = $src =~ /\$arch_raw eq 'x86_64'/g;
    is $inlined, 0, 'the ternary chain is gone from both Cilium tasks';

    my $uses = () = $src =~ /_node_arch\(\)/g;
    cmp_ok $uses, '>=', 3,
        'RKE2 plus both Cilium tasks resolve the architecture through the helper';

    like $src, qr{cilium-\$os-\$arch\.tar\.gz},
        'the Cilium CLI URL still interpolates the detected architecture';
};

#
# A DGX Spark arrives with a vendor driver matched to its kernel and its
# silicon. install_nvidia used to run apt at it unconditionally, which on
# Ubuntu meant pulling nvidia-driver-535 over a working Blackwell driver.
#
subtest 'an existing working driver is respected, not overwritten' => sub {
    my ($task) = $src =~ /task "install_nvidia", sub \{(.*?)\n\};/s;
    ok $task, 'found the install_nvidia task';

    like $task, qr/if \(_nvidia_driver_present\(\)\)/,
        'the driver install is guarded by a check for an existing driver';
    like $task, qr/skipping driver install/i,
        'and says so instead of silently doing nothing';

    like $src, qr/sub _nvidia_driver_present \{/,
        'the check exists';

    my ($check) = $src =~ /^(sub _nvidia_driver_present \{.*?^\})/ms;
    like $check, qr/nvidia-smi/,
        'it asks nvidia-smi, not the package database — vendor drivers are not packaged';
    like $check, qr/libcuda\.so/,
        'and requires libcuda, which is what the container runtime consumes';
};

subtest 'the Debian kernel headers meta-package follows the host' => sub {
    unlike $src, qr/"linux-headers-amd64"/,
        'no hardcoded amd64 headers meta-package';
    like $src, qr/dpkg --print-architecture/,
        'the Debian architecture comes from dpkg';
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

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use version;

use OCP::Versions;

#
# karr #25 (protection ticket, not a bugfix): GB10/DGX Spark (Grace Blackwell)
# has a Unified Memory Architecture -- CPU and GPU share the 128 GB LPDDR5x
# pool, there is no dedicated framebuffer, and nvmlDeviceGetMemoryInfo answers
# "Not Supported". device-plugin builds before v0.17.4 treat that answer as
# fatal:
#
#   error building GPU device map: error visiting device: error getting info
#   for GPU 0: error getting memory info for device 0: Not Supported
#
# The pod crashes, the node registers 0 GPUs, and nothing about that looks
# like a version problem from the outside -- the GPU is healthy and the
# driver is fine. Upstream fixed this in k8s-device-plugin v0.17.4 (elezar,
# NVIDIA, in NVIDIA/gpu-operator#1794, 2025-10-22): the error is logged and
# ignored, the device is registered anyway.
#
# OCP pins nvidia_device_plugin => v0.19.3 today, which is correct and has
# been verified on real GB10 hardware (nvidia-device-plugin-daemonset
# Running, 0 restarts, nvidia.com/gpu: 1 in Capacity). This file exists so a
# routine-looking downgrade of that pin -- e.g. "pin everything to what the
# older gpu-operator bundles" -- fails loudly instead of silently shipping a
# device plugin that zeroes out every GB10 node's GPU count.
#
# The comparison below is real version arithmetic (version->parse), not
# string comparison. That distinction is the point of the first subtest:
# '0.9.0' sorts *after* '0.17.4' lexically (the character '9' is greater
# than '1'), which would make a naive `gt` on the bare strings say a
# dangerously old pin passes the floor.
#

my $MIN_DEVICE_PLUGIN = 'v0.17.4';

sub _ver_ge {
    my ($a, $b) = @_;
    s/^v//i for $a, $b;
    return version->parse("v$a") >= version->parse("v$b");
}

subtest 'the comparison helper does real version arithmetic, not string compare' => sub {
    ok !_ver_ge('0.9.0', '0.17.4'),
        '0.9.0 is NOT >= 0.17.4 (a string compare would get this backwards: "9" gt "1")';
    ok _ver_ge('0.17.4', '0.17.4'), '0.17.4 >= 0.17.4 (the floor itself passes)';
    ok _ver_ge('0.19.3', '0.17.4'), '0.19.3 >= 0.17.4 (todays pin passes)';
    ok _ver_ge('1.0.0', '0.17.4'),  '1.0.0 >= 0.17.4 (sanity: a major bump still passes)';
};

subtest 'nvidia_device_plugin pin stays >= v0.17.4 (karr #25, GB10/DGX Spark UMA)' => sub {
    my $pin = OCP::Versions->get_component_version('nvidia_device_plugin');
    ok defined $pin && length $pin, 'nvidia_device_plugin is pinned in OCP::Versions'
        or diag 'nvidia_device_plugin has no pin at all -- see karr #25 before adding one below v0.17.4';

    ok _ver_ge($pin, $MIN_DEVICE_PLUGIN), "nvidia_device_plugin ($pin) >= $MIN_DEVICE_PLUGIN"
        or diag <<"DIAG";
karr #25: nvidia_device_plugin dropped below v0.17.4 (currently: $pin).

GB10/DGX Spark has Unified Memory -- there is no dedicated framebuffer, so
nvmlDeviceGetMemoryInfo answers "Not Supported". device-plugin builds before
v0.17.4 treat that as fatal: the pod crashes and the node silently reports 0
GPUs even though the GPU is healthy. Upstream fixed this in v0.17.4
(NVIDIA/gpu-operator#1794). Do not pin nvidia_device_plugin below v0.17.4 in
lib/OCP/Versions.pm.
DIAG
};

subtest 'every OCP release that pins nvidia_device_plugin stays >= the floor' => sub {
    # Guards the invariant across future OCP releases too, not just the
    # current one -- a new '0.2.0' block that forgets to carry the pin
    # forward (or copies an older gpu-operator's bundle) would otherwise
    # slip past the subtest above once the default OCP version moves on.
    my @with_pin = grep {
        exists $OCP::Versions::VERSIONS->{$_}{components}{nvidia_device_plugin}
    } sort keys %$OCP::Versions::VERSIONS;

    ok scalar(@with_pin) >= 1, 'at least one OCP release pins nvidia_device_plugin';

    for my $ocp_version (@with_pin) {
        my $pin = $OCP::Versions::VERSIONS->{$ocp_version}{components}{nvidia_device_plugin};
        ok _ver_ge($pin, $MIN_DEVICE_PLUGIN),
            "OCP $ocp_version: nvidia_device_plugin ($pin) >= $MIN_DEVICE_PLUGIN"
            or diag "karr #25: OCP $ocp_version pins nvidia_device_plugin $pin, "
                   . "below the GB10/DGX Spark UMA floor of $MIN_DEVICE_PLUGIN "
                   . "-- see karr #25 for why that silently zeroes GPU counts.";
    }
};

subtest 'the DRA driver has the same UMA bug and is still unfixed upstream -- OCP must not pin it' => sub {
    # kubernetes-sigs/dra-driver-nvidia-gpu#1115 (2026-05): same "Not
    # Supported" crash, still open. OCP does not use the DRA driver. If a
    # component matching this name ever shows up in OCP::Versions it needs
    # the same floor-or-avoid treatment as nvidia_device_plugin above, not
    # a blind pin -- see karr #25.
    my @components = OCP::Versions->list_components();
    ok !(grep { /dra.?driver/i } @components),
        'no dra-driver-nvidia-gpu (or similarly named) component is pinned in OCP::Versions';
};

done_testing;

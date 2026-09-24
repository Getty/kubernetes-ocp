#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

use lib 't/lib';
use OCPTest::Rexfile;

#
# GPU detection used to ask `lspci -nn` for a name and match it against a list
# of known-good marketing names (RTX, GTX 16xx, Tesla, Quadro). The name comes
# out of the host's pci.ids database, so on hardware newer than that database
# lspci prints `Device [10de:2e12]` and the list cannot match anything — which
# is what a DGX Spark (GB10) did: `[skip] Unknown NVIDIA GPU`, no driver, while
# NFD on the same node labelled it feature.node.kubernetes.io/pci-0300_10de
# without difficulty. Vendor + PCI class come from the kernel, need no database
# and no pciutils, and are the same evidence NFD uses.
#
# Detection stays OCP's own since k155 (Rex::GPU's detection uses lspci); the
# driver and toolkit install go through Rex::GPU::NVIDIA, which OCP hands the
# GPUs it found (rex-gpu k42). The Rexfile runs against recorders
# (t/lib/OCPTest/Rexfile.pm).
#

my $src = OCPTest::Rexfile->rexfile->slurp_utf8;

# The comments explain what the old code did wrong and name the packages it
# named — assertions about what must not come back have to look at the code.
my $code = join '', grep { !/^\s*#/ } split /^/, $src;

my $sysfs_output;   # what the stubbed `run` returns
$OCPTest::Rexfile::RUN = sub { return ($sysfs_output, 0) };

my $pci_display_devices = OCPTest::Rexfile->helper('_pci_display_devices');
my $gpu_action          = OCPTest::Rexfile->helper('_gpu_action');
my $maybe_detect_gpu    = OCPTest::Rexfile->helper('_maybe_detect_gpu');

sub devices_for {
    $sysfs_output = shift;
    return [ $pci_display_devices->() ];
}

sub detect_tasks_after {
    my ($params) = @_;
    OCPTest::Rexfile->reset;
    { local *STDOUT; open STDOUT, '>', \my $sink; $maybe_detect_gpu->($params); }
    return [ map { $_->{args}[0] } OCPTest::Rexfile->calls('do_task') ];
}

#
# What the kernel actually exposes: /sys/bus/pci/devices/<slot>/{vendor,device,class}
# hold 0x-prefixed hex, and class is six digits — class, subclass, programming
# interface. NFD's label uses the first four.
#

subtest 'the GB10 that the whitelist could not name is found by vendor and class' => sub {
    my $devices = devices_for(<<'SYSFS');
/sys/bus/pci/devices/000f:01:00.0|0x10de|0x2e12|0x030000
SYSFS

    is scalar @$devices, 1, 'one display device';
    is $devices->[0]{vendor}, '10de', 'NVIDIA, from the hardware and not from pci.ids';
    is $devices->[0]{device}, '2e12', 'GB10';
    is $devices->[0]{class},  '0300', 'VGA controller — the class NFD labels as pci-0300_10de';
    is $devices->[0]{slot},   '000f:01:00.0', 'the slot keeps its domain';

    is $gpu_action->(@$devices), 'nvidia',
        'and it gets a driver, with nobody asking what the card is called';
};

subtest 'only display and 3D controllers count' => sub {
    my $devices = devices_for(<<'SYSFS');
/sys/bus/pci/devices/0000:00:00.0|0x8086|0x1234|0x060000
/sys/bus/pci/devices/0000:01:00.0|0x10de|0x2330|0x030200
/sys/bus/pci/devices/0000:01:00.1|0x10de|0x22ba|0x040300
/sys/bus/pci/devices/0000:02:00.0|0x10de|0x1eb8|0x030100
SYSFS

    is_deeply [ map { $_->{class} } @$devices ], ['0302'],
        'the host bridge, the GPU audio function and the XGA class are all left out';
    is $devices->[0]{device}, '2330', 'an H100 registers as a 3D controller';
};

subtest 'a broken or missing sysfs entry is skipped, not fatal' => sub {
    my $devices = devices_for(<<'SYSFS');
/sys/bus/pci/devices/0000:01:00.0||0x2e12|0x030000
/sys/bus/pci/devices/0000:02:00.0|0x10de|0x2e12|
/sys/bus/pci/devices/0000:03:00.0|0x10de|0x2e12|0x030000
SYSFS

    is scalar @$devices, 1, 'only the complete entry survives';
    is $devices->[0]{slot}, '0000:03:00.0', 'and it is the right one';

    is_deeply devices_for(''),    [], 'no devices at all is not an error';
    $sysfs_output = undef;
    is_deeply [ $pci_display_devices->() ], [],
        'neither is a command that produced nothing';
};

#
# The virtual-GPU blacklist stays: a short list of "definitely not" keeps
# working as hardware moves on, which is exactly what the whitelist did not.
#

subtest 'virtual display adapters still need no host driver' => sub {
    for my $vendor (qw(1af4 1b36 15ad 80ee)) {
        my $devices = devices_for("/sys/bus/pci/devices/0000:00:02.0|0x$vendor|0x1050|0x030000\n");
        is $gpu_action->(@$devices), 'virtual', "vendor $vendor is virtual";
    }
};

subtest 'a passed-through GPU beats the virtio adapter next to it' => sub {
    my $devices = devices_for(<<'SYSFS');
/sys/bus/pci/devices/0000:00:02.0|0x1af4|0x1050|0x030000
/sys/bus/pci/devices/0000:06:00.0|0x10de|0x20b5|0x030200
SYSFS

    is $gpu_action->(@$devices), 'nvidia',
        'the VM display adapter does not veto the card that is actually there';
};

subtest 'the other outcomes' => sub {
    my $amd = devices_for("/sys/bus/pci/devices/0000:03:00.0|0x1002|0x744c|0x030000\n");
    is $gpu_action->(@$amd), 'amd', 'AMD is recognised but unimplemented';

    is $gpu_action->(), 'none', 'nothing found means nothing to do';
};

#
# gpu.enabled and gpu.driver were config keys that nothing read: detect_gpu ran
# from all four install tasks unconditionally, so `gpu.enabled: false` in
# ocp.yaml still installed a driver.
#

subtest 'the spec can switch the host-side GPU work off' => sub {
    my %case = (
        'nothing passed'      => {},
        'gpu enabled'         => { gpu => 1 },
        'host driver mode'    => { gpu => 1, gpu_driver => 'host' },
    );
    for my $label (sort keys %case) {
        is_deeply detect_tasks_after($case{$label}), ['detect_gpu'], "$label: detection runs";
    }

    is_deeply detect_tasks_after({ gpu => 0 }), [],
        'gpu.enabled: false: no detection, so no driver install';
    is_deeply detect_tasks_after({ gpu => 1, gpu_driver => 'operator' }), [],
        'gpu.driver: operator: the operator installs driver and toolkit, Rex stays off the host';
};

subtest 'every install task goes through the guard' => sub {
    my $direct = () = $code =~ /do_task "detect_gpu";/g;
    is $direct, 1, 'the only call to detect_gpu is the one inside the guard';

    for my $task (qw( install_rke2_server install_rke2_agent install_k3s_server install_k3s_agent )) {
        for my $case ([ { gpu => 0 }, 0 ], [ { gpu => 1, gpu_driver => 'operator' }, 0 ], [ {}, 1 ]) {
            my ($extra, $want) = @$case;
            OCPTest::Rexfile->reset;
            OCPTest::Rexfile->run_task($task, { token => 't', server => 'https://x:9345', %$extra });
            my $detect = grep { $_->{args}[0] eq 'detect_gpu' } OCPTest::Rexfile->calls('do_task');
            is $detect, $want, "$task, " . join(',', map { "$_=$extra->{$_}" } sort keys %$extra)
                . ': detect_gpu ' . ($want ? 'runs' : 'does not run');
        }
    }
};

#
# Source-level: the things that must not grow back.
#

subtest 'the model whitelist is gone for good' => sub {
    unlike $code, qr/_check_nvidia_compute/, 'the whitelist helper is gone';
    unlike $code, qr/\blspci\b/,    'nothing shells out to lspci';
    unlike $code, qr/\bpciutils\b/, 'and the node no longer gets pciutils installed for it';

    unlike $code, qr/not in known compute-capable list/,
        'no "unknown GPU" skip left to strand the next new card';
    unlike $code, qr/\bTITAN\b|\bQuadro\b/,
        'no marketing names are matched anywhere';

    like $code, qr{/sys/bus/pci/devices},
        'detection reads sysfs instead';
};

#
# nvidia-driver-535 was hardcoded for Ubuntu. R535 reached end of life in June
# 2026 and on Ubuntu 24.04 the name is now a transitional package pulling 580,
# so the pin pinned nothing — on amd64 as much as on arm64. And
# linux-headers-generic tracks the generic kernel flavour, which on a vendor
# kernel (a DGX Spark runs 6.17.0-1029-nvidia) is a different kernel entirely.
#

subtest 'no branch number and no kernel flavour is guessed' => sub {
    unlike $code, qr/nvidia-driver-\d/,
        'no hardcoded driver branch — it decides open vs proprietary too, and that is per GPU';
    unlike $code, qr/linux-headers-generic/,
        'no headers for a kernel the node may not be running';

    my ($ubuntu) = $code =~ /^(sub _install_nvidia_driver_ubuntu \{.*?^\})/ms;
    ok $ubuntu, 'Ubuntu has a driver install of its own';

    like $ubuntu, qr/linux-headers-\$running_kernel/,
        'headers are for the running kernel, which is the one DKMS builds against';
    like $ubuntu, qr/ubuntu-drivers install/,
        'the package choice is delegated to ubuntu-drivers, which asks the PCI modalias';
    like $ubuntu, qr/\bdie\b/,
        'and a failure dies instead of falling back to a guessed package name';
};

#
# With detection fixed, install_nvidia now actually runs on a DGX — where the
# driver guard stops the driver install but the toolkit step used to carry on
# and add NVIDIA's apt source to a host that already had the toolkit from its
# vendor image.
#

my $GB10 = "/sys/bus/pci/devices/000f:01:00.0|0x10de|0x2e12|0x030000\n";

sub install_nvidia_on {
    my (%o) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::OS = $o{os} // 'Debian';
    local %OCPTest::Rexfile::CAN_RUN = %{ $o{can_run} // {} };
    local $OCPTest::Rexfile::RUN = sub {
        my ($cmd) = @_;
        return ($o{sysfs} // $GB10, 0) if $cmd =~ m{/sys/bus/pci/devices};
        return ('', 0);
    };
    return OCPTest::Rexfile->run_task('install_nvidia');
}

subtest 'a host that already has the toolkit keeps its apt sources' => sub {
    my ($check) = $code =~ /^(sub _nvidia_toolkit_present \{.*?^\})/ms;
    ok $check, 'there is a check for an existing container toolkit';
    like $check, qr/nvidia-container-runtime/,
        'it asks for the binary the CRI execs, not for a package name';
    like $check, qr/nvidia-ctk/, 'and for the toolkit CLI next to it';

    my $out = install_nvidia_on(can_run => { 'nvidia-container-runtime' => 1, 'nvidia-ctk' => 1 });
    is scalar(OCPTest::Rexfile->calls('Rex::GPU::NVIDIA::install_container_toolkit')), 0,
        'the toolkit install is not asked for';
    like $out, qr/leaving the host's apt sources alone/, 'and it says so';

    install_nvidia_on(can_run => { 'nvidia-ctk' => 1 });
    is scalar(OCPTest::Rexfile->calls('Rex::GPU::NVIDIA::install_container_toolkit')), 1,
        'without the runtime binary, Rex::GPU installs the toolkit';
};

#
# The driver itself, outside Ubuntu, is Rex::GPU's since k155. It gets the
# GPUs OCP found in sysfs, in the shape Rex::GPU takes from a caller without
# lspci (rex-gpu k42): device_id as four hex digits, and a name.
#

subtest 'Rex::GPU installs the driver for the GPUs sysfs found' => sub {
    install_nvidia_on(sysfs => $GB10
        . "/sys/bus/pci/devices/0000:01:00.0|0x10de|0x2330|0x030200\n"
        . "/sys/bus/pci/devices/0000:00:02.0|0x1af4|0x1050|0x030000\n");
    my $o = OCPTest::Rexfile->lib_opts('Rex::GPU::NVIDIA::install_driver');
    ok $o, 'install_driver called' or return;
    is_deeply [ map { $_->{device_id} } @{ $o->{gpus} } ], [ '2e12', '2330' ],
        'every NVIDIA card, by device ID, nothing else';
    like $o->{gpus}[0]{name}, qr/10de:2e12/, 'named by its PCI ID -- sysfs knows no names';
    ok !exists $o->{gpu}, 'as gpus, not the older single-GPU form';
    is scalar(OCPTest::Rexfile->calls('Rex::GPU::NVIDIA::verify_nvidia')), 1, 'then verified';

    my $toolkit = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::GPU::NVIDIA::install_container_toolkit' });
    my $driver  = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::GPU::NVIDIA::install_driver' });
    ok $driver >= 0 && $toolkit > $driver, 'driver before toolkit';
};

subtest 'a device ID sysfs does not give is left out, not guessed' => sub {
    install_nvidia_on(sysfs => "/sys/bus/pci/devices/0000:01:00.0|0x10de||0x030200\n");
    my $o = OCPTest::Rexfile->lib_opts('Rex::GPU::NVIDIA::install_driver');
    is scalar @{ $o->{gpus} }, 1, 'the card is still passed';
    ok !exists $o->{gpus}[0]{device_id}, 'without a device_id: an unknown GPU to the library';
};

subtest 'Ubuntu keeps OCP\'s own driver install (rex-gpu k69)' => sub {
    install_nvidia_on(os => 'Ubuntu');
    is scalar(OCPTest::Rexfile->calls('Rex::GPU::NVIDIA::install_driver')), 0, 'not Rex::GPU\'s';
    ok((grep { /^ubuntu-drivers install/ } OCPTest::Rexfile->commands), 'ubuntu-drivers install');
    my @pkgs = map { @{ $_->{args}[0] } } OCPTest::Rexfile->calls('pkg');
    ok !(grep { $_ eq 'linux-headers-generic' } @pkgs), 'no linux-headers-generic';
    ok((grep { /^linux-headers-/ } @pkgs), 'the running kernel\'s headers');
    is scalar(OCPTest::Rexfile->calls('Rex::GPU::NVIDIA::install_container_toolkit')), 1,
        'the toolkit still comes from Rex::GPU';
};

#
# _configure_nvidia_containerd wrote /var/lib/rancher/rke2/... unconditionally,
# so under k3s it silently did nothing — verified on a DGX Spark, where the RKE2
# directory does not exist and the nvidia runtime was registered anyway, because
# k3s and RKE2 both scan PATH for it at startup. Worse, the template it wrote
# carried no `{{ template "base" . }}`: k3s and RKE2 render such a file *instead
# of* their generated config, so on an RKE2 GPU node it would have taken the
# registry mirrors and the CNI settings down with it.
#

subtest 'OCP writes no containerd configuration for the GPU' => sub {
    unlike $code, qr/_configure_nvidia_containerd/, 'the old helper is gone';
    unlike $code, qr/configure_containerd|generate_cdi_specs|gpu_setup/,
        'Rex::GPU\'s containerd, CDI and full setup are not used -- the GPU Operator owns them';
    unlike $code, qr/Configuring RKE2 containerd/,
        'nothing claims to configure RKE2 while running under k3s';

    # Both paths do appear in the Rexfile again, but only in
    # cleanup_legacy_containerd_template, which REMOVES the template a pre-k23
    # OCP left behind on hosts that are never destroyed (k45). The claim
    # of this subtest is unchanged — OCP writes no containerd config — so it is
    # asserted against everything except that task, which also pins the
    # mentions to it: no future writer can hide behind the exception.
    my $writers = $code;
    $writers =~ s/^sub _legacy_containerd_template \{.*?^\}//ms;
    $writers =~ s/^sub _is_legacy_containerd_template \{.*?^\}//ms;
    $writers =~ s/^sub _legacy_containerd_template_paths \{.*?^\}//ms;
    $writers =~ s/^task "cleanup_legacy_containerd_template", sub \{.*?^\};//ms;

    unlike $writers, qr/config\.toml\.tmpl/,
        'no containerd config template is written at all';
    unlike $writers, qr{/etc/containerd/conf\.d},
        'and no drop-in either — the GPU Operator owns that file';

    my ($cleanup) = $code =~ /^task "cleanup_legacy_containerd_template", sub \{(.*?)^\};/ms;
    ok $cleanup, 'the template code that is left is the cleanup task';
    unlike $cleanup, qr/\bfile\s+["'\$]/, 'it writes nothing';
    like $cleanup, qr/\bunlink\b/, 'it only removes';

    # What is left is the RKE2 runtime lookup: a PATH in /etc/default/rke2-*,
    # written by Rex::Rancher when asked (nvidia_runtime_path), only when a
    # runtime is on the host, and never for k3s (held in t/155-rex-libraries.t).
    for my $task (qw( install_rke2_server install_rke2_agent install_k3s_server install_k3s_agent )) {
        OCPTest::Rexfile->reset;
        OCPTest::Rexfile->run_task($task, { token => 't', server => 'https://x:9345' });
        my ($call) = grep { $_->{name} =~ /^Rex::Rancher::(?:Server|Agent)::install_/ } @OCPTest::Rexfile::CALLS;
        my %o = @{ $call->{args} };
        ok $o{nvidia_runtime_path}, "$task asks for the runtime PATH lookup";
    }
};

done_testing;

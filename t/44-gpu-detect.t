#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

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
# The Rexfile is a Rex script, not a module, so the helpers are lifted out and
# executed against stubbed Rex commands — the same trick t/35-multi-arch.t uses
# for _node_arch.
#

my $root    = path(__FILE__)->parent->parent;
my $rexfile = $root->child('share/Rexfile');

plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

my $src = $rexfile->slurp_utf8;

# The comments explain what the old code did wrong and name the packages it
# named — assertions about what must not come back have to look at the code.
my $code = join '', grep { !/^\s*#/ } split /^/, $src;

my $sysfs_output;   # what the stubbed `run` returns
my @said;           # what the stubbed `say` printed
my @tasks;          # which tasks the stubbed `do_task` was asked for

{
    no strict 'refs';
    *{'RexGpuProbe::run'}     = sub { return $sysfs_output };
    *{'RexGpuProbe::say'}     = sub { push @said, join '', @_; return 1 };
    *{'RexGpuProbe::do_task'} = sub { push @tasks, $_[0]; return 1 };
    *{'RexGpuProbe::FALSE'}   = sub { 0 };
}

for my $name (qw(_pci_display_devices _gpu_action _maybe_detect_gpu)) {
    my ($sub_src) = $src =~ /^(sub \Q$name\E \{.*?^\})/ms;
    ok $sub_src, "share/Rexfile defines $name";
    eval "package RexGpuProbe; $sub_src; 1"
        or die "could not load $name out of the Rexfile: $@";
}

sub devices_for {
    $sysfs_output = shift;
    return [ RexGpuProbe::_pci_display_devices() ];
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

    is RexGpuProbe::_gpu_action(@$devices), 'nvidia',
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
    is_deeply [ RexGpuProbe::_pci_display_devices() ], [],
        'neither is a command that produced nothing';
};

#
# The virtual-GPU blacklist stays: a short list of "definitely not" keeps
# working as hardware moves on, which is exactly what the whitelist did not.
#

subtest 'virtual display adapters still need no host driver' => sub {
    for my $vendor (qw(1af4 1b36 15ad 80ee)) {
        my $devices = devices_for("/sys/bus/pci/devices/0000:00:02.0|0x$vendor|0x1050|0x030000\n");
        is RexGpuProbe::_gpu_action(@$devices), 'virtual', "vendor $vendor is virtual";
    }
};

subtest 'a passed-through GPU beats the virtio adapter next to it' => sub {
    my $devices = devices_for(<<'SYSFS');
/sys/bus/pci/devices/0000:00:02.0|0x1af4|0x1050|0x030000
/sys/bus/pci/devices/0000:06:00.0|0x10de|0x20b5|0x030200
SYSFS

    is RexGpuProbe::_gpu_action(@$devices), 'nvidia',
        'the VM display adapter does not veto the card that is actually there';
};

subtest 'the other outcomes' => sub {
    my $amd = devices_for("/sys/bus/pci/devices/0000:03:00.0|0x1002|0x744c|0x030000\n");
    is RexGpuProbe::_gpu_action(@$amd), 'amd', 'AMD is recognised but unimplemented';

    is RexGpuProbe::_gpu_action(), 'none', 'nothing found means nothing to do';
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
        @tasks = ();
        RexGpuProbe::_maybe_detect_gpu($case{$label});
        is_deeply \@tasks, ['detect_gpu'], "$label: detection runs";
    }

    @tasks = ();
    RexGpuProbe::_maybe_detect_gpu({ gpu => 0 });
    is_deeply \@tasks, [], 'gpu.enabled: false: no detection, so no driver install';

    @tasks = ();
    RexGpuProbe::_maybe_detect_gpu({ gpu => 1, gpu_driver => 'operator' });
    is_deeply \@tasks, [],
        'gpu.driver: operator: the operator installs driver and toolkit, Rex stays off the host';
};

subtest 'every install task goes through the guard' => sub {
    my $direct = () = $code =~ /do_task "detect_gpu";/g;
    is $direct, 1,
        'the only call to detect_gpu is the one inside the guard';

    my $guarded = () = $code =~ /_maybe_detect_gpu\(\$params\);/g;
    is $guarded, 4,
        'all four install tasks (rke2 server/agent, k3s server/agent) ask first';
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

subtest 'a host that already has the toolkit keeps its apt sources' => sub {
    my ($check) = $code =~ /^(sub _nvidia_toolkit_present \{.*?^\})/ms;
    ok $check, 'there is a check for an existing container toolkit';
    like $check, qr/nvidia-container-runtime/,
        'it asks for the binary the CRI execs, not for a package name';
    like $check, qr/nvidia-ctk/, 'and for the toolkit CLI next to it';

    my ($task) = $code =~ /task "install_nvidia", sub \{(.*?)\n\};/s;
    like $task, qr/if \(_nvidia_toolkit_present\(\)\)/,
        'the repository and package step is guarded by it';

    my ($guarded) = $task =~ /if \(_nvidia_toolkit_present\(\)\) \{(.*?)^    \}/ms;
    unlike $guarded, qr{sources\.list\.d},
        'nothing writes an apt source on the already-equipped path';
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
    unlike $code, qr/config\.toml\.tmpl/,
        'no containerd config template is written at all';
    unlike $code, qr{/etc/containerd/conf\.d},
        'and no drop-in either — the GPU Operator owns that file';
    unlike $code, qr/Configuring RKE2 containerd/,
        'nothing claims to configure RKE2 while running under k3s';

    my ($path_helper) = $code =~ /^(sub _configure_nvidia_runtime_path \{.*?^\})/ms;
    ok $path_helper, 'what is left is the RKE2 runtime lookup';
    like $path_helper, qr/can_run\("nvidia-container-runtime"\)/,
        'which only fires when there is a runtime to find';
    like $path_helper, qr{/etc/default/\$unit},
        'and writes the EnvironmentFile the RKE2 docs name';
    like $path_helper, qr/\bPATH=/, 'with a PATH for the service';

    like $src, qr/_configure_nvidia_runtime_path\('rke2-server'\)/, 'called for the server';
    like $src, qr/_configure_nvidia_runtime_path\('rke2-agent'\)/,  'and for the agent';
    unlike $src, qr/_configure_nvidia_runtime_path\('k3s/,
        'never for k3s, which finds the runtime on its own';
};

done_testing;

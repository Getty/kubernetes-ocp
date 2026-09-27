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
# OCP read sysfs itself from k155 on; since k196 the reading is Rex::GPU's
# (Rex::GPU::Detect::Sysfs, rex-gpu k73), which gives the full GPU hashes --
# a compute verdict from the generation table, vGPU keys, NVSwitches -- and
# dies for a host whose sysfs it cannot read. What it finds on which hardware
# is held against the real library in t/155-rex-libraries.t. What stays OCP's
# and is held here, against recorders (t/lib/OCPTest/Rexfile.pm): which of
# the GPUs found get a driver (k194), that the host is read once, and what
# OCP hands Rex::GPU::NVIDIA.
#

my $src = OCPTest::Rexfile->rexfile->slurp_utf8;

# The comments explain what the old code did wrong and name the packages it
# named — assertions about what must not come back have to look at the code.
my $code = join '', grep { !/^\s*#/ } split /^/, $src;

my $gpu_action       = OCPTest::Rexfile->helper('_gpu_action');
my $driver_gpus      = OCPTest::Rexfile->helper('_driver_gpus');
my $maybe_detect_gpu = OCPTest::Rexfile->helper('_maybe_detect_gpu');

# GPUs in the shape Rex::GPU::Detect::Sysfs returns them.
sub nvidia {
    my ($id, $compute, %more) = @_;
    return {
        name      => 'NVIDIA GPU [10de:' . ($id // '????') . ']',
        vendor    => 'nvidia',
        pci_class => '0300',
        compute   => $compute,
        device_id => $id,
        subsystem_vendor_id => '10de',
        subsystem_id        => '0000',
        vgpu      => 0,
        %more,
    };
}
my $GB10    = nvidia('2e12', 1);                         # DGX Spark
my $H100    = nvidia('2330', 1, pci_class => '0302');
my $KEPLER  = nvidia('128b', 0);                         # GT 710, GK208
my $UNKNOWN = nvidia('3000', undef);                     # no generation row, no name
my $SWITCH  = { name => 'NVIDIA NVSwitch [10de:22a3]', vendor => 'nvidia',
                pci_class => '0680', device_id => '22a3' };

sub detected {
    my (%d) = @_;
    return { nvidia => [], amd => [], nvswitch => [], %d };
}

sub detect_tasks_after {
    my ($params) = @_;
    OCPTest::Rexfile->reset;
    { local *STDOUT; open STDOUT, '>', \my $sink; $maybe_detect_gpu->($params); }
    return [ map { $_->{args}[0] } OCPTest::Rexfile->calls('do_task') ];
}

# detect_gpu, and install_nvidia behind it, on a host whose detection says
# $detected. Returns what the tasks printed.
sub detect_gpu_on {
    my ($detected, %o) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::OS = $o{os} // 'Debian';
    local $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::Detect::Sysfs::detect'} = sub { $detected };
    local $OCPTest::Rexfile::FOLLOW{install_nvidia} = 1;
    return OCPTest::Rexfile->run_task('detect_gpu');
}

sub install_nvidia_on {
    my (%o) = @_;
    return detect_gpu_on($o{detected} // detected(nvidia => [ $GB10 ]), %o);
}

sub driver_call { OCPTest::Rexfile->lib_opts('Rex::GPU::NVIDIA::install_driver') }
sub count       { scalar OCPTest::Rexfile->calls($_[0]) }

#
# Detection is Rex::GPU's, read once.
#

subtest 'the host is read once, through Rex::GPU::Detect::Sysfs' => sub {
    detect_gpu_on(detected(nvidia => [ $GB10 ]));
    my @detect = OCPTest::Rexfile->calls('Rex::GPU::Detect::Sysfs::detect');
    is scalar @detect, 1, 'one detection for detect_gpu and the install behind it';
    is $detect[0]{args}[0], 'Rex::GPU::Detect::Sysfs', 'the sysfs detection, as a class method';
    ok driver_call(), 'and the driver install ran on what it found';

    # A hand-run of install_nvidia alone detects for itself.
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::Detect::Sysfs::detect'} = sub { detected(nvidia => [ $GB10 ]) };
    OCPTest::Rexfile->run_task('install_nvidia');
    is count('Rex::GPU::Detect::Sysfs::detect'), 1, 'install_nvidia on its own: it detects';
    ok driver_call(), 'and installs';
};

subtest 'a host whose sysfs cannot be read fails, it is not GPU-less' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_DIE{'Rex::GPU::Detect::Sysfs::detect'} =
        "GPU detection from sysfs: could not read /sys/bus/pci/devices on the host (exit 3)\n";
    ok !eval { OCPTest::Rexfile->run_task('detect_gpu'); 1 }, 'detect_gpu dies';
    like $@, qr/could not read \/sys\/bus\/pci\/devices/, 'with the library\'s reason';
    is count('Rex::GPU::NVIDIA::install_driver'), 0, 'before any driver';
};

#
# Which GPUs get a driver (k194). Since k191 Rex::GPU refuses Kepler and older
# on Ubuntu too (Setup.pm _reject_unsupported_gpu, as on Debian): the newest
# driver for them is the end-of-life 470 branch. OCP handed every NVIDIA
# display card to install_driver, so a host with a GT 710 as its VGA died in
# `ocp apply` or a robocop join. Rex::GPU leaves "does this card get a
# driver" to its caller, and an empty gpus list means "install one for no GPU
# in particular", not "skip".
#

subtest 'the GB10 that the whitelist could not name gets a driver' => sub {
    is $gpu_action->(detected(nvidia => [ $GB10 ])), 'nvidia',
        'and nobody asked what the card is called';
};

subtest 'a Kepler-only host gets no driver, no toolkit, and is no GPU node (k194)' => sub {
    is $gpu_action->(detected(nvidia => [ $KEPLER ])), 'unsupported', 'decided as unsupported';

    my $out = detect_gpu_on(detected(nvidia => [ $KEPLER ]));
    is count('Rex::GPU::NVIDIA::install_driver'), 0, 'install_driver is never called';
    is count('Rex::GPU::NVIDIA::install_container_toolkit'), 0, 'nor the toolkit installed';
    ok !(grep { $_->{args}[0] eq 'install_nvidia' } OCPTest::Rexfile->calls('do_task')),
        'install_nvidia does not run';
    like $out, qr/10de:128b/, 'the card is named';
    like $out, qr/Kepler or older/, 'with the reason';
    like $out, qr/no GPU node/, 'and what it means for the node';

    for my $os (qw( Ubuntu Debian )) {
        detect_gpu_on(detected(nvidia => [ $KEPLER ]), os => $os);
        is count('Rex::GPU::NVIDIA::install_driver'), 0, "$os: no install_driver either";
    }
};

subtest 'next to a newer card a Kepler is left out, the newer one gets its driver' => sub {
    detect_gpu_on(detected(nvidia => [ $KEPLER, $GB10 ]));
    my $o = driver_call() or return fail('install_driver called');
    is_deeply [ map { $_->{device_id} } @{ $o->{gpus} } ], [ '2e12' ], 'only the GB10';
};

subtest 'a card the table does not know is handed on, not dropped' => sub {
    is_deeply [ $driver_gpus->(detected(nvidia => [ $UNKNOWN ])) ], [ $UNKNOWN ],
        'compute undef (no generation row, no name in sysfs) counts';
    detect_gpu_on(detected(nvidia => [ $UNKNOWN ]));
    my $o = driver_call() or return fail('install_driver called');
    is $o->{gpus}[0]{device_id}, '3000', 'install_driver gets it -- an unknown GPU to the library';

    my $unreadable = nvidia(undef, undef);
    detect_gpu_on(detected(nvidia => [ $unreadable ]));
    $o = driver_call() or return fail('install_driver called');
    is scalar @{ $o->{gpus} }, 1, 'a card whose device ID sysfs could not read is handed on too';
    ok !defined $o->{gpus}[0]{device_id}, 'without a device_id -- not guessed';
};

subtest 'install_driver never gets an empty list' => sub {
    for my $case (
        [ 'no GPU'        => detected() ],
        [ 'only a Kepler' => detected(nvidia => [ $KEPLER ]) ],
        [ 'only AMD'      => detected(amd => [ { name => 'AMD GPU [1002:744c]', vendor => 'amd',
                                                 pci_class => '0300', compute => 0 } ]) ],
    ) {
        my ($label, $d) = @$case;

        detect_gpu_on($d);
        is count('Rex::GPU::NVIDIA::install_driver'), 0, "$label: detect_gpu installs nothing";

        # install_nvidia run by hand on such a host: nothing either.
        OCPTest::Rexfile->reset;
        local $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::Detect::Sysfs::detect'} = sub { $d };
        my $out = OCPTest::Rexfile->run_task('install_nvidia');
        is count('Rex::GPU::NVIDIA::install_driver'), 0, "$label: install_nvidia installs nothing";
        is count('Rex::GPU::NVIDIA::install_container_toolkit'), 0, "$label: no toolkit";
        like $out, qr/nothing to install/, "$label: and says so";
    }
};

subtest 'the other outcomes' => sub {
    is $gpu_action->(detected(amd => [ { vendor => 'amd', compute => 0 } ])), 'amd',
        'AMD is recognised but unimplemented';
    is $gpu_action->(detected()), 'none', 'nothing found means nothing to do';
    # Virtual display adapters never reach OCP: Rex::GPU::Detect::Sysfs skips
    # them without hiding a passed-through card (t/155-rex-libraries.t).
    is $gpu_action->(detected(nvidia => [ $H100 ])), 'nvidia', 'a 3D controller is a GPU as well';
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

    like $code, qr/Rex::GPU::Detect::Sysfs->detect/,
        'detection reads sysfs, through Rex::GPU';
    unlike $code, qr{/sys/bus/pci/devices}, 'and OCP reads none of it itself';
};

#
# nvidia-driver-535 was hardcoded for Ubuntu. R535 reached end of life in June
# 2026 and on Ubuntu 24.04 the name is now a transitional package pulling 580,
# so the pin pinned nothing — on amd64 as much as on arm64. (The kernel
# headers and ubuntu-drivers are held by what install_nvidia runs, below.)
#

subtest 'no driver branch is hardcoded' => sub {
    unlike $code, qr/nvidia-driver-\d/,
        'no hardcoded driver branch — it decides open vs proprietary too, and that is per GPU';
};

#
# With detection fixed, install_nvidia now actually runs on a DGX — where the
# driver guard stops the driver install but the toolkit step used to carry on
# and add NVIDIA's apt source to a host that already had the toolkit from its
# vendor image. Up to k196 OCP checked for the binaries itself and skipped
# Rex::GPU; since rex-gpu k74 the library takes the binaries as a toolkit when
# asked to (binaries_suffice), and OCP always asks. That the library then
# leaves such a host alone is held against the real library in
# t/155-rex-libraries.t.
#

subtest 'the toolkit: the binaries a host already has suffice' => sub {
    install_nvidia_on();
    my @tk = OCPTest::Rexfile->calls('Rex::GPU::NVIDIA::install_container_toolkit');
    is scalar @tk, 1, 'install_container_toolkit, once';
    is_deeply +{ @{ $tk[0]{args} } }, { binaries_suffice => 1 },
        'with binaries_suffice: nvidia-container-runtime and a working nvidia-ctk are a toolkit';
    unlike $code, qr/_nvidia_toolkit_present|can_run\("nvidia/, 'no check of OCP\'s own left';
    unlike $code, qr/configure_containerd/, 'and no containerd configuration with it';
};

#
# The driver itself is Rex::GPU's since k155 (Ubuntu since k191). It gets the
# GPUs as Rex::GPU::Detect::Sysfs found them.
#

subtest 'Rex::GPU installs the driver for the GPUs found, as found' => sub {
    my $vgpu = nvidia('2236', 1, vgpu => 1, vgpu_type => 'NVIDIA A10-2Q', subsystem_id => '14b9');
    install_nvidia_on(detected => detected(nvidia => [ $GB10, $H100, $vgpu ]));
    my $o = driver_call() or return fail('install_driver called');
    is_deeply $o->{gpus}, [ $GB10, $H100, $vgpu ],
        'every GPU a driver is for, the whole hash -- vGPU keys included, so Rex::GPU can refuse a vGPU guest';
    ok !exists $o->{gpu}, 'as gpus, not the older single-GPU form';
    ok !exists $o->{nvswitches}, 'no NVSwitch, no nvswitches';
    is count('Rex::GPU::NVIDIA::verify_nvidia'), 1, 'then verified';

    my $toolkit = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::GPU::NVIDIA::install_container_toolkit' });
    my $driver  = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::GPU::NVIDIA::install_driver' });
    ok $driver >= 0 && $toolkit > $driver, 'driver before toolkit';
};

subtest 'an HGX baseboard\'s NVSwitches go with the driver' => sub {
    install_nvidia_on(detected => detected(nvidia => [ $H100 ], nvswitch => [ $SWITCH ]));
    my $o = driver_call() or return fail('install_driver called');
    is_deeply $o->{nvswitches}, [ $SWITCH ],
        'as nvswitches: Rex::GPU installs Fabric Manager with the driver';
};

#
# Ubuntu (k191, rex-gpu k69): the same install_driver, with the setup that has
# ubuntu-drivers name the package. That it installs only the running kernel's
# headers, never runs `ubuntu-drivers install`, and dies instead of guessing a
# package when ubuntu-drivers cannot name one is held against the real
# Rex::GPU in t/155-rex-libraries.t.
#

subtest 'Ubuntu: Rex::GPU installs the driver, ubuntu-drivers naming the package' => sub {
    install_nvidia_on(os => 'Ubuntu');
    my $o = driver_call() or return fail('install_driver called');
    is $o->{setup}, 'Rex::GPU::NVIDIA::Setup::UbuntuDrivers', 'with Setup::UbuntuDrivers';
    is_deeply [ map { $_->{device_id} } @{ $o->{gpus} } ], [ '2e12' ], 'for the GPUs found';
    is_deeply [ OCPTest::Rexfile->calls('pkg') ], [], 'no package of OCP\'s own';
    ok !(grep { /ubuntu-drivers|modprobe/ } OCPTest::Rexfile->commands), 'no command of its own';
    is count('Rex::GPU::NVIDIA::install_container_toolkit'), 1,
        'the toolkit still comes from Rex::GPU';

    install_nvidia_on(os => 'Debian');
    ok !exists driver_call()->{setup}, 'elsewhere the setup for the OS, as Rex::GPU picks it';
};

#
# linux-headers-generic tracks the generic kernel flavour, which on a vendor
# kernel (a DGX Spark runs 6.17.0-1029-nvidia) is a different kernel entirely.
# OCP installs no headers of its own, on any OS: Rex::GPU installs the running
# kernel's (held against the real library in t/155-rex-libraries.t).
#

subtest 'no kernel headers of OCP\'s own' => sub {
    for my $os (qw( Ubuntu Debian )) {
        install_nvidia_on(os => $os);
        my @named = (OCPTest::Rexfile->commands,
                     map { map { ref $_ eq 'ARRAY' ? @$_ : $_ } @{ $_->{args} } } OCPTest::Rexfile->calls('pkg'));
        ok !(grep { defined && /linux-headers/ } @named), "$os: no command or package names them";
    }
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

    # The template path does appear in the Rexfile, but only in the probe that
    # reports the template a pre-k23 OCP left behind and the remedy that has
    # Rex::Rancher remove it (k45) -- on hosts that are never destroyed. The
    # claim of this subtest is unchanged — OCP writes no containerd config —
    # so it is asserted against everything except those two tasks, which also
    # pins the mentions to them: no future writer can hide behind the
    # exception.
    my $writers = $code;
    $writers =~ s/^task "detect_legacy_containerd_template", sub \{.*?^\};//ms;
    $writers =~ s/^task "cleanup_legacy_containerd_template", sub \{.*?^\};//ms;

    unlike $writers, qr/config\.toml\.tmpl/,
        'no containerd config template is written at all';
    unlike $writers, qr{/etc/containerd/conf\.d},
        'and no drop-in either — the GPU Operator owns that file';

    my ($cleanup) = $code =~ /^task "cleanup_legacy_containerd_template", sub \{(.*?)^\};/ms;
    ok $cleanup, 'the template code that is left is the cleanup task';
    unlike $cleanup, qr/\bfile\s+["'\$]/, 'it writes nothing';
    like $cleanup, qr/remove_bare_containerd_template/, 'it only has the library remove';

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

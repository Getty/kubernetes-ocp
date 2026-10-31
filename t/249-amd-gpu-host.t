#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

# Loaded up front: the Rex::GPU::amd_class switches below must act on the
# Rex::GPU the Rexfile loads, not be overwritten by it.
OCPTest::Rexfile->load;

#
# k249: the host half of the AMD GPU worker (k248). detect_gpu answers per
# vendor, NVIDIA first, and an AMD GPU goes to install_amd, which has
# Rex::GPU::AMD (rex-gpu k1) install the amdgpu kernel driver and verify it --
# no ROCm, no toolkit, no CDI, no reboot. What the node gets out of it are its
# labels, registered with the kubelet (config.yaml node-label):
#
#   - ocp.internal/amd-gpu.present=true on every node with an accepted AMD GPU,
#     the marker the AMD cluster stack selects on (k251);
#   - ocp.internal/amd-gpu.gfx-target=<gfx>, or one
#     ocp.internal/amd-gpu.gfx-target.<gfx>=<count> per target when they differ.
#
# An integrated AMD GPU (Rex::GPU's `integrated => 1`: a Ryzen iGPU or APU) is
# set up only with gpu_amd_integrated, which OCP::Node passes for a node
# joined with --gpu or under gpu.amd.integrated (k250, t/250): detection runs
# on every node, and a Hetzner AX42 control plane's Phoenix iGPU is nobody's
# GPU node. Under gpu.driver: operator OCP installs no AMD driver (there is no
# AMD operator) but still labels the node; NVIDIA there stays the GPU
# Operator's, exactly as before.
#
# The labels have to come back from the tasks, so detect_gpu and install_amd
# are called as functions, in the install's own process -- do_task forks. The
# recorders (t/lib/OCPTest/Rexfile.pm) record those as task_call. Rex::GPU::AMD
# is not released yet: it is a recorder here, and Rex::GPU->can('amd_class')
# -- its flag -- is switched per test.
#

my $PRESENT = 'ocp.internal/amd-gpu.present=true';
my $GFX     = 'ocp.internal/amd-gpu.gfx-target';

# AMD GPUs in the shape Rex::GPU::Detect::Sysfs gives them from rex-gpu k1 on.
sub amd {
    my ($slot, $device_id, $gfx, %more) = @_;
    return {
        name       => "AMD GPU [1002:$device_id]",
        vendor     => 'amd',
        pci_class  => '0300',
        slot       => $slot,
        device_id  => $device_id,
        gfx_target => $gfx,
        compute    => 1,
        integrated => 0,
        %more,
    };
}
my $STRIX   = amd('0000:c5:00.0', '1586', 'gfx1151', integrated => 1);   # Ryzen AI Max (synapse)
my $PHOENIX = amd('0000:c4:00.0', '15bf', 'gfx1103', integrated => 1);   # Hetzner AX42's iGPU
my $W7900   = amd('0000:03:00.0', '7448', 'gfx1100');                    # Radeon PRO W7900
my $MI300   = amd('0000:05:00.0', '74a1', 'gfx942', pci_class => '0302');
my $OLD     = amd('0000:06:00.0', '6798', undef, compute => 0);          # known no compute GPU
my $NEW     = amd('0000:07:00.0', '7550', 'gfx1201', compute => undef);  # no verdict

my $GB10 = {
    name => 'NVIDIA GPU [10de:2e12]', vendor => 'nvidia', pci_class => '0300',
    device_id => '2e12', compute => 1, vgpu => 0,
};

sub detected {
    my (%d) = @_;
    return { nvidia => [], amd => [], nvswitch => [], %d };
}

sub count { scalar OCPTest::Rexfile->calls($_[0]) }

# verify_amd as Rex::GPU::AMD answers it on a host whose driver works: every
# GPU it was handed, with its gfx target.
sub verify_works {
    my (%o) = @_;
    return {
        ok   => 1,
        gpus => [ map { +{ slot => $_->{slot}, device_id => $_->{device_id},
                           gfx_target => $_->{gfx_target}, kfd_node => 1 } } @{ $o{gpus} || [] } ],
    };
}

# What Rex::GPU::AMD answers in install_amd_on, when a test says otherwise.
our ($VERIFY, $DRIVER);

# install_amd, called as detect_gpu calls it; returns (labels, output).
sub install_amd_on {
    my ($detected, %params) = @_;
    OCPTest::Rexfile->reset;
    $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::AMD::verify_amd'}     = $VERIFY // \&verify_works;
    $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::AMD::install_driver'} = $DRIVER if $DRIVER;
    my $code = OCPTest::Rexfile->task('install_amd');
    my ($labels, $out) = (undef, '');
    {
        local *STDOUT;
        open STDOUT, '>', \$out or die $!;
        $labels = $code->({ detected => $detected, %params });
    }
    return ($labels, $out);
}

# The slots install_driver got; undef when it was not called.
sub driver_gpus {
    my $o = OCPTest::Rexfile->lib_opts('Rex::GPU::AMD::install_driver');
    return $o ? [ map { $_->{slot} } @{ $o->{gpus} } ] : undef;
}

# --- the flag: Rex::GPU without Rex::GPU::AMD ------------------------------

subtest 'a Rex::GPU without Rex::GPU::AMD: said, skipped, never a die' => sub {
    no warnings 'redefine';
    local *Rex::GPU::amd_class;
    ok !Rex::GPU->can('amd_class'), 'the flag is off';

    my ($labels, $out);
    ok eval { ($labels, $out) = install_amd_on(detected(amd => [ $W7900 ])); 1 }, 'install_amd does not die'
        or diag $@;
    is count('Rex::GPU::AMD::install_driver'), 0, 'no driver install';
    is count('Rex::GPU::AMD::verify_amd'), 0, 'nothing verified';
    is_deeply $labels, [], 'and no labels: the stack must not select this node';
    like $out, qr/^\[WARN\] AMD GPU present \(AMD GPU \[1002:7448\]\), but Rex::GPU \S+ has no AMD support/m,
        'it says why, as a [WARN] OCP::Rex surfaces';
};

# Everything below runs with a Rex::GPU that has it.
local *Rex::GPU::amd_class = sub { 'Rex::GPU::AMD' };
ok(Rex::GPU->can('amd_class'), 'the flag is on for the rest');

# --- which GPUs ---------------------------------------------------------------

subtest 'a discrete AMD GPU: driver, verify, marker and gfx target' => sub {
    my ($labels, $out) = install_amd_on(detected(amd => [ $W7900 ]));
    my $o = OCPTest::Rexfile->lib_opts('Rex::GPU::AMD::install_driver') or return fail('install_driver called');
    is_deeply $o->{gpus}, [ $W7900 ], 'install_driver gets the GPU, as detected';
    is $o->{method}, 'auto', 'method auto: inbox where it serves the card, else DKMS';
    is $o->{reboot}, 0, 'and OCP never reboots the node';

    my $v = OCPTest::Rexfile->lib_opts('Rex::GPU::AMD::verify_amd') or return fail('verify_amd called');
    is_deeply $v->{gpus}, [ $W7900 ], 'verify_amd asks about the same GPUs';
    my $at = sub { my $n = shift; OCPTest::Rexfile->index_of(sub { $_->{name} eq "Rex::GPU::AMD::$n" }) };
    ok $at->('install_driver') < $at->('verify_amd'), 'after the install';

    is_deeply $labels, [ $PRESENT, "$GFX=gfx1100" ], 'the marker and the gfx target';
    like $out, qr/AMD GPU driver: present/, 'what install_driver did is said';
};

subtest 'Rex::GPU\'s compute verdict: 0 left out, undef handed on' => sub {
    install_amd_on(detected(amd => [ $OLD, $NEW ]));
    is_deeply driver_gpus(), [ $NEW->{slot} ], 'only the GPU without a "no" verdict';

    my ($labels, $out) = install_amd_on(detected(amd => [ $OLD ]));
    is count('Rex::GPU::AMD::install_driver'), 0, 'only a no-compute GPU: install_driver is not called';
    # rex-gpu k1: an explicit gpus => [] makes install_driver die and
    # verify_amd warn -- an empty selection reaches neither.
    is count('Rex::GPU::AMD::verify_amd'), 0, 'nor verify_amd';
    is_deeply $labels, [], 'no labels';
    like $out, qr/nothing to install/, 'and it says so';
};

subtest 'an integrated GPU without gpu_amd_integrated: one line, nothing else' => sub {
    for my $param ([ 'not passed' ], [ '0', gpu_amd_integrated => 0 ]) {
        my ($label, @p) = @$param;
        my ($labels, $out) = install_amd_on(detected(amd => [ $PHOENIX ]), @p);
        is count('Rex::GPU::AMD::install_driver'), 0, "gpu_amd_integrated $label: no driver install";
        is count('Rex::GPU::AMD::verify_amd'), 0, "gpu_amd_integrated $label: no verify";
        is_deeply $labels, [], "gpu_amd_integrated $label: no labels, not even the marker";
        my @lines = grep { /integrated AMD GPU/ } split /\n/, $out;
        is_deeply \@lines,
            [ 'integrated AMD GPU 0000:c4:00.0 (gfx1103) not set up — join the node with --gpu '
              . 'or set gpu.amd.integrated: true' ],
            "gpu_amd_integrated $label: one line, naming the slot, the gfx target and the way in";
        unlike $out, qr/\[WARN\]/, "gpu_amd_integrated $label: no warning -- a control plane's iGPU is no fault";
    }
};

subtest 'an integrated GPU with gpu_amd_integrated: set up like any other' => sub {
    my ($labels, $out) = install_amd_on(detected(amd => [ $STRIX ]), gpu_amd_integrated => 1);
    is_deeply driver_gpus(), [ $STRIX->{slot} ], 'install_driver gets it';
    is_deeply $labels, [ $PRESENT, "$GFX=gfx1151" ], 'the marker and the gfx target';
    unlike $out, qr/not set up/, 'nothing skipped';
};

subtest 'integrated 0 or undef: handed on with or without gpu_amd_integrated' => sub {
    my $unsaid = { %$W7900, integrated => undef };
    my $absent = { %$W7900 };
    delete $absent->{integrated};
    for my $case ([ 'integrated 0' => $W7900 ], [ 'integrated undef' => $unsaid ], [ 'no integrated key' => $absent ]) {
        my ($what, $gpu) = @$case;
        for my $p (0, 1) {
            my ($labels) = install_amd_on(detected(amd => [ $gpu ]), gpu_amd_integrated => $p);
            is_deeply driver_gpus(), [ $gpu->{slot} ], "$what, gpu_amd_integrated $p: install_driver gets it";
            is $labels->[0], $PRESENT, "$what, gpu_amd_integrated $p: marked";
        }
    }
};

subtest 'an iGPU next to a discrete GPU: only the one asked for' => sub {
    my ($labels, $out) = install_amd_on(detected(amd => [ $PHOENIX, $W7900 ]));
    is_deeply driver_gpus(), [ $W7900->{slot} ], 'install_driver gets the discrete GPU alone';
    my $v = OCPTest::Rexfile->lib_opts('Rex::GPU::AMD::verify_amd');
    is_deeply [ map { $_->{slot} } @{ $v->{gpus} } ], [ $W7900->{slot} ], 'verify_amd too';
    is_deeply $labels, [ $PRESENT, "$GFX=gfx1100" ], 'the iGPU\'s gfx target is no label';
    like $out, qr/integrated AMD GPU 0000:c4:00\.0 \(gfx1103\) not set up/, 'the iGPU is named as skipped';

    install_amd_on(detected(amd => [ $PHOENIX, $W7900 ]), gpu_amd_integrated => 1);
    is_deeply driver_gpus(), [ $PHOENIX->{slot}, $W7900->{slot} ], 'with gpu_amd_integrated: both';
};

# --- the gfx-target labels --------------------------------------------------

subtest 'gfx-target: one label for one target, one per target with a count otherwise' => sub {
    my $second = amd('0000:04:00.0', '7448', 'gfx1100');
    my ($labels) = install_amd_on(detected(amd => [ $W7900, $second ]));
    is_deeply $labels, [ $PRESENT, "$GFX=gfx1100" ], 'two GPUs, one target: one label';

    ($labels) = install_amd_on(detected(amd => [ $W7900, $second, $MI300 ]));
    is_deeply $labels, [ $PRESENT, "$GFX.gfx1100=2", "$GFX.gfx942=1" ],
        'two targets: one label each, valued with the count (AMD\'s labeller shape)';
};

subtest 'gfx-target: from verify_amd, only what is shaped like one' => sub {
    local $VERIFY = sub {
        +{ ok => 1, gpus => [ { slot => 'a', gfx_target => 'gfx1100' },
                              { slot => 'b', gfx_target => 'GFX 11; rm -rf' },
                              { slot => 'c', gfx_target => undef } ] };
    };
    my ($labels, $out) = install_amd_on(detected(amd => [ $W7900 ]));
    is_deeply $labels, [ $PRESENT, "$GFX=gfx1100" ], 'the odd one and the missing one add no label';
    like $out, qr/^\[WARN\] AMD GPU gfx target 'GFX 11; rm -rf' is no label value/m, 'the odd one is named';
};

subtest 'a driver that does not verify: warned, still marked, no gfx target' => sub {
    local $VERIFY = sub {
        +{ ok => 0, gpus => [ { slot => $W7900->{slot}, gfx_target => undef } ] };
    };
    local $DRIVER = sub { 'dkms' };
    my ($labels, $out) = install_amd_on(detected(amd => [ $W7900 ]));
    is_deeply $labels, [ $PRESENT ], 'an accepted GPU is an AMD node: the marker, no gfx target';
    like $out, qr/^\[WARN\] the AMD GPU driver did not verify on this host -- the DKMS module may need a reboot/m,
        'a DKMS install names the reboot it may need';
    is count('Rex::GPU::AMD::install_driver'), 1, 'and nothing is tried again';
};

subtest 'an install_driver that dies stops the install' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_DIE{'Rex::GPU::AMD::install_driver'} = "amdgpu: kernel 5.4 is not supported\n";
    local $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::Detect::Sysfs::detect'} = sub { detected(amd => [ $W7900 ]) };
    local $OCPTest::Rexfile::FOLLOW{detect_gpu}  = 1;
    local $OCPTest::Rexfile::FOLLOW{install_amd} = 1;
    ok !eval { OCPTest::Rexfile->run_task('install_rke2_agent', { token => 't', server => 'https://x:9345' }); 1 },
        'install_rke2_agent dies';
    like $@, qr/kernel 5\.4 is not supported/, 'the agent install dies with the library\'s reason';
    is count('Rex::Rancher::Agent::install_agent'), 0, 'before the agent is installed';
};

# --- gpu.driver: operator ---------------------------------------------------

subtest 'gpu.driver operator: no AMD driver, the node labelled all the same' => sub {
    my ($labels, $out) = install_amd_on(detected(amd => [ $W7900 ]), gpu_driver => 'operator');
    is count('Rex::GPU::AMD::install_driver'), 0, 'install_driver is not called';
    is count('Rex::GPU::AMD::verify_amd'), 1, 'verify_amd is (it only reads)';
    is_deeply $labels, [ $PRESENT, "$GFX=gfx1100" ], 'marker and gfx target, as in host mode';
    like $out, qr/GPU driver mode 'operator' — OCP has no AMD operator and installs no AMD driver: the amdgpu driver must already be on this host/,
        'it says the driver has to be there already';

    local $VERIFY = sub { +{ ok => 0, gpus => [] } };
    ($labels, $out) = install_amd_on(detected(amd => [ $W7900 ]), gpu_driver => 'operator');
    is_deeply $labels, [ $PRESENT ], 'no driver there yet: marked, no gfx target';
    like $out, qr/^\[WARN\] the AMD GPU driver did not verify on this host -- with gpu\.driver 'operator' it is yours to install/m,
        'and whose the driver is';
};

# Under operator the detection is there for the AMD labels only (it did not
# run there before k249), so a sysfs it cannot read must not stop the join of
# an NVIDIA operator-mode node. Under host it stays a failure.
my $SYSFS_DIES = "GPU detection from sysfs: could not read /sys/bus/pci/devices on the host (exit 3)\n"
               . "  ls: cannot access '/sys/bus/pci/devices'\n";

subtest 'a detection that dies: a warning under operator, the node joins without AMD labels' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_DIE{'Rex::GPU::Detect::Sysfs::detect'} = $SYSFS_DIES;
    my ($labels, $out) = (undef, '');
    my $ok = eval {
        local *STDOUT;
        open STDOUT, '>', \$out or die $!;
        $labels = OCPTest::Rexfile->task('detect_gpu')->({ gpu_driver => 'operator' });
        1;
    };
    ok $ok, 'detect_gpu does not die' or diag $@;
    is_deeply $labels, [], 'no labels';
    my @warn = grep { /^\[WARN\]/ } split /\n/, $out;
    is_deeply \@warn,
        [ "[WARN] GPU detection failed under gpu.driver 'operator': GPU detection from sysfs: could not read "
          . "/sys/bus/pci/devices on the host (exit 3); ls: cannot access '/sys/bus/pci/devices' -- "
          . "AMD GPU labels not set, the node joins without AMD labels" ],
        'one [WARN] line, with the library\'s error';

    for my $task (qw( install_rke2_agent install_k3s_server )) {
        OCPTest::Rexfile->reset;
        local $OCPTest::Rexfile::LIB_DIE{'Rex::GPU::Detect::Sysfs::detect'} = $SYSFS_DIES;
        local $OCPTest::Rexfile::FOLLOW{detect_gpu} = 1;
        ok eval { OCPTest::Rexfile->run_task($task, { token => 't', server => 'https://x:9345', gpu_driver => 'operator' }); 1 },
            "$task under operator: the install goes on" or diag $@;
        my $lib = $task =~ /agent/ ? 'Rex::Rancher::Agent::install_agent' : 'Rex::Rancher::Server::install_server';
        my $o = OCPTest::Rexfile->lib_opts($lib);
        ok $o, "$task under operator: $lib runs";
        ok !exists $o->{node_labels}, "$task under operator: without GPU labels";
    }
};

subtest 'a detection that dies: still a failure under host' => sub {
    for my $params ({}, { gpu_driver => 'host' }) {
        my $label = %$params ? 'gpu_driver host' : 'nothing passed';
        OCPTest::Rexfile->reset;
        local $OCPTest::Rexfile::LIB_DIE{'Rex::GPU::Detect::Sysfs::detect'} = $SYSFS_DIES;
        my $out = '';
        my $ok = eval {
            local *STDOUT;
            open STDOUT, '>', \$out or die $!;
            OCPTest::Rexfile->task('detect_gpu')->($params);
            1;
        };
        ok !$ok, "$label: detect_gpu dies";
        like $@, qr/could not read \/sys\/bus\/pci\/devices/, "$label: with the library's reason";
        unlike $out, qr/\[WARN\] GPU detection failed/, "$label: not turned into a warning";

        OCPTest::Rexfile->reset;
        local $OCPTest::Rexfile::LIB_DIE{'Rex::GPU::Detect::Sysfs::detect'} = $SYSFS_DIES;
        local $OCPTest::Rexfile::FOLLOW{detect_gpu} = 1;
        ok !eval { OCPTest::Rexfile->run_task('install_rke2_agent', { token => 't', server => 'https://x:9345', %$params }); 1 },
            "$label: install_rke2_agent dies";
        is count('Rex::Rancher::Agent::install_agent'), 0, "$label: before the agent is installed";
    }
};

subtest 'gpu.driver operator: the integrated gate holds there too' => sub {
    my ($labels, $out) = install_amd_on(detected(amd => [ $STRIX ]), gpu_driver => 'operator');
    is_deeply $labels, [], 'without gpu_amd_integrated: no labels';
    is count('Rex::GPU::AMD::verify_amd'), 0, 'nothing asked';
    like $out, qr/integrated AMD GPU 0000:c5:00\.0 \(gfx1151\) not set up/, 'the one line';

    ($labels) = install_amd_on(detected(amd => [ $STRIX ]), gpu_driver => 'operator', gpu_amd_integrated => 1);
    is_deeply $labels, [ $PRESENT, "$GFX=gfx1151" ], 'with it: labelled';
    is count('Rex::GPU::AMD::install_driver'), 0, 'still no driver install';
};

# --- detect_gpu: both vendors, the parameters on the way ----------------------

# detect_gpu, with install_nvidia and install_amd behind it, on a host whose
# detection says $detected. Returns (labels, output).
sub detect_gpu_on {
    my ($detected, %params) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::Detect::Sysfs::detect'} = sub { $detected };
    local $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::AMD::verify_amd'} = \&verify_works;
    local $OCPTest::Rexfile::FOLLOW{install_nvidia} = 1;
    local $OCPTest::Rexfile::FOLLOW{install_amd}    = 1;
    my $code = OCPTest::Rexfile->task('detect_gpu');
    my ($labels, $out) = (undef, '');
    { local *STDOUT; open STDOUT, '>', \$out or die $!; $labels = $code->({ %params }); }
    return ($labels, $out);
}

subtest 'NVIDIA and AMD on one host: both drivers, NVIDIA first' => sub {
    my ($labels) = detect_gpu_on(detected(nvidia => [ $GB10 ], amd => [ $W7900 ]));
    is count('Rex::GPU::Detect::Sysfs::detect'), 1, 'the host is read once';
    my $nv  = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::GPU::NVIDIA::install_driver' });
    my $amd = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::GPU::AMD::install_driver' });
    ok $nv >= 0 && $amd > $nv, 'the NVIDIA driver, then the AMD one';
    my ($call) = OCPTest::Rexfile->task_calls('install_amd');
    is $call->{args}[1]{detected}{amd}[0], $W7900, 'install_amd gets what detect_gpu read';
    is_deeply $labels, [ $PRESENT, "$GFX=gfx1100" ], 'detect_gpu returns the AMD labels';
};

subtest 'gpu.driver operator, NVIDIA and AMD: NVIDIA unchanged, AMD labelled' => sub {
    my ($labels, $out) = detect_gpu_on(detected(nvidia => [ $GB10 ], amd => [ $W7900 ]), gpu_driver => 'operator');
    is_deeply [ map { $_->{args}[0] } OCPTest::Rexfile->calls('do_task') ], [], 'no install_nvidia';
    is count('Rex::GPU::NVIDIA::install_driver'), 0, 'no NVIDIA driver';
    is count('Rex::GPU::NVIDIA::install_container_toolkit'), 0, 'no toolkit';
    unlike $out, qr/NVIDIA GPU present/, 'and no word on the NVIDIA card: it is the operator\'s';
    is count('Rex::GPU::AMD::install_driver'), 0, 'no AMD driver either';
    is_deeply $labels, [ $PRESENT, "$GFX=gfx1100" ], 'but the AMD labels';
};

subtest 'gpu_amd_integrated and gpu_driver travel from the install task to install_amd' => sub {
    for my $case (
        [ {},                                               { gpu_driver => 'host',     gpu_amd_integrated => 0 } ],
        [ { gpu_amd_integrated => 1 },                      { gpu_driver => 'host',     gpu_amd_integrated => 1 } ],
        [ { gpu_driver => 'operator', gpu_amd_integrated => 1 }, { gpu_driver => 'operator', gpu_amd_integrated => 1 } ],
    ) {
        my ($extra, $want) = @$case;
        my $label = join(',', map { "$_=$extra->{$_}" } sort keys %$extra) || 'nothing passed';
        OCPTest::Rexfile->reset;
        local $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::Detect::Sysfs::detect'} = sub { detected(amd => [ $STRIX ]) };
        local $OCPTest::Rexfile::FOLLOW{detect_gpu} = 1;
        OCPTest::Rexfile->run_task('install_k3s_agent', { token => 't', server => 'https://x:9345', %$extra });
        my ($detect) = OCPTest::Rexfile->task_calls('detect_gpu');
        my ($amd)    = OCPTest::Rexfile->task_calls('install_amd');
        is $detect->{args}[1]{$_}, $want->{$_}, "$label: detect_gpu gets $_ $want->{$_}" for sort keys %$want;
        is $amd->{args}[1]{$_},    $want->{$_}, "$label: install_amd gets $_ $want->{$_}" for sort keys %$want;
    }
};

# --- the labels reach the registration ------------------------------------------

sub install_on {
    my ($task, $detected, %params) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::Detect::Sysfs::detect'} = sub { $detected };
    local $OCPTest::Rexfile::LIB_CODE{'Rex::GPU::AMD::verify_amd'} = \&verify_works;
    local $OCPTest::Rexfile::FOLLOW{detect_gpu}  = 1;
    local $OCPTest::Rexfile::FOLLOW{install_amd} = 1;
    OCPTest::Rexfile->run_task($task, { token => 't', server => 'https://x:9345', %params });
}

my %INSTALL = (
    install_rke2_agent  => 'Rex::Rancher::Agent::install_agent',
    install_k3s_agent   => 'Rex::Rancher::Agent::install_agent',
    install_rke2_server => 'Rex::Rancher::Server::install_server',
    install_k3s_server  => 'Rex::Rancher::Server::install_server',
);
my %PREFLIGHT = (
    'Rex::Rancher::Agent::install_agent'   => 'Rex::Rancher::Agent::preflight_agent',
    'Rex::Rancher::Server::install_server' => 'Rex::Rancher::Server::preflight_server',
);

for my $task (sort keys %INSTALL) {
    my $lib = $INSTALL{$task};

    subtest "$task: the AMD labels are registered with the node" => sub {
        install_on($task, detected(amd => [ $STRIX ]), gpu_amd_integrated => 1);
        my $o = OCPTest::Rexfile->lib_opts($lib) or return fail("$lib called");
        is_deeply $o->{node_labels}, [ $PRESENT, "$GFX=gfx1151" ], 'node_labels: marker and gfx target';
        my $pre = OCPTest::Rexfile->lib_opts($PREFLIGHT{$lib});
        ok !exists $pre->{node_labels}, 'the checks up front ran before the GPU step, without them';

        install_on($task, detected(amd => [ $STRIX ]), gpu_amd_integrated => 1,
            node_labels => [ 'tier=gpu', "$GFX=gfx1150" ]);
        $o = OCPTest::Rexfile->lib_opts($lib);
        is_deeply $o->{node_labels}, [ 'tier=gpu', "$GFX=gfx1150", $PRESENT ],
            'next to spec.labels, and a key the spec sets keeps the spec\'s value';

        install_on($task, detected(amd => [ $STRIX ]));
        $o = OCPTest::Rexfile->lib_opts($lib);
        ok !exists $o->{node_labels}, 'an iGPU nobody asked for: no node_labels at all, as before';

        install_on($task, detected(nvidia => [ $GB10 ]), node_labels => [ 'tier=gpu' ]);
        $o = OCPTest::Rexfile->lib_opts($lib);
        is_deeply $o->{node_labels}, [ 'tier=gpu' ], 'an NVIDIA node: spec.labels only, as before';
    };
}

# --- what install_amd leaves alone ----------------------------------------------

subtest 'no ROCm, no toolkit, no CDI, no reboot of OCP\'s' => sub {
    my $code = join '', grep { !/^\s*#/ } split /^/, OCPTest::Rexfile->rexfile->slurp_utf8;
    my ($task) = $code =~ /^task "install_amd", sub \{(.*?)^\};/ms;
    ok $task, 'install_amd is there' or return;
    unlike $task, qr/install_rocm/, 'ROCm is the containers\' own';
    unlike $task, qr/toolkit|cdi|containerd/i, 'no container toolkit, CDI or containerd configuration';
    unlike $code, qr/reboot\s*=>\s*1/, 'no reboot anywhere';
    unlike $code, qr/Rex::GPU::AMD::(?!install_driver\b|verify_amd\b)\w+/,
        'of Rex::GPU::AMD only install_driver and verify_amd';
};

# --- the label keys are OCP::Config's -------------------------------------------

# The Rexfile runs under rex without OCP's lib/ and writes the keys out; they
# are $OCP::Config's (k250).
subtest 'the label keys match OCP::Config' => sub {
    use lib 'lib';
    require OCP::Config;
    no warnings 'once';
    my %want = (
        AMD_GPU_PRESENT_LABEL    => $PRESENT,
        AMD_GPU_GFX_TARGET_LABEL => $GFX,
    );
    for my $name (sort keys %want) {
        my $const = do { no strict 'refs'; ${"OCP::Config::$name"} };
        SKIP: {
            skip "\$OCP::Config::$name is not defined (k250)", 1 unless defined $const;
            # The marker constant may be the key or the whole label.
            my ($key) = split /=/, $want{$name}, 2;
            ok $const eq $want{$name} || $const eq $key, "\$OCP::Config::$name ($const)";
        }
    }
};

done_testing;

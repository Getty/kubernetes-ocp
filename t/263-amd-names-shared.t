#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw( path );

use lib 'lib';
use OCP::Config;
use OCP::Cmd::Status;
use OCP::Cmd::Apply::AMDGPU;

#
# k263 (k258's remainder): the names the AMD stack shows in the cluster --
# the device plugin's resource amd.com/gpu, the amd.com/ prefix its mixed
# naming puts partitioned resources under, and gpu.amd.com, the DRA driver's
# name on its ResourceSlices -- live in OCP::Config beside the AMD node
# labels. ocp status (k252) and ocp apply's readiness wait (k251) each held a
# copy of their own.
#
# The claims here:
#   1. OCP::Config carries the three names;
#   2. neither reader holds a copy: no literal of them in their code;
#   3. both read them from OCP::Config at run time.
#

# --- 1. one place -------------------------------------------------------------

subtest 'OCP::Config carries the names' => sub {
    is $OCP::Config::AMD_GPU_RESOURCE,        'amd.com/gpu', 'the device plugin resource';
    is $OCP::Config::AMD_GPU_RESOURCE_PREFIX, 'amd.com/',    'the mixed-naming prefix';
    is $OCP::Config::AMD_GPU_DRA_DRIVER,      'gpu.amd.com', 'the DRA driver name';
    is index($OCP::Config::AMD_GPU_RESOURCE, $OCP::Config::AMD_GPU_RESOURCE_PREFIX), 0,
        'the resource lies under the prefix';
};

# --- 2. no copies -------------------------------------------------------------

# A module's code: POD and comments gone, so prose may name what it reads.
sub code_of {
    my ($file) = @_;
    my $src = path($file)->slurp_utf8;
    $src =~ s/^__END__\n.*\z//ms;
    $src =~ s/^=[a-z].*?^=cut\n//msg;
    $src =~ s/^\s*#.*$//mg;
    return $src;
}

for my $file ('lib/OCP/Cmd/Status.pm', 'lib/OCP/Cmd/Apply/AMDGPU.pm') {
    subtest "$file holds no copy" => sub {
        my $code = code_of($file);
        ok length $code > 1000, 'the code was read';
        for my $name ('amd.com/gpu', 'amd.com/', 'gpu.amd.com') {
            unlike $code, qr/['"]\Q$name\E['"]/, "no literal '$name'";
        }
    };
}

# --- 3. read from OCP::Config --------------------------------------------------

subtest 'ocp status reads them from OCP::Config' => sub {
    my $status = bless {}, 'OCP::Cmd::Status';
    my $node = { status => { allocatable => { 'amd.com/gpu' => 1, 'example.com/gpu' => 2 } } };
    my @slices = (
        { spec => { driver => 'gpu.amd.com',     nodeName => 'n1', pool => { name => 'n1', generation => 1 }, devices => [ 1 ] } },
        { spec => { driver => 'gpu.example.com', nodeName => 'n1', pool => { name => 'n1', generation => 1 }, devices => [ 1, 2 ] } },
    );

    is $status->_amd_gpu_quantity($node, 'allocatable'), 1, 'amd.com/gpu as shipped';
    is_deeply $status->_amd_gpu_slice_devices(\@slices), { n1 => 1 }, 'gpu.amd.com as shipped';

    local $OCP::Config::AMD_GPU_RESOURCE   = 'example.com/gpu';
    local $OCP::Config::AMD_GPU_DRA_DRIVER = 'gpu.example.com';
    is $status->_amd_gpu_quantity($node, 'allocatable'), 2, 'the resource OCP::Config names';
    is_deeply $status->_amd_gpu_slice_devices(\@slices), { n1 => 2 }, 'the driver OCP::Config names';
};

package FakeK8s { sub new { bless {}, shift } sub object_to_struct { $_[1] } }
package FakeApi {
    sub new { my ($class, %o) = @_; bless { %o }, $class }
    sub k8s { FakeK8s->new }
    sub get {
        my ($self, $kind, %o) = @_;
        return { metadata => { generation => 1 }, status => { observedGeneration => 1,
            desiredNumberScheduled => 1, numberReady => 1, updatedNumberScheduled => 1 } }
            if $kind eq 'DaemonSet';
        return { status => { allocatable => $self->{allocatable} } } if $kind eq 'Node';
        die "unexpected get $kind";
    }
}
package FakeApply {
    sub new { my ($class, %o) = @_; bless { %o }, $class }
    sub _crd_get { $_[0]{slices} }
}
package main;

subtest 'ocp apply\'s readiness wait reads them from OCP::Config' => sub {
    my $nodes = [ { name => 'n1' } ];
    my $plugin = sub {
        my ($naming, %alloc) = @_;
        return OCP::Cmd::Apply::AMDGPU::not_ready(FakeApply->new, FakeApi->new(allocatable => \%alloc),
            'device_plugin', { resource_naming => $naming }, $nodes);
    };
    my $dra = sub {
        my ($driver) = @_;
        my $slices = { items => [ { spec => { driver => $driver, nodeName => 'n1' } } ] };
        return OCP::Cmd::Apply::AMDGPU::not_ready(FakeApply->new(slices => $slices), FakeApi->new,
            'dra', {}, $nodes);
    };

    is $plugin->(single => 'amd.com/gpu' => 1), undef, 'amd.com/gpu as shipped: ready';
    is $plugin->(mixed => 'amd.com/gpu-partition' => 1), undef, 'amd.com/* as shipped: ready';
    is $dra->('gpu.amd.com'), undef, 'gpu.amd.com as shipped: ready';

    local $OCP::Config::AMD_GPU_RESOURCE        = 'example.com/gpu';
    local $OCP::Config::AMD_GPU_RESOURCE_PREFIX = 'example.com/';
    local $OCP::Config::AMD_GPU_DRA_DRIVER      = 'gpu.example.com';
    is $plugin->(single => 'example.com/gpu' => 1), undef, 'the resource OCP::Config names: ready';
    like $plugin->(single => 'amd.com/gpu' => 1), qr/shows no example\.com\/gpu in status\.allocatable/,
        'and the shipped one no longer counts, said in the configured name';
    is $plugin->(mixed => 'example.com/gpu-partition' => 1), undef, 'the prefix OCP::Config names: ready';
    is $dra->('gpu.example.com'), undef, 'the driver OCP::Config names: ready';
    like $dra->('gpu.amd.com'), qr/no ResourceSlice of driver gpu\.example\.com for node 'n1'/,
        'and the shipped one no longer counts';
};

done_testing;

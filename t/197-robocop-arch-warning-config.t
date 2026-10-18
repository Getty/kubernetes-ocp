#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny;
use OCP;
use OCP::Config;

# k197: the robocop image is amd64 only. When no control plane is amd64
# (every one a Hetzner CAX/ARM type) and robocop is on, config says so up
# front -- a warning, never a refusal.

local @ARGV = ();
my $ocp = OCP->new;
my $tmp = Path::Tiny->tempdir;
my $n   = 0;

sub cfg {
    my (%spec) = @_;
    my $f = $tmp->child('ocp' . ++$n . '.yaml');
    $ocp->dump_file($f->stringify, { name => 'test', %spec });
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

sub hz { { provider => 'hetzner', location => 'fsn1', server_type => $_[0] } }

subtest 'CAX control plane, robocop auto-on by hetzner: warns' => sub {
    my $w = cfg(control_planes => hz('cax21'))->robocop_arch_warning;
    ok defined $w, 'a warning';
    like $w, qr/^\[WARN\]/, 'starts with [WARN]';
    like $w, qr/amd64/, 'names amd64';
    like $w, qr/Pending/, 'names the Pending pod';
    like $w, qr/robocop: false/, 'names the way out: robocop: false';
    like $w, qr/amd64.*control.plane|control.plane.*amd64/i, 'or an amd64 control plane';
    like $w, qr/join/i, 'names the worker joins';
};

subtest 'CAX control plane with robocop: false: nothing' => sub {
    is cfg(robocop => 0, control_planes => hz('cax21'))->robocop_arch_warning, undef, 'undef';
};

subtest 'amd64 control plane: nothing' => sub {
    is cfg(control_planes => hz('cpx31'))->robocop_arch_warning, undef, 'cpx';
    is cfg(control_planes => hz('cx32'))->robocop_arch_warning,  undef, 'cx';
};

subtest 'mixed CAX and CPX control planes: nothing' => sub {
    is cfg(control_planes => [ hz('cax21'), hz('cpx31') ])->robocop_arch_warning, undef, 'undef';
};

subtest 'all control planes CAX (array form): warns' => sub {
    like cfg(control_planes => [ hz('cax21'), hz('CAX31') ])->robocop_arch_warning,
        qr/^\[WARN\]/, 'warns, case-insensitive';
};

done_testing;

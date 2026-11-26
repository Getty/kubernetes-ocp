#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use Cwd qw( getcwd );
use Path::Tiny ();

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Health;
use OCP::Config;

#
# k415 (maintainer decision 2026-11-08): every [WARN] of the apply lane goes
# to STDERR, the robocop arch warning included -- STDOUT is the narrative,
# STDERR everything that went wrong (.claude/rules/ocp-rules.md). This file
# holds the arch warning at both of its places (the start of ocp apply and the
# health finisher) and the health [WARN]s. The other lines are held where
# their harness lives: t/231 (Health::print, warn_unlisted_failed_ocpnodes
# counted), t/38 (could not verify cluster health), t/54 (deploy-image
# ad-hoc override), t/374 and t/381 (host probes skipped).
#

$SIG{ALRM} = sub { die "k415 fuse: the test ran out of time\n" };
alarm 120;

my @KEEP;

sub project {
    my ($yaml) = @_;
    my $dir = Path::Tiny->tempdir;
    push @KEEP, $dir;
    $dir->child('ocp.yaml')->spew_utf8("name: k415\n$yaml");
    return $dir;
}

sub capture_both {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my $rc;
    {
        local *STDOUT = $o;
        local *STDERR = $e;
        $rc = $code->();
    }
    return ($out, $err, $rc);
}

# --- 1. the start of ocp apply ------------------------------------------------

# Runs ocp apply in $dir up to the step after the warnings, where a stub stops
# it (the t/325 harness): { out, err, died, warnings }.
sub apply_in {
    my ($dir) = @_;
    local @ARGV = ();
    my $apply = OCP::Cmd::Apply->new(command_chain => [ OCP->new ]);
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my ($out, $err) = capture_both(sub {
        no warnings 'redefine';
        local *OCP::Cmd::Apply::SopsRepair::repair_sops_files = sub { die "k415: stop\n" };
        eval { $apply->execute([], []) };
        return;
    });
    my $died = $@;
    chdir $cwd or die "chdir back: $!";
    return { out => $out, err => $err, died => $died, warnings => $apply->{_apply_warnings} // [] };
}

my $CAX = "control_planes:\n  provider: hetzner\n  location: fsn1\n  server_type: cax21\n";

subtest 'ocp apply, every control plane ARM: the arch [WARN] on STDERR, counted' => sub {
    my $r = apply_in(project($CAX));
    is $r->{died}, "k415: stop\n", 'ran up to the stub';
    like $r->{err}, qr/^\[WARN\] robocop image is amd64 only, but every control plane is an ARM server/m,
        'the line, on STDERR';
    unlike $r->{out}, qr/amd64 only/, 'not on STDOUT';
    like $r->{out}, qr/^Cluster: k415$/m, 'STDOUT keeps the progress';
    is_deeply $r->{warnings}, [ 'robocop arch' ], 'in {_apply_warnings}: WITH WARNINGS';
};

subtest 'ocp apply, robocop off: nothing' => sub {
    my $r = apply_in(project("robocop: false\n$CAX"));
    is $r->{died}, "k415: stop\n", 'ran up to the stub';
    is $r->{err}, '', 'nothing on STDERR';
    is_deeply $r->{warnings}, [], 'nothing counted';
};

# --- 2. the health finisher ---------------------------------------------------

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeApi  {
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list {
        my ($s, $kind) = @_;
        die "connection refused\n" if $s->{explode};
        return FakeList->new($s->{ $kind eq 'Node' ? 'nodes' : 'pods' } // []);
    }
}
package FakeConfig {
    sub new             { my ($c, %a) = @_; bless {%a}, $c }
    sub name            { 'k415' }
    sub api_url         { "https://$_[1]:6443" }
    sub robocop_enabled { $_[0]{robocop} }
}
package main;

sub arm_cp {
    return { metadata => { name => 'police1', labels => {
        'kubernetes.io/arch' => 'arm64', 'node-role.kubernetes.io/control-plane' => 'true' } } };
}

sub finish_with {
    my (%a) = @_;
    my $apply = bless {}, 'OCP::Cmd::Apply';
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_stamp_ocp_version = sub { 1 };
    my ($out, $err, $rc) = capture_both(sub {
        $apply->_finish_apply(config => FakeConfig->new(robocop => $a{robocop}), api => $a{api});
    });
    return { out => $out, err => $err, rc => $rc, warnings => $apply->{_apply_warnings} // [] };
}

subtest 'finish: no amd64 control-plane Node, robocop on: the arch [WARN] on STDERR, counted' => sub {
    # The apply has no ->config: before k415 the eval swallowed that, and
    # this line never came at all. It reads the config finish is handed.
    my $r = finish_with(robocop => 1, api => FakeApi->new(nodes => [ arm_cp() ]));
    like $r->{err}, qr/^  \[WARN\] robocop image is amd64 only, but no control-plane Node is amd64/m,
        'the line, on STDERR';
    unlike $r->{out}, qr/amd64 only/, 'not on STDOUT';
    is_deeply $r->{warnings}, [ 'robocop arch' ], 'counted';
    like $r->{out}, qr/WITH WARNINGS/, 'the banner says so';
    is $r->{rc}, 0, 'exit stays 0';
};

subtest 'finish: robocop off: no arch line' => sub {
    my $r = finish_with(robocop => 0, api => FakeApi->new(nodes => [ arm_cp() ]));
    unlike $r->{err}, qr/amd64 only/, 'nothing on STDERR about it';
    is_deeply $r->{warnings}, [], 'nothing counted';
    like $r->{out}, qr/SUCCESSFULLY/, 'the plain banner';
};

subtest 'finish: a health check that cannot run is a [WARN] on STDERR' => sub {
    my $r = finish_with(robocop => 0, api => FakeApi->new(explode => 1));
    like $r->{err}, qr/^  \[WARN\] could not verify cluster health: connection refused$/m, 'on STDERR';
    unlike $r->{out}, qr/could not verify/, 'not on STDOUT';
    is $r->{rc}, 0, 'and still not a failed apply';
};

subtest 'Health::print: a warning pod is [WARN] on STDERR, a starting one stays narrative' => sub {
    my $health = { critical => [],
                   warnings => [ { namespace => 'ocp-system', name => 'robocop-x', reason => 'slow' } ],
                   starting => [ { namespace => 'default', name => 'web-1' } ] };
    my ($out, $err) = capture_both(sub { OCP::Cmd::Apply::Health::print(undef, $health) });
    is $err, "  [WARN] ocp-system/robocop-x — slow\n", 'the [WARN] on STDERR';
    unlike $out, qr/\[WARN\]/, 'not on STDOUT';
    like $out, qr{^  \[\.\.\] default/web-1 — still starting$}m, 'a starting pod is progress, on STDOUT';
};

alarm 0;
done_testing;

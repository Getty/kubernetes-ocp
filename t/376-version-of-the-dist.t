#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';
use OCP;
use OCP::Config;
use OCP::Cmd::Apply::Validate;
use OCP::Cmd::DeployImage;
use OCP::Cmd::DeployRobocop;
use OCP::Cmd::Destroy;
use OCP::Cmd::Kubeconfig;
use OCP::Cmd::Node::Add;
use OCP::Cmd::Status;
use OCP::Cmd::Update;

#
# k376: a kubernetes.version that is a release of the other distribution is a
# line of validate()'s. v1.36.4+k3s1 under dist: rke2 (or under no dist, which
# is rke2), or v1.36.4+rke2r1 under dist: k3s, went to the installer as is,
# which fails on it only on the machine -- after a server was bought. k355
# checked that the version is a string, not whose release it is.
#
# The maintainer's decision (2026-11-06): only the other distribution's suffix
# is refused. A version without one (v1.31.3, as t/04 writes it) passes, and
# nothing else about the version's form is checked.
#
# The claims:
#   1. +k3sN under dist: rke2, +rke2rN under dist: k3s: one line, which names
#      the key, the value, whose release it is, the dist, and the two fixes;
#   2. under no dist the same, the dist said to be rke2 because it is not set;
#   3. what passes: each dist's own release, a version without a suffix under
#      either dist or none, empty, null, and a form OCP does not judge;
#   4. beside a dist that is none (rke3, a list, a boolean) only the dist's
#      line: whose release the version must be is not known;
#   5. version refuses it in validate()'s words; kubernetes, distribution
#      and supervisor_port read on -- the line is version's alone;
#   6. the line is at the path kubernetes: every command that declares it
#      refuses it before it runs, ocp apply lists it before it touches a host,
#      and a command that does not read kubernetes: is not held up by it.
#

local @ARGV = ();
my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);
my $local  = { provider => 'local' };

# Through a file, as ocp reads it.
sub config_for {
    my ($k8s) = @_;
    my $f = path($tmpdir)->child('c' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8(YAML::XS::Dump({ name => 'k376', control_planes => $local, kubernetes => $k8s }));
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

sub config_from_text {
    my ($text) = @_;
    my $f = path($tmpdir)->child('t' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8("name: k376\ncontrol_planes:\n  provider: local\n$text");
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

# A die comes back as a line of its own, so each claim fails on its own.
sub errors_for {
    my @e = eval { config_for(@_)->validate };
    return $@ ? ("validate() died: $@") : @e;
}

my $K3S_UNDER_RKE2 = "kubernetes.version: 'v1.36.4+k3s1' is a release of k3s, but kubernetes.dist is rke2; "
                   . 'write a release of rke2 (like v1.36.4+rke2r1), or set kubernetes.dist to k3s';
my $K3S_UNDER_NONE = "kubernetes.version: 'v1.36.4+k3s1' is a release of k3s, but kubernetes.dist is rke2 "
                   . '(not set, the default); write a release of rke2 (like v1.36.4+rke2r1), or set '
                   . 'kubernetes.dist to k3s';
my $RKE2_UNDER_K3S = "kubernetes.version: 'v1.31.3+rke2r2' is a release of rke2, but kubernetes.dist is k3s; "
                   . 'write a release of k3s (like v1.36.4+k3s1), or set kubernetes.dist to rke2';

# --- 1. the other distribution's release ---------------------------------------------------------

subtest 'a release of the other distribution is one line' => sub {
    is_deeply [ errors_for({ dist => 'rke2', version => 'v1.36.4+k3s1' }) ], [ $K3S_UNDER_RKE2 ],
        'v1.36.4+k3s1 under dist: rke2';
    is_deeply [ errors_for({ dist => 'k3s', version => 'v1.31.3+rke2r2' }) ], [ $RKE2_UNDER_K3S ],
        'v1.31.3+rke2r2 under dist: k3s';
    is_deeply [ config_from_text("kubernetes:\n  dist: rke2\n  version: v1.36.4+k3s1\n")->validate ],
        [ $K3S_UNDER_RKE2 ], 'as typed';
    is_deeply [ errors_for({ dist => 'k3s', version => 'v1.30.0-rc1+rke2r12' }) ],
        [ "kubernetes.version: 'v1.30.0-rc1+rke2r12' is a release of rke2, but kubernetes.dist is k3s; "
        . 'write a release of k3s (like v1.36.4+k3s1), or set kubernetes.dist to rke2' ],
        'a pre-release with a revision of two digits';
    is_deeply [ errors_for({ dist => 'rke2', version => 'v1.36.4+k3s1', cni => 'cilium' }) ],
        [ $K3S_UNDER_RKE2, 'kubernetes.cni: unknown key (must be dist or version)' ],
        'beside a key nothing reads: a line each, in validate()\'s order';
};

# --- 2. no dist --------------------------------------------------------------------------------------

subtest 'under no dist, which is rke2' => sub {
    is_deeply [ errors_for({ version => 'v1.36.4+k3s1' }) ], [ $K3S_UNDER_NONE ], 'kubernetes: { version: ... }';
    is_deeply [ errors_for({ dist => undef, version => 'v1.36.4+k3s1' }) ], [ $K3S_UNDER_NONE ], 'dist: null';
    is_deeply [ errors_for({ version => 'v1.36.4+rke2r1' }) ], [], 'its own release passes';
};

# --- 3. what passes ------------------------------------------------------------------------------------

subtest 'what passes: its own release, no suffix, empty, and forms OCP does not judge' => sub {
    my %own = (rke2 => 'v1.36.4+rke2r1', k3s => 'v1.36.4+k3s1');
    for my $dist (sort keys %own) {
        is_deeply [ errors_for({ dist => $dist, version => $own{$dist} }) ], [], "$own{$dist} under dist: $dist";
    }
    for my $dist ('rke2', 'k3s', undef) {
        my $under = defined $dist ? "dist: $dist" : 'no dist';
        for my $v ('v1.31.3', '1.31.3', '', undef, 'latest', 'v1.36.4+k3s', 'v1.36.4+rke2r', 'v1.36.4+k3s1-x',
                   'v1.36.4+K3S1') {
            is_deeply [ errors_for({ (defined $dist ? (dist => $dist) : ()), version => $v }) ], [],
                'version: ' . (defined $v ? "'$v'" : 'null') . " under $under passes";
        }
    }
};

# --- 4. a dist that is none ------------------------------------------------------------------------

subtest 'beside a dist that is none, only its own line' => sub {
    is_deeply [ errors_for({ dist => 'rke3', version => 'v1.36.4+k3s1' }) ],
        [ "kubernetes.dist: invalid value 'rke3' (must be rke2 or k3s)" ], 'dist: rke3';
    is_deeply [ errors_for({ dist => [ 'rke2' ], version => 'v1.36.4+k3s1' }) ],
        [ 'kubernetes.dist: invalid value a list (must be rke2 or k3s)' ], 'dist: a list';
    is_deeply [ config_from_text("kubernetes:\n  dist: true\n  version: v1.36.4+rke2r1\n")->validate ],
        [ 'kubernetes.dist: invalid value true (must be rke2 or k3s)' ], 'dist: true';
};

# --- 5. the accessors -------------------------------------------------------------------------------

subtest 'version refuses it in validate()\'s words; the rest read on' => sub {
    for my $case ([ { dist => 'rke2', version => 'v1.36.4+k3s1' }, 'rke2', 9345 ],
                  [ { version => 'v1.36.4+k3s1' },                  'rke2', 9345 ],
                  [ { dist => 'k3s', version => 'v1.31.3+rke2r2' }, 'k3s',  6443 ]) {
        my ($k8s, $dist, $port) = @$case;
        my $c     = config_for($k8s);
        my @lines = $c->validate;
        my $what  = join(', ', map { "$_: " . ($k8s->{$_} // 'null') } sort keys %$k8s);
        is scalar(@lines), 1, "$what -- one line" or diag explain \@lines;

        ok !defined eval { $c->version }, "version refuses $what";
        is $@, "$lines[0]\n", "... in validate()'s words";

        my %got = map { my $m = $_; ($m => scalar eval { $c->$m }) } qw( distribution supervisor_port );
        is $@, '', "distribution and supervisor_port read on ($what)";
        is_deeply \%got, { distribution => $dist, supervisor_port => $port }, '... as set';
        is_deeply eval { $c->kubernetes }, $k8s, "kubernetes reads on ($what)";
    }
    is config_for({ dist => 'k3s', version => 'v1.36.4+k3s1' })->version, 'v1.36.4+k3s1',
        'its own release: version reads it as before';
    is config_for({ dist => 'k3s', version => 'v1.31.3' })->version, 'v1.31.3', 'no suffix: as before';
};

# --- 6. the commands ---------------------------------------------------------------------------------

subtest 'at the path kubernetes, so the commands that read it refuse it' => sub {
    my $c = config_for({ dist => 'rke2', version => 'v1.36.4+k3s1' });
    is_deeply [ $c->spec_errors('kubernetes') ], [ $K3S_UNDER_RKE2 ], 'spec_errors(kubernetes) has it';
    is_deeply [ $c->spec_errors('name', 'network', 'network.pod_cidr', 'ssh', 'control_planes[*]') ], [],
        'no other path does';

    my $file = $c->file;
    for my $class (qw( Status Update Node::Add DeployRobocop DeployImage )) {
        my $cmd = "OCP::Cmd::$class"->new;
        ok !eval { $cmd->refuse_spec_errors($c); 1 }, $cmd->_command_words . ' refuses it';
        is $@, "$file has 1 error:\n  - $K3S_UNDER_RKE2\n" . 'Nothing was done: ' . $cmd->_command_words
            . " checks what it reads of $file before it asks for a PIN or touches the cluster or a machine. "
            . "Fix the line above and run it again.\n", '... before it runs, in the one refusal text';
    }

    ok !eval { OCP::Cmd::Apply::Validate::refuse_invalid_config($c); 1 }, 'ocp apply refuses it';
    like $@, qr/\A\Q$file\E has 1 error:\n  - \Q$K3S_UNDER_RKE2\E\nNothing was done: ocp apply checks /,
        '... before it touches a host or the cluster';

    for my $cmd (OCP::Cmd::Kubeconfig->new, OCP::Cmd::Destroy->new) {
        is eval { $cmd->refuse_spec_errors($c) }, 1, $cmd->_command_words . ', which does not read kubernetes:, runs'
            or diag $@;
    }
};

done_testing;

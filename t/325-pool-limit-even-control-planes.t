#!/usr/bin/env perl
# karr k325 -- two questions k315 left open, settled by the maintainer
# (2026-11-06):
#
#   * a counted worker pool -- every provider but ssh, nodes: N -- has at most
#     10 machines ($OCP::Config::MAX_WORKER_POOL_NODES). validate() refuses 11
#     and more with a line that names the limit and the docs. An ssh pool
#     lists its hosts, is not counted, and has no such limit. Before, any
#     whole number passed: nodes: 1000000000000 went on to worker_ocpnodes,
#     which built OCPNodes until memory ran out (k361's notes).
#   * the line is at workers[N].nodes, so every command that walks the pools
#     without validate() -- ocp keys operator add|rm, ocp keys secure
#     --drop-bootstrap, ocp node ls --json, and ocp status, which counts them
#     -- refuses it before it reads the count. ocp destroy does not read a
#     count and is not stopped by it: it is the way out.
#   * an even control-plane count (2, 4, 6) is no refusal but a [WARN] that
#     ocp apply prints on STDERR and counts in {_apply_warnings}
#     (even_control_planes_warning, after robocop_arch_warning). rke2 only:
#     k3s deploys only the first control plane.

use strict;
use warnings;
use Test::More;

use Cwd qw( getcwd );
use Path::Tiny ();

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Validate;
use OCP::Cmd::Destroy;
use OCP::Cmd::Keys::Operator::Add;
use OCP::Cmd::Keys::Operator::Rm;
use OCP::Cmd::Keys::Secure;
use OCP::Cmd::Node::Ls;
use OCP::Cmd::Status;
use OCP::Config;

$SIG{ALRM} = sub { die "k325 fuse: the test ran out of time\n" };
alarm 120;

my @KEEP;

# ocp.yaml as typed, in a project dir of its own.
sub project {
    my ($yaml) = @_;
    my $dir = Path::Tiny->tempdir;
    push @KEEP, $dir;
    $dir->child('ocp.yaml')->spew_utf8("name: k325\n$yaml");
    return $dir;
}

sub config_of {
    my ($yaml) = @_;
    return OCP::Config->new(file => project($yaml)->child('ocp.yaml')->stringify);
}

my $CP = "control_planes:\n  provider: ssh\n  host: cp.k325.test\n";

sub pool {
    my ($provider, $nodes, $name) = @_;
    $name //= 'big';
    return "  - name: $name\n    provider: $provider\n"
        . ($provider eq 'hetzner' ? "    server_type: cpx22\n" : '')
        . "    nodes: $nodes\n";
}

sub over_line {
    my ($name, $n) = @_;
    return "worker pool '$name': nodes must be at most 10, not '$n'; "
        . "10 machines is OCP's limit for a pool for now (see docs/configuration.md)";
}

# --- 1. a counted pool holds at most 10 ------------------------------------------

subtest 'the limit is 10' => sub {
    no warnings 'once';
    is $OCP::Config::MAX_WORKER_POOL_NODES, 10, '$MAX_WORKER_POOL_NODES';
};

subtest 'a counted pool of up to 10 passes' => sub {
    for my $provider (qw( hetzner local )) {
        for my $n (0, 1, 10) {
            is_deeply [ config_of($CP . "workers:\n" . pool($provider, $n))->validate ], [],
                "$provider, nodes: $n";
        }
    }
};

subtest 'a counted pool of 11 and more is refused, with the limit and the docs' => sub {
    for my $case ([ hetzner => 11 ], [ local => 11 ], [ hetzner => 100 ],
                  [ hetzner => '1000000000000' ]) {
        my ($provider, $n) = @$case;
        is_deeply [ config_of($CP . "workers:\n" . pool($provider, $n))->validate ],
            [ over_line('big', $n) ], "$provider, nodes: $n: the one line";
    }
};

subtest 'an ssh pool lists its hosts and is not counted' => sub {
    my $hosts = join ', ', map { "w$_.k325.test" } 1 .. 11;
    is_deeply [ config_of($CP . "workers:\n  - name: s\n    provider: ssh\n    nodes: [ $hosts ]\n")
        ->validate ], [], 'eleven hosts pass';
};

subtest 'the line is at the pool\'s nodes' => sub {
    my $config = config_of($CP . "workers:\n" . pool(hetzner => 3, 'small') . pool(hetzner => 11));
    is_deeply [ $config->spec_errors('workers[2].nodes') ], [ over_line('big', 11) ],
        'workers[2].nodes';
    is_deeply [ $config->spec_errors('workers[1].nodes') ], [], 'not the first pool\'s';
};

# --- 2. the commands that walk the pools without validate() ----------------------

subtest 'every command that reads a pool\'s count refuses it before it reads it' => sub {
    my $dir = project($CP . "workers:\n" . pool(hetzner => '1000000000000'));
    $dir->child('keys.yaml')->spew_utf8("{}\n");    # keys secure --drop-bootstrap reads the machines
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);

    my $line = over_line('big', '1000000000000');
    for my $case ([ 'ocp keys operator add'            => 'OCP::Cmd::Keys::Operator::Add' ],
                  [ 'ocp keys operator rm'             => 'OCP::Cmd::Keys::Operator::Rm' ],
                  [ 'ocp keys secure --drop-bootstrap' => OCP::Cmd::Keys::Secure->new(drop_bootstrap => 1) ],
                  [ 'ocp node ls --json'               => OCP::Cmd::Node::Ls->new(json => 1) ],
                  [ 'ocp status'                       => 'OCP::Cmd::Status' ]) {
        my ($what, $cmd) = @$case;
        ok !eval { $cmd->refuse_spec_errors($config); 1 }, "$what: refused";
        like $@, qr/^  - \Q$line\E$/m, "$what: in validate()'s words";
    }
};

# The gate runs before execute (OCP::Role::Cmd), so before execute's walk.
subtest 'ocp keys operator add: refused by the gate in front of execute' => sub {
    my $dir = project($CP . "workers:\n" . pool(hetzner => '1000000000000'));
    local @ARGV = ();
    my $ocp = OCP->new;
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my $ok = eval {
        no warnings 'redefine';
        local *OCP::Cmd::Apply::CR::worker_ocpnodes = sub { die "k325: walked\n" };
        local *OCP::Password::prompt_password       = sub { die "k325: prompted\n" };
        OCP::Cmd::Keys::Operator::Add->new(command_chain => [ $ocp ], name => 'second')->execute([], []);
        1;
    };
    my $died = $@;
    chdir $cwd or die "chdir back: $!";
    ok !$ok, 'refused';
    like $died, qr/^  - \Q${\ over_line('big', '1000000000000')}\E$/m, 'with the line';
    like $died, qr/^Nothing was done: ocp keys operator add checks what it reads/m,
        'by the gate, before the command ran';
};

subtest 'ocp destroy is not stopped by a pool count' => sub {
    my $config = config_of($CP . "workers:\n" . pool(hetzner => 11));
    is(OCP::Cmd::Destroy->refuse_spec_errors($config), 1, 'destroy reads past it');
};

subtest 'ocp apply\'s validate gate refuses it' => sub {
    my $config = config_of($CP . "workers:\n" . pool(local => 11, 'lp'));
    ok !eval { OCP::Cmd::Apply::Validate::refuse_invalid_config($config); 1 }, 'refused';
    like $@, qr/^  - \Q${\ over_line('lp', 11)}\E$/m, 'with the line';
};

# --- 3. an even control-plane count ----------------------------------------------

sub cp_list {
    my ($n, $dist) = @_;
    return (defined $dist ? "kubernetes:\n  dist: $dist\n" : '')
        . "control_planes:\n" . join('', map { "  - provider: ssh\n    host: cp$_.k325.test\n" } 1 .. $n);
}

sub cp_nodes {
    my ($n) = @_;
    return "control_planes:\n  provider: hetzner\n  server_type: cpx22\n  location: fsn1\n  nodes: $n\n";
}

my %EVEN = (
    2 => '[WARN] 2 control planes: each is an etcd member and etcd needs a majority of them up '
       . '(its quorum), so 2 tolerate no more failures than 1 does; add one or remove one, for 3 or 1',
    4 => '[WARN] 4 control planes: each is an etcd member and etcd needs a majority of them up '
       . '(its quorum), so 4 tolerate no more failures than 3 do; add one or remove one, for 5 or 3',
    6 => '[WARN] 6 control planes: each is an etcd member and etcd needs a majority of them up '
       . '(its quorum), so 6 tolerate no more failures than 5 do; add one or remove one, for 7 or 5',
);

subtest 'an even count on rke2: the line, counted either way' => sub {
    for my $n (sort keys %EVEN) {
        my $list = config_of(cp_list($n));
        is_deeply [ $list->validate ], [], "list of $n: validate() passes it";
        is $list->even_control_planes_warning, $EVEN{$n}, "list of $n: the line";
        is config_of(cp_nodes($n))->even_control_planes_warning, $EVEN{$n}, "nodes: $n: the line";
    }
    is config_of(cp_list(4, 'rke2'))->even_control_planes_warning, $EVEN{4}, 'dist: rke2 set';
};

subtest 'an odd count: nothing' => sub {
    for my $n (1, 3, 5, 7) {
        is config_of(cp_list($n))->even_control_planes_warning, undef, "list of $n";
        is config_of(cp_nodes($n))->even_control_planes_warning, undef, "nodes: $n";
    }
    is config_of("control_planes:\n  provider: ssh\n  host: cp.k325.test\n")->even_control_planes_warning,
        undef, 'one control plane, no nodes:';
};

subtest 'k3s: nothing, it deploys only the first control plane' => sub {
    for my $n (2, 4) {
        is config_of(cp_list($n, 'k3s'))->even_control_planes_warning, undef, "list of $n";
    }
};

subtest 'a count validate() refuses: no advice past the bound' => sub {
    is config_of(cp_list(8))->even_control_planes_warning, undef, 'a list of 8';
    is config_of("control_planes: []\n")->even_control_planes_warning, undef, 'an empty list';
};

# --- 4. ocp apply prints it, on STDERR ---------------------------------------------

# Runs ocp apply in $dir up to the step after the warnings, where a stub stops
# it: { out, err, died, warnings }.
sub apply_in {
    my ($dir) = @_;
    local @ARGV = ();
    my $apply = OCP::Cmd::Apply->new(command_chain => [ OCP->new ]);
    my ($out, $err) = ('', '');
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    {
        no warnings 'redefine';
        local *OCP::Cmd::Apply::SopsRepair::repair_sops_files = sub { die "k325: stop\n" };
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        eval { $apply->execute([], []) };
    }
    my $died = $@;
    chdir $cwd or die "chdir back: $!";
    return { out => $out, err => $err, died => $died, warnings => $apply->{_apply_warnings} // [] };
}

subtest 'ocp apply, 4 control planes: [WARN] on STDERR, counted' => sub {
    my $r = apply_in(project(cp_list(4)));
    is $r->{died}, "k325: stop\n", 'ran up to the stub';
    is $r->{err}, "$EVEN{4}\n", 'the line, on STDERR';
    unlike $r->{out}, qr/control planes: each is an etcd member/, 'not on STDOUT';
    like $r->{out}, qr/^Cluster: k325$/m, 'STDOUT has the progress';
    is_deeply $r->{warnings}, [ 'even control planes' ], 'in {_apply_warnings}: WITH WARNINGS';
};

subtest 'ocp apply, 3 control planes: nothing' => sub {
    my $r = apply_in(project(cp_list(3)));
    is $r->{died}, "k325: stop\n", 'ran up to the stub';
    is $r->{err}, '', 'nothing on STDERR';
    is_deeply $r->{warnings}, [], 'nothing counted';
};

alarm 0;
done_testing;

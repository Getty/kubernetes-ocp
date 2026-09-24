#!/usr/bin/env perl
# karr k186 (+ k184) -- robocop must know the cluster's distribution and pod
# CIDR, and must never guess them.
#
# Live finding: on a k3s cluster robocop's banner said distribution=rke2.
# OCP::Robocop::Controller read OCP_DISTRIBUTION with a silent rke2 default and
# nothing set it, so robocop would have joined RKE2 agents to a k3s cluster.
# k184 is the same transport gap for network.pod_cidr: robocop's control-plane
# joins ran on the Rexfile's 10.42.0.0/16 fallback, which RKE2 refuses as a
# critical-config mismatch on a cluster with its own pod_cidr.
#
# The one source of truth is the robocop Deployment's environment, written
# from ocp.yaml by OCP::Robocop::Manifest on both deploy paths (`ocp apply`
# and `ocp deploy-robocop`). This file pins:
#
#   1. the shipped deployment.yaml carries no value (nothing to guess from)
#   2. Manifest->for_config writes both from the config, on top of the level
#   3. both deploy paths apply it
#   4. the controller refuses to start without them, or with a value it does
#      not know -- croaked from from_env, exit 1 + STDERR from bin/robocop
#      (the CrashLoopBackOff pattern of k170)
#
# That the controller hands both to OCP::Node is t/33; that OCP::Node puts
# pod_cidr on a control-plane join is t/08.

use strict;
use warnings;
use Test::More;

use File::Temp ();
use Path::Tiny ();
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Config;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::DeployRobocop;
use OCP::Robocop::Controller;
use OCP::Robocop::Manifest;

local @ARGV = ();
my $ocp = OCP->new;

package FakeApi {
    sub new     { bless { ensured => [] }, shift }
    sub ensure  { push @{ $_[0]{ensured} }, $_[1]; return $_[1] }
    sub ensured { $_[0]{ensured} }
}

package FakeOCP {
    sub new     { my ($c, %a) = @_; bless { %a }, $c }
    sub config  { $_[0]{config} }
    sub verbose { 0 }
}

package FakeShareCmd {
    sub new             { bless {}, shift }
    sub _find_share_dir { Path::Tiny::path('share') }
}

package main;

my @KEEP;

sub config_for {
    my (%opt) = @_;
    my $dir  = Path::Tiny->tempdir;
    my $spec = {
        name           => 'test',
        control_planes => { provider => 'ssh', host => 'police1' },
    };
    $spec->{kubernetes} = { dist => $opt{dist} } if defined $opt{dist};
    $spec->{network}    = { pod_cidr => $opt{pod_cidr} } if defined $opt{pod_cidr};
    $spec->{robocop}    = { security_level => $opt{level} } if defined $opt{level};
    my $file = $dir->child('ocp.yaml');
    $ocp->dump_file($file->stringify, $spec);
    push @KEEP, $dir;   # the tempdir outlives the config that reads it
    return OCP::Config->new(file => $file->stringify);
}

sub deployment_doc {
    my ($doc) = grep { ref $_ eq 'HASH' && ($_->{kind} // '') eq 'Deployment' }
        YAML::XS::LoadFile('share/robocop/deployment.yaml');
    return $doc;
}

sub env_of {
    my ($doc) = @_;
    my ($ctr) = grep { ($_->{name} // '') eq 'controller' }
        @{ $doc->{spec}{template}{spec}{containers} };
    return { map { $_->{name} => $_ } @{ $ctr->{env} } };
}

sub quietly (&) {
    my ($code) = @_;
    my $sink = '';
    open my $fh, '>', \$sink or die $!;
    local *STDOUT = $fh;
    return $code->();
}

# ---------------------------------------------------------------------------
# 1 + 2: the manifest
# ---------------------------------------------------------------------------

subtest 'the shipped Deployment names no distribution and no pod CIDR' => sub {
    my $env = env_of(deployment_doc());
    ok !exists $env->{OCP_DISTRIBUTION},
        'no OCP_DISTRIBUTION in deployment.yaml -- a value there would be a guess';
    ok !exists $env->{OCP_POD_CIDR}, 'no OCP_POD_CIDR either';
};

subtest 'for_config writes both values from ocp.yaml' => sub {
    my $config = config_for(dist => 'k3s', pod_cidr => '10.44.0.0/16');
    my $env = env_of(OCP::Robocop::Manifest->for_config(deployment_doc(), $config));

    is $env->{OCP_DISTRIBUTION}{value}, 'k3s',          'distribution from kubernetes.dist';
    is $env->{OCP_POD_CIDR}{value},     '10.44.0.0/16', 'pod CIDR from network.pod_cidr';
    ok exists $env->{ROBO_SSH_KEY}, 'secret level: the rest of the env untouched';
};

subtest 'for_config writes the config defaults when ocp.yaml sets nothing' => sub {
    # Not a guess on robocop's side: OCP::Config's defaults are what the
    # cluster was bootstrapped with, and the Deployment now says so.
    my $config = config_for();
    my $env = env_of(OCP::Robocop::Manifest->for_config(deployment_doc(), $config));
    is $env->{OCP_DISTRIBUTION}{value}, $config->distribution, 'distribution: the config default';
    is $env->{OCP_POD_CIDR}{value},     $config->pod_cidr,     'pod CIDR: the config default';
};

subtest 'for_config applies the security level too' => sub {
    my $config = config_for(dist => 'k3s', level => 'inject');
    my $env = env_of(OCP::Robocop::Manifest->for_config(deployment_doc(), $config));
    ok !exists $env->{ROBO_SSH_KEY},                     'inject: no private key';
    is $env->{ROBOCOP_SECURITY_LEVEL}{value}, 'inject', 'inject: the level is set';
    is $env->{OCP_DISTRIBUTION}{value},       'k3s',    'and the distribution as well';
};

subtest 'for_config replaces a value already there instead of adding a second' => sub {
    my $doc = OCP::Robocop::Manifest->for_config(deployment_doc(), config_for(dist => 'rke2'));
    $doc = OCP::Robocop::Manifest->for_config($doc, config_for(dist => 'k3s'));
    my ($ctr) = @{ $doc->{spec}{template}{spec}{containers} };
    my @dist = grep { $_->{name} eq 'OCP_DISTRIBUTION' } @{ $ctr->{env} };
    is scalar @dist, 1,        'one OCP_DISTRIBUTION entry';
    is $dist[0]{value}, 'k3s', 'carrying the newer value';
};

subtest 'for_config leaves every other document alone' => sub {
    my $sa = { kind => 'ServiceAccount', metadata => { name => 'robocop' } };
    is_deeply(OCP::Robocop::Manifest->for_config({ %$sa }, config_for(dist => 'k3s')), $sa,
        'a ServiceAccount passes through');
};

# ---------------------------------------------------------------------------
# 3: both deploy paths
# ---------------------------------------------------------------------------

subtest 'ocp deploy-robocop and ocp apply both put the values in place' => sub {
    my $config = config_for(dist => 'k3s', pod_cidr => '10.44.0.0/16');

    my $api = FakeApi->new;
    quietly {
        OCP::Cmd::DeployRobocop->new(command_chain => [ FakeOCP->new ])
            ->_apply_manifests($api, $config);
    };
    my ($dep) = grep { $_->{kind} eq 'Deployment' } @{ $api->ensured };
    is env_of($dep)->{OCP_DISTRIBUTION}{value}, 'k3s',          'deploy-robocop: distribution';
    is env_of($dep)->{OCP_POD_CIDR}{value},     '10.44.0.0/16', 'deploy-robocop: pod CIDR';

    my $api2 = FakeApi->new;
    quietly { OCP::Cmd::Apply::CR::ensure_robocop(FakeShareCmd->new, $api2, $config) };
    my ($dep2) = grep { $_->{kind} eq 'Deployment' } @{ $api2->ensured };
    is env_of($dep2)->{OCP_DISTRIBUTION}{value}, 'k3s',          'ocp apply: distribution';
    is env_of($dep2)->{OCP_POD_CIDR}{value},     '10.44.0.0/16', 'ocp apply: pod CIDR';
};

# ---------------------------------------------------------------------------
# 4: the controller refuses to guess
# ---------------------------------------------------------------------------

sub base_env {
    return (
        ROBO_SSH_KEY     => "PRIVATE-KEY\n",
        RKE2_SERVER_URL  => 'https://police1:6443',
        RKE2_TOKEN       => 'JOIN-TOKEN',
        OCP_DISTRIBUTION => 'k3s',
        OCP_POD_CIDR     => '10.44.0.0/16',
    );
}

sub from_env_with {
    my (%env) = @_;
    local %ENV = %ENV;
    delete @ENV{qw( ROBOCOP_SECURITY_LEVEL NAMESPACE )};
    for my $k (keys %env) {
        if (defined $env{$k}) { $ENV{$k} = $env{$k} } else { delete $ENV{$k} }
    }
    my $ctrl = eval { OCP::Robocop::Controller->from_env };
    return ($ctrl, $@);
}

subtest 'from_env reads both values' => sub {
    my ($ctrl, $err) = from_env_with(base_env());
    ok $ctrl, 'built' or diag $err;
    is $ctrl->distribution, 'k3s',          'distribution from OCP_DISTRIBUTION';
    is $ctrl->pod_cidr,     '10.44.0.0/16', 'pod_cidr from OCP_POD_CIDR';
};

subtest 'from_env dies without them -- no rke2 default' => sub {
    for my $var (qw( OCP_DISTRIBUTION OCP_POD_CIDR )) {
        my ($ctrl, $err) = from_env_with(base_env(), $var => undef);
        ok !$ctrl, "no controller without $var";
        like $err, qr/\Q$var\E/, "the error names $var";
        like $err, qr/ocp apply|ocp deploy-robocop/,
            "and says how to put it there ($var)";
    }
};

subtest 'from_env dies on a value it does not know' => sub {
    my ($ctrl, $err) = from_env_with(base_env(), OCP_DISTRIBUTION => 'rke3');
    ok !$ctrl, 'no controller for an unknown distribution';
    like $err, qr/OCP_DISTRIBUTION/, 'the error names the variable';
    like $err, qr/rke3/,             'and the value';

    ($ctrl, $err) = from_env_with(base_env(), OCP_POD_CIDR => 'ten-dot-42');
    ok !$ctrl, 'no controller for a pod CIDR that is none';
    like $err, qr/OCP_POD_CIDR/, 'the error names the variable';
    like $err, qr/ten-dot-42/,   'and the value';
};

subtest 'the constructor has no default either' => sub {
    my $err = do {
        local $@;
        eval { OCP::Robocop::Controller->new(
            ssh_key => 'K', server_url => 'U', join_token => 'T',
            pod_cidr => '10.42.0.0/16') };
        $@;
    };
    like $err, qr/distribution/, 'no distribution, no controller';

    $err = do {
        local $@;
        eval { OCP::Robocop::Controller->new(
            ssh_key => 'K', server_url => 'U', join_token => 'T',
            distribution => 'rke2') };
        $@;
    };
    like $err, qr/pod_cidr/, 'no pod_cidr, no controller';
};

subtest 'bin/robocop controller exits 1 with the reason on STDERR' => sub {
    my $out = File::Temp->new;
    my $err = File::Temp->new;
    my %env = base_env();
    delete $env{OCP_DISTRIBUTION};

    my $pid = fork // die "fork: $!";
    if ($pid == 0) {
        delete @ENV{qw( OCP_DISTRIBUTION OCP_POD_CIDR ROBOCOP_SECURITY_LEVEL NAMESPACE )};
        $ENV{$_} = $env{$_} for keys %env;
        open STDOUT, '>', $out->filename or die $!;
        open STDERR, '>', $err->filename or die $!;
        exec $^X, '-Ilib', 'bin/robocop', 'controller';
        exit 127;
    }
    local $SIG{ALRM} = sub { kill 'KILL', $pid };
    alarm 60;
    waitpid $pid, 0;
    alarm 0;

    my $stdout = Path::Tiny::path($out->filename)->slurp;
    my $stderr = Path::Tiny::path($err->filename)->slurp;
    is $? >> 8, 1, 'exit status 1 -- CrashLoopBackOff, not a guessing controller'
        or diag "stdout: $stdout\nstderr: $stderr";
    like $stderr, qr/^robocop: fatal: .*OCP_DISTRIBUTION/m, 'the reason is on STDERR';
    unlike $stdout, qr/starting/, 'nothing started';
};

done_testing;

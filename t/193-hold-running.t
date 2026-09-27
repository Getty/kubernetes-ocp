#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

use Rex::Rancher::Server ();
use Rex::Rancher::Agent ();

# The real checks, taken before OCPTest::Rexfile records over them.
my %PREFLIGHT = (
    server => \&Rex::Rancher::Server::preflight_server,
    agent  => \&Rex::Rancher::Agent::preflight_agent,
);

#
# k193: with Rex::Rancher 0.003 an install_server against a server that is
# already there either rolled it to OCP's pin (the pinned patch, or the next
# minor) or refused it (running newer than the pin, or more than a minor
# behind -- after a hand-made upgrade, say). OCP runs install_server against a
# running control plane only on a re-bootstrap (kubeconfig.yaml lost), but
# there it contradicted what OCP::Drift says: distribution upgrades are a
# manual step, node by node, never remedied.
#
# Maintainer decision (option b): OCP holds what runs. Rex::Rancher's
# hold_running (rex-rancher k77) makes the version on the host this run's
# version -- the running service's, else the installed binary's, else the
# pin -- with a warning when the pin loses, and restarts only for a changed
# configuration. OCP passes it on every server and agent install (k196).
#
#   1. every install task hands hold_running => 1 to the install and to the
#      checks before it;
#   2. against the real library: a running server keeps its version, newer or
#      older than the pin, and neither dies nor is rolled; a fresh host gets
#      the pin; an agent holds its own version too.
#
# Network-free: the Rexfile runs against recorders, the library against a
# host made of canned command output.
#

# --- 1. the Rexfile asks for it ----------------------------------------------

for my $case (
    [ install_rke2_server => 'Rex::Rancher::Server', 'server' ],
    [ install_k3s_server  => 'Rex::Rancher::Server', 'server' ],
    [ install_rke2_agent  => 'Rex::Rancher::Agent',  'agent'  ],
    [ install_k3s_agent   => 'Rex::Rancher::Agent',  'agent'  ],
) {
    my ($task, $pkg, $role) = @$case;
    subtest "$task holds a running $role" => sub {
        OCPTest::Rexfile->reset;
        OCPTest::Rexfile->run_task($task,
            { token => 't', server => 'https://10.0.0.1:9345', version => 'v1.36.4+rke2r1' });
        for my $fn ("preflight_$role", "install_$role") {
            my $o = OCPTest::Rexfile->lib_opts("${pkg}::$fn");
            ok $o, "$fn called" or next;
            is $o->{hold_running}, 1, "$fn: hold_running => 1";
            is $o->{version}, 'v1.36.4+rke2r1', "$fn: the pin still goes along -- for a host with nothing to hold";
        }
    };
}

# --- 2. what the library makes of it ------------------------------------------

my @LOG;
{
    no warnings 'redefine';
    *Rex::Logger::info = sub { push @LOG, [ @_ ] };
}

# A host: which rke2 unit runs which version, what binary is installed, and
# config.yaml. Every command the library asks gets its canned answer; the
# commands are collected.
sub on_host {
    my (%h) = @_;
    my @cmds;
    my $service = $h{service} // 'rke2-server';
    return (\@cmds, sub {
        my ($cmd) = @_;
        push @cmds, $cmd;
        my ($out, $exit) = ('', 0);
        if ($cmd =~ /^systemctl show -p MainPID (\S+)/) {
            $out = "MainPID=" . ($1 eq $service && $h{running} ? 4242 : 0) . "\n";
        }
        elsif ($cmd =~ m{^/proc/4242/exe --version}) {
            $out = "rke2 version $h{running} (0123abcd)\ngo version go1.25.3 X:boringcrypto\n";
        }
        elsif ($cmd =~ /^rke2 --version/) {
            ($out, $exit) = $h{installed}
                ? ("rke2 version $h{installed} (0123abcd)\ngo version go1.25.3\n", 0)
                : ("sh: 1: rke2: not found\n", 127);
        }
        elsif ($cmd =~ /^systemctl is-active --quiet rke2-server/) {
            $exit = $h{running} && $service eq 'rke2-server' ? 0 : 3;
        }
        elsif ($cmd =~ m{^test -e '/var/lib/rancher/rke2/server/token'}) {
            $exit = $h{installed} || $h{running} ? 0 : 1;
        }
        elsif ($cmd =~ m{^test -e '/etc/rancher/rke2/config.yaml'}) {
            $exit = $h{config} ? 0 : 1;
        }
        elsif ($cmd =~ m{^test -d }) {
            $exit = 1;
        }
        elsif ($cmd =~ m{^cat '/etc/rancher/rke2/config.yaml'}) {
            $out = $h{config} // '';
        }
        $? = $exit << 8;
        return $out;
    });
}

sub preflight {
    my ($fn, $host, %opts) = @_;
    my ($cmds, $run) = on_host(%$host);
    @LOG = ();
    no warnings 'redefine';
    local *Rex::Commands::Run::run = $run;
    my $checked = eval {
        $fn eq 'agent'
            ? $PREFLIGHT{agent}->(distribution => 'rke2', %opts)
            : $PREFLIGHT{server}->(distribution => 'rke2',
                cluster_cidr => '10.42.0.0/16', install_method => 'artifact', %opts);
    };
    return ($checked, $@, $cmds);
}

sub warnings_logged { map { $_->[0] } grep { ($_->[1] // '') eq 'warn' } @LOG }

my $PIN    = 'v1.36.4+rke2r1';
my $CONFIG = "token: t\ncluster-cidr: 10.42.0.0/16\n";

subtest 'a server running a newer version than the pin keeps it' => sub {
    my %host = (running => 'v1.37.1+rke2r1', installed => 'v1.37.1+rke2r1', config => $CONFIG);

    my ($checked, $err) = preflight(server => \%host, version => $PIN);
    ok !$checked, 'without hold_running: refused';
    like $err, qr/downgrade/, '-- as a downgrade';

    ($checked, $err) = preflight(server => \%host, version => $PIN, hold_running => 1);
    ok $checked, 'with hold_running: not refused' or diag $err;
    is $checked && $checked->{version}, 'v1.37.1+rke2r1', 'the running version is this run\'s version';
    my @warn = warnings_logged();
    ok((grep { /rke2-server runs v1\.37\.1\+rke2r1/ && /not version => '\Q$PIN\E'/ } @warn),
        'and a warning names both') or diag explain \@warn;
};

subtest 'a server running an older minor is not rolled to the pin' => sub {
    my %host = (running => 'v1.35.3+rke2r1', installed => 'v1.35.3+rke2r1', config => $CONFIG);

    my ($checked) = preflight(server => \%host, version => $PIN);
    is $checked && $checked->{version}, $PIN, 'without hold_running: the pin, one minor up -- a roll';

    ($checked) = preflight(server => \%host, version => $PIN, hold_running => 1);
    is $checked && $checked->{version}, 'v1.35.3+rke2r1', 'with hold_running: it stays where it is';
};

subtest 'a stopped server holds its installed binary' => sub {
    my ($checked, $err) = preflight(server => { installed => 'v1.37.1+rke2r1', config => $CONFIG },
        version => $PIN, hold_running => 1);
    is $checked && $checked->{version}, 'v1.37.1+rke2r1', 'the binary\'s version' or diag $err;
};

subtest 'a fresh host gets the pin' => sub {
    my ($checked, $err, $cmds) = preflight(server => {}, version => $PIN, hold_running => 1);
    is $checked && $checked->{version}, $PIN, 'nothing to hold: the pin' or diag $err;
    ok !(grep { /^(?:install|systemctl (?:start|restart)|curl|rm |mkdir|tee)/ } @$cmds),
        'and the checks only read the host';
};

subtest 'an agent holds its own version' => sub {
    my ($checked, $err) = preflight(agent => { service => 'rke2-agent.service',
                                               running => 'v1.35.3+rke2r1', installed => 'v1.35.3+rke2r1' },
        version => $PIN, hold_running => 1, server => 'https://10.0.0.1:9345', token => 't');
    is $checked && $checked->{version}, 'v1.35.3+rke2r1', 'rke2-agent\'s running version' or diag $err;
};

done_testing;

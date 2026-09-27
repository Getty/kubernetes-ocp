#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;
use OCPTest::UninstallHost;

#
# k190: after `ocp destroy` (rke2-uninstall.sh) and a fresh RKE2 bootstrap on
# the same host WITHOUT a reboot, connect() to the old NodePort localhost:30500
# hung instead of being refused. Cilium's socket-LB programs were still
# attached to the root cgroup through the bpf_links pinned in
# /sys/fs/bpf/cilium; containerd's registries.yaml mirror
# http://localhost:30500 made every image pull wait ~2.5 minutes, and RKE2
# missed its 10-minute start bound. A reboot cleared it. (Live, ocpt-cp.)
#
# Since k196 both halves are Rex::Rancher's (rex-rancher k71): the uninstall
# line that clears the datapath (Rex::Rancher::Uninstall::uninstall_cmd) and
# the guard that refuses a host carrying it (check_cilium_residue), both
# testing the one list of signals the library keeps (cilium_residue). What
# the line is made of, step by step, and the guard's probe are held there
# (rex-rancher t/uninstall.t, t/cilium-residue.t, ported from this file); so
# is that the two test the same signals, which this file used to keep in step
# between the Rexfile and OCP::Role::Provider::ExistingHost.
#
# The claims here are OCP's, through its own code paths:
#   1. OCP's uninstall (ExistingHost::delete_server, the one `ocp destroy` and
#      `ocp node rm` run) clears Cilium's datapath -- the pins (the unpin is
#      the detach of a link-attached program), the cilium_* devices, the
#      cgroup2 mount, the runtime dir -- and succeeds on a host it leaves clean;
#   2. Cilium state that survives fails it, naming the host, what is left, and
#      that a reboot is needed;
#   3. the install tasks refuse a host with Cilium state before anything
#      touches it, prepare_node included -- the guard is the first thing they
#      do; on a clean host they go ahead.
#
# Whether the kernel really detaches the programs when the pins go is a live
# question (Cilium's own detach does exactly that for its bpf_links), NOT
# claimed here.
#

plan skip_all => 'needs a POSIX /bin/sh' unless -x '/bin/sh';

# --- 1. the uninstall clears the datapath ---------------------------------------

subtest 'delete_server clears Cilium\'s datapath and succeeds on a clean host' => sub {
  my $h = OCPTest::UninstallHost->new(
    stubs => {
      ( map { $_ => "exit 0\n" } qw( rm tc umount ) ),
      # deleting a device works; nothing is left to show, no rule to drain
      ip => "case \"\$1 \$2\" in \"link del\") exit 0;; esac\nexit 1\n",
    },
    real => [qw( grep sed )],
  );
  my $res = eval { $h->delete_server(undef, host => '10.0.0.5') };
  ok $res, 'no error' or diag $@;
  is $res && $res->{exit}, 0, 'the uninstall exits 0';

  my $log = $h->log;
  like $log, qr{^rm -rf .*/sys/fs/bpf/cilium\b}m,
    'the pinned links and maps go -- unpinning a link Cilium no longer holds detaches its program';
  like $log, qr/^ip link del dev cilium_host$/m, 'cilium_host is deleted';
  like $log, qr{^umount /run/cilium/cgroupv2$}m, "Cilium's cgroup2 mount is unmounted";
  like $log, qr{^rm -rf --one-file-system /run/cilium$}m,
    'the runtime dir goes, never recursing into a mount that stayed';
};

# --- 2. the outcome check -------------------------------------------------------

subtest 'Cilium state that survived fails delete_server, asking for a reboot' => sub {
  my $h = OCPTest::UninstallHost->new(
    stubs => {
      rm => "exit 0\n",
      ip => "case \"\$*\" in \"link show dev cilium_host\") exit 0;; esac\nexit 1\n",
    },
    real => [qw( grep sed )],
  );
  my $ok = eval { $h->delete_server(undef, host => '10.0.0.5'); 1 };
  my $err = $@;
  ok !$ok, 'dies';
  like $err, qr/^10\.0\.0\.5: /, 'naming the host';
  like $err, qr/Cilium datapath state is still on the host.*cilium_host/, 'and what is left';
  like $err, qr/reboot the host/, 'and what to do about it';
};

# --- 3. the install path refuses leftovers, before anything else ----------------

my $REFUSAL = "This host still carries Cilium datapath state from an earlier cluster "
  . "(/sys/fs/bpf/cilium, cilium_host), and no RKE2/K3s is installed on it. [...] "
  . "Nothing was written or installed. Reboot the host, then run the install again.\n";

for my $case (
  [ install_rke2_server => 'Rex::Rancher::Server::install_server', {} ],
  [ install_k3s_server  => 'Rex::Rancher::Server::install_server', {} ],
  [ install_rke2_agent  => 'Rex::Rancher::Agent::install_agent',
    { server => 'https://10.0.0.1:9345', token => 't' } ],
  [ install_k3s_agent   => 'Rex::Rancher::Agent::install_agent',
    { server => 'https://10.0.0.1:6443', token => 't' } ],
) {
  my ( $task, $lib, $params ) = @$case;

  subtest "$task refuses a host with Cilium leftovers before touching it" => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_DIE{'Rex::Rancher::Uninstall::check_cilium_residue'} = $REFUSAL;
    my $ok = eval { OCPTest::Rexfile->run_task($task, { %$params }); 1 };
    ok !$ok, 'the task dies';
    is $@, $REFUSAL, 'with the library\'s refusal';
    is scalar(OCPTest::Rexfile->calls($lib)), 0, "$lib is never called";
    is scalar(OCPTest::Rexfile->calls('do_task')), 0, 'nothing is prepared either';
    is_deeply [ OCPTest::Rexfile->commands ], [], 'no command of OCP\'s own ran on the host';
  };

  subtest "$task goes ahead on a clean host, after the check" => sub {
    OCPTest::Rexfile->reset;
    my $ok = eval { OCPTest::Rexfile->run_task($task, { %$params }); 1 };
    ok $ok, 'the task runs' or diag $@;
    is scalar(OCPTest::Rexfile->calls('Rex::Rancher::Uninstall::check_cilium_residue')), 1,
      'the host was checked';
    is $OCPTest::Rexfile::CALLS[0]{name}, 'Rex::Rancher::Uninstall::check_cilium_residue',
      'first, before anything else';
    my $prep = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'do_task' && $_->{args}[0] eq 'prepare_node' });
    ok $prep > 0, 'then prepare_node';
    is scalar(OCPTest::Rexfile->calls($lib)), 1, "then $lib";
  };
}

done_testing;

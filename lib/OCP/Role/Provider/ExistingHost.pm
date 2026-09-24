package OCP::Role::Provider::ExistingHost;
# ABSTRACT: Provider behaviour for hosts OCP does not create

use Moo::Role;

# Uninstall both distributions — we don't track which one is on the host.
#
# The vendor uninstallers stop at their own footprint and leave behind what OCP
# put there on top: the Cilium CLI (installed by the install_cilium task), the
# CNI plugin directory, and the k3s runtime dir. Leaving those is not cosmetic —
# a later bootstrap finds the stale `cilium` binary and, if its version happens
# to match what is wanted, keeps it instead of installing the pinned one.
#
# So this cleans up after itself by default rather than behind a flag: every
# path below is something OCP or its distribution installed, never user data.
our @LEFTOVER_PATHS = qw(
    /usr/local/bin/cilium
    /opt/cni
    /run/k3s
);

# rke2-uninstall.sh / k3s-uninstall.sh tear down the distribution but leave
# Cilium's policy-routing ip rules in place: the fwmark rules that point at
# Cilium's dedicated proxy route tables (2004 to-proxy, 2005 from-proxy) and
# the local-table lookup Cilium relocates from priority 0 to priority 100.
# Those tables and rules are OCP/Cilium's own, nothing else uses the magic
# table ids. They are harmless on a fresh box — the reboot before a first
# bootstrap clears them — but on the ExistingHost path we uninstall a host we
# will NOT reboot before re-provisioning, so they accumulate as ballast. This
# is the one uninstall path that runs on such a host, so it flushes them here.
our @LEFTOVER_IP_TABLES = (2004, 2005);

# Every statement below is defensive: draining a table that holds no rules, or
# deleting a rule that is not there, exits non-zero and is swallowed, so an
# already-clean host — or one without `ip` on PATH — is a no-op, never a failed
# uninstall. The relocated local rule is handled last and only ever removed
# once a priority-0 local lookup is back in place, so the host can never end up
# with no local-table rule at all.
#
# The vendor uninstallers themselves: RKE2's installer ships rke2-uninstall.sh
# for server and agent alike, K3s names it after the service it set up --
# k3s-uninstall.sh on a server, k3s-agent-uninstall.sh on an agent, and a k3s
# worker has only the latter (k183). Every one that is on the host runs, and a
# failing one does not keep the next from running: the outcome check at the
# end is what decides whether the uninstall worked.
our @UNINSTALLERS = qw(
    rke2-uninstall.sh
    k3s-uninstall.sh
    k3s-agent-uninstall.sh
);

# Cilium's datapath outlives the uninstallers (k190). rke2-uninstall.sh stops
# the agent but not what the agent attached to the kernel: the socket-LB
# programs on the root cgroup (through /run/cilium/cgroupv2), the tc/tcx
# programs on the host's devices, the maps and links pinned in bpffs, the
# cilium_* devices and the CILIUM_* iptables chains. Until a reboot the
# socket LB keeps translating the old cluster's service addresses to pods that
# are gone, so connect() to e.g. localhost:30500 -- the registry mirror every
# node's containerd is pointed at -- hangs instead of being refused, every
# image pull waits minutes for it, and a fresh RKE2 on the host never gets
# etcd up within its start bound. Measured on ocpt-cp.
#
# This clears it the way Cilium's own post-uninstall cleanup does, without
# bpftool (not on the hosts) and without the agent's image:
#
#   - pinned objects: Cilium attaches its cgroup and tcx programs as bpf_links
#     (kernel 5.7+) and pins the links under /sys/fs/bpf/cilium, precisely so
#     they survive the agent. Unpinning the last reference -- the agent is
#     gone -- releases the link, and the kernel detaches the program. So the
#     rm IS the detach. (Only a pre-5.7 kernel attaches without links; Cilium
#     1.20 does not run there.)
#   - legacy tc attachments (kernel without tcx): the clsact qdisc of every
#     device that carries a Cilium program goes, and its filters with it;
#   - Cilium's devices, and its iptables chains in every backend present:
#     jumps into them deleted, then flushed and removed, in one restore
#     transaction per table;
#   - the cgroup2 mount, then Cilium's runtime dir -- with --one-file-system,
#     so a mount that refused to go is never recursed into.
our @CILIUM_PINS = qw(
    /sys/fs/bpf/cilium
    /sys/fs/bpf/tc/globals/cilium_*
);
our $CILIUM_CGROUP_ROOT = '/run/cilium/cgroupv2';
our $CILIUM_RUN_DIR     = '/run/cilium';
our @CILIUM_LINKS = qw(
    cilium_host
    cilium_net
    cilium_vxlan
    cilium_geneve
    cilium_wg0
);
our @IPTABLES = qw(
    iptables ip6tables
    iptables-legacy ip6tables-legacy
    iptables-nft ip6tables-nft
);

# What still being there means the datapath outlived the cleanup. The install
# path refuses a host that shows any of these without a distribution on it
# (share/Rexfile, _cilium_leftovers) -- keep the two in step, t/190 checks.
our @CILIUM_RESIDUE = (
    [ '[ -e /sys/fs/bpf/cilium ]', '/sys/fs/bpf/cilium' ],
    [ 'grep -qs " ' . $CILIUM_CGROUP_ROOT . ' " /proc/mounts', $CILIUM_CGROUP_ROOT ],
    [ 'ip link show dev cilium_host >/dev/null 2>&1', 'cilium_host' ],
);

our $CILIUM_CLEANUP_CMD = join ' ; ',
    'for d in /sys/class/net/*; do d=${d##*/};'
        . ' if tc filter show dev $d ingress 2>/dev/null | grep -qE "cil_|bpf_(netdev|host|overlay|lxc)"'
        . ' || tc filter show dev $d egress 2>/dev/null | grep -qE "cil_|bpf_(netdev|host|overlay|lxc)";'
        . ' then tc qdisc del dev $d clsact 2>/dev/null || true; fi; done',
    'rm -rf ' . join(' ', @CILIUM_PINS) . ' 2>/dev/null || true',
    'for l in ' . join(' ', @CILIUM_LINKS) . '; do ip link del dev $l 2>/dev/null || true; done',
    'for ipt in ' . join(' ', @IPTABLES) . '; do'
        . ' command -v $ipt-save >/dev/null 2>&1 && command -v $ipt-restore >/dev/null 2>&1 || continue;'
        . ' for tb in filter nat mangle raw; do'
        . ' s=$($ipt-save -t $tb 2>/dev/null) || continue;'
        . ' printf "%s\n" "$s" | grep -qE "^:(OLD_)?CILIUM_" || continue;'
        . ' { echo "*$tb";'
        . ' printf "%s\n" "$s" | grep -E "^-A " | grep -vE "^-A (OLD_)?CILIUM_" | grep -E -- "-j (OLD_)?CILIUM_" | sed "s/^-A /-D /";'
        . ' printf "%s\n" "$s" | sed -nE "s/^:((OLD_)?CILIUM_[^ ]*) .*/-F \1/p";'
        . ' printf "%s\n" "$s" | sed -nE "s/^:((OLD_)?CILIUM_[^ ]*) .*/-X \1/p";'
        . ' echo COMMIT; } | $ipt-restore --noflush 2>/dev/null || true;'
        . ' done; done',
    "umount $CILIUM_CGROUP_ROOT 2>/dev/null || umount -l $CILIUM_CGROUP_ROOT 2>/dev/null || true",
    "rm -rf --one-file-system $CILIUM_RUN_DIR 2>/dev/null || true";

our $UNINSTALL_CMD = join ' ; ',
    'for u in ' . join(' ', @UNINSTALLERS) . '; do'
        . ' if command -v $u >/dev/null 2>&1; then $u 2>/dev/null || true; fi;'
        . ' done',
    'rm -rf ' . join(' ', @LEFTOVER_PATHS) . ' 2>/dev/null || true',
    $CILIUM_CLEANUP_CMD,
    'for t in ' . join(' ', @LEFTOVER_IP_TABLES)
        . '; do while ip rule del lookup $t 2>/dev/null; do :; done; done',
    'ip rule list 2>/dev/null | grep -qE "^0:[[:space:]].*lookup local"'
        . ' || ip rule add from all lookup local priority 0 2>/dev/null || true',
    'ip rule list 2>/dev/null | grep -qE "^0:[[:space:]].*lookup local"'
        . ' && ip rule del from all lookup local priority 100 2>/dev/null || true',
    # Everything above is guarded, so without this the chain exited 0 whatever
    # happened -- a missing or failing uninstaller left rke2 in place and read
    # as a clean uninstall (k175). The outcome is what gets checked, not the
    # steps: the command fails when a distribution binary is still on PATH.
    'if command -v rke2 >/dev/null 2>&1 || command -v k3s >/dev/null 2>&1;'
        . ' then echo "RKE2/K3s is still installed after the uninstall" >&2; exit 1; fi',
    # And the datapath (k190): a host whose Cilium state survived is not clean,
    # the next bootstrap on it would hang. Only a reboot clears what is left.
    'left=""',
    ( map { $_->[0] . ' && left="$left ' . $_->[1] . '"' } @CILIUM_RESIDUE ),
    'if [ -n "$left" ]; then echo "Cilium datapath state is still on the host after the uninstall:$left'
        . ' -- reboot the host before it is bootstrapped again" >&2; exit 1; fi';

# A consumer only has to say which host it talks to, how to check that the
# host is there, and how to run a command on it. Everything else is the same
# for every provider that works on pre-existing machines.
requires 'resolve_host';     # (%opts)           -> host, or dies
requires 'host_reachable';   # ($host, $timeout) -> bool
requires 'run_command';      # ($host, $command) -> output

=attr verbose

    my $p = MyProvider->new(verbose => 1);

Boolean verbosity flag, consumed by subclasses (e.g. L<OCP::Provider::Local>
prints command output when set). Default C<0>.

=cut

has verbose => (is => 'ro', default => 0);

# Nothing to create, so nothing to prepare or clean up.
sub upload_ssh_key          { return }
sub cleanup_on_failure      { return }
sub list_servers_by_cluster { return [] }

=method advertised_host

    my $host = $p->advertised_host(host => '10.0.0.5');

The address other machines and the operator's kubeconfig should use to reach
this host: the kube-apiserver's C<tls-san>, the kubeconfig C<server> endpoint,
and the C<cp_ip> every downstream deploy step addresses the control plane by.

Defaults to C<resolve_host> -- for a host OCP does not create, the address we
advertise IS the address we reach it at. It is a method rather than a plain
attribute for the same reason C<resolve_host> is: SSH reads the host out of the
options at call time, so there is nothing to build eagerly.

L<OCP::Provider::Local> is the one consumer that overrides it. It reaches
localhost over C<127.0.0.1> (self-ssh-local), which is useless as a kubeconfig
endpoint from anywhere but the machine itself, so it advertises the machine's
routable IP instead while the transport target stays C<127.0.0.1>.

=cut

sub advertised_host {
    my ($self, %opts) = @_;
    return $self->resolve_host(%opts);
}

=method server_exists

    my $info = $p->server_exists($node_name, host => '10.0.0.5');

Returns C<< { ip => $host } >> when the host resolves and answers; C<undef>
when C<resolve_host> dies or the host is unreachable. Used by callers that
want to know whether to provision or to skip.

=method create_server

    my $info = $p->create_server(host => '10.0.0.5', name => 'w1');

Reports the host back as an existing, not newly created server.
C<id> is C<undef>; C<newly_created> is C<0>. The caller treats both fields
the same way as the cloud adapter would.

=method wait_for_running

    my $info = $p->wait_for_running($info);

No-op: the host was running before we got here. Returns its argument.

=method delete_server

    $p->delete_server(undef, host => '10.0.0.5');

Runs every RKE2/K3s uninstall script present on the host (see
C<@UNINSTALLERS>: C<rke2-uninstall.sh> for both RKE2 roles,
C<k3s-uninstall.sh> on a K3s server, C<k3s-agent-uninstall.sh> on a K3s
agent), then removes the leftovers the
vendor uninstallers stand: OCP-installed paths (see C<@LEFTOVER_PATHS>) and
Cilium's residual policy-routing ip rules (see C<@LEFTOVER_IP_TABLES>), which
matter on this reboot-less re-provisioning path. It also clears Cilium's
datapath, which outlives the agent (see C<$CILIUM_CLEANUP_CMD>): the bpf_links
and maps pinned under F</sys/fs/bpf> (unpinning is what detaches the socket-LB
and tcx programs), legacy tc attachments, the C<cilium_*> devices, the
C<CILIUM_*> iptables chains, the F</run/cilium/cgroupv2> mount and
F</run/cilium>. C<$server_id> is ignored (the machine does not belong to OCP);
C<host> is read through C<resolve_host>.

The command ends by checking its own outcome: it fails when C<rke2> or C<k3s>
is still on C<PATH>, and when Cilium state survived the cleanup
(C<@CILIUM_RESIDUE>) -- a host in that state hangs the next bootstrap on it
until it is rebooted, and the message says so.  B<A failed uninstall dies> — a refused SSH login, a
command that exits non-zero — with the exit status and the remote side's
stderr in the message.  Returns the C<run_command> result on success.  A host
that cannot be resolved is still a no-op: there is nowhere to uninstall from.

This is the one uninstall implementation; L<OCP::Node/Teardown>
(C<ocp node rm>) and L<OCP::Cmd::Destroy> both reach the machine through it.

=cut

sub server_exists {
    my ($self, $node_name, %opts) = @_;

    my $host = eval { $self->resolve_host(%opts) };
    return unless defined $host && length $host;

    return $self->host_reachable($host, $opts{timeout} // 10)
        ? { ip => $host }
        : undef;
}

sub create_server {
    my ($self, %opts) = @_;

    my $host = $self->resolve_host(%opts);

    return {
        id            => undef,
        ip            => $host,
        newly_created => 0,
    };
}

sub wait_for_running {
    my ($self, $server_info, $timeout) = @_;
    return $server_info;   # it was running before we got here
}

# We can't delete the machine, so we remove what we installed on it.
sub delete_server {
    my ($self, $server_id, %opts) = @_;

    my $host = eval { $self->resolve_host(%opts) };
    return unless defined $host && length $host;

    my $result = $self->run_command($host, $UNINSTALL_CMD);

    # run_command reports a refused login or a failed step as a non-zero exit,
    # not as an exception -- and OCP::Node::teardown, which only listens for
    # exceptions, deleted the Node and the OCPNode of a worker that kept
    # running rke2-agent (k175). Say it the way every caller already hears.
    my $exit = ref $result eq 'HASH' ? $result->{exit} // 0 : 1;
    if ($exit) {
        my $why = ref $result eq 'HASH' ? $result->{stderr} // '' : '';
        $why =~ s/\s+\z//;
        die "Uninstall of RKE2/K3s on $host failed (exit $exit)"
          . (length $why ? ": $why" : '') . "\n";
    }
    return $result;
}

1;

__END__

=synopsis

    package My::Provider::New;
    use Moo;
    with 'OCP::Role::Provider::ExistingHost';

    sub resolve_host   { ... }   # where to talk
    sub host_reachable { ... }   # how to check it
    sub run_command    { ... }   # how to run things on it

=description

Some providers manage machines; others just use machines that are already
there. This role holds everything the second kind has in common: creation is
a no-op that reports the host back, waiting is instant, there is no key to
upload and no server list to query, and deletion means uninstalling the
Kubernetes distribution instead of destroying hardware.

B<Any adapter that wraps a host the user already controls MUST consume this
role.> Adapter-specific overrides are for IP discovery or transport
(SSH vs serial vs local execution), NOT for the lifecycle shape
(create/delete/run_command). The lifecycle methods here are the seam:
callers depend on them, and a host adapter that re-implements them in its
own way will silently drift from the cloud adapter's contract.

Consumers supply the three things that actually differ: which host to talk
to, how to test it, and how to run a command on it.
L<OCP::Provider::SSH> does that over SSH;
L<OCP::Provider::Local> does it on the local machine.

=method required

These methods B<must> be implemented by the consuming class. The role calls
each in the methods below (C<server_exists>, C<create_server>,
C<delete_server>), so an undefined body is a hard error at composition
time — Moo::Role's C<requires> enforces it.

=over 4

=item C<resolve_host(%opts) — str, dies on failure>

Returns the host to act on. Callers pass C<host => ...> when they have one;
OCP::Node::_provision passes C<spec => $cr->{spec}> instead, so an
adapter reading only C<$opts{host}> will die there. The SSH adapter shows
the pattern: prefer an explicit C<host>, fall back to C<spec.host>.

=item C<host_reachable($host, $timeout) — bool>

Whether the host answers within C<$timeout> seconds. Used by
C<server_exists> to decide between C<< { ip => $host } >> and C<undef>.

=item C<run_command($host, $command) — output>

Runs a shell command on the host and returns its output (shape matching
L<OCP::SSH/run>). Used by C<delete_server> to uninstall the distribution.

=back

=method upload_ssh_key, cleanup_on_failure, list_servers_by_cluster

    $p->upload_ssh_key($name, $pubkey);   # no-op
    $p->cleanup_on_failure($server_id);   # no-op
    my $servers = $p->list_servers_by_cluster($cluster);  # []

No-ops. There is no provider API behind these hosts, and callers know it.

=seealso

L<OCP::Provider::SSH>, L<OCP::Provider::Local>, L<OCP::Provider::Hetzner>,
L<OCP::Provider>

=cut

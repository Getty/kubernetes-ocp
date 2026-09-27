package OCP::Role::Provider::ExistingHost;
# ABSTRACT: Provider behaviour for hosts OCP does not create

use Moo::Role;

use Rex::Rancher::Uninstall ();

# The uninstall is Rex::Rancher's (rex-rancher k71), the one line its own
# uninstall_node runs: every RKE2/K3s uninstall script on the host (we do not
# track which distribution or role is there); what they leave behind -- the
# Cilium CLI install_cilium put there, /opt/cni, /run/k3s --; Cilium's datapath,
# which outlives them and hangs the next install on a host that is not
# rebooted (k190); Cilium's policy-routing ip rules. It ends by checking its own
# outcome: RKE2/K3s still on PATH (k175), or Cilium state that survived, fails
# it, the latter asking for a reboot.
#
# This role only brings that line to the host over its own channel -- SSH or
# the local shell, through run_command -- since these hosts are not reached
# through Rex here, and says a failure the way every caller hears it.

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

Runs L<Rex::Rancher::Uninstall/uninstall_cmd> on the host through
C<run_command>: every RKE2/K3s uninstall script present (C<rke2-uninstall.sh>
for both RKE2 roles, C<k3s-uninstall.sh> on a K3s server,
C<k3s-agent-uninstall.sh> on a K3s agent), then what they leave behind -- the
Cilium CLI, F</opt/cni>, F</run/k3s> --, Cilium's datapath, which outlives the
agent and matters on this reboot-less re-provisioning path (the pins under
F</sys/fs/bpf>, whose removal detaches the socket-LB and tcx programs, legacy tc
attachments, the C<cilium_*> devices, the C<CILIUM_*> iptables chains, the
F</run/cilium/cgroupv2> mount and F</run/cilium>), and Cilium's policy-routing
ip rules. C<$server_id> is ignored (the machine does not belong to OCP);
C<host> is read through C<resolve_host>.

The line ends by checking its own outcome: it fails when RKE2 or K3s is still
on C<PATH>, and when Cilium state survived the cleanup -- a host in that state
hangs the next bootstrap on it until it is rebooted, and the message says so.
B<A failed uninstall dies> -- a refused SSH login, a command that exits
non-zero -- with the host and L<Rex::Rancher::Uninstall/uninstall_failure>'s
message: the exit status and the remote side's stderr, without the warning
lines. Those -- L<Rex::Rancher::Uninstall/uninstall_warnings>, a cleanup step
the host had no tool for (C<tc>, an iptables backend), so that part of the
datapath was not checked; a reboot clears it -- go to STDERR, one line each
with the host in front, and fail nothing. Returns the C<run_command> result
on success. A host that cannot be resolved is still a
no-op: there is nowhere to uninstall from.

This is OCP's one uninstall path; L<OCP::Node/Teardown>
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

    my $result = $self->run_command($host, Rex::Rancher::Uninstall->uninstall_cmd);

    # run_command reports a refused login or a failed step as a non-zero exit,
    # not as an exception -- and OCP::Node::teardown, which only listens for
    # exceptions, deleted the Node and the OCPNode of a worker that kept
    # running rke2-agent (k175). Say it the way every caller already hears,
    # with the host in front: the library's message cannot know it.
    my ($exit, $stdout, $stderr) = ref $result eq 'HASH'
        ? ($result->{exit} // 0, $result->{stdout}, $result->{stderr})
        : (1, '', '');

    # A cleanup step the host could not run -- no tc, no iptables backend with
    # both -save and -restore -- leaves that part of Cilium's datapath
    # unchecked; a reboot clears it. Not a failure (rex-rancher k79): only the
    # line's exit status decides that, and its message leaves these out. Said
    # on STDERR, as the diagnosis it is, whatever the outcome.
    warn "$host: $_\n" for Rex::Rancher::Uninstall->uninstall_warnings($stdout, $stderr);

    my $failure = Rex::Rancher::Uninstall->uninstall_failure($exit, $stderr);
    die "$host: $failure" if defined $failure;
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

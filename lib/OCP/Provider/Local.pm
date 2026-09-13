package OCP::Provider::Local;
# ABSTRACT: Local infrastructure provider (localhost)

use Moo;
use OCP::Exec qw(capture_command);

with 'OCP::Role::Provider::ExistingHost';

# How long a local command may run before it is killed -- see the same
# attribute on OCP::SSH. The uninstall this provider runs is short; the bound
# just stops a wedged child from hanging the caller forever.
has command_timeout => (
    is      => 'ro',
    default => 600,
);

# The machine OCP itself runs on. Kept as an IP rather than 'localhost' so
# the value can be handed to SSH-based code paths unchanged.
=method resolve_host

    my $host = $p->resolve_host();

Always C<127.0.0.1>. Arguments are ignored — the local provider talks to
exactly one host.

=cut

sub resolve_host { return '127.0.0.1' }

# The address to advertise, which is NOT the transport target here.
#
# OCP reaches the local machine over 127.0.0.1 (self-ssh-local), but a
# kubeconfig, tls-san or cp_ip pinned to 127.0.0.1 is only usable from the box
# itself -- from a laptop it points at the laptop's own loopback. So the local
# provider advertises the routable address the machine speaks to the outside
# with, taken from the default-route source IP, while resolve_host (the
# transport) stays 127.0.0.1.
#
# Only ever an improvement: a real IPv4 is used, and anything else (no route,
# a parse miss, no `ip` binary) falls back to resolve_host -- the 127.0.0.1
# status quo -- rather than advertising something worse. k138, pikachu.
=method advertised_host

    my $host = $p->advertised_host();   # e.g. '10.5.10.5', else '127.0.0.1'

The machine's default-route source IP when that is a valid IPv4; otherwise
C<resolve_host> (C<127.0.0.1>). Used for the tls-san, the kubeconfig server
endpoint and the advertised C<cp_ip> -- never as the transport target, which
stays C<127.0.0.1>.

=cut

sub advertised_host {
    my ($self, %opts) = @_;
    my $ip = $self->_default_route_source_ip;
    return $ip if defined $ip && $self->_is_ipv4($ip);
    return $self->resolve_host(%opts);
}

# The source address the kernel would use to reach a routable destination sits
# in the `src` field of `ip route get`. 1.1.1.1 is a literal target, not a DNS
# lookup, and this consults the routing table without sending a packet. Kept in
# its own method so a test can replace it without a routing table to depend on.
sub _default_route_source_ip {
    my ($self) = @_;
    my $r = eval {
        capture_command(['ip', '-4', 'route', 'get', '1.1.1.1'], timeout => 5);
    };
    return unless $r && $r->{exit} == 0;
    return $r->{stdout} =~ /\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b/ ? $1 : undef;
}

# A syntactically valid dotted-quad, every octet in range. Deliberately strict:
# a non-address parsed out of unexpected `ip` output must fall through to the
# 127.0.0.1 fallback, not become the endpoint the whole cluster is addressed by.
sub _is_ipv4 {
    my ($self, $ip) = @_;
    return 0 unless defined $ip && $ip =~ /\A([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\z/;
    for my $octet ($1, $2, $3, $4) {
        return 0 if $octet > 255;
    }
    return 1;
}

=method host_reachable

    my $ok = $p->host_reachable($host, $timeout);

Always C<1>. We are already here.

=cut

sub host_reachable { return 1 }

# Same contract as OCP::SSH::run, minus the SSH.
=method run_command

    my $result = $p->run_command('127.0.0.1', 'uptime');

Runs the command through C<sh -c> on the local machine. Returns the same
hashref shape as L<OCP::SSH/run>: C<< { stdout, stderr, exit } >>.

=cut

sub run_command {
    my ($self, $host, $command) = @_;
    return capture_command(['sh', '-c', $command],
        timeout => $self->command_timeout);
}

1;

__END__

=synopsis

    use OCP::Provider::Local;

    my $p = OCP::Provider::Local->new;
    my $info = $p->create_server();   # ip => '127.0.0.1'
    $p->delete_server(undef);          # uninstalls RKE2/K3s locally

=description

Does what L<OCP::Provider::SSH> does, without the SSH: commands run
directly on this machine through C<sh -c>. Shared provider behaviour
lives in L<OCP::Role::Provider::ExistingHost>.

Note that this covers the I<provider> side only — reporting the host and
uninstalling the distribution. Installing Kubernetes still goes through
L<OCP::Rex>, which connects to 127.0.0.1 over SSH, so the local host
needs the OCP public key in its F<authorized_keys>.

=seealso

L<OCP::Provider::SSH>, L<OCP::Provider::Hetzner>,
L<OCP::Role::Provider::ExistingHost>

=cut

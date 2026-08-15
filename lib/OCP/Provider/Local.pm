package OCP::Provider::Local;
# ABSTRACT: Local infrastructure provider (localhost)

use Moo;
use IPC::Open3 qw(open3);
use Symbol qw(gensym);

with 'OCP::Role::Provider::ExistingHost';

# The machine OCP itself runs on. Kept as an IP rather than 'localhost' so
# the value can be handed to SSH-based code paths unchanged.
=method resolve_host

    my $host = $p->resolve_host();

Always C<127.0.0.1>. Arguments are ignored — the local provider talks to
exactly one host.

=cut

sub resolve_host { return '127.0.0.1' }

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

    my $err = gensym;
    my $pid = open3(my $in, my $out, $err, 'sh', '-c', $command);
    close $in;

    my $stdout = do { local $/; <$out> };
    my $stderr = do { local $/; <$err> };

    close $out;
    close $err;

    waitpid($pid, 0);

    return {
        stdout => $stdout // '',
        stderr => $stderr // '',
        exit   => $? >> 8,
    };
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

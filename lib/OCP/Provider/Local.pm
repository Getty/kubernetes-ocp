package OCP::Provider::Local;
# ABSTRACT: Local infrastructure provider (localhost)

use Moo;
use IPC::Open3 qw(open3);
use Symbol qw(gensym);

with 'OCP::Role::Provider::ExistingHost';

our $VERSION = '0.001';

# The machine OCP itself runs on. Kept as an IP rather than 'localhost' so
# the value can be handed to SSH-based code paths unchanged.
sub resolve_host { return '127.0.0.1' }

# We are already here.
sub host_reachable { return 1 }

# Same contract as OCP::SSH::run, minus the SSH.
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

=head1 NAME

OCP::Provider::Local - Local provider for localhost installations

=head1 DESCRIPTION

Does what L<OCP::Provider::SSH> does, without the SSH: commands run directly
on this machine. Shared provider behaviour lives in
L<OCP::Role::Provider::ExistingHost>.

Note that this covers the I<provider> side only — reporting the host and
uninstalling the distribution. Installing Kubernetes still goes through
L<OCP::Rex>, which connects to 127.0.0.1 over SSH, so the local host needs
the OCP public key in its F<authorized_keys>.

=head1 METHODS

=head2 resolve_host

Always C<127.0.0.1>.

=head2 host_reachable

Always true.

=head2 run_command

    my $result = $provider->run_command($host, 'uptime');

Runs the command through C<sh -c> on the local machine. Returns a hashref
with C<stdout>, C<stderr> and C<exit>, matching L<OCP::SSH/run>.

=cut

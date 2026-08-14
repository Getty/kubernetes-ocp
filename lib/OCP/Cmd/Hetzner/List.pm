package OCP::Cmd::Hetzner::List;
# ABSTRACT: List servers the Hetzner token can see (debug tool, not an adapter call)

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);

use OCP::Secrets;
use WWW::Hetzner::Cloud;

our $VERSION = '0.001';

option label => (
    is     => 'ro',
    format => 's',
    doc    => 'Filter by label (e.g., ocp-cluster=prod)',
);

sub execute {
    my ($self, $args, $chain) = @_;

    # Get token from secrets or environment
    my $secrets = OCP::Secrets->new(project_dir => path('.'));
    my $token = $secrets->hetzner_token;

    unless ($token) {
        die "Hetzner API token required.\n" .
            "Set HETZNER_API_TOKEN or run 'ocp init --hetzner' to configure.\n";
    }

    my $cloud = WWW::Hetzner::Cloud->new(token => $token);

    my $servers = $self->label
        ? $cloud->servers->list_by_label($self->label)
        : $cloud->servers->list;

    if (!@$servers) {
        print "No servers found.\n";
        return;
    }

    printf "%-10s %-25s %-10s %-16s %-10s %s\n",
        'ID', 'NAME', 'STATUS', 'IP', 'TYPE', 'LABELS';
    print "-" x 90, "\n";

    for my $server (@$servers) {
        my $ip = $server->ipv4 // '-';
        my $labels_hash = $server->labels // {};
        my $labels = join(', ', map { "$_=$labels_hash->{$_}" } keys %$labels_hash);

        printf "%-10s %-25s %-10s %-16s %-10s %s\n",
            $server->id,
            $server->name,
            $server->status,
            $ip,
            $server->server_type->{name},
            $labels || '-';
    }

    return 0;
}

1;

__END__

=synopsis

    # List every server the Hetzner project can see
    ocp hetzner list

    # Filter by OCP cluster label
    ocp hetzner list --label ocp-cluster=prod

=description

C<ocp hetzner list> is a debug-only listing command that talks straight to
the Hetzner Cloud API via L<WWW::Hetzner::Cloud>.  It is not an adapter
for cluster provisioning — for that, see L<OCP::Provider::Hetzner>, which
is what C<ocp apply> actually uses.

The command exists to answer the question "what does this token see?" when
reconciling a cluster by hand: servers whose C<ocp-cluster=> label does
not match the current C<ocp.yaml>, leftover orphans after a partial
C<ocp destroy>, or machines the API key has access to but the project
directory does not name.

The token is read from C<$HETZNER_API_TOKEN> or the encrypted secrets
store (set up by C<ocp init --hetzner>); without it the command dies with
a hint to run C<ocp init --hetzner>.

=opt label

    --label ocp-cluster=prod[,key=value,...]

Filter the listing to servers carrying every label key/value pair given.
Passes through to L<WWW::Hetzner::Cloud/servers/list_by_label>.

=method execute

    $cmd->execute($args, $chain)

Prints a tabular listing (ID, name, status, IPv4, server type, labels).
Returns 0 on success, or dies when no token is configured.

=seealso

L<OCP::Provider::Hetzner>, L<OCP::Hetzner::Picker>, L<OCP::Secrets>,
L<WWW::Hetzner::Cloud>

=cut

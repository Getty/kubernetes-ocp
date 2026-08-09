package OCP::Cmd::Hetzner;
# ABSTRACT: Hetzner Cloud debugging

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);

use OCP::Secrets;
use WWW::Hetzner::Cloud;

our $VERSION = '0.001';

option list => (
    is      => 'ro',
    short   => 'l',
    doc     => 'List servers (default)',
    default => 1,
);

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

    # Default: list servers
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

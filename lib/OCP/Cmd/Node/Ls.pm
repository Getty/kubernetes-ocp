package OCP::Cmd::Node::Ls;
# ABSTRACT: List OCPNode CRs

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use OCP::Config;
use OCP::Secrets;
use OCP::K8s;
use Time::Piece;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

has k8s => (is => 'rw');

sub _k8s {
    my $self = shift;
    return $self->k8s if $self->k8s;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config  = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $kc_content = $secrets->read_kubeconfig;
    die "ERROR: Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
        unless $kc_content;

    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$kc_fh} $kc_content;
    close $kc_fh;

    my $api = Kubernetes::REST::Kubeconfig->new(
        kubeconfig_path => $kc_fh->filename,
    )->api;

    OCP::K8s->register($api);
    $self->k8s($api);
    return $api;
}

sub execute {
    my ($self, $args, $chain) = @_;

    my $api = $self->_k8s;
    my $ns  = 'ocp-system';

    my $list = $api->list('OCPNode', namespace => $ns);
    my @nodes = map { $api->k8s->object_to_struct($_) } @{ $list->items // [] };

    printf "%-16s %-13s %-12s %-14s %-15s %s\n",
        qw(NAME ROLE PHASE PROVIDER IP AGE);
    for my $n (sort { $a->{metadata}{name} cmp $b->{metadata}{name} } @nodes) {
        printf "%-16s %-13s %-12s %-14s %-15s %s\n",
            $n->{metadata}{name},
            $n->{spec}{role}              // '',
            $n->{status}{phase}           // 'Pending',
            $n->{spec}{providerRef}       // '',
            $n->{status}{publicIP}        // '',
            _age($n->{metadata}{creationTimestamp});
    }

    return 0;
}

sub _age {
    my $ts = shift;
    return '?' unless $ts;
    my $created = eval { Time::Piece->strptime($ts, '%Y-%m-%dT%H:%M:%SZ')->epoch };
    return '?' unless $created;
    my $diff = time - $created;
    return $diff < 60   ? "${diff}s"
         : $diff < 3600 ? sprintf('%dm', $diff / 60)
         : $diff < 86400 ? sprintf('%dh', $diff / 3600)
         :                 sprintf('%dd', $diff / 86400);
}

1;

__END__

=head1 NAME

OCP::Cmd::Node::Ls - List OCPNode CRs

=head1 SYNOPSIS

    ocp node ls

=head1 DESCRIPTION

Lists all OCPNode CRs in the C<ocp-system> namespace.  Columns: NAME, ROLE,
PHASE, PROVIDER, IP, AGE.

=head1 SEE ALSO

L<OCP::Cmd::Node::Add>, L<OCP::Cmd::Node::Rm>

=cut

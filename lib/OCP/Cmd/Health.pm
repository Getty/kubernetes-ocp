package OCP::Cmd::Health;
# ABSTRACT: One-shot cluster health report

use Moo;
use MooX::Cmd;
use MooX::Options;
use JSON::MaybeXS ();

use OCP::Cmd::Apply::Health ();
use OCP::Config;
use OCP::Kubernetes;
use OCP::Secrets;

with 'OCP::Role::Cmd';

=opt json

    --json

Print one canonical JSON document on STDOUT instead of the text report;
diagnostics go to STDERR.  See L</JSON OUTPUT>.

=cut

option json => (
    is  => 'ro',
    doc => 'Print the health report as canonical JSON on STDOUT (diagnostics on STDERR, no timestamps)',
);

=attr api

An already built Kubernetes API client.  Unset, the command builds one from the
project's kubeconfig.  Mainly the seam for tests.

=cut

has api => (is => 'rw');

sub _api {
    my ($self) = @_;
    return $self->api if $self->api;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config = OCP::Config->new(file => $file);
    die "No cluster deployed yet. Run 'ocp apply' to deploy.\n"
        unless $config->cluster_exists;

    my $kc = OCP::Secrets->new(project_dir => $config->project_dir)->read_kubeconfig;
    die "Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
        unless $kc;

    return $self->api(OCP::Kubernetes->new(kubeconfig => $kc)->api);
}

# One scan, no waiting: check() with a zero timeout stops after the first scan
# whatever is still starting, so the critical/warnings/starting split is the
# one the gate at the end of `ocp apply` applies.
sub _health {
    my ($self, $api) = @_;
    return OCP::Cmd::Apply::Health::check($self, $api, timeout => 0);
}

sub execute {
    my ($self, $args, $chain) = @_;

    my $health = eval { $self->_health($self->_api) };
    unless ($health) {
        my $error = $@ || 'Unknown error';
        chomp $error;
        # The JSON form still answers on STDOUT; the diagnosis goes to STDERR.
        if ($self->json) {
            print STDERR "ERROR: $error\n";
            print JSON::MaybeXS->new(canonical => 1, pretty => 1)->encode({
                error => $error, healthy => JSON::MaybeXS::false(), pods => [],
            });
            return 1;
        }
        die "$error\n";
    }

    my $fatal = OCP::Cmd::Apply::Health::is_fatal($self, $health) ? 1 : 0;

    if ($self->json) {
        my @pods;
        for my $pair ([critical => 'critical'], [warnings => 'warning'], [starting => 'starting']) {
            push @pods, map {
                +{
                    namespace => $_->{namespace},
                    name      => $_->{name},
                    state     => $pair->[1],
                    reason    => ($pair->[1] eq 'starting' && !length($_->{reason} // '')
                                  ? 'still starting' : $_->{reason}),
                }
            } @{ $health->{ $pair->[0] } };
        }
        @pods = sort { $a->{namespace} cmp $b->{namespace} || $a->{name} cmp $b->{name} } @pods;

        print JSON::MaybeXS->new(canonical => 1, pretty => 1)->encode({
            healthy => ($fatal || @pods ? JSON::MaybeXS::false() : JSON::MaybeXS::true()),
            fatal   => ($fatal ? JSON::MaybeXS::true() : JSON::MaybeXS::false()),
            pods    => \@pods,
        });
        return $fatal;
    }

    OCP::Cmd::Apply::Health::print($self, $health);
    return $fatal;
}

1;

__END__

=head1 SYNOPSIS

    ocp health
    ocp health --json

=head1 DESCRIPTION

C<ocp health> scans every pod once through the Kubernetes API and reports what
is not healthy, using the same classification and the same severity split as
the health gate at the end of C<ocp apply> (L<OCP::Cmd::Apply::Health>):
C<critical> is a durable fault in C<kube-system> (fatal, exit code 1),
C<warning> a durable fault elsewhere, C<starting> a pod that is still coming
up.  Unlike the gate it does not wait for the cluster to settle, and it never
changes anything.  Exit code: 1 when a critical pod exists (or the cluster
cannot be reached), else 0.

=head1 JSON OUTPUT

C<--json> prints one canonical JSON object (sorted keys, no timestamps) on
STDOUT and nothing else; diagnostics go to STDERR.

    {
       "fatal" : false,
       "healthy" : false,
       "pods" : [
          {
             "name" : "dcgm-exporter-x7k2p",
             "namespace" : "gpu-operator",
             "reason" : "ImagePullBackOff",
             "state" : "warning"
          },
          {
             "name" : "cilium-8pjjp",
             "namespace" : "kube-system",
             "reason" : "still starting",
             "state" : "starting"
          }
       ]
    }

C<pods> is sorted by namespace, then name; C<state> is C<critical>,
C<warning> or C<starting>.  C<healthy> is true when C<pods> is empty.  When
the cluster cannot be reached the object has an C<error> string, an empty
C<pods> and the exit code is 1.

B<Known instability:> a pod stuck for a long time gets a reason such as
C<stuck in Init for 17m (ContainerCreating)>, and the minutes are part of the
text, so that reason changes between runs while the pod stays stuck.  Compare
C<namespace>, C<name> and C<state>, not C<reason>, if byte-identical runs
matter.

=seealso

L<OCP::Cmd::Apply::Health>, L<OCP::Cmd::Status>

=cut

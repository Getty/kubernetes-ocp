package OCP::Cmd::Health;
# ABSTRACT: One-shot cluster health report

use Moo;
use MooX::Cmd;
use MooX::Options;
use JSON::MaybeXS ();

use OCP ();
use OCP::Cmd::Apply::Health ();
use OCP::Config;
use OCP::ErrorLine ();

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

    # The key, kubeconfig.yaml, the client and one GET /version: an API that
    # does not answer, or answers /version with an error, is said there, in
    # one line (k384, k387, k399).
    return $self->api($self->cluster_api);
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
        # An error the API answered the scan with is one line naming the
        # server (k387); anything else is said as it came.
        $error = $self->cluster_api_error($self->api, $error) // $error;
        chomp $error;
        # The JSON form still answers on STDOUT, the error one line without
        # a label; STDERR says it as ocp health says it without --json, by
        # the renderer that says the die below (k395). It said "ERROR:"
        # where the text form says "Error:", and "ERROR: ERROR:" for a
        # refusal that carries its own.
        if ($self->json) {
            print JSON::MaybeXS->new(canonical => 1, pretty => 1)->encode({
                error   => OCP::ErrorLine::json_error($error),
                healthy => JSON::MaybeXS::false(),
                pods    => [],
            });
            my $root = ($self->command_chain // [])->[0];
            return OCP::_report_error("$error\n",
                $root && $root->can('verbose') ? $root->verbose : 0, 0);
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
cannot be read), else 0.  An API server that does not answer, or answers
with an error status (a token it refuses, RBAC that denies the pod list), is
one line on STDERR naming the server from the kubeconfig, what became of the
request and why (L<OCP::Role::Cmd/cluster_api_error>); with C<--json> the
same line is the C<error> of the object.

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
the cluster cannot be reached the object has an C<error> string -- the
message as one line, without an C<ERROR:> label --, an empty C<pods> and the
exit code is 1.  STDERR says the error as C<ocp health> says it without
C<--json>.

B<Known instability:> a pod stuck for a long time gets a reason such as
C<stuck in Init for 17m (ContainerCreating)>, and the minutes are part of the
text, so that reason changes between runs while the pod stays stuck.  Compare
C<namespace>, C<name> and C<state>, not C<reason>, if byte-identical runs
matter.

=seealso

L<OCP::Cmd::Apply::Health>, L<OCP::Cmd::Status>

=cut

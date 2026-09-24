package OCP::Robocop::Manifest;
# ABSTRACT: Shape the shipped robocop manifests for a robocop.security_level

use strict;
use warnings;

use Carp qw( croak );

#
# share/robocop/deployment.yaml is the `secret` Deployment: ROBO_SSH_KEY comes
# from the robocop-credentials Secret. `inject` (k2) must not reference the
# private key at all, so both paths that apply the manifests --
# `ocp deploy-robocop` and `ocp apply` -- pass every document through here.
# One transform instead of a second deployment.yaml: the two would drift, and
# the inject variant differs in exactly the lines below.
#
# inject changes the robocop Deployment's controller container:
#
#   - ROBO_SSH_KEY goes; ROBOCOP_SECURITY_LEVEL=inject and ROBO_SSH_PUBLIC_KEY
#     (the public half, from the same Secret) come in
#   - the /tmp emptyDir becomes medium: Memory -- OCP::Node hands the key to
#     Rex as a temp file there (OCP::TempKeyPair), and on tmpfs that file
#     never reaches the node's disk
#   - a readinessProbe on the controller's key-held file, so a robocop
#     without a key is not Ready
#
# Everything else passes through unchanged.
#
# for_config wraps that and adds what robocop has to know about the cluster
# and can learn nowhere else (k186, k184): the distribution and the pod CIDR,
# as plain values from ocp.yaml. The shipped deployment.yaml carries neither,
# so a Deployment that did not come through here has no value to guess from,
# and the controller refuses to start without them.
#
# Why the Deployment's env and not the robocop-credentials Secret or the
# OCPNodeProvider CR:
#
#   - both deploy paths write the Deployment on every run, unconditionally;
#     the Secret is skipped while current, and rewriting it costs an SSH
#     read of the join token (PIN2 in secure mode)
#   - a changed value changes the pod template, so the Deployment rolls and
#     robocop restarts with it; a changed Secret key reaches a running pod
#     only on its next restart
#   - it is there at startup, where a missing value can end the process;
#     a provider CR is read per OCPNode event, is per provider rather than
#     per cluster, and `ocp deploy-robocop` does not write it
#   - neither value is a secret
#

# The file the controller keeps while it holds a key; OCP::Robocop::Controller's
# ready_file defaults to this, so probe and writer cannot disagree.
use constant READY_FILE => '/tmp/robocop-key-ready';

=method for_security_level

    my $doc = OCP::Robocop::Manifest->for_security_level($doc, $level);

Returns the manifest document for C<$level>. Only the robocop C<Deployment>
under C<inject> is changed (in place, and returned); any other document or
level comes back as given.

=cut

sub for_security_level {
    my ($class, $doc, $level) = @_;

    return $doc unless ($level // '') eq 'inject';
    return $doc unless ref $doc eq 'HASH'
        && ($doc->{kind} // '') eq 'Deployment'
        && ($doc->{metadata}{name} // '') eq 'robocop';

    my $pod = $doc->{spec}{template}{spec};
    my ($ctr) = grep { ($_->{name} // '') eq 'controller' } @{ $pod->{containers} // [] };
    return $doc unless $ctr;

    $ctr->{env} = [
        (grep { ($_->{name} // '') ne 'ROBO_SSH_KEY' } @{ $ctr->{env} // [] }),
        { name => 'ROBOCOP_SECURITY_LEVEL', value => 'inject' },
        {
            name      => 'ROBO_SSH_PUBLIC_KEY',
            valueFrom => {
                secretKeyRef => { name => 'robocop-credentials', key => 'robo-ssh-public-key' },
            },
        },
    ];

    $ctr->{readinessProbe} = {
        exec                => { command => [ 'test', '-f', READY_FILE ] },
        initialDelaySeconds => 5,
        periodSeconds       => 10,
    };

    for my $vol (@{ $pod->{volumes} // [] }) {
        next unless ($vol->{name} // '') eq 'tmp';
        $vol->{emptyDir} = { %{ $vol->{emptyDir} // {} }, medium => 'Memory' };
    }

    return $doc;
}

=method for_config

    my $doc = OCP::Robocop::Manifest->for_config($doc, $config);

L</for_security_level> for C<< $config->robocop_security_level >>, and on the
robocop C<Deployment> the controller's env entries from L</cluster_env>,
replacing any value already there. Any other document comes back as the
level shapes it.

=cut

sub for_config {
    my ($class, $doc, $config) = @_;

    $doc = $class->for_security_level($doc, $config->robocop_security_level);

    my $ctr = $class->_controller($doc) or return $doc;

    my $env = $class->cluster_env($config);
    my %set = map { $_->{name} => 1 } @$env;

    $ctr->{env} = [
        (grep { !$set{ $_->{name} // '' } } @{ $ctr->{env} // [] }),
        @$env
    ];

    return $doc;
}

=method cluster_env

    my $env = OCP::Robocop::Manifest->cluster_env($config);
    # [ { name => 'OCP_DISTRIBUTION', value => 'k3s' },
    #   { name => 'OCP_POD_CIDR',     value => '10.42.0.0/16' } ]

The controller's env entries for what robocop has to know about the cluster:
C<OCP_DISTRIBUTION> from C<< $config->distribution >> and C<OCP_POD_CIDR>
from C<< $config->pod_cidr >>, sorted by name. Croaks when the config has
either empty. L</for_config> writes them into a full manifest;
C<ocp deploy-image> sends them in its image patch (k187), so a Deployment
written before robocop needed them gets them together with the new image.

=cut

sub cluster_env {
    my ($class, $config) = @_;

    my %value = (
        OCP_DISTRIBUTION => $config->distribution,
        OCP_POD_CIDR     => $config->pod_cidr,
    );
    for my $name (sort keys %value) {
        croak __PACKAGE__.'->cluster_env: no value for '.$name
            unless defined $value{$name} && length $value{$name};
    }

    return [ map { { name => $_, value => $value{$_} } } sort keys %value ];
}

# The robocop Deployment's controller container; nothing for any other
# document.
sub _controller {
    my ($class, $doc) = @_;
    return unless ref $doc eq 'HASH'
        && ($doc->{kind} // '') eq 'Deployment'
        && ($doc->{metadata}{name} // '') eq 'robocop';
    my ($ctr) = grep { ($_->{name} // '') eq 'controller' }
        @{ $doc->{spec}{template}{spec}{containers} // [] };
    return $ctr;
}

1;

=head1 SYNOPSIS

    for my $doc (YAML::XS::LoadFile($file)) {
        $api->ensure(OCP::Robocop::Manifest->for_config($doc, $config));
    }

=head1 SEE ALSO

L<OCP::Cmd::DeployRobocop>, L<OCP::Cmd::Apply::CR>, L<OCP::Robocop::Controller>

=cut

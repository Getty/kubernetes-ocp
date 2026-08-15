package OCP::Role::Cmd;
# ABSTRACT: Base role for OCP commands

use Moo::Role;

sub ocp { $_[0]->command_chain->[0] }

# Which private key reaches this cluster's machines — see OCP::ClusterKey for
# the answer itself. This is only the caching: on secure mode + a provider OCP
# created the machines for, obtaining it prompts for PIN2, and `ocp update`
# asks once per component. Cached per command object, so the prompt happens on
# the first component and the temp file lives exactly as long as the command
# that needed it.
#
# Deliberately a plain hash slot rather than a Moo attribute: this role is
# consumed by every OCP::Cmd::* class and its constructor surface is part of
# the CLI's contract (MooX::Cmd/MooX::Options both read it). Nothing should be
# able to pass a cluster key in from the command line.
sub cluster_ssh_key {
    my ($self, $config, %opt) = @_;

    require OCP::ClusterKey;

    # Keyed on the project, not just on the object. One command instance can
    # be handed more than one config — the tests do exactly that — and a flat
    # slot would then serve a key built for a different project directory.
    my $slot = OCP::ClusterKey::cache_slot($config, %opt);
    return $self->{_cluster_ssh_key}{$slot}
        //= OCP::ClusterKey->for_config($config, %opt);
}

1;

__END__

=synopsis

    package OCP::Cmd::Something;
    use Moo;
    use MooX::Cmd;
    with 'OCP::Role::Cmd';

    sub execute {
        my $self = shift;
        my $config_path = $self->ocp->config;   # path to ocp.yaml
        my $verbose     = $self->ocp->verbose;  # 0 / 1
    }

=description

A small role consumed by every C<OCP::Cmd::*> class.  Its main job is to
expose the root C<OCP> object so commands can reach the project
configuration without each command having to thread it through.

L<MooX::Cmd> composes commands into a chain (root, sub-command, sub-sub).
The root is always the first element; C<ocp> returns it directly, so
commands at any depth see the same C<OCP> instance.

=method ocp

    my $ocp = $self->ocp;

Returns the first element of the L<MooX::Cmd> C<command_chain>, i.e. the
root C<OCP> object.  Use it to read C<config> (path to C<ocp.yaml>) and
C<verbose>, and to share file/IO helpers (C<dump>, C<dump_file>,
C<load_file>) across commands.

=method cluster_ssh_key

    my $key = $self->cluster_ssh_key($config);
    my $key = $self->cluster_ssh_key($config, provider => 'ssh',
                                              reason   => 'ocp destroy');

The L<OCP::ClusterKey> for this cluster, built once per command object and
reused for every later call.  Dies with a message naming what was missing if
no usable key can be obtained.

The caching is the point: in secure mode on a provider whose machines OCP
created, building this key prompts for PIN2.  C<ocp update> walks a list of
components and would otherwise prompt once per component.  Because the object
is held by the command, its temporary files also live exactly as long as the
command that needed them and are unlinked when it goes away.

=seealso

L<MooX::Cmd>, L<OCP>, L<OCP::ClusterKey>, L<OCP::Cmd::Apply>,
L<OCP::Cmd::Status>

=cut

package OCP::Role::Cmd;
# ABSTRACT: Base role for OCP commands

use Moo::Role;

sub ocp { $_[0]->command_chain->[0] }

# Provider types, as spelled in spec.type and in `ocp init --provider`. Listed
# here only to recognise the mistake in provider_cr below; OCP::Provider is the
# authority on what OCP can actually build.
my @PROVIDER_TYPES = qw(hetzner ssh local);

# A provider is addressed by the NAME of its OCPNodeProvider CR, while
# `ocp init --provider` and spec.type speak provider TYPES. Naming the type
# (`--provider ssh` for the CR `ssh-default` that `ocp apply` writes) is the
# mistake people actually make, and it cost a SPIKE iteration before the
# rejection said anything useful (karr #89). So every command that rejects a
# provider name does it from here, in the shape `ocp typo` answers in
# (OCP::_resolve_commands): name the word, then say what would have worked.
#
# Deliberately not resolving 'ssh' to 'ssh-default': that would open a second
# namespace next to the CR names, and nothing stops anyone from calling a
# provider 'ssh'. Input we do not understand is refused and explained.
sub provider_crs {
    my ($self, $api, %opt) = @_;

    my $ns = $opt{namespace} // 'ocp-system';

    my $list = eval { $api->list('OCPNodeProvider', namespace => $ns) }
        or return ();

    return sort { $a->{metadata}{name} cmp $b->{metadata}{name} }
           map  { $api->k8s->object_to_struct($_) } @{ $list->items // [] };
}

sub provider_choices {
    my ($self, @providers) = @_;

    return "No OCPNodeProvider exists in this cluster.\n"
         . "'ocp apply' writes one per provider in ocp.yaml;"
         . " 'ocp provider add' adds one by hand.\n"
        unless @providers;

    # Name AND type: the type is what the operator typed, so leaving it out
    # would show the right answer without showing why it is the right answer.
    return 'Available: '
         . join(', ', map {
               sprintf '%s (type %s)',
                   $_->{metadata}{name}, $_->{spec}{type} // '?'
           } @providers)
         . "\n";
}

sub provider_cr {
    my ($self, $api, $name, %opt) = @_;

    my $ns = $opt{namespace} // 'ocp-system';

    my $cr = eval { $api->get('OCPNodeProvider', name => $name, namespace => $ns) };
    return $api->k8s->object_to_struct($cr) if $cr;

    # The type hint only where it helps: on a cluster without any provider CR
    # the answer is "run ocp apply", and naming the CR that run would create
    # would just say ocp apply twice.
    my @providers = $self->provider_crs($api, %opt);
    my $type_hint = (@providers && grep { $_ eq $name } @PROVIDER_TYPES)
        ? "'$name' is a provider type, not a provider name."
          . " 'ocp apply' names its CR '$name-default'.\n"
        : '';

    die "Unknown provider '$name'.\n"
      . $self->provider_choices(@providers)
      . $type_hint;
}

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

# The key this command has ALREADY got, or nothing. Never builds one.
#
# For explaining a failure, not for reaching a machine. What a refused SSH
# login probably means is OCP::ClusterKey::migration_hint's answer, and asking
# for it costs a key object — but going through cluster_ssh_key above to get
# one would prompt for PIN2 in the middle of a rollout that never asked for a
# password, purely to decide whether to print a paragraph. That is the wrong
# way round: a diagnosis may not change what the run does.
#
# No key means no diagnosis, which is the honest outcome — a run that never
# obtained a key never offered one to a machine either, so it has nothing to
# say about which key that machine trusts.
sub cluster_ssh_key_if_known {
    my ($self, $config, %opt) = @_;

    require OCP::ClusterKey;

    return $self->{_cluster_ssh_key}{ OCP::ClusterKey::cache_slot($config, %opt) };
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

=method cluster_ssh_key_if_known

    my $key = $self->cluster_ssh_key_if_known($config);
    print $key->migration_hint if $key;

The L<OCP::ClusterKey> this command has already built, or C<undef>.  Unlike
L</cluster_ssh_key> it never builds one, never prompts and never writes a temp
file.

Use it for diagnosis after something failed — the case it exists for is
L<OCP::ClusterKey/migration_hint>, where the only question is whether to print
an explanation.  Building a key for that would make a message cost a PIN2
prompt in the middle of a run that had not asked for one.  Use
L</cluster_ssh_key> whenever the key is actually going to reach a machine.

=method provider_crs

    my @providers = $self->provider_crs($api);
    my @providers = $self->provider_crs($api, namespace => 'other');

Every C<OCPNodeProvider> CR in the namespace (C<ocp-system> by default) as
plain hashes, sorted by name.  Returns an empty list when the cluster has
none or when the list call fails, so it is safe to call while building an
error message.

=method provider_choices

    die "Multiple providers found, --provider required.\n"
      . $self->provider_choices(@providers);

The C<Available: NAME (type TYPE), ...> line for a list of provider hashes,
newline-terminated.  Given an empty list it returns the bootstrap hint
instead (C<ocp apply> / C<ocp provider add>), so a caller never has to
special-case a cluster without providers.

Both name and type are shown on purpose: C<--provider> takes the CR name,
while C<ocp init --provider> and C<spec.type> take the type, and confusing
the two is the mistake this exists to answer.

=method provider_cr

    my $provider = $self->provider_cr($api, 'ssh-default');

The named C<OCPNodeProvider> as a plain hash.  Dies if there is no such CR,
naming the providers that do exist with their types:

    Unknown provider 'ssh'.
    Available: hetzner-default (type hetzner), ssh-default (type ssh)
    'ssh' is a provider type, not a provider name. 'ocp apply' names its CR 'ssh-default'.

The last line appears only when the rejected name is a provider type and the
cluster has providers at all; without any, the bootstrap hint is the whole
answer.  A type is never resolved to the CR that happens to carry it:
provider names and provider types are separate namespaces and may collide.

=seealso

L<MooX::Cmd>, L<OCP>, L<OCP::ClusterKey>, L<OCP::Cmd::Apply>,
L<OCP::Cmd::Status>, L<OCP::Cmd::Node::Add>, L<OCP::Cmd::Provider::Rm>

=cut

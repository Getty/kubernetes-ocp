package OCP::Cmd::Node::TrustHost;
# ABSTRACT: Forget the pinned SSH host keys of an OCPNode

use Moo;
use MooX::Cmd;
use MooX::Options;
use List::Util qw(first);
use OCP::Choices;
use OCP::K8s;

with 'OCP::Role::Cmd';
with 'OCP::Role::Cmd::Confirm';

option name => (
    is     => 'ro',
    format => 's',
    doc    => 'Node name (may also be given as the first argument)',
);

option yes => (
    is  => 'ro',
    doc => 'Do not ask for confirmation',
);

has k8s => (is => 'rw');

sub _k8s {
    my $self = shift;
    return $self->k8s if $self->k8s;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    # The key, kubeconfig.yaml, the client and one GET /version: an API that
    # does not answer, or answers /version with an error, is said there, in
    # one line (k389, k399).
    return $self->k8s($self->cluster_api);
}

sub _node_names {
    my ($self, $api, $ns) = @_;
    my $list = eval { $api->list('OCPNode', namespace => $ns) } or return ();
    return sort map { $api->k8s->object_to_struct($_)->{metadata}{name} }
                @{ $list->items // [] };
}

sub execute {
    my ($self, $args, $chain) = @_;

    my $name = $self->name // first { !/^-/ } @{ $args // [] };
    die "Usage: ocp node trust-host NAME [--yes]\n" unless defined $name && length $name;

    my $api = $self->_k8s;
    my $ns  = 'ocp-system';

    my $cr_obj = eval { $api->get('OCPNode', name => $name, namespace => $ns) };
    if ($@ || !$cr_obj) {
        die OCP::Choices::unknown('node', $name, [ $self->_node_names($api, $ns) ],
            empty => "No OCPNode exists in this cluster;"
                   . " 'ocp node add' creates one.\n");
    }

    my $cr   = $api->k8s->object_to_struct($cr_obj);
    my $keys = $cr->{status}{hostKeys};
    unless (ref $keys eq 'ARRAY' && @$keys) {
        print "Node '$name' has no pinned host keys; the next contact trusts on first use.\n";
        return 0;
    }

    # Forgetting the pins lets the next contact trust whatever key the
    # machine presents, so the answer has to come from a person at a
    # terminal; --yes is the way to confirm from a script (k293).
    unless ($self->yes || $self->confirmed(
        question => "Forget the pinned host keys of node '".$name."'?\n"
                  . join('', map { '  '.$_->{fingerprint}.' ('.$_->{type}.")\n" } @$keys)
                  . 'The next contact trusts whatever key the machine presents then.',
        action   => "forgetting the pinned host keys of node '".$name."'",
        switch   => '--yes',
    )) {
        print STDERR "Aborted; the pinned host keys stay.\n";
        return 1;
    }

    # Merge patch: null removes the field. The message is cleared with it
    # when it is the changed-key complaint this command answers.
    my $status = { hostKeys => undef };
    $status->{message} = undef
        if ($cr->{status}{message} // '') =~ /\Ahost key of .* changed/;
    OCP::K8s->patch_status($api,
        kind      => 'OCPNode',
        name      => $name,
        namespace => $ns,
        status    => $status,
    );

    print "Pinned host keys of node '$name' removed; the next contact trusts on first use.\n";
    return 0;
}

1;

__END__

=head1 NAME

OCP::Cmd::Node::TrustHost - Forget the pinned SSH host keys of an OCPNode

=head1 SYNOPSIS

    ocp node trust-host worker-1
    ocp node trust-host worker-1 --yes

=head1 DESCRIPTION

The first successful SSH contact with a node pins the machine's host keys in
the OCPNode's C<status.hostKeys> (SHA256 fingerprint and key per type), and the
CLI and every robocop pod verify each later contact against them. A key that
differs leaves the node's phase alone, writes C<host key of X changed (expected
SHA256:..., got SHA256:...)> to C<status.message> and touches nothing.

If the machine was rebuilt on purpose, this command deletes C<status.hostKeys>
(after a confirmation, or at once with C<--yes>); the next contact is trust on
first use again and pins whatever the machine presents then.

The confirmation is asked on a terminal only. Without one (a pipe, a CI job)
the command does not read STDIN at all: it says so on STDERR, leaves the pins
and exits C<1>; a piped C<y> is not a confirmation. C<--yes> is the way to
confirm from a script.

=head1 OPTIONS

=head2 --yes

Skip the confirmation; the only way to forget the pins without a terminal.

=cut

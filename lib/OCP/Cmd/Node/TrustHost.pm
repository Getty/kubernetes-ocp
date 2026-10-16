package OCP::Cmd::Node::TrustHost;
# ABSTRACT: Forget the pinned SSH host keys of an OCPNode

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use List::Util qw(first);
use OCP::Choices;
use OCP::Config;
use OCP::Secrets;
use OCP::K8s;

with 'OCP::Role::Cmd';

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

sub _node_names {
    my ($self, $api, $ns) = @_;
    my $list = eval { $api->list('OCPNode', namespace => $ns) } or return ();
    return sort map { $api->k8s->object_to_struct($_)->{metadata}{name} }
                @{ $list->items // [] };
}

# Stdin is the confirmation; a closed or non-terminal stdin answers "no".
sub _confirmed {
    my ($self, $name, $keys) = @_;
    print STDERR "Forget the pinned host keys of node '$name'?\n";
    print STDERR '  ' . $_->{fingerprint} . ' (' . $_->{type} . ")\n" for @$keys;
    print STDERR "The next contact trusts whatever key the machine presents then. [y/N] ";
    my $answer = <STDIN>;
    return defined $answer && $answer =~ /\A\s*y(?:es)?\s*\z/i;
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

    unless ($self->yes || $self->_confirmed($name, $keys)) {
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

=head1 OPTIONS

=head2 --yes

Skip the confirmation.

=cut

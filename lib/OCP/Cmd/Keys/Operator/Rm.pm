package OCP::Cmd::Keys::Operator::Rm;
# ABSTRACT: Revoke an operator: its SSH key off every machine, its age key out, say what to rotate

use Moo;
use MooX::Cmd;
use MooX::Options;

use OCP::Choices;

with 'OCP::Role::Cmd';
with 'OCP::Role::Cmd::Recipients';
with 'OCP::Role::Cmd::Machines';
with 'OCP::Role::Cmd::Operator';

my $USAGE = 'ocp keys operator rm NAME';

#
# k216: revoking a Leitstand takes away both of its keys. Its SSH key comes off
# every machine (logged in with the admin key, PIN2), its entry out of
# keys.yaml, its age recipient out of .sops.yaml, and the files are
# re-encrypted without it.
#
# The revocation does not wait for a dead machine: a host that cannot be
# reached is named -- with the line still on it, so it can be removed by hand
# -- and the entry and the recipient go anyway; the exit code is 1. Waiting
# would leave the operator able to decrypt everything written from now on
# because one machine was down.

sub execute {
    my ( $self, $args, $chain ) = @_;

    my @words = $self->positional_args($args);
    die "usage: $USAGE\n" if @words > 1;
    my $name = $self->operator_name_arg($words[0], $USAGE);

    my ( $config, $secrets, $keys ) = $self->operator_project('rm');

    my @operators = $self->operator_entries($keys);
    my ($entry) = grep { $_->{name} eq $name } @operators;
    die OCP::Choices::unknown('operator', $name, [ map { $_->{name} } @operators ],
        empty => "keys.yaml lists no operator.\n")
        unless $entry;

    my $age    = $entry->{age} // '';
    my $public = $entry->{public} // '';
    my $blob   = eval { $self->_key_blob($public) };

    my @extras   = $secrets->extra_recipients;
    my $listed   = grep { $_ eq $age } @extras;
    my $external = $listed && !$secrets->sops_config_editable;

    # The machines first, while the entry still says which key to take off.
    my $api = $self->_cluster_api($config, $secrets);
    my ($machines) = $self->_machines($config, $api);
    my @failed = defined $blob ? $self->_take_off($config, $machines, $name, $blob) : ();

    # Then the record, whatever the machines said.
    print "\n";
    if ($listed && !$external) {
        $secrets->set_sops_recipients([ grep { $_ ne $age } @extras ]);
        print "[ok] Removed $age from " . $secrets->sops_config_file . "\n";
    }
    $keys->delete_key($name);
    print "[ok] keys.yaml: operator '$name' removed\n";

    my @done = $self->reencrypt($secrets);
    print STDERR $self->rotation_hint($secrets, $age, @done) if length $age;

    my $rc = 0;
    if ($external) {
        my $file = $secrets->governing_sops_config;
        print STDERR "\n"
          . "[!!] $age is still a recipient: it is listed in\n"
          . "       $file\n"
          . "     which lies outside this project; ocp reads it but does not rewrite it.\n"
          . "     Remove it from the creation rule there, then run\n"
          . "       ocp keys recipients rm $age\n"
          . "     to re-encrypt the files without it.\n";
        $rc = 1;
    }

    if (@failed) {
        print STDERR "\n";
        print STDERR "[!!] $_->{label}: could not remove the operator key: $_->{why}\n" for @failed;
        print STDERR "\n"
          . "The operator key '$name' is STILL in authorized_keys on:\n"
          . join('', map { "  $_->{label}\n" } @failed)
          . "and still opens them. keys.yaml and the recipients no longer list it, so\n"
          . "this command cannot be repeated for them: remove the line carrying\n"
          . "  $public\n"
          . "there by hand, e.g. as root on each:\n"
          . "  grep -vF '$blob' ~/.ssh/authorized_keys > /tmp/ak && cat /tmp/ak > ~/.ssh/authorized_keys\n";
        $rc = 1;
    }

    return $rc;
}

# The operator's SSH key off every machine. Returns the machines it could not
# be taken off, each with a reason.
sub _take_off {
    my ( $self, $config, $machines, $name, $blob ) = @_;

    unless (@$machines) {
        print "[ok] No machine has been deployed: there is no key to take off\n";
        return ();
    }

    my $key = $self->cluster_ssh_key($config, reason => 'ocp keys operator rm');
    die "ERROR: 'ocp keys operator rm' takes the key off the machines with the admin key,\n"
      . "       and this run holds " . $key->label . ".\n"
        unless $key->origin eq 'admin';

    print "\n";
    my @failed;
    for my $m (@$machines) {
        my $label   = $self->_machine_label($m);
        my $removed = eval { $self->_remove_blob($m, [ $key->path, $key->label ], $blob) };
        unless (defined $removed) {
            push @failed, { label => $label, why => $self->_oneline($@) };
            next;
        }
        print $removed
            ? "[ok] $label: operator key '$name' removed ($removed line"
              . ($removed == 1 ? '' : 's') . ")\n"
            : "[ok] $label: the operator key '$name' was not there\n";
    }
    return @failed;
}

1;

__END__

=head1 NAME

OCP::Cmd::Keys::Operator::Rm - Revoke an operator: its SSH key off every machine, its age key out, say what to rotate

=head1 SYNOPSIS

    ocp keys operator rm leitstand

=head1 DESCRIPTION

Revokes an operator registered with L<OCP::Cmd::Keys::Operator::Add> (k216).
Runs where the project key is: PIN1, and PIN2 for the admin key when there are
machines.

=over 4

=item 1.

Every F</root/.ssh/authorized_keys> line carrying the operator's SSH key is
removed on every machine of the cluster, logged in with the admin key; the
other lines, owner and mode stay.

=item 2.

The entry leaves F<keys.yaml>, the operator's age recipient leaves the
project's F<.sops.yaml>, and the files are re-encrypted with a new data key.
STDERR then says what the operator could read until now and what to rotate
(as C<ocp keys recipients rm>): re-encryption only locks it out of what is
written from now on.

=back

A machine the key cannot be taken off is named on STDERR, with the line to
remove there by hand, and the exit code is 1 -- but step 2 happens anyway: a
revocation must not hang on a machine that is down. A F<.sops.yaml> outside
the project that lists the recipient is not rewritten; the command says so,
exits 1, and C<ocp keys recipients rm> finishes the job once it is edited.

=head1 SEE ALSO

L<OCP::Cmd::Keys::Operator>, L<OCP::Cmd::Keys::Operator::Add>,
L<OCP::Cmd::Keys::Recipients::Rm>, F<docs/security.md>

=cut

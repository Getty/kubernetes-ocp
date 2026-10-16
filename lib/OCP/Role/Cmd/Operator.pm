package OCP::Role::Cmd::Operator;
# ABSTRACT: What the `ocp keys operator` commands share

use OCP::ClusterKey;
use OCP::Config;
use OCP::Keys;

use Moo::Role;

requires qw( ocp project_secrets );

# An operator's name: what `ocp keys operator rm` takes and keys.yaml shows.
# Lower case, digits and dashes, a letter or digit first -- a word that is
# safe in a message, a shell line and a Hetzner key name alike.
my $NAME_RE = qr/\A[a-z0-9][a-z0-9-]{0,62}\z/;

sub operator_name_arg {
    my ($self, $name, $usage) = @_;

    die "usage: $usage\n" unless defined $name && length $name;
    die "Not an operator name: '$name'.\n"
      . "A name is lower-case letters, digits and dashes, starting with a letter\n"
      . "or digit, at most 63 characters (e.g. leitstand-1). Nothing was changed.\n"
        unless $name =~ $NAME_RE;
    return $name;
}

# The project, ready for an operator to be added or removed: secure mode,
# this run holding the project key (an operator does not appoint operators),
# and the age key unlocked (PIN1). Returns ($config, $secrets, $keys).
sub operator_project {
    my ($self, $verb) = @_;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config = OCP::Config->new(file => $file);
    my $keys   = OCP::Keys->new(project_dir => $config->project_dir);

    die "ERROR: Operators exist in secure mode only, and this project has no keys.yaml\n"
      . "       (dev mode, ocp init --nopassword). Move it with 'ocp keys secure' first.\n"
        unless $keys->has_keys_file;

    my ($who, $entry) = OCP::ClusterKey->identity_of($config);
    die "ERROR: 'ocp keys operator $verb' runs where the project key is (PIN1 + PIN2),\n"
      . "       and this run decrypts as the operator '$entry->{name}' (SOPS_AGE_KEY_FILE).\n"
      . "       Unset SOPS_AGE_KEY_FILE there and run it with the project key.\n"
        if $who eq 'operator';
    die OCP::ClusterKey->foreign_identity_refusal($config,
        "'ocp keys operator $verb' runs where the project key is (PIN1 + PIN2).")
        if $who eq 'other';

    my $secrets = $self->project_secrets(unlock => 1);
    return ($config, $secrets, $keys);
}

sub operator_entries {
    my ($self, $keys) = @_;
    return grep { ($_->{purpose} // '') eq 'operator' } @{ $keys->list_keys };
}

1;

__END__

=head1 NAME

OCP::Role::Cmd::Operator - What the C<ocp keys operator> commands share

=head1 DESCRIPTION

C<operator_name_arg> (an operator's name, C<[a-z0-9][a-z0-9-]*>, checked
before anything is touched), C<operator_project> (secure mode, the project key
in hand -- an operator's own identity is refused --, PIN1) and
C<operator_entries> (the C<purpose: operator> entries of F<keys.yaml>), for
L<OCP::Cmd::Keys::Operator::Add> and L<OCP::Cmd::Keys::Operator::Rm>. The
consumer also consumes L<OCP::Role::Cmd> and L<OCP::Role::Cmd::Recipients>.

=cut

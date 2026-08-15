package OCP::Cmd::Keys::Show;
# ABSTRACT: Print a public key from keys.yaml

use Moo;
use MooX::Cmd;
use MooX::Options;

use OCP::Config;
use OCP::Keys;
use OCP::Secrets;

with 'OCP::Role::Cmd';

option purpose => (
    is      => 'ro',
    format  => 's',
    doc     => 'Which key to print: admin (default), automation, general',
);

option name => (
    is     => 'ro',
    format => 's',
    doc    => 'Print the key with this exact name instead of matching a purpose',
);

# The public half of a key in keys.yaml sits behind the age layer only —
# _write_keys_file_encrypted SOPS-encrypts every leaf value, but only
# `private` gets the second, PIN2-derived layer from _double_encrypt (see
# OCP::Keys::add_key). Reading a public key therefore needs PIN1 at most, and
# nothing at all once .ocp/age.key is unlocked. Asking for PIN2 here would be
# security theatre that costs the operator the one thing they need before the
# cluster exists: something to paste into authorized_keys.
#
# Deliberately no cluster_exists gate either. `ocp ssh` has one and is right
# to — it connects to a node. This command answers a question that only
# matters BEFORE the first apply, when there is no cluster yet.
sub execute {
    my ($self, $args, $chain) = @_;

    my $config      = OCP::Config->new(file => $self->ocp->config);
    my $project_dir = $config->project_dir;

    my $secrets = OCP::Secrets->new(project_dir => $project_dir);
    my $keys    = OCP::Keys->new(project_dir => $project_dir);

    unless ($keys->has_keys_file) {
        die "No keys.yaml found in " . $project_dir->stringify . ".\n"
          . "Two-tier keys exist only in secure mode; a --nopassword project\n"
          . "keeps its single key at .ocp/id_ed25519.pub instead.\n";
    }

    # PIN1, if age.key is not already unlocked. Prompts on STDERR.
    $secrets->ensure_age_key();

    my @matched;
    if (my $name = $self->name) {
        my $key = $keys->get_key($name)
            or die "No key named '$name' in keys.yaml.\n";
        @matched = ($key);
    }
    else {
        my $purpose = $self->purpose // 'admin';
        @matched = grep { ($_->{purpose} // '') eq $purpose && !$_->{deprecated} }
                   @{ $keys->list_keys };
        die "No key with purpose '$purpose' in keys.yaml.\n" unless @matched;
    }

    # Public keys go to STDOUT and nothing else does, so the command composes:
    #   ocp keys show --purpose admin >> ~/.ssh/authorized_keys
    for my $key (@matched) {
        my $public = $key->{public};
        unless (defined $public && length $public) {
            die "Key '$key->{name}' has no public half stored in keys.yaml.\n";
        }
        chomp $public;

        print STDERR "$key->{name} ($key->{purpose}):\n";
        print "$public\n";
    }

    return 0;
}

1;

__END__

=head1 NAME

OCP::Cmd::Keys::Show - Print a public key from keys.yaml

=head1 SYNOPSIS

    # The admin public key — what a machine needs in authorized_keys
    # before `ocp apply` or `ocp ssh` can reach it
    ocp keys show

    ocp keys show --purpose automation
    ocp keys show --name admin-ssh-20260815

    # Composes, because only the key itself goes to STDOUT
    ocp keys show --purpose admin >> ~/.ssh/authorized_keys

=head1 DESCRIPTION

Prints the B<public> half of a key stored in F<keys.yaml>. Nothing else: the
private half never leaves the encrypted file through this command, and no
plaintext key is written to disk.

Selection is by C<--purpose> (default C<admin>), which prints every
non-deprecated key of that purpose, or by C<--name> for one exact key.

=head2 What it asks for

PIN1 only, and only when F<.ocp/age.key> is not already unlocked. The public
field is protected by the age layer alone — the PIN2 layer applies to the
private field (see L<OCP::Keys>) — so requiring PIN2 here would block the one
step that has to happen I<before> a cluster exists.

The command works in a freshly initialized project, with no C<ocp.yaml>
deployed and no cluster running.

=head1 OPTIONS

=head2 --purpose <admin|automation|general>

Which key to print. Defaults to C<admin>, the key that reaches control planes
and backs C<ocp ssh>.

=head2 --name <name>

Print the key with this exact name, deprecated or not. Overrides
C<--purpose>.

=head1 SEE ALSO

L<OCP::Cmd::Keys>, L<OCP::Keys>, L<OCP::Cmd::SSH>

=cut

package OCP::Role::Cmd::Recipients;
# ABSTRACT: What the `ocp keys recipients` commands share

use Moo::Role;

use Crypt::Age::Keys;
use OCP::Config;
use OCP::Secrets;

requires 'ocp';

# The project's OCP::Secrets, with the project's own recipient in hand: from
# .ocp/age.pub, or from the key once it is unlocked (PIN1 when it is not).
sub project_secrets {
    my ($self, %opt) = @_;

    my $config  = OCP::Config->new(file => $self->ocp->config);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    # Re-encrypting needs the private key; listing only the public one.
    $secrets->ensure_age_key if $opt{unlock} || !defined $secrets->age_recipient;
    die "No age key in this project. Run 'ocp init' first.\n"
        unless defined $secrets->age_recipient;

    return $secrets;
}

# A recipient from the command line, checked before anything is touched.
sub recipient_arg {
    my ($self, $args, $verb) = @_;

    my $recipient = $args->[0];
    die "usage: ocp keys recipients $verb AGE_RECIPIENT\n"
        unless defined $recipient && length $recipient;
    die "Not an age recipient: '$recipient'.\n"
      . "An age recipient is the PUBLIC key, age1... -- the machine that holds\n"
      . "the private half prints it with 'age-keygen -y'. Nothing was changed.\n"
        unless $recipient =~ /\Aage1/
            && eval { Crypt::Age::Keys->decode_public_key($recipient); 1 };
    return $recipient;
}

# Re-encrypt what is out of step, and say what happened on STDOUT.
sub reencrypt {
    my ($self, $secrets) = @_;

    my @done = $secrets->rotate_sops_files;
    print @done
        ? "[ok] Re-encrypted with a new data key: " . join(', ', @done) . "\n"
        : "[ok] Every encrypted file is already encrypted for this list\n";
    return @done;
}

1;

__END__

=head1 NAME

OCP::Role::Cmd::Recipients - What the C<ocp keys recipients> commands share

=head1 DESCRIPTION

C<project_secrets> (the project's L<OCP::Secrets>, PIN1 when C<unlock> asks
for the private key), C<recipient_arg> (an age recipient from the command line,
checked before anything is touched) and C<reencrypt> (re-encrypt what is out
of step and say so on STDOUT), for L<OCP::Cmd::Keys::Recipients::Ls>,
L<OCP::Cmd::Keys::Recipients::Add> and L<OCP::Cmd::Keys::Recipients::Rm>.

=cut

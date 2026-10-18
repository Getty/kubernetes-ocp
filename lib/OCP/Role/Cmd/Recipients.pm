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

    my ($recipient) = $self->positional_args($args);
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

# "keys.yaml was re-encrypted", "A and B were", "A, B and C were" -- every file
# reencrypt rewrote, in the number it has (k237).
sub reencrypted_clause {
    my ($self, @files) = @_;

    my $list = @files < 2 ? join('', @files)
             : join(', ', @files[ 0 .. $#files - 1 ]) . ' and ' . $files[-1];
    return $list . (@files == 1 ? ' was' : ' were') . ' re-encrypted';
}

# What a removed recipient could read until now (F3). Shared by
# `ocp keys recipients rm` and `ocp keys operator rm` (k216). Re-encrypting only
# locks it out of what is written from here on; every version it could
# decrypt -- git history included -- stays readable for it.
sub rotation_hint {
    my ($self, $secrets, $recipient, @done) = @_;

    my @names = eval { sort keys %{ $secrets->read_all_secrets } };
    my $hint = "\n[!!] $recipient is no longer a recipient"
        . (@done ? ' and ' . $self->reencrypted_clause(@done) : '') . ".\n"
        . "     That only locks it out of what is written from now on. Every version\n"
        . "     it could decrypt until now -- the old ones in git history included --\n"
        . "     stays readable for it. Rotate what those held:\n";
    $hint .= "       secrets.yaml:    " . join(', ', @names) . "\n"
          .  "                        (hetzner_token: revoke it in the Hetzner Cloud\n"
          .  "                        console, then store a new one)\n"
        if $secrets->has_secrets_file;
    $hint .= "       kubeconfig.yaml: the cluster admin credentials (client certificate\n"
          .  "                        and key) -- issue new ones on the control plane\n"
        if $secrets->has_kubeconfig;
    $hint .= "     keys.yaml held names and public keys for it; the private SSH keys in\n"
          .  "     it carry their own age layer for the project key alone.\n";
    return $hint;
}

1;

__END__

=head1 NAME

OCP::Role::Cmd::Recipients - What the C<ocp keys recipients> commands share

=head1 DESCRIPTION

C<project_secrets> (the project's L<OCP::Secrets>, PIN1 when C<unlock> asks
for the private key), C<recipient_arg> (an age recipient from the command line,
checked before anything is touched), C<reencrypt> (re-encrypt what is out
of step and say so on STDOUT) and C<rotation_hint> (what a removed recipient
could read until now, for STDERR) and C<reencrypted_clause> (the files
C<reencrypt> rewrote as a clause in the right number -- "keys.yaml was
re-encrypted", "A and B were re-encrypted" -- used by C<rotation_hint>, k237),
for L<OCP::Cmd::Keys::Recipients::Ls>,
L<OCP::Cmd::Keys::Recipients::Add>, L<OCP::Cmd::Keys::Recipients::Rm> and the
operator commands (L<OCP::Cmd::Keys::Operator::Add>,
L<OCP::Cmd::Keys::Operator::Rm>).

=cut

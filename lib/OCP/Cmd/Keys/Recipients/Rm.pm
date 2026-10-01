package OCP::Cmd::Keys::Recipients::Rm;
# ABSTRACT: Remove an age recipient, re-encrypt, and say what to rotate

use Moo;
use MooX::Cmd;
use MooX::Options;

use OCP::Choices;

with 'OCP::Role::Cmd', 'OCP::Role::Cmd::Recipients';

sub execute {
    my ($self, $args, $chain) = @_;

    my $recipient = $self->recipient_arg($args, 'rm');
    my $secrets   = $self->project_secrets(unlock => 1);
    my $project   = $secrets->age_recipient;

    die "$recipient is the project key: the key age.key.enc keeps behind PIN1.\n"
      . "It stays a recipient of every file; nothing was changed.\n"
        if $recipient eq $project;

    # Removable: what the list names, and what a file is still encrypted for.
    my @extras = $secrets->extra_recipients;
    my %seen   = ($project => 1);
    my @known  = grep { !$seen{$_}++ }
                 @extras, map { $_->{recipient} } @{ $secrets->age_key_bindings };
    die OCP::Choices::unknown('recipient', $recipient, [ @known ],
        empty => "The project key is the only recipient.\n")
        unless grep { $_ eq $recipient } @known;

    if (grep { $_ eq $recipient } @extras) {
        unless ($secrets->sops_config_editable) {
            my $config = $secrets->governing_sops_config;
            die "$recipient is listed in\n"
              . "  $config\n"
              . "which lies outside this project; ocp reads it but does not rewrite it.\n"
              . "Remove it from the creation rule there, then run\n"
              . "  ocp keys recipients rm $recipient\n"
              . "again to re-encrypt the files. Nothing was changed.\n";
        }
        $secrets->set_sops_recipients([ grep { $_ ne $recipient } @extras ]);
        print "[ok] Removed $recipient from " . $secrets->sops_config_file . "\n";
    }

    my @done = $self->reencrypt($secrets);
    print STDERR $self->rotation_hint($secrets, $recipient, @done);
    return 0;
}

# What a removed recipient could read until now (F3). Re-encrypting only
# locks it out of what is written from here on; every version it could
# decrypt -- git history included -- stays readable for it.
sub rotation_hint {
    my ($self, $secrets, $recipient, @done) = @_;

    my @names = eval { sort keys %{ $secrets->read_all_secrets } };
    my $hint = "\n[!!] $recipient is no longer a recipient"
        . (@done ? ' and ' . join(', ', @done) . ' were re-encrypted' : '') . ".\n"
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

OCP::Cmd::Keys::Recipients::Rm - Remove an age recipient, re-encrypt, and say what to rotate

=head1 SYNOPSIS

    ocp keys recipients rm age1...

=head1 DESCRIPTION

Takes the recipient out of the project's F<.sops.yaml> and re-encrypts
F<keys.yaml>, F<secrets.yaml> and F<kubeconfig.yaml> with a new data key, so
nothing written from now on opens for it. Needs the project key (PIN1). The
project key itself cannot be removed.

That is not the end of it, and the command says so on STDERR: whatever the
removed recipient could decrypt until now -- every committed version, git
history included -- stays readable for it. The hint names what to rotate:
the entries of F<secrets.yaml> (the Hetzner API token) and the cluster admin
credentials in F<kubeconfig.yaml>. The private SSH keys in F<keys.yaml> were
never readable for another recipient (their own age layer is the project
key's).

=cut

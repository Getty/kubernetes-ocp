package OCP::Cmd::Keys::Recipients::Add;
# ABSTRACT: Add an age recipient and re-encrypt the project's SOPS files

use Moo;
use MooX::Cmd;
use MooX::Options;

with 'OCP::Role::Cmd', 'OCP::Role::Cmd::Recipients';

sub execute {
    my ($self, $args, $chain) = @_;

    my $recipient = $self->recipient_arg($args, 'add');
    my $secrets   = $self->project_secrets(unlock => 1);
    my @extras    = $secrets->extra_recipients;

    if ($recipient eq $secrets->age_recipient) {
        print "[ok] $recipient is the project key -- already a recipient of every file\n";
    } elsif (grep { $_ eq $recipient } @extras) {
        print "[ok] $recipient is already a recipient ("
            . $secrets->governing_sops_config . ")\n";
    } elsif ($secrets->sops_config_editable) {
        $secrets->set_sops_recipients([ @extras, $recipient ]);
        print "[ok] Added $recipient to " . $secrets->sops_config_file . "\n";
    } else {
        my $config = $secrets->governing_sops_config;
        die "The project's SOPS files take their recipients from\n"
          . "  $config\n"
          . "which lies outside this project; ocp reads it but does not rewrite it.\n"
          . "Add $recipient to the creation rule there that matches keys.yaml,\n"
          . "secrets.yaml and kubeconfig.yaml, then run\n"
          . "  ocp keys recipients add $recipient\n"
          . "again to re-encrypt the files. Nothing was changed.\n";
    }

    $self->reencrypt($secrets);
    return 0;
}

1;

__END__

=head1 NAME

OCP::Cmd::Keys::Recipients::Add - Add an age recipient and re-encrypt the project's SOPS files

=head1 SYNOPSIS

    ocp keys recipients add age1...

=head1 DESCRIPTION

Puts the recipient into the project's F<.sops.yaml> (created when missing) and
re-encrypts F<keys.yaml>, F<secrets.yaml> and F<kubeconfig.yaml> for the
project key plus every listed recipient, with a new data key. Needs the
project key (PIN1). Takes the B<public> key only.

A recipient already listed is not added twice, but files not yet encrypted for
it are still re-encrypted -- which is also how a F<.sops.yaml> edited by hand,
or one further up that OCP does not rewrite, is brought into effect.

=cut

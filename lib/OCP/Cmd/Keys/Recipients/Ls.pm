package OCP::Cmd::Keys::Recipients::Ls;
# ABSTRACT: List who the project's SOPS files are encrypted for

use Moo;
use MooX::Cmd;
use MooX::Options;

with 'OCP::Role::Cmd', 'OCP::Role::Cmd::Recipients';

sub execute {
    my ($self, $args, $chain) = @_;

    my $secrets = $self->project_secrets;
    my $config  = $secrets->governing_sops_config;

    # Recipients on STDOUT and nothing else, one per line, so the list pipes;
    # what each one is goes to STDERR, the way `ocp keys show` does it.
    my $project = $secrets->age_recipient;
    print STDERR "project key (.ocp/age.key, age.key.enc behind PIN1):\n";
    print "$project\n";
    for my $r ($secrets->extra_recipients) {
        print STDERR "from $config:\n";
        print "$r\n";
    }

    # A file encrypted for another list than the one above.
    my %have;
    push @{ $have{ $_->{file} } }, $_->{recipient} for @{ $secrets->age_key_bindings };
    for my $file (sort keys %have) {
        my $want = join ',', sort @{ $secrets->recipients_for($secrets->project_dir->child($file)) };
        next if $want eq join ',', sort @{ $have{$file} };
        print STDERR "[!!] $file is encrypted for: " . join(', ', @{ $have{$file} }) . "\n"
                   . "     'ocp keys recipients add' or 'rm' re-encrypts it for the list above.\n";
    }

    return 0;
}

1;

__END__

=head1 NAME

OCP::Cmd::Keys::Recipients::Ls - List who the project's SOPS files are encrypted for

=head1 SYNOPSIS

    ocp keys recipients ls

=head1 DESCRIPTION

Prints the age recipients of the project's SOPS files on STDOUT, one per
line: the project key first, then those from the governing F<.sops.yaml>. What
each one is, and any file still encrypted for a different list, goes to
STDERR. Needs no PIN while F<.ocp/age.pub> is there.

=cut

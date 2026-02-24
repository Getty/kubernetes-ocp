package OCP::UI::Wizard;
# ABSTRACT: Multi-step wizard using sequential OCP::UI calls

use Moo;
use OCP::UI;

has title => (is => 'ro', default => 'OCP');
has steps => (is => 'ro', required => 1);  # ArrayRef of CodeRefs

sub run {
    my ($self) = @_;
    my %collected;

    for my $step_fn (@{$self->steps}) {
        my $step_def = $step_fn->(\%collected);
        next unless $step_def;  # Step skipped


        my $ui = OCP::UI->new(
            title  => $step_def->{title} // $self->title,
            fields => $step_def->{fields},
        );
        my $result = $ui->run;
        return undef unless $result;  # Cancel

        %collected = (%collected, %$result);
    }
    return \%collected;
}

1;

package OCP::UI::Form;
# ABSTRACT: Form builder for OCP TUI

use Moo;
use OCP::UI::Field;

has fields => (is => 'ro', required => 1);  # ArrayRef of hashrefs
has _field_objects => (is => 'lazy', builder => '_build_fields');

sub _build_fields {
    my ($self) = @_;
    return [ map { OCP::UI::Field->new(%$_) } @{$self->fields} ];
}

sub values {
    my ($self) = @_;
    my %result;
    for my $field (@{$self->_field_objects}) {
        next if $field->type eq 'static';
        $result{$field->name} = $field->value;
    }
    return \%result;
}

sub set_values {
    my ($self, $data) = @_;
    for my $field (@{$self->_field_objects}) {
        next unless exists $data->{$field->name};
        $field->set_value($data->{$field->name});
    }
}

1;

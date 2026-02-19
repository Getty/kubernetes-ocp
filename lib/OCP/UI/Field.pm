package OCP::UI::Field;
# ABSTRACT: Single form field for OCP TUI

use Moo;
use Tickit::Widget::Entry;
use Tickit::Widget::RadioButton;
use Tickit::Widget::CheckButton;
use Tickit::Widget::VBox;
use Tickit::Widget::HBox;
use Tickit::Widget::Static;

has name    => (is => 'ro', required => 1);
has type    => (is => 'ro', required => 1);  # text, choice, bool, static
has label   => (is => 'ro', required => 1);
has default => (is => 'ro');
has options => (is => 'ro');  # For choice: [{ label => "...", value => "..." }]

# Internal widget refs
has on_submit => (is => 'rw');  # CodeRef, set by UI before create_widget

# Internal widget refs
has _widget  => (is => 'rw');
has _group   => (is => 'rw');  # RadioButton::Group for choice fields
has _buttons => (is => 'rw');  # ArrayRef of RadioButtons for set_value

sub create_widget {
    my ($self) = @_;

    if ($self->type eq 'text') {
        my $field_self = $self;
        my $entry = Tickit::Widget::Entry->new(
            text     => $self->default // '',
            on_enter => sub { $field_self->on_submit->() if $field_self->on_submit },
        );
        $self->_widget($entry);
        return $entry;
    }
    elsif ($self->type eq 'choice') {
        my $group = Tickit::Widget::RadioButton::Group->new;
        $self->_group($group);
        my $box = Tickit::Widget::HBox->new;
        my @buttons;
        my $activated = 0;
        for my $opt (@{$self->options}) {
            my $rb = Tickit::Widget::RadioButton->new(
                label => $opt->{label},
                group => $group,
                value => $opt->{value},
            );
            if (defined $self->default && $opt->{value} eq $self->default) {
                $rb->activate;
                $activated = 1;
            }
            push @buttons, $rb;
            $box->add($rb, expand => 1);
        }
        $buttons[0]->activate if @buttons && !$activated;
        $self->_buttons(\@buttons);
        $self->_widget($box);
        return $box;
    }
    elsif ($self->type eq 'bool') {
        my $cb = Tickit::Widget::CheckButton->new(label => '');
        $cb->activate if $self->default;
        $self->_widget($cb);
        return $cb;
    }
    elsif ($self->type eq 'static') {
        my $st = Tickit::Widget::Static->new(text => $self->label);
        $self->_widget($st);
        return $st;
    }
}

sub focus_widget {
    my ($self) = @_;
    if ($self->type eq 'choice') {
        my $active = $self->_group->active;
        return $active if $active;
        return $self->_buttons->[0] if $self->_buttons && @{$self->_buttons};
    }
    return $self->_widget;
}

sub value {
    my ($self) = @_;
    return undef unless $self->_widget;

    if ($self->type eq 'text') {
        return $self->_widget->text;
    }
    elsif ($self->type eq 'choice') {
        my $active = $self->_group->active;
        return $active ? $active->value : undef;
    }
    elsif ($self->type eq 'bool') {
        return $self->_widget->is_active ? 1 : 0;
    }
    return undef;
}

sub summary {
    my ($self) = @_;
    my $val = $self->value;
    return '' unless defined $val;

    if ($self->type eq 'text') {
        return length($val) > 20 ? substr($val, 0, 17) . '...' : $val;
    }
    elsif ($self->type eq 'choice') {
        for my $opt (@{$self->options || []}) {
            return $opt->{label} if $opt->{value} eq $val;
        }
        return $val;
    }
    elsif ($self->type eq 'bool') {
        return $val ? 'yes' : 'no';
    }
    return '';
}

sub set_value {
    my ($self, $val) = @_;
    return unless $self->_widget;

    if ($self->type eq 'text') {
        $self->_widget->set_text($val // '');
    }
    elsif ($self->type eq 'choice') {
        my $buttons = $self->_buttons // [];
        for my $rb (@$buttons) {
            if ($rb->value eq $val) {
                $rb->activate;
                last;
            }
        }
    }
    elsif ($self->type eq 'bool') {
        $val ? $self->_widget->activate : $self->_widget->deactivate;
    }
}

1;

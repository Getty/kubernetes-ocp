package OCP::UI;
# ABSTRACT: Terminal UI for OCP forms

use Moo;
use Tickit;
use Tickit::Widget::VBox;
use Tickit::Widget::HBox;
use Tickit::Widget::Static;
use Tickit::Widget::Frame;
use OCP::UI::Field;

has title   => (is => 'ro', default => 'OCP');
has fields  => (is => 'ro', required => 1);  # ArrayRef of field definitions
has context => (is => 'ro', default => sub { [] });  # [{label=>"...", value=>"..."}]

has _tickit        => (is => 'rw');
has _result        => (is => 'rw');
has _current       => (is => 'rw', default => 0);
has _field_objects  => (is => 'rw', default => sub { [] });
has _menu_labels   => (is => 'rw', default => sub { [] });
has _max_label_len => (is => 'rw', default => 0);

sub run {
    my ($self) = @_;

    # Create field objects (skip static)
    my @fields = grep { $_->type ne 'static' }
                 map  { OCP::UI::Field->new(%$_) }
                 @{$self->fields};
    return {} unless @fields;
    $self->_field_objects(\@fields);

    # Compute max label length for sidebar alignment
    my $max = 0;
    for (@fields) { my $l = length($_->label); $max = $l if $l > $max }
    $self->_max_label_len($max);

    # Set on_submit callbacks (Entry needs this before create_widget)
    $_->on_submit(sub { $self->_advance(1) }) for @fields;

    # Create all widgets upfront
    $_->create_widget for @fields;

    # === Build widget tree ===

    my $outer = Tickit::Widget::Frame->new(
        title => " " . $self->title . " ",
        style => { linetype => "single" },
    );

    my $main = Tickit::Widget::VBox->new;
    $main->add(Tickit::Widget::Static->new(text => ""));

    # Context: show previous selections as read-only summary
    if (@{$self->context}) {
        for my $ctx (@{$self->context}) {
            $main->add(Tickit::Widget::Static->new(
                text => sprintf("   %s: %s", $ctx->{label}, $ctx->{value}),
            ));
        }
        $main->add(Tickit::Widget::Static->new(text => ""));
    }

    # Two columns: sidebar + all fields
    my $columns = Tickit::Widget::HBox->new;

    # Left sidebar
    my $sidebar = Tickit::Widget::VBox->new;
    my @labels;
    for my $i (0 .. $#fields) {
        my $label = Tickit::Widget::Static->new(text => '');
        push @labels, $label;
        $sidebar->add($label);
    }
    $self->_menu_labels(\@labels);
    $columns->add($sidebar, expand => 1);

    # Right: all fields visible, each in a Frame
    my $content = Tickit::Widget::VBox->new;
    for my $field (@fields) {
        my $frame = Tickit::Widget::Frame->new(
            title => $field->label,
            style => { linetype => "single" },
        )->set_child($field->_widget);
        $content->add($frame);
    }
    $columns->add($content, expand => 3);

    $main->add($columns, expand => 1);

    # Help line
    $main->add(Tickit::Widget::Static->new(text => ""));
    $main->add(Tickit::Widget::Static->new(
        text => " \x{2190}\x{2192}:Select  Enter/Tab:Next  Esc:Cancel",
    ));

    $outer->set_child($main);
    $self->_update_labels;

    my $tickit = Tickit->new(root => $outer);
    $self->_tickit($tickit);

    # === Key handling at TERM level ===
    # Widgets (RadioButton, Entry) consume keys before $tickit->bind_key
    # sees them. Intercepting at the terminal level fires FIRST.

    $tickit->term->bind_event(key => sub {
        my ($term, $ev, $info) = @_;

        # Let text input (typing) pass to widgets
        return 0 if $info->type == Tickit::KEYEV_TEXT;

        my $key = $info->str;

        # Navigation
        if ($key eq 'Up')     { $self->_navigate(-1); return 1 }
        if ($key eq 'Down')   { $self->_advance(1);   return 1 }
        if ($key eq 'Tab')    { $self->_advance(1);   return 1 }
        if ($key eq 'Enter')  { $self->_advance(1);   return 1 }
        if ($key eq 'Escape') { $self->_cancel;        return 1 }
        if ($key eq 'F10')    { $self->_submit;        return 1 }

        # Choice cycling: Left/Right only for choice fields
        my $field = $self->_field_objects->[$self->_current];
        if ($field && $field->type eq 'choice') {
            if ($key eq 'Left')  { $self->_cycle_radio($field, -1); return 1 }
            if ($key eq 'Right') { $self->_cycle_radio($field, 1);  return 1 }
        }

        return 0;  # Let everything else (Backspace, Home, etc.) reach widgets
    });

    # Initial focus
    $fields[0]->focus_widget->take_focus;

    $tickit->run;

    # Cleanup: ensure Tickit releases the terminal before returning
    my $result = $self->_result;
    $self->_tickit(undef);
    return $result;
}

# Navigate forward: submit if on last field, otherwise move to next
sub _advance {
    my ($self, $direction) = @_;
    my $fields = $self->_field_objects;
    my $count = scalar @$fields;

    if ($self->_current >= $count - 1) {
        # On last field: submit
        $self->_submit;
    } else {
        $self->_navigate($direction);
    }
}

sub _navigate {
    my ($self, $direction) = @_;
    my $fields = $self->_field_objects;
    my $count = scalar @$fields;

    my $next = $self->_current + $direction;
    return if $next < 0 || $next >= $count;  # Don't wrap
    $self->_current($next);
    $self->_update_labels;

    $fields->[$next]->focus_widget->take_focus;
}

sub _cycle_radio {
    my ($self, $field, $direction) = @_;
    my $buttons = $field->_buttons;
    my $count = scalar @$buttons;

    # Find currently active button
    my $active = $field->_group->active;
    my $idx = 0;
    for my $i (0 .. $#$buttons) {
        if ($buttons->[$i] == $active) {
            $idx = $i;
            last;
        }
    }

    my $next = ($idx + $direction) % $count;
    $buttons->[$next]->activate;
    $buttons->[$next]->take_focus;
}

sub _update_labels {
    my ($self) = @_;
    my $fields = $self->_field_objects;
    my $labels = $self->_menu_labels;
    my $current = $self->_current;
    my $pad = $self->_max_label_len;

    for my $i (0 .. $#$fields) {
        my $marker = $i == $current ? " \x{25B8} " : '   ';
        my $name = sprintf("%-${pad}s", $fields->[$i]->label);
        $labels->[$i]->set_text($marker . $name);
    }
}

sub _submit {
    my ($self) = @_;
    my %result;
    for my $field (@{$self->_field_objects}) {
        $result{$field->name} = $field->value;
    }
    $self->_result(\%result);
    $self->_tickit->stop;
}

sub _cancel {
    my ($self) = @_;
    $self->_result(undef);
    $self->_tickit->stop;
}

1;

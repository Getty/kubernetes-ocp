package OCP::Cmd::Keys::AddPin2;
# ABSTRACT: Put the missing PIN2 layer on an admin key stored without one

use Moo;
use MooX::Cmd;
use MooX::Options;

use OCP::ClusterKey;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

with 'OCP::Role::Cmd';

# k450: before k390 a PIN2 of "0" was read as none, so `ocp init` and `ocp
# keys secure` stored the admin key under PIN1 alone while saying "age+PIN2".
# Nothing else re-creates an existing admin key: this re-adds it, the same
# key, under both layers. The key does not change, so no machine has to learn
# a new one.
#
# Only keys without the layer: one that has it opens for its own PIN2 alone,
# and changing a PIN2 is another command's question.
sub execute {
    my ($self, $args, $chain) = @_;

    my $config      = OCP::Config->new(file => $self->ocp->config);
    my $project_dir = $config->project_dir;

    my $secrets = OCP::Secrets->new(project_dir => $project_dir);
    my $keys    = OCP::Keys->new(project_dir => $project_dir);

    die "No keys.yaml found in " . $project_dir->stringify . ".\n"
      . "An admin key exists only in secure mode; a --nopassword project has\n"
      . "none ('ocp keys secure' moves it to secure mode).\n"
        unless $keys->has_keys_file;

    # PIN1, if age.key is not already unlocked. Prompts on STDERR.
    $secrets->ensure_age_key();

    my @admin = grep {
        ($_->{purpose} // '') eq 'admin'
            && defined $_->{private} && length $_->{private}
    } @{ $keys->list_keys };
    die "keys.yaml holds no admin key.\n" unless @admin;

    my @bare = grep { !$keys->has_pin2_layer($_->{name}) } @admin;
    unless (@bare) {
        print "[ok] Every admin key has its PIN2 layer: "
            . join(', ', map { $_->{name} } @admin) . ". Nothing to do.\n";
        return 0;
    }

    die "ERROR: Setting a PIN2 asks for it twice, and there is no terminal to\n"
      . "       ask on. Run 'ocp keys add-pin2' from an interactive shell, or\n"
      . "       feed it with --pins-stdin.\n"
        unless OCP::ClusterKey->can_prompt;

    print "The admin key" . (@bare > 1 ? 's ' : ' ')
        . join(', ', map { $_->{name} } @bare)
        . (@bare > 1 ? ' are' : ' is')
        . " stored under PIN1 alone, without the PIN2 layer.\n"
        . "Set the PIN2 that protects " . (@bare > 1 ? 'them' : 'it') . " from now on.\n";

    my $pin2 = OCP::Password::prompt_new_pin('PIN2', 'admin SSH access');

    for my $key (@bare) {
        $keys->add_pin2_layer($key->{name}, $pin2);
        print "[ok] $key->{name}: re-encrypted under age + PIN2\n";
    }

    print "\nThe key itself is unchanged; the machines that trust it need nothing.\n"
        . "Commit keys.yaml.\n";
    return 0;
}

1;

__END__

=head1 SYNOPSIS

    ocp keys add-pin2
    ocp keys add-pin2 --pins-stdin < <(printf '%s\n%s\n%s\n' "$PIN1" "$PIN2" "$PIN2")

=head1 DESCRIPTION

Before the fix for a PIN of C<"0">, C<ocp init> and C<ocp keys secure> stored
the admin key without its PIN2 layer when PIN2 was C<"0">: under PIN1 alone,
like the robo key, and no PIN2 opened it again.

C<add-pin2> finds every admin key in F<keys.yaml> stored that way, asks for a
new PIN2 (twice), and re-encrypts each under the age layer B<and> the PIN2
layer, as C<ocp init> stores one. The key is the same key, so no machine's
F<authorized_keys> changes. Commit F<keys.yaml> afterwards.

Needs the project key (PIN1). An admin key that has its PIN2 layer already is
left alone; when all of them have it, the command says so and changes nothing.
It does not change an existing PIN2.

Prompts go to STDERR; what was done to STDOUT.

=cut

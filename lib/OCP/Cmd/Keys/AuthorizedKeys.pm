package OCP::Cmd::Keys::AuthorizedKeys;
# ABSTRACT: Print the authorized_keys lines a cluster machine needs

use Moo;
use MooX::Cmd;
use MooX::Options;

use Path::Tiny qw( path );

use OCP::Choices;
use OCP::Config;
use OCP::Keys;
use OCP::Secrets;

with 'OCP::Role::Cmd';

option purpose => (
    is     => 'ro',
    format => 's',
    doc    => 'Which keys to print: all (default), admin, automation, operator',
);

# Which key does what, in secure mode (k209). Two keys reach machines, and an
# ssh-provider worker needs both of them:
#
#   admin       the CLI -- `ocp apply`, `ocp ssh`, `ocp node add` when it
#               joins a worker itself, `ocp node rm` when it tears one down.
#               OCP::ClusterKey picks it, on every provider.
#   automation  robocop -- the robo key it joins and tears down workers with.
#
# A control plane needs the admin key; a worker the ssh provider reaches needs
# both, because which of the two shows up depends on who drives the node at
# that moment, not on the node. `ocp keys show` answers "print this one key";
# this answers "what goes into authorized_keys", which is why `all` is the
# default and the purposes are a fixed pair rather than whatever keys.yaml
# happens to hold.
#
# The order is the listing's: admin first, the key every machine needs.
#
# k216 adds the operators (a Leitstand, `ocp keys operator add`): each brings
# its own SSH key, and the CLI on its machine reaches every machine with it.
# `all` carries them, so a host set up from this output admits the operators
# too -- but they are optional: a project with none is complete without them.
my @PURPOSES = qw( admin automation operator );
my %REQUIRED = map { $_ => 1 } qw( admin automation );

my %NAME = (
    admin      => 'admin',
    automation => 'robo',
    operator   => 'operator',
);

my %ROLE = (
    admin      => 'the CLI: ocp apply, ocp ssh, ocp node add/rm',
    automation => 'robocop: worker joins and teardowns',
    operator   => 'an operator: ocp apply unattended, with its own key',
);

sub execute {
    my ( $self, $args, $chain ) = @_;

    # Before anything is unlocked: a typo must not cost a PIN1 prompt.
    my $purpose = $self->purpose // 'all';
    die OCP::Choices::unknown('key purpose', $purpose, [ sort 'all', @PURPOSES ])
        unless $purpose eq 'all' || grep { $_ eq $purpose } @PURPOSES;

    my @wanted = $purpose eq 'all' ? @PURPOSES : ($purpose);

    my $config = OCP::Config->new(file => $self->ocp->config);
    my $keys   = OCP::Keys->new(project_dir => $config->project_dir);

    return $self->_dev_mode_key($config, $purpose) unless $keys->has_keys_file;

    # PIN1, if age.key is not already unlocked; never PIN2. Public halves sit
    # behind the age layer alone (OCP::Keys, ENCRYPTION LAYERS), and this is
    # the command an operator runs before the first `ocp apply` -- or with the
    # admin key refused, which is no moment to ask for the admin key's PIN.
    OCP::Secrets->new(project_dir => $config->project_dir)->ensure_age_key();

    my $all = $keys->list_keys;

    # Every wanted key found before a single line is printed. Piped into
    # `ssh root@HOST 'cat >> ~/.ssh/authorized_keys'`, half the set followed
    # by an error still appends that half -- and the machine looks done.
    my ( @lines, @missing );
    for my $p (@wanted) {
        my @found = grep {
            ($_->{purpose} // '') eq $p && !$_->{deprecated}
            && defined $_->{public} && length $_->{public}
        } @$all;
        push @missing, $p unless @found || ($purpose eq 'all' && !$REQUIRED{$p});
        push @lines, map { [ $p, $_ ] } @found;
    }

    die join('', map { 'No '.$NAME{$_}.' key (purpose '.$_.') in '
                         .$keys->keys_file.' that is not deprecated.'."\n" } @missing)
      . "Nothing was printed: half the set in authorized_keys would look like all of it.\n"
        if @missing;

    # Public keys go to STDOUT and nothing else does -- the rule `ocp keys
    # show` set (k84), so this pipes straight into authorized_keys.
    for my $line (@lines) {
        my ( $p, $key ) = @$line;
        my $public = $key->{public};
        chomp $public;

        print STDERR $key->{name}.' ('.$p.', '.$ROLE{$p}.')'."\n";
        print $public."\n";
    }

    return 0;
}

# --nopassword dev mode has no keys.yaml and therefore no admin and no robo
# key: .ocp/id_ed25519 is the only key material there is, and OCP::ClusterKey
# uses it on every provider (ADR 0027). Whichever purpose was asked for, that
# is the answer -- once, since a second copy of the same line is not a second
# key.
sub _dev_mode_key {
    my ( $self, $config, $purpose ) = @_;

    die "No keys.yaml: dev mode (--nopassword) has no operators. Operators exist in\n"
      . "secure mode only ('ocp keys secure', then 'ocp keys operator add').\n"
        if $purpose eq 'operator';

    my $path = $config->ssh_public_key_path;
    die "No keys.yaml and no $path in " . $config->project_dir->stringify . ".\n"
      . "Dev mode (--nopassword) keeps its single key there; run 'ocp init'.\n"
        unless -f $path;

    my $public = path($path)->slurp;
    chomp $public;
    die "$path is empty.\n" unless length $public;

    print STDERR 'Dev mode (no keys.yaml): '.$path.' is the only key this project '
      . 'has, so it stands in for '
      . ($purpose eq 'all' ? 'admin and automation' : $purpose).".\n";
    print $public."\n";

    return 0;
}

1;

__END__

=head1 NAME

OCP::Cmd::Keys::AuthorizedKeys - Print the authorized_keys lines a cluster machine needs

=head1 SYNOPSIS

    # Everything an ssh-provider worker needs: admin + robo
    ocp keys authorized-keys

    # What a control plane needs: the admin key
    ocp keys authorized-keys --purpose admin

    # The robo key alone -- what robocop joins workers with
    ocp keys authorized-keys --purpose automation

    # The operators' keys alone (a Leitstand, ocp keys operator add)
    ocp keys authorized-keys --purpose operator

    # Composes, because only authorized_keys lines go to STDOUT
    ocp keys authorized-keys | ssh root@worker 'cat >> ~/.ssh/authorized_keys'

=head1 DESCRIPTION

Prints the public keys a machine of this cluster must trust, one
F<authorized_keys> line each, and nothing else on STDOUT. Key names and what
each key is for go to STDERR.

In secure mode two keys reach machines (ADR 0006):

=over 4

=item * B<admin> (C<purpose: admin>) -- every CLI command that opens a
connection: C<ocp apply>, C<ocp ssh>, C<ocp node add> when it joins a worker
itself, C<ocp node rm> when it tears one down. A control plane needs it.

=item * B<robo> (C<purpose: automation>) -- robocop, which joins and tears
down workers with it.

=item * B<operator> (C<purpose: operator>, k216) -- the SSH key of an
operator (a Leitstand) registered with C<ocp keys operator add>, which runs
C<ocp apply> unattended and reaches every machine with it. One line per
operator; a project may have none.

=back

So a worker reached through the C<ssh> provider needs B<both>: which one
arrives depends on whether robocop or the CLI is driving the node at that
moment. On Hetzner both are uploaded through the API; on the C<ssh> provider
nothing writes F<authorized_keys>, and this is the command whose output goes
there.

All requested keys are looked up before anything is printed. A purpose with
no (non-deprecated) key in F<keys.yaml> fails with a message naming it, prints
nothing, and exits non-zero -- half the set appended to F<authorized_keys>
would look like all of it.

=head2 Dev mode

A C<--nopassword> project has no F<keys.yaml> and a single key,
F<.ocp/id_ed25519>. Its public half is printed for every purpose (once for
C<all>), with a note on STDERR that dev mode knows only this one key.

=head2 What it asks for

PIN1 only, and only when F<.ocp/age.key> is not already unlocked -- never
PIN2. The public halves in F<keys.yaml> sit behind the age layer alone (see
L<OCP::Keys>). No cluster has to exist.

=head1 OPTIONS

=head2 --purpose <all|admin|automation|operator>

Which keys to print. C<all> (the default) prints the admin key, then the robo
key, then every operator key -- so a machine set up from it admits the
operators too. A project without operators is complete without them; asked
for alone (C<--purpose operator>), none is an error like a missing admin key.
In dev mode C<operator> is refused: there are no operators there. Anything
else is refused with the purposes that exist.

=head1 SEE ALSO

L<OCP::Cmd::Keys>, L<OCP::Cmd::Keys::Show>, L<OCP::Keys>, L<OCP::ClusterKey>

=cut

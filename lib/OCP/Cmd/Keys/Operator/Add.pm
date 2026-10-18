package OCP::Cmd::Keys::Operator::Add;
# ABSTRACT: Register an operator: its SSH key onto every machine, its age key as a recipient

use Moo;
use MooX::Cmd;
use MooX::Options;

use Crypt::Age::Keys;
use Path::Tiny qw( path );

with 'OCP::Role::Cmd';
with 'OCP::Role::Cmd::Recipients';
with 'OCP::Role::Cmd::Machines';
with 'OCP::Role::Cmd::Operator';

option name => (
    is     => 'ro',
    format => 's',
    doc    => "The operator's name in keys.yaml: [a-z0-9][a-z0-9-]*",
);

option ssh_pubkey => (
    is     => 'ro',
    format => 's',
    doc    => "File with the operator's SSH public key (one authorized_keys line)",
);

option age => (
    is     => 'ro',
    format => 's',
    doc    => "The operator's age recipient (age1..., its PUBLIC key)",
);

my $USAGE = 'ocp keys operator add --name NAME --ssh-pubkey FILE --age AGE1...';

#
# k216: a Leitstand runs `ocp apply` unattended with an age identity and an
# SSH key of its own. This is the one step a human with the project key takes
# for it, and the order is the one `ocp keys secure` (k96) uses: the machines
# first, the record after --
#
#   1. everything checked that can be checked before a PIN: the name, the
#      public key file, the age recipient; then against keys.yaml (PIN1)
#   2. the SSH public key appended to root's authorized_keys on every machine,
#      logged in with the admin key (PIN2) -- a blob already there is not
#      added twice
#   3. only when every machine took it: the keys.yaml entry (purpose operator,
#      public half and age recipient, no private half) and the age recipient
#      in .sops.yaml, the files re-encrypted for it
#
# A machine that fails is named, nothing is recorded, exit 1; running the
# same command again is safe. An operator that is recorded already, with the
# same keys, goes through all of it again -- that is how a machine added
# later gets the key.

sub execute {
    my ( $self, $args, $chain ) = @_;

    die "usage: $USAGE\n" if $self->positional_args($args);

    # Before any PIN: a typo must not cost one.
    my $name   = $self->operator_name_arg($self->name, $USAGE);
    my $public = $self->_ssh_public_key;
    my $age    = $self->_age_recipient;
    my $blob   = $self->_key_blob($public);

    my ( $config, $secrets, $keys ) = $self->operator_project('add');

    die "ERROR: $age is the project key itself, not an operator's.\n"
        if $age eq $secrets->age_recipient;

    my $existing = $self->_check_against_keys($keys, $name, $public, $blob, $age);

    # Where the recipient goes, decided before any machine is touched: a
    # .sops.yaml outside the project is not OCP's to rewrite.
    my @extras = $secrets->extra_recipients;
    my $listed = grep { $_ eq $age } @extras;
    unless ($listed || $secrets->sops_config_editable) {
        my $file = $secrets->governing_sops_config;
        die "The project's SOPS files take their recipients from\n"
          . "  $file\n"
          . "which lies outside this project; ocp reads it but does not rewrite it.\n"
          . "Add $age to the creation rule there that matches keys.yaml,\n"
          . "secrets.yaml and kubeconfig.yaml, then run\n"
          . "  $USAGE\n"
          . "again. Nothing was changed.\n";
    }

    my $api = $self->_cluster_api($config, $secrets);
    my ( $machines, $pending ) = $self->_machines($config, $api);

    my @failed = $self->_distribute($config, $machines, $name, $public);
    if (@failed) {
        print STDERR "[!!] $_->{label}: could not add the operator key: $_->{why}\n" for @failed;
        print STDERR "\n"
          . "Not registered: keys.yaml and the recipients are unchanged, and the\n"
          . "operator cannot reach " . join(', ', map { $_->{label} } @failed) . ".\n"
          . "The machines that took the key keep it. Fix the ones above and run the\n"
          . "same command again: it adds nothing twice.\n";
        return 1;
    }

    # The record. .sops.yaml first, so keys.yaml is written for the new list.
    print "\n";
    if ($listed) {
        print "[ok] $age is already a recipient (" . $secrets->governing_sops_config . ")\n";
    } else {
        $secrets->set_sops_recipients([ @extras, $age ]);
        print "[ok] Added $age to " . $secrets->sops_config_file . "\n";
    }

    if ($existing) {
        print "[ok] keys.yaml already has the operator '$name' with these keys\n";
    } else {
        $keys->add_public_key(
            name    => $name,
            # ssh-ed25519 -> ssh_ed25519, as add_cluster_keys spells it
            type    => 'ssh_' . ((split ' ', $public)[0] =~ s/\Assh-//r =~ tr/-/_/r),
            purpose => 'operator',
            public  => $public,
            age     => $age,
        );
        print "[ok] keys.yaml: operator '$name' (purpose operator, no private key)\n";
    }

    $self->reencrypt($secrets);

    $self->_print_pending_operator($pending);
    $self->_print_hetzner_gap($config, $api);

    print "\n";
    print "Commit keys.yaml, .sops.yaml and the re-encrypted files. On the operator's\n";
    print "machine, 'ocp apply' then runs without a PIN:\n";
    print "  SOPS_AGE_KEY_FILE=<its age identity> OCP_OPERATOR_KEY=<its SSH private key> ocp apply\n";

    return 0;
}

# The authorized_keys line from --ssh-pubkey: one public key, nothing else.
sub _ssh_public_key {
    my ($self) = @_;

    my $file = $self->ssh_pubkey;
    die "usage: $USAGE\n" unless defined $file && length $file;
    die "--ssh-pubkey: no such file: $file\n" unless -f $file;

    my $content = path($file)->slurp;
    die "--ssh-pubkey: $file holds a PRIVATE key. Pass the public half (the .pub file);\n"
      . "the private half stays on the operator's machine. Nothing was changed.\n"
        if $content =~ /PRIVATE KEY/;

    my @lines = grep { /\S/ && !/\A\s*#/ } split /\n/, $content;
    die "--ssh-pubkey: $file holds " . (@lines ? scalar(@lines) . ' lines' : 'nothing')
      . "; it takes one SSH public key (an authorized_keys line).\n"
        unless @lines == 1;

    my $line = $lines[0] =~ s/\A\s+|\s+\z//gr;
    die "--ssh-pubkey: $file is not an SSH public key (type and base64, e.g. ssh-ed25519 AAAA...).\n"
        unless $line =~ m{\A(?:ssh-|ecdsa-|sk-)\S+\s+[A-Za-z0-9+/]+=*(?:\s|\z)};
    return $line;
}

sub _age_recipient {
    my ($self) = @_;

    my $age = $self->age;
    die "usage: $USAGE\n" unless defined $age && length $age;
    die "--age: not an age recipient: '$age'.\n"
      . "An age recipient is the PUBLIC key, age1... -- the machine that holds\n"
      . "the private half prints it with 'age-keygen -y'. Nothing was changed.\n"
        unless $age =~ /\Aage1/
            && eval { Crypt::Age::Keys->decode_public_key($age); 1 };
    return $age;
}

# The operator against what keys.yaml holds already. True when it is there
# with exactly these keys (a re-run), dies on any clash: the name taken by
# another key or by this operator with other keys, the SSH key or the age
# recipient already another operator's (or the SSH key another key's).
sub _check_against_keys {
    my ( $self, $keys, $name, $public, $blob, $age ) = @_;

    my $all = $keys->list_keys;
    my $existing;

    for my $key (@$all) {
        my $its_blob = eval { $self->_key_blob($key->{public} // '') } // '';
        my $purpose  = $key->{purpose} // '';

        if ($key->{name} eq $name) {
            die "ERROR: '$name' is already a key in keys.yaml, of purpose $purpose.\n"
              . "       Choose another name for the operator.\n"
                unless $purpose eq 'operator';
            die "ERROR: The operator '$name' is already registered, with other keys:\n"
              . "         ssh: " . ($key->{public} // '?') . "\n"
              . "         age: " . ($key->{age} // '?') . "\n"
              . "       Remove it first ('ocp keys operator rm $name'), or choose another name.\n"
                unless $its_blob eq $blob && ($key->{age} // '') eq $age;
            $existing = 1;
            next;
        }

        die "ERROR: That SSH key is already in keys.yaml as '$key->{name}' (purpose $purpose).\n"
          . "       An operator brings a key of its own.\n"
            if $its_blob eq $blob;
        die "ERROR: $age is already the age recipient of the operator '$key->{name}'.\n"
            if $purpose eq 'operator' && ($key->{age} // '') eq $age;
    }

    return $existing;
}

# Step 2. Returns the machines that did not take the key, each with a reason.
sub _distribute {
    my ( $self, $config, $machines, $name, $public ) = @_;

    unless (@$machines) {
        print "[ok] No machine has been deployed yet: there is nothing to put the key on\n";
        return ();
    }

    my $key = $self->cluster_ssh_key($config, reason => 'ocp keys operator add');
    die "ERROR: 'ocp keys operator add' puts the key on the machines with the admin key,\n"
      . "       and this run holds " . $key->label . ".\n"
        unless $key->origin eq 'admin';

    print "\n";
    my @failed;
    for my $m (@$machines) {
        my $label = $self->_machine_label($m);
        my $did = eval {
            $self->_append_keys($m, [ $key->path, $key->label ], [ $public, "operator '$name'" ]);
        };
        if ($did) {
            print "[ok] $label: $did\n";
            next;
        }
        push @failed, { label => $label, why => $self->_oneline($@) };
    }
    return @failed;
}

sub _print_pending_operator {
    my ( $self, $pending ) = @_;
    return unless @$pending;

    print "\n";
    print "In ocp.yaml, not joined yet (no OCPNode): "
        . join(', ', map { "$_->{name} ($_->{host})" } @$pending) . "\n";
    print "Their authorized_keys need the operator key too; 'ocp keys authorized-keys'\n";
    print "prints it with the admin and robo keys:\n";
    print "  ocp keys authorized-keys | ssh root\@HOST 'cat >> ~/.ssh/authorized_keys'\n";
    return;
}

# Not built (k216): Hetzner servers are created with the admin and the robo
# key the Hetzner project holds -- the operator key is not uploaded there.
sub _print_hetzner_gap {
    my ( $self, $config, $api ) = @_;

    return unless $self->_uses_hetzner($config, $api);
    print "\n";
    print "[--] Hetzner: servers created from now on get the admin and robo keys only,\n";
    print "     not this one. Run 'ocp keys operator add' with the same arguments again\n";
    print "     after a new server joined: it puts the key on the machines that lack it.\n";
    return;
}

1;

__END__

=head1 NAME

OCP::Cmd::Keys::Operator::Add - Register an operator: its SSH key onto every machine, its age key as a recipient

=head1 SYNOPSIS

    ocp keys operator add --name leitstand --ssh-pubkey leitstand.pub --age age1...

=head1 DESCRIPTION

Registers an operator (a Leitstand) that runs C<ocp apply> unattended with its
own age identity and its own SSH key (k216). Runs where the project key is:
PIN1, and PIN2 for the admin key when there are machines.

=over 4

=item 1.

C<--name>, C<--ssh-pubkey> and C<--age> are checked before anything is
unlocked; then against F<keys.yaml>: the name must be free (or this operator's
with exactly these keys -- a re-run), and the SSH key and the age recipient
must not belong to another key or operator. The project key is no operator's
recipient.

=item 2.

The SSH public key is appended to F</root/.ssh/authorized_keys> on every
machine of the cluster (the control planes, and every machine an OCPNode
names), logged in with the admin key. A key already there is not added again.

=item 3.

Only when every machine took it: F<keys.yaml> gets the entry -- C<name>,
C<type>, C<purpose: operator>, C<public>, C<age>, C<created>, C<deprecated>,
and B<no> C<private> --, the age recipient goes into the project's
F<.sops.yaml>, and F<keys.yaml>, F<secrets.yaml> and F<kubeconfig.yaml> are
re-encrypted for it with a new data key.

=back

A machine that refuses is named on STDERR, nothing is recorded, and the exit
code is 1; the same command again carries on. A F<.sops.yaml> outside the
project that governs the files is not rewritten: the command stops before any
machine and says to add the recipient there first.

Hosts listed in F<ocp.yaml> without an OCPNode are named:
C<ocp keys authorized-keys> prints the operator keys for them too. Hetzner
servers created later are not given the operator key (not built); running the
command again puts it onto machines that lack it.

=head1 OPTIONS

=head2 --name NAME

The operator's name in F<keys.yaml> and for C<ocp keys operator rm>:
lower-case letters, digits and dashes, a letter or digit first, at most 63
characters.

=head2 --ssh-pubkey FILE

A file holding the operator's SSH public key, one F<authorized_keys> line. A
private key is refused.

=head2 --age AGE1...

The operator's age recipient -- the public key of the identity its
C<SOPS_AGE_KEY_FILE> names (C<age-keygen -y>).

=head1 SEE ALSO

L<OCP::Cmd::Keys::Operator>, L<OCP::Cmd::Keys::Operator::Rm>,
L<OCP::ClusterKey>, F<docs/security.md>

=cut

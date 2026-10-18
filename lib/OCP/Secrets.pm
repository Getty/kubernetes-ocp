package OCP::Secrets;
# ABSTRACT: Secret management for OCP using Crypt::Age and File::SOPS

use Moo;
use OCP;
use OCP::Password;
use Path::Tiny qw(path);
use Carp qw(croak);
use Fcntl qw(O_WRONLY O_CREAT O_EXCL);
use Crypt::Age;
use Crypt::Age::Keys;
use File::SOPS;
use YAML::XS ();

has ocp => (
    is      => 'lazy',
    default => sub { OCP->instance },
);

has project_dir => (
    is       => 'ro',
    required => 1,
);

has secrets_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('secrets.yaml') },
);

has age_key_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('.ocp', 'age.key') },
);

has age_recipient_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('.ocp', 'age.pub') },
);

has kubeconfig_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('kubeconfig.yaml') },
);

has age_key_enc_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('age.key.enc') },
);

#
# Secure file write
#

# Write private key material / a decrypted kubeconfig to $path, created 0600
# before a single byte lands. Path::Tiny's spew is not usable here: it stages
# the content through a sibling temp file opened at the umask default (~0644,
# and .ocp/ is mkpath'd ~0755) and only then renames it into place — so a
# `spew` followed by `chmod 0600` leaves a real, if brief, world-readable
# window on the inode that ends up as the key. Create-then-write is what
# OCP::TempKeyPair and OCP::ClusterKey already do (via File::Temp, which opens
# 0600 with O_EXCL); this is the same pattern for a named file.
sub _spew_secure {
    my ($self, $path, $content) = @_;

    $path = path($path);
    $path->remove;    # clear the way for an O_EXCL create (no-op if absent)

    sysopen my $fh, $path->stringify, O_WRONLY | O_CREAT | O_EXCL, 0600
        or croak "Cannot create ".$path." securely: ".$!;
    print {$fh} $content
        or do { my $err = $!; close $fh; croak "Cannot write ".$path.": ".$err };
    close $fh
        or croak "Cannot write ".$path.": ".$!;

    # Force the exact mode: sysopen's 0600 is masked by umask, which cannot add
    # bits but a pathological umask could clear the owner ones.
    $path->chmod(0600);

    return;
}

#
# Age key management
#

sub has_age_key {
    my ($self) = @_;
    return -f $self->age_key_file;
}

#
# The age identity this run decrypts with (k216)
#
# sops' own variable first: SOPS_AGE_KEY_FILE, set and not empty, names the
# file the identity is read from, as it does for the sops CLI. That is how a
# Leitstand -- another recipient of the project's SOPS files, added with
# `ocp keys operator add` or `ocp keys recipients add` -- runs OCP with its
# own key: no PIN1, nothing unlocked into .ocp/. Without it, the project key
# in .ocp/age.key (unlocked from age.key.enc with PIN1).
#
# The variable's file is read, never copied: age_key_file stays .ocp/age.key,
# the project key's cache, and age.key.enc stays the project key behind PIN1.
# Nor is the project's recipient ever derived from it -- see age_recipient.

sub sops_age_key_file {
    my ($self) = @_;
    my $file = $ENV{SOPS_AGE_KEY_FILE};
    return (defined $file && length $file) ? path($file) : undef;
}

# Every decrypt in OCP::Secrets and OCP::Keys takes its identities from here.
# A file as age-keygen writes it: comments, then AGE-SECRET-KEY-1... lines;
# sops reads every one of them, and so does this.
sub identities {
    my ($self) = @_;

    my $file = $self->sops_age_key_file;
    unless ($file) {
        my $identity = $self->age_key_file->slurp;
        chomp $identity;
        return ($identity);
    }

    die "SOPS_AGE_KEY_FILE is set to ".$file.", and there is no such file.\n"
      . "Point it at the age identity this machine decrypts the project with, or\n"
      . "unset it to use the project key (.ocp/age.key, age.key.enc behind PIN1).\n"
        unless -f $file;

    my $content = eval { $file->slurp };
    unless (defined $content) {
        my $why = "$@";
        $why =~ s/\s+\z//;
        die "SOPS_AGE_KEY_FILE is set to ".$file.", which cannot be read: ".$why."\n";
    }

    my @ids = grep { /\AAGE-SECRET-KEY-1/ }
              map  { s/\A\s+|\s+\z//gr } split /\n/, $content;
    die "SOPS_AGE_KEY_FILE is set to ".$file.", which holds no age identity\n"
      . "(no AGE-SECRET-KEY-1... line, as age-keygen writes it).\n"
        unless @ids;

    for my $id (@ids) {
        die "SOPS_AGE_KEY_FILE is set to ".$file.", and a line in it is not a valid age identity.\n"
            unless eval { $self->_recipient_of_key($id); 1 };
    }

    return @ids;
}

# The recipients (public keys) of those identities.
sub identity_recipients {
    my ($self) = @_;
    return map { $self->_recipient_of_key($_) } $self->identities;
}

# Do the identities open the private SSH keys inside keys.yaml? Those carry an
# age layer of their own for the project key alone (OCP::Keys), so this is the
# one test that tells the project key from another recipient without knowing
# the project's recipient first. 1 or 0; undef when there is nothing to try
# it on (no keys.yaml, none of it readable, or no private half in it).
sub identity_opens_private_keys {
    my ($self) = @_;
    return $self->_opens_private_keys([ $self->identities ]);
}

sub _opens_private_keys {
    my ($self, $ids) = @_;

    my $data = $self->_keys_yaml_data($ids) or return undef;
    my ($entry) = grep { ref $_ eq 'HASH' && defined $_->{private} && length $_->{private} }
                  @{ $data->{keys} // [] };
    return undef unless $entry;

    my $private = $entry->{private};
    return eval { Crypt::Age->decrypt(ciphertext => $private, identities => $ids); 1 } ? 1 : 0;
}

# keys.yaml without its SOPS layer, or undef. Read here rather than through
# OCP::Keys, which builds on this class.
sub _keys_yaml_data {
    my ($self, $ids) = @_;

    my $file = $self->project_dir->child('keys.yaml');
    return undef unless -f $file;

    my $data = eval {
        File::SOPS->decrypt(encrypted => $file->slurp, identities => $ids, format => 'yaml');
    };
    return ref $data eq 'HASH' ? $data : undef;
}

# The SOPS files OCP writes. Every one of them records, in plaintext, the age
# recipient its data key is wrapped for:
#
#     sops:
#       age:
#       - enc: |
#           -----BEGIN AGE ENCRYPTED FILE-----
#         recipient: age1...
#
# That block is readable without holding any key, which makes it the honest
# answer to "which age key does this project belong to" — as opposed to
# has_age_key, which only answers "is there one on this machine".
sub _sops_files {
    my ($self) = @_;
    return map { $self->project_dir->child($_) } $self->sops_file_names;
}

# The names of the SOPS-encrypted project files, in the order they are listed
# everywhere (k241): the one list reencrypt's [ok] line and the rotation
# message are both ordered by.
sub sops_file_names { qw(keys.yaml secrets.yaml kubeconfig.yaml) }

# Which committed files are bound to which recipient. Returns a list of
# { file => 'keys.yaml', recipient => 'age1...' } — names, not a boolean,
# because every caller is about to tell a human what stands in the way.
sub age_key_bindings {
    my ($self) = @_;

    my @bindings;
    for my $file ($self->_sops_files) {
        next unless -f $file;

        my $data = eval { $self->ocp->load($file->slurp) };
        next unless $data && ref $data eq 'HASH';

        my $age = $data->{sops} && $data->{sops}{age};
        next unless $age && ref $age eq 'ARRAY';

        for my $entry (@$age) {
            next unless ref $entry eq 'HASH';
            my $recipient = $entry->{recipient};
            next unless defined $recipient && length $recipient;
            push @bindings, {
                file      => $file->basename,
                recipient => $recipient,
            };
        }
    }

    return \@bindings;
}

sub project_age_recipients {
    my ($self) = @_;

    my %seen;
    return [ grep { !$seen{$_}++ }
             map  { $_->{recipient} } @{ $self->age_key_bindings } ];
}

# Does this PROJECT already have an age key — even one this checkout does not
# hold? .ocp/ is gitignored (ADR 0004), so a clone has age.key.enc and the
# encrypted files but never .ocp/age.key. Asking has_age_key there and
# generating on "no" is what k86 was: a fresh key written over
# .ocp/age.pub, and keys.yaml bound to a recipient nobody has any more.
sub project_has_age_key {
    my ($self) = @_;

    return 1 if $self->has_age_key;
    return 1 if $self->has_age_key_enc;
    return @{ $self->age_key_bindings } ? 1 : 0;
}

# Everything a new key would orphan. A lone .ocp/age.pub is deliberately not
# on this list: nothing is encrypted to it, so replacing it costs nothing.
sub _age_key_blockers {
    my ($self) = @_;

    my %seen;
    my @blockers;
    push @blockers, 'age.key.enc' if $self->has_age_key_enc;
    push @blockers, grep { !$seen{$_}++ }
                    map  { $_->{file} } @{ $self->age_key_bindings };

    return \@blockers;
}

sub generate_age_key {
    my ($self) = @_;

    my $key_file = $self->age_key_file;
    my $pub_file = $self->age_recipient_file;

    # The safety net for k86, placed here rather than in the caller so it
    # holds for any path to generation — present or added later. A generated
    # keypair is always new, so it can never be the recipient the committed
    # files already name; writing .ocp/age.pub from it is therefore always the
    # damaging move whenever anything is bound.
    my $blockers = $self->_age_key_blockers;
    if (@$blockers) {
        croak
            "Refusing to generate a new age key: this project already has one.\n"
          . "  Bound to it: " . join(', ', @$blockers) . "\n"
          . "A new key would replace .ocp/age.pub, and none of those files could\n"
          . "be decrypted again. Unlock the existing key with PIN1 (age.key.enc),\n"
          . "or copy .ocp/age.key from whoever set the project up — .ocp/ is\n"
          . "gitignored, so a clone never carries it.";
    }

    # Ensure .ocp directory exists
    $key_file->parent->mkpath;

    # Generate key using Crypt::Age
    my ($public_key, $secret_key) = Crypt::Age->generate_keypair;

    # Write files. The secret half is created 0600 from the start (see
    # _spew_secure); the public half is public, so plain spew is fine.
    $self->_spew_secure($key_file, $secret_key . "\n");

    $pub_file->spew($public_key . "\n");

    return {
        public_key => $public_key,
        secret_key => $secret_key,
    };
}

# The project key's recipient: .ocp/age.pub. Under SOPS_AGE_KEY_FILE without
# one -- a Leitstand's checkout never held the project key -- it is read off
# the committed files instead (_derive_project_recipient), never taken from
# the identity in use. undef when there is no answer, or no unambiguous one.
sub age_recipient {
    my ($self) = @_;

    if (-f $self->age_recipient_file) {
        my $recipient = $self->age_recipient_file->slurp;
        chomp $recipient;
        return $recipient;
    }
    return undef unless $self->sops_age_key_file;

    my ($recipient) = $self->_derive_project_recipient;
    return $recipient;
}

# Which of the recipients the SOPS files are encrypted for is the project
# key? Returns ($recipient or undef, [ the candidates ]).
#
#   1. An identity that opens the private keys inside keys.yaml IS the
#      project key -- no other recipient can (their own age layer).
#   2. Otherwise the recipients the files are bound to (age_key_bindings),
#      minus those the governing .sops.yaml lists: OCP's own .sops.yaml lists
#      the project key too, so when nothing is left, all bound ones remain.
#   3. Still more than one: minus the operators' recipients in keys.yaml, and
#      minus this run's own identities once (1) said they are not the key.
#
# Exactly one left is the answer; anything else is no answer, and the write
# paths refuse instead of guessing (project_recipient).
sub _derive_project_recipient {
    my ($self) = @_;

    my @ids = eval { $self->identities };
    for my $id (@ids) {
        return ($self->_recipient_of_key($id), [])
            if $self->_opens_private_keys([$id]);
    }
    my $opens = @ids ? $self->_opens_private_keys(\@ids) : undef;

    my @bound  = @{ $self->project_age_recipients };
    my %listed = map { $_ => 1 }
                 eval { $self->sops_recipients_for($self->project_dir->child('keys.yaml')) };
    my @candidates = grep { !$listed{$_} } @bound;
    @candidates = @bound unless @candidates;

    if (@candidates > 1) {
        my %other = map { $_ => 1 } $self->_operator_recipients(\@ids);
        if (defined $opens && !$opens) {
            $other{ $self->_recipient_of_key($_) } = 1 for @ids;
        }
        @candidates = grep { !$other{$_} } @candidates;
    }

    return (@candidates == 1 ? $candidates[0] : undef, \@candidates);
}

# The age recipients of the operator entries in keys.yaml (k216).
sub _operator_recipients {
    my ($self, $ids) = @_;

    my $data = $self->_keys_yaml_data($ids) or return ();
    return map  { $_->{age} }
           grep { ref $_ eq 'HASH' && ($_->{purpose} // '') eq 'operator'
                  && defined $_->{age} && length $_->{age} }
           @{ $data->{keys} // [] };
}

# The project's recipient for a write, or a refusal that says why there is
# none. Without SOPS_AGE_KEY_FILE that is the old "no recipient" -- a project
# that never had a key. With it, the files could not tell (see
# _derive_project_recipient), and encrypting on a guess could leave the
# project key out of every file this run writes.
sub project_recipient {
    my ($self) = @_;

    my $recipient = $self->age_recipient;
    return $recipient if defined $recipient;

    my $file = $self->sops_age_key_file
        or croak "No age recipient found. Run generate_age_key first.";

    my (undef, $candidates) = $self->_derive_project_recipient;
    die "ERROR: Which age recipient is this project's own key? This run decrypts\n"
      . "       with SOPS_AGE_KEY_FILE (".$file."), and this checkout has no\n"
      . "       .ocp/age.pub to say.\n"
      . (@$candidates
          ? "       The encrypted files leave these open:\n"
            . join('', map { "         $_\n" } @$candidates)
          : "       The encrypted files name no recipient that could be it.\n")
      . "       Writing on a guess could encrypt them without the project key, so\n"
      . "       nothing was written. Put the project key's recipient -- the first\n"
      . "       line of 'ocp keys recipients ls' where the project key is -- into\n"
      . "       .ocp/age.pub, and run again.\n";
}

# The public half of an age secret key. X25519, so it is derivable — there is
# never a reason to guess at a recipient or to mint a new key just because
# .ocp/age.pub is missing.
sub _recipient_of_key {
    my ($self, $secret_key) = @_;

    my $secret = $secret_key;
    chomp $secret;

    return Crypt::Age::Keys->public_key_from_secret($secret);
}

# Does this secret key open what the project is bound to? Called before any
# write that would act on the key's authority, so a stale or foreign
# age.key.enc fails here — with the two recipients named — instead of later,
# as an opaque "could not decrypt data key with any of the provided
# identities" from three commands down.
#
# Several keys (SOPS_AGE_KEY_FILE may hold more than one, k216): one of them
# opening the files is enough, as for sops.
sub _assert_key_matches_project {
    my ($self, @secret_keys) = @_;

    my $bound = $self->age_key_bindings;
    return 1 unless @$bound;

    my @public = map { $self->_recipient_of_key($_) } @secret_keys;
    my %bound  = map { $_->{recipient} => 1 } @$bound;
    return 1 if grep { $bound{$_} } @public;

    my $from = $self->sops_age_key_file;
    croak
        "This age key does not belong to this project.\n"
      . join('', map { "  The key opens:   $_\n" } @public)
      . ($from ? "  (read from SOPS_AGE_KEY_FILE=$from)\n" : '')
      . join('', map { sprintf "  %-16s %s\n", "$_->{file} needs:", $_->{recipient} }
                 @$bound)
      . "Nothing was done. Use the key those files name.";
}

# Does the key in this checkout open what the project is bound to? Croaks
# with both recipients named when it does not. That is the state an old
# `ocp init` left a fresh clone in — a minted key sitting next to committed
# files it cannot read — and without this the only symptom is "could not
# decrypt data key with any of the provided identities" from wherever the run
# happens to reach first.
sub check_local_age_key {
    my ($self) = @_;

    return $self->_assert_key_matches_project($self->identities)
        if $self->sops_age_key_file;
    return 0 unless $self->has_age_key;
    return $self->_assert_key_matches_project($self->age_key_file->slurp);
}

# Rebuild .ocp/age.pub from .ocp/age.key when it is missing. Every encrypt
# path reads it — create_secrets, save_kubeconfig, OCP::Keys::add_key — so a
# checkout that unlocked age.key.enc but has no recipient file can decrypt
# everything and encrypt nothing.
#
# It never overwrites an existing recipient file: that file is what the
# committed material is bound to, and replacing it is the whole failure mode
# this guards against.
#
# Never under SOPS_AGE_KEY_FILE (k216): that identity may be another
# recipient, and an age.pub written from it would make the next write encrypt
# kubeconfig.yaml, secrets.yaml and keys.yaml without the project key.
sub restore_age_recipient {
    my ($self) = @_;

    return 0 if $self->sops_age_key_file;
    return 0 if -f $self->age_recipient_file;
    return 0 unless $self->has_age_key;

    my $secret = $self->age_key_file->slurp;
    $self->_assert_key_matches_project($secret);

    my $public = $self->_recipient_of_key($secret);

    $self->age_recipient_file->parent->mkpath;
    $self->age_recipient_file->spew($public . "\n");

    return $public;
}

#
# Recipients (k212)
#
# The project key -- .ocp/age.key, age.key.enc behind PIN1 -- is a recipient of
# every SOPS file OCP writes, always. Further recipients (a Leitstand machine,
# a second operator) come from the .sops.yaml that governs the files, the way
# sops itself decides: the nearest one at or above the project directory, its
# first creation rule whose path_regex matches. Only the rule's age
# recipients are taken; what gets encrypted stays OCP's business (everything).
#
# Every write path asks recipients_for, so an `ocp apply` that rewrites
# kubeconfig.yaml keeps the extra recipients instead of silently dropping
# them. A recipient only ever hands over its public key.
#
# Not covered: the private halves inside keys.yaml carry a second age layer
# of their own (OCP::Keys::_single_encrypt / _double_encrypt) for the project
# key alone. Another recipient reads keys.yaml, not the project's SSH keys.

# The rule OCP writes into a .sops.yaml it creates.
our $SOPS_RULE_REGEX = '^(keys|secrets|kubeconfig)\.yaml$';

sub sops_config_file { $_[0]->project_dir->child('.sops.yaml') }

# The .sops.yaml sops would read for the project's files, or undef: the
# nearest one at or above the project directory, up to the filesystem root.
sub governing_sops_config {
    my ($self) = @_;

    my $dir = $self->project_dir->absolute;
    while (1) {
        my $candidate = $dir->child('.sops.yaml');
        return $candidate->stringify if -f $candidate;
        last if $dir->is_rootdir;
        $dir = $dir->parent;
    }
    return undef;
}

# Is the governing .sops.yaml the project's own (the one OCP may rewrite)?
sub sops_config_is_ours {
    my ($self) = @_;

    my $config = $self->governing_sops_config // return 0;
    return 0 unless -f $self->sops_config_file;
    return path($config)->realpath eq $self->sops_config_file->realpath ? 1 : 0;
}

# The age recipients the governing .sops.yaml names for $file; empty without
# a .sops.yaml or without a rule matching the file -- a .sops.yaml further up
# that is about other files must not break OCP. Anything else wrong with the
# config dies, as it does for sops.
sub sops_recipients_for {
    my ($self, $file) = @_;

    my $config = $self->governing_sops_config // return ();
    my %args = eval {
        File::SOPS->creation_rules_for(file => path($file)->absolute->stringify, config => $config);
    };
    if (my $err = $@) {
        return () if $err =~ /\ANo creation rule in /;
        die $err;
    }
    return @{ $args{recipients} // [] };
}

# Everyone $file is encrypted for: the project key first, then the
# .sops.yaml recipients.
sub recipients_for {
    my ($self, $file) = @_;

    my $project = $self->project_recipient;
    my %seen;
    return [ grep { !$seen{$_}++ } $project, $self->sops_recipients_for($file) ];
}

# The recipients besides the project key, as the governing .sops.yaml has
# them for the project's files (keys.yaml stands for all three).
sub extra_recipients {
    my ($self) = @_;

    my $project = $self->age_recipient // '';
    return grep { $_ ne $project } $self->sops_recipients_for($self->project_dir->child('keys.yaml'));
}

# May OCP write the recipient list into the project's own .sops.yaml? Yes
# when that is the governing one, or when there is none, or when the one
# further up has no rule for the project's files. A rule further up that does
# match is somebody else's file: OCP reads it and leaves it alone.
sub sops_config_editable {
    my ($self) = @_;

    my $config = $self->governing_sops_config // return 1;
    return 1 if $self->sops_config_is_ours;
    my $ok = eval {
        File::SOPS->creation_rules_for(
            file   => $self->project_dir->child('keys.yaml')->absolute->stringify,
            config => $config);
        1;
    };
    return 1 if !$ok && $@ =~ /\ANo creation rule in /;
    return 0;
}

# Write the project's .sops.yaml so the OCP files go to the project key plus
# @$extras. An existing file keeps every rule but the one matching the OCP
# files, which gets the new list; without one a rule is put first. Rewritten
# through YAML, so comments in an existing file do not survive.
sub set_sops_recipients {
    my ($self, $extras) = @_;

    croak "The project's SOPS files take their recipients from "
        . $self->governing_sops_config . ", outside this project; OCP does not rewrite it"
        unless $self->sops_config_editable;

    my $project = $self->project_recipient;
    my %seen;
    my $age = join ',', grep { !$seen{$_}++ } $project, @$extras;

    my $file = $self->sops_config_file;
    my $conf = -f $file ? YAML::XS::LoadFile($file->stringify) : undef;
    $conf = {} unless ref $conf eq 'HASH';
    my $rules = $conf->{creation_rules} = ref $conf->{creation_rules} eq 'ARRAY'
        ? $conf->{creation_rules} : [];

    my %index;
    for my $name (qw( keys.yaml secrets.yaml kubeconfig.yaml )) {
        my $i = 0;
        for my $rule (@$rules) {
            my $re = ref $rule eq 'HASH' ? $rule->{path_regex} : undef;
            last if !defined $re || !length $re || $name =~ /$re/;
            $i++;
        }
        $index{$i}++ if $i < @$rules;
    }
    croak "The creation rules in ".$file." split keys.yaml, secrets.yaml and kubeconfig.yaml"
        . " over several rules; give them one rule so they share one recipient list"
        if keys %index > 1;

    if (my ($i) = keys %index) {
        $rules->[$i]{age} = $age;
    } else {
        unshift @$rules, { path_regex => $SOPS_RULE_REGEX, age => $age };
    }

    my $header = -f $file ? '' :
        "# Who the OCP files (keys.yaml, secrets.yaml, kubeconfig.yaml) are\n"
      . "# encrypted for: the project key first, then the others. Kept by\n"
      . "# `ocp keys recipients add|rm`, which also re-encrypts the files.\n";
    $file->spew($header . YAML::XS::Dump($conf));
    return 1;
}

# Re-encrypt every SOPS file of the project whose recipients are not the ones
# recipients_for names now, with a new data key (File::SOPS rotate, sops
# updatekeys + rotate). Needs the project key; returns the files it rewrote.
sub rotate_sops_files {
    my ($self) = @_;

    my @identities = $self->identities;
    $self->_assert_key_matches_project(@identities);

    my %have;
    push @{ $have{ $_->{file} } }, $_->{recipient} for @{ $self->age_key_bindings };

    my @done;
    for my $file ($self->_sops_files) {
        next unless -f $file;
        my $want = $self->recipients_for($file);
        next if join(',', sort @$want) eq join(',', sort @{ $have{ $file->basename } // [] });

        File::SOPS->rotate(
            file       => $file->stringify,
            identities => \@identities,
            recipients => $want,
            format     => 'yaml',
        );
        $file->spew($self->ocp->quote_sops_lastmodified($file->slurp));
        push @done, $file->basename;
    }
    return @done;
}

#
# Password-encrypted age.key (Defense in Depth!)
#

sub has_age_key_enc {
    my ($self) = @_;
    return -f $self->age_key_enc_file;
}

sub encrypt_age_key_with_password {
    my ($self, $password) = @_;

    unless ($self->has_age_key) {
        croak "No age.key found. Run generate_age_key first.";
    }


    my $age_key = $self->age_key_file->slurp;
    my $encrypted = OCP::Password::encrypt_age_key($age_key, $password);

    $self->age_key_enc_file->spew($encrypted);
    return 1;
}

sub decrypt_age_key_with_password {
    my ($self, $password) = @_;

    unless ($self->has_age_key_enc) {
        croak "No age.key.enc found.";
    }


    my $encrypted = $self->age_key_enc_file->slurp;
    chomp $encrypted;

    my $age_key = OCP::Password::decrypt_age_key($encrypted, $password);

    # Before caching it: is this the key the project's files are bound to?
    # Caching a mismatched key would make has_age_key say yes from then on,
    # and every later run would fail at the SOPS layer instead of here.
    $self->_assert_key_matches_project($age_key);

    # Write to .ocp/age.key (cached), created 0600 without a world-readable
    # staging file (see _spew_secure).
    $self->_spew_secure($self->age_key_file, $age_key);

    # ...and the recipient half, which a clone has no other source for.
    $self->restore_age_recipient;

    return $age_key;
}

sub ensure_age_key {
    my ($self, $password) = @_;

    # SOPS_AGE_KEY_FILE (k216): that file is the identity. No PIN1, nothing
    # written to .ocp/ -- checked that it opens this project, and done.
    if ($self->sops_age_key_file) {
        $self->_assert_key_matches_project($self->identities);
        return 1;
    }

    # If .ocp/age.key exists, we're good
    if ($self->has_age_key) {
        $self->restore_age_recipient;
        return 1;
    }

    # Try to decrypt from age.key.enc
    if ($self->has_age_key_enc) {
        unless ($password) {
        
            $password = OCP::Password::prompt_password("Enter PIN1 (cluster access): ");
        }
        $self->decrypt_age_key_with_password($password);
        return 1;
    }

    # No age.key available
    croak "No age.key found. Run 'ocp init' first.";
}

#
# SOPS operations
#

sub has_secrets_file {
    my ($self) = @_;
    return -f $self->secrets_file;
}

sub create_secrets {
    my ($self, %secrets) = @_;

    # Encrypt with File::SOPS, for every recipient of the project (k212)
    my $encrypted = File::SOPS->encrypt(
        data       => \%secrets,
        recipients => $self->recipients_for($self->secrets_file),
        format     => 'yaml',
    );

    $self->secrets_file->spew($self->ocp->quote_sops_lastmodified($encrypted));
    return 1;
}

sub read_secret {
    my ($self, $key) = @_;

    return undef unless $self->has_secrets_file;

    my $secrets = $self->read_all_secrets;
    return $secrets->{$key};
}

sub read_all_secrets {
    my ($self) = @_;

    return {} unless $self->has_secrets_file;

    my @identities = $self->identities;
    # The same guard the write paths use: a foreign key in .ocp/age.key
    # must surface as the named-recipients error, not as File::SOPS's
    # opaque "could not decrypt data key" line (k118).
    $self->_assert_key_matches_project(@identities);

    my $encrypted = $self->secrets_file->slurp;

    return File::SOPS->decrypt(
        encrypted  => $encrypted,
        identities => \@identities,
        format     => 'yaml',
    );
}

sub update_secret {
    my ($self, $key, $value) = @_;

    my $secrets = $self->read_all_secrets;
    $secrets->{$key} = $value;

    $self->create_secrets(%$secrets);
}

#
# SSH key management
#

sub has_ssh_key {
    my ($self) = @_;
    my $key_path = $self->project_dir->child('.ocp', 'id_ed25519');
    return -f $key_path;
}

sub generate_ssh_key {
    my ($self, %opts) = @_;

    my $name = $opts{name} // 'id_ed25519';
    my $key_path = $self->project_dir->child('.ocp', $name);
    my $pub_path = $self->project_dir->child('.ocp', "$name.pub");

    # Ensure .ocp directory exists
    $key_path->parent->mkpath;

    # Remove existing file to avoid ssh-keygen "Overwrite?" prompt
    unlink $key_path->stringify if -f $key_path;
    unlink $pub_path->stringify if -f $pub_path;

    # Generate ED25519 key. List-form exec, not a shell string: a project_dir
    # whose absolute path carries a single quote or a shell metacharacter would
    # break out of the quotes in an interpolated command line and write the key
    # somewhere else (or run whatever the path spells). Same failure-report
    # shape as the other exec sites, e.g. OCP::SSH's scp helpers.
    system('ssh-keygen', '-t', 'ed25519', '-N', '', '-f', $key_path->stringify,
        '-C', 'ocp-cluster-key') == 0
        or croak "Failed to generate SSH key: $?";

    $key_path->chmod(0600);

    return {
        private_key => $key_path->stringify,
        public_key  => $pub_path->stringify,
    };
}

#
# Hetzner token helpers
#

sub hetzner_token {
    my ($self) = @_;

    # First check environment
    return $ENV{HETZNER_API_TOKEN} if $ENV{HETZNER_API_TOKEN};

    # Then check secrets file
    return $self->read_secret('hetzner_token');
}

sub set_hetzner_token {
    my ($self, $token) = @_;

    if ($self->has_secrets_file) {
        $self->update_secret('hetzner_token', $token);
    } else {
        $self->create_secrets(hetzner_token => $token);
    }
}

#
# Kubeconfig management (encrypted file)
#

sub has_kubeconfig {
    my ($self) = @_;
    return -f $self->kubeconfig_file;
}

sub save_kubeconfig {
    my ($self, $kubeconfig_yaml) = @_;

    # Encrypt kubeconfig with SOPS
    my $encrypted = File::SOPS->encrypt(
        data       => $self->ocp->load($kubeconfig_yaml),
        recipients => $self->recipients_for($self->kubeconfig_file),
        format     => 'yaml',
    );

    $self->kubeconfig_file->spew($self->ocp->quote_sops_lastmodified($encrypted));
    return 1;
}

sub read_kubeconfig {
    my ($self) = @_;

    return undef unless $self->has_kubeconfig;

    my @identities = $self->identities;
    # Same guard as the write paths — k118.
    $self->_assert_key_matches_project(@identities);

    my $encrypted = $self->kubeconfig_file->slurp;

    my $decrypted = File::SOPS->decrypt(
        encrypted  => $encrypted,
        identities => \@identities,
        format     => 'yaml',
    );

    return $self->ocp->dump($decrypted);
}

sub decrypt_kubeconfig_to_file {
    my ($self, $target_file) = @_;

    my $kubeconfig = $self->read_kubeconfig
        or croak "No kubeconfig found";

    # Ensure parent directory exists
    my $target = path($target_file);
    $target->parent->mkpath;

    $self->_spew_secure($target, $kubeconfig);

    return $target->stringify;
}

#
# Generic encrypted file helper
#

sub encrypt_file {
    my ($self, $content, $file) = @_;

    # If content is YAML string, parse it first
    my $data = ref($content) ? $content : $self->ocp->load($content);

    my $file_path = $self->project_dir->child($file);

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => $self->recipients_for($file_path),
        format     => 'yaml',
    );

    $file_path->spew($self->ocp->quote_sops_lastmodified($encrypted));

    return 1;
}

sub decrypt_file {
    my ($self, $file) = @_;

    my $file_path = $self->project_dir->child($file);
    return undef unless -f $file_path;

    my @identities = $self->identities;
    # Same guard as the write paths — k118.
    $self->_assert_key_matches_project(@identities);

    my $encrypted = $file_path->slurp;

    my $decrypted = File::SOPS->decrypt(
        encrypted  => $encrypted,
        identities => \@identities,
        format     => 'yaml',
    );

    return $self->ocp->dump($decrypted);
}

1;

__END__

=head1 NAME

OCP::Secrets - Secret management for OCP using SOPS and age

=head1 SYNOPSIS

    use OCP::Secrets;

    my $secrets = OCP::Secrets->new(project_dir => path('.'));

    # Generate encryption key
    $secrets->generate_age_key;

    # Store Hetzner token
    $secrets->set_hetzner_token('xxx');

    # Read token
    my $token = $secrets->hetzner_token;

=head1 DESCRIPTION

OCP::Secrets manages encrypted secrets using File::SOPS with Crypt::Age encryption.
Secrets are stored in C<secrets.yaml> (encrypted) and the age key is
stored in C<.ocp/age.key>.

This module uses pure Perl implementations (Crypt::Age and File::SOPS)
and does not require any external CLI tools.

=head1 WHICH IDENTITY DECRYPTS

Every decrypt -- C<read_all_secrets>, C<read_kubeconfig>, C<decrypt_file>,
C<rotate_sops_files>, and L<OCP::Keys> -- takes its age identities from
C<identities> (k216):

=over 4

=item * C<SOPS_AGE_KEY_FILE>, when set and not empty: every
C<AGE-SECRET-KEY-1...> line of that file, as sops reads it. No PIN1 is asked,
and nothing is written to F<.ocp/> -- the file is never copied to
F<.ocp/age.key>, and F<.ocp/age.pub> is never derived from it. A missing,
unreadable or empty file dies naming the variable. This is how an operator (a
Leitstand, C<ocp keys operator add>) runs OCP with its own identity.

=item * otherwise F<.ocp/age.key>, the project key, unlocked from
F<age.key.enc> with PIN1. F<age.key.enc> holds the project key only, always.

=back

Under another identity the project's recipient (L</age_recipient>) is read
off the committed files, never taken from that identity: a write must stay
encrypted for the project key. The private SSH keys inside F<keys.yaml> stay
closed to such an identity; L<OCP::Keys> says so by name.

=head2 sops_age_key_file

The path C<SOPS_AGE_KEY_FILE> names, as a L<Path::Tiny>, or C<undef>.

=head2 identities / identity_recipients

The age identities this run decrypts with, and their recipients.

=head2 identity_opens_private_keys

1 when the identities open the private keys inside F<keys.yaml> (their inner
age layer is the project key's alone -- so this identity is the project
key), 0 when they do not, C<undef> when there is nothing to try.

=head2 age_recipient / project_recipient

The project key's recipient: F<.ocp/age.pub>. Under C<SOPS_AGE_KEY_FILE>
without one: the identity's own recipient when it opens the private keys in
F<keys.yaml>; otherwise the recipients the SOPS files are bound to, less the
ones the governing F<.sops.yaml> lists (unless that leaves none), less the
operators' recipients from F<keys.yaml> and the run's own identities. Exactly
one left is the answer. C<age_recipient> returns C<undef> without one;
C<project_recipient>, which every write path uses, dies -- naming the
candidates and the way out (the project key's recipient into
F<.ocp/age.pub>) -- rather than encrypt on a guess.

=head1 WHOSE KEY IS IT

F<.ocp/> is gitignored; F<keys.yaml>, F<secrets.yaml>, F<kubeconfig.yaml> and
F<age.key.enc> are committed. So "is there an age key on this machine" and
"does this project have an age key" are B<different questions>, and a checkout
that confuses them mints a new key over F<.ocp/age.pub> and orphans everything
the project ever encrypted (k86).

=over 4

=item C<has_age_key> — is F<.ocp/age.key> here? Machine-local.

=item C<project_has_age_key> — does the project have one at all, held or not?

=back

=head2 age_key_bindings

Returns an arrayref of C<< { file => 'keys.yaml', recipient => 'age1...' } >>
for every committed SOPS file. SOPS records its recipient in plaintext, so
this reads without any key — which is what makes it usable I<before> deciding
whether to generate.

=head2 project_age_recipients

The deduplicated recipients from L</age_key_bindings>.

=head2 project_has_age_key

True when F<.ocp/age.key> or F<age.key.enc> exists, or when any committed SOPS
file names a recipient. This is the question to ask before generating.

=head2 generate_age_key

Generates a keypair into F<.ocp/age.key> and F<.ocp/age.pub>.

B<Croaks> when anything is already bound to a recipient (F<age.key.enc> or a
SOPS file). A generated keypair is always new, so it can never be the
recipient those files name — writing F<.ocp/age.pub> from it would always be
the destructive move. The guard sits here, below every command, so it holds
for paths added later as well.

=head2 recipients_for

    my $recipients = $secrets->recipients_for($secrets->secrets_file);

Everyone a SOPS file of the project is encrypted for (k212): the project key
first, then the age recipients of the first creation rule matching the file in
the governing F<.sops.yaml> -- the nearest one at or above the project
directory, as sops finds it. A F<.sops.yaml> without a rule for the file adds
nothing. Every write path (C<create_secrets>, C<save_kubeconfig>,
C<encrypt_file>, L<OCP::Keys>) encrypts for this list.

=head2 governing_sops_config / sops_config_is_ours / sops_config_editable

Which F<.sops.yaml> governs the project's files, whether it is the project's
own, and whether OCP may write the list there (its own file, none at all, or
one further up without a rule for the project's files).

=head2 extra_recipients

The recipients besides the project key.

=head2 set_sops_recipients

    $secrets->set_sops_recipients([ 'age1...' ]);

Writes the project key plus these recipients into the project's
F<.sops.yaml>: into the rule matching F<keys.yaml>, F<secrets.yaml> and
F<kubeconfig.yaml>, or as a new first rule. Other rules stay; comments do
not. Refuses a F<.sops.yaml> outside the project that has the rule.

=head2 rotate_sops_files

Re-encrypts every SOPS file whose recipients differ from L</recipients_for>
with a new data key (L<File::SOPS/rotate>). Needs an identity that opens the
files (F<.ocp/age.key>, or C<SOPS_AGE_KEY_FILE>). Returns the file names it
rewrote.

=head2 restore_age_recipient

Never under C<SOPS_AGE_KEY_FILE> (k216). Rebuilds F<.ocp/age.pub> from
F<.ocp/age.key> when it is missing — the public
half is derivable (X25519), so a clone that unlocked F<age.key.enc> does not
need a stored copy in order to encrypt again. It never overwrites an existing
recipient file, and refuses outright when the local key does not open what the
project is bound to.

=cut

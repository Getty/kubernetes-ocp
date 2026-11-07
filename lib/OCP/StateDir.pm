package OCP::StateDir;
# ABSTRACT: The project's .ocp/ directory, made 0700 with the .gitignore that keeps it out of git

use strict;
use warnings;
use Path::Tiny qw( path );

# What `ocp init` has always written to .ocp/.gitignore (k215): everything in
# .ocp/ is decrypted state or a local cache, and none of it may be committed.
our $GITIGNORE = "# Decrypted OCP state - never commit (written by ocp init)\n*\n";

# Make the directory $file is about to be written into. When that is a .ocp/
# -- the project's local state, gitignored (ADR 0004) -- it gets its own
# .gitignore as well, before the first file lands in it (k371): a clone's
# .ocp/ is made by whatever writes first (the first PIN1 unlock, status.yaml,
# known_hosts, deployed.yaml), never by `ocp init`, and keeping the plaintext
# age key out of git must not rest on the project's own .gitignore alone.
# Returns the directory.
sub make_parent {
    my ($file) = @_;

    my $dir = make_dir(path($file)->parent);
    write_gitignore($dir) if $dir->basename eq '.ocp';
    return $dir;
}

=head1 FUNCTIONS

=func make_parent

    OCP::StateDir::make_parent($file);

Makes C<$file>'s directory, as L</make_dir> does. When that directory is
named F<.ocp>, writes its F<.gitignore> as well, unless one is there. Returns
the directory as a L<Path::Tiny>.

=cut

# Make $dir and the directories above it, unless it is there. A .ocp/ is made
# 0700 (k372): the secrets in it are each 0600, but a directory at the umask
# default (0755 under 022) still let every local user list it and read their
# names. It is created with that mode, not chmod'd to it afterwards, so there
# is no moment it stands open; the chmod, on a .ocp/ made by this very call
# only (mkpath returns what it made), gives back owner bits a pathological
# umask took -- a umask takes bits away, it never adds one. The directories
# above it get the default, and a directory that is there keeps its mode:
# nothing here tightens a .ocp/ made before. Every writer that can make .ocp/
# comes through here (ocp init's step 3 directly, the rest through
# make_parent), so its mode does not depend on which command ran first.
# Returns $dir.
sub make_dir {
    my ($dir) = @_;

    $dir = path($dir);
    if ($dir->basename ne '.ocp') {
        $dir->mkpath;    # no-op if it is there
        return $dir;
    }

    $dir->parent->mkpath;
    $dir->chmod(0700) if $dir->mkpath({ mode => 0700 });
    return $dir;
}

=func make_dir

    OCP::StateDir::make_dir(path('.ocp'));

Makes C<$dir> and the directories above it, unless it is there. A directory
named F<.ocp> is created mode C<0700>; the directories above it, and every
other directory, get the default (C<0777> less the umask). A directory that is
there is left as it is, mode included. Writes no F<.gitignore>: that is
L</make_parent>'s and L</write_gitignore>'s. Returns the directory as a
L<Path::Tiny>.

=cut

# Write $dir/.gitignore with $GITIGNORE, unless something is there already: a
# .gitignore someone wrote or edited is never replaced. 1 when it wrote one.
sub write_gitignore {
    my ($dir) = @_;

    my $ignore = path($dir)->child('.gitignore');
    return 0 if -e $ignore || -l $ignore;
    $ignore->spew($GITIGNORE);
    return 1;
}

=func write_gitignore

    my $wrote = OCP::StateDir::write_gitignore($dir);

Writes F<$dir/.gitignore> with C<$OCP::StateDir::GITIGNORE> unless something
by that name is there already. 1 when it wrote one, 0 otherwise.

=cut

1;

__END__

=head1 SYNOPSIS

    use OCP::StateDir;

    OCP::StateDir::make_parent($project_dir->child('.ocp', 'status.yaml'));

    OCP::StateDir::make_dir(path('.ocp'));
    print "[ok] Created .ocp/.gitignore\n"
        if OCP::StateDir::write_gitignore(path('.ocp'));

=head1 DESCRIPTION

F<.ocp/> holds the project's decrypted state -- the age key, status, host
keys -- and must never be committed. Whichever command makes it first gives
it the F<.gitignore> C<ocp init> writes (C<*>), so a clone's F<.ocp/> ignores
itself as an initialised project's does.

Whichever command makes F<.ocp/> makes it mode C<0700>, so only its owner can
list it. A F<.ocp/> that is there already keeps the mode it has.

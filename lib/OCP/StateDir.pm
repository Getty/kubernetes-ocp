package OCP::StateDir;
# ABSTRACT: The project's .ocp/ directory, made with the .gitignore that keeps it out of git

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

    my $dir = path($file)->parent;
    $dir->mkpath;    # no-op if it is there
    write_gitignore($dir) if $dir->basename eq '.ocp';
    return $dir;
}

# Write $dir/.gitignore with $GITIGNORE, unless something is there already: a
# .gitignore someone wrote or edited is never replaced. 1 when it wrote one.
sub write_gitignore {
    my ($dir) = @_;

    my $ignore = path($dir)->child('.gitignore');
    return 0 if -e $ignore || -l $ignore;
    $ignore->spew($GITIGNORE);
    return 1;
}

1;

__END__

=head1 SYNOPSIS

    use OCP::StateDir;

    OCP::StateDir::make_parent($project_dir->child('.ocp', 'status.yaml'));

    print "[ok] Created .ocp/.gitignore\n"
        if OCP::StateDir::write_gitignore(path('.ocp'));

=head1 DESCRIPTION

F<.ocp/> holds the project's decrypted state -- the age key, status, host
keys -- and must never be committed. Whichever command makes it first gives
it the F<.gitignore> C<ocp init> writes (C<*>), so a clone's F<.ocp/> ignores
itself as an initialised project's does.

=head1 FUNCTIONS

=head2 make_parent

    OCP::StateDir::make_parent($file);

Makes C<$file>'s directory. When that directory is named F<.ocp>, writes its
F<.gitignore> as well, unless one is there. Returns the directory as a
L<Path::Tiny>.

=head2 write_gitignore

    my $wrote = OCP::StateDir::write_gitignore($dir);

Writes F<$dir/.gitignore> with C<$OCP::StateDir::GITIGNORE> unless something
by that name is there already. 1 when it wrote one, 0 otherwise.

=cut

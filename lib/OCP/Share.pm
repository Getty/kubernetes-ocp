package OCP::Share;
# ABSTRACT: Resolve the share directory that belongs to the running code

use strict;
use warnings;

use FindBin;
use File::ShareDir ();
use Path::Tiny qw(path);

our $VERSION = '0.001';

# A directory is only OCP's share directory if it carries the Rexfile.
# Deciding on -d alone adopts any stray share/ that happens to sit in the
# right place — and an empty one would then shadow the real one.
our $MARKER = 'Rexfile';

# Where the image puts the distribution (Dockerfile: $OCP_ROOT/src).
our $IMAGE_DIR = '/opt/ocp/src/share';

# The order below used to start at $IMAGE_DIR, which made the image win over
# everything else inside a container — including over the working tree the
# operator had just mounted. The usual test invocation
#
#   docker run -v $REPO:/src:ro --entrypoint perl IMAGE -I/src/lib /src/bin/ocp
#
# only redirects lib/ via -I. share/ kept coming from the image, so every run
# executed the Rexfile of the last built image while claiming to test the
# working tree. Nothing said so: an arm64 bootstrap downloaded the amd64
# tarball, because the fix for that was in the tree and not in the image.
#
# So the share directory is now looked for next to the code that is running.
# In the image that resolves to $IMAGE_DIR anyway (bin/ and share/ are
# siblings under $OCP_ROOT/src), so the container case is unchanged; with
# -I/src/lib /src/bin/ocp it resolves to the working tree, which is what the
# invocation meant. $IMAGE_DIR stays behind it for a script started from
# outside the distribution's own tree.
sub candidates {
    my ($class) = @_;

    my @dirs;

    # Next to the running script: <bin>/../share. RealBin first, so a symlink
    # into the distribution resolves to the distribution and not to the
    # directory the symlink sits in.
    my %seen;
    for my $bin (grep { defined && length } $FindBin::RealBin, $FindBin::Bin) {
        next if $seen{$bin}++;
        push @dirs, path($bin)->parent->child('share');
    }

    push @dirs, path($IMAGE_DIR);

    # Installed from CPAN.
    eval { push @dirs, path(File::ShareDir::dist_dir('OCP')); 1 };

    return @dirs;
}

sub dir {
    my ($class) = @_;

    # An explicit pointer is authoritative and never falls through: a wrong
    # OCP_SHARE_DIR has to fail loudly, or it silently reintroduces exactly
    # the confusion it was set to end.
    if (defined $ENV{OCP_SHARE_DIR} && length $ENV{OCP_SHARE_DIR}) {
        my $dir = path($ENV{OCP_SHARE_DIR});
        die "OCP_SHARE_DIR is set to '$dir', which is not a directory\n"
            unless -d $dir;
        return $dir;
    }

    my @tried;
    for my $dir ($class->candidates) {
        push @tried, "$dir";
        return path($dir) if -d $dir && -f path($dir)->child($MARKER);
    }

    die "OCP share directory not found. Tried:\n"
        . join("\n", map { "  - $_" } @tried) . "\n"
        . "Set OCP_SHARE_DIR to point at it.\n";
}

sub rexfile {
    my ($class) = @_;

    my $dir = $class->dir;
    my $rexfile = $dir->child('Rexfile');
    die "Rexfile not found in share directory $dir\n" unless -f $rexfile;

    return $rexfile;
}

1;

__END__

=head1 NAME

OCP::Share - Resolve the share directory that belongs to the running code

=head1 SYNOPSIS

    use OCP::Share;

    my $crd = OCP::Share->dir->child('nfd', 'crds', 'nfd-api-crds.yaml');
    my $rexfile = OCP::Share->rexfile;

    # override everything:
    $ENV{OCP_SHARE_DIR} = '/src/share';

=head1 DESCRIPTION

Everything OCP ships as data rather than as code lives in F<share/>: the
Rexfile that carries the whole bootstrap, and the CRD bundles for NFD, the GPU
operator and robocop. Three modules used to look for it on their own, all with
the same hardcoded image path in first position, so inside a container the
image always won — even when the caller had mounted a working tree and put its
F<lib/> on C<@INC>.

One resolver, one order, and the working tree ahead of the image. The share
directory is the one next to the script that is running; C</opt/ocp/src/share>
and L<File::ShareDir> follow as fallbacks. C<OCP_SHARE_DIR> overrides all of
it and dies if it points at nothing, because a share directory found by
accident is the bug this module exists to prevent.

=head1 METHODS

=head2 dir

    my $share = OCP::Share->dir;

The share directory as a L<Path::Tiny>. Dies when none of the candidates
carries a F<Rexfile>.

=head2 rexfile

    my $rexfile = OCP::Share->rexfile;

The F<Rexfile> inside L</dir>.

=head2 candidates

    my @dirs = OCP::Share->candidates;

The locations L</dir> considers, in order. C<OCP_SHARE_DIR> is not among them
— it bypasses the search entirely.

=cut

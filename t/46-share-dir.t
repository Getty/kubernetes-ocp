#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use Path::Tiny qw(path);

use OCP::Share;
use OCP::Rex;

#
# share/ is where nearly all of the bootstrap lives — the Rexfile is 1200
# lines of it — and for the whole life of the distribution no test run ever
# executed the one in the working tree.
#
# Three modules looked for it on their own, all with /opt/ocp/src/share (the
# path inside the Docker image) in first position. The way OCP is tested is
#
#   docker run -v $REPO:/src:ro --entrypoint perl IMAGE -I/src/lib /src/bin/ocp
#
# where -I redirects lib/ and nothing redirects share/. Position one won every
# time, so the mounted working tree supplied the modules while the image
# supplied the Rexfile. The bill came due on an aarch64 host: the run pulled
# rke2.linux-amd64.tar.gz against an install script that wanted the arm64
# checksums, because the arm64 fix was in the tree and the February image knew
# nothing about it. No error pointed at the mismatch — the "Node architecture:
# arm64" line the fixed Rexfile prints was simply absent.
#
# The rule now: the share directory is the one next to the code that is
# running, and OCP_SHARE_DIR overrules everything without falling through.
#

# A share directory is only a share directory if it carries the marker.
sub make_share {
    my ($label) = @_;
    my $root = path(tempdir(CLEANUP => 1));
    my $bin  = $root->child('bin');
    my $share = $root->child('share');
    $bin->mkpath;
    $share->mkpath;
    $share->child('Rexfile')->spew("# $label\n");
    return ($root, $bin, $share);
}

subtest 'the working tree wins over the image path' => sub {
    my ($tree, $tree_bin, $tree_share) = make_share('working tree');
    my (undef, undef, $image_share)    = make_share('image');

    local $FindBin::RealBin = "$tree_bin";
    local $FindBin::Bin     = "$tree_bin";
    local $OCP::Share::IMAGE_DIR = "$image_share";

    my $chosen = OCP::Share->dir;
    is "$chosen", "$tree_share",
        'the share next to the running bin/ is chosen, not the image copy';
    is(OCP::Share->rexfile->slurp, "# working tree\n",
        'and the Rexfile that is executed comes from it');

    my @candidates = map { "$_" } OCP::Share->candidates;
    ok +(grep { $_ eq "$tree_share" } @candidates), 'working tree is a candidate';
    my ($tree_at) = grep { $candidates[$_] eq "$tree_share" } 0 .. $#candidates;
    my ($image_at) = grep { $candidates[$_] eq "$image_share" } 0 .. $#candidates;
    ok $tree_at < $image_at, 'and it is ordered ahead of the image path';
};

subtest 'the image still finds its own share when nothing is mounted' => sub {
    # In the image bin/ and share/ are siblings under /opt/ocp/src, so the
    # container case resolves to exactly the same directory as before — the
    # reordering must not cost the normal `docker run ocp ...` invocation
    # anything.
    my (undef, undef, $image_share) = make_share('image');

    my $nowhere = path(tempdir(CLEANUP => 1))->child('bin');
    $nowhere->mkpath;

    local $FindBin::RealBin = "$nowhere";
    local $FindBin::Bin     = "$nowhere";
    local $OCP::Share::IMAGE_DIR = "$image_share";

    my $chosen = OCP::Share->dir;
    is "$chosen", "$image_share",
        'a script outside the distribution tree falls back to the image path';
};

subtest 'a directory without the marker is not adopted' => sub {
    my $root = path(tempdir(CLEANUP => 1));
    my $bin  = $root->child('bin');
    $bin->mkpath;
    $root->child('share')->mkpath;   # exists, but empty

    my (undef, undef, $image_share) = make_share('image');

    local $FindBin::RealBin = "$bin";
    local $FindBin::Bin     = "$bin";
    local $OCP::Share::IMAGE_DIR = "$image_share";

    my $chosen = OCP::Share->dir;
    is "$chosen", "$image_share",
        'an empty share/ does not shadow a real one';
};

subtest 'OCP_SHARE_DIR is explicit and never falls through' => sub {
    my (undef, $tree_bin, $tree_share) = make_share('working tree');
    my (undef, undef, $explicit_share) = make_share('explicit');

    local $FindBin::RealBin = "$tree_bin";
    local $FindBin::Bin     = "$tree_bin";

    {
        local $ENV{OCP_SHARE_DIR} = "$explicit_share";
        my $chosen = OCP::Share->dir;
        is "$chosen", "$explicit_share",
            'the environment beats every guessed location';
        ok !(grep { $_ eq "$explicit_share" } map { "$_" } OCP::Share->candidates),
            'because it bypasses the search instead of joining it';
    }

    {
        # Silently searching on would put the run right back where it started:
        # using a share directory nobody asked for.
        local $ENV{OCP_SHARE_DIR} = '/no/such/share';
        my $dir = eval { OCP::Share->dir };
        ok !defined $dir, 'a wrong OCP_SHARE_DIR does not fall back';
        like $@, qr/OCP_SHARE_DIR/, 'and says which setting is wrong';
    }
};

subtest 'every consumer asks the one resolver' => sub {
    # The bug was three copies of the same search. A fourth would reintroduce
    # it, so no module may look for share/ on its own again.
    for my $file (qw(
        lib/OCP/Rex.pm
        lib/OCP/Cmd/Apply.pm
        lib/OCP/Cmd/DeployRobocop.pm
    )) {
        my $src = path($file)->slurp_utf8;

        unlike $src, qr{^[^#\n]*'/opt/ocp/src/share}m,
            "$file has no hardcoded image path";
        unlike $src, qr/dist_dir|File::ShareDir::/, "$file does not call File::ShareDir";
        unlike $src, qr/FindBin::(?:Real)?Bin/,     "$file does not derive share/ from FindBin";
        like   $src, qr/OCP::Share->(?:dir|rexfile)/, "$file goes through OCP::Share";
    }
};

#
# Fixing the order alone would have broken the very invocation it serves: the
# working tree arrives as a read-only mount, and Rex writes Rexfile.lock next
# to the Rexfile before it runs anything (Rex::CLI::handle_lock_file). That is
# a hard stop — "Read-only file system" — and it is why the workaround for
# this bug needed a mktemp copy of share/ to work at all.
#

subtest 'Rex runs from a writable copy of the Rexfile' => sub {
    my (undef, undef, $share) = make_share('working tree');
    $share->child('Rexfile')->spew("# the shipped Rexfile\n");
    chmod 0555, "$share";

    my $rex = OCP::Rex->new(host => 'cortex.example', key_file => '/dev/null');
    {
        no warnings 'redefine';
        local *OCP::Rex::_find_rexfile = sub { $share->child('Rexfile')->stringify };
        my $runtime = path($rex->_runtime_rexfile);

        isnt "$runtime", $share->child('Rexfile')->stringify,
            'the Rexfile handed to rex is not the one in share/';
        is $runtime->slurp, "# the shipped Rexfile\n",
            'but it is byte-for-byte what share/ ships';

        # What Rex actually needs: to create a file in that directory.
        my $lock = $runtime->parent->child('Rexfile.lock');
        ok eval { $lock->spew('12345'); 1 },
            'and its directory takes the lock file Rex insists on writing';

        is path($rex->_runtime_rexfile)->stringify, "$runtime",
            'the copy is made once and reused for every task';
    }

    chmod 0755, "$share";
};

subtest 'the smoke test runs the working tree it promises to run' => sub {
    my $smoke = path("$FindBin::Bin/../xt/smoke.sh");
    plan skip_all => 'xt/smoke.sh not found' unless -f $smoke;

    my $src = $smoke->slurp_utf8;

    like $src, qr/OCP_SHARE_DIR=\/src\/share/,
        'the container is told to use the mounted tree share/, not the image one';

    my ($header) = $src =~ /\A(.*?)^set -euo/ms;
    like $header, qr/share\//,
        'and the header comment no longer claims lib/ and bin/ are all of it';
};

done_testing;

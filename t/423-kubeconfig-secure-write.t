#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Cwd qw( getcwd );

use lib 'lib';

use OCP;
use OCP::Kubeconfig;
use OCP::Secrets;

#
# k423: `ocp kubeconfig -o FILE` and OCP::Kubeconfig->export (`ocp
# kubeconfig -e`) wrote the decrypted kubeconfig with Path::Tiny's spew and
# chmod'd it 0600 afterwards. spew stages the bytes in a temp file opened at
# the umask default and renames it into place, so the credentials stood on
# disk world-readable until the chmod. The export's backup of the user's
# previous kubeconfig (a File::Copy copy) was never chmod'd at all.
#
# What is pinned: each of these files is 0600 *at creation*. The test takes
# the after-the-fact chmod away (Path::Tiny::chmod made a no-op) and sets
# umask 0: a file created by spew is then 0666, one created 0600 stays 0600.
# Also pinned: the export follows a symlinked kubeconfig to its target, as
# spew did, instead of replacing the link with a file.
#

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};

local @ARGV = ();
my $ocp = OCP->new;

my $KUBE = "apiVersion: v1\nkind: Config\n"
    . "clusters:\n- name: default\n  cluster:\n    server: https://127.0.0.1:6443\n"
    . "contexts:\n- name: default\n  context:\n    cluster: default\n    user: default\n"
    . "users:\n- name: default\n  user:\n    token: secret-k423\n"
    . "current-context: default\n";

sub mode_of { sprintf '%04o', (stat $_[0])[2] & 07777 }

# Runs $code under umask 0 with every Path::Tiny chmod a no-op: the mode a
# file ends up with is the mode it was created with.
sub created_mode_only {
    my ($code) = @_;
    my $old = umask 0;
    my $ok = eval {
        no warnings 'redefine';
        local *Path::Tiny::chmod = sub { 1 };
        $code->();
        1;
    };
    my $err = $@;
    umask $old;
    die $err unless $ok;
    return;
}

subtest 'OCP::Kubeconfig->export creates the target 0600' => sub {
    my $target = path(tempdir(CLEANUP => 1))->child('config');
    created_mode_only(sub {
        OCP::Kubeconfig->export(kubeconfig => $KUBE, name => 'k423', target => "$target");
    });
    ok -f $target, 'target written';
    is mode_of($target), '0600', 'created 0600, not chmod-ed to it';
    like $target->slurp_utf8, qr/secret-k423/, 'and holds the credentials';
};

subtest 'OCP::Kubeconfig->export creates the backup 0600' => sub {
    my $target = path(tempdir(CLEANUP => 1))->child('config');
    $target->spew("apiVersion: v1\nkind: Config\nusers:\n- name: old\n  user:\n    token: old-k423\n");
    $target->chmod(0600);
    my $result;
    created_mode_only(sub {
        $result = OCP::Kubeconfig->export(kubeconfig => $KUBE, name => 'k423', target => "$target");
    });
    ok $result->{backup} && -f $result->{backup}, 'backup written';
    is mode_of($result->{backup}), '0600', 'backup created 0600';
    like path($result->{backup})->slurp_utf8, qr/old-k423/, 'backup holds the previous file';
    is mode_of($target), '0600', 'target created 0600';
};

subtest 'OCP::Kubeconfig->export writes through a symlinked target' => sub {
    my $dir  = path(tempdir(CLEANUP => 1));
    my $real = $dir->child('real-config');
    $real->spew("apiVersion: v1\nkind: Config\n");
    my $link = $dir->child('config');
    symlink "$real", "$link" or plan skip_all => 'no symlinks here';

    OCP::Kubeconfig->export(kubeconfig => $KUBE, name => 'k423', target => "$link");
    ok -l $link, 'the link is still a link';
    like $real->slurp_utf8, qr/secret-k423/, 'its target holds the merged kubeconfig';
    is mode_of($real), '0600', 'target 0600';
};

subtest 'ocp kubeconfig -o creates the file 0600' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->save_kubeconfig($KUBE);
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k423',
        control_planes => { provider => 'ssh', host => 'cp.k423.invalid' },
    });

    # bin/ocp in a child, with Path::Tiny::chmod a no-op and umask 0.
    my $pre = path(tempdir(CLEANUP => 1));
    $pre->child('K423NoChmod.pm')->spew(
        "package K423NoChmod;\nuse Path::Tiny ();\nno warnings 'redefine';\n"
        . "*Path::Tiny::chmod = sub { 1 };\n1;\n");
    my ($bin, $lib) = (path('bin/ocp')->absolute, path('lib')->absolute);
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my $old = umask 0;
    my $out = `$^X -I'$lib' -I'$pre' -MK423NoChmod '$bin' kubeconfig -o out/kc.yaml 2>&1 </dev/null`;
    my $rc  = $? >> 8;
    umask $old;
    chdir $cwd or die "chdir back: $!";

    is $rc, 0, 'ocp kubeconfig -o exits 0' or diag $out;
    my $file = $dir->child('out', 'kc.yaml');
    ok -f $file, 'file written';
    is mode_of($file), '0600', 'created 0600, not chmod-ed to it';
    like $file->slurp_utf8, qr/secret-k423/, 'and holds the credentials';
};

done_testing;

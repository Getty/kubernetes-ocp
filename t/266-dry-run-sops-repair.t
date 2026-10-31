#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Digest::MD5 ();
use File::Temp qw( tempdir );
use FindBin;
use Path::Tiny qw( path );

use lib 'lib';
use OCP;
use OCP::Keys;
use OCP::Secrets;

#
# k266, left over from k259: `ocp apply` re-quotes a SOPS file whose
# lastmodified is a bare timestamp (repair_sops_lastmodified), and
# `ocp apply --dry-run` skipped that without a word, while the rest of the
# dry run names what a real run would change. The claims:
#
#   1. OCP::Secrets->bare_sops_lastmodified_files names the project's SOPS
#      files that are still bare, in sops_file_names order, read off the text:
#      no key, no PIN, no decrypt, no write. It is the selection
#      repair_sops_lastmodified rewrites, so the two cannot disagree;
#   2. a dry run that holds the project key says, on STDOUT, that a real run
#      would repair each of them, after the banner and set off by a blank line
#      as the real run's [ok] lines are, and leaves the project directory byte
#      for byte as it was;
#   3. a project with nothing bare gets no such line;
#   4. a checkout with no key at hand gets none either: a real run repairs
#      only with the key it already holds and never asks PIN1 for it (t/153),
#      so it would repair nothing -- and the dry run says nothing it would not.
#
# t/259 pins the same line at the level of OCP::Cmd::Apply, both paths.
#

my $bin = "$FindBin::Bin/../bin/ocp";
my $lib = "$FindBin::Bin/../lib";

local @ARGV = ();
my $ocp = OCP->new;    # load/dump for the fixture

my $PIN1    = 'pin1-k266';
my $PIN2    = 'pin2-k266';
my $warn_qr = qr/time\.Time|PLAIN scalar/;

delete $ENV{SOPS_AGE_KEY_FILE};

# A secure-mode project as the machine that made it has it: the project key
# in .ocp/ and behind PIN1 in age.key.enc, an admin key (PIN2) and a robo key
# in keys.yaml, a token in secrets.yaml. No kubeconfig.yaml: no cluster yet,
# so a dry run takes the first apply's path (t/297).
sub origin {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8(<<'YAML');
name: k266
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: cp.k266.test
YAML
    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k266', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k266\n", public => 'ssh-ed25519 AAAAadmin k266', pin2 => $PIN2);
    $keys->add_key(name => 'robo-ssh-k266', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO PRIVATE k266\n", public => 'ssh-ed25519 AAAArobo k266');

    $s->create_secrets(hetzner_token => 'token-k266');
    return $dir;
}

# The named files as File::SOPS 0.002 left them: lastmodified unquoted. The
# parsed value is the same string either way, so the MAC still holds and the
# files still open -- what k259 found in projects at rest.
sub make_bare {
    my ($dir, @names) = @_;
    for my $name (@names) {
        my $file = $dir->child($name);
        my $raw  = $file->slurp_raw;
        $raw =~ s/^([ \t]+lastmodified:[ \t]+)"([^"\n]+)"[ \t]*$/$1$2/m
            or die "no quoted lastmodified in $name";
        $file->spew_raw($raw);
    }
    return $dir;
}

# A copy of $src: every committed file, and .ocp/ unless told otherwise.
sub copy_of {
    my ($src, %o) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    unless ($o{no_ocp_dir}) {
        $dst->child('.ocp')->mkpath;
        $_->copy($dst->child('.ocp', $_->basename)) for $src->child('.ocp')->children;
    }
    return $dst;
}

# Every path under $dir, directories too, with the digest of each file:
# what a write anywhere in the project changes (t/297).
sub listing {
    my ($dir) = @_;
    my %seen;
    $dir->visit(sub {
        my ($p) = @_;
        $seen{ $p->relative($dir)->stringify } = -d $p ? 'dir' : Digest::MD5::md5_hex($p->slurp_raw);
    }, { recurse => 1 });
    return \%seen;
}

# `ocp @args` in $dir as a user runs it, no terminal, HOME the project itself
# so that a write to HOME shows up in the listing: (stdout, stderr, exit).
# A leading { stdin => TEXT } is fed to it -- the PINs for --pins-stdin.
sub ocp_in {
    my ($dir, @args) = @_;
    my $stdin = ref $args[0] eq 'HASH' ? shift(@args)->{stdin} : undef;
    my $io  = path(tempdir(CLEANUP => 1));
    my ($in, $out, $err) = map { $io->child($_) } qw( in out err );
    $in->spew_utf8($stdin) if defined $stdin;
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        delete local $ENV{SOPS_AGE_KEY_FILE};
        open STDIN,  '<', defined $stdin ? "$in" : '/dev/null' or die;
        open STDOUT, '>', "$out"      or die;
        open STDERR, '>', "$err"      or die;
        exec $^X, "-I$lib", $bin, @args or die "exec: $!";
    }
    waitpid $pid, 0;
    return ($out->slurp_utf8, $err->slurp_utf8, $? >> 8);
}

# STDERR without File::SOPS's warnings about a bare timestamp it read.
sub without_bare_warnings {
    my ($err) = @_;
    return join '', grep { !/$warn_qr/ } split /^/, $err;
}

sub would_repair { "[..] A real run would repair $_[0]: its sops lastmodified is a bare timestamp, which sops -d refuses" }

my $ORIGIN = origin();

# --- 1. the read-only check ---------------------------------------------------

subtest 'bare_sops_lastmodified_files: the bare files by name, off the text alone' => sub {
    can_ok 'OCP::Secrets', 'bare_sops_lastmodified_files' or return;
    my $quoted = copy_of($ORIGIN);
    is_deeply [ OCP::Secrets->new(project_dir => $quoted)->bare_sops_lastmodified_files ], [],
        'a project OCP writes today: none';

    my $one = make_bare(copy_of($ORIGIN), 'secrets.yaml');
    is_deeply [ OCP::Secrets->new(project_dir => $one)->bare_sops_lastmodified_files ],
        [ 'secrets.yaml' ], 'one bare file: that one';

    # No key anywhere: no .ocp/, and a SOPS_AGE_KEY_FILE that names nothing --
    # identities would die on either. No PIN either.
    my $dir    = make_bare(copy_of($ORIGIN, no_ocp_dir => 1), 'keys.yaml', 'secrets.yaml');
    my $before = listing($dir);
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { die "asked for a PIN\n" };
    local $ENV{SOPS_AGE_KEY_FILE} = $dir->child('no-such-key.txt')->stringify;
    my @bare = eval { OCP::Secrets->new(project_dir => $dir)->bare_sops_lastmodified_files };
    is $@, '', 'no key and no PIN needed';
    is_deeply \@bare, [ 'keys.yaml', 'secrets.yaml' ],
        'both bare files, in sops_file_names order; the missing kubeconfig.yaml not among them';
    is_deeply listing($dir), $before, 'and the project directory as it was';
};

subtest 'bare_sops_lastmodified_files names what repair_sops_lastmodified rewrites' => sub {
    can_ok 'OCP::Secrets', 'bare_sops_lastmodified_files' or return;
    my $dir = make_bare(copy_of($ORIGIN), 'keys.yaml', 'secrets.yaml');
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    my @named = $s->bare_sops_lastmodified_files;

    my $out = '';
    my @repaired = do {
        open my $fh, '>', \$out or die;
        local *STDOUT = $fh;
        local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ $warn_qr };
        $s->repair_sops_lastmodified;
    };
    is_deeply \@repaired, \@named, 'the files the check named are the ones repaired';
    is_deeply [ $s->bare_sops_lastmodified_files ], [], 'after which none is bare';
};

# --- 2.-4. ocp apply --dry-run ------------------------------------------------

subtest 'a dry run that holds the key names each bare file, touching nothing' => sub {
    my $dir    = make_bare(copy_of($ORIGIN), 'keys.yaml', 'secrets.yaml');
    my $before = listing($dir);

    my ($out, $err, $rc) = ocp_in($dir, { stdin => "$PIN2\n" }, 'apply', '--dry-run', '--pins-stdin');

    is $rc, 0, 'exit 0' or diag $err;
    is_deeply listing($dir), $before, 'the project directory, .ocp/ included, byte for byte as it was'
        or diag explain listing($dir);
    is_deeply [ $out =~ /^\[\.\.\] A real run would repair (\S+):/mg ], [ 'keys.yaml', 'secrets.yaml' ],
        'STDOUT: one line per bare file, naming it';
    like $out, qr/^Cluster: k266\n\n\Q${\ would_repair('keys.yaml')}\E\n\Q${\ would_repair('secrets.yaml')}\E\n\n(?!\n)/m,
        'after the banner, set off by a blank line, as the real run\'s [ok] lines are';
    unlike $out, qr/Repaired/, 'and none repaired';
    like $out, qr/\[Dry run - no changes made\]\n\z/, 'the dry run goes on to its end';
    is without_bare_warnings($err), "Enter PIN2 (admin-key): \n",
        'STDERR: PIN2, and only File::SOPS\'s word about the bare timestamp it read';
};

subtest 'nothing bare: no line' => sub {
    my $dir    = copy_of($ORIGIN);
    my $before = listing($dir);

    my ($out, $err, $rc) = ocp_in($dir, { stdin => "$PIN2\n" }, 'apply', '--dry-run', '--pins-stdin');

    is $rc, 0, 'exit 0' or diag $err;
    is_deeply listing($dir), $before, 'the project directory as it was';
    unlike $out, qr/would repair/, 'no would-repair line';
    like $out, qr/^Cluster: k266\n\n(?!\n)/m, 'and no blank line of its own';
    is $err, "Enter PIN2 (admin-key): \n", 'STDERR: PIN2 alone';
};

subtest 'no key at hand: a real run would repair nothing, and the dry run names nothing' => sub {
    my $dir    = make_bare(copy_of($ORIGIN, no_ocp_dir => 1), 'keys.yaml', 'secrets.yaml');
    my $before = listing($dir);

    my ($out, $err, $rc) = ocp_in($dir, { stdin => "$PIN1\n$PIN2\n" }, 'apply', '--dry-run', '--pins-stdin');

    is $rc, 0, 'exit 0' or diag $err;
    is_deeply listing($dir), $before, 'the project directory as it was: no .ocp/'
        or diag explain listing($dir);
    unlike $out, qr/would repair/, 'no would-repair line';
    like $out, qr/\[Dry run - no changes made\]\n\z/, 'the dry run goes on to its end';
    is without_bare_warnings($err), "Enter PIN1 (cluster access): \nEnter PIN2 (admin-key): \n",
        'STDERR: PIN1 for the run itself, then PIN2';
};

done_testing;

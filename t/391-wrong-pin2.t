#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::ClusterKey;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

#
# k391: a wrong PIN2 is refused as a wrong PIN2, wherever it is asked for --
# never as "AES-GCM authentication failed", never as an internal error, never
# with a Perl location. OCP::Keys does not return undef for a PIN2 that does
# not open the admin key: the PIN2 layer's AES-GCM tag fails and it dies with
# that line. A caller that only checks for undef never reaches its own
# refusal.
#
# The fixture is real: an age key, and keys.yaml with an admin key
# double-encrypted under $PIN2 by OCP::Keys::add_key -- nothing stubbed, so a
# wrong PIN2 fails the way it fails for a user.
#
# The claims, one subtest each, named after the path they hold:
#
#   OCP::ClusterKey (the key every secure-mode command reaches the machines
#   with)
#     1. the fixture opens with $PIN2: the admin key, its private half;
#     2. a wrong PIN2 handed in (pin2 => ...) dies with exactly
#        "ERROR: Wrong PIN2 or no admin-key found!\n";
#     3. a wrong PIN2 at the prompt (--pins-stdin), the same -- and the
#        dispatcher shows it as that line, no internal error;
#     4. a failure that is not the PIN2's is not blamed on it: an .ocp/age.key
#        that does not open keys.yaml, with the right PIN2, dies with what
#        OCP::Keys dies with, unchanged;
#     5. from bin/ocp, `ocp ssh --pins-stdin` with a wrong PIN2: STDERR has
#        the refusal, no AES-GCM, no location, no internal error, exit 1.
#
# Helpers for the paths that join this file: secure_project, config_of,
# with_stdin, shown, run_ocp, refused_ok.
#

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};
delete local $ENV{HETZNER_API_TOKEN};

my $PIN2    = 'pin2-k391';
my $WRONG   = 'not-pin2-k391';
my $PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----\nADMIN PRIVATE k391\n-----END OPENSSH PRIVATE KEY-----\n";
my $PUBLIC  = 'ssh-ed25519 AAAAadminpublick391 admin@k391';
my $REFUSAL = "ERROR: Wrong PIN2 or no admin-key found!\n";

# The tree under test is the one in ./lib, not a copy elsewhere in @INC.
for my $mod (qw( OCP/ClusterKey.pm OCP/Keys.pm OCP/Password.pm OCP/Secrets.pm )) {
    is path($INC{$mod})->realpath->stringify, path("lib/$mod")->realpath->stringify,
        "$mod is loaded from ./lib";
}

# A secure-mode project as the machine that made it has it: the project key
# in .ocp/, keys.yaml holding the admin key under $PIN2, kubeconfig.yaml (so
# the cluster counts as deployed; none with kubeconfig => 0), an ocp.yaml for
# an ssh control plane at a host that never resolves.
sub secure_project {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));

    my $secrets = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $secrets->generate_age_key;

    OCP::Keys->new(project_dir => $dir, ocp => $ocp)->add_key(
        name    => 'admin-k391',
        type    => 'ssh_ed25519',
        purpose => 'admin',
        private => $PRIVATE,
        public  => $PUBLIC,
        pin2    => $PIN2,
    );

    $secrets->save_kubeconfig(join "\n",
        'apiVersion: v1', 'kind: Config', 'current-context: k391',
        'clusters:', '- name: k391', '  cluster:', '    server: https://127.0.0.1:1',
        'users:', '- name: k391', '  user:', '    token: t',
        'contexts:', '- name: k391', '  context:', '    cluster: k391', '    user: k391', '')
        unless defined $o{kubeconfig} && !$o{kubeconfig};

    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k391',
        control_planes => { provider => 'ssh', host => 'cp.k391.invalid' },
    });

    return $dir;
}

sub config_of {
    my ($dir) = @_;
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# Feed $input as STDIN in --pins-stdin mode, capture STDOUT and STDERR, run
# $code. Term::ReadKey is never reached: there is no terminal to wait on.
# STDOUT itself, not just the selected handle: OCP::ClusterKey prints to
# \*STDOUT by name when the PIN2 is handed in.
sub with_stdin {
    my ($input, $code) = @_;

    my ($out, $err) = ('', '');
    open my $in,  '<', \$input or die "stdin: $!";
    open my $ofh, '>', \$out   or die "stdout: $!";
    open my $efh, '>', \$err   or die "stderr: $!";

    no warnings 'redefine';
    local *OCP::Password::ReadMode = sub { die "the terminal was reached\n" };
    local *OCP::Password::ReadLine = sub { die "the terminal was reached\n" };
    local $OCP::Password::PINS_STDIN = 1;
    local *STDIN  = $in;
    local *STDOUT = $ofh;
    local *STDERR = $efh;
    my @r = eval { $code->() };
    my $died = $@;

    return { out => $out, err => $err, died => $died, result => \@r };
}

# What the dispatcher prints on STDERR for an exception that escapes a
# command (OCP::_report_error, without --verbose).
sub shown {
    my ($died) = @_;
    my $err = '';
    open my $efh, '>', \$err or die "stderr: $!";
    {
        local *STDERR = $efh;
        OCP::_report_error($died, 0);
    }
    return $err;
}

# bin/ocp from this tree, in $dir, with $stdin on STDIN and --pins-stdin.
my $bin = path('bin/ocp')->absolute;
my $lib = path('lib')->absolute;

sub run_ocp {
    my ($dir, $stdin, @argv) = @_;
    my ($in, $out, $err) = map { Path::Tiny->tempfile } 1 .. 3;
    $in->spew($stdin);
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        open STDIN,  '<', "$in"  or die;
        open STDOUT, '>', "$out" or die;
        open STDERR, '>', "$err" or die;
        alarm 120;
        exec $^X, "-I$lib", "$bin", @argv, '--pins-stdin' or die "exec: $!";
    }
    waitpid $pid, 0;
    return ($?, $out->slurp_utf8, $err->slurp_utf8);
}

# A refusal as the dispatcher prints it: on STDERR, after "Error:", with
# neither the internal-error line, nor a Perl location, nor crypto internals.
sub refused_ok {
    my ($what, $st, $out, $err, $re) = @_;
    isnt $st >> 8, 0, "$what: exit non-zero";
    like   $err, $re,                   "$what: the refusal on STDERR";
    unlike $err, qr/internal error/i,   "$what: not called an internal error";
    unlike $err, qr/ at \S+ line \d+/,  "$what: no Perl location";
    unlike $err, qr/AES-GCM/,           "$what: no crypto internals";
    unlike $out, qr/Error:|AES-GCM/,    "$what: none of it on STDOUT";
}

#
# OCP::ClusterKey
#

subtest 'OCP::ClusterKey: the fixture opens with its PIN2' => sub {
    my $dir = secure_project(kubeconfig => 0);
    my $r   = with_stdin('', sub { OCP::ClusterKey->for_config(config_of($dir), pin2 => $PIN2) });
    is $r->{died}, '', 'unlocked' or diag $r->{died};
    my ($key) = @{ $r->{result} };
    is $key && $key->origin, 'admin', 'the admin key';
    is $key && $key->content, $PRIVATE, 'with its private half';
    $key->cleanup if $key;
};

subtest 'OCP::ClusterKey: a wrong PIN2 handed in is refused as one' => sub {
    my $dir = secure_project(kubeconfig => 0);
    my $r   = with_stdin('', sub { OCP::ClusterKey->for_config(config_of($dir), pin2 => $WRONG) });
    is $r->{died}, $REFUSAL, 'the PIN2 refusal, exactly';
    unlike $r->{died}, qr/AES-GCM/,          'no crypto internals';
    unlike $r->{died}, qr/ line \d+\./,      'no Perl location';
    is_deeply $r->{result}, [], 'and no key';
};

subtest 'OCP::ClusterKey: a wrong PIN2 at the prompt is refused as one' => sub {
    my $dir = secure_project(kubeconfig => 0);
    my $r   = with_stdin("$WRONG\n",
        sub { OCP::ClusterKey->for_config(config_of($dir), reason => 'k391') });
    like $r->{err}, qr/Enter PIN2/, 'PIN2 was asked for';
    is $r->{died}, $REFUSAL, 'the PIN2 refusal, exactly';

    my $shown = shown($r->{died});
    is $shown, "Error: Wrong PIN2 or no admin-key found!\n",
        'the dispatcher shows that line and nothing else';
    unlike $shown, qr/internal error/i, 'not called an internal error';
};

subtest 'OCP::ClusterKey: a failure that is not the PIN2\'s is not blamed on it' => sub {
    my $dir   = secure_project(kubeconfig => 0);
    my $other = path(tempdir(CLEANUP => 1));
    OCP::Secrets->new(project_dir => $other, ocp => $ocp)->generate_age_key;
    $other->child('.ocp', 'age.key')->copy($dir->child('.ocp', 'age.key'));

    my $direct = eval { OCP::Keys->new(project_dir => $dir, ocp => $ocp)->get_admin_key($PIN2); 1 }
        ? '' : "$@";
    isnt $direct, '', 'with another project\'s age key, keys.yaml does not open';

    my $r = with_stdin('', sub { OCP::ClusterKey->for_config(config_of($dir), pin2 => $PIN2) });
    is $r->{died}, $direct, 'OCP::ClusterKey dies with what OCP::Keys died with, unchanged';
    unlike $r->{died}, qr/PIN2/, 'and does not blame the right PIN2';
};

subtest 'ocp ssh --pins-stdin: a wrong PIN2 is refused as one' => sub {
    my $dir = secure_project();
    my ($st, $out, $err) = run_ocp($dir, "$WRONG\n", 'ssh', '--node', 'cp-1');
    refused_ok('ocp ssh', $st, $out, $err, qr/^Error: Wrong PIN2 or no admin-key found!$/m);
    unlike $err, qr/\[ok\] admin key/, 'no key was taken';
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use FindBin;
use Path::Tiny qw( path );

use lib 'lib';
use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Drift;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

#
# k391, the apply side. Two leftovers of k375:
#   * `ocp apply` Step 2 (Admin authentication) called get_admin_key without
#     an eval. A wrong PIN2 died inside the decrypt, so the user read "Error:
#     AES-GCM authentication failed" -- crypto internals, not a PIN2 line --
#     and the "Wrong PIN2" refusal after it was never reached. An empty PIN2
#     died in get_admin_key's croak "PIN2 required for admin key at FILE line
#     N.", which the dispatcher labels an internal error.
#   * reconcile_components, when kubeconfig.yaml cannot be read, said "Cannot
#     decrypt kubeconfig.yaml ... Make sure .ocp/age.key exists." on STDOUT.
#     Since k370/k375 read_kubeconfig unlocks or refuses for the key itself,
#     so undef means one thing: there is no kubeconfig.yaml.
# The claims:
#   1. through bin/ocp, a wrong PIN2 at Step 2 is refused with a PIN2 line on
#      STDERR, exit non-zero: no "AES-GCM", no Perl location, no "internal
#      error"; nothing after Step 2 ran. The same for an empty PIN2, with its
#      own line. The right PIN2 gets past Step 2 (the fixture is sound);
#   2. a failure of get_admin_key that is not the PIN2 layer's keeps its own
#      words: it is not reported as a wrong PIN2;
#   3. reconcile_components on a project with no kubeconfig.yaml says
#      OCP::Secrets' refusal on STDERR, nothing of it on STDOUT, and stops
#      before the cluster API -- in a real run and in a dry run.
#
# Network-free: every run is `apply --dry-run` on an ssh control plane with
# a .test name, refused or stopped before anything leaves the process.
#

my $bin = "$FindBin::Bin/../bin/ocp";
my $lib = "$FindBin::Bin/../lib";

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{HETZNER_API_TOKEN};

my $PIN1 = 'pin1-k391';
my $PIN2 = 'pin2-k391';

my $OCP_YAML = <<'YAML';
name: k391
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: cp.k391.test
YAML

# A secure-mode project before its first apply: the project key in .ocp/ and
# behind PIN1 in age.key.enc, an admin key behind PIN2 and a robo key in
# keys.yaml, a token in secrets.yaml, no kubeconfig.yaml.
sub secure_origin {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8($OCP_YAML);
    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k391', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k391\n", public => 'ssh-ed25519 AAAAadmin k391', pin2 => $PIN2);
    $keys->add_key(name => 'robo-ssh-k391', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO PRIVATE k391\n", public => 'ssh-ed25519 AAAArobo k391');

    $s->create_secrets(hetzner_token => 'token-k391');
    return $dir;
}

# A dev-mode project with no kubeconfig.yaml: ocp.yaml and the key in .ocp/.
sub dev_no_kubeconfig {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8($OCP_YAML);
    OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->generate_age_key;
    return $dir;
}

# What a clone gets: every committed file, no .ocp/.
sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

# `ocp @args` in $dir as a user runs it, the PINs on STDIN: (out, err, exit).
sub ocp_in {
    my ($dir, $stdin, @args) = @_;
    my $io = path(tempdir(CLEANUP => 1));
    my ($in, $out, $err) = map { $io->child($_) } qw( in out err );
    $in->spew_utf8($stdin);
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        delete $ENV{KUBECONFIG};
        open STDIN,  '<', "$in"  or die;
        open STDOUT, '>', "$out" or die;
        open STDERR, '>', "$err" or die;
        alarm 120;
        exec $^X, "-I$lib", $bin, @args or die "exec: $!";
    }
    waitpid $pid, 0;
    return ($out->slurp_utf8, $err->slurp_utf8, $? >> 8);
}

# A refusal as the user meets it: exit non-zero, the line on STDERR after
# "Error:", no internal-error line, no Perl location, no crypto internals;
# STDOUT has the narrative up to Step 2 and nothing after it.
sub pin2_refused_ok {
    my ($what, $out, $err, $rc, $line) = @_;
    isnt $rc, 0, "$what: exit non-zero";
    like $err, qr/^Error: \Q$line\E$/m, "$what: the PIN2 line on STDERR" or diag $err;
    unlike $err, qr/AES-GCM/, "$what: no crypto internals";
    unlike $err, qr/ at \S+ line \d+/, "$what: no Perl location";
    unlike $err, qr/internal error/, "$what: not called an internal error";
    unlike $err, qr/PIN2 required for/, "$what: not get_admin_key's croak";
    like $out, qr/^Step 2: Admin authentication \(PIN2 required\)$/m, "$what: Step 2 was reached";
    unlike $out, qr/admin-key decrypted|Admin authenticated|Dry run/, "$what: nothing after it ran";
    unlike $out, qr/Error:|Wrong PIN2|No PIN2/, "$what: none of the refusal on STDOUT";
}

my $SECURE = secure_origin();

subtest 'the right PIN2 gets past Step 2 (the fixture is sound)' => sub {
    my ($out, $err, $rc) = ocp_in(clone_of($SECURE), "$PIN1\n$PIN2\n",
        'apply', '--dry-run', '--pins-stdin');
    is $rc, 0, 'exit 0' or diag $err;
    like $out, qr/^\[ok\] admin-key decrypted: admin-ssh-k391$/m, 'the admin key opened';
    like $out, qr/\[Dry run - no changes made\]\n\z/, 'to the dry run\'s end';
};

subtest 'a wrong PIN2 at Step 2: a PIN2 line, not AES-GCM' => sub {
    my ($out, $err, $rc) = ocp_in(clone_of($SECURE), "$PIN1\nnot-the-pin2\n",
        'apply', '--dry-run', '--pins-stdin');
    like $err, qr/Enter PIN1 .*\nEnter PIN2 \(admin-key\): \n/s, 'PIN1, then PIN2, asked';
    pin2_refused_ok('wrong PIN2', $out, $err, $rc, 'Wrong PIN2 or no admin-key found!');
};

subtest 'an empty PIN2 at Step 2: said as empty, not an internal error' => sub {
    my ($out, $err, $rc) = ocp_in(clone_of($SECURE), "$PIN1\n\n",
        'apply', '--dry-run', '--pins-stdin');
    pin2_refused_ok('empty PIN2', $out, $err, $rc,
        'No PIN2 given, cannot decrypt the admin key.');
};

subtest 'a failure that is not the PIN2 layer\'s keeps its own words' => sub {
    my $dir   = clone_of($SECURE);
    my $root  = OCP->new(config => $dir->child('ocp.yaml')->stringify);
    my $apply = OCP::Cmd::Apply->new(command_chain => [ $root ], dry_run => 1);
    my ($out, $err) = ('', '');
    my $died;
    {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub { $_[0] =~ /PIN1/ ? $PIN1 : $PIN2 };
        local *OCP::Keys::get_admin_key = sub { die "ERROR: keys.yaml cannot be read here\n" };
        open my $ofh, '>', \$out or die;
        open my $efh, '>', \$err or die;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $died = eval { $apply->execute([], []); 1 } ? '' : "$@";
    }
    is $died, "ERROR: keys.yaml cannot be read here\n", 'the error as it was raised';
    unlike $out, qr/admin-key decrypted/, 'and nothing past Step 2';
};

for my $dry (0, 1) {
    my $run = $dry ? 'a dry run' : 'a real run';
    subtest "reconcile_components, no kubeconfig.yaml, $run: the refusal on STDERR" => sub {
        my $dir = dev_no_kubeconfig();
        ok !-e $dir->child('kubeconfig.yaml'), 'precondition: no kubeconfig.yaml';
        my $root   = OCP->new(config => $dir->child('ocp.yaml')->stringify);
        my $apply  = OCP::Cmd::Apply->new(command_chain => [ $root ], dry_run => $dry);
        my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);

        my ($out, $err, $rv) = ('', '');
        my $api_calls = 0;
        {
            no warnings 'redefine';
            local *OCP::Password::prompt_password = sub { die "no PIN may be asked\n" };
            local *OCP::Cmd::Apply::_k8s_api = sub { $api_calls++; return };
            open my $ofh, '>', \$out or die;
            open my $efh, '>', \$err or die;
            local *STDOUT = $ofh;
            local *STDERR = $efh;
            $rv = eval { OCP::Cmd::Apply::Drift::reconcile_components($apply, $config) };
            is $@, '', 'did not die';
        }
        ok !$rv, 'nothing reconciled: a false return, the dispatcher passes no verdict';
        is $err, OCP::Secrets->no_kubeconfig_refusal, "STDERR: OCP::Secrets' refusal";
        unlike $out, qr/kubeconfig|age\.key|Cannot decrypt|skipping/,
            'none of it on STDOUT';
        is $out, '', 'STDOUT has nothing at all';
        is $api_calls, 0, 'stopped before the cluster API';
    };
}

done_testing;

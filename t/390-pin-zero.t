#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Cwd qw( getcwd );

use lib 'lib';

use Crypt::Age;
use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Init;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

#
# k390: a PIN of "0" is a PIN. OCP::Password::prompt_new_pin accepted it --
# it checks defined && length -- but the code it was handed to asked Perl
# whether it was true, and "0" is not:
#
#   * PIN2 "0": OCP::Keys::add_key double-encrypted only `if ($pin2)`, so the
#     admin key fell through to the age layer alone, stored like the robo key,
#     while `ocp init` said "age+PIN2 encrypted". Reading it back then
#     croaked "PIN2 required" for the very PIN2 that had been set.
#   * PIN1 "0": OCP::Password::encrypt_age_key croaked "password required",
#     so `ocp init` ended in an internal error; and a PIN1 handed to
#     OCP::Secrets::ensure_age_key was asked for again.
#
# The claims:
#
#   PIN1 "0"
#     1. secure-mode `ocp init --pins-stdin` with PIN1 "0" completes, and its
#        age.key.enc opens with "0" -- and with no other PIN1;
#     2. a clone unlocks the project key with it: asked for on STDIN, and
#        handed to ensure_age_key, where it is used without asking again;
#     3. a wrong PIN1 against it is refused as any wrong PIN1 is.
#
#   PIN2 "0"
#     4. the admin key stored under it is double-encrypted -- its age layer,
#        opened with the project key alone, is the PIN2 layer and not the
#        private key, where the robo key's age layer is the private key. Both
#        through `ocp init` and through OCP::Keys::add_key directly;
#     5. it opens with PIN2 "0": decrypt_key, get_admin_key, and
#        OCP::ClusterKey, the path every secure-mode command reaches the
#        machines with;
#     6. a wrong PIN2 fails for it exactly as for an admin key under any
#        other PIN2.
#
# Each PIN has its own project (the other PIN an ordinary one), so a broken
# PIN1 path cannot hide whether the PIN2 path works, and the other way round.
#

plan skip_all => 'needs ssh-keygen'
    unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{HETZNER_API_TOKEN};

my $PIN1 = 'pin1-k390';
my $PIN2 = 'pin2-k390';

# The tree under test is the one in ./lib, not a copy elsewhere in @INC.
for my $mod (qw( OCP/Keys.pm OCP/Password.pm OCP/Secrets.pm )) {
    is path($INC{$mod})->realpath->stringify, path("lib/$mod")->realpath->stringify,
        "$mod is loaded from ./lib";
}

# Feed $input as STDIN in --pins-stdin mode, capture STDOUT and STDERR, run
# $code. Term::ReadKey is never reached: there is no terminal to wait on.
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
    local *STDERR = $efh;
    my $old = select $ofh;
    my @r = eval { $code->() };
    my $died = $@;
    select $old;

    return { out => $out, err => $err, died => $died, result => \@r };
}

# Secure-mode `ocp init` in a fresh dir, its four PIN prompts answered from
# STDIN: PIN1 and its confirmation, PIN2 and its confirmation.
sub init_project {
    my ($pin1, $pin2) = @_;

    my $dir  = tempdir(CLEANUP => 1);
    my $init = OCP::Cmd::Init->new(
        command_chain => [$ocp],
        nogit         => 1,
        name          => 'pinzero',
        provider      => 'ssh',
        host          => '10.0.0.1',
        pins_stdin    => 1,
    );

    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my $r = with_stdin("$pin1\n$pin1\n$pin2\n$pin2\n", sub { $init->execute([], []) });
    chdir $cwd or die "chdir back: $!";

    return (path($dir), $r);
}

# What a clone gets: every committed file, no .ocp/.
sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

# The private half of a keys.yaml entry with the age layer -- the project
# key's -- taken off, and nothing else: the private key itself for a key
# stored age-only, the base64 PIN2 layer for a double-encrypted one.
sub age_layer_of {
    my ($dir, $entry) = @_;
    return Crypt::Age->decrypt(
        ciphertext => $entry->{private},
        identities => [ OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->identities ],
    );
}

sub entry {
    my ($dir, $purpose) = @_;
    my ($e) = grep { ($_->{purpose} // '') eq $purpose }
        @{ OCP::Keys->new(project_dir => $dir, ocp => $ocp)->list_keys };
    return $e;
}

# The stored shape, both ways round.
sub pin2_layered_ok {
    my ($layer, $what) = @_;
    ok defined $layer, "$what: the age layer opens with the project key";
    unlike $layer // '', qr/PRIVATE KEY/,
        "$what: under it is no private key -- there is another layer";
    like $layer // '', qr{\A[A-Za-z0-9+/]+=*\z},
        "$what: it is the PIN2 layer (base64)";
}

sub age_only_ok {
    my ($layer, $what) = @_;
    like $layer // '', qr/PRIVATE KEY/,
        "$what: under the age layer is the private key itself";
}

#
# PIN1 "0"
#

my ($p1, $p1_init) = init_project('0', $PIN2);

subtest 'ocp init sets PIN1 "0"' => sub {
    is $p1_init->{died}, '', 'init completed'
        or diag $p1_init->{died}, $p1_init->{err};
    like $p1_init->{err}, qr/Enter PIN1.*Confirm PIN1.*Enter PIN2.*Confirm PIN2/s,
        'all four prompts were answered from STDIN';

    my $enc = $p1->child('age.key.enc');
    ok -f $enc, 'age.key.enc written';

    my $key = eval { OCP::Password::decrypt_age_key($enc->slurp, '0') };
    is $key, $p1->child('.ocp', 'age.key')->slurp, 'it opens with PIN1 "0" to the project key'
        or diag $@;

    for my $wrong ('00', '1', ' 0') {
        ok !eval { OCP::Password::decrypt_age_key($enc->slurp, $wrong); 1 },
            "and not with '$wrong'";
    }
};

subtest 'a clone unlocks with PIN1 "0" asked for on STDIN' => sub {
    my $clone = clone_of($p1);
    my $r = with_stdin("0\n", sub {
        OCP::Secrets->new(project_dir => $clone, ocp => $ocp)->ensure_age_key;
    });

    is $r->{died}, '', 'unlocked' or diag $r->{died};
    like $r->{err}, qr/Enter PIN1/, 'PIN1 was asked for';
    my $cached = $clone->child('.ocp', 'age.key');
    is(-f $cached ? $cached->slurp : undef, $p1->child('.ocp', 'age.key')->slurp,
        'the project key is cached in .ocp/age.key');
};

subtest 'PIN1 "0" handed to ensure_age_key is used, not asked for again' => sub {
    my $clone = clone_of($p1);
    my @asked;
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { push @asked, $_[0]; 'not-the-pin' };

    my $ok = eval { OCP::Secrets->new(project_dir => $clone, ocp => $ocp)->ensure_age_key('0'); 1 };
    ok $ok, 'unlocked' or diag $@;
    is_deeply \@asked, [], 'without a prompt';
    my $cached = $clone->child('.ocp', 'age.key');
    is(-f $cached ? $cached->slurp : undef, $p1->child('.ocp', 'age.key')->slurp,
        'the project key is cached in .ocp/age.key');
};

subtest 'a wrong PIN1 against PIN1 "0" is refused like any wrong PIN1' => sub {
    my $clone = clone_of($p1);
    my $r = with_stdin("00\n", sub {
        OCP::Secrets->new(project_dir => $clone, ocp => $ocp)->ensure_age_key;
    });
    like $r->{died}, qr/\APIN1 does not open age\.key\.enc\./, 'the wrong-PIN1 refusal';
    ok !-e $clone->child('.ocp', 'age.key'), 'nothing cached';
};

#
# PIN2 "0"
#

my ($p2, $p2_init) = init_project($PIN1, '0');

subtest 'ocp init stores the admin key under PIN2 "0", double-encrypted' => sub {
    is $p2_init->{died}, '', 'init completed'
        or diag $p2_init->{died}, $p2_init->{err};

    my $admin = entry($p2, 'admin');
    my $robo  = entry($p2, 'automation');
    ok $admin && $robo, 'keys.yaml holds an admin and a robo key' or return;

    pin2_layered_ok(age_layer_of($p2, $admin), 'admin key');
    age_only_ok(age_layer_of($p2, $robo), 'robo key (control)');
};

subtest 'the admin key opens with PIN2 "0"' => sub {
    my $admin = entry($p2, 'admin') or return fail 'no admin key';
    my $keys  = OCP::Keys->new(project_dir => $p2, ocp => $ocp);

    my $by_name = eval { $keys->decrypt_key($admin->{name}, '0') };
    my $private = $by_name ? $by_name->{private} : undef;
    like $private // '', qr/BEGIN OPENSSH PRIVATE KEY/,
        'decrypt_key: the private key' or diag $@;

    my $first = eval { $keys->get_admin_key('0') };
    is $first && $first->{name}, $admin->{name}, 'get_admin_key: the admin key' or diag $@;
    ok $first && defined $private && $first->{private} eq $private,
        'with the same private half';

    my $config = OCP::Config->new(file => $p2->child('ocp.yaml')->stringify);
    my $r = with_stdin("0\n", sub { OCP::ClusterKey->for_config($config, reason => 'k390') });
    is $r->{died}, '', 'OCP::ClusterKey: unlocked' or diag $r->{died};
    my ($ck) = @{ $r->{result} };
    is $ck && $ck->origin, 'admin', 'the key the machines trust is the admin key';
    like $r->{err}, qr/Enter PIN2/, 'PIN2 was asked for';
    ok $ck && defined $private && $ck->content eq $private, 'with its private half';
    $ck->cleanup if $ck;
};

# The reference: the same project shape under an ordinary PIN2.
my ($ref) = init_project($PIN1, $PIN2);

subtest 'a wrong PIN2 fails for PIN2 "0" as for any other PIN2' => sub {
    my $zero  = OCP::Keys->new(project_dir => $p2,  ocp => $ocp);
    my $other = OCP::Keys->new(project_dir => $ref, ocp => $ocp);

    ok $other->get_admin_key($PIN2), 'the reference admin key opens with its own PIN2';

    for my $wrong ('00', '1', ' 0', 'false') {
        my $want = eval { $other->get_admin_key($wrong); 1 } ? 'opened' : "$@";
        my $got  = eval { $zero->get_admin_key($wrong);  1 } ? 'opened' : "$@";
        isnt $got, 'opened', "'$wrong' does not open the PIN2 \"0\" key";
        is $got, $want, "and fails the way it fails for the reference";
    }

    for my $none (undef, '') {
        my $label = defined $none ? "''" : 'undef';
        ok !eval { $zero->get_admin_key($none); 1 }, "no PIN2 ($label) does not open it either";
    }
};

subtest 'OCP::Keys::add_key with pin2 "0" double-encrypts' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->generate_age_key;
    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);

    my $private = "-----BEGIN OPENSSH PRIVATE KEY-----\nADMIN k390\n-----END OPENSSH PRIVATE KEY-----\n";
    ok eval {
        $keys->add_key(name => 'admin-k390', type => 'ssh_ed25519', purpose => 'admin',
            private => $private, public => 'ssh-ed25519 AAAAadmin k390', pin2 => '0');
        1;
    }, 'added' or diag $@;

    pin2_layered_ok(age_layer_of($dir, $keys->get_key('admin-k390') // {}), 'admin key');

    my $got = eval { $keys->decrypt_key('admin-k390', '0') };
    is $got && $got->{private}, $private, 'and decrypt_key with PIN2 "0" gives it back' or diag $@;
    ok !eval { $keys->decrypt_key('admin-k390', '1'); 1 }, 'a wrong PIN2 does not';
};

done_testing;

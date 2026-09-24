#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use MIME::Base64 qw( encode_base64 );
use Digest::SHA qw( hmac_sha1 );
use Path::Tiny qw( path );

use OCP;
use OCP::KnownHosts;
use OCP::SSH;
use OCP::Rex;
use OCP::Provider::Hetzner;

#
# k168: host keys are trusted on first use and verified afterwards.
#
# Rex::LibSSH 0.004 / Net::LibSSH 0.004 verify the server host key against
# known_hosts and refuse an unknown one. OCP::SSH ran with
# StrictHostKeyChecking=no and UserKnownHostsFile=/dev/null, so nothing ever
# recorded a key, and in a --rm container there is no ~/.ssh/known_hosts
# either: every fresh machine passed the OCP::SSH readiness probe and then
# failed the Rex install with "host key is not in known_hosts".
#
# The model: one known_hosts file per project (.ocp/known_hosts, exported as
# OCP_KNOWN_HOSTS), written by OpenSSH's accept-new on first contact through
# OCP::SSH, read by Rex::LibSSH through the Rexfile. A changed key dies loudly
# with the command that removes the stale entry.
#
# Network-free: ssh and rex are never executed. OpenSSH's accept-new is played
# by the capture_command double, which appends the key the way ssh would.
#

delete local $ENV{OCP_REX_DEBUG};

my $tmp = path(tempdir(CLEANUP => 1));

# A syntactically valid ed25519 public key blob (fixed bytes, not a real key).
my $KEY_B64 = encode_base64(
    pack('N', 11) . 'ssh-ed25519' . pack('N', 32) . ('k' x 32), '');

sub fresh_file {
    my ($name) = @_;
    my $f = $tmp->child($name // 'kh-' . int(rand 1e9), 'known_hosts');
    return $f;
}

#
# OCP::KnownHosts
#

subtest 'where the file is' => sub {
    local $ENV{OCP_KNOWN_HOSTS} = '/some/where/known_hosts';
    is(OCP::KnownHosts->default_file, '/some/where/known_hosts',
        'OCP_KNOWN_HOSTS wins');

    delete local $ENV{OCP_KNOWN_HOSTS};
    local $ENV{TMPDIR} = '/tmpx';
    is(OCP::KnownHosts->default_file, '/tmpx/ocp-known_hosts-' . $<,
        'without it: a per-uid file in TMPDIR (robocop: the pod /tmp emptyDir)');

    is(OCP::KnownHosts->project_file($tmp->child('proj')),
        $tmp->child('proj', '.ocp', 'known_hosts')->stringify,
        'the project file is .ocp/known_hosts, absolute');
};

subtest 'reads plain, hashed and non-22 entries' => sub {
    my $file = fresh_file();
    $file->parent->mkpath;
    my $salt = 'saltsaltsaltsaltsalt';
    my $hashed = '|1|' . encode_base64($salt, '') . '|'
        . encode_base64(hmac_sha1('hashed.example', $salt), '');
    $file->spew(
        "# comment\n",
        "\n",
        "other.example,10.0.0.5 ssh-ed25519 $KEY_B64\n",
        "[10.0.0.6]:2222 ssh-ed25519 $KEY_B64\n",
        "$hashed ssh-ed25519 $KEY_B64\n",
        "\@cert-authority *.example ssh-ed25519 $KEY_B64\n",
    );
    my $kh = OCP::KnownHosts->new(file => $file);

    ok($kh->knows('10.0.0.5'),            'host in a comma list');
    ok($kh->knows('other.example'),       'first name of the list');
    ok(!$kh->knows('10.0.0.6'),           '[host]:port is not port 22');
    ok($kh->knows('10.0.0.6', 2222),      'but matches port 2222');
    ok($kh->knows('hashed.example'),      'hashed entry');
    ok(!$kh->knows('unknown.example'),    'unknown host');
    ok(!$kh->knows('x.example'),          '@cert-authority is not a host key');
    ok(!OCP::KnownHosts->new(file => fresh_file())->knows('10.0.0.5'),
        'a missing file knows nothing');
};

subtest 'fingerprint matches ssh-keygen -l' => sub {
    my $keygen = grep { -x "$_/ssh-keygen" } split /:/, ($ENV{PATH} // '');
    plan skip_all => 'ssh-keygen not installed' unless $keygen;

    my $dir = path(tempdir(CLEANUP => 1));
    my $priv = $dir->child('k');
    system('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', "$priv") == 0
        or plan skip_all => 'ssh-keygen failed';
    my (undef, $b64) = split ' ', path("$priv.pub")->slurp;
    my ($want) = `ssh-keygen -l -f $priv.pub` =~ /(SHA256:\S+)/;

    is(OCP::KnownHosts->new(file => '/dev/null')->fingerprint($b64), $want,
        'same SHA256 fingerprint as OpenSSH');
};

subtest 'forget removes only the host' => sub {
    my $file = fresh_file();
    $file->parent->mkpath;
    $file->spew(
        "10.0.0.5 ssh-ed25519 $KEY_B64\n",
        "10.0.0.7 ssh-ed25519 $KEY_B64\n",
        "10.0.0.5 ecdsa-sha2-nistp256 $KEY_B64\n",
    );
    my $kh = OCP::KnownHosts->new(file => $file);
    is($kh->forget('10.0.0.5'), 2, 'both entries of the host removed');
    ok(!$kh->knows('10.0.0.5'), 'host gone');
    ok($kh->knows('10.0.0.7'), 'other host kept');
    is($kh->forget('10.0.0.5'), 0, 'forgetting twice is a no-op');
    like($kh->remove_hint('10.0.0.5'), qr/^ssh-keygen -R '10\.0\.0\.5' -f '\Q$file\E'$/,
        'the manual removal command names host and file');
};

#
# OCP::SSH
#

# Plays OpenSSH: records the host key into UserKnownHostsFile on success
# (accept-new), or answers like ssh does for a changed key.
my @ssh_calls;
my $ssh_mode = 'accept';
{
    no warnings 'redefine';
    *OCP::SSH::capture_command = sub {
        my ($cmd) = @_;
        push @ssh_calls, [@$cmd];
        my ($kh) = map { /^UserKnownHostsFile=(.*)$/ ? $1 : () } @$cmd;
        my ($target) = grep { /\@/ } @$cmd;
        (my $host = $target) =~ s/.*\@//;
        if ($ssh_mode eq 'changed') {
            return { exit => 255, stdout => '', stderr =>
                "\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\@\n"
              . "\@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     \@\n"
              . "Host key verification failed.\n" };
        }
        if ($ssh_mode eq 'down') {
            return { exit => 255, stdout => '', stderr => "ssh: connect to host $host port 22: Connection refused\n" };
        }
        my $f = path($kh);
        die "known_hosts directory was not created before ssh ran\n"
            unless -d $f->parent;
        $f->append("$host ssh-ed25519 $KEY_B64\n")
            unless OCP::KnownHosts->new(file => $f)->knows($host);
        return { exit => 0, stdout => '', stderr => '' };
    };
}

sub capture_stderr (&) {
    my ($code) = @_;
    my $err = '';
    open my $fh, '>', \$err or die;
    local *STDERR = $fh;
    $code->();
    return $err;
}

subtest 'OCP::SSH records on first contact instead of ignoring host keys' => sub {
    my $file = fresh_file();
    my $ssh = OCP::SSH->new(host => '10.1.0.1', known_hosts => "$file");
    my $opts = join ' ', $ssh->_ssh_opts;

    like($opts, qr/StrictHostKeyChecking=accept-new/, 'accept-new: TOFU');
    like($opts, qr/UserKnownHostsFile=\Q$file\E(?:\s|$)/, 'the OCP file');
    like($opts, qr/GlobalKnownHostsFile=\/dev\/null/, 'no system file');
    like($opts, qr/HashKnownHosts=no/, 'plain entries');
    unlike($opts, qr/StrictHostKeyChecking=no/, 'host key checking is no longer off');
    unlike($opts, qr/UserKnownHostsFile=\/dev\/null/, 'keys are no longer thrown away');

    my @scp = $ssh->_build_scp_cmd;
    ok((grep { $_ eq "UserKnownHostsFile=$file" } @scp), 'scp uses the same file');
};

subtest 'first contact records the key and logs its fingerprint once' => sub {
    $ssh_mode = 'accept';
    my $file = fresh_file();
    ok(!-d $file->parent, 'directory does not exist yet');
    my $ssh = OCP::SSH->new(host => '10.1.0.2', known_hosts => "$file");

    my $err = capture_stderr { ok($ssh->is_reachable, 'reachable') };
    ok(OCP::KnownHosts->new(file => $file)->knows('10.1.0.2'), 'key recorded');
    my $fp = OCP::KnownHosts->new(file => '/dev/null')->fingerprint($KEY_B64);
    like($err, qr/10\.1\.0\.2/, 'log names the host');
    like($err, qr/\Q$fp\E/, 'log carries the fingerprint');
    like($err, qr/\Q$file\E/, 'log names the file');

    my $again = capture_stderr { $ssh->run('true') };
    is($again, '', 'no second log for the same object');

    my $later = capture_stderr {
        OCP::SSH->new(host => '10.1.0.2', known_hosts => "$file")->run('true')
    };
    is($later, '', 'a known host is not announced again');
};

subtest 'a changed host key dies loudly with the removal command' => sub {
    $ssh_mode = 'changed';
    my $file = fresh_file();
    $file->parent->mkpath;
    $file->spew("10.1.0.3 ssh-ed25519 $KEY_B64\n");
    my $ssh = OCP::SSH->new(host => '10.1.0.3', known_hosts => "$file");

    my $ok = eval { $ssh->run('true'); 1 };
    my $err = $@;
    ok(!$ok, 'run dies');
    like($err, qr/host key/i, 'says host key');
    like($err, qr/10\.1\.0\.3/, 'names the host');
    like($err, qr/ssh-keygen -R '10\.1\.0\.3' -f '\Q$file\E'/, 'tells how to remove the entry');

    local $OCP::SSH::WAIT_TIMEOUT = 30;
    my $t0 = time;
    ok(!eval { $ssh->wait_for_ssh(30, 1); 1 }, 'wait_for_ssh dies too');
    like($@, qr/ssh-keygen -R/, 'with the same message');
    cmp_ok(time - $t0, '<', 5, 'immediately, not after the boot budget');
    $ssh_mode = 'accept';
};

subtest 'learn_host_key' => sub {
    my $file = fresh_file();
    $ssh_mode = 'accept';
    my $ssh = OCP::SSH->new(host => '10.1.0.4', known_hosts => "$file");
    capture_stderr { ok($ssh->learn_host_key, 'learns on success') };
    ok(OCP::KnownHosts->new(file => $file)->knows('10.1.0.4'), 'recorded');

    $ssh_mode = 'down';
    my $down = OCP::SSH->new(host => '10.1.0.5', known_hosts => "$file");
    ok(!eval { $down->learn_host_key; 1 }, 'dies when the host cannot be reached');
    like($@, qr/10\.1\.0\.5.*Connection refused/s, 'with ssh\'s reason');
    $ssh_mode = 'accept';
};

subtest 'OCP_KNOWN_HOSTS is the default for OCP::SSH' => sub {
    local $ENV{OCP_KNOWN_HOSTS} = '/env/known_hosts';
    is(OCP::SSH->new(host => 'x')->known_hosts, '/env/known_hosts', 'from env');
};

#
# OCP::Rex
#

my $key = $tmp->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub');
my $rexfile = $tmp->child('Rexfile');
$rexfile->spew("# stub\n");

our ($rex_ok, $rex_err);
my @rex_calls;
{
    no warnings 'redefine';
    *OCP::Rex::_find_rexfile = sub { $rexfile->stringify };
    *OCP::Rex::run = sub {
        my ($cmd, $in, $out, $err) = @_;
        push @rex_calls, { cmd => [@$cmd], known_hosts => $ENV{OCP_KNOWN_HOSTS},
                           ssh_before => scalar @ssh_calls };
        $$out = '';
        $$err = $rex_err // '';
        return $rex_ok // 1;
    };
}

sub rex_run {
    my ($host, $file) = @_;
    my $out = '';
    open my $ofh, '>', \$out or die;
    local *STDOUT = $ofh;
    my $err = capture_stderr {
        OCP::Rex->new(host => $host, key_file => "$key", known_hosts => "$file")
            ->run_task('upgrade_cilium');
    };
    return $err;
}

subtest 'Rex: an unknown host is learned over SSH before rex connects' => sub {
    @ssh_calls = (); @rex_calls = ();
    my $file = fresh_file();
    delete local $ENV{OCP_KNOWN_HOSTS};

    rex_run('10.2.0.1', $file);
    is(scalar @ssh_calls, 1, 'one SSH contact');
    is($rex_calls[0]{ssh_before}, 1, 'and it happened before rex ran');
    ok(OCP::KnownHosts->new(file => $file)->knows('10.2.0.1'), 'key recorded');
    is($rex_calls[0]{known_hosts}, "$file", 'rex child sees the file as OCP_KNOWN_HOSTS');
    ok(!defined $ENV{OCP_KNOWN_HOSTS}, 'and the parent env is restored');
};

subtest 'Rex: a known host goes straight to rex (libssh verifies)' => sub {
    @ssh_calls = (); @rex_calls = ();
    my $file = fresh_file();
    $file->parent->mkpath;
    $file->spew("10.2.0.2 ssh-ed25519 $KEY_B64\n");

    rex_run('10.2.0.2', $file);
    is(scalar @ssh_calls, 0, 'no extra SSH contact');
    is(scalar @rex_calls, 1, 'rex ran');
};

subtest 'Rex: libssh refusing a changed key names the fix' => sub {
    my $file = fresh_file();
    $file->parent->mkpath;
    $file->spew("10.2.0.3 ssh-ed25519 $KEY_B64\n");
    local $rex_ok  = 0;
    local $rex_err = "[warn] LibSSH: can't connect to 10.2.0.3: host key has changed "
                   . "from the known_hosts entry -- possible man-in-the-middle attack\n";

    ok(!eval { rex_run('10.2.0.3', $file); 1 }, 'run_task dies');
    like($@, qr/ssh-keygen -R '10\.2\.0\.3' -f '\Q$file\E'/, 'with the removal command');
};

subtest 'Rex: the helper SSH calls use the same file' => sub {
    my $file = fresh_file();
    my %seen;
    no warnings 'redefine';
    local *OCP::SSH::run = sub { $seen{ $_[0]->known_hosts }++; { exit => 1, stdout => '', stderr => '' } };
    OCP::Rex->new(host => '10.2.0.4', key_file => "$key", known_hosts => "$file")
        ->_existing_server_token('rke2');
    ok($seen{"$file"}, 'token probe verifies against the Rex file');
};

subtest 'the Rexfile verifies against OCP_KNOWN_HOSTS' => sub {
    my $src = path('share/Rexfile')->slurp_utf8;
    like($src, qr/set_openssh_opt\s*\(\s*StrictHostKeyChecking\s*=>\s*'yes'/,
        'strict host key checking stays on');
    like($src, qr/UserKnownHostsFile\s*=>\s*\$ENV\{OCP_KNOWN_HOSTS\}/,
        'against the file OCP::Rex exports');
    unlike($src, qr/disable_strict_host_key_checking|strict_hostkeycheck\s*=>\s*0/,
        'no blanket opt-out');
};

#
# The CLI exports the project file for the whole run
#

subtest 'ocp exports .ocp/known_hosts of the project for the run' => sub {
    my $proj = $tmp->child('proj');
    $proj->mkpath;
    my $seen;
    no warnings 'redefine';
    local *OCP::execute = sub { $seen = $ENV{OCP_KNOWN_HOSTS}; return };

    {
        delete local $ENV{OCP_KNOWN_HOSTS};
        local @ARGV = ('-c', $proj->child('ocp.yaml')->stringify);
        OCP->run_cli;
        is($seen, $proj->child('.ocp', 'known_hosts')->stringify,
            'next to the ocp.yaml the run uses');
        ok(!defined $ENV{OCP_KNOWN_HOSTS}, 'not leaked past the run');
    }
    {
        local $ENV{OCP_KNOWN_HOSTS} = '/explicit/kh';
        local @ARGV = ('-c', $proj->child('ocp.yaml')->stringify);
        OCP->run_cli;
        is($seen, '/explicit/kh', 'an explicit OCP_KNOWN_HOSTS wins');
    }
};

#
# Hetzner: an address Hetzner hands out may have carried another machine
#

{
    package FakeServers;
    sub new { bless { ip => $_[1] }, $_[0] }
    sub wait_for_status { FakeServer->new($_[0]{ip}) }
    sub delete { $_[0]{deleted} = $_[1] }
    package FakeServer;
    sub new { bless { ip => $_[1] }, $_[0] }
    sub ipv4 { $_[0]{ip} }
    package FakeCloud;
    sub new { bless { servers => FakeServers->new($_[1]) }, $_[0] }
    sub servers { $_[0]{servers} }
}

subtest 'Hetzner: a new server\'s address starts without a recorded key' => sub {
    my $file = fresh_file();
    $file->parent->mkpath;
    $file->spew("10.3.0.1 ssh-ed25519 $KEY_B64\n10.3.0.9 ssh-ed25519 $KEY_B64\n");
    local $ENV{OCP_KNOWN_HOSTS} = "$file";

    my $hz = OCP::Provider::Hetzner->new(token => 'x', cloud => FakeCloud->new('10.3.0.1'));
    my $info = $hz->wait_for_running({ id => 42 });
    is($info->{ip}, '10.3.0.1', 'address resolved');
    my $kh = OCP::KnownHosts->new(file => $file);
    ok(!$kh->knows('10.3.0.1'), 'stale key of the previous machine forgotten');
    ok($kh->knows('10.3.0.9'), 'others kept');

    $hz->delete_server(43, host => '10.3.0.9');
    ok(!$kh->knows('10.3.0.9'), 'a deleted server\'s key is forgotten');
};

done_testing;

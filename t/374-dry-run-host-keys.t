#!/usr/bin/env perl
# karr k374 -- the host probes of `ocp apply --dry-run` and .ocp/known_hosts.
#
# A dry run of a cluster that exists runs OCP::Drift's host probes: a
# read-only Rex task on every machine OCP reaches over SSH. OCP::Rex hands
# Rex::LibSSH only a host whose key the known_hosts file holds, and contacts
# any other once through OCP::SSH first, whose accept-new records its key --
# in the project's .ocp/known_hosts, under a banner that ends "[Dry run - no
# changes made]". On a clone the probes were skipped "for want of an SSH key
# that needs no PIN2", while PIN1 had put the robo key in reach (k349): the
# key was there, what was missing was a known_hosts the probe may write to.
# The claims, for the dry run:
#
#   * a host whose key the project has not recorded is not contacted: no key
#     recorded, the project directory as it was, byte for byte; the skip line
#     names that as the reason;
#   * a host whose key is recorded is probed and checked against that key,
#     and nothing is written;
#   * a host that no longer presents the recorded key is reported as that, on
#     STDERR, with the way out -- with the robo key too, whose refusal by a
#     machine is only a skip;
#   * on a clone, the robo key is read with the key PIN1 opened: the skip line
#     names the missing host key, not a missing SSH key, and a clone whose
#     .ocp/ holds the host's key is probed;
#   * control: the same prober outside a dry run records the key on first
#     contact -- the fake host is reachable, the claims above can fail.
#
# Network-free and cluster-free: `ssh` and `rex` are fakes on PATH that play
# one reachable machine with one host key -- OpenSSH's accept-new against
# UserKnownHostsFile, libssh's strict check against OCP_KNOWN_HOSTS -- so
# OCP::SSH and OCP::Rex run as they are. The K8s API is a fake with nothing
# in it; the detector is cut down to its host probes (t/349 stubs them out,
# t/38 and t/234 have the rest). The age key, keys.yaml and kubeconfig.yaml
# are real; the PIN prompt is stubbed on OCP::Password.

use strict;
use warnings;
use Test::More;

use Digest::MD5 ();
use File::Temp qw( tempdir );
use Kubernetes::REST::APIError;
use MIME::Base64 ();
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Drift;
use OCP::Config;
use OCP::Drift;
use OCP::KnownHosts;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

local @ARGV = ();
my $ocp = OCP->new;

my $PIN1       = 'pin1-k374';
my $PIN2       = 'pin2-k374';
my $HOST       = 'cp.k374.test';
my $KUBECONFIG = "apiVersion: v1\nkind: Config\nclusters: []\n";
my $HOST_KEY   = 'ssh-ed25519 ' . MIME::Base64::encode_base64('k374 the host key', '');
my $OLD_KEY    = 'ssh-ed25519 ' . MIME::Base64::encode_base64('k374 a key it had once', '');

# --- Fakes ----------------------------------------------------------------

package FakeList {
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}

# Holds nothing: every get is a 404, every list empty. Records every write.
package FakeApi {
    sub new { bless { writes => [] }, shift }

    sub get {
        die Kubernetes::REST::APIError->new(
            code => 404, context => 'get',
            body => '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}',
        );
    }

    sub list             { FakeList->new([]) }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }

    for my $write (qw( ensure create update patch delete apply )) {
        no strict 'refs';
        *{"FakeApi::$write"} = sub { push @{ $_[0]{writes} }, $write; $_[1] };
    }
}

package FakeOCP {
    sub new     { bless {}, shift }
    sub verbose { 0 }
}

package main;

# The machine: `ssh` and `rex` on PATH, each logging the host it was asked
# for. ssh does what OpenSSH does with StrictHostKeyChecking=accept-new: a
# host the file does not hold is recorded, a recorded key that differs is
# refused. rex does what Rex::LibSSH does: verify against OCP_KNOWN_HOSTS,
# record nothing, refuse a host the file does not hold or holds another key
# for. The probe task itself prints nothing: no drift.
my $BIN = path(tempdir(CLEANUP => 1));
$BIN->child('ssh')->spew(<<'SH');
#!/bin/sh
kh=; host=
for a in "$@"; do
    case "$a" in
        UserKnownHostsFile=*) kh=${a#UserKnownHostsFile=} ;;
        *@*) host=${a#*@} ;;
    esac
done
echo "ssh $host" >> "$FAKE_LOG"
pinned=
if [ -f "$kh" ]; then
    while read -r h t k; do [ "$h" = "$host" ] && pinned="$t $k"; done < "$kh"
fi
if [ -z "$pinned" ]; then
    { echo "$host $FAKE_HOST_KEY" >> "$kh"; } 2>/dev/null \
        || echo "Failed to add the host to the list of known hosts ($kh)." >&2
    exit 0
fi
[ "$pinned" = "$FAKE_HOST_KEY" ] && exit 0
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" >&2
echo "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @" >&2
echo "Host key verification failed." >&2
exit 255
SH
$BIN->child('rex')->spew(<<'SH');
#!/bin/sh
host=; prev=
for a in "$@"; do
    [ "$prev" = "-H" ] && host=$a
    prev=$a
done
echo "rex $host" >> "$FAKE_LOG"
pinned=
if [ -f "$OCP_KNOWN_HOSTS" ]; then
    while read -r h t k; do [ "$h" = "$host" ] && pinned="$t $k"; done < "$OCP_KNOWN_HOSTS"
fi
[ "$pinned" = "$FAKE_HOST_KEY" ] && exit 0
if [ -n "$pinned" ]; then
    echo "[warn] LibSSH: can't connect to $host: host key has changed from the known_hosts entry -- possible man-in-the-middle attack" >&2
else
    echo "[warn] LibSSH: can't connect to $host: host is unknown" >&2
fi
exit 1
SH
chmod 0755, map { $BIN->child($_)->stringify } qw( ssh rex );

# --- Fixture --------------------------------------------------------------

# A secure-mode project with a cluster, as the machine that made it has it:
# the project key in .ocp/ and behind PIN1 in age.key.enc, an admin (PIN2)
# and a robo key in keys.yaml, kubeconfig.yaml. No known_hosts yet. No key
# of the kinds the probes prefer (dev-mode key, OCP_OPERATOR_KEY): they go
# with the robo key, which needs the project key alone.
sub origin {
    my $dir = path(tempdir(CLEANUP => 1));
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k374',
        kubernetes     => { dist => 'k3s' },
        control_planes => { provider => 'ssh', host => $HOST },
    });

    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k374', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k374\n", public => 'ssh-ed25519 AAAAadmin k374', pin2 => $PIN2);
    $keys->add_key(name => 'robo-ssh-k374', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO PRIVATE k374\n", public => 'ssh-ed25519 AAAArobo k374');

    $s->create_secrets(hetzner_token => 'token-k374');
    $s->save_kubeconfig($KUBECONFIG);
    return $dir;
}

# What a clone gets: every committed file, no .ocp/.
sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

# A checkout as the machine that made the project has it: .ocp/ too.
sub checkout_of {
    my ($src) = @_;
    my $dst = clone_of($src);
    $dst->child('.ocp')->mkpath;
    $_->copy($dst->child('.ocp', $_->basename)) for $src->child('.ocp')->children;
    return $dst;
}

sub known_hosts { OCP::KnownHosts->project_file($_[0]) }

sub pin {
    my ($dir, @lines) = @_;
    path(known_hosts($dir))->parent->mkpath;
    path(known_hosts($dir))->spew(map { "$_\n" } @lines);
}

# Every path under $dir, directories too, with each file's digest.
sub listing {
    my ($dir) = @_;
    my %seen;
    $dir->visit(sub {
        my ($p) = @_;
        $seen{ $p->relative($dir)->stringify } = -d $p ? 'dir' : Digest::MD5::md5_hex($p->slurp_raw);
    }, { recurse => 1 });
    return \%seen;
}

sub config_for {
    OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify, ocp => $ocp);
}

# The machine's environment around $code: the fakes first on PATH, a fresh
# log, OCP_KNOWN_HOSTS the project's file as `ocp` exports it for a run
# (OCP.pm, k168). Returns the hosts ssh and rex were asked for, in order.
sub on_the_machine {
    my ($dir, $code) = @_;
    my $log = path(tempdir(CLEANUP => 1))->child('log');
    $log->touch;
    local $ENV{PATH}            = "$BIN:$ENV{PATH}";
    local $ENV{FAKE_LOG}        = "$log";
    local $ENV{FAKE_HOST_KEY}   = $HOST_KEY;
    local $ENV{OCP_KNOWN_HOSTS} = known_hosts($dir);
    delete local $ENV{OCP_OPERATOR_KEY};
    delete local $ENV{OCP_REX_DEBUG};
    delete local $ENV{SOPS_AGE_KEY_FILE};
    $code->();
    return [ $log->lines_utf8({ chomp => 1 }) ];
}

# One `ocp apply --dry-run` reconcile in $dir: { died, out, err, prompts,
# contacts, writes }. contacts is what the machine was asked, in order.
sub dry_run_in {
    my ($dir) = @_;
    my $config = config_for($dir);
    my $api    = FakeApi->new;
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ], dry_run => 1);

    my @prompts;
    my ($out, $err, $died) = ('', '');
    my $contacts = on_the_machine($dir, sub {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub { push @prompts, $_[0]; $PIN1 };
        local *OCP::Cmd::Apply::_k8s_api      = sub { $api };
        local *OCP::Drift::detect             = sub { [ $_[0]->rex_probe_drift ] };
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        local $SIG{__WARN__} = sub { print STDERR $_[0] };
        eval { $apply->_reconcile_components($config) };
        $died = $@;
    });
    return { died => $died, out => $out, err => $err, prompts => \@prompts,
             contacts => $contacts, writes => $api->{writes} };
}

my $SKIP_LINE = qr/^  \[WARN\] host probes skipped on \Q$HOST\E: its host key is not in \S+\/\.ocp\/known_hosts yet, and a dry run records none \(the first ocp apply or ocp status does\)$/m;

my $ORIGIN = origin();

for my $case (
    [ 'no .ocp/known_hosts' => sub { } ],
    [ 'an .ocp/known_hosts that holds another host' => sub {
        pin($_[0], "other.k374.test $OLD_KEY");
    } ],
) {
    my ($what, $setup) = @$case;
    subtest "a host whose key is not recorded ($what): not contacted, nothing written" => sub {
        my $dir = checkout_of($ORIGIN);
        $setup->($dir);
        my $before = listing($dir);

        my $r = dry_run_in($dir);

        is $r->{died}, '', 'no death' or diag $r->{died};
        is_deeply $r->{contacts}, [], 'the machine was not contacted: no ssh, no rex';
        is_deeply listing($dir), $before, 'the project directory, .ocp/ included, as it was'
            or diag explain listing($dir);
        ok(!OCP::KnownHosts->new(file => known_hosts($dir))->knows($HOST), 'no host key recorded');
        like $r->{out}, $SKIP_LINE, 'the skip line says why: no recorded key, and a dry run records none';
        like $r->{out}, qr/\Q${\ known_hosts($dir) }\E/, 'naming the file';
        is_deeply $r->{prompts}, [], 'no PIN: the project key is on disk';
        like $r->{out}, qr/\[Dry run - no changes made\]\n\z/, 'to its end';
        is $r->{err}, '', 'nothing on STDERR';
        is_deeply $r->{writes}, [], 'nothing written to the cluster';
    };
}

subtest 'a host whose key is recorded: probed against it, nothing written' => sub {
    my $dir = checkout_of($ORIGIN);
    pin($dir, "$HOST $HOST_KEY");
    my $before = listing($dir);

    my $r = dry_run_in($dir);

    is $r->{died}, '', 'no death' or diag $r->{died};
    is_deeply $r->{contacts}, [ "rex $HOST" ], 'probed over rex, which verifies; no ssh to record a key';
    unlike $r->{out}, qr/host probes skipped/, 'no skip line';
    like $r->{out}, qr/^  \[ok\] No drift detected$/m, 'the probe ran and found nothing';
    is $r->{err}, '', 'nothing on STDERR';
    is_deeply listing($dir), $before, 'the project directory as it was'
        or diag explain listing($dir);
};

subtest 'a host that no longer presents the recorded key: reported, with the way out' => sub {
    my $dir = checkout_of($ORIGIN);
    pin($dir, "$HOST $OLD_KEY");
    my $before = listing($dir);
    my $file   = known_hosts($dir);

    my $r = dry_run_in($dir);

    is $r->{died}, '', 'no death' or diag $r->{died};
    is_deeply $r->{contacts}, [ "rex $HOST" ], 'probed against the recorded key';
    like $r->{err}, qr/The host key of \Q$HOST\E does not match the one recorded in \Q$file\E/,
        'STDERR: the key does not match the recorded one';
    like $r->{err}, qr/ssh-keygen -R '\Q$HOST\E' -f '\Q$file\E'/, 'and how to remove the stale entry';
    unlike $r->{out}, qr/robo key was not accepted/, 'not passed off as the robo key refused';
    ok(OCP::KnownHosts->new(file => $file)->knows($HOST), 'the recorded key stays');
    is_deeply listing($dir), $before, 'the project directory as it was'
        or diag explain listing($dir);
};

subtest 'a clone: PIN1 opens the robo key, the skip line names the missing host key' => sub {
    my $dir    = clone_of($ORIGIN);
    my $before = listing($dir);

    my $r = dry_run_in($dir);

    is $r->{died}, '', 'no death' or diag $r->{died};
    is_deeply $r->{prompts}, [ 'Enter PIN1 (cluster access): ' ], 'PIN1 asked, once';
    like $r->{out}, $SKIP_LINE, 'skipped: no recorded host key, and a dry run records none';
    unlike $r->{out}, qr/no SSH key to probe with/, 'not for want of a key: the robo key is in reach';
    is_deeply $r->{contacts}, [], 'the machine was not contacted';
    is $r->{err}, '', 'nothing on STDERR';
    is_deeply listing($dir), $before, 'the project directory as it was: no .ocp/'
        or diag explain listing($dir);
};

subtest 'a clone whose .ocp/ holds the host key and no age key: probed with the robo key' => sub {
    my $dir = clone_of($ORIGIN);
    pin($dir, "$HOST $HOST_KEY");
    my $before = listing($dir);

    my $r = dry_run_in($dir);

    is $r->{died}, '', 'no death' or diag $r->{died};
    is_deeply $r->{prompts}, [ 'Enter PIN1 (cluster access): ' ], 'PIN1 asked, once';
    is_deeply $r->{contacts}, [ "rex $HOST" ], 'probed';
    unlike $r->{out}, qr/host probes skipped/, 'no skip line';
    is $r->{err}, '', 'nothing on STDERR';
    is_deeply listing($dir), $before, 'the project directory as it was: no age key in .ocp/'
        or diag explain listing($dir);
};

subtest 'control: outside a dry run the first contact records the key' => sub {
    my $dir    = checkout_of($ORIGIN);
    my $config = config_for($dir);
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);

    my ($result, $err) = (undef, '');
    my $contacts = on_the_machine($dir, sub {
        open my $efh, '>', \$err or die $!;
        local *STDERR = $efh;
        my $prober = $apply->rex_prober($config);
        $result = $prober && $prober->($HOST, 'detect_legacy_containerd_template', {});
    });

    is ref $result, 'HASH', 'the probe ran';
    is_deeply $contacts, [ "ssh $HOST", "rex $HOST" ], 'ssh recorded the key, then rex verified it';
    my $kh = OCP::KnownHosts->new(file => known_hosts($dir));
    ok $kh->knows($HOST), 'the key is in .ocp/known_hosts';
    like $err, qr/^Trusted host key of \Q$HOST\E on first contact, recorded in \Q${\ known_hosts($dir) }\E/m,
        'and said';
};

done_testing;

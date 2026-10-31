#!/usr/bin/env perl
# karr k380 -- a host probe that failed is drift unknown, not no drift.
#
# OCP::Drift's host probes run a read-only Rex task over SSH on every machine
# OCP reaches that way. A probe that throws -- a host key that no longer
# matches the recorded one (k374 rethrows that whatever key the probe used),
# a machine that does not answer -- was carped to STDERR and left no entry:
# `ocp apply`, `ocp apply --dry-run` and `ocp status` read it as no drift,
# the first two with "[ok] No drift detected" under the error. A probe that
# did not run must not read as "no drift" (k234). It is now one entry of kind
# error, the shape of a drift read that failed (k268): drift unknown, no
# remedy, the cause carped to STDERR once.
#
# The claims, each with a host that no longer presents its recorded key:
#
#   * ocp apply --dry-run: no "[ok] No drift detected"; the probe is a
#     "could not be checked" line, counted apart from the actions;
#   * ocp apply: the same line, and the run is not complete over it;
#   * ocp status: the drift section names it, --json carries it as an entry
#     of kind error that is not fixable;
#   * in all three the cause is on STDERR, once, and STDOUT does not repeat it
#     beyond its first line;
#   * control: the host with its recorded key reads as no drift in all three,
#     so the fakes can tell the two apart.
#
# The harness is t/374's: `ssh` and `rex` are fakes on PATH that play one
# machine with one host key, so OCP::SSH and OCP::Rex run as they are. The
# detector is cut down to its host probes; the K8s API holds nothing. The age
# key, keys.yaml and kubeconfig.yaml are real; the probes go with the robo key.

use strict;
use warnings;
use Test::More;

use File::Temp qw( tempdir );
use JSON::MaybeXS qw( decode_json );
use Kubernetes::REST::APIError;
use MIME::Base64 ();
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::AMDGPU;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Status;
use OCP::Config;
use OCP::Drift;
use OCP::KnownHosts;
use OCP::Keys;
use OCP::Kubernetes;
use OCP::Password;
use OCP::Secrets;

local @ARGV = ();
my $ocp = OCP->new;

my $HOST     = 'cp.k380.test';
my $HOST_KEY = 'ssh-ed25519 ' . MIME::Base64::encode_base64('k380 the host key', '');
my $OLD_KEY  = 'ssh-ed25519 ' . MIME::Base64::encode_base64('k380 a key it had once', '');
my $LABEL    = 'Legacy containerd template';

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
    sub new     { my ($c, %a) = @_; bless { %a }, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# What ocp status reads off the cluster besides drift: one Ready control plane.
package FakeK8s {
    sub new              { bless { api => $_[1] }, $_[0] }
    sub api              { $_[0]{api} }
    sub list_nodes       { [ { metadata => { name => 'police1' } } ] }
    sub gpu_nodes        { [] }
    sub node_name        { $_[1]{metadata}{name} }
    sub node_ready       { 1 }
    sub node_roles       { 'control-plane' }
    sub node_version     { 'v1.32.1+k3s1' }
    sub node_internal_ip { '10.0.0.10' }
    sub node_gpu_count    { 0 }
    sub node_gpu_capacity { undef }
}

package main;

# The machine, as in t/374: ssh records a host it does not know and refuses
# a recorded key that differs; rex verifies against OCP_KNOWN_HOSTS and
# records nothing. The probe task itself prints nothing: no drift.
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

# A secure-mode project with a cluster, its .ocp/ in place, the host's key
# recorded in .ocp/known_hosts as $key. No dev-mode key, no OCP_OPERATOR_KEY:
# the probes go with the robo key, which needs the project key alone.
sub project {
    my ($key) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k380',
        kubernetes     => { dist => 'k3s' },
        control_planes => { provider => 'ssh', host => $HOST },
    });

    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password('pin1-k380');

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k380', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k380\n", public => 'ssh-ed25519 AAAAadmin k380', pin2 => 'pin2-k380');
    $keys->add_key(name => 'robo-ssh-k380', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO PRIVATE k380\n", public => 'ssh-ed25519 AAAArobo k380');

    $s->create_secrets(hetzner_token => 'token-k380');
    $s->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");

    my $kh = path(OCP::KnownHosts->project_file($dir));
    $kh->parent->mkpath;
    $kh->spew("$HOST $key\n");
    return $dir;
}

sub known_hosts { OCP::KnownHosts->project_file($_[0]) }

# $code on the machine: the fakes first on PATH, OCP_KNOWN_HOSTS the
# project's file, STDOUT and STDERR captured, warnings onto STDERR. Returns
# { rv, died, out, err, contacts }.
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

    my ($out, $err) = ('', '');
    my ($rv, $died);
    {
        no warnings 'redefine';
        local *OCP::Drift::detect = sub { [ $_[0]->rex_probe_drift ] };
        # The project key is on disk: nothing here may ask for a PIN.
        local *OCP::Password::prompt_password = sub { die "k380: unexpected PIN prompt\n" };
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        local $SIG{__WARN__} = sub { print STDERR $_[0] };
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, died => $died, out => $out, err => $err,
             contacts => [ $log->lines_utf8({ chomp => 1 }) ] };
}

# The steps of a real reconcile past the drift check, which this test does
# not look at: stubbed for the rest of this file, as t/38 does. ocp status
# reaches none of them.
my @WRITERS = qw(
    _run_remedy _setup_registry _configure_registry_dns _setup_nfd
    _setup_gpu_operator _apply_cert_manager _wait_cert_manager_and_create_issuers
    _save_deployed_hash _setup_cilium_gateway _setup_lb_ipam _ensure_crds
    _ensure_providers _migrate_legacy_nodes _ensure_cp_ocpnode
    _ensure_robocop_credentials _ensure_robocop
);
my %STUB_RETURN = (
    _setup_registry => 'unchanged', _setup_nfd => 'unchanged',
    _setup_gpu_operator => 'skipped', _setup_cilium_gateway => 'unchanged',
    _configure_registry_dns => 0, _run_remedy => 0,
);
{
    no strict 'refs';
    no warnings 'redefine';
    for my $writer (@WRITERS) {
        *{"OCP::Cmd::Apply::$writer"} = sub {
            exists $STUB_RETURN{$writer} ? $STUB_RETURN{$writer} : 1;
        };
    }
    *OCP::Cmd::Apply::AMDGPU::step = sub { +{ changed => 0, failed => [] } };
}

# One `ocp apply` reconcile in $dir, a dry run or a real one. The real run
# also returns what it leaves short of spec ({_failed_components}).
sub apply_in {
    my ($dir, %opt) = @_;
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify, ocp => $ocp);
    my $api    = FakeApi->new;
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ],
        dry_run => $opt{dry_run} ? 1 : 0);

    no warnings 'redefine';
    local *OCP::Cmd::Apply::_k8s_api = sub { $api };

    my $r = on_the_machine($dir, sub { $apply->_reconcile_components($config) });
    $r->{failed} = $apply->{_failed_components} // [];
    $r->{writes} = $api->{writes};
    return $r;
}

# One `ocp status` (text, or --json) in $dir.
sub status_in {
    my ($dir, %opt) = @_;
    my $cmd = OCP::Cmd::Status->new(
        ($opt{json} ? (json => 1) : ()),
        command_chain => [ FakeOCP->new(config => $dir->child('ocp.yaml')->stringify) ],
    );
    no warnings 'redefine';
    local *OCP::Kubernetes::new = sub { FakeK8s->new(FakeApi->new) };
    return on_the_machine($dir, sub { $cmd->execute([], []) });
}

# The drift block of a reconcile's narrative: from its "Checking for drift"
# to the next step's "[..] Checking" (a dry run: to the end).
sub drift_block {
    my ($out) = @_;
    my ($block) = $out =~ /(\[\.\.\] Checking for drift.*?)(?=\n  \[\.\.\] Checking (?!for drift)|\z)/s;
    return $block // '';
}

# The cause, as k374 has OCP::Rex say it, and how often STDERR says it.
my $CAUSE = qr/The host key of \Q$HOST\E does not match the one recorded in /;
sub times_said { my ($text) = @_; scalar(() = $text =~ /$CAUSE/g) }

my $UNCHECKED = qr/^  \[drift\] could not be checked: \Q$LABEL\E: could not probe \Q$HOST\E, drift unknown: Rex task 'detect_legacy_containerd_template' failed: .+$/m;

# --- ocp apply --dry-run --------------------------------------------------

subtest 'ocp apply --dry-run: a probe that failed is not "no drift"' => sub {
    my $dir = project($OLD_KEY);
    my $r   = apply_in($dir, dry_run => 1);

    is $r->{died}, '', 'no death' or diag $r->{died};
    is_deeply $r->{contacts}, [ "rex $HOST" ], 'the host was probed, against its recorded key';
    unlike $r->{out}, qr/No drift detected/, 'no "[ok] No drift detected"';
    like $r->{out}, $UNCHECKED, 'the probe: could not be checked, the host named';
    like $r->{out}, qr/^  0 difference\(s\) a real run would act on\.$/m, 'no action counted for it';
    like $r->{out}, qr/^  1 more could not be checked -- a real run would not complete until it can be read\.$/m,
        'counted apart, as a check that could not be made';
    unlike $r->{out}, $CAUSE, 'STDOUT carries the first line of the cause, not all of it';
    is times_said($r->{err}), 1, 'STDERR names the cause, once';
    is_deeply $r->{writes}, [], 'nothing written to the cluster';
};

# --- ocp apply ------------------------------------------------------------

subtest 'ocp apply: a probe that failed is not "no drift", and the run is not complete' => sub {
    my $dir = project($OLD_KEY);
    my $r   = apply_in($dir);

    is $r->{died}, '', 'no death' or diag $r->{died};
    is_deeply $r->{contacts}, [ "rex $HOST" ], 'the host was probed, against its recorded key';
    my $block = drift_block($r->{out});
    like $block, qr/Checking for drift/, 'the drift check ran';
    unlike $block, qr/No drift detected/, 'no "[ok] No drift detected"';
    like $block, $UNCHECKED, 'the probe: could not be checked, the host named';
    unlike $r->{out}, $CAUSE, 'STDOUT carries the first line of the cause, not all of it';
    is times_said($r->{err}), 1, 'STDERR names the cause, once';
    is_deeply $r->{failed}, [ "$LABEL drift check" ], 'the run is not complete over it';
};

# --- ocp status -----------------------------------------------------------

subtest 'ocp status: a probe that failed is named in the drift section' => sub {
    my $dir = project($OLD_KEY);
    my $r   = status_in($dir);

    is $r->{died}, '', 'no death' or diag $r->{died};
    is_deeply $r->{contacts}, [ "rex $HOST" ], 'the host was probed, against its recorded key';
    like $r->{out}, qr/^=== Drift ===$/m, 'a drift section';
    like $r->{out}, $UNCHECKED, 'the probe: could not be checked, the host named';
    unlike $r->{out}, qr/can be reconciled automatically/, 'not counted as a finding';
    unlike $r->{out}, $CAUSE, 'STDOUT carries the first line of the cause, not all of it';
    is times_said($r->{err}), 1, 'STDERR names the cause, once';
};

subtest 'ocp status --json: an entry of kind error, not fixable' => sub {
    my $dir = project($OLD_KEY);
    my $r   = status_in($dir, json => 1);

    is $r->{died}, '', 'no death' or diag $r->{died};
    my $doc = eval { decode_json($r->{out}) };
    ok $doc, 'STDOUT is the JSON document alone' or diag $r->{out};
    my @drift = @{ $doc->{drift} // [] };
    is scalar @drift, 1, 'one drift entry';
    is $drift[0]{kind}, 'error', 'of kind error: drift unknown';
    is $drift[0]{component}, 'legacy_containerd_template', 'the probe';
    like $drift[0]{message}, qr/^\Q$LABEL\E: could not probe \Q$HOST\E, drift unknown: /, 'naming the host';
    ok !$drift[0]{fixable}, 'not fixable';
    is times_said($r->{err}), 1, 'STDERR names the cause, once';
};

# --- control: the recorded key --------------------------------------------

subtest 'control: the host with its recorded key is no drift in all three' => sub {
    my $dir = project($HOST_KEY);

    my $dry = apply_in($dir, dry_run => 1);
    is_deeply $dry->{contacts}, [ "rex $HOST" ], 'dry run: probed';
    like $dry->{out}, qr/^  \[ok\] No drift detected$/m, 'dry run: no drift';
    is $dry->{err}, '', 'dry run: nothing on STDERR';

    my $real = apply_in($dir);
    is_deeply $real->{contacts}, [ "rex $HOST" ], 'apply: probed';
    like drift_block($real->{out}), qr/^  \[ok\] No drift detected$/m, 'apply: no drift';
    is_deeply $real->{failed}, [], 'apply: complete';
    is $real->{err}, '', 'apply: nothing on STDERR';

    my $status = status_in($dir);
    is_deeply $status->{contacts}, [ "rex $HOST" ], 'status: probed';
    unlike $status->{out}, qr/=== Drift ===/, 'status: no drift section';
    is $status->{err}, '', 'status: nothing on STDERR';
};

done_testing;

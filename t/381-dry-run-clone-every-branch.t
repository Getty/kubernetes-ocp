#!/usr/bin/env perl
# karr k381 -- `ocp apply --dry-run` on a clone, every reader of the dry run
# at once: PIN1 asked once, the project directory left as it was.
#
# Since k370 the reads of OCP::Secrets -- read_all_secrets (hetzner_token,
# read_secret), read_kubeconfig, decrypt_file -- unlock the project key on a
# clone the way ensure_age_key does: PIN1, and the key cached in
# .ocp/age.key. The dry run opens the key into memory once (k349) and hands
# it on. A reader on its path that opened an OCP::Secrets of its own would
# ask PIN1 a second time and write .ocp/age.key under the dry-run banner.
#
# The readers the dry run of a cluster that exists reaches, and the
# OCP::Secrets / OCP::Keys each makes (k381):
#
#   OCP::Cmd::Apply::execute           one, for repair_sops_lastmodified,
#                                      which a dry run skips: no read
#   reconcile_components               the run's own: unlock_age_key, then
#                                      read_kubeconfig with the key in memory
#   rex_prober / _robo_probe_key       OCP::Keys with the run's age_key
#                                      (k374); identities() only, no prompt
#   OCP::ClusterKey operator_probe_key ones of its own only with both
#                                      OCP_OPERATOR_KEY and SOPS_AGE_KEY_FILE
#                                      set: that file is the identity, no
#                                      PIN1, nothing written
#   robocop_dry_run                    the run's $secrets, read_only; the
#                                      OCP::Keys of _robo_key_entry with its
#                                      age_key
#   OCP::Drift detect, gpu_dry_run,    none: the K8s API, ocp.yaml and the
#   Workloads::reapplies,              share/ manifests only
#   CR::missing_worker_ocpnodes,
#   CR::sync_worker_meta (dry_run),
#   AMDGPU::dry_run
#
# The claim, for a clone (every committed file, no .ocp/) whose ocp.yaml
# turns every branch of the dry run on -- a Hetzner and an ssh worker pool,
# robocop, the NVIDIA GPU Operator and the AMD GPU stack, the registry:
#
#   * PIN1 asked once, every branch reached, the run at its end, nothing
#     written to the cluster or contacted over SSH that has no recorded key;
#   * the project directory as it was, byte for byte: no .ocp/ at all;
#   * the same with the host probes run (the hosts' keys in a known_hosts
#     file outside the project): the robo key read with the key in memory.
#
# Network-free and cluster-free: the K8s API is a fake that serves what each
# branch reads; `ssh` and `rex` are fakes on PATH (t/374's machine); the PIN
# prompt is stubbed on OCP::Password. The run goes through
# OCP::Cmd::Apply::execute, no step of it stubbed. One check is: whether the
# loaded Rex::Rancher can deploy the AMD GPU stack -- an image with an older
# one ends the AMD plan before its reads, and the dry run calls none of the
# deploys. The age key, keys.yaml, secrets.yaml and kubeconfig.yaml are real.
# t/349 has the dry run's PIN1 on a clone, t/374 its host probes, t/370 the
# reads that unlock.

use strict;
use warnings;
use Test::More;

use Digest::MD5 ();
use File::Temp qw( tempdir );
use JSON::PP ();
use Kubernetes::REST::APIError;
use MIME::Base64 ();
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::AMDGPU;
use OCP::Config;
use OCP::Drift;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

local @ARGV = ();
my $ocp = OCP->new;

my $PIN1       = 'pin1-k381';
my $PIN2       = 'pin2-k381';
my $CP         = '192.0.2.10';
my $WORKER     = 'gpu1.k381.test';
my $WORKER_IP  = '192.0.2.21';
my $ROBO_PRIV  = "-----BEGIN OPENSSH PRIVATE KEY-----\nROBO k381\n-----END OPENSSH PRIVATE KEY-----\n";
my $TOKEN      = 'K10k381::server:k381';
my $KUBECONFIG = "apiVersion: v1\nkind: Config\nclusters: []\n";
my $HOST_KEY   = 'ssh-ed25519 ' . MIME::Base64::encode_base64('k381 the host key', '');
my $AMD        = $OCP::Config::AMD_GPU_PRESENT_LABEL;
my $NVIDIA     = $OCP::Drift::NVIDIA_GPU_LABELS[1];    # NFD's 3D controller, 10de

# --- Fakes ----------------------------------------------------------------

package FakeList {
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}

package FakeResponse {
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}

# A cluster: the objects it holds, by kind/namespace/name, and the raw GET
# paths. Anything else is a 404. Every write is recorded -- there must be
# none.
package FakeApi {
    my $NOT_FOUND = '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}';

    sub new {
        my ($c, %a) = @_;
        my $self = bless { objects => {}, paths => $a{paths} // {}, writes => [] }, $c;
        $self->{objects}{ join '/', $_->{kind}, $_->{metadata}{namespace} // '-', $_->{metadata}{name} } = $_
            for @{ $a{objects} // [] };
        return $self;
    }

    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub expand_class     { undef }

    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : undef;
        my %opt  = @rest;
        $name //= $opt{name};
        return $self->{objects}{ join '/', $kind, $opt{namespace} // '-', $name }
            // die Kubernetes::REST::APIError->new(code => 404, context => 'get', body => $NOT_FOUND);
    }

    sub list {
        my ($self, $kind, %opt) = @_;
        my ($lk, $lv) = split /=/, $opt{labelSelector} // '', 2;
        my @items = grep {
            $_->{kind} eq $kind
                && (!defined $opt{namespace} || ($_->{metadata}{namespace} // '') eq $opt{namespace})
                && (!defined $lk || (($_->{metadata}{labels} // {})->{$lk} // '') eq ($lv // ''))
        } values %{ $self->{objects} };
        return FakeList->new([ sort { $a->{metadata}{name} cmp $b->{metadata}{name} } @items ]);
    }

    sub _request {
        my ($self, $method, $path) = @_;
        unless ($method eq 'GET') {
            push @{ $self->{writes} }, "$method $path";
            return FakeResponse->new(200, '{}');
        }
        my $obj = $self->{paths}{$path} or return FakeResponse->new(404, $NOT_FOUND);
        return FakeResponse->new(200, JSON::PP::encode_json($obj));
    }

    for my $write (qw( ensure create update patch delete apply )) {
        no strict 'refs';
        *{"FakeApi::$write"} = sub { push @{ $_[0]{writes} }, $write; $_[1] };
    }
}

package main;

# The machines: `ssh` and `rex` on PATH, each logging the host it was asked
# for (t/374). rex does what Rex::LibSSH does: verify against
# OCP_KNOWN_HOSTS, record nothing, refuse a host the file does not hold. ssh
# records a host it does not know, as accept-new does -- a dry run must not
# get that far. The probe tasks print nothing: no host-side drift.
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
{ echo "$host $FAKE_HOST_KEY" >> "$kh"; } 2>/dev/null
exit 0
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
echo "[warn] LibSSH: can't connect to $host: host is unknown" >&2
exit 1
SH
chmod 0755, map { $BIN->child($_)->stringify } qw( ssh rex );

# --- Fixture --------------------------------------------------------------

# A secure-mode project with a cluster, every branch of the dry run on, as
# the machine that made it has it: the project key in .ocp/ and behind PIN1
# in age.key.enc, an admin (PIN2) and a robo key in keys.yaml, the Hetzner
# token in secrets.yaml, kubeconfig.yaml.
sub origin {
    my $dir = path(tempdir(CLEANUP => 1));
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k381',
        kubernetes     => { dist => 'k3s' },
        control_planes => { provider => 'ssh', host => $CP },
        workers        => [
            { name => 'hz', provider => 'hetzner', server_type => 'cpx21', location => 'fsn1', nodes => 1 },
            { name => 'gpu', provider => 'ssh', host => $WORKER, labels => { 'k381.test/tier' => 'gpu' } },
        ],
        robocop        => { enabled => 1, security_level => 'secret' },
        gpu            => {
            enabled => 1,
            driver  => 'operator',
            toolkit => 1,
            amd     => { allocation => 'device-plugin', labeller => 1, metrics => 1 },
        },
        registry       => { name => 'ocp.internal', cache => 'https://cache.k381.test' },
    });

    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k381', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k381\n", public => 'ssh-ed25519 AAAAadmin k381', pin2 => $PIN2);
    $keys->add_key(name => 'robo-ssh-k381', type => 'ssh_ed25519', purpose => 'automation',
        private => $ROBO_PRIV, public => 'ssh-ed25519 AAAArobo k381');

    $s->create_secrets(hetzner_token => 'token-k381');
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

# The cluster, as each branch of the dry run reads it: robocop's Secret
# (current: the robo key it holds is the one keys.yaml has) and Deployment;
# the GPU Operator running, its ClusterPolicy with the container toolkit off,
# and one NVIDIA GPU node, the GPU step's to run for (k313); one AMD GPU node; the ssh worker's OCPNode without the pool's labels, the
# Hetzner worker's none; a CoreDNS Corefile without registry.local.
sub cluster_for {
    my ($dir) = @_;
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify, ocp => $ocp);
    my %plain = (
        'robo-ssh-key' => $ROBO_PRIV,
        'server-url'   => $config->join_url($CP),
        'rke2-token'   => $TOKEN,
    );
    return FakeApi->new(
        objects => [
            { kind => 'Secret',
              metadata => { name => 'robocop-credentials', namespace => 'ocp-system' },
              data => { map { $_ => MIME::Base64::encode_base64($plain{$_}, '') } keys %plain } },
            { kind => 'Deployment', metadata => { name => 'robocop', namespace => 'ocp-system' } },
            { kind => 'Deployment', metadata => { name => 'gpu-operator', namespace => 'gpu-operator' } },
            { kind => 'Node', metadata => { name => 'crag', labels => { $NVIDIA => 'true' } } },
            { kind => 'Node', metadata => { name => 'synapse', labels => { $AMD => 'true' } } },
            { kind => 'Node', metadata => { name => 'k381', labels => {} } },
            { kind => 'OCPNode',
              metadata => { name => 'gpu1', namespace => 'ocp-system', resourceVersion => '7' },
              spec => { role => 'worker', providerRef => 'ssh-default', host => $WORKER },
              status => { phase => 'Ready', publicIP => $WORKER_IP } },
            { kind => 'ConfigMap', metadata => { name => 'coredns', namespace => 'kube-system' },
              data => { Corefile => ".:53 {\n    errors\n    forward . /etc/resolv.conf\n}\n" } },
        ],
        paths => {
            '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy' => {
                kind => 'ClusterPolicy', metadata => { name => 'gpu-cluster-policy' },
                spec => { toolkit => { enabled => JSON::PP::false } },
            },
        },
    );
}

# One `ocp apply --dry-run` in $dir, through OCP::Cmd::Apply::execute, every
# PIN prompt answered with PIN1, the machines on PATH, OCP_KNOWN_HOSTS
# $known_hosts (the project's file, as `ocp` exports it, unless the caller
# names one): { rv, died, out, err, prompts, contacts, writes, kubeconfigs }.
sub dry_run_in {
    my ($dir, %o) = @_;
    my $api   = cluster_for($dir);
    my $root  = OCP->new(config => $dir->child('ocp.yaml')->stringify);
    my $apply = OCP::Cmd::Apply->new(command_chain => [ $root ], dry_run => 1);
    my $log   = path(tempdir(CLEANUP => 1))->child('log');
    $log->touch;

    my (@prompts, @kubeconfigs);
    my ($out, $err, $rv, $died) = ('', '');
    {
        no warnings 'redefine';
        local $ENV{PATH}            = "$BIN:$ENV{PATH}";
        local $ENV{FAKE_LOG}        = "$log";
        local $ENV{FAKE_HOST_KEY}   = $HOST_KEY;
        local $ENV{OCP_KNOWN_HOSTS} = $o{known_hosts} // $dir->child('.ocp', 'known_hosts')->stringify;
        delete local $ENV{OCP_OPERATOR_KEY};
        delete local $ENV{OCP_REX_DEBUG};
        delete local $ENV{SOPS_AGE_KEY_FILE};
        delete local $ENV{HETZNER_API_TOKEN};
        local *OCP::Password::prompt_password = sub { push @prompts, $_[0]; $PIN1 };
        local *OCP::Cmd::Apply::AMDGPU::lib_too_old = sub { 0 };
        local *OCP::Cmd::Apply::_k8s_api = sub {
            my ($self, $kubeconfig) = @_;
            push @kubeconfigs, $kubeconfig if defined $kubeconfig;
            return $api;
        };
        open my $in,  '<', '/dev/null' or die $!;
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDIN  = $in;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        local $SIG{__WARN__} = sub { print STDERR $_[0] };
        $rv   = eval { $apply->execute([], []) };
        $died = $@;
    }
    return { rv => $rv, died => $died, out => $out, err => $err, prompts => \@prompts,
             contacts => [ $log->lines_utf8({ chomp => 1 }) ], writes => $api->{writes},
             kubeconfigs => \@kubeconfigs };
}

# What every run below has to say: each branch of the dry run reached.
sub every_branch_reached {
    my ($r) = @_;
    like $r->{out}, qr/^\[ok\] Cluster already exists/m, 'the reconcile path of the dispatcher';
    is scalar @{ $r->{kubeconfigs} }, 1, 'the API built once';
    like $r->{kubeconfigs}[0] // '', qr/^kind: Config$/m,
        'from the kubeconfig decrypted with the key in memory';
    like $r->{out}, qr/^  \[\.\.\] Checking for drift \(read-only\)\.\.\.$/m, 'the detector';
    like $r->{out}, qr/^  \[drift\] registry\.local is missing from the CoreDNS Corefile/m,
        'the registry: its CoreDNS record read';
    like $r->{out},
        qr/^  \[drift\] GPU Operator ClusterPolicy differs from the spec at spec\.toolkit\.enabled$/m,
        'the NVIDIA GPU Operator: its ClusterPolicy read';
    like $r->{out}, qr/^  \[WARN\] gpu\.toolkit changed \(false -> true\)/m,
        'and read again for the toolkit switch';
    like $r->{out}, qr/^  \[workers\] hz-1 has no OCPNode$/m, 'the Hetzner worker: missing';
    like $r->{out}, qr/^  \[workers\] gpu1: labels\/taints differ from ocp\.yaml$/m,
        'the ssh worker: its labels compared';
    unlike $r->{out}, qr/robocop-credentials/, 'robocop: its Secret is current, the robo key read';
    unlike $r->{out}, qr/Deployment\/robocop/, 'robocop: its Deployment there';
    like $r->{out}, qr/^  \[amd\] AMD GPU node\(s\): synapse \(device-plugin\)$/m,
        'the AMD GPU stack: its node';
    for my $label ('AMD GPU device plugin', 'AMD GPU node labeller', 'AMD device metrics exporter') {
        like $r->{out}, qr/^  \[amd\] \Q$label\E is not deployed\n {10}would deploy it \(\S+\) on synapse$/m,
            "the AMD GPU stack: $label read off the cluster";
    }
    like $r->{out}, qr/\[Dry run - no changes made\]\n\z/, 'to its end';
    is $r->{died}, '', 'no death' or diag $r->{died};
    is $r->{err}, '', 'nothing on STDERR';
    is_deeply $r->{writes}, [], 'nothing written to the cluster';
}

my $ORIGIN = origin();

subtest 'a clone: PIN1 once, every branch read, no .ocp/ after' => sub {
    my $dir    = clone_of($ORIGIN);
    my $before = listing($dir);
    ok !-e $dir->child('.ocp'), 'precondition: the clone has no .ocp/';

    my $r = dry_run_in($dir);

    every_branch_reached($r);
    is_deeply $r->{prompts}, [ 'Enter PIN1 (cluster access): ' ], 'PIN1 asked, once'
        or diag explain $r->{prompts};
    like $r->{out}, qr/^  \[WARN\] host probes skipped on \Q$CP\E, \Q$WORKER_IP\E: its host key is not in /m,
        'the host probes: both machines skipped for want of a recorded host key, not of an SSH key';
    is_deeply $r->{contacts}, [], 'no machine contacted';
    is_deeply listing($dir), $before, 'the project directory as it was: no .ocp/'
        or diag explain listing($dir);
    diag "STDOUT:\n$r->{out}\nSTDERR:\n$r->{err}" unless Test::More->builder->is_passing;
};

subtest 'a clone whose hosts are known elsewhere: probed with the robo key, PIN1 once' => sub {
    my $dir    = clone_of($ORIGIN);
    my $kh     = path(tempdir(CLEANUP => 1))->child('known_hosts');
    $kh->spew("$CP $HOST_KEY\n$WORKER_IP $HOST_KEY\n");
    my $before = listing($dir);

    my $r = dry_run_in($dir, known_hosts => "$kh");

    every_branch_reached($r);
    is_deeply $r->{prompts}, [ 'Enter PIN1 (cluster access): ' ], 'PIN1 asked, once'
        or diag explain $r->{prompts};
    unlike $r->{out}, qr/host probes skipped/, 'no host skipped';
    my %asked = map { $_ => 1 } @{ $r->{contacts} };
    is_deeply [ sort keys %asked ], [ "rex $CP", "rex $WORKER_IP" ],
        'both machines probed over rex, which verifies; no ssh to record a key';
    is_deeply listing($dir), $before, 'the project directory as it was: no .ocp/'
        or diag explain listing($dir);
    diag "STDOUT:\n$r->{out}\nSTDERR:\n$r->{err}" unless Test::More->builder->is_passing;
};

done_testing;

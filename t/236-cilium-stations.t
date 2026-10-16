#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 't/lib';
use OCPTest::Rexfile;
use OCP;
use OCP::Config;
use OCP::Drift;
use OCP::Rex;
use OCP::Versions;

#
# k195: Cilium upgrades one minor at a time (Rex::Rancher), so a cluster more
# than one minor behind the pin used to die in the upgrade_cilium drift remedy
# and in `ocp update`. OCP now walks it through the minor stations of
# OCP::Versions, one [STEP] line per station, and a failed step names the
# station reached.
#
# Held here: the station list (gapless up to the pin), that the remedy params
# carry it, the walk the Rexfile task makes against a recorder that refuses
# like the library does (the message is Rex::Rancher::Cilium::_settle_version's),
# that the step lines reach the `ocp` narrative, and what a break does. What a
# live Cilium does between the stations is NOT claimed here.
#

my $PIN = OCP::Versions->get_component_version('cilium');

subtest 'the stations: one per minor, ascending, up to the pin' => sub {
    my @st = OCP::Versions->cilium_stations;
    my @minor = map { /^1\.(\d+)\.\d+$/ ? $1 : die "not a version: $_" } @st;
    is_deeply \@minor, [ $minor[0] .. $minor[-1] ], 'consecutive minors, no gap';
    my ($pin_minor) = $PIN =~ /^1\.(\d+)\./;
    is $minor[-1], $pin_minor, 'the last station is the pin\'s minor' ;
    is $st[-1], $PIN, 'and it is the pin itself';
};

subtest 'the drift remedy carries the stations' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8("name: t\ncontrol_planes:\n  provider: hetzner\n  public_ip: 1.2.3.4\n");
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    my $p = OCP::Drift->remedy_params($config, 'cilium', $PIN);
    is_deeply $p->{cilium_stations}, [ OCP::Versions->cilium_stations ], 'cilium';
    ok !exists OCP::Drift->remedy_params($config, 'cert_manager', 'v1')->{cilium_stations},
        'and only cilium';
};

# The Rexfile reads the running version out of the library's refusal. Held
# against the real library (its private _settle_version, the one place that
# words it), so a changed wording turns this red instead of silently ending
# the walk.
subtest 'the library still words the one-minor refusal the way the Rexfile reads it' => sub {
    require Rex::Rancher::Cilium;
    my $settle = Rex::Rancher::Cilium->can('_settle_version')
        or plan skip_all => 'Rex::Rancher::Cilium has no _settle_version any more';
    eval { $settle->({ version => '1.20.0', version_pinned => 1 }, '1.17.2'); 1 };
    like $@, qr/\bCilium runs (\S+), version \S+ is more than one minor version away/,
        'the message the walk is started from';
    my ($running) = $@ =~ /\bCilium runs (\S+),/;
    is $running, '1.17.2', 'naming the running version';
};

# --- the task ---------------------------------------------------------------

my @ST = qw( 1.17.0 1.18.0 1.19.2 1.20.0 );
my %params = (
    version             => '1.20.0',
    cli_version         => 'v0.19.7',
    gateway_api_version => 'v1.6.1',
    cilium_stations     => [@ST],
);
my $KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n";

our @CALLS_OPTS;
# A cluster running $running: the library's rule, one minor per step.
sub cluster {
    my ($running, %o) = @_;
    my @asked;
    my $code = sub {
        my (%opts) = @_;
        push @asked, $opts{version};
        push @CALLS_OPTS, { %opts };
        my ($rm) = $running =~ /^1\.(\d+)/;
        my ($wm) = $opts{version} =~ /^1\.(\d+)/;
        die "Cilium runs $running, version $opts{version} is more than one minor version away: "
          . "Cilium upgrades and rolls back one minor at a time. Go to the latest 1.".($rm + 1).".x first, then on\n"
            if abs($wm - $rm) > 1;
        die $o{fail_at}{ $opts{version} } if $o{fail_at} && $o{fail_at}{ $opts{version} };
        $running = $opts{version};
        return 1;
    };
    return (\@asked, $code, sub { $running });
}

sub upgrade {
    my ($running, %o) = @_;
    @CALLS_OPTS = ();
    my ($asked, $code, $now) = cluster($running, %o);
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = sub { $_[0] =~ /^cat / ? ($KUBECONFIG, 0) : ('', 0) };
    local %ENV = %ENV;
    delete @ENV{qw(OCP_GATEWAY_API_VERSION OCP_CILIUM_CLI_VERSION)};
    local $OCPTest::Rexfile::LIB_CODE{'Rex::Rancher::Cilium::upgrade_cilium'} = $code;
    my $out = eval { OCPTest::Rexfile->run_task('upgrade_cilium', { %params, %{ $o{params} // {} } }) };
    return ($out, $@, $asked, $now->());
}

subtest 'three minors behind: walked station by station' => sub {
    my ($out, $err, $asked, $now) = upgrade('1.17.0');
    ok !$err, 'the task succeeds' or diag $err;
    is_deeply $asked, [ '1.20.0', '1.18.0', '1.19.2', '1.20.0' ],
        'the pin first (refused for free), then every station, then the pin';
    is $now, '1.20.0', 'the cluster ends on the pin';
    my @lines = $out =~ /^\[STEP\] (.*)$/mg;
    is_deeply \@lines, [
        'Gateway API may be degraded until the last step: the CRDs stay as they are until Cilium 1.20.0',
        'Cilium 1.17.0 -> 1.18.0 (step 1 of 3)',
        'Cilium 1.18.0 -> 1.19.2 (step 2 of 3)',
        'Cilium 1.19.2 -> 1.20.0 (step 3 of 3)',
    ], 'one line per station';
    like $out, qr/Cilium upgraded successfully to 1\.20\.0/, 'and the usual closing line';

    # [0] is the refused first try at the pin; [1..3] the stations.
    is_deeply [ map { $_->{gateway_api} ? 1 : 0 } @CALLS_OPTS ], [ 1, 0, 0, 1 ],
        'the CRDs only with the pin\'s step (and the free first ask)';
    ok $CALLS_OPTS[$_]{helm_values}{gatewayAPI}{enabled}, "station step $_ keeps gatewayAPI enabled in the Helm values"
        for 1, 2;
};

subtest 'on a later patch of a minor, the walk goes on from there' => sub {
    my ($out, $err, $asked) = upgrade('1.18.4');
    ok !$err, 'ok' or diag $err;
    is_deeply $asked, [ '1.20.0', '1.19.2', '1.20.0' ], 'only the stations above the running minor';
    is_deeply [ map { $_->{gateway_api} ? 1 : 0 } @CALLS_OPTS ], [ 1, 0, 1 ], 'CRDs with the last step only';
};

subtest 'one minor behind: one step, no walk, as before' => sub {
    my ($out, $err, $asked) = upgrade('1.19.1');
    ok !$err, 'ok' or diag $err;
    is_deeply $asked, ['1.20.0'], 'one call';
    ok $CALLS_OPTS[0]{gateway_api}, 'with the CRDs, as always';
    unlike $out, qr/\[STEP\]/, 'no station lines';
};

subtest 'a failing step stops the walk and names the station reached' => sub {
    my ($out, $err, $asked, $now) = upgrade('1.17.0',
        fail_at => { '1.19.2' => "cilium-agent did not become ready in 300s\n" });
    like $err, qr/Cilium upgrade stopped at 1\.18\.0, on the way to 1\.20\.0: the step to 1\.19\.2 failed: cilium-agent did not become ready/,
        'the station reached, the target, the step, the reason';
    like $err, qr/\(the Gateway API CRDs are unchanged\)\n\z/, 'and that the Gateway API CRDs are unchanged';
    is $err =~ tr/\n//, 1, 'one line';
    is_deeply $asked, [ '1.20.0', '1.18.0', '1.19.2' ], 'nothing after the failed step';
    is $now, '1.18.0', 'the cluster stays on the station';
    ok !OCPTest::Rexfile->lib_opts('Rex::Rancher::Cilium::install_cilium'),
        'and a failed station is no cluster without Cilium';
};

subtest 'no stations known: the library\'s refusal stands' => sub {
    my ($out, $err, $asked) = upgrade('1.17.0', params => { cilium_stations => [] });
    like $err, qr/more than one minor version away/, 'unchanged';
    is_deeply $asked, ['1.20.0'], 'nothing walked';
};

subtest 'downwards is not walked' => sub {
    my ($out, $err, $asked) = upgrade('1.20.0', params => { version => '1.17.0' });
    like $err, qr/more than one minor version away/, 'the library refuses a rollback of three minors';
    is_deeply $asked, ['1.17.0'], 'and OCP does not walk it';
};

# --- the narrative ----------------------------------------------------------

subtest 'ocp prints the station lines of a task that worked' => sub {
    my $tmp = tempdir(CLEANUP => 1);
    my $key = path($tmp)->child('id_ed25519');
    $key->spew('fake key');
    path("$key.pub")->spew('fake pub key');
    my $rexfile = path($tmp)->child('Rexfile');
    $rexfile->spew("# stub\n");
    my $kh = path($tmp)->child('known_hosts');
    $kh->spew("cp.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr\n");
    local $ENV{OCP_KNOWN_HOSTS} = $kh->stringify;
    delete local $ENV{OCP_REX_DEBUG};

    my $OUT = "Upgrading Cilium to 1.20.0...\n[STEP] Cilium 1.17.0 -> 1.18.0 (step 1 of 2)\n"
            . "\e[1m[STEP] Cilium 1.18.0 -> 1.20.0 (step 2 of 2)\e[0m\nCilium upgraded successfully to 1.20.0\n";
    no warnings 'redefine';
    local *OCP::Rex::_find_rexfile = sub { $rexfile->stringify };
    local *OCP::Rex::run = sub { ${ $_[2] } = $OUT; ${ $_[3] } = ''; return 1 };

    my ($out, $err) = ('', '');
    my $r;
    {
        open my $o, '>', \$out or die;
        open my $e, '>', \$err or die;
        local *STDOUT = $o;
        local *STDERR = $e;
        $r = OCP::Rex->new(host => 'cp.example', key_file => "$key")->run_task('upgrade_cilium');
    }
    like $out, qr/^  \[\.\.\] Cilium 1\.17\.0 -> 1\.18\.0 \(step 1 of 2\)$/m, 'step 1 on STDOUT';
    like $out, qr/^  \[\.\.\] Cilium 1\.18\.0 -> 1\.20\.0 \(step 2 of 2\)$/m, 'step 2, without colour';
    is $err, '', 'STDERR stays empty';
    is scalar @{ $r->{steps} }, 2, 'and the caller gets them';
};

done_testing;

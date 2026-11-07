#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use JSON::MaybeXS qw( decode_json );

use lib 'lib';

use OCP;
use OCP::Cmd::Status;
use OCP::Config;
use OCP::Secrets;

#
# The error field of `ocp status --json` when cluster_api(optional => 1)
# answers (undef, undef). That is no kubeconfig.yaml, and nothing else: a key
# the read lacks is unlocked or refused inside read_kubeconfig (k370, k375),
# and a client or API failure comes back as a line. The field said "Cannot
# decrypt kubeconfig.yaml (is .ocp/age.key present?)", naming a key that is
# not what is missing.
#
# Status asks OCP::Config::cluster_exists first, so the case is reached only
# when kubeconfig.yaml goes between that check and cluster_api's own. The
# test makes that race deterministic: after every cluster_exists, right as
# cluster_api is called, the file is removed. cluster_api itself and
# OCP::Secrets behind it are the real code, nothing faked.
#

{ package Local::FakeOCP; use Moo; has config => (is => 'ro', required => 1); sub verbose { 0 } }

my $ocp = OCP->new;
my $tmp = tempdir(CLEANUP => 1);

sub project {
    my ($name) = @_;
    my $dir = path($tmp)->child($name);
    $dir->mkpath;
    my $cfg = $dir->child('ocp.yaml');
    $ocp->dump_file($cfg->stringify, {
        name           => $name,
        version        => 'v1.32.1+rke2r1',
        control_planes => [{ provider => 'hetzner', server_type => 'cx32' }],
    });
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n");
    return $cfg->stringify;
}

my $raced = 0;
sub run_status {
    my ($cfg, %opt) = @_;
    my $cmd = OCP::Cmd::Status->new(
        ($opt{json} ? (json => 1) : ()),
        command_chain => [Local::FakeOCP->new(config => $cfg)],
    );
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my $rc;
    {
        my $cluster_api = \&OCP::Cmd::Status::cluster_api;
        my $kubeconfig  = path($cfg)->parent->child('kubeconfig.yaml');
        no warnings 'redefine';
        local *OCP::Cmd::Status::cluster_api = sub {
            $raced++ if $kubeconfig->remove;
            goto &$cluster_api;
        };
        local *STDOUT = $o;
        local *STDERR = $e;
        $rc = $cmd->execute([], []);
    }
    return ($rc, $out, $err);
}

# The refusal as one line without its ERROR:, built here from the lines
# themselves rather than by the code under test.
my $refusal = OCP::Secrets->no_kubeconfig_refusal;
(my $refusal_line = join ' ', map { s/\A\s+//r } split /\n/, $refusal) =~ s/\AERROR: //;

my ($json_rc, $json_out, $json_err);

#### --json: kubeconfig.yaml gone after cluster_exists

{
    my $cfg = project('gone-json');
    $raced = 0;
    ($json_rc, $json_out, $json_err) = run_status($cfg, json => 1);
    is $raced, 1, 'the race happened: cluster_exists saw kubeconfig.yaml, then it was gone';

    is $json_rc, 1, 'exit 1';

    # STDOUT: the JSON object and nothing else.
    my $d = eval { decode_json($json_out) };
    ok $d, 'STDOUT decodes as one JSON document' or diag $@;
    is $json_out, JSON::MaybeXS->new(canonical => 1, pretty => 1)->encode($d),
        'STDOUT is exactly that document, canonical, with nothing around it';
    ok $d->{deployed}, 'deployed: cluster_exists said yes';
    is_deeply $d->{nodes}, [], 'no nodes';

    # error: what is missing, not a key.
    my $error = $d->{error} // '';
    unlike $error, qr/age\.key/, 'error does not name .ocp/age.key';
    unlike $error, qr/decrypt/i, 'error does not speak of a decrypt';
    like $error, qr/\AThis project has no kubeconfig\.yaml, so there is no cluster API to reach\./,
        'error says kubeconfig.yaml is what is missing';
    is $error, $refusal_line, "error is OCP::Secrets' refusal, as one line";
    unlike $error, qr/\n|\AERROR/, 'error: one line, no ERROR: prefix';

    # STDERR: the refusal, as the text form prints it.
    is $json_err, $refusal, "STDERR: OCP::Secrets' refusal, and only that";
}

#### the text form in the same case: the same STDERR and exit

{
    my $cfg = project('gone-text');
    $raced = 0;
    my ($rc, $out, $err) = run_status($cfg);
    is $raced, 1, 'text form: the same race';
    is $rc, 1, 'text form: exit 1';
    is $rc, $json_rc, 'text form: the exit code of --json';
    is $err, $refusal, "text form: STDERR is OCP::Secrets' refusal";
    is $err, $json_err, 'text form: the STDERR of --json';
    like $out, qr/^Cluster exists \(kubeconfig\.yaml found\)$/m, 'text form: STDOUT is the report';
    unlike $out, qr/age\.key|decrypt|ERROR/i, 'text form: neither the error nor its diagnosis on STDOUT';
}

ok !exists $INC{'Rex.pm'}, 'Rex was not loaded: lib/ is the only source of OCP::*';
like $INC{'OCP/Cmd/Status.pm'}, qr{\Alib/}, 'OCP::Cmd::Status came from ./lib';

done_testing;

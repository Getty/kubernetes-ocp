#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS qw(encode_json);
use Path::Tiny qw(path);
use POSIX ();

use lib 'lib';

use WWW::Hetzner::HTTPResponse;
use WWW::Hetzner::LWPIO;

use OCP;
use OCP::Password;
use OCP::Secrets;

#
# k382: with HETZNER_API_TOKEN set, `ocp destroy` does not read secrets.yaml,
# so the first decrypt of the run is kubeconfig.yaml, inside _cluster_api's
# eval -- and the PIN1 that unlocks the key for it was asked in there too. A
# mistyped PIN1 died in the eval and came out as "no API": the teardown went
# on without the OCPNodes, from status.yaml, the label search and ocp.yaml.
# Without the variable the same PIN1 is asked for the token, outside any
# eval, and stops the run with OCP::Secrets' refusal (k375).
#
# The claims, through bin/ocp's run_cli with --pins-stdin and the variable
# set:
#   1. a wrong PIN1 is said in OCP::Secrets' words, unchanged, as the
#      dispatcher prints a user error -- and that is all: destroy stops
#      before it lists, searches or asks anything. So do the other refusals
#      on the way to the key (k375): an empty PIN1, an empty age.key.enc, a
#      key this project's files are not bound to -- opened from age.key.enc,
#      or found in .ocp/;
#   2. what is no refusal stays as it was: the right PIN1 opens the key and
#      the teardown goes on; no kubeconfig.yaml asks no PIN1; no key at all
#      is a missing API, as before (whether destroy should go on without the
#      API is k354, not decided here);
#   3. without the variable, a wrong PIN1 is the same line (unchanged).
#
# The wire is the only fake, as in t/383: the Hetzner client is the real one,
# and every request it makes is recorded and answered with no servers. The
# cluster API is 127.0.0.1:9, which refuses at once. No terminal: nothing is
# confirmed, so nothing could be deleted on any path.
#

no warnings 'once';

umask 022;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};
local $ENV{HETZNER_API_TOKEN} = 'hzTOKEN-k382-env-0123456789';

my $PIN1   = 'pin1-k382';
my $TOKEN  = 'hzTOKEN-k382-secrets-0123456789';
my $PROMPT = 'Enter PIN1 (cluster access): ';

local @ARGV = ();
my $ocp = OCP->new;

my $KUBECONFIG = join "\n",
    'apiVersion: v1', 'kind: Config', 'current-context: k382',
    'clusters:', '- name: k382', '  cluster:', '    server: https://127.0.0.1:9',
    '    insecure-skip-tls-verify: true',
    'users:', '- name: k382', '  user:', '    token: t',
    'contexts:', '- name: k382', '  context:', '    cluster: k382', '    user: k382', '';

# A project as the machine that made it has it: the project key in .ocp/ and,
# unless dev => 1, behind PIN1 in age.key.enc; the Hetzner token in
# secrets.yaml; kubeconfig.yaml unless kubeconfig => 0; a hetzner control
# plane, which the fallback names by its label (k345) and lists no machine for.
sub origin {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($o{pin1} // $PIN1) unless $o{dev};
    $s->create_secrets(hetzner_token => $TOKEN);
    $s->save_kubeconfig($KUBECONFIG) unless defined $o{kubeconfig} && !$o{kubeconfig};
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k382',
        control_planes => { provider => 'hetzner' },
    });
    return $dir;
}

# What a clone gets: every committed file, no .ocp/.
sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

my $secure    = origin();
my $other     = origin(pin1 => 'pin1-other-k382');
my $no_kc     = origin(kubeconfig => 0);
my $dev       = origin(dev => 1);

our $LOG;

sub note_side {
    open my $fh, '>>', $LOG or die "log: $!";
    print {$fh} "@_\n";
    close $fh;
}

# Every Hetzner request recorded, and answered with no servers.
sub wire {
    my ($io, $req) = @_;
    (my $path = $req->url) =~ s{\Ahttps://api\.hetzner\.cloud/v1}{};
    ($path) = split /\?/, $path;
    note_side('REQUEST', $req->method, $path);
    return WWW::Hetzner::HTTPResponse->new(status => 200, content => encode_json({
        servers => [],
        meta    => { pagination => { page => 1, next_page => undef } },
    }));
}

# `ocp destroy --pins-stdin` the way bin/ocp runs it -- OCP->run_cli -- in a
# child: in $dir, $stdin as STDIN, the wire fake, the terminal reads counted.
sub run_destroy {
    my ($dir, $stdin) = @_;
    my ($in, $out, $err, $log) = map { Path::Tiny->tempfile } 1 .. 4;
    $in->spew($stdin);

    my $pid = fork // die "fork: $!";
    unless ($pid) {
        local $LOG = "$log";
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        open STDIN,  '<', "$in"  or die;
        open STDOUT, '>', "$out" or die;
        open STDERR, '>', "$err" or die;
        alarm 120;
        no warnings 'redefine';
        *WWW::Hetzner::LWPIO::call = \&wire;
        *OCP::Password::ReadMode   = sub { note_side('TERMINAL', 'ReadMode'); return };
        *OCP::Password::ReadLine   = sub { note_side('TERMINAL', 'ReadLine'); return };
        @ARGV = ('destroy', '--pins-stdin');
        my $code = OCP->run_cli;
        close STDOUT;
        close STDERR;
        POSIX::_exit($code);
    }
    waitpid $pid, 0;
    my $st = $?;
    my @side = -s $log ? $log->lines_utf8({ chomp => 1 }) : ();
    return {
        signal   => $st & 127,
        exit     => $st >> 8,
        out      => $out->slurp_utf8,
        err      => $err->slurp_utf8,
        requests => [ grep { /\AREQUEST / } @side ],
        terminal => [ grep { /\ATERMINAL / } @side ],
    };
}

# A refusal on the way to the key: the dispatcher's line for a user error on
# STDERR, and destroy stopped there -- nothing listed or said on STDOUT, no
# label search, no word about the API, no terminal touched.
sub stopped_ok {
    my ($what, $r, $re) = @_;
    is $r->{signal}, 0, "$what: no signal (alarm)";
    isnt $r->{exit}, 0, "$what: exit non-zero";
    like $r->{err}, $re, "$what: OCP::Secrets' refusal, as the dispatcher prints it";
    unlike $r->{err}, qr/internal error/, "$what: not called an internal error";
    unlike $r->{err}, qr/ at \S+ line \d+/, "$what: no Perl location";
    unlike $r->{err}, qr/OCPNodes|cluster API|NOT torn down/,
        "$what: not taken for an API that does not answer";
    is $r->{out}, '', "$what: nothing on STDOUT -- nothing listed, nothing found";
    is_deeply $r->{requests}, [], "$what: no label search";
    is_deeply $r->{terminal}, [], "$what: the terminal is never touched";
}

# The teardown went on: the label search ran, the fallback found nothing, and
# the run came to its end -- with no terminal, at the question about the local
# state when there is any (k304).
sub went_on_ok {
    my ($what, $r) = @_;
    is $r->{signal}, 0, "$what: no signal (alarm)";
    unlike $r->{err}, qr/^Error:/m, "$what: no refusal";
    ok scalar(grep { m{\AREQUEST GET /servers\z} } @{ $r->{requests} }),
        "$what: the label search ran" or diag explain $r->{requests};
    like $r->{out}, qr/^No nodes to destroy\.$/m, "$what: the run went on to its end";
    is_deeply $r->{terminal}, [], "$what: the terminal is never touched";
}

# kubeconfig.yaml is local state: removing it needs a yes no one can give here.
sub asked_to_remove_ok {
    my ($what, $r) = @_;
    like $r->{err}, qr/^Aborted; nothing was removed\.$/m,
        "$what: stopped at the question about kubeconfig.yaml, with no terminal";
    is $r->{exit}, 1, "$what: exit 1, as an unanswered question";
}

# ---------------------------------------------------------------- claim 1

subtest 'a wrong PIN1: said in OCP::Secrets\' words, unchanged, and destroy stops' => sub {
    my $clone = clone_of($secure);
    my $r = run_destroy($clone, "not-the-pin\n");
    (my $refusal = OCP::Secrets->_wrong_pin1_refusal) =~ s/\s+\z//;
    is $r->{err}, "$PROMPT\nError: $refusal\n",
        'STDERR: the PIN1 prompt, then the refusal, unchanged -- and nothing else';
    stopped_ok('wrong PIN1', $r, qr/^Error: PIN1 does not open age\.key\.enc\. Nothing was unlocked, nothing written\.$/m);
    ok !-e $clone->child('.ocp/age.key'), 'no key written';
    ok -f $clone->child('kubeconfig.yaml'), 'kubeconfig.yaml kept';
};

subtest 'an empty PIN1: said as empty, and destroy stops' => sub {
    my $clone = clone_of($secure);
    my $r = run_destroy($clone, "\n");
    stopped_ok('empty PIN1', $r, qr/^Error: No PIN1 given, so age\.key\.enc stays locked\./m);
    ok !-e $clone->child('.ocp/age.key'), 'no key written';
};

subtest 'an empty age.key.enc: said, and destroy stops' => sub {
    my $clone = clone_of($secure);
    $clone->child('age.key.enc')->spew('');
    my $r = run_destroy($clone, "$PIN1\n");
    stopped_ok('empty age.key.enc', $r,
        qr/^Error: age\.key\.enc is empty: there is no key in it for PIN1 to open\.$/m);
};

subtest "another project's age.key.enc, opened with its PIN1: said, and destroy stops" => sub {
    my $clone = clone_of($secure);
    $other->child('age.key.enc')->copy($clone->child('age.key.enc'));
    my $r = run_destroy($clone, "pin1-other-k382\n");
    stopped_ok('foreign age.key.enc', $r, qr/^Error: This age key does not belong to this project\.$/m);
    ok !-e $clone->child('.ocp/age.key'), 'the foreign key not cached';
};

subtest 'a foreign key in .ocp/: said, no PIN1 asked, and destroy stops' => sub {
    my $clone = clone_of($secure);
    $clone->child('.ocp')->mkpath;
    $other->child('.ocp/age.key')->copy($clone->child('.ocp/age.key'));
    my $r = run_destroy($clone, '');
    stopped_ok('foreign .ocp/age.key', $r, qr/^Error: This age key does not belong to this project\.$/m);
    unlike $r->{err}, qr/\Q$PROMPT\E/, 'no PIN1 asked: the key is there already';
};

# ---------------------------------------------------------------- claim 2

subtest 'the right PIN1: the key opens and the teardown goes on' => sub {
    my $clone = clone_of($secure);
    my $r = run_destroy($clone, "$PIN1\n");
    like $r->{err}, qr/\Q$PROMPT\E\n/, 'PIN1 asked, on STDERR';
    went_on_ok('right PIN1', $r);
    asked_to_remove_ok('right PIN1', $r);
    like $r->{err}, qr/^\[!!\] Could not read the OCPNodes from the cluster API:$/m,
        'the API was asked with the key opened (127.0.0.1:9 does not answer)';
    ok -f $clone->child('.ocp/age.key'), 'the key cached in .ocp/, as every command does';
};

subtest 'no kubeconfig.yaml: no PIN1 asked, as before' => sub {
    my $clone = clone_of($no_kc);
    ok !-e $clone->child('kubeconfig.yaml'), 'precondition: no kubeconfig.yaml';
    ok -f $clone->child('age.key.enc'),      'precondition: age.key.enc';
    my $r = run_destroy($clone, '');
    unlike $r->{err}, qr/\Q$PROMPT\E/, 'no PIN1 asked: there is no API to open';
    went_on_ok('no kubeconfig.yaml', $r);
    is $r->{exit}, 0, 'exit 0: no local state to ask about';
};

subtest 'no key at all: a missing API, as before (k354 is not decided here)' => sub {
    my $clone = clone_of($dev);
    ok !-e $clone->child('age.key.enc'), 'precondition: no age.key.enc (dev mode)';
    my $r = run_destroy($clone, '');
    unlike $r->{err}, qr/\Q$PROMPT\E/, 'no PIN1 asked: there is nothing to unlock';
    went_on_ok('no key', $r);
    asked_to_remove_ok('no key', $r);
};

# ---------------------------------------------------------------- claim 3

subtest 'without HETZNER_API_TOKEN a wrong PIN1 is the same line' => sub {
    local $ENV{HETZNER_API_TOKEN};
    delete $ENV{HETZNER_API_TOKEN};
    my $clone = clone_of($secure);
    my $r = run_destroy($clone, "not-the-pin\n");
    (my $refusal = OCP::Secrets->_wrong_pin1_refusal) =~ s/\s+\z//;
    is $r->{err}, "$PROMPT\nError: $refusal\n", 'STDERR: the same prompt and refusal';
    stopped_ok('wrong PIN1, token from secrets.yaml', $r, qr/^Error: PIN1 does not open age\.key\.enc\./m);
};

done_testing;

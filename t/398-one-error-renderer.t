#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Carp ();
use File::Temp qw( tempdir );
use JSON::MaybeXS ();
use POSIX ();
use Path::Tiny qw( path );

use lib 'lib';

use Kubernetes::REST::APIError;
use OCP;
use OCP::Cmd::Node::Ls;
use OCP::ErrorLine;
use OCP::Hetzner::Picker;
use OCP::Provider::Hetzner;
use OCP::Secrets;

#
# k398 (Part A of the one-place-per-concern design): an error is rendered in
# one place, OCP::run_cli's _report_error, instead of a wrapper per command.
# The claims, one subtest each:
#   1. api_error_line: the cluster API's wording (k384, k387), as a function
#      of the error and the endpoint, so the one renderer can say it; with no
#      endpoint the line says "The cluster API" without one, and a 599 with
#      an empty body still names a reason.
#   2. the secret registry: a value the process has read as a secret (a
#      Hetzner token) is ******** in whatever is masked from then on, by
#      mask_secrets and by one_line; undef, '' and anything shorter than 8
#      characters is no secret, so a "0" does not mask every number. The
#      Hetzner adapter and the catalogue picker register the token they are
#      built with, OCP::Secrets the one hetzner_token gives; a secret inside a
#      longer one never leaves the longer one half masked.
#   3. foreign errors are user lines: an APIError and a Path::Tiny error that
#      reach OCP::_report_error are one "Error:" line with no internal-error
#      hint ("cannot read FILE: why", "cannot write ..."); anything else that
#      carries a source location is still an internal error (t/219's claim).
#      --verbose prints the raw exception, location included, and masks the
#      registry there too.
#   4. a --json command that fails prints one JSON error object on STDOUT,
#      {"error": the line STDERR says}, from OCP.pm and not per command (the
#      k388 precedent, moved out of node ls); STDOUT is always exactly one
#      document -- status and health, which print their own object, too --
#      and a command without a json option prints no JSON for --json.
#

sub api_err { Kubernetes::REST::APIError->new(@_) }

# A 599 as Kubernetes::REST throws it: the transport reason, and the location
# croak would add.
my $e599 = api_err(code => 599, body => "Connection refused\n",
    _location => ' at lib/Kubernetes/REST.pm line 1546.');

my $tmp = tempdir(CLEANUP => 1);

# What $code prints on STDERR.
sub stderr_of {
    my ($code) = @_;
    my $err = '';
    open my $fh, '>', \$err or die "stderr: $!";
    local *STDERR = $fh;
    $code->();
    close $fh;
    return $err;
}

subtest 'api_error_line' => sub {
    is OCP::ErrorLine::api_error_line(api_err(code => 599, body => "Connection refused\n"), undef),
        'The cluster API could not be reached: Connection refused',
        '599, no endpoint: the reason';
    is OCP::ErrorLine::api_error_line(api_err(code => 599, body => ''), undef),
        'The cluster API could not be reached: unknown error',
        '599, an empty body: never an empty reason';
    is OCP::ErrorLine::api_error_line(api_err(code => 599, body => 'refused'), 'https://h:6443'),
        'The cluster API at https://h:6443 could not be reached: refused',
        '599 with an endpoint: named';
    like OCP::ErrorLine::api_error_line(api_err(code => 403,
            body => '{"kind":"Status","reason":"Forbidden","message":"nodes is forbidden"}'), undef),
        qr/\AThe cluster API denied the request \(403 Forbidden\): nodes is forbidden\z/,
        '403: denied, the status and the message';
    is OCP::ErrorLine::api_error_line("plain string\n", undef), undef,
        'a string: nothing';
};

subtest 'secret registry' => sub {
    OCP::ErrorLine::add_secret('tok-abcdefgh-1234567890');
    OCP::ErrorLine::add_secret($_) for undef, '', '0', 'short';
    is OCP::ErrorLine::mask_secrets('GET with tok-abcdefgh-1234567890 failed'),
        'GET with ******** failed', 'a registered secret is masked';
    is OCP::ErrorLine::mask_secrets('port 0 and a short word'), 'port 0 and a short word',
        'undef, empty and short values mask nothing';
    is OCP::ErrorLine::mask_secrets(undef), '', 'undef comes back as the empty string';
    is OCP::ErrorLine::one_line("x tok-abcdefgh-1234567890 at lib/X.pm line 3.\n"), 'x ********',
        'one_line masks the registry';
    my $p = OCP::Provider::Hetzner->new(token => 'hz-token-registered-0001');
    is OCP::ErrorLine::mask_secrets('hz-token-registered-0001'), '********',
        'the Hetzner adapter registers its token';
    OCP::Hetzner::Picker->new(token => 'hz-picker-registered-0002');
    is OCP::ErrorLine::mask_secrets('hz-picker-registered-0002'), '********',
        'the catalogue picker registers its token';
    {
        local $ENV{HETZNER_API_TOKEN} = 'hz-env-registered-0003';
        my $secrets = OCP::Secrets->new(project_dir => path(tempdir(CLEANUP => 1)));
        is $secrets->hetzner_token, 'hz-env-registered-0003', 'hetzner_token gives the token';
    }
    is OCP::ErrorLine::mask_secrets('hz-env-registered-0003'), '********',
        'and registers it';
    OCP::ErrorLine::add_secret('tok-abcdefgh');
    is OCP::ErrorLine::mask_secrets('tok-abcdefgh-1234567890 and tok-abcdefgh'),
        '******** and ********', 'the longer secret first: never half masked';
    is OCP::ErrorLine::one_line('Bearer tok-abcdefgh-1234567890-and-more',
            mask => 'tok-abcdefgh-1234567890-and-more'),
        'Bearer ********', 'nor by the registry inside the mask one_line is given';
};

subtest 'foreign errors are user lines' => sub {
    is stderr_of(sub { OCP::_report_error($e599, 0) }),
        "Error: The cluster API could not be reached: Connection refused\n",
        'a 599: one line, no internal-error hint';
    eval { Path::Tiny::path("$tmp/missing/file")->slurp_utf8 };
    like stderr_of(sub { OCP::_report_error($@, 0) }),
        qr{\AError: cannot read \Q$tmp\E/missing/file: No such file or directory\n\z},
        'a file that cannot be read: cannot read FILE: why';
    eval { Path::Tiny::path("$tmp/missing/dir/x")->spew_utf8('x') };
    like stderr_of(sub { OCP::_report_error($@, 0) }), qr{\AError: cannot write },
        'a file that cannot be written: cannot write';
    eval { Carp::croak('boom') };
    like stderr_of(sub { OCP::_report_error($@, 0) }), qr/internal error/,
        'anything else with a source location is still internal (t/219)';
    like stderr_of(sub { OCP::_report_error($e599, 1) }), qr/line 1546/,
        '--verbose: the raw exception, location included';
    OCP::ErrorLine::add_secret('tok-abcdefgh-1234567890');
    unlike stderr_of(sub { OCP::_report_error("x tok-abcdefgh-1234567890\n", 1) }),
        qr/tok-abcdefgh/, '--verbose: the registry masked there too';
};

# A project directory: an ocp.yaml and nothing deployed (no kubeconfig.yaml).
sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew(join "\n",
        'name: k398', 'control_planes:', '  provider: ssh', '  host: cp.k398.invalid', '');
    return $dir;
}

# `ocp @argv` the way bin/ocp runs it -- OCP->run_cli -- in a child, in $dir,
# STDIN empty; $setup runs in the child first, so what it replaces stays
# there. The child's END is the first to run and ends it at once: none of this
# file's own END blocks, and no global destruction, run in the child.
sub run_ocp {
    my ($dir, $setup, @argv) = @_;
    my $io = path(tempdir(CLEANUP => 1));
    my ($in, $out, $err) = map { $io->child($_)->stringify } qw( in out err );
    path($in)->spew('');
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        eval q{ END { close STDOUT; close STDERR; POSIX::_exit($?) } 1 } or POSIX::_exit(96);
        my $code = eval {
            chdir $dir or die "chdir: $!";
            local $ENV{HOME} = "$dir";
            open STDIN,  '<', $in  or die "stdin: $!";
            open STDOUT, '>', $out or die "stdout: $!";
            open STDERR, '>', $err or die "stderr: $!";
            alarm 120;
            $setup->() if $setup;
            @ARGV = @argv;
            OCP->run_cli;
        } // 97;
        exit $code;
    }
    waitpid $pid, 0;
    return {
        exit   => $? >> 8,
        signal => $? & 127,
        out    => path($out)->slurp_utf8,
        err    => path($err)->slurp_utf8,
    };
}

# STDOUT as one JSON document: decoding the whole of it fails on anything
# before or after the one document.
sub one_document {
    my ($text) = @_;
    my $doc = eval { JSON::MaybeXS->new->decode($text) };
    ok ref $doc eq 'HASH', 'STDOUT: exactly one JSON object' or diag "STDOUT:\n$text";
    return $doc // {};
}

subtest 'the JSON error object, in one place' => sub {
    my $dir = project();
    my $fails_with = sub {
        my ($err) = @_;
        return sub { no warnings 'redefine'; *OCP::Cmd::Node::Ls::_ls = sub { die $err } };
    };

    my $r = run_ocp($dir, $fails_with->("nodes failed\n"), 'node', 'ls', '--json');
    is $r->{signal}, 0, 'node ls --json, a user error: no signal';
    is $r->{exit}, 1, 'node ls --json, a user error: exit 1';
    is_deeply one_document($r->{out}), { error => 'nodes failed' },
        'node ls --json, a user error: the object, the line as its error';
    is $r->{err}, "Error: nodes failed\n", 'node ls --json, a user error: STDERR says it';

    $r = run_ocp($dir, $fails_with->($e599), 'node', 'ls', '--json');
    is $r->{exit}, 1, 'node ls --json, a 599: exit 1';
    is_deeply one_document($r->{out}),
        { error => 'The cluster API could not be reached: Connection refused' },
        'node ls --json, a 599: the line as its error';
    is $r->{err}, "Error: The cluster API could not be reached: Connection refused\n",
        'node ls --json, a 599: STDERR says it';

    $r = run_ocp($dir, undef, 'version', '--json');
    isnt $r->{exit}, 0, 'version --json: refused';
    unlike $r->{out}, qr/\{/, 'version --json: no JSON, version has no json option';

    for my $cmd ('status', 'health') {
        $r = run_ocp($dir, undef, $cmd, '--json');
        is $r->{signal}, 0, "$cmd --json, nothing deployed: no signal";
        one_document($r->{out});
        unlike $r->{err}, qr/internal error/, "$cmd --json, nothing deployed: no internal error";
    }
};

done_testing;

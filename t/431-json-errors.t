#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use JSON::MaybeXS ();
use Path::Tiny qw( path );

use lib 'lib', 't/lib';

use Kubernetes::REST::APIError ();
use OCP;
use OCP::ErrorLine;
use OCPTest::Cli qw( run_ocp );

#
# k431: the error field of a --json command's object is the message as one
# line (k395), so a refusal written for STDERR with a list below it lost its
# layout there. The maintainer's decision: keep error, and add errors beside
# it, one entry per line of the refusal. The claims:
#   1. OCP::ErrorLine::json_errors holds the message one entry per line, each
#      as one_line makes it (masked, no location, no indentation), a line
#      nothing is left of left out, the label off the first; the entries
#      joined by one space are json_error's string; a 599 is its one line.
#   2. a command that dies under --json -- OCP.pm's renderer, ocp node ls
#      --json among them -- prints errors beside error, and a refusal with a
#      list keeps one entry per item.
# status and health: t/391, t/395 (the same refusal in all three), t/384,
# t/387 (an API error, one entry).
#

local @ARGV = ();
delete local @ENV{qw( http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY )};

#### 1: json_errors

subtest 'json_errors: one entry per line' => sub {
    my $refusal = "ocp.yaml has 2 errors:\n"
                . "  - workers: must be a list\n"
                . "  - network: must be a mapping\n"
                . "Nothing was done: fix the lines above.\n";
    my $entries = OCP::ErrorLine::json_errors($refusal);
    is_deeply $entries, [
        'ocp.yaml has 2 errors:',
        '- workers: must be a list',
        '- network: must be a mapping',
        'Nothing was done: fix the lines above.',
    ], 'a refusal with a list: every line its entry, the indentation off';
    is join(' ', @$entries), OCP::ErrorLine::json_error($refusal), 'joined by one space: json_error';

    my $labelled = "ERROR: This is the first line.\n       the second, indented.\n\n"
                 . "third at lib/OCP/X.pm line 3.\n at lib/OCP/Y.pm line 9.\n";
    my $l = OCP::ErrorLine::json_errors($labelled);
    is_deeply $l, [ 'This is the first line.', 'the second, indented.', 'third' ],
        'the label off the first, no source location, blank and bare-location lines no entry';
    is join(' ', @$l), OCP::ErrorLine::json_error($labelled), 'joined by one space: json_error';

    is_deeply OCP::ErrorLine::json_errors("Error:\n  the reason below the label\n"),
        [ 'the reason below the label' ], 'a label on a line of its own: no empty entry';
    is_deeply OCP::ErrorLine::json_errors('one line'), [ 'one line' ], 'one line: one entry';
    is_deeply OCP::ErrorLine::json_errors(undef), [ 'unknown error' ], 'undef: unknown error';
    is_deeply OCP::ErrorLine::json_errors("ERROR:  \n\n"), [ 'unknown error' ], 'nothing left: unknown error';

    OCP::ErrorLine::add_secret('k431-secret-token');
    is_deeply OCP::ErrorLine::json_errors("refused\n  token k431-secret-token was wrong\n"),
        [ 'refused', 'token ******** was wrong' ], 'a secret is masked in its entry';

    my $e599 = Kubernetes::REST::APIError->new(code => 599, context => 'list Node',
        body => "Can't connect to 10.0.0.1:6443 (Connection refused)\n\n"
              . "Connection refused at /usr/share/perl5/LWP/Protocol/http.pm line 49.",
        _location => ' at lib/OCP/Kubernetes.pm line 1.');
    is_deeply OCP::ErrorLine::json_errors($e599), [ OCP::ErrorLine::json_error($e599) ],
        'a 599: one entry, json_error\'s line -- the body\'s lines after the first are LWP again';
};

#### 2: through OCP.pm's renderer: ocp node ls --json

sub project {
    my (%spec) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew(join "\n",
        'name: k431', 'control_planes:', '  provider: ssh', '  host: cp.k431.invalid', @{ $spec{extra} // [] }, '');
    return $dir;
}

sub one_document {
    my ($text) = @_;
    my $doc = eval { JSON::MaybeXS->new->decode($text) };
    ok ref $doc eq 'HASH', 'STDOUT: exactly one JSON object' or diag "STDOUT:\n$text";
    return $doc // {};
}

subtest 'node ls --json, a one-line refusal: errors holds it once' => sub {
    my $r   = run_ocp(path(tempdir(CLEANUP => 1)), undef, 'node', 'ls', '--json');   # no ocp.yaml
    my $doc = one_document($r->{out});
    is $r->{exit}, 1, 'exit 1';
    is_deeply [ sort keys %$doc ], [ 'error', 'errors' ], 'error and errors, nothing else';
    is_deeply $doc->{errors}, [ $doc->{error} ], 'errors: the one line, once';
};

subtest 'node ls --json, a refusal with a list: one entry per item' => sub {
    my $r = run_ocp(project(extra => [
        'workers:',
        '  - name: a',
        '    provider: ssh',
        '    host: [ x ]',
        '  - name: b',
        '    provider: ssh',
        '    host: { y: 1 }',
    ]), undef, 'node', 'ls', '--json');
    my $doc = one_document($r->{out});
    is $r->{exit}, 1, 'exit 1';
    my @e = @{ $doc->{errors} // [] };
    like $e[0], qr/\Aocp\.yaml has (\d+) errors:\z/, 'the first entry: the head of the refusal'
        or diag explain $doc;
    my ($n) = ($e[0] // '') =~ /has (\d+) errors/;
    is scalar(grep { /\A- / } @e), $n // -1, 'one entry per item of the list';
    like $e[-1], qr/\ANothing was done: ocp node ls checks what it reads/, 'the last entry: what was not done';
    is join(' ', @e), $doc->{error}, 'joined by one space: the error field';
    unlike $doc->{error}, qr/\n/, 'error stays one line';
    like $r->{err}, qr/\AError: ocp\.yaml has \d+ errors:\n  - /, 'STDERR: the refusal with its layout, as before';
};

done_testing;

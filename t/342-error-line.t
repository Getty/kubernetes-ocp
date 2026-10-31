#!/usr/bin/env perl
# karr k342 -- one helper turns an exception into one STDERR line, where
# OCP::Role::Cmd::Machines (_oneline: ocp keys secure, ocp keys operator
# add|rm) and OCP::Cmd::Init (_catalogue_error) each had their own.
#
# The claims:
#
#   * every Perl source location goes, " at FILE line N." -- the last one and
#     one inside the message alike
#   * whitespace, newlines too, folds into single spaces, none at either end
#   * a secret given as mask is ******** wherever it stands, taken as text
#   * nothing left is 'unknown error', or what the caller says empty is
#   * the callers are that helper: Machines' _oneline with nothing left as ''
#     (its callers print "unexpected answer: " and the like after it),
#     Init's _catalogue_error with the token masked

use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP;
use OCP::Cmd::Init;
use OCP::Cmd::Keys::Operator::Rm;
use OCP::ErrorLine;

local @ARGV = ();

sub line { OCP::ErrorLine::one_line(@_) }

subtest 'source locations' => sub {
    is line("Permission denied at lib/OCP/SSH.pm line 88.\n"), 'Permission denied', 'die\'s';
    is line("boom at /opt/ocp/src/lib/OCP/Rex.pm line 12\n"), 'boom', 'without the period';
    is line("Hetzner API error: Can't connect to 127.0.0.1:1 (Connection refused)"
          . " at /usr/share/perl5/LWP/Protocol/http.pm line 50.\n"
          . " at /opt/ocp/install/lib/WWW/Hetzner/Role/HTTP.pm line 77.\n"),
        "Hetzner API error: Can't connect to 127.0.0.1:1 (Connection refused)",
        'every one of a chain';
    is line("outer: inner at lib/A.pm line 3. and on at lib/B.pm line 4.\n"),
        'outer: inner and on', 'one inside the message too';
    is line('connected at last'), 'connected at last', 'an "at" that is no location stays';
};

subtest 'whitespace' => sub {
    is line("  first\n\tsecond   third \n\n"), 'first second third', 'folded, trimmed';
    is line("one\r\ntwo"), 'one two', 'CRLF';
    is line('already one line'), 'already one line', 'a line stays as it is';
};

subtest 'masking' => sub {
    my $token = 'tok-k342.secret+1';
    is line("401 Unauthorized Bearer $token at lib/X.pm line 9.\n", mask => $token),
        '401 Unauthorized Bearer ********', 'the token';
    is line("$token and $token", mask => $token), '******** and ********', 'every time';
    is line('tok-k342Xsecret11', mask => $token), 'tok-k342Xsecret11', 'as text, not a pattern';
    is line("nothing secret\n", mask => undef), 'nothing secret', 'an undef mask masks nothing';
    is line("nothing secret\n", mask => ''), 'nothing secret', 'nor does an empty one';
    is line($token, mask => $token), '********', 'a message that is the token alone';
};

subtest 'nothing left' => sub {
    is line(undef), 'unknown error', 'undef';
    is line(''), 'unknown error', 'empty';
    is line(" \n\t"), 'unknown error', 'blank';
    is line(" at lib/X.pm line 3.\n"), 'unknown error', 'a bare location';
    is line('', empty => ''), '', 'empty => \'\'';
    is line(undef, empty => 'no answer'), 'no answer', 'empty => a word';
    is line('0'), '0', '"0" is something';
};

subtest 'an exception object, stringified' => sub {
    package K342::Error {
        use overload '""' => sub { "object failure at lib/K.pm line 2.\n" }, fallback => 1;
        sub new { bless {}, shift }
    }
    is line(K342::Error->new), 'object failure', 'as its text';
};

subtest 'the callers say it the same way' => sub {
    my $rm   = OCP::Cmd::Keys::Operator::Rm->new(command_chain => [ OCP->new ]);
    my $init = OCP::Cmd::Init->new;
    my $token = 'tok-k342';
    for my $err ("refused at lib/OCP/SSH.pm line 3.\n", "a\n b at x line 1.\n at y line 2.\n",
                 "Bearer $token denied\n", '', undef) {
        my $shown = defined $err ? $err =~ s/\n/\\n/gr : 'undef';
        is $rm->_oneline($err), line($err, empty => ''), "Machines' _oneline: $shown";
        is $init->_catalogue_error($err, $token), line($err, mask => $token),
            "Init's _catalogue_error: $shown";
    }
    is $rm->_oneline(''), '', "_oneline: nothing is '', as before";
    is $init->_catalogue_error('', $token), 'unknown error', "_catalogue_error: 'unknown error', as before";
    is $init->_catalogue_error("Bearer $token\n", $token), 'Bearer ********', 'the token masked';
};

done_testing;

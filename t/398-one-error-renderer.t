#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use Kubernetes::REST::APIError;
use OCP::ErrorLine;

#
# k398 (Part A of the one-place-per-concern design): an error is rendered in
# one place, OCP::run_cli's _report_error, instead of a wrapper per command.
# The claims, one subtest each:
#   1. api_error_line: the cluster API's wording (k384, k387), as a function
#      of the error and the endpoint, so the one renderer can say it; with no
#      endpoint the line says "The cluster API" without one, and a 599 with
#      an empty body still names a reason.
#

sub api_err { Kubernetes::REST::APIError->new(@_) }

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

done_testing;

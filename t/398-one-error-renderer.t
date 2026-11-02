#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use Kubernetes::REST::APIError;
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

done_testing;

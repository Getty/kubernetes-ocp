#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Kubernetes::REST::APIError;

use lib 'lib';

use OCP::ErrorLine;
use OCP::Cmd::Apply::K8s;

#
# k437 (maintainer decision 2026-11-08): ocp apply says a failed API read
# as ocp status, drift and destroy do -- OCP::ErrorLine::api_error_line, a
# line naming the server, what it did and the status with its reason, then
# the API's message. It said "Kubernetes API error (get): 403" and the raw
# JSON body. The read helpers (read_or_absent, read_or_why, crd_get,
# resource_exists, poll_deployment_ready) carry it into every WARN and !!
# line that prints their words; t/269, t/319, t/328 and the other files of
# the apply lane hold those lines.
#
# A Kubernetes Status body without a message was said as its raw JSON by
# api_error_line itself (message // body); its POD said the body stands in
# only when it is no Status object. That is what it does now.
#

my $ENDPOINT = 'https://10.0.0.1:6443';
OCP::ErrorLine::set_cluster_endpoint($ENDPOINT);

my $FORBIDDEN = '{"kind":"Status","apiVersion":"v1","status":"Failure",'
              . '"message":"deployments.apps \"robocop\" is forbidden","reason":"Forbidden","code":403}';
my $BARE      = '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"InternalError","code":500}';

sub api_error {
    my ($code, $body) = @_;
    return do { local $@; eval { Kubernetes::REST::APIError->throw(code => $code, context => 'get', body => $body) }; $@ };
}

my $SAID_403 = "The cluster API at $ENDPOINT denied the request (403 Forbidden): deployments.apps \"robocop\" is forbidden";
my $SAID_500 = "The cluster API at $ENDPOINT failed (500 Internal Error)";

subtest 'read_or_absent and read_or_why: the line naming the server' => sub {
    my $what = 'Deployment ocp-system/robocop';
    eval { OCP::Cmd::Apply::K8s::read_or_absent($what, sub { die api_error(403, $FORBIDDEN) }) };
    is $@, "could not read $what: $SAID_403\n", 'read_or_absent: no "Kubernetes API error", no JSON';

    my (undef, $why) = OCP::Cmd::Apply::K8s::read_or_why($what, sub { die api_error(500, $BARE) });
    is $why, "could not read $what: $SAID_500", 'read_or_why: a Status without a message, said by its reason';
    unlike $why, qr/[{}]/, 'no raw body';
};

{
    package GetApi;
    sub new          { my ($c, $e) = @_; bless { e => $e }, $c }
    sub get          { die $_[0]{e} }
    sub wait_seconds { }

    package Resp;
    sub new     { my ($c, $s, $b) = @_; bless { status => $s, content => $b }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }

    package RawApi;
    sub new      { my ($c, $r) = @_; bless { r => $r }, $c }
    sub _request { $_[0]{r} }
}

subtest 'resource_exists and poll_deployment_ready: the same line' => sub {
    eval { OCP::Cmd::Apply::K8s::resource_exists({}, GetApi->new(api_error(403, $FORBIDDEN)),
        'Deployment', 'robocop', namespace => 'ocp-system') };
    is $@, "could not read Deployment ocp-system/robocop: $SAID_403\n", 'resource_exists';

    eval { OCP::Cmd::Apply::K8s::poll_deployment_ready(GetApi->new, GetApi->new(api_error(500, $BARE)),
        'robocop', 'ocp-system', 5) };
    is $@, "Deployment ocp-system/robocop not ready within 5s; the last read failed: $SAID_500\n",
        'poll_deployment_ready';
};

subtest 'crd_get: an error status as the APIError a typed call dies with would be said' => sub {
    my $path = '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';
    eval { OCP::Cmd::Apply::K8s::crd_get({}, RawApi->new(Resp->new(403, $FORBIDDEN)), $path) };
    is $@, "GET $path failed: $SAID_403\n", 'a Status body: reason and message, no JSON';

    eval { OCP::Cmd::Apply::K8s::crd_get({}, RawApi->new(Resp->new(502, '<html>bad gateway</html>')), $path) };
    is $@, "GET $path failed: The cluster API at $ENDPOINT failed (502): <html>bad gateway</html>\n",
        'no Status body: the body, as one line';
};

subtest 'api_error_line: a Status without a message is no raw JSON' => sub {
    is OCP::ErrorLine::api_error_line(api_error(500, $BARE), $ENDPOINT), $SAID_500, 'reason in words, nothing after';
    is OCP::ErrorLine::api_error_line(api_error(404, '404 page not found'), undef),
        'The cluster API answered (404): 404 page not found', 'no Status object: the body';
};

OCP::ErrorLine::set_cluster_endpoint(undef);

done_testing;

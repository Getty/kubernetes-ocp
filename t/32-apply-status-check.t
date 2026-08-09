#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::Cmd::Apply;

#
# _server_side_apply drives Kubernetes::REST::_request, which is the raw
# transport: it returns whatever the API answered and never inspects the
# status — only the typed methods run _check_response.
#
# OCP did not check either, so every failed apply was silent. A 404 for a CRD
# the API server had not registered yet was indistinguishable from success, and
# `ocp apply` went on to report resources it had never created.
#

package FakeResponse {
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}

package FakeApi {
    sub new { my ($c, %a) = @_; bless { calls => [], %a }, $c }
    sub _request {
        my ($self, $method, $path, $body, %opts) = @_;
        push @{$self->{calls}}, [$method, $path];
        return FakeResponse->new(
            status  => $self->{status}  // 200,
            content => $self->{content} // '{}',
        );
    }
}

my $resource = {
    apiVersion => 'cert-manager.io/v1',
    kind       => 'ClusterIssuer',
    metadata   => { name => 'selfsigned-issuer' },
    spec       => { selfSigned => {} },
};

my $apply = bless {}, 'OCP::Cmd::Apply';

subtest 'a 2xx apply succeeds' => sub {
    my $api = FakeApi->new(status => 200);
    ok eval { $apply->_server_side_apply($api, $resource); 1 },
        'does not die on success';
    is scalar @{$api->{calls}}, 1, 'one request was made';
    is $api->{calls}[0][0], 'PATCH', 'server-side apply uses PATCH';
};

subtest 'an error status is not swallowed' => sub {
    for my $status (400, 403, 404, 409, 500) {
        my $api = FakeApi->new(
            status  => $status,
            content => '{"kind":"Status","message":"the server could not find the requested resource"}',
        );
        my $ok = eval { $apply->_server_side_apply($api, $resource); 1 };

        ok !$ok, "HTTP $status makes the apply fail";
        like $@, qr/\bClusterIssuer\/selfsigned-issuer\b/,
            "HTTP $status names the resource that failed";
        like $@, qr/\b$status\b/, "HTTP $status appears in the message";
    }
};

subtest 'the API error body reaches the operator' => sub {
    my $api = FakeApi->new(
        status  => 404,
        content => '{"message":"clusterissuers.cert-manager.io not found"}',
    );
    eval { $apply->_server_side_apply($api, $resource) };

    like $@, qr/clusterissuers\.cert-manager\.io not found/,
        'the server explanation is included, not just the status code';
};

done_testing;

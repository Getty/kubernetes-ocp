#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

#
# k154: a bare hand-run of the Rexfile server-install tasks must not rotate the
# token of a cluster that already exists.
#
# This is the defense-in-depth twin of k150. k150 fixed the controller side
# (OCP::Rex::install_server reuses the on-disk token), so the `ocp apply` path is
# already safe -- it always passes a token= param down to the task. But the
# Rexfile tasks themselves once minted a fresh token whenever none was passed,
# so a human running `rex -f share/Rexfile install_rke2_server` WITHOUT token= on
# a machine that already carries a cluster wrote a new token into config.yaml
# while the embedded-etcd datastore stayed sealed with the original, arming a
# fatal reconcile crash on the next server restart:
#
#   bootstrap data already found and encrypted with different token
#
# Since k155 the decision is Rex::Rancher::Server::install_server's: without a
# token it reads /var/lib/rancher/<dist>/server/token on the node and reuses it,
# minting one only for a fresh server; a passed token wins. That behaviour is
# held against the real library in t/155-rex-libraries.t. What OCP owns, and
# what this test holds: the task hands the library NO token (undef) when it got
# none -- an empty string would count as a given token there and be written
# into config.yaml -- and hands a passed one through unchanged.
#
# What only a real cluster can confirm -- that RKE2/k3s accept the reused token
# and the datastore reconciles -- is deliberately NOT claimed here.
#

sub token_handed_over {
    my ($task, $params) = @_;
    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task($task, $params);
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    return ($o, $o && $o->{token});
}

for my $task (qw( install_rke2_server install_k3s_server )) {
    subtest "$task: no token param -> the library decides (reuse or mint)" => sub {
        my ($o, $token) = token_handed_over($task, {});
        ok $o, 'install_server is called' or return;
        ok exists $o->{token}, 'the token option is present';
        ok !defined $token, 'and undef -- the library reuses the sealed token';
    };

    subtest "$task: an empty token param is no token" => sub {
        my (undef, $token) = token_handed_over($task, { token => '' });
        ok !defined $token, "'' becomes undef, never an empty token in config.yaml";
    };

    subtest "$task: an explicit token param still wins (the ocp-apply path)" => sub {
        my (undef, $token) = token_handed_over($task, { token => 'PASSED-BY-OCP-APPLY' });
        is $token, 'PASSED-BY-OCP-APPLY', 'handed through unchanged';
    };

    subtest "$task: the Rexfile mints no token of its own" => sub {
        token_handed_over($task, {});
        ok !(grep { m{/dev/urandom|server/token} } OCPTest::Rexfile->commands),
            'no token generation or token read in the Rexfile itself';
    };
}

done_testing;

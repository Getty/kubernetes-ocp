#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Apply::Network;
use OCP::Cmd::Apply::K8s;
use OCP::Drift;

#
# k198: the cert-manager upgrade used to be a client-side `kubectl apply` on the
# node, which mixed field managers with the installation's server-side apply and
# put kubectl on a code path that has none by house rule. It is now the same
# server-side apply, from the CLI.
#

my @applied;
my $polled;
{
    no warnings 'redefine';
    local *HTTP::Tiny::get = sub {
        my ($s, $url) = @_;
        push @applied, "GET $url";
        return { success => 1, content => "kind: Namespace\nmetadata:\n  name: cert-manager\n" };
    };
    local *OCP::Cmd::Apply::K8s::server_side_apply = sub {
        my ($self, $api, $res) = @_;
        push @applied, "SSA $res->{kind}/$res->{metadata}{name}";
    };
    local *OCP::Cmd::Apply::K8s::poll_deployment_ready = sub {
        my ($self, $api, $name, $ns, $t) = @_;
        $polled = "$ns/$name";
        return 1;
    };

    my $self = bless {}, 'FakeCmd';
    ok OCP::Cmd::Apply::Network::upgrade_cert_manager($self, {}, 'v1.19.0'), 'upgrade succeeds';
}

like $applied[0], qr{releases/download/v1\.19\.0/cert-manager\.yaml}, 'downloads the requested version';
is $applied[1], 'SSA Namespace/cert-manager', 'applies server-side';
is $polled, 'cert-manager/cert-manager', 'waits for the Deployment';

{
    no warnings 'redefine';
    local *HTTP::Tiny::get = sub { { success => 1, content => "kind: Namespace\nmetadata:\n  name: x\n" } };
    local *OCP::Cmd::Apply::K8s::server_side_apply = sub { };
    local *OCP::Cmd::Apply::K8s::poll_deployment_ready = sub { 0 };
    ok !eval { OCP::Cmd::Apply::Network::upgrade_cert_manager(bless({}, 'FakeCmd'), {}, 'v1.19.0'); 1 },
        'a Deployment that does not become ready is an error';
    like $@, qr/not ready after the upgrade/, 'that says so';
}

# The drift entry for cert-manager asks for the API remedy.
my ($probe) = grep { $_->{component} eq 'cert_manager' } @OCP::Drift::COMPONENT_PROBES;
is $probe->{remedy_type}, 'api', 'the drift probe names an API remedy';

done_testing;

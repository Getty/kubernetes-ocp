#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

#
# k161: RKE2 v1.37+ ships its own rke2-gateway-api-crd chart, which would
# overwrite the Gateway API CRDs OCP applies (OCP stays their owner). OCP calls
# install_server directly, so the disable list is OCP's to hand over: the
# distribution's default list plus that chart. RKE2 ignores a chart name it does
# not ship (rex-rancher: Server.pm, `disable`), so the name goes in whatever the
# pinned version is -- no version comparison to get wrong. K3s has no such chart
# and keeps its own default.
#

sub disable_handed_over {
    my ($task) = @_;
    OCPTest::Rexfile->reset;
    OCPTest::Rexfile->run_task($task, {});
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Server::install_server');
    return $o && $o->{disable};
}

subtest 'rke2: default disable list plus rke2-gateway-api-crd' => sub {
    my $d = disable_handed_over('install_rke2_server');
    is ref $d, 'ARRAY', 'a list is handed over' or return;
    ok scalar(grep { $_ eq 'rke2-gateway-api-crd' } @$d), 'rke2-gateway-api-crd is disabled';
    for my $chart (qw( rke2-ingress-nginx rke2-traefik rke2-traefik-crd )) {
        ok scalar(grep { $_ eq $chart } @$d), "the library default $chart stays disabled";
    }
};

subtest 'k3s: no rke2 chart in its list' => sub {
    my $d = disable_handed_over('install_k3s_server');
    ok !$d || !grep({ /gateway-api-crd/ } @$d), 'no gateway-api-crd chart';
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

use lib 'lib';

#
# A `local` control plane resolves its own address -- k152.
#
# `ocp apply` over an existing local-CP cluster (provider: local, dev mode)
# could not find the control plane's address:
#
#   [!!] No control plane address known, cannot run upgrade_cert_manager.
#   Control Plane: police1 ()
#
# and OCP::Cmd::Apply::Health printed "Use of uninitialized value $args{cp_ip}".
# The CP OCPNode carried the IP (ensure_cp_ocpnode wrote police1 = 10.5.10.5),
# but every reader of the control-plane address goes through
# OCP::Config::cluster_status, which for a local CP returned {} -- no node was
# recorded in .ocp/status.yaml and the spec pins neither public_ip nor host.
# So the version-drift remedies (upgrade_cert_manager) never ran and the ssh
# worker join had no server URL, until the operator set control_planes.public_ip
# by hand.
#
# The fix: cluster_status resolves a local CP's address through the provider
# (advertised_host -- the routable default-route source IP, else 127.0.0.1),
# exactly what bootstrap already advertised. ssh pins host and hetzner pins
# public_ip in the spec, so neither reaches the new branch.
#

use OCP::Config;
use OCP::Provider::Local;
use OCP::Cmd::Apply::Drift;

# Build a real on-disk project with the given control_planes: block.
sub local_config {
    my ($cp_yaml) = @_;
    my $tmp = Path::Tiny->tempdir;
    $tmp->child('.ocp')->mkpath;
    $tmp->child('ocp.yaml')->spew("name: cihq\n$cp_yaml");
    my $config = OCP::Config->new(file => $tmp->child('ocp.yaml')->stringify);
    # spec is lazy; force it now, while the tempdir still exists -- it is
    # cleaned up when this sub returns and $tmp goes out of scope.
    $config->spec;
    return $config;
}

sub capture_stdout (&) {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $rc;
    {
        local *STDOUT = $fh;
        $rc = $code->();
    }
    return ($out, $rc);
}

#
# 1. The root cause: a local CP with nothing pinned still yields an address.
#
subtest 'local cluster_status resolves the advertised address' => sub {
    my $config = local_config("control_planes:\n  provider: local\n");

    # Replace the routing-table probe so the test never depends on the host's
    # network -- this is the seam OCP::Provider::Local documents for exactly
    # this purpose.
    no warnings 'redefine';
    local *OCP::Provider::Local::_default_route_source_ip = sub { '10.5.10.5' };

    my $status = $config->cluster_status;
    is $status->{public_ip}, '10.5.10.5',
        'cluster_status hands back the routable advertised IP, not {}';
    is $status->{name}, 'cp-1', 'and a name so downstream readers can print it';
};

#
# 2. No route to be found: still an address (127.0.0.1), never the empty {}
#    that produced "No control plane address known".
#
subtest 'local cluster_status falls back to 127.0.0.1 when no route resolves' => sub {
    my $config = local_config("control_planes:\n  provider: local\n");

    no warnings 'redefine';
    local *OCP::Provider::Local::_default_route_source_ip = sub { undef };

    my $status = $config->cluster_status;
    is $status->{public_ip}, '127.0.0.1',
        'the loopback fallback is still a usable, non-empty address';
};

#
# 3. The reported symptom, end to end: the reconcile-path Rex remedy no longer
#    aborts with "No control plane address known" on a local CP. It now gets a
#    host and proceeds -- here to the "could not get a key" decline, which is a
#    different, later outcome and proves the address guard was cleared.
#
subtest 'a drift remedy on a local CP gets a host instead of "no address"' => sub {
    my $config = local_config("control_planes:\n  provider: local\n");

    no warnings 'redefine';
    local *OCP::Provider::Local::_default_route_source_ip = sub { '10.5.10.5' };

    # run_remedy needs $self->cluster_ssh_key; returning undef routes it to the
    # key-decline branch AFTER the host guard, without touching SSH or Rex.
    my $fake_self = bless {}, 'FakeApply';
    my $entry = {
        label     => 'cert-manager',
        component => 'cert_manager',
        remedy    => { type => 'rex', task => 'upgrade_cert_manager' },
    };

    my ($out, $ran) = capture_stdout {
        OCP::Cmd::Apply::Drift::run_remedy($fake_self, $config, $entry);
    };

    unlike $out, qr/No control plane address known/,
        'the k152 error is gone -- a host was resolved for the local CP';
    like $out, qr/needs SSH access to the control plane/,
        'and the remedy reaches the later (key) stage, host in hand';
    ok !$ran, 'still returns falsy -- no key here, so nothing was applied';
};

#
# 4. Regression guard: ssh and hetzner never reach the local resolver.
#
subtest 'ssh and hetzner are untouched by the local branch' => sub {
    # If the local resolver fires for a non-local provider, this blows up
    # loudly instead of quietly returning a wrong address.
    no warnings 'redefine';
    local *OCP::Provider::Local::_default_route_source_ip =
        sub { die "local resolver must not run for a non-local provider\n" };

    my $ssh = local_config("control_planes:\n  provider: ssh\n  host: cortex.example\n");
    is $ssh->cluster_status->{public_ip}, 'cortex.example',
        'ssh still uses spec.host, resolver never consulted';

    my $htz = local_config("control_planes:\n  provider: hetzner\n"
        . "  server_type: cx32\n  location: fsn1\n");
    is_deeply $htz->cluster_status, {},
        'hetzner with no pinned public_ip is unchanged: still {}';
};

package FakeApply {
    # The reconcile path asks the command object for the cluster SSH key; a run
    # with no key in hand is the ordinary no-terminal case (OCP::ClusterKey),
    # which run_remedy turns into a printed decline, not an exception.
    sub cluster_ssh_key { return undef }
}

done_testing;

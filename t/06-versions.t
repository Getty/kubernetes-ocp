#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::Versions;

#
# Test: get_versions returns manifest for known version
#

{
    my $v = OCP::Versions->get_versions('0.001');
    ok($v, 'get_versions returns data for 0.001');
    ok($v->{components}, 'manifest has components');
    ok($v->{notes}, 'manifest has notes');
}

#
# Test: get_versions returns undef for unknown version
#

{
    my $v = OCP::Versions->get_versions('99.99.99');
    is($v, undef, 'get_versions returns undef for unknown version');
}

#
# Test: get_versions defaults to current VERSION
#

{
    my $v = OCP::Versions->get_versions();
    ok($v, 'get_versions defaults to current version');
    is_deeply($v, OCP::Versions->get_versions('0.001'), 'default matches 0.001');
}

#
# Test: get_component_version
#

{
    is(OCP::Versions->get_component_version('cilium'), '1.20.0', 'cilium version');
    is(OCP::Versions->get_component_version('rke2'), 'v1.36.3+rke2r1', 'rke2 version');
    is(OCP::Versions->get_component_version('k3s'), 'v1.36.3+k3s1', 'k3s version');
    is(OCP::Versions->get_component_version('cilium_cli'), 'v0.19.7', 'cilium_cli version');
    is(OCP::Versions->get_component_version('cert_manager'), 'v1.21.1', 'cert_manager version');
    is(OCP::Versions->get_component_version('traefik'), undef, 'traefik gone (replaced by Cilium Gateway API)');
}

#
# Test: get_component_version for missing component
#

{
    is(OCP::Versions->get_component_version('nonexistent'), undef, 'unknown component returns undef');
    is(OCP::Versions->get_component_version('cilium', '99.99.99'), undef, 'unknown version returns undef');
}

#
# Test: GPU component versions
#

{
    is(OCP::Versions->get_component_version('gpu_operator'), 'v26.3.3', 'gpu_operator version');
    is(OCP::Versions->get_component_version('nvidia_toolkit'), 'v1.19.1', 'nvidia_toolkit version');
    is(OCP::Versions->get_component_version('nvidia_device_plugin'), 'v0.19.3', 'nvidia_device_plugin version');
    is(OCP::Versions->get_component_version('dcgm_exporter'), '4.5.3-4.8.2-distroless', 'dcgm_exporter version');
    is(OCP::Versions->get_component_version('nfd'), 'v0.18.3', 'nfd version');
}

#
# Test: list_components
#

{
    my @components = sort OCP::Versions->list_components();
    ok(scalar @components >= 11, 'at least 11 components (incl. GPU)');
    ok((grep { $_ eq 'cilium' } @components), 'cilium in components list');
    ok((grep { $_ eq 'rke2' } @components), 'rke2 in components list');
    ok((grep { $_ eq 'k3s' } @components), 'k3s in components list');
    ok((grep { $_ eq 'cert_manager' } @components), 'cert_manager in components list');
    ok(!(grep { $_ eq 'traefik' } @components), 'traefik not in components list');
    ok((grep { $_ eq 'gpu_operator' } @components), 'gpu_operator in components list');
    ok((grep { $_ eq 'nfd' } @components), 'nfd in components list');
}

#
# Test: list_components for unknown version
#

{
    my @c = OCP::Versions->list_components('99.99.99');
    is(scalar @c, 0, 'list_components returns empty for unknown version');
}

#
# Test: has_breaking_changes (0.001 has none)
#

{
    ok(!OCP::Versions->has_breaking_changes('0.0.1', '0.001'), 'no breaking changes in 0.001');
}

#
# Test: get_breaking_changes returns empty arrayref
#

{
    my $changes = OCP::Versions->get_breaking_changes('0.0.1', '0.001');
    is_deeply($changes, [], 'no breaking changes');
}

#
# Test: get_manual_steps returns empty arrayref
#

{
    my $steps = OCP::Versions->get_manual_steps('0.0.1', '0.001');
    is_deeply($steps, [], 'no manual steps');
}

#
# Test: unknown target version returns undef
#

{
    is(OCP::Versions->get_breaking_changes('0.001', '99.99.99'), undef, 'breaking changes for unknown returns undef');
    is(OCP::Versions->get_manual_steps('0.001', '99.99.99'), undef, 'manual steps for unknown returns undef');
}

done_testing;

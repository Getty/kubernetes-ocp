#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# The share/Rexfile used to carry CILIUM_VERSION / CILIUM_CLI_VERSION /
# GATEWAY_API_VERSION `use constant` pins as a hand-run fallback. They
# drifted behind OCP::Versions (1.19.2 vs 1.20.0, v0.18.5 vs v0.19.7), so
# every fresh cluster came up on an older Cilium and OCP::Drift reported
# drift against the distribution's own manifest on the very next status
# call (ADR 0014). The constants are gone now; the only source of truth
# is OCP::Versions, and the Rexfile reads each pin from task_params or
# from an explicit OCP_*_VERSION env var, dying loudly if neither is set.
#

my $root    = path(__FILE__)->parent->parent;
my $rexfile = $root->child('share/Rexfile');

plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

my $src = $rexfile->slurp_utf8;

subtest 'no Cilium pin lives in the Rexfile any more' => sub {
    # ADR 0014 says every pin lives exactly once, in OCP::Versions. The
    # three Cilium-family constants used to violate that — checking by
    # name keeps the trap closed if a fourth constant shows up.
    my @leftover = $src =~ /^\s*use constant \s+\w*VERSION\b/gmx;
    is_deeply \@leftover, [],
        'no use-constant VERSION lines remain in the Rexfile'
        or diag "Constant lines still present: @leftover";

    my @cst_names = $src =~ /use constant \s+ (CILIUM|CILIUM_CLI|GATEWAY_API)_VERSION \b/gx;
    is_deeply \@cst_names, [],
        'no Cilium-family version constants remain'
        or diag "Leftover: @cst_names";

    my @bodies
        = $src =~ /(\bCILIUM_VERSION\b|\bCILIUM_CLI_VERSION\b|\bGATEWAY_API_VERSION\b)/g;
    is_deeply \@bodies, [],
        'no identifier references to the old constants remain'
        or diag "Bare references to the old constants: @bodies";
};

subtest 'install_cilium takes every version from task_params or ENV' => sub {
    # Each of the three reads has the same shape: task_params field, ENV
    # fallback, hard fail.
    for my $case (
        { name => 'cilium',     env => 'OCP_CILIUM_VERSION',     param => 'version' },
        { name => 'cilium cli', env => 'OCP_CILIUM_CLI_VERSION', param => 'cli_version' },
        { name => 'gateway',    env => 'OCP_GATEWAY_API_VERSION', param => 'gateway_api_version' },
    ) {
        my $pattern = qr/
            my \ \$\w* \s* = \s* \$params->\{ \Q$case->{param}\E \} \s*
                \/\/ \s* \$ENV\{ \Q$case->{env}\E \} \s*
                \n \s* or \s* die
            /x;

        like $src, $pattern,
            "$case->{name} version: \$params->{$case->{param}} \\/\\/ \$ENV{$case->{env}} \\ or die";
    }
};

subtest 'install_cilium actually fails loud when both channels are empty' => sub {
    # Extract the three `// ... or die` expressions verbatim and eval them
    # against an empty $params and an unset $ENV. The syntax-checking
    # through perl itself is the regression check: if the constants ever
    # come back, this is the layer that catches it.
    my @exprs = $src =~ /
        ( my \s+ \$ \w+ \s* = \s* \$params->\{ \w+ \} \s*
            \/\/ \s* \$ENV\{ \w+ \} \s*
            \n \s* or \s* die [^;]+ ; )
    /gx;

    cmp_ok scalar(@exprs), '>=', 4,
        'at least four fail-loud reads exist (install_cilium x3 + upgrade_cilium cli_version)'
        or diag "Found only: " . scalar(@exprs);

    for my $expr (@exprs) {
        my $params = {};
        local %ENV = (%ENV);
        delete $ENV{OCP_CILIUM_VERSION};
        delete $ENV{OCP_CILIUM_CLI_VERSION};
        delete $ENV{OCP_GATEWAY_API_VERSION};

        my $died = !eval "$expr; 1";
        ok $died, "the expression dies when both \$params and \$ENV are empty\n  $expr"
            or diag "Survived: $expr";
        like $@, qr/required/, 'and the error names the missing input'
            or diag "Died with: $@";
    }
};

subtest 'OCP::Rex::install_server is the only thing that has to send the pins' => sub {
    # Installing the cluster is the one path that has to land a Cilium on
    # a node. The drift remedy is an upgrade task and ends with the same
    # `version` parameter it already required. Each component version
    # travels through $opts{cilium_*} || OCP::Versions->get_component_version(...)
    # in install_server, and the slug in get_component_version is what
    # names the pin. If any of these slugs changes, Versions.pm and the
    # Rexfile both have to follow — the rest of the test asserts that.
    my $rex = $root->child('lib/OCP/Rex.pm')->slurp_utf8;

    for my $pair (
        [ 'cilium version'       => 'cilium',         'cilium_version' ],
        [ 'cilium CLI version'   => 'cilium_cli',     'cilium_cli_version' ],
        [ 'gateway API version'  => 'gateway_api',    'gateway_api_version' ],
    ) {
        my ($label, $slug, $param) = @$pair;
        like $rex, qr/\Q$param\E[\s\S]{0,120}?get_component_version\(\s*'\Q$slug\E'\s*\)/,
            "install_server passes the $label pin from OCP::Versions";
    }
};

subtest 'the pinned manifest matches what the Rexfile can ask for' => sub {
    use OCP::Versions;
    for my $component (qw(cilium cilium_cli gateway_api)) {
        my $v = OCP::Versions->get_component_version($component);
        ok defined $v && length $v,
            "$component is pinned in OCP::Versions (got: " . ($v // '<undef>') . ')';
    }
};

done_testing;

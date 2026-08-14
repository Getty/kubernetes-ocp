#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# After Phase 10, OCP::Cmd::Apply::execute is a thin dispatcher:
#   - auth/key preparation (one inline block — small enough to live here)
#   - bootstrap_control_plane call
#   - deploy call
#   - finish_apply call
#
# What it must NOT be is the place that knows about specific components.
# Adding a component must not require editing execute(). If you find
# yourself adding a print + setup_x + [ok] block here, the component
# belongs in one of the phase modules and execute() should not know
# the name.
#

my $src = path('lib/OCP/Cmd/Apply.pm')->slurp_utf8;

subtest 'execute dispatches to the phase modules' => sub {
    my ($execute) = $src =~ /^sub execute \{\n(.*?)\n\}\s*$/ms;
    ok defined $execute, 'execute() exists';

    # execute() calls forwarders on $self (preserves the test surface)
    # which in turn call the phase modules. The bootstrap / deploy /
    # finish calls are direct — those are the seams that prove this is
    # a dispatcher and not the implementation.
    like $execute, qr/\$self->_reconcile_components/,
        'reconcile path goes through the forwarder seam';
    like $execute, qr/OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane/,
        'fresh-deploy path delegates to OCP::Cmd::Apply::Bootstrap';
    like $execute, qr/OCP::Cmd::Apply::Deploy::deploy/,
        'post-bootstrap deploy delegates to OCP::Cmd::Apply::Deploy';
    like $execute, qr/\$self->_finish_apply/,
        'both paths return through the shared finisher';

    # Every forwarder execute calls must actually delegate. A forwarder
    # that just inlines the implementation again is a smell — it has
    # become the implementation, the test grep would not catch it, and
    # the module extraction did not happen.
    for my $pair (
        ['_reconcile_components' => 'OCP::Cmd::Apply::Drift::reconcile_components'],
        ['_setup_ssh_key'        => 'OCP::Cmd::Apply::Bootstrap::setup_ssh_key'],
        ['_cp_identity'          => 'OCP::Cmd::Apply::Bootstrap::cp_identity'],
        ['_finish_apply'         => 'OCP::Cmd::Apply::Health::finish'],
    ) {
        my ($method, $target) = @$pair;
        my ($body) = $src =~ /^sub \Q$method\E \{\n(.*?)\n\}\s*$/ms;
        ok defined $body, "$method has a body";
        like $body, qr/\Q$target\E/,
            "$method delegates to $target";
    }
};

subtest 'execute does not own component logic' => sub {
    my ($execute) = $src =~ /^sub execute \{\n(.*?)\n\}\s*$/ms;

    # Every component setup call below has moved to a phase module.
    # If any of these regexes match, execute has grown component logic
    # that belongs somewhere else — either the component needs to be
    # added to Deploy.pm, or the dispatcher needs to call a new phase
    # module.
    my @forbidden = (
        ['_setup_registry'         => qr/\$self->_setup_registry\b/],
        ['_setup_nfd'              => qr/\$self->_setup_nfd\b/],
        ['_setup_gpu_operator'     => qr/\$self->_setup_gpu_operator\b/],
        ['_apply_cert_manager'     => qr/\$self->_apply_cert_manager\b/],
        ['_setup_cilium_gateway'   => qr/\$self->_setup_cilium_gateway\b/],
        ['_setup_lb_ipam'          => qr/\$self->_setup_lb_ipam\b/],
        ['_configure_registry_dns' => qr/\$self->_configure_registry_dns\b/],
        ['_ensure_crds'            => qr/\$self->_ensure_crds\b/],
        ['_ensure_providers'       => qr/\$self->_ensure_providers\b/],
        ['_ensure_cp_ocpnode'      => qr/\$self->_ensure_cp_ocpnode\b/],
        ['_ensure_worker_ocpnodes' => qr/\$self->_ensure_worker_ocpnodes\b/],
        ['_drive_workers'          => qr/\$self->_drive_workers\b/],
        ['_ensure_robocop'         => qr/\$self->_ensure_robocop\b/],
        ['_wait_robocop_ready'     => qr/\$self->_wait_robocop_ready\b/],
        ['_print_worker_status'    => qr/\$self->_print_worker_status\b/],
        ['install_server'          => qr/install_server\b/],
    );
    for my $pair (@forbidden) {
        my ($name, $re) = @$pair;
        unlike $execute, $re, "execute does not own $name";
    }
};

subtest 'execute stays within the dispatcher size budget' => sub {
    my ($execute) = $src =~ /^sub execute \{\n(.*?)\n\}\s*$/ms;
    my $lines = () = $execute =~ /\n/g;

    # The brief said "dispatcher only, ~400 lines for Apply.pm". execute()
    # is the bulk of the non-forwarder code; the rest is just option
    # declarations and the _cp_identity / _dist_label / _setup_ssh_key
    # forwarders. A hard ceiling on execute() is what keeps the
    # dispatcher honest — adding inline logic here will trip it.
    ok $lines < 200,
        "execute() body is $lines lines (< 200)";
};

subtest 'apply.pm is a dispatcher, not the implementation' => sub {
    # The brief target is ~400 lines for Apply.pm. With all phase
    # modules extracted, Apply.pm is mostly forwarders — anything past
    # that means we have stopped dispatching and started re-implementing.
    my $total_lines = () = $src =~ /\n/g;
    ok $total_lines < 700,
        "Apply.pm is $total_lines lines (< 700)";
};

done_testing;

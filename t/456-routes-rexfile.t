#!/usr/bin/env perl
# karr k456: the install tasks write routes: into the node's network
# configuration, before RKE2/K3s start, so that they survive a reboot and the
# private interface going down and up (a DHCP renew, a re-plug), whoever
# manages that interface on the image.
#
# The claims:
#
#   1. every install task (RKE2/K3s server and agent) with routes writes
#      /etc/ocp/routes ("TO VIA" lines), the ocp-routes script, the
#      ocp-routes.service oneshot (after network-online, before the rke2/k3s
#      units, enabled) and the ocp-routes.timer (every minute), the dhclient
#      exit hook, and the ifupdown hook where /etc/network/if-up.d/ is there
#      (not where only /etc/network/interfaces is: netplan images, k474); it
#      sets the routes at once and fails the install when they cannot be set
#      -- all of it after the checks up front and before prepare_node and the
#      install, so Kubernetes starts with them
#   2. routes that are none -- no list, a to that is no CIDR, a via that is
#      no address (an unresolved gateway among them), anything a shell would
#      read more into -- die before the host is touched
#   3. without a routes parameter nothing of it happens: no file, no command
#   4. a route an earlier run set and this one does not list is deleted from
#      the kernel; an empty list removes OCP's routes, units and files, and is
#      a no-op on a node OCP never gave routes
#   5. the script itself: sets each route with `ip route replace TO via VIA`
#      (idempotent), skips comments, retries with --wait, exits non-zero
#      naming what it could not set; it and the hooks are valid sh
#
# Network-free: the Rexfile runs in OCPTest::Rexfile's sandbox; the script
# runs against a stand-in `ip` that only records.

use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';
use lib 't/lib';
use OCPTest::Rexfile;

no warnings 'once';

# The harness answers is_file, not is_dir: the one directory _ensure_routes
# asks about is answered here, recorded like is_file.
my %IS_DIR;
OCPTest::Rexfile->load;
{
    no warnings 'redefine';
    *OCPTest::Rexfile::Sandbox::is_dir = sub {
        push @OCPTest::Rexfile::CALLS, { name => 'is_dir', args => [@_] };
        return $IS_DIR{ $_[0] } ? 1 : 0;
    };
}

my @R = ({ to => '10.230.30.0/24', via => '10.200.0.1' }, { to => '10.230.31.0/24', via => '10.200.0.9' });
my @TASKS = map { ("install_${_}_server", "install_${_}_agent") } qw( rke2 k3s );

sub run_install {
    my ($task, %o) = @_;
    OCPTest::Rexfile->reset;
    %OCPTest::Rexfile::IS_FILE = %{ $o{is_file} // {} };
    %OCPTest::Rexfile::CAT     = %{ $o{cat}     // {} };
    %IS_DIR                    = %{ $o{is_dir}  // {} };
    local $OCPTest::Rexfile::RUN = $o{run} // sub { ('', 0) };
    my $err = '';
    my $out = eval {
        local *STDERR;
        open STDERR, '>', \$err or die $!;
        OCPTest::Rexfile->run_task($task, {
            token => 't',
            ($task =~ /_agent\z/ ? (server => 'https://10.200.0.2:9345') : ()),
            %{ $o{params} // {} },
        });
    };
    return ($out, $@);
}

sub files_written {
    return { map { $_->{args}[0] => $_->{args}[1] } OCPTest::Rexfile->calls('file') };
}

sub idx { my ($pred) = @_; OCPTest::Rexfile->index_of($pred) }

# ---------------------------------------------------------------- 1

subtest 'routes are written and set, before prepare_node and the install' => sub {
    for my $task (@TASKS) {
        my ($out, $err) = run_install($task, params => { routes => \@R },
            is_dir => { '/etc/network/if-up.d' => 1 });
        is $err, '', "$task: ran" or next;

        my $f = files_written();
        is $f->{'/etc/ocp/routes'}{content},
            "# Written by OCP (k456) from ocp.yaml's routes: -- TO VIA, one per line\n"
            . "10.230.30.0/24 10.200.0.1\n10.230.31.0/24 10.200.0.9\n", "$task: /etc/ocp/routes";
        is $f->{'/usr/local/sbin/ocp-routes'}{mode}, '0755', "$task: the script, executable";
        my $unit = $f->{'/etc/systemd/system/ocp-routes.service'}{content} // '';
        like $unit, qr/^After=network-online\.target$/m, "$task: the unit runs after network-online";
        like $unit, qr/^Before=rke2-server\.service rke2-agent\.service k3s\.service k3s-agent\.service$/m,
            "$task: and before the rke2/k3s units";
        like $unit, qr/^Type=oneshot$/m, "$task: a oneshot";
        like $unit, qr/^WantedBy=multi-user\.target$/m, "$task: at every boot";
        like $f->{'/etc/systemd/system/ocp-routes.timer'}{content} // '', qr/^OnUnitInactiveSec=1min$/m,
            "$task: the timer, every minute";
        like $f->{'/etc/dhcp/dhclient-exit-hooks.d/ocp-routes'}{content} // '', qr/BOUND\|RENEW\|REBIND\|REBOOT/,
            "$task: the dhclient hook, on a bound lease";
        is $f->{'/etc/network/if-up.d/ocp-routes'}{mode}, '0755', "$task: the ifupdown hook";

        my @cmds = OCPTest::Rexfile->commands;
        ok grep({ /systemctl enable ocp-routes\.service ocp-routes\.timer/ } @cmds), "$task: enabled";
        ok grep({ $_ eq '/usr/local/sbin/ocp-routes --wait 30 2>&1' } @cmds), "$task: set now";
        like $out, qr/Static routes set: 10\.230\.30\.0\/24 via 10\.200\.0\.1, 10\.230\.31\.0\/24 via 10\.200\.0\.9/,
            "$task: said";

        my $side = $task =~ /_agent\z/ ? 'Agent::preflight_agent' : 'Server::preflight_server';
        my $first_file = idx(sub { $_->{name} eq 'file' });
        ok idx(sub { $_->{name} eq "Rex::Rancher::$side" }) < $first_file, "$task: after the checks up front";
        ok $first_file < idx(sub { $_->{name} eq 'do_task' && $_->{args}[0] eq 'prepare_node' }),
            "$task: before prepare_node";
        my $install = $task =~ /_agent\z/ ? 'Agent::install_agent' : 'Server::install_server';
        my $set = idx(sub { $_->{name} eq 'run' && $_->{args}[0] =~ /ocp-routes --wait/ });
        ok $set < idx(sub { $_->{name} eq "Rex::Rancher::$install" }), "$task: set before the install";
    }

    run_install('install_rke2_agent', params => { routes => \@R });
    ok !exists files_written()->{'/etc/network/if-up.d/ocp-routes'}, 'no ifupdown: no if-up.d hook';

    # k474: /etc/network/interfaces without ifupdown's if-up.d (netplan
    # images): the hook would have nowhere to go, so none is written and the
    # install carries on -- the directory is what counts, not the file.
    my ($nout, $nerr) = run_install('install_rke2_agent', params => { routes => \@R },
        is_file => { '/etc/network/interfaces' => 1 });
    is $nerr, '', 'interfaces but no if-up.d: the install runs';
    ok !exists files_written()->{'/etc/network/if-up.d/ocp-routes'}, '... without the if-up.d hook';
    ok grep({ $_->{args}[0] eq '/etc/network/if-up.d' } OCPTest::Rexfile->calls('is_dir')),
        '... the if-up.d directory is what was asked';
    ok grep({ $_ eq '/usr/local/sbin/ocp-routes --wait 30 2>&1' } OCPTest::Rexfile->commands),
        '... and the routes are still set';

    my ($out, $err) = run_install('install_rke2_agent', params => { routes => \@R },
        run => sub { $_[0] =~ /ocp-routes --wait/ ? ("ocp-routes: could not set: 10.230.30.0/24 via 10.200.0.1;\n", 1) : ('', 0) });
    like $err, qr/\Aroutes: ocp-routes: could not set: 10\.230\.30\.0\/24 via 10\.200\.0\.1;/,
        'routes that cannot be set fail the install, with what the script said';
    ok !OCPTest::Rexfile->calls('Rex::Rancher::Agent::install_agent'), '... before the agent is installed';

    ($out, $err) = run_install('install_rke2_agent', params => { routes => \@R },
        run => sub { $_[0] =~ /systemctl enable/ ? ('', 1) : ('', 0) });
    like $err, qr/\Aroutes: could not enable ocp-routes\.service/, 'a unit that cannot be enabled fails it too';
};

# ---------------------------------------------------------------- 2

subtest 'routes that are none die before the host is touched' => sub {
    for my $bad ('10.230.30.0/24', [ '10.230.30.0/24' ],
                 [ { to => '10.230.30.0/24', via => 'gateway' } ],
                 [ { to => '10.230.30.0/24; reboot', via => '10.200.0.1' } ],
                 [ { to => '10.230.30.0/24', via => '10.200.0.1 dev eth0' } ],
                 [ { to => '10.230.30.0/24', via => '$(reboot)' } ],
                 [ { to => '10.230.30.0', via => '10.200.0.1' } ],
                 [ { via => '10.200.0.1' } ]) {
        for my $task (qw( install_rke2_server install_k3s_agent )) {
            my (undef, $err) = run_install($task, params => { routes => $bad });
            like $err, qr/\Aroutes/, "$task: refused";
            my @touched = grep { $_->{name} =~ /\A(?:run|file|unlink|do_task)\z|::(?:preflight|install)_/ }
                @OCPTest::Rexfile::CALLS;
            is_deeply \@touched, [], "$task: nothing run, written or checked";
        }
    }
};

# ---------------------------------------------------------------- 3

subtest 'without a routes parameter the node is left alone' => sub {
    for my $task (@TASKS) {
        my (undef, $err) = run_install($task);
        is $err, '', "$task: ran";
        ok !grep({ $_->{args}[0] =~ m{ocp|/etc/dhcp|if-up\.d} } OCPTest::Rexfile->calls('file')), "$task: no file of it";
        ok !grep({ /ocp-routes|ip route/ } OCPTest::Rexfile->commands), "$task: no command of it";
        ok !OCPTest::Rexfile->calls('is_file') || !grep({ $_->{args}[0] eq '/etc/ocp/routes' }
            OCPTest::Rexfile->calls('is_file')), "$task: not even looked at";
    }
};

# ---------------------------------------------------------------- 4

my $HAD = "# Written by OCP (k456)\n10.230.30.0/24 10.200.0.1\n10.230.40.0/24 10.200.0.1\n";

subtest 'what an earlier run set and this one does not list goes' => sub {
    my ($out, $err) = run_install('install_rke2_agent', params => { routes => [ $R[0] ] },
        is_file => { '/etc/ocp/routes' => 1 }, cat => { '/etc/ocp/routes' => $HAD });
    is $err, '', 'ran';
    my @cmds = OCPTest::Rexfile->commands;
    is_deeply [ grep { /ip route del/ } @cmds ], [ 'ip route del 10.230.40.0/24 via 10.200.0.1' ],
        'the dropped route is deleted, the kept one is not';
    like $out, qr/Removed route 10\.230\.40\.0\/24 via 10\.200\.0\.1/, 'said';
    is files_written()->{'/etc/ocp/routes'}{content} =~ tr/\n//, 2, 'the file lists the one route left';

    ($out, $err) = run_install('install_rke2_server', params => { routes => [] },
        is_file => { map { $_ => 1 } '/etc/ocp/routes', '/usr/local/sbin/ocp-routes',
                     '/etc/systemd/system/ocp-routes.service', '/etc/systemd/system/ocp-routes.timer',
                     '/etc/dhcp/dhclient-exit-hooks.d/ocp-routes' },
        cat => { '/etc/ocp/routes' => $HAD });
    is $err, '', 'an empty list: ran';
    @cmds = OCPTest::Rexfile->commands;
    is_deeply [ grep { /ip route del/ } @cmds ],
        [ 'ip route del 10.230.30.0/24 via 10.200.0.1', 'ip route del 10.230.40.0/24 via 10.200.0.1' ],
        'every route deleted';
    ok grep({ $_ eq 'systemctl disable --now ocp-routes.timer ocp-routes.service' } @cmds), 'the units disabled';
    is_deeply [ sort map { $_->{args}[0] } OCPTest::Rexfile->calls('unlink') ],
        [ sort '/etc/ocp/routes', '/usr/local/sbin/ocp-routes', '/etc/systemd/system/ocp-routes.service',
               '/etc/systemd/system/ocp-routes.timer', '/etc/dhcp/dhclient-exit-hooks.d/ocp-routes' ],
        'the files removed (those there)';
    ok !OCPTest::Rexfile->calls('file'), 'nothing written';
    like $out, qr/Removed OCP's static routes/, 'said';

    ($out, $err) = run_install('install_rke2_agent', params => { routes => [] });
    is $err, '', 'an empty list on a node without routes: ran';
    ok !grep({ /ocp-routes|ip route/ } OCPTest::Rexfile->commands), '... and did nothing';
    ok !OCPTest::Rexfile->calls('unlink'), '... removed nothing';
};

# ---------------------------------------------------------------- 5

my $tmp = path(tempdir(CLEANUP => 1));
my $sh  = -x '/bin/sh' ? '/bin/sh' : undef;

SKIP: {
    skip 'no /bin/sh to run the script with', 1 unless $sh;

    subtest 'the script, against a stand-in ip' => sub {
        my $helper = OCPTest::Rexfile->helper('_routes_script');
        my $script = $helper->();
        my $conf   = $tmp->child('routes');
        my $log    = $tmp->child('ip.log');
        $script =~ s{/etc/ocp/routes}{$conf}g;
        my $file = $tmp->child('ocp-routes');
        $file->spew($script);
        my $bin = $tmp->child('bin');
        $bin->mkpath;
        # Records every call; fails a route via 10.200.0.99, the gateway that
        # is not reachable.
        $bin->child('ip')->spew("#!/bin/sh\necho \"\$*\" >> '$log'\ncase \"\$*\" in *10.200.0.99*) exit 2 ;; esac\nexit 0\n");
        chmod 0755, $bin->child('ip');
        local $ENV{PATH} = "$bin:$ENV{PATH}";

        $conf->spew("# a comment\n10.230.30.0/24 10.200.0.1\n\n10.230.31.0/24 10.200.0.9\n");
        my $out = `$sh '$file' 2>&1`;
        is $? >> 8, 0, 'exit 0' or diag $out;
        is $log->slurp, "route replace 10.230.30.0/24 via 10.200.0.1\nroute replace 10.230.31.0/24 via 10.200.0.9\n",
            'each route replaced, comments and blank lines skipped';
        `$sh '$file' 2>&1`;
        is scalar(() = $log->slurp =~ /\n/g), 4, 'run again: the same two commands again (idempotent)';

        $log->remove;
        $conf->spew("10.230.30.0/24 10.200.0.99\n");
        $out = `$sh '$file' --wait 0 2>&1`;
        is $? >> 8, 1, 'a route that cannot be set: exit 1';
        like $out, qr/could not set: 10\.230\.30\.0\/24 via 10\.200\.0\.99;/, 'naming it';

        $log->remove;
        $out = `$sh '$file' --wait 3 2>&1`;
        cmp_ok scalar(() = $log->slurp =~ /\n/g), '>=', 2, '--wait: tried again before giving up';

        $conf->remove;
        $out = `$sh '$file' 2>&1`;
        is $? >> 8, 0, 'no /etc/ocp/routes: nothing to do, exit 0';

        for my $hook (qw( _routes_dhclient_hook _routes_ifup_hook )) {
            my $f = $tmp->child($hook);
            $f->spew(OCPTest::Rexfile->helper($hook)->());
            `$sh -n '$f' 2>&1`;
            is $? >> 8, 0, "$hook: valid sh";
        }
    };
}

done_testing;

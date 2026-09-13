#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS;
use Path::Tiny qw(path);

use OCP::Rex;

# This file mocks OCP::Rex::run with a fixed 4-arg (\@cmd,\undef,\$out,\$err)
# signature -- the non-debug call shape. OCP_REX_DEBUG switches run_task to a
# coderef-tee shape, so keep it off here regardless of the ambient environment.
delete local $ENV{OCP_REX_DEBUG};

#
# Task parameters reach the Rexfile through REX_TASK_PARAMS, never through
# the command line. This went unnoticed for a long time: OCP::Rex encoded the
# JSON but no task ever read the variable, so every parameter silently
# vanished and `upgrade_cilium` died with "version parameter required".
#
# The command line is deliberately kept free of parameters — `install_rke2_agent`
# receives the cluster join token, and arguments are world-readable via `ps`.
#

my $tmp = tempdir(CLEANUP => 1);
my $key = path($tmp)->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub key');

# Capture what run_task hands to IPC::Run instead of executing rex.
my @captured;

{
    no warnings 'redefine';
    *OCP::Rex::run = sub {
        my ($cmd, $in, $out, $err) = @_;
        push @captured, {
            cmd    => [@$cmd],
            params => $ENV{REX_TASK_PARAMS},
        };
        $$out = '';
        $$err = '';
        return 1;
    };
}

# The Rexfile lookup insists on a real file; point it at a stub.
my $rexfile = path($tmp)->child('Rexfile');
$rexfile->spew("# stub\n");
{
    no warnings 'redefine';
    *OCP::Rex::_find_rexfile = sub { $rexfile->stringify };
}

sub run_task_capturing {
    my (%params) = @_;
    my $task = delete $params{_task} // 'upgrade_cilium';
    @captured = ();
    OCP::Rex->new(host => 'psyduck.example', key_file => $key->stringify)
        ->run_task($task, %params);
    return $captured[0];
}

subtest 'parameters travel as JSON in REX_TASK_PARAMS' => sub {
    my $call = run_task_capturing(version => '1.20.0');

    ok defined $call->{params}, 'REX_TASK_PARAMS was set for the child process';

    my $decoded = JSON::MaybeXS->new(utf8 => 1)->decode($call->{params});
    is_deeply $decoded, { version => '1.20.0' }, 'round-trips to the original parameters';
};

subtest 'nested structures survive' => sub {
    my $call = run_task_capturing(
        version => '1.20.0',
        gpu     => { enabled => 1, driver => '580.65.06' },
    );

    my $decoded = JSON::MaybeXS->new(utf8 => 1)->decode($call->{params});
    is_deeply $decoded->{gpu}, { enabled => 1, driver => '580.65.06' },
        'a hashref parameter arrives intact, not flattened to a string';
};

subtest 'secrets stay out of the command line' => sub {
    my $call = run_task_capturing(
        _task => 'install_rke2_agent',
        token => 'K10c0ffee::server:s3cr3t',
    );

    my $cmdline = join ' ', @{ $call->{cmd} };
    unlike $cmdline, qr/s3cr3t/, 'the join token is not visible in `ps` output';
    unlike $cmdline, qr/token/,  'not even the parameter name is passed as an argument';
    is $call->{cmd}[-1], 'install_rke2_agent', 'the task name is the final argument';
};

subtest 'no parameters means no leftover variable' => sub {
    $ENV{REX_TASK_PARAMS} = '{"stale":"from a previous task"}';
    my $call = run_task_capturing(_task => 'install_cilium');

    is $call->{params}, undef,
        'a parameterless task does not inherit the previous task parameters';
};

subtest 'the environment is restored afterwards' => sub {
    local $ENV{REX_TASK_PARAMS} = '{"outer":"value"}';
    run_task_capturing(version => '1.20.0');

    is $ENV{REX_TASK_PARAMS}, '{"outer":"value"}',
        'run_task puts back what it found';
};

#
# The original defect sat in neither half but in the gap between them: OCP::Rex
# encoded the JSON, the Rexfile never read it. Nothing failed loudly, tasks just
# saw empty parameters. So assert the far end of the handover too.
#

#
# gpu.enabled and gpu.driver were config keys nothing read: OCP::Rex forwarded
# timezone/locale/ntp but not these, so the Rexfile ran GPU detection on every
# node and `gpu.enabled: false` in ocp.yaml changed nothing.
#

subtest 'the GPU switches reach the install task' => sub {
    my $decode = sub {
        @captured = ();
        OCP::Rex->new(host => 'psyduck.example', key_file => $key->stringify)
            ->install_agent(server => 'https://cp:9345', token => 'tok', @_);
        return JSON::MaybeXS->new(utf8 => 1)->decode($captured[0]{params});
    };

    my $default = $decode->();
    is $default->{gpu}, 1, 'a caller that says nothing gets GPU handling';
    is $default->{gpu_driver}, 'host', 'with the host driver, which is what Rex installs';

    my $off = $decode->(gpu => 0);
    is $off->{gpu}, 0, 'gpu.enabled: false travels all the way to the task';

    my $operator = $decode->(gpu_driver => 'operator');
    is $operator->{gpu_driver}, 'operator', 'so does the driver mode';
};

subtest 'the Rexfile picks the parameters back up' => sub {
    my $shipped = path(__FILE__)->parent->parent->child('share', 'Rexfile');
    plan skip_all => "share/Rexfile not found at $shipped" unless -f $shipped;

    my $source = $shipped->slurp_utf8;

    like $source, qr/\bREX_TASK_PARAMS\b/,
        'the Rexfile reads the variable OCP::Rex sets';

    my @raw = $source =~ /^\s*my \$params = (shift.*)$/mg;
    is_deeply \@raw, [],
        'no task takes parameters straight off @_ — those never arrive'
        or diag "Tasks bypassing task_params(): @raw";

    my $helpers = () = $source =~ /^\s*my \$params = task_params\(shift\);/mg;
    ok $helpers > 0, "$helpers task(s) go through task_params()";
};

#
# advertised_host vs the transport host. The tls-san the install task receives
# and the kubeconfig `server` endpoint both take the ADVERTISED address, while
# rex/ssh still connect to `host`. advertised_host defaults to host, so only the
# local provider (127.0.0.1 transport, routable advertised) sees them diverge.
# k138 (pikachu self-ssh-local).
#

subtest 'advertised_host defaults to the transport host' => sub {
    my $rex = OCP::Rex->new(host => '1.2.3.4', key_file => $key->stringify);
    is $rex->advertised_host, '1.2.3.4',
        'a caller that names only host advertises that same host';
};

subtest 'the install task tls-san is the advertised address, not the transport' => sub {
    my @tasks;
    no warnings 'redefine';
    # install_server also fetches the kubeconfig over SSH; stub that out so the
    # test never opens a connection.
    local *OCP::Rex::fetch_kubeconfig_ssh = sub { "stub-kubeconfig\n" };
    local *OCP::Rex::run_task = sub {
        my ($self, $task, %params) = @_;
        push @tasks, { task => $task, %params };
        return { stdout => '', stderr => '', exit => 0 };
    };

    OCP::Rex->new(
        host            => '127.0.0.1',
        advertised_host => '10.5.10.5',
        key_file        => $key->stringify,
    )->install_server(distribution => 'rke2', node_name => 'police1');

    my ($install) = grep { $_->{task} eq 'install_rke2_server' } @tasks;
    ok $install, 'the install task ran';
    is $install->{tls_san}, '10.5.10.5',
        'tls-san is the advertised address, not the 127.0.0.1 transport';
};

subtest 'the kubeconfig server endpoint takes the advertised address' => sub {
    my @ssh_hosts;
    no warnings 'redefine';
    # Fake OCP::SSH: capture which host it was told to connect to, and hand back
    # an rke2.yaml pinned to 127.0.0.1, as the real one ships.
    local *OCP::SSH::new = sub {
        my ($class, %args) = @_;
        push @ssh_hosts, $args{host};
        return bless { %args }, $class;
    };
    local *OCP::SSH::run = sub {
        return {
            stdout => "apiVersion: v1\nclusters:\n- cluster:\n"
                    . "    server: https://127.0.0.1:6443\n",
            stderr => '',
            exit   => 0,
        };
    };

    my $kubeconfig = OCP::Rex->new(
        host            => '127.0.0.1',
        advertised_host => '10.5.10.5',
        key_file        => $key->stringify,
    )->fetch_kubeconfig_ssh('rke2');

    like $kubeconfig, qr{server: https://10\.5\.10\.5:6443},
        'the kubeconfig server points at the advertised address';
    unlike $kubeconfig, qr{https://127\.0\.0\.1:6443},
        'and no longer at the 127.0.0.1 transport';
    is $ssh_hosts[0], '127.0.0.1',
        'yet the kubeconfig was fetched over SSH to the transport host';
};

done_testing;

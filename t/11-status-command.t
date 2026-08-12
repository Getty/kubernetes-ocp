#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP;
use OCP::Cmd::Status;
use OCP::Kubernetes;

{
    package Local::FakeOCP;
    use Moo;
    has config => (is => 'ro', required => 1);
    sub verbose { 0 }
}

{
    package Local::FakeSecrets;
    sub new { bless {}, $_[0] }
    sub read_kubeconfig { return "apiVersion: v1\nkind: Config\n"; }
}

{
    package Local::FakeK8s;
    sub new { bless { nodes => $_[1] }, $_[0] }
    sub list_nodes { $_[0]{nodes} }
    sub node_name { $_[1]{metadata}{name} }
    sub node_ready { $_[1]{ready} }
    sub node_roles { $_[1]{roles} }
    sub node_version { $_[1]{version} }
    sub node_internal_ip { $_[1]{internal_ip} }
    sub gpu_nodes { [] }
    sub node_gpu_count { 0 }
}

my $ocp = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

sub capture_stdout (&) {
    my ($code) = @_;
    my $stdout = '';
    open my $fh, '>', \$stdout or die "open stdout capture: $!";
    local *STDOUT = $fh;
    $code->();
    return $stdout;
}

{
    my $project = path($tmpdir)->child('no-cluster');
    $project->mkpath;
    my $config_file = $project->child('ocp.yaml');
    $ocp->dump_file($config_file->stringify, {
        name         => 'nocluster',
        control_planes => [{ provider => 'ssh', host => '127.0.0.1' }],
    });

    my $cmd = OCP::Cmd::Status->new(
        command_chain => [Local::FakeOCP->new(config => $config_file->stringify)],
    );

    my $output = capture_stdout { $cmd->execute([], []) };
    like($output, qr/No cluster deployed yet/, 'status reports missing cluster');
}

{
    my $project = path($tmpdir)->child('with-cluster');
    $project->mkpath;
    my $config_file = $project->child('ocp.yaml');
    my $kubeconfig_file = $project->child('kubeconfig.yaml');

    $ocp->dump_file($config_file->stringify, {
        name         => 'withcluster',
        control_planes => [{ provider => 'hetzner', server_type => 'cx32' }],
    });
    $kubeconfig_file->spew("encrypted-placeholder\n");

    my $helper_called = 0;
    my $cmd = OCP::Cmd::Status->new(
        command_chain => [Local::FakeOCP->new(config => $config_file->stringify)],
    );

    no warnings 'redefine';
    local *OCP::Secrets::new = sub { Local::FakeSecrets->new };
    local *OCP::Kubernetes::new = sub {
        $helper_called++;
        return Local::FakeK8s->new([
            {
                metadata    => { name => 'police1' },
                ready       => 1,
                roles       => 'control-plane',
                version     => 'v1.32.1',
                internal_ip => '10.0.0.10',
            },
        ]);
    };

    my $output = capture_stdout { $cmd->execute([], []) };

    is($helper_called, 1, 'status uses OCP::Kubernetes helper when cluster exists');
    like($output, qr/police1/, 'status prints node row');
    unlike($output, qr/kubectl --kubeconfig/, 'status no longer prints kubectl command hint');
}

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Config;
use OCP::Secrets;
use OCP::SSH;

#
# k226 (the k204 cosmetics), lab 2026-10-15/16: a control plane that refused
# the key ended `ocp apply` with
#
#     Error:   [FAIL] SSH not ready: SSH key rejected by ...: user root with key
#     /tmp/XXXXXXXX was refused ...
#
# -- a status tag behind the "Error:" label, and the key named by the temp copy
# OCP::ClusterKey writes for the admin key, a path the operator never chose.
# Now: "Error: SSH not ready: ..." and the key as keys.yaml names it, still
# with its fingerprint.
#

no warnings 'once';

subtest 'OCP::ClusterKey names a key the way the operator knows it' => sub {
    my $admin = bless { origin => 'admin', name => 'admin-ssh', provider => 'hetzner' },
        'OCP::ClusterKey';
    is $admin->label, "the admin key 'admin-ssh' from keys.yaml", 'the admin key by its keys.yaml name';
    my $boot = bless { origin => 'bootstrap', provider => 'ssh' }, 'OCP::ClusterKey';
    is $boot->label, 'the bootstrap key .ocp/id_ed25519', 'the bootstrap key by its project path';
};

subtest 'a refusal names the label and the fingerprint, not the temp path' => sub {
    my $dir = tempdir(CLEANUP => 1);
    system('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', "$dir/k") == 0
        or plan skip_all => 'no ssh-keygen';
    my ($fp) = `ssh-keygen -lf $dir/k.pub` =~ /(SHA256:\S+)/;

    my $ssh = OCP::SSH->new(host => 'cp.example', user => 'root', key_file => "$dir/k",
        key_label => "the admin key 'admin-ssh' from keys.yaml");
    no warnings 'redefine';
    local *OCP::SSH::run = sub { { exit => 255, stdout => '',
        stderr => "root\@cp.example: Permission denied (publickey).\n" } };
    eval { $ssh->wait_for_ssh(120, 2) };

    like   $@, qr/user root with the admin key 'admin-ssh' from keys\.yaml \(\Q$fp\E\) was refused/,
        'the key as keys.yaml names it, with its fingerprint';
    unlike $@, qr/\Q$dir\E/, 'the temp path is not the name';
};

package FakeOcp {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

package FakeProv {
    sub new { bless {}, $_[0] }
    sub upload_ssh_key     { }
    sub server_exists      { { ip => 'cp.example', newly_created => 0 } }
    sub create_server      { { ip => 'cp.example', newly_created => 0 } }
    sub wait_for_running   { $_[1] }
    sub advertised_host    { my ($s, %o) = @_; $o{host} }
    sub cleanup_on_failure { }
}

package main;

subtest 'bootstrap: "SSH not ready", no status tag, the key by name' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(<<'YAML');
name: lab
control_planes:
  provider: ssh
  host: cp.example
YAML
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);

    my %ssh_args;
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $old = select $fh;
    eval {
        no warnings 'redefine';
        local *OCP::Provider::for_spec       = sub { FakeProv->new };
        local *OCP::Secrets::ensure_age_key  = sub { 1 };
        local *OCP::SSH::new = sub { my ($c, %a) = @_; %ssh_args = %a; bless {%a}, $c };
        local *OCP::SSH::wait_for_ssh = sub {
            die "SSH key rejected by cp.example: user root with $_[0]{key_label} "
              . "was refused (Permission denied).\n";
        };
        OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
            $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
            admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
        );
    };
    my $err = $@;
    select $old;

    is $ssh_args{key_label}, 'the bootstrap key .ocp/id_ed25519',
        'OCP::SSH is told which key it holds';
    like   $err, qr/\ASSH not ready: SSH key rejected by cp\.example/, 'the error starts with what failed';
    unlike $err, qr/\[FAIL\]/, 'no status tag in it';

    my $shown = '';
    {
        open my $e, '>', \$shown or die $!;
        local *STDERR = $e;
        OCP::_report_error($err, 0);
    }
    like $shown, qr/\AError: SSH not ready: SSH key rejected/,
        'and the operator reads "Error: SSH not ready: ..."';
};

done_testing;

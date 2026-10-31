#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Config;
use OCP::Provider::Local;
use OCP::Provider::SSH;
use OCP::Secrets;
use OCP::SSH;

#
# k298: bootstrap_control_plane handed create_server server_type cx32, image
# debian-13 and location fsn1 whenever ocp.yaml named none -- for every
# provider type, and cx32 against OCP::Config's %HETZNER_DEFAULTS (cpx21), the
# one default a spec gets. Since k255 `ocp apply` runs validate() first, which
# requires server_type and location of a Hetzner control plane, so those two
# fallbacks were dead; the image one was not. Now a Hetzner control plane gets
# exactly what ocp.yaml says and %HETZNER_DEFAULTS for what it leaves out; the
# ssh and local providers are handed none of the three and still resolve
# their host as before.
#

no warnings 'once';

package FakeOcp {
    sub new     { bless {}, shift }
    sub verbose { 0 }
}

# Hetzner stand-in: stops the bootstrap at create_server -- nothing past
# placement is under test, and nothing is created.
package PlacementProv {
    sub new            { bless {}, shift }
    sub upload_ssh_key { }
    sub create_server  { die "stop after create_server\n" }
}

package main;

sub project {
    my ($yaml) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8($yaml);
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# Runs bootstrap_control_plane up to the SSH wait and returns the options
# create_server got, what it answered and how the run ended. $prov is the
# provider for_spec hands back; its own create_server runs, wrapped to record
# the call -- the real one for ssh and local.
sub bootstrap_placement {
    my ($config, $prov) = @_;
    my (%seen, $info);
    my $class = ref $prov;
    my $create = $prov->can('create_server');
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $old = select $fh;
    eval {
        no strict 'refs';
        no warnings 'redefine';
        local *{"${class}::create_server"} = sub {
            my ($self, %o) = @_;
            %seen = %o;
            return $info = $create->(@_);
        };
        local *OCP::Provider::for_spec      = sub { $prov };
        local *OCP::Secrets::ensure_age_key = sub { 1 };
        local *OCP::Provider::Local::_default_route_source_ip = sub { undef };
        local *OCP::SSH::new          = sub { my ($c, %a) = @_; bless {%a}, $c };
        local *OCP::SSH::wait_for_ssh = sub { die "stop at the SSH wait\n" };
        OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
            $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
            admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
        );
    };
    my $died = $@;
    select $old;
    return { opts => \%seen, info => $info, died => $died };
}

sub placement { my ($o) = @_; return { map { $_ => $o->{$_} } qw( server_type image location ) } }

subtest 'Hetzner: exactly what ocp.yaml says' => sub {
    my $config = project(<<'YAML');
name: lab
control_planes:
  provider: hetzner
  server_type: cx42
  location: nbg1
  image: ubuntu-24.04
YAML
    is_deeply [ $config->validate ], [], 'a valid ocp.yaml';
    my $r = bootstrap_placement($config, PlacementProv->new);
    is $r->{died}, "stop after create_server\n", 'reached create_server';
    is_deeply placement($r->{opts}), { server_type => 'cx42', location => 'nbg1', image => 'ubuntu-24.04' },
        'server type, location and image as written';
    is $r->{opts}{role}, 'control-plane', 'as the control plane';
};

subtest 'Hetzner without an image: the image default %HETZNER_DEFAULTS has' => sub {
    my $config = project(<<'YAML');
name: lab
control_planes:
  provider: hetzner
  server_type: cx42
  location: nbg1
YAML
    is_deeply [ $config->validate ], [], 'valid: the image is not required';
    my $r = bootstrap_placement($config, PlacementProv->new);
    is_deeply placement($r->{opts}),
        { server_type => 'cx42', location => 'nbg1', image => $OCP::Config::HETZNER_DEFAULTS{image} },
        'what it says, and the one image default';
};

subtest 'Hetzner with nothing set (validate() skipped): %HETZNER_DEFAULTS, not cx32' => sub {
    my $config = project("name: lab\ncontrol_planes:\n  provider: hetzner\n");
    ok scalar(grep { /server_type required/ } $config->validate), 'ocp apply would refuse this (k255)';
    my $r = bootstrap_placement($config, PlacementProv->new);
    is_deeply placement($r->{opts}), { %OCP::Config::HETZNER_DEFAULTS },
        'one source of defaults: the one a fresh spec gets';
    isnt $r->{opts}{server_type}, 'cx32', 'no server type of its own';
};

subtest 'ssh: no Hetzner placement handed over, the host resolved as before' => sub {
    my $config = project("name: lab\ncontrol_planes:\n  provider: ssh\n  host: cp.example\n");
    my $r = bootstrap_placement($config, OCP::Provider::SSH->new);
    like $r->{died}, qr/\ASSH not ready: stop at the SSH wait/, 'ran on to the SSH wait';
    is_deeply placement($r->{opts}), { server_type => undef, image => undef, location => undef },
        'no server type, image or location';
    is $r->{opts}{host}, 'cp.example', 'the host';
    is $r->{info}{ip}, 'cp.example', 'create_server answers with it';
};

subtest 'local: no Hetzner placement handed over, 127.0.0.1 as before' => sub {
    my $config = project("name: lab\ncontrol_planes:\n  provider: local\n");
    my $r = bootstrap_placement($config, OCP::Provider::Local->new);
    like $r->{died}, qr/\ASSH not ready: stop at the SSH wait/, 'ran on to the SSH wait';
    is_deeply placement($r->{opts}), { server_type => undef, image => undef, location => undef },
        'no server type, image or location';
    is $r->{info}{ip}, '127.0.0.1', 'create_server answers 127.0.0.1';
};

done_testing;

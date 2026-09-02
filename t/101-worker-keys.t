#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;

#
# k101, variant a: robocop must be able to reach the Hetzner workers it
# provisions, and it holds the ROBO key, never the admin key. So every Hetzner
# machine of a secure-mode cluster has to trust BOTH public keys — the admin
# key a human uses and the robo key automation uses.
#
# Today only the admin key is uploaded and referenced at server creation
# (Bootstrap.pm had a single upload_ssh_key call, with $admin_key->{public}).
# This test is the claim that the robo PUBLIC key is uploaded too and that
# create_server references both names.
#
# Why this is not the ADR 0027 "upload both public keys" that was rejected:
# that pair was BOOTSTRAP + ADMIN, and the bootstrap key is an unencrypted
# private key on the operator's disk with no second factor. The robo key is
# age-encrypted and is exactly the automation tier ADR 0006/0027 keep. Only the
# PUBLIC half travels to Hetzner here, and a public half sits behind the age
# layer alone — no PIN2 is entered on this path, which is what keeps variant a
# clean.
#

my $ADMIN = {
    name    => 'admin-ssh',
    purpose => 'admin',
    private => "-----BEGIN OPENSSH PRIVATE KEY-----\nADMINKEYMATERIAL\n",
    public  => 'ssh-ed25519 AAAAadminpublic admin@ocp',
};

my $ROBO = {
    name       => 'robo-ssh',
    purpose    => 'automation',
    public     => 'ssh-ed25519 AAAArobopublic robo@ocp',
    deprecated => 0,
};

my $BOOTSTRAP_PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----\nBOOTSTRAPKEY\n";
my $BOOTSTRAP_PUBLIC  = "ssh-ed25519 AAAAboot boot\n";

# A Hetzner-control-plane project. `secure` writes keys.yaml, whose mere
# presence flips OCP::ClusterKey out of dev mode so the passed-in admin key is
# used rather than the bootstrap key on disk.
sub project {
    my (%args) = @_;
    my $secure = exists $args{secure} ? $args{secure} : 1;

    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;

    $dir->child('ocp.yaml')->spew_utf8(<<'YAML');
name: cortex
control_planes:
  provider: hetzner
  location: fsn1
  server_type: cx32
YAML

    $dir->child('keys.yaml')->spew_utf8("keys: []\n") if $secure;

    # A bootstrap key is always on disk; in secure mode it must NOT win.
    $dir->child('.ocp', 'id_ed25519')->spew_utf8($BOOTSTRAP_PRIVATE);
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8($BOOTSTRAP_PUBLIC);

    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub capture {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die "capture: $!";
    my $old = select $fh;
    my @r = eval { $code->() };
    my $err = $@;
    select $old;
    close $fh;
    return ($out, $err, @r);
}

package FakeOcp {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# Records every upload_ssh_key call and the ssh_keys create_server was asked
# for. Stands in for a real OCP::Provider::Hetzner so no test talks to Hetzner.
package FakeProv {
    sub new { my ($c, %a) = @_; bless { uploads => [], created => [], %a }, $c }
    sub upload_ssh_key {
        my ($self, $name, $pub) = @_;
        push @{ $self->{uploads} }, { name => $name, public => $pub };
    }
    sub create_server {
        my ($self, %opts) = @_;
        push @{ $self->{created} }, \%opts;
        return { id => 'SRV-1', ip => undef, newly_created => 1 };
    }
    sub wait_for_running {
        my ($self, $info) = @_;
        $info->{ip} = '1.2.3.4';
        return $info;
    }
    sub cleanup_on_failure { }
}

# A Node that is Ready on the first poll, so bootstrap_control_plane's wait
# loop exits at once and never sleeps.
package FakeCond   { sub new { bless { t => $_[1], s => $_[2] }, $_[0] } sub type { $_[0]{t} } sub status { $_[0]{s} } }
package FakeStatus { sub conditions { [ FakeCond->new('Ready', 'True') ] } }
package FakeNodeObj { sub status { bless {}, 'FakeStatus' } }
package FakeNodeList { sub items { [ bless {}, 'FakeNodeObj' ] } }
package FakeApi {
    sub _request { 1 }
    sub list     { bless {}, 'FakeNodeList' }
}

package main;

# Drive bootstrap_control_plane with every machine-touching layer faked, and
# return the FakeProv so the test can read what was uploaded and referenced.
sub run_bootstrap {
    my ($config, %opt) = @_;

    my $admin_key = $opt{admin_key} // $ADMIN;

    my $prov = FakeProv->new;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);

    my ($out, $err);
    {
        no warnings 'redefine';
        local *OCP::Provider::for_spec        = sub { $prov };
        local *OCP::Cmd::Apply::_k8s_api       = sub { bless {}, 'FakeApi' };
        local *OCP::Secrets::hetzner_token     = sub { 'test-token' };
        local *OCP::Secrets::save_kubeconfig   = sub { 1 };
        local *OCP::Secrets::ensure_age_key    = sub { 1 };
        local *OCP::SSH::new          = sub { bless {}, 'OCP::SSH' };
        local *OCP::SSH::wait_for_ssh = sub { 1 };
        local *OCP::SSH::run          = sub { { stdout => 'Ready' } };
        local *OCP::Rex::new           = sub { bless {}, 'OCP::Rex' };
        local *OCP::Rex::install_server = sub { { kubeconfig => "apiVersion: v1\n" } };

        # In secure mode the robo public comes off keys.yaml with no PIN2. Stub
        # the store so this test needs no age/Crypt setup; the dev-mode subtest
        # deliberately leaves it unstubbed so has_keys_file answers for real.
        if ($opt{robo}) {
            local *OCP::Keys::has_keys_file = sub { 1 };
            local *OCP::Keys::list_keys     = sub { [ $ROBO ] };
            ($out, $err) = capture(sub {
                OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
                    $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
                    admin_key => $admin_key,
                );
            });
        }
        else {
            ($out, $err) = capture(sub {
                OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
                    $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
                    admin_key => $admin_key,
                );
            });
        }
    }

    return { prov => $prov, out => $out, err => $err };
}

subtest 'secure mode uploads BOTH the admin and the robo public key' => sub {
    my $config = project(secure => 1);
    my $r = run_bootstrap($config, robo => 1);
    is $r->{err}, '', 'bootstrap ran to completion' or diag $r->{out};

    my %uploaded = map { $_->{name} => $_->{public} } @{ $r->{prov}{uploads} };

    is $uploaded{'ocp-cortex-admin'}, $ADMIN->{public},
        'the admin public key is uploaded under ocp-<cluster>-admin';
    is $uploaded{'ocp-cortex-robo'}, $ROBO->{public},
        'the robo public key is uploaded under ocp-<cluster>-robo';
    is scalar(keys %uploaded), 2, 'exactly those two keys were uploaded';
};

subtest 'create_server references BOTH key names at machine creation' => sub {
    my $config = project(secure => 1);
    my $r = run_bootstrap($config, robo => 1);
    is $r->{err}, '', 'bootstrap ran' or diag $r->{out};

    my $created = $r->{prov}{created}[0];
    ok $created, 'a server was created';

    is_deeply [ sort @{ $created->{ssh_keys} } ],
        [ 'ocp-cortex-admin', 'ocp-cortex-robo' ],
        'the control-plane machine trusts both the admin and the robo key';
};

subtest 'dev mode uploads only the one key it has, no robo' => sub {
    # --nopassword mode has no keys.yaml, therefore no robo key. The admin_key
    # passed in is really the bootstrap key. Nothing extra must be uploaded.
    my $config = project(secure => 0);
    my $DEV_KEY = {
        name    => 'bootstrap',
        purpose => 'admin',
        private => $BOOTSTRAP_PRIVATE,
        public  => 'ssh-ed25519 AAAAboot boot@ocp',
    };

    my $r = run_bootstrap($config, admin_key => $DEV_KEY);   # robo NOT stubbed
    is $r->{err}, '', 'bootstrap ran' or diag $r->{out};

    my %uploaded = map { $_->{name} => $_->{public} } @{ $r->{prov}{uploads} };
    is scalar(keys %uploaded), 1, 'only one key uploaded in dev mode';
    is $uploaded{'ocp-cortex-admin'}, $DEV_KEY->{public},
        'and it is the single (bootstrap-standing-in-for-admin) key';

    my $created = $r->{prov}{created}[0];
    is_deeply $created->{ssh_keys}, ['ocp-cortex-admin'],
        'the machine references that one key and no robo key';
};

subtest 'Hetzner create_server passes both names through to the API' => sub {
    # Point 3, against the real adapter rather than FakeProv: a create_server
    # handed two key names must attach both to the machine, not collapse them.
    require OCP::Provider::Hetzner;

    my $servers = bless { created => [] }, 'FakeHzServers101';
    my $cloud   = bless { servers => $servers }, 'FakeHzCloud101';
    {
        package FakeHzServer101;
        sub new  { my ($c, %a) = @_; bless {%a}, $c }
        sub id   { 'SRV-1' }
        sub ipv4 { undef }
        package FakeHzServers101;
        sub list_by_label { [] }
        sub create {
            my ($s, %p) = @_;
            push @{ $s->{created} }, \%p;
            return FakeHzServer101->new;
        }
        package FakeHzCloud101;
        sub servers { $_[0]{servers} }
    }

    my $prov = OCP::Provider::Hetzner->new(
        token => 'fake', cluster_name => 'cortex', cloud => $cloud,
    );
    $prov->create_server(
        name     => 'cortex-police1',
        node     => 'police1',
        role     => 'control-plane',
        ssh_keys => ['ocp-cortex-admin', 'ocp-cortex-robo'],
    );

    is_deeply $servers->{created}[0]{ssh_keys},
        ['ocp-cortex-admin', 'ocp-cortex-robo'],
        'both key names reach cloud->servers->create';
};

subtest 'the robo key name follows the admin convention' => sub {
    my $config = project(secure => 1);
    is $config->robo_ssh_key_name, 'ocp-cortex-robo',
        'ocp-<cluster>-robo, mirroring admin_ssh_key_name';
    is $config->admin_ssh_key_name, 'ocp-cortex-admin',
        'and the admin name is unchanged';
};

done_testing;

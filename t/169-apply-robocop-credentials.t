#!/usr/bin/env perl
# karr k169 -- `ocp apply` rolls robocop out WITH its credentials Secret.
#
# Live finding: apply deployed Deployment/robocop but only `ocp deploy-robocop`
# wrote Secret robocop-credentials, so the pod sat in CreateContainerConfigError
# ("secret robocop-credentials not found") and apply fell back to the CLI after
# 60s. The claim here: the worker step -- the one place both apply paths (fresh
# deploy and reconcile) roll robocop out -- writes the Secret per
# robocop.security_level BEFORE the Deployment, through the same code
# deploy-robocop uses (OCP::Role::Cmd::RobocopCredentials), without a second
# PIN2 when this run already has one, and without re-writing a Secret that is
# already current.
#
# Network-free and cluster-free: the K8s api is a fake that stores what is
# ensured and serves it back the way the API server does (Secret values
# base64-encoded under data). keys.yaml / age.key are real, so the robo key
# decrypt runs for real. The PIN prompt is stubbed on OCP::Password, the SSH
# token read on OCP::SSH::run; the robocop wait and the worker drive are
# recorded instead of run.

use strict;
use warnings;
use Test::More;

use MIME::Base64 ();
use Path::Tiny ();

use lib 'lib';

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::Deploy;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;
use OCP::SSH;

local @ARGV = ();
my $ocp = OCP->new;

my $ROBO_PRIV  = "-----BEGIN OPENSSH PRIVATE KEY-----\nROBOAUTOMATIONKEY\n-----END OPENSSH PRIVATE KEY-----\n";
my $ROBO_PUB   = 'ssh-ed25519 AAAArobo robo';
my $ADMIN_PRIV = "-----BEGIN OPENSSH PRIVATE KEY-----\nADMINHUMANKEY\n-----END OPENSSH PRIVATE KEY-----\n";
my $PIN2       = 'correct-horse';
my $TOKEN      = 'K10deadbeefcafe::server:0123456789abcdef';
my $CP_IP      = '10.0.0.1';

# --- Fakes ----------------------------------------------------------------

package FakeList {
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}

# Stores every ensured object under kind/namespace/name and serves it back.
# A Secret comes back as the API server returns it: stringData is write-only,
# the values sit base64-encoded under data.
package FakeApi {
    sub new { bless { log => [], objects => {} }, shift }

    sub ensure {
        my ($self, $obj) = @_;
        my $key = join '/', $obj->{kind}, $obj->{metadata}{namespace} // '-',
            $obj->{metadata}{name};
        push @{ $self->{log} }, $key;
        my %stored = %$obj;
        if ($obj->{kind} eq 'Secret' && $obj->{stringData}) {
            delete $stored{stringData};
            $stored{data} = { map {
                $_ => MIME::Base64::encode_base64($obj->{stringData}{$_}, '')
            } keys %{ $obj->{stringData} } };
        }
        $self->{objects}{$key} = \%stored;
        return $obj;
    }

    sub get {
        my ($self, $kind, $name, %opt) = @_;
        my $key = join '/', $kind, $opt{namespace} // '-', $name;
        return $self->{objects}{$key} // die "404 $key\n";
    }

    sub list             { FakeList->new([]) }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }

    sub ensured    { $_[0]{log} }
    sub secret     { $_[0]{objects}{'Secret/ocp-system/robocop-credentials'} }
    sub index_of   {
        my ($self, $re) = @_;
        my @log = @{ $self->{log} };
        for my $i (0 .. $#log) { return $i if $log[$i] =~ $re }
        return -1;
    }
}

package FakeOCP {
    sub new     { bless {}, shift }
    sub verbose { 0 }
}

package main;

# The worker step's slow ends, recorded instead of run.
our $ROBOCOP_READY = 0;
my (@waits, @drives);
{
    no warnings qw( redefine once );
    *OCP::Cmd::Apply::_wait_robocop_ready = sub {
        push @waits, $_[2];
        return $ROBOCOP_READY;
    };
    *OCP::Cmd::Apply::_drive_workers = sub {
        my ($self, $api, $config, $deps) = @_;
        push @drives, { %$deps };
        return map { { name => $_, phase => 'Ready', message => '' } }
            @{ $deps->{names} // [] };
    };
    *OCP::Cmd::Apply::_print_worker_status = sub { };
    *OCP::Cmd::Apply::wait_seconds         = sub { };
}

# A secure-mode project (keys.yaml with a robo and an admin key, a real age
# key), robocop on at the given level, one ssh worker.
sub make_project {
    my (%opt) = @_;
    my $dir = Path::Tiny->tempdir;

    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'test',
        control_planes => { provider => 'ssh', host => 'police1' },
        robocop        => { enabled => 1, security_level => $opt{level} // 'secret' },
        workers        => [ { name => 'pool', provider => 'ssh', nodes => ['w1.invalid'] } ],
    });

    OCP::Secrets->new(project_dir => $dir)->generate_age_key;

    my $keys = OCP::Keys->new(project_dir => $dir);
    $keys->add_key(
        name    => 'robo-ssh',
        type    => 'ssh_ed25519',
        private => $ROBO_PRIV,
        public  => $ROBO_PUB,
        purpose => 'automation',
    );
    $keys->add_key(
        name    => 'admin-ssh',
        type    => 'ssh_ed25519',
        private => $ADMIN_PRIV,
        public  => 'ssh-ed25519 AAAAadmin admin',
        purpose => 'admin',
        pin2    => $PIN2,
    );
    return $dir;
}

sub config_for {
    OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify, ocp => $ocp);
}

sub new_apply { OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]) }

# One worker step as `ocp apply` runs it. Returns what happened.
sub run_step {
    my (%opt) = @_;
    my $dir   = $opt{dir};
    my $cfg   = config_for($dir);
    my $api   = $opt{api}   // FakeApi->new;
    my $apply = $opt{apply} // new_apply();

    my $prompts = 0;
    my @ssh;
    @waits  = ();
    @drives = ();

    no warnings 'redefine';
    local $OCP::ClusterKey::INTERACTIVE = 1;
    local *OCP::Password::prompt_password = sub {
        $prompts++;
        return exists $opt{pin2} ? $opt{pin2} : $PIN2;
    };
    local *OCP::SSH::run = sub {
        push @ssh, $_[1];
        return { stdout => "$TOKEN\n", stderr => '', exit => 0 };
    };

    my ($out, $err) = ('', '');
    {
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        OCP::Cmd::Apply::Deploy::worker_step($apply, $api, $cfg, {
            ssh_key_path => '/nonexistent/key',
            cp_ip        => $CP_IP,
            secrets      => OCP::Secrets->new(project_dir => $dir),
        });
    }

    return {
        api     => $api,
        apply   => $apply,
        config  => $cfg,
        prompts => $prompts,
        ssh     => \@ssh,
        waits   => [ @waits ],
        drives  => [ @drives ],
        out     => $out,
        err     => $err,
    };
}

sub secret_values {
    my ($api) = @_;
    my $s = $api->secret or return;
    return { map { $_ => MIME::Base64::decode_base64($s->{data}{$_}) } keys %{ $s->{data} } };
}

# ==========================================================================

subtest 'secret: apply writes the Secret, and before the Deployment' => sub {
    my $r = run_step(dir => make_project(level => 'secret'));

    my $v = secret_values($r->{api});
    ok $v, 'Secret robocop-credentials is written by ocp apply';
    is_deeply [ sort keys %$v ], [ 'rke2-token', 'robo-ssh-key', 'server-url' ],
        'the three contract keys';
    is $v->{'robo-ssh-key'}, $ROBO_PRIV,              'the private robo key';
    is $v->{'server-url'},   "https://$CP_IP:9345",   'join URL of the cp apply has in hand';
    is $v->{'rke2-token'},   $TOKEN,                  'token read over SSH';

    my $secret_at = $r->{api}->index_of(qr{^Secret/ocp-system/robocop-credentials$});
    my $deploy_at = $r->{api}->index_of(qr{^Deployment/ocp-system/robocop$});
    ok $deploy_at >= 0, 'the Deployment is rolled out';
    ok $secret_at >= 0 && $secret_at < $deploy_at, 'Secret before Deployment';

    is $r->{prompts}, 1,
        'secure mode, nothing unlocked yet: ONE PIN2 for the key that reads the token';
    is_deeply $r->{waits}, [60], 'readiness is waited for as before';
    is $r->{err}, '', 'nothing on STDERR';
};

subtest 'secret: a current Secret is left alone -- no SSH, no PIN2' => sub {
    my $dir = make_project(level => 'secret');
    my $first = run_step(dir => $dir);
    my $api   = $first->{api};
    my $writes = grep { m{^Secret/} } @{ $api->ensured };

    my $r = run_step(dir => $dir, api => $api);
    is scalar(grep { m{^Secret/} } @{ $api->ensured }), $writes,
        'the Secret is not written again';
    is $r->{prompts}, 0, 'no PIN2 prompt';
    is scalar @{ $r->{ssh} }, 0, 'no SSH read of the token';
    like $r->{out}, qr{Secret/robocop-credentials is current}, 'and says so';
    ok $api->index_of(qr{^Deployment/}) >= 0, 'the Deployment is still ensured';
};

subtest 'a stale Secret is rewritten: level switched secret -> inject' => sub {
    my $dir = make_project(level => 'secret');
    my $api = run_step(dir => $dir)->{api};

    my $inject = make_project(level => 'inject');
    # Same project dir contents matter only for the level; reuse the api.
    my $r = run_step(dir => $inject, api => $api);
    my $v = secret_values($api);
    ok !exists $v->{'robo-ssh-key'}, 'the private key is gone from the Secret';
    is $v->{'robo-ssh-public-key'}, $ROBO_PUB, 'the public half is in it';
};

subtest 'a Secret without a token is not current' => sub {
    my $dir = make_project(level => 'secret');
    my $api = run_step(dir => $dir)->{api};
    $api->secret->{data}{'rke2-token'} = '';

    my $r = run_step(dir => $dir, api => $api);
    is secret_values($api)->{'rke2-token'}, $TOKEN, 'rewritten with the token';
    is scalar @{ $r->{ssh} }, 1, 'which took the SSH read';
};

subtest 'secret_approved, fresh apply: the PIN2 of the admin step is the approval' => sub {
    my $dir   = make_project(level => 'secret_approved');
    my $cfg   = config_for($dir);
    my $apply = new_apply();

    # What `ocp apply` on a new cluster did in its admin-authentication step:
    # PIN2 typed, admin key unlocked, parked on the command object.
    my $admin = OCP::Keys->new(project_dir => $dir)->get_admin_key($PIN2);
    {
        my $sink = '';
        open my $fh, '>', \$sink or die $!;
        local *STDOUT = $fh;
        OCP::Cmd::Apply::Bootstrap::setup_ssh_key($apply, $cfg, admin_key => $admin);
    }

    my $r = run_step(dir => $dir, apply => $apply);
    is $r->{prompts}, 0, 'no second PIN2 prompt';
    is secret_values($r->{api})->{'robo-ssh-key'}, $ROBO_PRIV, 'the Secret is written';
    like $r->{out}, qr/approved by the PIN2 given earlier/, 'the reuse is said out loud';
};

subtest 'secret_approved, reconcile: ONE prompt covers approval and SSH read' => sub {
    my $dir = make_project(level => 'secret_approved');
    my $r   = run_step(dir => $dir);

    is $r->{prompts}, 1, 'PIN2 asked exactly once';
    ok secret_values($r->{api}), 'the Secret is written';
    is scalar @{ $r->{ssh} }, 1, 'token read with the approved admin key';
    is $r->{apply}->cluster_ssh_key_if_known($r->{config})->origin, 'admin',
        'and that key stays on the command for the CLI fallback';

    my $again = run_step(dir => $dir, api => $r->{api});
    is $again->{prompts}, 0, 're-apply with a current Secret: no approval needed';
};

subtest 'secret_approved, wrong PIN2: neither Secret nor Deployment, CLI takes over' => sub {
    my $r = run_step(dir => make_project(level => 'secret_approved'), pin2 => 'nope');

    ok !$r->{api}->secret, 'no Secret written';
    is $r->{api}->index_of(qr{^Deployment/}), -1,
        'no Deployment either -- a pod that cannot start is no controller';
    is scalar @{ $r->{ssh} }, 0, 'the control plane was never contacted';
    like $r->{err}, qr/robocop deploy failed.*PIN2/s, 'the failure is on STDERR, named';
    is_deeply $r->{waits}, [], 'no 60s wait for a robocop that was not deployed';
    ok !$r->{drives}[0]{robocop_ready}, 'the CLI drives the workers';
};

subtest 'inject: public key only, a note, and no 60s wait' => sub {
    my $r = run_step(dir => make_project(level => 'inject'));

    my $v = secret_values($r->{api});
    is_deeply [ sort keys %$v ], [ 'rke2-token', 'robo-ssh-public-key', 'server-url' ],
        'the public half instead of the private key';
    unlike join("\n", values %$v), qr/PRIVATE KEY/, 'no private key material';

    my $secret_at = $r->{api}->index_of(qr{^Secret/ocp-system/robocop-credentials$});
    my $deploy_at = $r->{api}->index_of(qr{^Deployment/ocp-system/robocop$});
    ok $secret_at >= 0 && $secret_at < $deploy_at, 'Secret before Deployment';

    is_deeply $r->{waits}, [0], 'readiness is looked at once, not waited for';
    like $r->{out}, qr/ocp inject-key/, 'STDOUT tells the operator to inject the key';
    ok !$r->{drives}[0]{robocop_ready}, 'the CLI brings the workers up this run';
    is $r->{err}, '', 'not an error';

    local $ROBOCOP_READY = 1;
    my $ready = run_step(dir => make_project(level => 'inject'));
    ok $ready->{drives}[0]{robocop_ready}, 'an already-injected robocop drives';
    unlike $ready->{out}, qr/ocp inject-key/, 'and no note';
};

done_testing;

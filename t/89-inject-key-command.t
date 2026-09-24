#!/usr/bin/env perl
# karr k2 -- `ocp inject-key`: hand the private robo key to the running robocop
# pod over a Kubernetes port-forward (robocop.security_level: inject).
#
# Network-free and cluster-free: keys.yaml and the age key are real (temp
# project), PIN2 is stubbed on OCP::Password::prompt_password, and the async
# Kubernetes client is a fake whose port-forward feeds the REAL robocop-side
# protocol handler (OCP::Robocop::KeyInjection->handle_request).

use strict;
use warnings;
use Test::More;

use Future;
use IO::Async::Loop;
use Path::Tiny ();

use lib 'lib';

use OCP;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;
use OCP::Robocop::KeyInjection;
use OCP::Cmd::InjectKey;

local @ARGV = ();
my $ocp = OCP->new;

# TEST FIXTURES ONLY (same pair as t/87), trusted nowhere.
my $ROBO_PRIV = <<'KEY';
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCjx1LAEqprX25BhoqMOTYatLiWTFUp5yZ3QeRVFERELAAAAJBghgLhYIYC
4QAAAAtzc2gtZWQyNTUxOQAAACCjx1LAEqprX25BhoqMOTYatLiWTFUp5yZ3QeRVFERELA
AAAEB4j2YTstm3JkTHirZKgotr5qZlJtYh9RdFBD1clvK63qPHUsASqmtfbkGGiow5Nhq0
uJZMVSnnJndB5FUUREQsAAAADGZpeHR1cmUtcm9ibwE=
-----END OPENSSH PRIVATE KEY-----
KEY
my $ROBO_PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKPHUsASqmtfbkGGiow5Nhq0uJZMVSnnJndB5FUUREQs fixture-robo';
my $ROBO_FP  = 'SHA256:nqNyKkWIC8O8E3VIvmGZ4SqG0Pq9iXqcUpZCIVpLsSk';
my $PIN2     = 'correct-horse';

package FakeOCP {
    sub new     { my ($c, %a) = @_; bless { %a }, $c }
    sub config  { $_[0]{config} }
    sub verbose { 0 }
}

package FakeSession {
    sub new { my ($c, %a) = @_; bless { writes => [], %a }, $c }
    sub write_channel {
        my ($self, $ch, $payload) = @_;
        push @{ $self->{writes} }, [ $ch, $payload ];
        $self->{on_write}->($payload);
        return Future->done;
    }
    sub close { $_[0]{closed}++; Future->done }
}

# Pods as IO::K8s would hand them back, reduced to what the command reads.
package FakePod {
    sub new      { my ($c, %a) = @_; bless { %a }, $c }
    sub metadata { FakeMeta->new(%{ $_[0] }) }
    sub status   { FakeStatus->new(phase => $_[0]{phase}) }
}
package FakeMeta {
    sub new               { my ($c, %a) = @_; bless { %a }, $c }
    sub name              { $_[0]{name} }
    sub labels            { $_[0]{labels} }
    sub deletionTimestamp { $_[0]{deleting} }
}
package FakeStatus {
    sub new   { my ($c, %a) = @_; bless { %a }, $c }
    sub phase { $_[0]{phase} }
}
package FakeList {
    sub new   { my ($c, @i) = @_; bless { items => [@i] }, $c }
    sub items { $_[0]{items} }
}

package FakeKube {
    sub new  { my ($c, %a) = @_; bless { forwards => [], sessions => [], %a }, $c }
    sub loop { $_[0]{loop} }
    sub list {
        my ($self, $kind, %args) = @_;
        $self->{listed} = [ $kind, %args ];
        return $self->loop->new_future->done(FakeList->new(@{ $self->{pods} }));
    }
    sub port_forward {
        my ($self, $kind, $name, %args) = @_;
        push @{ $self->{forwards} }, $name;
        my $loop = $self->loop;
        my $srv  = $self->{server};
        my $session = FakeSession->new(on_write => sub {
            my ($payload) = @_;
            my $resp = $srv->handle_request($payload) // return;
            $loop->later(sub { $args{on_frame}->(0, pack('v', 9999) . $resp) });
        });
        push @{ $self->{sessions} }, $session;
        return $loop->new_future->done($session);
    }
}

package main;

sub make_project {
    my (%opt) = @_;
    my $dir = Path::Tiny->tempdir;

    my $spec = { name => 'test', control_planes => { provider => 'ssh', host => 'police1' } };
    $spec->{robocop} = { security_level => $opt{level} } if defined $opt{level};
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, $spec);

    my $secrets = OCP::Secrets->new(project_dir => $dir);
    $secrets->generate_age_key;

    unless ($opt{dev_mode}) {
        my $keys = OCP::Keys->new(project_dir => $dir);
        $keys->add_key(name => 'robo-ssh', type => 'ssh_ed25519', purpose => 'automation',
                       private => $ROBO_PRIV, public => $ROBO_PUB);
        $keys->add_key(name => 'admin-ssh', type => 'ssh_ed25519', purpose => 'admin',
                       private => "ADMIN\n", public => 'ssh-ed25519 AAAAadmin admin',
                       pin2 => $PIN2);
    }
    return $dir;
}

sub pod {
    my (%a) = @_;
    return FakePod->new(labels => { app => 'robocop' }, phase => 'Running', %a);
}

# Runs the command with PIN2 stubbed and the fake kube in place of the real
# client. Returns exit code / error, both output channels and the fakes.
sub run_inject {
    my (%opt) = @_;
    my $loop = IO::Async::Loop->new;
    my $srv  = OCP::Robocop::KeyInjection->new(
        expected_public_key => $opt{robocop_expects} // $ROBO_PUB,
        on_key              => sub { },
    );
    my $kube = FakeKube->new(loop => $loop, server => $srv,
                             pods => $opt{pods} // [ pod(name => 'robocop-abc') ]);

    my $cmd = OCP::Cmd::InjectKey->new(
        command_chain => [ FakeOCP->new(config => $opt{dir}->child('ocp.yaml')->stringify) ],
    );

    my $prompts = 0;
    my ($out, $err) = ('', '');
    my ($rc, $died);
    {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub { $prompts++; $opt{pin2} // $PIN2 };
        local *OCP::Cmd::InjectKey::_async_kube = sub { $kube };
        open my $ofh, '>', \$out or die;
        open my $efh, '>', \$err or die;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rc = eval { $cmd->execute(undef, []) };
        $died = $@;
    }
    return { rc => $rc, died => $died, out => $out, err => $err,
             prompts => $prompts, kube => $kube };
}

subtest 'inject-key delivers the robo key and reports the fingerprint on STDOUT' => sub {
    my $r = run_inject(dir => make_project(level => 'inject'));

    is $r->{died}, '', 'no error';
    is $r->{rc}, 0, 'exit 0';
    is $r->{prompts}, 1, 'PIN2 asked once -- injecting is admin-gated';
    is_deeply $r->{kube}{forwards}, ['robocop-abc'], 'port-forwarded to the robocop pod';
    like $r->{out}, qr/robocop-abc.*\Q$ROBO_FP\E/, 'STDOUT: pod and acknowledged fingerprint';
    unlike $r->{out} . $r->{err}, qr/PRIVATE KEY|b3BlbnNzaC/, 'key material is never printed';
    my $sent = $r->{kube}{sessions}[0]{writes}[0][1];
    like $sent, qr/\Q$ROBO_PRIV\E\z/, 'the private robo key is what went over the wire';
    ok $r->{kube}{sessions}[0]{closed}, 'the session was closed';
};

subtest 'only Running robocop pods are targeted' => sub {
    my $r = run_inject(dir => make_project(level => 'inject'), pods => [
        pod(name => 'robocop-old', deleting => '2026-09-24T10:00:00Z'),
        pod(name => 'robocop-pending', phase => 'Pending'),
        pod(name => 'ocp-registry-0', labels => { app => 'ocp-registry' }),
        pod(name => 'robocop-new'),
    ]);
    is $r->{rc}, 0, 'exit 0';
    is_deeply $r->{kube}{forwards}, ['robocop-new'],
        'terminating, pending and foreign pods are skipped';
    is $r->{kube}{listed}[0], 'Pod', 'listed Pods';
    is +{ @{ $r->{kube}{listed} }[1 .. $#{ $r->{kube}{listed} }] }->{namespace}, 'ocp-system',
        'in ocp-system';
};

subtest 'no running robocop pod: fail loud on STDERR' => sub {
    my $r = run_inject(dir => make_project(level => 'inject'),
                       pods => [ pod(name => 'robocop-x', phase => 'Pending') ]);
    like $r->{died}, qr/no running robocop pod/i, 'dies';
    like $r->{died}, qr/deploy-robocop/, 'with what to do';
};

subtest 'robocop refuses the key: exit 1, reason on STDERR, nothing on STDOUT claims success' => sub {
    my $r = run_inject(dir => make_project(level => 'inject'),
        robocop_expects => 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKhJw/y+Q3x+xwFObxVqq/rbjh27tAs5dM2z0r3oAcAx other');
    is $r->{died}, '', 'does not die';
    is $r->{rc}, 1, 'exit 1';
    like $r->{err}, qr/robocop-abc.*does not match/s, 'STDERR names the pod and the reason';
    unlike $r->{out}, qr/\[ok\]/, 'no success line';
};

subtest 'wrong PIN2: refused before any cluster contact' => sub {
    my $r = run_inject(dir => make_project(level => 'inject'), pin2 => 'wrong');
    like $r->{died}, qr/PIN2/, 'dies naming PIN2';
    is scalar @{ $r->{kube}{forwards} }, 0, 'no port-forward was opened';
};

subtest 'not in inject mode: refused, explaining why' => sub {
    my $r = run_inject(dir => make_project(level => 'secret'));
    like $r->{died}, qr/security_level is 'secret'/, 'names the configured level';
    like $r->{died}, qr/inject/, 'and the level that would need this';
    is $r->{prompts}, 0, 'no PIN2 asked';
    is scalar @{ $r->{kube}{forwards} }, 0, 'no port-forward';
};

subtest 'dev mode (no keys.yaml) has no robo key to inject' => sub {
    my $r = run_inject(dir => make_project(level => 'inject', dev_mode => 1));
    like $r->{died}, qr/keys\.yaml/, 'dies naming keys.yaml';
    is scalar @{ $r->{kube}{forwards} }, 0, 'no port-forward';
};

done_testing;

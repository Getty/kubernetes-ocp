#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::SSH;

#
# Test: Constructor defaults
#

{
    my $ssh = OCP::SSH->new(host => 'example.com');
    isa_ok($ssh, 'OCP::SSH');
    is($ssh->host, 'example.com', 'host set');
    is($ssh->user, 'root', 'default user is root');
    is($ssh->port, 22, 'default port is 22');
    is($ssh->connect_timeout, 10, 'default connect_timeout is 10');
    is($ssh->key_file, undef, 'key_file undef without env');
}

#
# Test: Constructor with all params
#

{
    my $ssh = OCP::SSH->new(
        host            => '10.0.0.1',
        user            => 'admin',
        port            => 2222,
        key_file        => '/tmp/test.key',
        connect_timeout => 30,
    );
    is($ssh->host, '10.0.0.1', 'custom host');
    is($ssh->user, 'admin', 'custom user');
    is($ssh->port, 2222, 'custom port');
    is($ssh->key_file, '/tmp/test.key', 'custom key_file');
    is($ssh->connect_timeout, 30, 'custom connect_timeout');
}

#
# Test: _ssh_opts contains hardening options
#

{
    my $ssh = OCP::SSH->new(host => 'test.host');
    my @opts = $ssh->_ssh_opts;

    # Must have -F /dev/null to ignore user config
    my $opts_str = join(' ', @opts);
    like($opts_str, qr/-F\s+\/dev\/null/, '_ssh_opts includes -F /dev/null');
    like($opts_str, qr/StrictHostKeyChecking=no/, '_ssh_opts includes StrictHostKeyChecking=no');
    like($opts_str, qr/UserKnownHostsFile=\/dev\/null/, '_ssh_opts includes UserKnownHostsFile=/dev/null');
    like($opts_str, qr/IdentitiesOnly=yes/, '_ssh_opts includes IdentitiesOnly=yes');
    like($opts_str, qr/ConnectTimeout=10/, '_ssh_opts includes ConnectTimeout');
}

#
# Test: _build_ssh_cmd basic
#

{
    my $ssh = OCP::SSH->new(
        host     => 'server.example.com',
        key_file => '/path/to/key',
    );
    my @cmd = $ssh->_build_ssh_cmd('uname -a');

    is($cmd[0], 'ssh', 'command starts with ssh');
    ok((grep { $_ eq '-F' } @cmd), 'has -F flag');
    ok((grep { $_ eq '/dev/null' } @cmd), 'has /dev/null config');
    ok((grep { $_ eq 'BatchMode=yes' } @cmd), 'has BatchMode=yes');
    ok((grep { $_ eq 'LogLevel=ERROR' } @cmd), 'has LogLevel=ERROR');
    ok((grep { $_ eq '/path/to/key' } @cmd), 'has key file');

    # user@host should be there
    ok((grep { $_ eq 'root@server.example.com' } @cmd), 'has user@host');

    # command at the end
    is($cmd[-1], 'uname -a', 'command is last argument');
}

#
# Test: _build_ssh_cmd with custom port
#

{
    my $ssh = OCP::SSH->new(host => 'test', port => 2222);
    my @cmd = $ssh->_build_ssh_cmd('true');

    ok((grep { $_ eq '-p' } @cmd), 'custom port includes -p');
    ok((grep { $_ eq 2222 } @cmd), 'custom port value present');
}

#
# Test: _build_ssh_cmd default port omits -p
#

{
    my $ssh = OCP::SSH->new(host => 'test');
    my @cmd = $ssh->_build_ssh_cmd('true');

    ok(!(grep { $_ eq '-p' } @cmd), 'default port 22 does not add -p');
}

#
# Test: _build_ssh_cmd without key_file omits -i
#

{
    my $ssh = OCP::SSH->new(host => 'test');
    my @cmd = $ssh->_build_ssh_cmd('true');

    ok(!(grep { $_ eq '-i' } @cmd), 'no key_file means no -i');
}

#
# Test: _build_ssh_cmd with multiple extra args
#

{
    my $ssh = OCP::SSH->new(host => 'test');
    my @cmd = $ssh->_build_ssh_cmd('bash', '-s');

    is($cmd[-2], 'bash', 'first extra arg');
    is($cmd[-1], '-s', 'second extra arg');
}

#
# Test: _build_scp_cmd basic
#

{
    my $ssh = OCP::SSH->new(
        host     => 'server.example.com',
        key_file => '/path/to/key',
    );
    my @cmd = $ssh->_build_scp_cmd;

    is($cmd[0], 'scp', 'scp command starts with scp');
    ok((grep { $_ eq '-F' } @cmd), 'scp has -F flag');
    ok((grep { $_ eq '/dev/null' } @cmd), 'scp has /dev/null config');
    ok((grep { $_ eq '/path/to/key' } @cmd), 'scp has key file');
    ok((grep { $_ eq 'LogLevel=ERROR' } @cmd), 'scp has LogLevel');
}

#
# Test: _build_scp_cmd with custom port uses -P (uppercase)
#

{
    my $ssh = OCP::SSH->new(host => 'test', port => 2222);
    my @cmd = $ssh->_build_scp_cmd;

    ok((grep { $_ eq '-P' } @cmd), 'scp uses -P (uppercase) for port');
    ok((grep { $_ eq 2222 } @cmd), 'scp port value present');
}

#
# Test: _build_scp_cmd does NOT include user@host (caller adds that)
#

{
    my $ssh = OCP::SSH->new(host => 'test');
    my @cmd = $ssh->_build_scp_cmd;

    ok(!(grep { /root\@test/ } @cmd), 'scp_cmd does not include user@host');
}

#
# Test: Custom user in SSH command
#

{
    my $ssh = OCP::SSH->new(host => 'myhost', user => 'deploy');
    my @cmd = $ssh->_build_ssh_cmd('ls');

    ok((grep { $_ eq 'deploy@myhost' } @cmd), 'custom user in user@host');
}

#
# Test: Custom connect_timeout in SSH opts
#

{
    my $ssh = OCP::SSH->new(host => 'test', connect_timeout => 60);
    my @opts = $ssh->_ssh_opts;
    my $opts_str = join(' ', @opts);

    like($opts_str, qr/ConnectTimeout=60/, 'custom connect_timeout in opts');
}

#
# Test: key_file from OCP_SSH_KEY env
#

{
    local $ENV{OCP_SSH_KEY} = '/env/ssh/key';
    my $ssh = OCP::SSH->new(host => 'test');
    is($ssh->key_file, '/env/ssh/key', 'key_file from OCP_SSH_KEY env');
}

#
# Test: is_reachable takes no timeout -- SSH's ConnectTimeout is the only
# ceiling on a probe (karr #112). The argument used to be there, defaulted to
# 5, and was never read: a caller thinking "give it 10s" got one probe with a
# 10s ConnectTimeout, and the parameter told it its number mattered.
#

{
    # Bound probe, returns reachable=0 by default.
    package FakeSSH {
        sub new { my ($c, %a) = @_; bless { %a }, $c }
        sub run {
            my ($s, $cmd) = @_;
            return { exit => $s->{reachable} ? 0 : 1, stdout => '', stderr => '' };
        }
    }
    my $up   = FakeSSH->new(reachable => 1);
    my $down = FakeSSH->new(reachable => 0);
    ok  OCP::SSH::is_reachable($up),
        'is_reachable answers true when run returns 0';
    ok !OCP::SSH::is_reachable($down),
        'is_reachable answers false when run returns non-zero';
}

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::SSH;

#
# k204: a refused key looked like an unreachable host -- 120 s of waiting and
# "SSH not reachable" for a machine that answered at once with Permission
# denied. The wait now stops on the refusal and names user, key and the way out.
#

my $ssh = OCP::SSH->new(host => 'otho-lab.example', user => 'root',
                        key_file => '/p/.ocp/id_ed25519');

my $runs = 0;
{
    no warnings 'redefine';
    local *OCP::SSH::run = sub {
        $runs++;
        return { exit => 255, stdout => '',
                 stderr => "root\@otho-lab.example: Permission denied (publickey).\n" };
    };

    my $ok = eval { $ssh->wait_for_ssh(120, 2); 1 };
    ok !$ok, 'dies';
    like $@, qr/key rejected by otho-lab\.example/, 'names the host';
    like $@, qr{user root with key /p/\.ocp/id_ed25519}, 'names user and key';
    like $@, qr/authorized_keys/, 'and where it has to go';
    unlike $@, qr/not reachable/, 'it is not called unreachable';
    is $runs, 1, 'one probe, no waiting';
}

# An unreachable host still waits out its budget.
{
    no warnings 'redefine';
    my $n = 0;
    local *OCP::SSH::run = sub { $n++; return { exit => 255, stdout => '',
        stderr => "ssh: connect to host x port 22: Connection refused\n" } };
    local $OCP::SSH::WAIT_TIMEOUT = 1;
    my $ok = eval { $ssh->wait_for_ssh(1, 1); 1 };
    ok !$ok, 'dies after the budget';
    like $@, qr/SSH not reachable on otho-lab\.example after 1s/, 'with the reachability message';
    cmp_ok $n, '>=', 1, 'probed';
}

# The key named by its fingerprint: OCP::Node hands wait_for_ssh a temporary
# copy of the cluster key (/tmp/XXXX.key, lab 2026-10-15), a path that tells the
# operator nothing; the fingerprint is what ssh-keygen -l on their side shows.
SKIP: {
    require File::Temp;
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    system('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', "$dir/k") == 0
        or skip 'no ssh-keygen', 2;
    my ($fp) = `ssh-keygen -lf $dir/k.pub` =~ /(SHA256:\S+)/;
    my $s2 = OCP::SSH->new(host => 'h.example', user => 'root', key_file => "$dir/k");
    no warnings 'redefine';
    local *OCP::SSH::run = sub { { exit => 255, stdout => '',
        stderr => "root\@h.example: Permission denied (publickey).\n" } };
    eval { $s2->wait_for_ssh(120, 2) };
    like $@, qr/\Q$fp\E/, 'names the key by its fingerprint';
    like $@, qr/key rejected by h\.example/, 'still names the host';
}

done_testing;

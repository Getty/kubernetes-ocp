#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::K8s;
use OCP::Node;

#
# k449 (found during k445): a failed install left the OCPNode's
# status.message as "Rex task failed: Rex task 'install_rke2_agent' failed:
# ..." -- OCP::Rex names the task and OCP::Node prefixed it again. The
# wording of OCP::Rex is pinned by t/219; OCP::Node keeps it as it is and
# prefixes only an error that does not already name a failed Rex task (one
# raised before the task ran, e.g. learning the host key).
#

my @patches;
{
    no warnings 'redefine';
    *OCP::K8s::patch_status = sub { my ($c, $api, %a) = @_; push @patches, $a{status}; 1 };
}
our $REX_ERR;
{
    package FakeSSH;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub wait_for_ssh { 1 }
    sub run { +{ exit => 0 } }
    package FakeRex;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub run_task { die $main::REX_ERR }
}
sub last_patch { my %m; for my $p (@patches) { $m{$_} = $p->{$_} for keys %$p } \%m }

sub install_fails_with {
    my ($err) = @_;
    @patches = ();
    local $REX_ERR = $err;
    my $n = OCP::Node->from_cr({
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => '10.0.0.5' },
        status   => { phase => 'Installing', publicIP => '10.0.0.5' },
    }, k8s => 'x', ssh_key => 'K', server_url => 'https://cp:9345', join_token => 'T',
       ssh_class => 'FakeSSH', rex_class => 'FakeRex');
    {
        no warnings 'redefine';
        local *OCP::Node::_seed_known_hosts = sub { '/dev/null' };
        local *OCP::Node::_pin_host_keys    = sub { 1 };
        $n->_install_kubernetes;
    }
    return last_patch();
}

subtest 'a failed Rex task: the message names it once' => sub {
    my $p = install_fails_with("Rex task 'install_rke2_agent' failed: the host refused\n");
    is $p->{phase}, 'Failed', 'Failed';
    is $p->{message}, "Rex task 'install_rke2_agent' failed: the host refused\n",
        'the message is OCP::Rex\'s, unprefixed';
    unlike $p->{message}, qr/Rex task failed/, 'no second prefix';
};

subtest 'an error before the task ran keeps the prefix' => sub {
    my $p = install_fails_with("ssh: connect to host 10.0.0.5 port 22: Connection refused\n");
    is $p->{phase}, 'Failed', 'Failed';
    is $p->{message}, "Rex task failed: ssh: connect to host 10.0.0.5 port 22: Connection refused\n",
        'prefixed once, so it still says where it came from';
};

done_testing;

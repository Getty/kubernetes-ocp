#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';
use OCP::K8s;
use OCP::Node;
use OCP::SSH;

#
# k240 (lab round 10, note 46): the "does not resolve" text of k236 is the
# CLI's -- "the lookup failed on this machine (DNS or /etc/hosts)". Under
# robocop the lookup ran inside its pod, through the cluster DNS (CoreDNS), so
# the same words send the operator to the wrong machine. The message is one
# source with a context:
#   robocop (reconciler_id robocop@...): the lookup failed in the cluster,
#     fix = cluster DNS entry or the IP;
#   CLI (reconciler_id 'cli', and OCP::SSH->unresolved_message($host) alone):
#     the wording stays word for word.
#

my @patches;
{
    no warnings 'redefine';
    *OCP::K8s::patch_status = sub { my ($c, $api, %a) = @_; push @patches, $a{status}; 1 };
}
our $ERR;
{
    package FakeSSH;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub wait_for_ssh { 1 }
    sub run { +{ exit => 0 } }
    package FakeRex;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub run_task { die $main::ERR }
    package FakeProvider;
    sub new { bless {}, shift }
    sub delete_server { die $main::ERR }
}
sub last_patch { my %m; for my $p (@patches) { $m{$_} = $p->{$_} for keys %$p } \%m }

my $CLI_TEXT = "Name 'crag.lab' does not resolve: the lookup failed on this machine"
             . " (DNS or /etc/hosts), so no SSH connection was attempted. This is"
             . " not a key problem. Fix the name or use the IP address.\n";

sub install_message {
    my ($rid) = @_;
    @patches = ();
    local $ERR = "Rex task 'install_rke2_agent' failed: Failed to resolve hostname crag.lab (Name or service not known)\n";
    my $n = OCP::Node->from_cr({
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => 'crag.lab' },
        status   => { phase => 'Installing', publicIP => 'crag.lab' },
    }, k8s => 'x', ssh_key => 'K', server_url => 'https://cp:9345', join_token => 'T',
       ssh_class => 'FakeSSH', rex_class => 'FakeRex', ($rid ? (reconciler_id => $rid) : ()));
    no warnings 'redefine';
    local *OCP::Node::_seed_known_hosts = sub { '/dev/null' };
    local *OCP::Node::_pin_host_keys    = sub { 1 };
    $n->_install_kubernetes;
    my $p = last_patch();
    return ($p->{phase}, $p->{message});
}

sub teardown_message {
    my ($rid) = @_;
    @patches = ();
    local $ERR = "ssh: Could not resolve hostname crag.lab: Name or service not known\n";
    my $n = OCP::Node->from_cr({
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', host => 'crag.lab' },
        status   => { phase => 'Ready', publicIP => 'crag.lab', providerId => 'SRV1' },
    }, k8s => 'x', provider => FakeProvider->new, ($rid ? (reconciler_id => $rid) : ()));
    no warnings 'redefine';
    local *OCP::Node::_acquire_lease    = sub { 1 };
    local *OCP::Node::_release_lease    = sub { 1 };
    local *OCP::Node::_cordon           = sub { 0 };
    local *OCP::Node::_seed_known_hosts = sub { '/dev/null' };
    eval { $n->teardown };
    return (last_patch()->{phase}, last_patch()->{message});
}

sub robocop_ok {
    my ($msg, $label) = @_;
    like   $msg, qr/Name 'crag\.lab' does not resolve/, $label . ': still names the host and the problem';
    like   $msg, qr/CoreDNS|cluster DNS/,               $label . ': the lookup failed in the cluster DNS';
    like   $msg, qr/robocop/,                           $label . ': names robocop / its pod';
    like   $msg, qr/\bIP\b/,                            $label . ': offers the IP as the way out';
    unlike $msg, qr/this machine/,                      $label . ': not "this machine"';
    unlike $msg, qr{/etc/hosts},                        $label . ': not /etc/hosts';
}

subtest 'robocop: Rex install failure on an unresolvable name' => sub {
    my ($phase, $msg) = install_message('robocop@robocop-7d9f-abcde');
    is $phase, 'Failed', 'Failed';
    robocop_ok($msg, 'install');
};

subtest 'robocop: teardown on an unresolvable name' => sub {
    my ($phase, $msg) = teardown_message('robocop@robocop-7d9f-abcde');
    is $phase, 'Failed', 'Failed';
    like $msg, qr/\ATeardown failed: Name 'crag\.lab' does not resolve/, 'teardown prefix kept';
    robocop_ok($msg, 'teardown');
    like $msg, qr/ocp node rm w1/, 'way out kept';
};

subtest 'CLI: wording unchanged, word for word' => sub {
    my ($phase, $msg) = install_message('cli');
    is $phase, 'Failed', 'Failed';
    (my $want = $CLI_TEXT) =~ s/\n\z//;
    is $msg, $want, 'install: status.message is the k236 text exactly';

    my (undef, $tmsg) = teardown_message('cli');
    like $tmsg, qr/\ATeardown failed: \Q$want\E\n/, 'teardown: embeds the k236 text exactly';

    my (undef, $default) = install_message(undef);
    is $default, $want, 'default reconciler_id (cli) is the CLI text';
};

subtest 'OCP::SSH->unresolved_message with one argument is unchanged' => sub {
    is( OCP::SSH->unresolved_message('crag.lab'), $CLI_TEXT, 'verbatim' );
};

done_testing;

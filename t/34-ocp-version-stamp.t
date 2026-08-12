#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Update;

#
# `ocp update` gates on status.ocpVersion and `ocp version` reports it. The
# only writer was update itself, at the end of a run it refused to start —
# so on a cluster this CLI had just bootstrapped, `ocp update` answered
# "Cluster not yet deployed. Run 'ocp apply' first." while `ocp status` on
# the same project listed a Ready node.
#

local @ARGV = ();
my $ocp = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);

sub project {
    my ($name, %opts) = @_;
    my $dir = path($tmpdir)->child($name);
    $dir->mkpath;
    my $file = $dir->child('ocp.yaml');
    $ocp->dump_file($file->stringify, {
        name           => $name,
        control_planes => [{ provider => 'ssh', host => '127.0.0.1' }],
    });
    $dir->child('kubeconfig.yaml')->spew("encrypted-placeholder\n")
        if $opts{deployed};
    return $file;
}

package Local::FakeOCP {
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub config  { $_[0]{config} }
    sub verbose { 0 }
}

subtest 'apply stamps the OCP version into the status file' => sub {
    my $file   = project('stamped');
    my $config = OCP::Config->new(file => $file->stringify, ocp => $ocp);

    ok !$config->status->{ocpVersion}, 'nothing recorded before';

    OCP::Cmd::Apply::_stamp_ocp_version(undef, $config);

    is $config->status->{ocpVersion}, $OCP::VERSION,
        'the running OCP version is recorded';

    my $reread = OCP::Config->new(file => $file->stringify, ocp => $ocp);
    is $reread->status->{ocpVersion}, $OCP::VERSION,
        'and it survives a reload, so update sees it in the next process';
};

subtest 'update tells the two situations apart' => sub {
    my $undeployed = OCP::Cmd::Update->new(
        command_chain => [Local::FakeOCP->new(
            config => project('undeployed')->stringify)],
    );
    eval { $undeployed->execute([], []) };
    like $@, qr/not yet deployed/,
        'no cluster at all: says so';

    my $unstamped = OCP::Cmd::Update->new(
        command_chain => [Local::FakeOCP->new(
            config => project('unstamped', deployed => 1)->stringify)],
    );
    eval { $unstamped->execute([], []) };
    like $@, qr/did not record its version/,
        'a deployed cluster without a stamp is not called undeployed';
    unlike $@, qr/not yet deployed/,
        'and is not sent to `ocp apply first` as if nothing existed';
};

done_testing;

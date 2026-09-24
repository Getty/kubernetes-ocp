#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

#
# k155: prepare_node is Rex::Rancher::Node::prepare_node plus the three things
# OCP does differently (rex-rancher k42): NTP is only installed when the clock
# is not synchronised yet and a failed chrony install is not fatal, a node
# without a domain still gets its /etc/hosts entry, and the locale is
# generated. Then the legacy containerd template cleanup (t/68).
#
# The Rexfile runs against recorders (t/lib/OCPTest/Rexfile.pm).
#

sub prepare {
    my (%o) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = $o{run} // sub { ('', 0) };
    return OCPTest::Rexfile->run_task('prepare_node', $o{params} // {});
}

subtest 'the library prepares the node, NTP left to OCP' => sub {
    prepare(params => { hostname => 'police1', timezone => 'Europe/Berlin', locale => 'de_DE.UTF-8' });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Node::prepare_node');
    ok $o, 'Rex::Rancher::Node::prepare_node called' or return;
    is $o->{hostname}, 'police1', 'hostname';
    is $o->{timezone}, 'Europe/Berlin', 'timezone';
    is $o->{locale}, 'de_DE.UTF-8', 'locale';
    ok exists $o->{ntp} && !$o->{ntp}, 'ntp => 0: the library does not force chrony';
    ok !exists $o->{domain}, 'no domain given, none passed';
};

subtest 'defaults' => sub {
    prepare();
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Node::prepare_node');
    is $o->{timezone}, 'UTC', 'UTC';
    is $o->{locale}, 'en_US.UTF-8', 'en_US.UTF-8';
    ok !exists $o->{hostname}, 'no hostname: the host keeps its own';
    is scalar(OCPTest::Rexfile->calls('host_entry')), 0, 'and no /etc/hosts entry';
};

subtest '/etc/hosts without a domain' => sub {
    prepare(params => { hostname => 'raichu' });
    my ($e) = OCPTest::Rexfile->calls('host_entry');
    ok $e, 'an entry is written' or return;
    is $e->{args}[0], 'raichu', 'for the hostname';
    my %o = @{ $e->{args} }[1 .. $#{ $e->{args} }];
    is $o{ip}, '127.0.1.1', 'on 127.0.1.1';

    prepare(params => { hostname => 'raichu', domain => 'vm' });
    is scalar(OCPTest::Rexfile->calls('host_entry')), 0, 'with a domain the library writes it';
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Node::prepare_node');
    is $o->{domain}, 'vm', 'domain passed';
};

subtest 'the locale is generated' => sub {
    prepare(params => { locale => 'de_DE.UTF-8' });
    ok((grep { /^locale-gen de_DE\.UTF-8\b/ } OCPTest::Rexfile->commands), 'locale-gen');
};

subtest 'NTP: a synchronised clock is left alone' => sub {
    prepare(run => sub { $_[0] =~ /NTPSynchronized/ ? ("yes\n", 0) : ('', 0) });
    is scalar(OCPTest::Rexfile->calls('pkg')), 0, 'no chrony install';
};

subtest 'NTP: an unsynchronised clock gets chrony' => sub {
    prepare(run => sub { $_[0] =~ /NTPSynchronized/ ? ("no\n", 0) : ('', 0) });
    my ($p) = OCPTest::Rexfile->calls('pkg');
    is_deeply $p && $p->{args}[0], ['chrony'], 'chrony';
    ok((grep { /enable --now chrony/ } OCPTest::Rexfile->commands), 'enabled');
};

subtest 'NTP: ntp => 0 skips it' => sub {
    prepare(params => { ntp => 0 }, run => sub { ("no\n", 0) });
    is scalar(OCPTest::Rexfile->calls('pkg')), 0, 'nothing installed';
    ok !(grep { /NTPSynchronized/ } OCPTest::Rexfile->commands), 'nothing asked';
};

subtest 'the legacy containerd template cleanup runs last' => sub {
    prepare();
    my @calls = @OCPTest::Rexfile::CALLS;
    is $calls[-1]{name}, 'do_task', 'a task';
    is $calls[-1]{args}[0], 'cleanup_legacy_containerd_template', 'the cleanup';
};

done_testing;

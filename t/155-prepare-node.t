#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;

#
# k155: prepare_node is Rex::Rancher::Node::prepare_node, then the legacy
# containerd template cleanup (t/68).
#
# Up to Rex::Rancher 0.002 OCP did three things itself (rex-rancher k42): NTP
# only when the clock was not synchronised yet, with a failed chrony install
# not fatal; the /etc/hosts entry for a node without a domain; locale-gen.
# Rex::Rancher 0.003 does all three with those semantics, so the claim here is
# that OCP hands the library its parameters -- ntp included -- and does none of
# them on its own any more. What the library does with them is held against
# the real library in t/155-rex-libraries.t.
#
# The Rexfile runs against recorders (t/lib/OCPTest/Rexfile.pm).
#

sub prepare {
    my (%o) = @_;
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::RUN = $o{run} // sub { ('', 0) };
    return OCPTest::Rexfile->run_task('prepare_node', $o{params} // {});
}

subtest 'the library prepares the node, NTP included' => sub {
    prepare(params => { hostname => 'police1', timezone => 'Europe/Berlin', locale => 'de_DE.UTF-8' });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Node::prepare_node');
    ok $o, 'Rex::Rancher::Node::prepare_node called' or return;
    is $o->{hostname}, 'police1', 'hostname';
    is $o->{timezone}, 'Europe/Berlin', 'timezone';
    is $o->{locale}, 'de_DE.UTF-8', 'locale';
    ok $o->{ntp}, 'ntp on by default: the library leaves a synchronised clock alone';
    ok !exists $o->{domain}, 'no domain given, none passed';
};

subtest 'defaults' => sub {
    prepare();
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Node::prepare_node');
    is $o->{timezone}, 'UTC', 'UTC';
    is $o->{locale}, 'en_US.UTF-8', 'en_US.UTF-8';
    ok !exists $o->{hostname}, 'no hostname: the host keeps its own';
};

subtest 'ntp => 0 reaches the library' => sub {
    prepare(params => { ntp => 0 });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Node::prepare_node');
    ok exists $o->{ntp} && !$o->{ntp}, 'ntp => 0';
};

subtest 'a domain is passed on' => sub {
    prepare(params => { hostname => 'raichu', domain => 'vm' });
    my $o = OCPTest::Rexfile->lib_opts('Rex::Rancher::Node::prepare_node');
    is $o->{hostname}, 'raichu', 'hostname';
    is $o->{domain}, 'vm', 'domain';
};

subtest 'OCP does none of the library\'s steps itself any more' => sub {
    prepare(params => { hostname => 'raichu', locale => 'de_DE.UTF-8' },
            run => sub { $_[0] =~ /NTPSynchronized/ ? ("no\n", 0) : ('', 0) });
    is scalar(OCPTest::Rexfile->calls('host_entry')), 0, 'no /etc/hosts entry of its own';
    is scalar(OCPTest::Rexfile->calls('pkg')), 0, 'no chrony install of its own';
    is_deeply [ OCPTest::Rexfile->commands ], [],
        'no command of its own: no locale-gen, no timedatectl, no systemctl';
};

subtest 'the legacy containerd template cleanup runs last' => sub {
    prepare();
    my @calls = @OCPTest::Rexfile::CALLS;
    is $calls[-1]{name}, 'do_task', 'a task';
    is $calls[-1]{args}[0], 'cleanup_legacy_containerd_template', 'the cleanup';
    my $lib = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'Rex::Rancher::Node::prepare_node' });
    ok $lib >= 0 && $lib < $#calls, 'after the library';
};

done_testing;

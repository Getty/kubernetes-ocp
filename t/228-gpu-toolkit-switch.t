#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Cmd::Apply::Workloads;

#
# k228 point 5 (lab note 15): gpu.toolkit decides at join time who prepares a
# GPU node. Flipping it under a running cluster changes the ClusterPolicy but
# not the nodes; apply says so instead of staying quiet.
#

sub warning_for {
    my ($enabled, $now) = @_;
    my $cp = defined $enabled ? { spec => { toolkit => { enabled => $enabled } } } : undef;
    return OCP::Cmd::Apply::Workloads::toolkit_switch_warning($cp, $now);
}

like warning_for(JSON::PP::false, 1), qr/\[WARN\] gpu\.toolkit changed \(false -> true\).*Re-join them/s,
    'false -> true is said, with the way out';
like warning_for(JSON::PP::true, 0), qr/\(true -> false\)/, 'true -> false too';
is warning_for(JSON::PP::true, 1),  undef, 'unchanged: nothing';
is warning_for(JSON::PP::false, 0), undef, 'unchanged false: nothing';
is warning_for(undef, 1), undef, 'no ClusterPolicy yet: nothing to compare';
is OCP::Cmd::Apply::Workloads::toolkit_switch_warning({ spec => {} }, 1), undef,
    'a ClusterPolicy without toolkit: nothing';

like path('lib/OCP/Cmd/Apply/Workloads.pm')->slurp_utf8,
    qr/sub setup_gpu_operator \{.*toolkit_switch_warning\(\$cp, \$config->gpu_toolkit\)/s,
    'setup_gpu_operator asks it for the running cluster';

done_testing;

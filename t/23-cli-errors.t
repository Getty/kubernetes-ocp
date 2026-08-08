#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Cwd qw(getcwd);
use FindBin;

use OCP;

#
# Test: _clean_message separates user-facing messages from internal errors
#

{
    my ($msg, $internal) = OCP::_clean_message("No cluster deployed. Run 'ocp apply' first.\n");
    is($msg, "No cluster deployed. Run 'ocp apply' first.", 'user message kept verbatim');
    is($internal, 0, 'trailing newline means user-facing');
}

{
    my ($msg, $internal) = OCP::_clean_message("Something broke at /opt/ocp/lib/OCP.pm line 42.\n");
    is($msg, 'Something broke', 'source location stripped');
    is($internal, 1, 'source location means internal');
}

{
    my ($msg, $internal) = OCP::_clean_message("ERROR: Cannot decrypt kubeconfig.yaml\n");
    is($msg, 'Cannot decrypt kubeconfig.yaml', 'existing ERROR prefix normalized away');
    is($internal, 0, 'still user-facing');
}

{
    my ($msg) = OCP::_clean_message("Multi\nline\nmessage\n");
    is($msg, "Multi\nline\nmessage", 'multi-line user messages survive');
}

{
    my ($msg, $internal) = OCP::_clean_message(
        "Bad thing at /opt/ocp/lib/OCP/Node.pm line 10.\n"
      . "\tOCP::Node::reconcile called at /opt/ocp/lib/OCP/Cmd/Apply.pm line 20\n"
    );
    is($msg, 'Bad thing', 'confess trace tail stripped');
    is($internal, 1, 'confess counts as internal');
}

{
    my ($msg) = OCP::_clean_message("\n");
    is($msg, 'unknown error', 'empty error gets a placeholder');
}

#
# Test: the CLI reports a missing config without a Perl stacktrace
#

{
    my $dir = tempdir(CLEANUP => 1);
    my $bin = "$FindBin::Bin/../bin/ocp";
    my $cwd = getcwd();

    chdir $dir or die "chdir: $!";
    my $output = `$^X $bin status 2>&1`;
    my $rc = $? >> 8;
    chdir $cwd or die "chdir back: $!";

    is($rc, 1, 'missing config exits 1');
    like($output, qr/Config file 'ocp\.yaml' not found/, 'reports the actual problem');
    unlike($output, qr/ line \d+\./, 'no Perl source location in output');
    unlike($output, qr/internal error/, 'not flagged as internal');
}

done_testing;

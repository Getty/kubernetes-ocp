package OCPTest::Watchdog;
# ABSTRACT: end a test file that runs past OCP_TEST_TIMEOUT seconds, naming it

use strict;
use warnings;
use POSIX ();

# `make test` preloads this into every perl of the run (PERL5OPT, k467) and
# sets OCP_TEST_TIMEOUT. A test file that hangs -- t/435 sat 23 min in a real
# 60x10s wait -- used to stall the whole binding run without a word; now it
# is ended after OCP_TEST_TIMEOUT seconds, the line below names it on STDERR,
# and prove counts the file as failed and goes on with the next one.
#
# A watchdog process, not alarm(): there is one alarm per process, and a test
# that sets its own (alarm 120 at the top, alarm 0 at the end, a $SIG{ALRM}
# of its own) would silently replace or cancel it. The watchdog is a
# grandchild (double fork), so no wait() in the test -- Test2's IPC wait
# included -- ever waits for it. The test file moves into a process group of
# its own first, so the kill also reaches whatever the test started (a fake
# API server, an `ocp` child) and could still hold prove's TAP pipe open.
#
# Armed only in a test file itself ($0 ending in .t): every other perl of the
# run (bin/ocp, a rex child, $^X -e ...) loads this, finds nothing to do, and
# is left as it was.

sub import {
  my ( $class ) = @_;
  my $limit = $ENV{OCP_TEST_TIMEOUT} // '';
  return unless $limit =~ /\A[0-9]+\z/ && $limit > 0;
  return unless $0 =~ /\.t\z/;
  $class->_arm( $limit, $0 );
}

sub _arm {
  my ( $class, $limit, $file ) = @_;
  my $test = $$;
  setpgrp( 0, 0 );
  my $pid = fork;
  return unless defined $pid;   # no watchdog is no reason to fail the file
  if ($pid) {
    waitpid( $pid, 0 );
    return;
  }
  # Intermediate child: fork the watchdog and leave at once.
  POSIX::_exit(0) if fork // 1;
  $class->_watch( $limit, $file, $test );
}

sub _watch {
  my ( $class, $limit, $file, $test ) = @_;
  # Out of the test's group, so the kill below does not reach the watchdog.
  # Off the test's STDOUT *and* STDERR: prove reads both pipes to their end
  # (TAP::Parser::Iterator::Process selects on the two), so a watchdog that
  # kept either one would hold every file open until its limit ran out.
  setpgrp( 0, 0 );
  open STDIN,  '<', '/dev/null';
  open STDOUT, '>', '/dev/null';
  open STDERR, '>', '/dev/null';
  my $end = time + $limit;
  while ( time < $end ) {
    POSIX::_exit(0) unless kill 0, $test;
    sleep 1;
  }
  POSIX::_exit(0) unless kill 0, $test;
  # The test's own STDERR, reopened through /proc only now (Linux, as in the
  # image), so the line lands where the file's own diagnostics would.
  if ( open my $err, '>>', '/proc/'.$test.'/fd/2' ) {
    print {$err} '# '.$file.': still running after '.$limit.' s, killed'
      .' (OCP_TEST_TIMEOUT; raise it with make test TEST_TIMEOUT=N, 0 = off)'."\n";
    close $err;
  }
  kill 'TERM', -$test;
  sleep 3;
  kill 'KILL', -$test;
  POSIX::_exit(0);
}

1;

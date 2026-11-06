package OCPTest::CiliumRefusal;
# ABSTRACT: The refusal Rex::Rancher's Cilium residue guard dies with, from the library itself

use strict;
use warnings;
use Carp qw( croak );

use Rex::Commands::Run ();
use Rex::Rancher::Uninstall ();

# t/190 and t/219 hand a refused install the guard's message and assert that
# OCP passes it on. They carried a copy of its words, which went stale when
# Rex::Rancher 0.005 named a way out without a reboot as well (k406). This
# asks the real check_cilium_residue instead, with its probe answered by the
# names given: the text is whatever the installed library says.
#
#   my $refusal = OCPTest::CiliumRefusal->text('/sys/fs/bpf/cilium', 'cilium_host');
#
# Nothing runs on a host: Rex::Commands::Run::run, the one channel the guard
# reads the host through, is replaced while it runs. A guard that no longer
# refuses for these names, or no longer reads through that channel, croaks
# here, so a test cannot go on with an empty refusal.
#
# The real check_cilium_residue, taken when this file loads: OCPTest::Rexfile
# records over it once it loads the Rexfile (the install tasks call it since
# k406), and a recorder refuses nothing -- which croaks below, never passes.
my $CHECK = \&Rex::Rancher::Uninstall::check_cilium_residue;

sub text {
  my ( $class, @found ) = @_;
  croak 'text needs at least one residue name' unless @found;

  my $probe = Rex::Rancher::Uninstall->cilium_residue_probe_cmd;
  my @ran;
  my $ok = do {
    no warnings 'redefine';
    local *Rex::Commands::Run::run = sub {
      push @ran, $_[0];
      $? = 0;
      return $_[0] eq $probe ? join('', map { "$_\n" } @found) : '';
    };
    eval { $CHECK->('Rex::Rancher::Uninstall'); 1 };
  };
  my $refusal = $@;

  croak 'check_cilium_residue did not refuse a host with ' . join(', ', @found)
    . ' (it ran: ' . join(' | ', @ran) . ')' if $ok;
  croak 'check_cilium_residue died with something other than a message: ' . $refusal
    unless !ref $refusal && length $refusal;
  return $refusal;
}

1;

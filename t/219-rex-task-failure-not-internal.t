#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP;
use OCP::Rex;

#
# k219: install_rke2_server refused a host with Cilium state from an earlier
# cluster, correctly, with "... Reboot the host, then run the install again."
# -- and ocp put "This is an internal error. Run again with --verbose for the
# full trace." under it (ocpt, 2026-10-01).
#
# OCP::run_cli calls an error internal when it ends in a source location, and
# OCP::Rex reported a failed task with croak, which always appends one (the
# caller's line in lib/). A failed Rex task is not an OCP bug: it is the
# remote step refusing or failing, its diagnosis is the task's own message
# (Rex output, on STDERR already), and --verbose has no trace to add. So it
# is reported as a plain message, and run_cli says nothing about internals.
#

my $tmp = tempdir(CLEANUP => 1);
my $key = path($tmp)->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub key');
my $rexfile = path($tmp)->child('Rexfile');
$rexfile->spew("# stub\n");
my $known_hosts = path($tmp)->child('known_hosts');
$known_hosts->spew("cp.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr\n");
$ENV{OCP_KNOWN_HOSTS} = $known_hosts->stringify;

my $PREFLIGHT = "[2026-10-01 07:40:00] ERROR - Error executing task:\n"
  . "[2026-10-01 07:40:00] ERROR - This host still carries Cilium datapath state from an "
  . "earlier cluster (cilium_host). Nothing was written or installed. Reboot the host, "
  . "then run the install again.\n";

{
    no warnings 'redefine';
    *OCP::Rex::_find_rexfile = sub { $rexfile->stringify };
    *OCP::Rex::run = sub { ${ $_[3] } = $PREFLIGHT; return 0 };
}

sub quiet (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    local *STDOUT = $ofh;
    local *STDERR = $efh;
    return ($code->(), $err);
}

my ($ok) = quiet {
    my $r = eval { OCP::Rex->new(host => 'cp.example', key_file => "$key")->run_task('install_rke2_server'); 1 };
    $r ? 1 : 0;
};
my $died = $@;

ok !$ok, 'the failed task dies';
like $died, qr/Rex task 'install_rke2_server' failed:.*Reboot the host/s,
    'with the task and its reason';
unlike $died, qr/ at \S+ line \d+\.?\s*\z/, 'and no source location of OCP\'s own';

my (undef, $stderr) = quiet { OCP::_report_error($died, 0) };
like $stderr, qr/Reboot the host, then run the install again/, 'run_cli shows the reason';
unlike $stderr, qr/internal error/, 'and does not call it an internal error';

# The classification itself is unchanged: an error with a location stays internal.
my (undef, $internal) = quiet { OCP::_report_error("Can't call method \"x\" on undef at lib/OCP/Foo.pm line 3.\n", 0) };
like $internal, qr/internal error/, 'a real Perl error is still reported as internal';

done_testing;

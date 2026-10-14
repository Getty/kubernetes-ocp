#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Rex;

#
# k201: a refusal from a Rex task (rex-rancher k67, "Refusing to install rke2
# with cluster-cidr ...") reached the operator three times: Rex's ERROR line,
# the task error, and OCP's "Error: Rex task ... failed" with the whole Rex
# log. The reason is now said once, in the error, and the raw log stays out of
# the way unless --verbose asks for it.
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

my $REFUSAL = "Refusing to install rke2 with cluster-cidr 10.9.0.0/16: the running server has 10.42.0.0/16";
my $LOG = "[2026-09-27 03:41:00] ERROR - Error executing task:\n"
        . "[2026-09-27 03:41:00] ERROR - $REFUSAL\n"
        . "[2026-09-27 03:41:00] ERROR - $REFUSAL\n"
        . "[2026-09-27 03:41:01] ERROR - Error executing task:\n";

{
    no warnings 'redefine';
    *OCP::Rex::_find_rexfile = sub { $rexfile->stringify };
    *OCP::Rex::run = sub { ${ $_[3] } = $LOG; return 0 };
}

sub run_failing {
    my (%args) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my $died;
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        eval { OCP::Rex->new(host => 'cp.example', key_file => "$key", %args)->run_task('install_rke2_server'); 1 }
            or $died = $@;
    }
    return ($died, $err);
}

my ($died, $stderr) = run_failing();

is scalar(() = $died =~ /Refusing to install/g), 1, 'the refusal is in the error exactly once';
unlike $died, qr/Error executing task/, 'without Rex\'s header line';
unlike $stderr, qr/Refusing to install/, 'and the raw log is not printed besides it';

my (undef, $verbose_err) = run_failing(verbose => 1);
like $verbose_err, qr/--- Rex Output ---.*Refusing to install/s, '--verbose still shows the log';

# No ERROR line at all: the whole of stderr is the diagnosis, as before.
{
    no warnings 'redefine';
    *OCP::Rex::run = sub { ${ $_[3] } = "something odd happened\n"; return 0 };
}
my ($d2, $s2) = run_failing();
like $d2, qr/something odd happened/, 'without ERROR lines the full output is the reason';
like $s2, qr/--- Rex Output ---/, 'and the log is shown';

done_testing;

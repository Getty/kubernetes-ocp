#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Cwd qw( getcwd );
use File::Temp qw( tempdir );
use FindBin;
use IPC::Run ();
use JSON::MaybeXS ();
use Path::Tiny qw( path );

use OCP::Rex;

#
# k316: the rex child that runs share/Rexfile compares a boolean parameter as
# ocp and robocop do since k314. task_params() decodes REX_TASK_PARAMS with
# JSON::MaybeXS, so a true or false arrives as a JSON::PP::Boolean, and under
# Cpanel::JSON::XS `'hetzner' eq $true` was 1 there (t/314-boolean-eq.t has
# the cause). The correction lives in OCP::BooleanEq, which OCP.pm and the
# Rexfile both load.
#
# A module in lib/ only helps if the child can load it, and the suite is the
# one place where that is easy to get wrong: in the image the child's @INC is
# the image's local-lib and nothing else -- bin/ocp's `use lib` stays in the
# ocp process, and OCP::Rex runs a private copy of the Rexfile from a
# temporary directory. Under `prove -l` the child would find lib/ anyway,
# through the PERL5LIB prove exports and through Rex, which puts <cwd>/lib in
# front of @INC. So this runs the child the way the image does: from a
# project directory outside the checkout, with the checkout's lib/ taken out
# of PERL5LIB. What is left to put it back is OCP::Rex.
#
# The child is the real one: OCP::Rex->run_task builds the command, copies the
# Rexfile and sets the environment, and the stand-in for IPC::Run::run starts
# that same rex on that same copy in that environment. Only the host and the
# task are swapped for `-e`, which runs a few lines of Perl on <local> after
# the Rexfile has loaded -- no task of the Rexfile, no host.
#

my $rex_bin = (grep { -x "$_/rex" } split /:/, $ENV{PATH} // '')[0];
plan skip_all => 'no rex on PATH; the image has it' unless defined $rex_bin;

# The fixed 4-argument run shape; OCP_REX_DEBUG would switch to the tee shape.
delete local $ENV{OCP_REX_DEBUG};

my $checkout_lib = path($FindBin::Bin)->parent->child('lib')->realpath;

my $tmp = tempdir(CLEANUP => 1);
my $key = path($tmp)->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub key');

# A host already in known_hosts goes straight to rex (k168).
my $known_hosts = path($tmp)->child('known_hosts');
$known_hosts->spew("psyduck.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr\n");

my $project = path($tmp)->child('project');
$project->mkpath;

# The image's PERL5LIB: what prove exported, without the checkout's lib/.
sub is_checkout_lib {
    my ($dir) = @_;
    my $real = eval { path($dir)->realpath } or return 0;
    return "$real" eq "$checkout_lib";
}
my $image_perl5lib = join ':', grep { length && !is_checkout_lib($_) }
    split /:/, ($ENV{PERL5LIB} // '');

# Runs a perl snippet in the rex child, as OCP::Rex starts it. Returns what
# the child printed and the environment and command run_task handed it.
my $PROBE = <<'PROBE';
my $p = task_params();
my $t = $p->{probe};
print 'REF=', ref($t), "\n";
print 'BACKEND=', JSON::MaybeXS::JSON(), "\n";
print 'HETZNER_EQ_TRUE=', ('hetzner' eq $t ? 1 : 0), "\n";
print 'TRUE_EQ_TRUE=', ('true' eq $t ? 1 : 0), "\n";
print 'FIX_FROM=', ($INC{'OCP/BooleanEq.pm'} // ''), "\n";
PROBE

sub run_child {
    my (%params) = @_;
    my %seen;
    no warnings 'redefine';
    local *OCP::Rex::run = sub {
        my ($cmd, $in, $out, $err) = @_;
        $seen{cmd}      = [@$cmd];
        $seen{perl5lib} = $ENV{PERL5LIB};
        my ($o, $e) = ('', '');
        $seen{ok}  = IPC::Run::run([ @$cmd[0 .. 2], '-m', '-e', $PROBE ], \undef, \$o, \$e);
        $seen{out} = $o;
        $seen{err} = $e;
        $$out = '';
        $$err = '';
        return 1;
    };
    my $cwd = getcwd;
    chdir "$project" or die "chdir $project: $!";
    local $ENV{PERL5LIB} = $image_perl5lib;
    my $ok = eval {
        my $stdout = '';
        local *STDOUT;
        open STDOUT, '>', \$stdout or die "STDOUT: $!";
        OCP::Rex->new(
            host        => 'psyduck.example',
            key_file    => $key->stringify,
            known_hosts => $known_hosts->stringify,
        )->run_task('prepare_node', %params);
        1;
    };
    my $died = $@;
    $seen{perl5lib_after} = $ENV{PERL5LIB};
    chdir $cwd or die "chdir $cwd: $!";
    die $died unless $ok;
    $seen{probe} = { $seen{out} =~ /^([A-Z_]+)=(.*)$/mg };
    return \%seen;
}

subtest 'the test runs where the image runs: a plain perl there has no OCP' => sub {
    my $cwd = getcwd;
    chdir "$project" or die "chdir $project: $!";
    local $ENV{PERL5LIB} = $image_perl5lib;
    my $out = `$^X -e 'print eval { require OCP::Rex; 1 } ? "found" : \$@ =~ m{^Can.t locate OCP/Rex[.]pm} ? "absent" : "broken: \$@"' 2>&1`;
    chdir $cwd or die "chdir $cwd: $!";
    is $out, 'absent', "from $project with PERL5LIB=$image_perl5lib, lib/ is out of reach"
        or diag 'the test would prove nothing: the child finds the checkout without OCP::Rex';
};

subtest 'a boolean parameter is no word in the rex child either' => sub {
    my $seen = run_child(probe => JSON::MaybeXS::true());
    is_deeply [ @{ $seen->{cmd} }[0, 1] ], [ 'rex', '-f' ], 'OCP::Rex starts rex -f <Rexfile>';
    ok $seen->{ok}, 'the child loaded the Rexfile and ran the probe'
        or return diag "stdout:\n$seen->{out}\nstderr:\n$seen->{err}";
    my $p = $seen->{probe};
    note "child backend: $p->{BACKEND}";
    is $p->{REF}, 'JSON::PP::Boolean', 'task_params() hands the true back as a JSON::PP::Boolean';
    is $p->{HETZNER_EQ_TRUE}, 0, "'hetzner' eq true is false there";
    is $p->{TRUE_EQ_TRUE}, 1, "'true' eq true is still true"
        if $p->{BACKEND} eq 'Cpanel::JSON::XS';
    my $from = length $p->{FIX_FROM} ? path($p->{FIX_FROM})->realpath : '';
    is "$from", "" . $checkout_lib->child('OCP', 'BooleanEq.pm'),
        "the Rexfile loaded OCP::BooleanEq from this checkout's lib/";
};

subtest 'run_task hands the child its own lib/ and puts PERL5LIB back' => sub {
    my $seen = run_child(probe => JSON::MaybeXS::false());
    my ($first) = split /:/, $seen->{perl5lib} // '';
    is "" . path($first)->realpath, "$checkout_lib",
        'PERL5LIB in the child starts with the lib/ OCP::Rex was loaded from';
    like $seen->{perl5lib}, qr/:\Q$image_perl5lib\E\z/, 'followed by what was there'
        if length $image_perl5lib;
    is $seen->{perl5lib_after}, $image_perl5lib, 'and afterwards PERL5LIB is what it was';
};

# Loading OCP::BooleanEq is the whole fix, whatever came before it. The
# Rexfile and OCP.pm both happen to have JSON::MaybeXS loaded by then; a
# process that loads the module first must still get Cpanel loaded ahead of
# the correction, or Cpanel would overload the class later and put its own
# handler back.
subtest 'OCP::BooleanEq alone, loaded first, is the whole fix' => sub {
    my $script = path($tmp)->child('alone.pl');
    $script->spew_utf8(join "\n",
        'use strict;',
        'use warnings;',
        'use OCP::BooleanEq ();',
        'use JSON::MaybeXS ();',
        q{my $t = JSON::MaybeXS->new->decode('[true]')->[0];},
        q{print 'backend=', JSON::MaybeXS::JSON(), "\n";},
        q{print 'hetzner eq true=', ('hetzner' eq $t ? 1 : 0), "\n";},
        '');
    my $out = `$^X -w -I$checkout_lib $script 2>&1`;
    is $?, 0, 'the script ran' or diag $out;
    like $out, qr/^hetzner eq true=0$/m, "'hetzner' eq true is false";
    unlike $out, qr/redefined/, 'and -w says nothing about it';
    note $out;
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

BEGIN { delete $ENV{ANSI_COLORS_DISABLED}; delete $ENV{NO_COLOR} }

use lib 'lib';

use OCP;
use OCP::Cmd::Update;
use OCP::Rex;
use OCP::Versions;

#
# k226, lab 2026-10-15/16: `ocp update > update.log` wrote ANSI escapes into
# the file -- Term::ANSIColor's colored() ran on every line whether or not a
# terminal was there to read it. Colour is now a terminal's, asked per channel:
# STDOUT into a pipe gets plain text even while STDERR is still the terminal.
# The rule OCP::_report_error already had for its "Error:" label.
#
# And --verbose reaches the Rex task, which since k226 shows its log only then.
#

my $CURRENT = $OCP::VERSION;
my %PINS    = %{ OCP::Versions->get_versions($CURRENT)->{components} };

{
    package FakeOcp;
    sub new     { my ($class, %args) = @_; bless {%args}, $class }
    sub verbose { $_[0]{verbose} // 0 }
    sub config  { $_[0]{config} }
}

# A deployed dev-mode project stamped with an older manifest, '0.000', whose
# cilium pin differs: one Rex update to plan and run.
sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(<<"YAML");
name: updatetest
control_planes:
  provider: hetzner
  public_ip: 1.2.3.4
YAML
    $dir->child('kubeconfig.yaml')->spew_utf8("encrypted-placeholder\n");
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nBOOT\n");
    $dir->child('.ocp', 'status.yaml')->spew_utf8(<<"YAML");
ocpVersion: '0.000'
nodes:
  - name: police1
    provider: hetzner
    public_ip: 1.2.3.4
YAML
    return $dir->child('ocp.yaml')->stringify;
}

sub run_update {
    my (%opt) = @_;
    my (@rex, $rc);
    my ($out, $err) = ('', '');
    my %old = (%PINS, cilium => '0.0.1');
    local $OCP::Versions::VERSIONS = {
        %$OCP::Versions::VERSIONS,
        '0.000' => { components => \%old },
    };
    {
        no warnings 'redefine';
        local *OCP::Rex::new = sub { my ($c, %a) = @_; push @rex, {%a}; bless {%a}, $c };
        local *OCP::Rex::run_task = sub {
            die "boom\n" if $opt{fail};
            return 1;
        };
        # Only the TTY question is faked; the real one says "no" to a scalar.
        my $real = \&OCP::Cmd::Update::_on_terminal;
        local *OCP::Cmd::Update::_on_terminal = exists $opt{tty}
            ? sub { $opt{tty} ? 1 : 0 } : $real;
        my $cmd = OCP::Cmd::Update->new(
            command_chain => [ FakeOcp->new(config => project(), verbose => $opt{verbose}) ],
            component     => 'cilium',
        );
        local *STDOUT;
        local *STDERR;
        open STDOUT, '>', \$out or die $!;
        open STDERR, '>', \$err or die $!;
        $rc = eval { $cmd->execute([], []) };
        $err .= "DIED: $@" if $@;
    }
    return { rc => $rc, out => $out, err => $err, rex => \@rex };
}

subtest 'no terminal: no escape codes on either channel' => sub {
    my $r = run_update();
    is $r->{rc}, 0, 'the update ran' or diag $r->{err};
    like   $r->{out}, qr/cilium updated to/, 'the narrative is there';
    unlike $r->{out}, qr/\e\[/, 'STDOUT carries no ANSI';

    my $f = run_update(fail => 1);
    like   $f->{err}, qr/Failed to update cilium/, 'a failure is said on STDERR';
    unlike $f->{err}, qr/\e\[/, 'without ANSI either';
};

subtest 'a terminal still gets its colours' => sub {
    my $r = run_update(tty => 1);
    like $r->{out}, qr/\e\[[0-9;]*m/, 'the gate, not a removal: colours on a TTY';
};

subtest '--verbose reaches the Rex task' => sub {
    is run_update(verbose => 1)->{rex}[0]{verbose}, 1, 'verbose => 1';
    is run_update()->{rex}[0]{verbose}, 0, 'and 0 without it';
};

done_testing;

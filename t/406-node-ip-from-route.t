#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Cwd qw(getcwd);
use Path::Tiny ();

use lib 'lib';
use lib 't/lib';

# Rex first: it puts <cwd>/lib at the front of @INC, and the asserts on %INC
# below are what show which tree this ran against.
use Rex ();
use Rex::Commands::Run ();
use Rex::Rancher::Agent ();
use Rex::Rancher::Server ();
use Rex::Rancher::Distribution ();

# The real preflights, taken before OCPTest::Rexfile records over them.
my %REAL;
BEGIN {
  %REAL = (
    agent  => \&Rex::Rancher::Agent::preflight_agent,
    server => \&Rex::Rancher::Server::preflight_server,
  );
}

use OCPTest::Rexfile;

no warnings 'once';   # the sandbox package is filled by a string eval

#
# k406, point 2 (decision 2026-11-06): node_ip_from_route => 1 is the default
# for every join without a node_ip -- agents and joining servers (police2+).
# The first server derives nothing; an explicit node_ip wins. Gated on
# Rex::Rancher::Distribution->can('node_ip_from_route'), as node_ip is on
# can('node_addresses'), so an older Rex::Rancher is not handed an option it
# would ignore without a word.
#
# Claims:
#   1. a join -- every task run with a `server` -- without a node_ip hands
#      Rex::Rancher's preflight and install node_ip_from_route => 1 and no
#      node_ip, agents and servers, RKE2 and k3s; an empty node_ip is none;
#   2. the first server (no `server`) gets neither;
#   3. a node_ip given is all that is handed: no node_ip_from_route;
#   4. a Rex::Rancher without node_ip_from_route is handed nothing, and the
#      join goes on with a [WARN] on its STDOUT (which OCP::Rex surfaces);
#      no warning for the first server, which derives nothing anyway;
#   5. against the real Rex::Rancher: the options the Rexfile hands the
#      preflight make it take the node-ip from `ip -o route get` to the join
#      server's host -- node_ip_from_route is an option that library reads.
#

my $CWD = getcwd();
like $INC{'OCPTest/Rexfile.pm'}, qr{^(?:\Q$CWD\E/)?t/lib/}, 'the harness from ./t/lib';
is( Path::Tiny::path(OCPTest::Rexfile->rexfile)->realpath->stringify,
  Path::Tiny::path("$CWD/share/Rexfile")->realpath->stringify, 'the Rexfile of this tree');

my $JOIN = 'https://203.0.113.1:9345';
my $IP   = '10.230.30.50';

# Rex::Rancher's capability, switched per test: the Rexfile asks
# Rex::Rancher::Distribution->can('node_ip_from_route') and nothing else of it.
sub with_route_support {
  my ($code) = @_;
  no warnings 'redefine';
  local *Rex::Rancher::Distribution::node_ip_from_route = sub { die "the Rexfile only asks can()\n" };
  local *Rex::Rancher::Distribution::node_addresses     = sub { die "the Rexfile only asks can()\n" };
  return $code->();
}
sub without_route_support {
  my ($code) = @_;
  no warnings 'redefine';
  local *Rex::Rancher::Distribution::node_ip_from_route;
  local *Rex::Rancher::Distribution::node_addresses = sub { die "the Rexfile only asks can()\n" };
  return $code->();
}

sub install_task {
  my ($task, %params) = @_;
  OCPTest::Rexfile->reset;
  my $err = '';
  my $out;
  {
    local *STDERR;
    open STDERR, '>', \$err or die "cannot capture STDERR: $!";
    $out = OCPTest::Rexfile->run_task($task, { token => 't', %params });
  }
  return ($out, $err);
}

sub lib_calls_for {
  my ($task) = @_;
  my $side = $task =~ /_agent\z/ ? 'Agent::%s_agent' : 'Server::%s_server';
  return map { 'Rex::Rancher::' . sprintf($side, $_) } qw( preflight install );
}

# Every join: the agents, and a server joining police1 (k3s servers are not
# joined by OCP, but the task takes a server all the same).
my @JOINS = map { ("install_${_}_agent", "install_${_}_server") } qw( rke2 k3s );

# --- 1. a join without node_ip ------------------------------------------------

subtest 'a join without node_ip: node_ip_from_route, server and agent' => sub {
  with_route_support(sub {
    for my $task (@JOINS) {
      for my $unset ([], [ node_ip => '' ], [ node_ip => [] ], [ node_ip => undef ]) {
        my $how = @$unset ? 'node_ip ' . (defined $unset->[1] ? (ref $unset->[1] ? '[]' : "''") : 'undef') : 'no node_ip';
        my ($out) = install_task($task, server => $JOIN, @$unset);
        for my $fn (lib_calls_for($task)) {
          my $o = OCPTest::Rexfile->lib_opts($fn);
          ok $o, "$task ($how): $fn called" or next;
          is $o->{node_ip_from_route}, 1, "$task ($how): $fn gets node_ip_from_route => 1";
          ok !exists $o->{node_ip}, "$task ($how): and no node_ip";
        }
        unlike $out, qr/\[WARN\]/, "$task ($how): nothing said";
      }
    }
  });
};

# --- 2. the first server -------------------------------------------------------

subtest 'the first server joins nothing: neither option' => sub {
  with_route_support(sub {
    for my $task (qw( install_rke2_server install_k3s_server )) {
      for my $server ([], [ server => '' ], [ server => undef ]) {
        my ($out) = install_task($task, @$server);
        for my $fn (lib_calls_for($task)) {
          my $o = OCPTest::Rexfile->lib_opts($fn);
          ok $o, "$task: $fn called" or next;
          ok !exists $o->{node_ip_from_route}, "$task: $fn gets no node_ip_from_route";
          ok !exists $o->{node_ip}, "$task: nor node_ip";
        }
        unlike $out, qr/\[WARN\]/, "$task: nothing said";
      }
    }
  });
};

# --- 3. an explicit node_ip wins ----------------------------------------------

subtest 'a node_ip given is all that is handed' => sub {
  with_route_support(sub {
    for my $task (@JOINS) {
      for my $ip ($IP, "$IP,fd00:30::50", [ $IP ]) {
        install_task($task, server => $JOIN, node_ip => $ip);
        for my $fn (lib_calls_for($task)) {
          my $o = OCPTest::Rexfile->lib_opts($fn);
          ok $o, "$task: $fn called" or next;
          is_deeply $o->{node_ip}, $ip, "$task: $fn gets the node_ip";
          ok !exists $o->{node_ip_from_route}, "$task: and no node_ip_from_route";
        }
      }
    }
  });
};

# --- 4. a Rex::Rancher without it ----------------------------------------------

subtest 'a Rex::Rancher without node_ip_from_route: nothing handed, a [WARN]' => sub {
  without_route_support(sub {
    ok !Rex::Rancher::Distribution->can('node_ip_from_route'), 'the library has none';
    for my $task (@JOINS) {
      my ($out, $err);
      ok eval { ($out, $err) = install_task($task, server => $JOIN); 1 }, "$task: the join goes on"
        or diag $@;
      for my $fn (lib_calls_for($task)) {
        my $o = OCPTest::Rexfile->lib_opts($fn);
        ok $o, "$task: $fn called" or next;
        ok !exists $o->{node_ip_from_route}, "$task: $fn is not handed node_ip_from_route";
        ok !exists $o->{node_ip}, "$task: nor a node_ip";
      }
      my @warn = grep { /\[WARN\]/ } split /\n/, $out;
      is scalar @warn, 1, "$task: one [WARN]";
      like $warn[0] // '', qr/^\[WARN\] node-ip is not taken from the route to the join server: this image's Rex::Rancher \S+ cannot, so the node registers the address of its default route\. Set node_ip if the other nodes cannot reach that address$/,
        "$task: saying what happens instead and what to do";
      is $err, '', "$task: on STDOUT, where OCP::Rex picks [WARN] lines up";
    }
    my ($out) = install_task('install_rke2_server');
    unlike $out, qr/\[WARN\]/, 'the first server: nothing said, it derives nothing anyway';
  });
};

# --- 5. the real Rex::Rancher ----------------------------------------------------

# The options the Rexfile handed the recorded preflight, given to the real one
# with Rex::Commands::Run::run -- its channel to the host -- answered here.
subtest 'the real Rex::Rancher takes the node-ip from the route to the join server' => sub {
  plan skip_all => 'this Rex::Rancher has no node_ip_from_route (needs 0.005)'
    unless Rex::Rancher::Distribution->can('node_ip_from_route');

  for my $case ([ install_rke2_agent => 'agent' ], [ install_rke2_server => 'server' ]) {
    my ($task, $role) = @$case;
    install_task($task, server => $JOIN, version => 'v1.36.4+rke2r1');
    my ($preflight) = lib_calls_for($task);
    my $opts = OCPTest::Rexfile->lib_opts($preflight) or next;

    my @ran;
    my $checked;
    {
      no warnings 'redefine';
      local *Rex::Commands::Run::run = sub {
        my ($cmd) = @_;
        push @ran, $cmd;
        $? = 0;
        return "203.0.113.1 via 10.230.30.1 dev vlan30 src $IP uid 0\n    cache\n"
          if $cmd =~ /^ip -o route get /;
        return '';
      };
      local *Rex::Logger::info = sub { };
      $checked = eval { $REAL{$role}->(%$opts) };
    }
    ok $checked, "$role: the real preflight passes" or do { diag $@; next };
    ok scalar(grep { /^ip -o route get '?203\.0\.113\.1'?/ } @ran),
      "$role: it asked the host for the route to the join server's host";
    is_deeply $checked->{node_ip}, [ $IP ], "$role: and returns its source address as the node-ip";
  }
};

done_testing;

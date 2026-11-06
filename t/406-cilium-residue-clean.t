#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::PP ();
use Path::Tiny qw(path);
use Cwd qw(getcwd);

use lib 'lib';
use lib 't/lib';

# Rex first: it puts <cwd>/lib at the front of @INC, and the asserts on %INC
# below are what show which tree this ran against.
use Rex ();
use Rex::Commands::Run ();
use Rex::Rancher::Uninstall ();

# The real guard, taken before OCPTest::Rexfile records over it (the install
# tasks call it; a recorder would refuse nothing).
my $REAL_CHECK;
BEGIN { $REAL_CHECK = \&Rex::Rancher::Uninstall::check_cilium_residue }

use OCPTest::Rexfile;
use OCPTest::CiliumRefusal;
use OCP;
use OCP::Rex;
use OCP::Node;
use OCP::K8s;
use OCP::KnownHosts;
use OCP::Versions;
use OCP::Config;
use OCP::Secrets;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Node::Add;

no warnings 'once';   # the sandbox package is filled by a string eval

#
# k406, point 1 (decision 2026-11-06): OCP offers the cleanup of Cilium's
# leftover datapath state without a reboot, as a switch that sits where the
# reboot refusal comes, and the refusal names it. The functions are
# Rex::Rancher 0.005's: check_cilium_residue(clean => 1).
#
# Claims:
#   1. without the switch each install task refuses a host with leftovers in
#      the library's words with OCP's switch after them, one line, before
#      the preflight, prepare_node or the install -- and the check it asks
#      is the plain one, never clean;
#   2. with clean_cilium_residue the task asks check_cilium_residue(clean =>
#      1) before the preflight and goes on when it returns; a JSON false or
#      0 is no switch;
#   3. with the switch, what the cleanup leaves fails the task in the
#      library's words, no switch sentence after them (it was used);
#   4. against the real Rex::Rancher: the refusal is its text plus OCP's
#      sentence, and the switch runs its cleanup line and probes again --
#      clean => 1 is an option that library reads;
#   5. OCP::Rex hands clean_cilium_residue => 1 to the install tasks only
#      when asked; OCP::Node only when its attribute is set (not by default,
#      which is what robocop gets);
#   6. `ocp apply --clean_cilium_residue` reaches the first control plane's
#      install (install_server) and every node the CLI drives (OCP::Node);
#   7. `ocp node add --clean_cilium_residue` reaches the node the CLI joins,
#      and is refused before anything is written with --nowait or when robocop
#      would join the node;
#   8. the refusal with its switch sentence is the failed task's reason
#      through OCP::Rex, whole -- what ocp prints and robocop writes into the
#      Failed OCPNode.
#

# This ran against the tree it was given, not an installed OCP.
my $CWD = getcwd();
like $INC{'OCP/Rex.pm'}, qr{^(?:\Q$CWD\E/)?lib/}, 'OCP::Rex from ./lib';
like $INC{'OCPTest/Rexfile.pm'}, qr{^(?:\Q$CWD\E/)?t/lib/}, 'the harness from ./t/lib';

my $SWITCH = qr/In OCP that clearing is --clean_cilium_residue: run ocp apply with it again, or ocp node add for a node joined without robocop\. robocop takes no such switch: reboot a host robocop joins\./;

my $CHECK = 'Rex::Rancher::Uninstall::check_cilium_residue';

my @TASKS = (
  [ install_rke2_server => 'Server', {} ],
  [ install_k3s_server  => 'Server', {} ],
  [ install_rke2_agent  => 'Agent', { server => 'https://10.0.0.1:9345', token => 't' } ],
  [ install_k3s_agent   => 'Agent', { server => 'https://10.0.0.1:6443', token => 't' } ],
);

sub lib_fns {
  my ($side) = @_;
  my $role = lc $side;
  return ("Rex::Rancher::${side}::preflight_$role", "Rex::Rancher::${side}::install_$role");
}

# The options the recorded check was called with (after the class).
sub check_opts {
  my @c = OCPTest::Rexfile->calls($CHECK);
  return [ map { my @a = @{ $_->{args} }; shift @a; +{ @a } } @c ];
}

# The library's refusal, from the real guard.
my $REFUSAL = OCPTest::CiliumRefusal->text('/sys/fs/bpf/cilium', 'cilium_host');
(my $REFUSAL_LINE = $REFUSAL) =~ s/\s+\z//;

# --- 1. no switch: refused, naming it ----------------------------------------

for my $t (@TASKS) {
  my ($task, $side, $params) = @$t;
  my ($preflight, $install) = lib_fns($side);

  subtest "$task: leftovers without the switch are refused, naming it" => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_CODE{$CHECK} = sub {
      my ($class, %o) = @_;
      die $REFUSAL unless $o{clean};
      return 1;
    };
    my $ok = eval { OCPTest::Rexfile->run_task($task, { %$params }); 1 };
    my $died = $@;
    ok !$ok, 'the task dies';
    like $died, qr/\A\Q$REFUSAL_LINE\E $SWITCH\n\z/,
      'the library\'s refusal, then OCP\'s switch sentence';
    unlike $died, qr/\n./, 'one line, so Rex logs it as one ERROR line';
    is_deeply check_opts(), [ {} ], 'the plain check, never clean';
    is scalar(OCPTest::Rexfile->calls($preflight)), 0, 'the preflight is not reached';
    is scalar(OCPTest::Rexfile->calls('do_task')), 0, 'nothing is prepared';
    is scalar(OCPTest::Rexfile->calls($install)), 0, 'nothing is installed';
    is_deeply [ OCPTest::Rexfile->commands ], [], 'no command of OCP\'s own ran on the host';
  };
}

# --- 2. the switch: cleared, then the install --------------------------------

for my $t (@TASKS) {
  my ($task, $side, $params) = @$t;
  my ($preflight, $install) = lib_fns($side);

  subtest "$task: with clean_cilium_residue the check clears, then the install goes on" => sub {
    for my $on (1, JSON::PP::true) {
      OCPTest::Rexfile->reset;
      my $ok = eval { OCPTest::Rexfile->run_task($task, { %$params, clean_cilium_residue => $on }); 1 };
      ok $ok, 'the task runs (' . (ref $on ? 'JSON true' : '1') . ')' or diag $@;
      is_deeply check_opts(), [ { clean => 1 } ], 'check_cilium_residue(clean => 1), once';
      is $OCPTest::Rexfile::CALLS[0]{name}, $CHECK, 'first of all';
      my $check = OCPTest::Rexfile->index_of(sub { $_->{name} eq $CHECK });
      my $pre   = OCPTest::Rexfile->index_of(sub { $_->{name} eq $preflight });
      my $prep  = OCPTest::Rexfile->index_of(sub { $_->{name} eq 'do_task' && $_->{args}[0] eq 'prepare_node' });
      ok $check < $pre && $pre < $prep, 'before the preflight, which comes before prepare_node';
      is scalar(OCPTest::Rexfile->calls($install)), 1, 'then the install';
      ok !exists OCPTest::Rexfile->lib_opts($install)->{clean_cilium_residue},
        'the switch is OCP\'s, not an option handed to the library';
    }

    for my $off (0, '', JSON::PP::false) {
      OCPTest::Rexfile->reset;
      my $ok = eval { OCPTest::Rexfile->run_task($task, { %$params, clean_cilium_residue => $off }); 1 };
      ok $ok, 'the task runs' or diag $@;
      is_deeply check_opts(), [ {} ], 'a false switch (' . (ref $off ? 'JSON false' : "'$off'") . ') is none';
    }
  };
}

# --- 3. the switch did not clear it all --------------------------------------

subtest 'with the switch, what is left fails the task in the library\'s words' => sub {
  my $left = "This host still carries Cilium datapath state from an earlier cluster (cilium_host) "
    . "after clearing it without a reboot, and no RKE2 or K3s is installed on it. "
    . "Nothing was installed. Reboot the host, then run the install again.\n";
  for my $t (@TASKS) {
    my ($task, $side, $params) = @$t;
    my ($preflight, $install) = lib_fns($side);
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_DIE{$CHECK} = $left;
    my $ok = eval { OCPTest::Rexfile->run_task($task, { %$params, clean_cilium_residue => 1 }); 1 };
    ok !$ok, "$task: dies";
    is $@, $left, "$task: with the library's message, unchanged -- the switch was used already";
    is scalar(OCPTest::Rexfile->calls($preflight)) + scalar(OCPTest::Rexfile->calls($install))
       + scalar(OCPTest::Rexfile->calls('do_task')), 0, "$task: nothing after it";
  }
};

# --- 4. the real Rex::Rancher -------------------------------------------------

# The Rexfile's own helper, with the real guard in place of the recorder and
# Rex::Commands::Run::run -- its one channel to the host -- answered here.
sub real_check {
  my ($params, $answer) = @_;
  my @ran;
  my $ok;
  {
    no warnings 'redefine';
    local *Rex::Rancher::Uninstall::check_cilium_residue = $REAL_CHECK;
    local *Rex::Commands::Run::run = sub {
      my ($cmd) = @_;
      push @ran, $cmd;
      $? = 0;
      return $answer->($cmd, scalar @ran);
    };
    local *Rex::Logger::info = sub { };
    $ok = eval { OCPTest::Rexfile->helper('_cilium_residue_check')->($params); 1 };
  }
  return ($ok, $@, \@ran);
}

my $PROBE   = Rex::Rancher::Uninstall->cilium_residue_probe_cmd;
my $CLEANUP = Rex::Rancher::Uninstall->cilium_residue_cleanup_cmd;

subtest 'the real Rex::Rancher: refused with its text and OCP\'s sentence' => sub {
  my ($ok, $err, $ran) = real_check({}, sub { $_[0] eq $PROBE ? "/sys/fs/bpf/cilium\n" : '' });
  ok !$ok, 'refused';
  (my $own = OCPTest::CiliumRefusal->text('/sys/fs/bpf/cilium')) =~ s/\s+\z//;
  like $err, qr/\A\Q$own\E $SWITCH\n\z/, 'its refusal, then the switch sentence';
  is_deeply $ran, [ $PROBE ], 'only probed';
};

subtest 'the real Rex::Rancher: the switch runs its cleanup and probes again' => sub {
  my ($ok, $err, $ran) = real_check({ clean_cilium_residue => 1 }, sub {
    my ($cmd, $n) = @_;
    return $cmd eq $PROBE && $n == 1 ? "/sys/fs/bpf/cilium\ncilium_host\n" : '';
  });
  ok $ok, 'cleared: the install may go on' or diag $err;
  is_deeply $ran, [ $PROBE, $CLEANUP, $PROBE ], 'probe, the cleanup line, probe again';

  ($ok, $err, $ran) = real_check({ clean_cilium_residue => 1 }, sub {
    $_[0] eq $PROBE ? "cilium_host\n" : '';
  });
  ok !$ok, 'still there after the cleanup: dies';
  like $err, qr/after clearing it without a reboot/, 'saying so';
  like $err, qr/Reboot the host/, 'asking for a reboot';
  unlike $err, qr/--clean_cilium_residue/, 'not for the switch it ran with';

  ($ok, $err, $ran) = real_check({ clean_cilium_residue => 1 }, sub { '' });
  ok $ok, 'a clean host passes';
  is_deeply $ran, [ $PROBE ], 'only probed: nothing to clear';
};

# --- 5. OCP::Rex and OCP::Node hand it over ----------------------------------

my $tmp = tempdir(CLEANUP => 1);
my $key = path($tmp)->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub key');
my $known_hosts = path($tmp)->child('known_hosts');
$known_hosts->spew('');

sub rex { OCP::Rex->new(host => '203.0.113.9', key_file => "$key", known_hosts => "$known_hosts") }

sub ocp_rex_tasks {
  my ($method, %opts) = @_;
  my %tasks;
  no warnings 'redefine';
  local *OCP::Rex::fetch_kubeconfig_ssh   = sub { "stub-kubeconfig\n" };
  local *OCP::Rex::_existing_server_token = sub { undef };
  local *OCP::Rex::run_task = sub { my ($self, $task, %p) = @_; $tasks{$task} = \%p; 1 };
  rex()->$method(%opts);
  return \%tasks;
}

subtest 'OCP::Rex: clean_cilium_residue reaches the install task only when asked' => sub {
  my %agent = (server => 'https://203.0.113.1:9345', token => 't');
  my $t = ocp_rex_tasks('install_server', distribution => 'rke2', clean_cilium_residue => 1);
  is $t->{install_rke2_server}{clean_cilium_residue}, 1, 'install_server';
  ok !exists $t->{install_cilium}{clean_cilium_residue}, 'not install_cilium';
  $t = ocp_rex_tasks('install_agent', distribution => 'k3s', %agent, clean_cilium_residue => 1);
  is $t->{install_k3s_agent}{clean_cilium_residue}, 1, 'install_agent';
  for my $off ([], [ clean_cilium_residue => 0 ]) {
    $t = ocp_rex_tasks('install_server', distribution => 'rke2', @$off);
    ok !exists $t->{install_rke2_server}{clean_cilium_residue}, 'install_server: none unless asked';
    $t = ocp_rex_tasks('install_agent', distribution => 'rke2', %agent, @$off);
    ok !exists $t->{install_rke2_agent}{clean_cilium_residue}, 'install_agent: none unless asked';
  }
};

{
  package FakeRex;
  our @calls;
  sub new      { bless {}, shift }
  sub run_task { my ($s, $task, %p) = @_; push @calls, [ $task, \%p ]; 1 }
}
{ package FakeSSH; sub new { bless {}, shift } sub wait_for_ssh { 1 } }
{ package FakeIO; sub new { bless {}, shift } sub object_to_struct { $_[1] } }
{ package FakeNodeK8s; sub new { bless {}, shift } sub k8s { FakeIO->new } sub get { die "404\n" } }

sub node_install {
  my (%attr) = @_;
  @FakeRex::calls = ();
  no warnings 'redefine';
  local *OCP::K8s::patch_status = sub { 1 };
  local *OCP::KnownHosts::scan  = sub { () };
  local *OCP::Versions::get_component_version = sub { 'v9.9.9' };
  my $node = OCP::Node->from_cr({
      apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
      metadata => { name => 'worker-9', namespace => 'ocp-system', resourceVersion => '1' },
      spec     => { role => $attr{role} // 'worker', providerRef => 'ssh-default', host => '10.0.0.9' },
      status   => { phase => 'Installing', publicIP => '10.0.0.9' },
    },
    k8s => FakeNodeK8s->new, ssh_key => 'KEY',
    server_url => 'https://10.0.0.1:9345', join_token => 'TOKEN',
    ssh_class => 'FakeSSH', rex_class => 'FakeRex',
    (exists $attr{clean} ? (clean_cilium_residue => $attr{clean}) : ()),
  );
  $node->_install_kubernetes;
  return $FakeRex::calls[0];
}

subtest 'OCP::Node: clean_cilium_residue only when the caller sets it' => sub {
  my $call = node_install(clean => 1);
  ok $call, 'the install ran' or return;
  is $call->[1]{clean_cilium_residue}, 1, 'a worker\'s install gets it';
  $call = node_install(clean => 1, role => 'control-plane');
  is $call->[0], 'install_rke2_server', 'a control plane joins as a server';
  is $call->[1]{clean_cilium_residue}, 1, 'and gets it too';
  for my $off ([], [ clean => 0 ]) {
    $call = node_install(@$off);
    ok !exists $call->[1]{clean_cilium_residue},
      'none ' . (@$off ? 'when set false' : 'by default -- what robocop, which sets nothing, gets');
  }
};

# --- 6. ocp apply ------------------------------------------------------------

{ package ApplyOcp; sub new { bless {}, shift } sub verbose { 0 } }

sub project {
  my $dir = path(tempdir(CLEANUP => 1));
  $dir->child('.ocp')->mkpath;
  # dev mode (no keys.yaml): the bootstrap key on disk is used
  $dir->child('.ocp', 'id_ed25519')->spew("fake key\n");
  $dir->child('.ocp', 'id_ed25519.pub')->spew("ssh-ed25519 AAAAdev dev\n");
  $dir->child('ocp.yaml')->spew_utf8("name: k406\ncontrol_planes:\n  provider: ssh\n  host: 1.2.3.4\n");
  return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

{
  package BootProv;
  sub new                { bless {}, shift }
  sub upload_ssh_key     { }
  sub create_server      { { ip => '1.2.3.4', newly_created => 0 } }
  sub wait_for_running   { $_[1] }
  sub advertised_host    { my ($s, %o) = @_; $o{host} }
  sub cleanup_on_failure { }
}

# The options bootstrap_control_plane hands OCP::Rex install_server; it stops
# right there.
sub bootstrap_server_opts {
  my ($apply) = @_;
  my $config = project();
  my %opts;
  no warnings 'redefine';
  local *OCP::Provider::for_spec       = sub { BootProv->new };
  local *OCP::Secrets::ensure_age_key  = sub { 1 };
  local *OCP::SSH::new                 = sub { bless {}, 'OCP::SSH' };
  local *OCP::SSH::wait_for_ssh        = sub { 1 };
  local *OCP::Rex::new                 = sub { bless {}, 'OCP::Rex' };
  local *OCP::Rex::install_server      = sub { shift; %opts = @_; die "STOP\n" };
  my $out = '';
  my $err = '';
  {
    local *STDOUT; local *STDERR;
    open STDOUT, '>', \$out or die;
    open STDERR, '>', \$err or die;
    eval { OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
      $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
      admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' }) };
  }
  my $died = $@;
  return ($died, \%opts);
}

subtest 'ocp apply --clean_cilium_residue: the first control plane\'s install gets it' => sub {
  my ($died, $opts) = bootstrap_server_opts(
    OCP::Cmd::Apply->new(command_chain => [ ApplyOcp->new ], clean_cilium_residue => 1));
  is $died, "STOP\n", 'install_server was reached' or return;
  is $opts->{clean_cilium_residue}, 1, 'with clean_cilium_residue';

  ($died, $opts) = bootstrap_server_opts(OCP::Cmd::Apply->new(command_chain => [ ApplyOcp->new ]));
  is $died, "STOP\n", 'install_server was reached' or return;
  ok !exists $opts->{clean_cilium_residue}, 'without the switch: none';
};

{
  package FakeSecrets;
  sub new             { bless {}, shift }
  sub read_kubeconfig { undef }
}
{
  package FakeApi;
  sub new  { bless {}, shift }
  sub k8s  { $_[0] }
  sub object_to_struct { $_[1] }
  sub get {
    my ($self, $kind, @rest) = @_;
    my $name = @rest % 2 ? $rest[0] : { @rest }->{name};
    return { metadata => { name => $name, namespace => 'ocp-system' },
             spec     => { role => 'worker', providerRef => 'ssh-default' }, status => {} }
      if $kind eq 'OCPNode';
    return { metadata => { name => 'ssh-default', namespace => 'ocp-system' }, spec => { type => 'ssh' } }
      if $kind eq 'OCPNodeProvider';
    return undef;
  }
}
{ package FakeNode; sub reconcile_until_ready { 1 } sub phase { 'Ready' } }

# The %deps OCP::Node->from_cr is built with, one hash per node.
sub node_deps (&) {
  my ($run) = @_;
  my @deps;
  no warnings 'redefine';
  local *OCP::Node::from_cr     = sub { my ($c, $cr, %d) = @_; push @deps, \%d; bless {}, 'FakeNode' };
  local *OCP::Provider::from_cr = sub { bless {}, 'FakeProvider' };
  local *OCP::SSH::new          = sub { bless {}, $_[0] };
  local *OCP::SSH::run          = sub { { stdout => "K10::token\n", stderr => '', exit => 0 } };
  my $out = '';
  {
    local *STDOUT;
    open STDOUT, '>', \$out or die $!;
    $run->();
  }
  return @deps;
}

subtest 'ocp apply --clean_cilium_residue: every node the CLI drives gets it' => sub {
  my $config = project();
  for my $case ([ 1, 1 ], [ 0, 0 ]) {
    my ($set, $want) = @$case;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ ApplyOcp->new ],
      ($set ? (clean_cilium_residue => 1) : ()));
    my @deps = node_deps {
      OCP::Cmd::Apply::CR::cli_reconcile_workers($apply, FakeApi->new, $config,
        [ 'police2', 'worker-1' ],
        { ssh_key_path => '/nonexistent', cp_ip => '1.2.3.4', secrets => FakeSecrets->new });
    };
    is scalar @deps, 2, 'two nodes driven' or next;
    is $_->{clean_cilium_residue}, $want, ($set ? 'with' : 'without') . " the switch: $want" for @deps;
  }
};

# --- 7. ocp node add ---------------------------------------------------------

{
  package FakeAddConfig;
  sub new            { bless {}, shift }
  sub cluster_status { {} }
  sub distribution   { 'rke2' }
  sub pod_cidr       { '10.42.0.0/16' }
}

subtest 'ocp node add --clean_cilium_residue: the node the CLI joins gets it' => sub {
  my $cr = { metadata => { name => 'worker-9', namespace => 'ocp-system' },
             spec     => { role => 'worker', providerRef => 'ssh-default' } };
  for my $set (1, 0) {
    my $add = OCP::Cmd::Node::Add->new(k8s => FakeApi->new, name => 'worker-9',
      ($set ? (clean_cilium_residue => 1) : ()));
    my @deps = node_deps { $add->_cli_reconcile($cr, FakeApi->new, FakeAddConfig->new, FakeSecrets->new) };
    is scalar @deps, 1, 'one node driven' or next;
    is $deps[0]{clean_cilium_residue}, $set, ($set ? 'with' : 'without') . " the switch: $set";
  }
};

{
  package AddApi;
  our @ensured;
  sub new    { bless {}, shift }
  sub ensure { push @ensured, $_[1]; 1 }
}

# execute up to the first write, the steps before it answered here.
sub add_execute {
  my (%o) = @_;
  @AddApi::ensured = ();
  my $preflights = 0;
  no warnings 'redefine';
  local *OCP::Cmd::Node::Add::_k8s              = sub { AddApi->new };
  local *OCP::Cmd::Node::Add::_resolve_provider = sub {
    +{ metadata => { name => 'ssh-default' }, spec => { type => 'ssh' } } };
  local *OCP::Cmd::Node::Add::_validate_flags   = sub { 1 };
  local *OCP::Cmd::Node::Add::_refuse_unstored_node_ip = sub { 1 };
  local *OCP::Cmd::Node::Add::_robocop_ready    = sub { $o{robocop} };
  local *OCP::Cmd::Node::Add::_preflight_host   = sub { $preflights++; 1 };
  local *OCP::Cmd::Node::Add::_build_cr         = sub { die "WROTE\n" };
  my $add = OCP::Cmd::Node::Add->new(name => 'worker-9', host => '10.0.0.9',
    provider => 'ssh-default', clean_cilium_residue => 1, ($o{nowait} ? (nowait => 1) : ()));
  my $ok = eval { $add->execute([], []); 1 };
  return ($ok, $@, scalar @AddApi::ensured);
}

subtest 'ocp node add --clean_cilium_residue: refused where no install of its own follows' => sub {
  my ($ok, $err, $written) = add_execute(robocop => 1);
  ok !$ok, 'robocop joins the node: refused';
  is $err, "--clean_cilium_residue: robocop joins this node, and robocop takes no such switch. "
    . "Nothing was written. Reboot the machine instead, then add the node without it\n",
    'saying why and what to do instead';
  is $written, 0, 'nothing written';

  ($ok, $err, $written) = add_execute(robocop => 0, nowait => 1);
  ok !$ok, '--nowait: refused';
  is $err, "--clean_cilium_residue: with --nowait this command installs nothing, so nothing "
    . "would clear the machine. Nothing was written. Leave out --nowait\n", 'saying why';
  is $written, 0, 'nothing written';

  ($ok, $err) = add_execute(robocop => 0);
  is $err, "WROTE\n", 'the CLI joins the node: it goes on to the write';
};

# --- 8. through OCP::Rex -------------------------------------------------------

subtest 'the refusal with its switch sentence is the failed task\'s reason, whole' => sub {
  OCPTest::Rexfile->reset;
  local $OCPTest::Rexfile::LIB_DIE{$CHECK} = $REFUSAL;
  ok !eval { OCPTest::Rexfile->run_task('install_rke2_agent',
    { server => 'https://10.0.0.1:9345', token => 't' }); 1 }, 'the task refuses';
  (my $line = $@) =~ s/\s+\z//;
  like $line, $SWITCH, 'naming the switch';

  my $rexfile = path($tmp)->child('Rexfile');
  $rexfile->spew("# stub\n");
  my $log = "[2026-11-06 10:00:00] ERROR - Error executing task:\n"
          . "[2026-11-06 10:00:00] ERROR - $line\n";
  my $died;
  {
    no warnings 'redefine';
    local *OCP::Rex::_ensure_host_key = sub { };
    local *OCP::Rex::_find_rexfile    = sub { "$rexfile" };
    local *OCP::Rex::run = sub { ${ $_[3] } = $log; 0 };
    my ($o, $e) = ('', '');
    open my $ofh, '>', \$o or die;
    open my $efh, '>', \$e or die;
    local *STDOUT = $ofh;
    local *STDERR = $efh;
    eval { rex()->run_task('install_rke2_agent'); 1 } or $died = $@;
  }
  is $died, "Rex task 'install_rke2_agent' failed: $line\n",
    'the library\'s refusal and the switch sentence, as one reason';
};

done_testing;

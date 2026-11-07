#!/usr/bin/env perl
use strict;
use warnings;

# OCP::Node waits 5s between reconciles: nothing here waits for anything that
# takes time, so sleep returns at once -- set before the modules below are
# compiled, or they would keep the real one.
BEGIN { *CORE::GLOBAL::sleep = sub { 0 } }

use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Storable qw(dclone);
use Cwd qw(getcwd);

use lib 'lib';
use lib 't/lib';

# Rex first: it puts <cwd>/lib at the front of @INC, and the asserts on %INC
# below are what show which tree this ran against.
use Rex ();
use Rex::Rancher::Uninstall ();

use OCPTest::Rexfile;
use OCPTest::CiliumRefusal;
use OCP;
use OCP::Rex;
use OCP::SSH;
use OCP::Node;
use OCP::KnownHosts;
use OCP::Config;
use OCP::Secrets;
use OCP::Provider;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Deploy;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Apply::SopsRepair;
use OCP::Cmd::Apply::AMDGPU;
use OCP::Cmd::Node::Add;
use OCP::Cmd::Node::Ls;

no warnings 'once';

#
# k445 (amdlab, image 01c9716): the Cilium leftover refusal told the operator
# to run `ocp apply` or `ocp node add` again with --clean_cilium_residue. For
# `ocp node add` that led nowhere: the refusal had left the node's OCPNode
# Failed, the rerun read that OCPNode back and returned its old message after
# 8 s, and only `ocp node rm synapse --keep_machine`, then `ocp node add` with
# the switch, reached an install (Ready after 3 min). Failed stays terminal
# (decision 2026-11-07); the sentence says what works instead. Which way works
# depends on the install, and this file walks each one:
#
#   1. the first control plane (`ocp apply`'s bootstrap): the refusal writes no
#      kubeconfig.yaml and no OCPNode, so the next `ocp apply` bootstraps
#      again and its switch reaches the check -- the sentence sends it there,
#      and nowhere else;
#   2. a node `ocp node add` joins, a worker and a control plane: refused, its
#      OCPNode is Failed; the rerun with the switch installs nothing and
#      repeats the old message; once the OCPNode is gone (what `ocp node rm
#      NAME --keep_machine` ends in) the `ocp node add` the sentence spells
#      out, typed with the PROVIDER and IP `ocp node ls` showed for the node,
#      reaches the install and the node comes up as what it was;
#   3. a node `ocp apply` joined (a worker, or police2+ of the first deploy):
#      the rerun is the reconcile path of a cluster that exists, which drives
#      no OCPNode that exists and joins no control plane, so with the switch
#      it installs nothing either; the Failed worker is named with its old
#      message, the sentence a joining node's refusal carries;
#   4. those nodes of `ocp apply`, made and refused the way its first deploy
#      makes and joins them: the same `ocp node add`, typed off the sentence
#      and `ocp node ls`, makes the OCPNode apply made (police2 a control
#      plane, the worker a worker) and brings it up.
#
# The refusal is the real Rexfile's (OCPTest::Rexfile, the library refusing a
# host with leftovers unless asked to clean), relayed as OCP::Rex relays a
# failed task.
#

# This ran against the tree it was given, not an installed OCP.
my $CWD = getcwd();
like $INC{'OCP/Node.pm'}, qr{^(?:\Q$CWD\E/)?lib/}, 'OCP::Node from ./lib';
like $INC{'OCP/Cmd/Node/Add.pm'}, qr{^(?:\Q$CWD\E/)?lib/}, 'OCP::Cmd::Node::Add from ./lib';
like $INC{'OCP/Cmd/Node/Ls.pm'}, qr{^(?:\Q$CWD\E/)?lib/}, 'OCP::Cmd::Node::Ls from ./lib';
like $INC{'OCPTest/Rexfile.pm'}, qr{^(?:\Q$CWD\E/)?t/lib/}, 'the harness from ./t/lib';
is(OCPTest::Rexfile->rexfile->realpath->stringify, path($CWD, 'share', 'Rexfile')->realpath->stringify,
  'the Rexfile of this tree');

my $CHECK = 'Rex::Rancher::Uninstall::check_cilium_residue';

# The library's refusal of a host with Cilium leftovers, its own words.
my $REFUSAL = OCPTest::CiliumRefusal->text('/sys/fs/bpf/cilium', 'cilium_host');
(my $REFUSAL_LINE = $REFUSAL) =~ s/\s+\z//;

# --- the machine: leftovers on it, cleared only when asked -------------------

# Every Rex task OCP::Rex is asked for, with its parameters.
my @REX_TASKS;

# Tasks after which the test stops the caller ("STOP"), and the nodes whose
# install went through (their Node registers, Ready).
our (%STOP_AFTER, %JOINED);

# OCP::Rex::run_task, through the real Rexfile on a host with leftovers: the
# library's guard refuses unless asked to clean, and a failed task dies the
# way OCP::Rex says it ("Rex task 'NAME' failed: <reason>").
sub rexfile_run_task {
  my ($self, $task, %p) = @_;
  push @REX_TASKS, [ $task, {%p} ];
  OCPTest::Rexfile->reset;
  local $OCPTest::Rexfile::LIB_CODE{$CHECK} = sub {
    my ($class, %o) = @_;
    die $REFUSAL unless $o{clean};
    return 1;
  };
  my $ok = eval { OCPTest::Rexfile->run_task($task, {%p}); 1 };
  unless ($ok) {
    (my $line = $@) =~ s/\s+\z//;
    die "Rex task '$task' failed: $line\n";
  }
  $JOINED{ $p{node_name} } = 1 if $p{server} && defined $p{node_name};
  die "STOP\n" if $STOP_AFTER{$task};
  return { stdout => '', stderr => '' };
}

# The checks the Rexfile asked of the guard in the last task, their options.
sub check_opts {
  return [ map { my @a = @{ $_->{args} }; shift @a; +{ @a } } OCPTest::Rexfile->calls($CHECK) ];
}

# --- the cluster: OCPNodes as the API server keeps them -----------------------
#
# The OCPNode CRD enables the status subresource: a create or an update of the
# object leaves status as it is stored (none, for a new one), only a status
# patch writes it. That is what keeps a Failed OCPNode Failed through
# `ocp node add`'s ensure.
#
# The one OCPNodeProvider is the one `ocp apply` writes for ssh: ssh-default,
# type ssh. Only it answers, so `ocp node add` resolves --provider the way it
# does on a cluster (a name it does not know is refused).
{
  package MemList;
  sub new   { my ($c, $i) = @_; bless { items => $i }, $c }
  sub items { $_[0]{items} }
}
{
  package MemK8s;
  my %PROVIDERS = (
    'ssh-default' => { apiVersion => 'ocp.internal/v1', kind => 'OCPNodeProvider',
                       metadata => { name => 'ssh-default', namespace => 'ocp-system' },
                       spec => { type => 'ssh' } },
  );
  sub new { my ($c, %a) = @_; bless { crs => {}, writes => [], %a }, $c }
  sub k8s              { $_[0] }
  sub object_to_struct { $_[1] }
  sub struct_to_object { $_[2] }
  sub expand_class     { 'OCPNode' }

  sub _name {
    my (@rest) = @_;
    return @rest % 2 ? $rest[0] : { @rest }->{name};
  }

  sub get {
    my ($s, $kind, @rest) = @_;
    my $name = _name(@rest);
    if ($kind eq 'OCPNode') {
      my $cr = $s->{crs}{$name} or die "404 OCPNode $name not found\n";
      return Storable::dclone($cr);
    }
    if ($kind eq 'OCPNodeProvider' && $PROVIDERS{$name}) {
      return Storable::dclone($PROVIDERS{$name});
    }
    # A node whose install went through registers, Ready, on the address OCP
    # reached it at.
    if ($kind eq 'Node' && $main::JOINED{$name}) {
      my $cr = $s->{crs}{$name} // {};
      my $ip = ($cr->{status} // {})->{publicIP} // ($cr->{spec} // {})->{host};
      return { metadata => { name => $name },
               status => { conditions => [ { type => 'Ready', status => 'True' } ],
                           addresses  => [ { type => 'InternalIP', address => $ip } ] } };
    }
    die "404 $kind $name not found\n";
  }

  sub list {
    my ($s, $kind) = @_;
    return MemList->new([ map { Storable::dclone($s->{crs}{$_}) } sort keys %{ $s->{crs} } ])
      if $kind eq 'OCPNode';
    return MemList->new([ map { Storable::dclone($PROVIDERS{$_}) } sort keys %PROVIDERS ])
      if $kind eq 'OCPNodeProvider';
    return MemList->new([]);
  }

  sub _store {
    my ($s, $obj) = @_;
    my $name = $obj->{metadata}{name};
    my $new = Storable::dclone($obj);
    delete $new->{status};
    $new->{status} = $s->{crs}{$name}{status} if $s->{crs}{$name} && $s->{crs}{$name}{status};
    $s->{crs}{$name} = $new;
    return Storable::dclone($new);
  }

  sub ensure { my ($s, $obj) = @_; push @{ $s->{writes} }, "ENSURE $obj->{metadata}{name}"; $s->_store($obj) }
  sub update { my ($s, $obj) = @_; $s->_store($obj) }

  sub patch_status {
    my ($s, $kind, %a) = @_;
    my $cr = $s->{crs}{ $a{name} } or die "404 $kind $a{name} not found\n";
    my $st = $cr->{status} //= {};
    for my $k (keys %{ $a{patch}{status} }) {
      my $v = $a{patch}{status}{$k};
      if (defined $v) { $st->{$k} = $v } else { delete $st->{$k} }
    }
    push @{ $s->{writes} }, "STATUS $a{name} " . ($st->{phase} // '');
    return 1;
  }

  # A Node patch (labels, taints) is taken; an OCPNode one answers with the
  # object as stored -- no test here changes an OCPNode's spec.
  sub patch {
    my ($s, $kind, %a) = @_;
    return 1 unless $kind eq 'OCPNode';
    my $cr = $s->{crs}{ $a{name} } or die "404 $kind $a{name} not found\n";
    push @{ $s->{writes} }, "PATCH $a{name}";
    return Storable::dclone($cr);
  }
}

{
  package FakeKey;
  sub new            { bless {}, shift }
  sub path           { '/nonexistent/cluster-key' }
  sub content        { "KEY\n" }
  sub label          { 'the admin key' }
  sub origin         { 'admin' }
  sub migration_hint { '' }
}
{
  package FakeAddConfig;
  sub new            { my ($c, %a) = @_; bless {%a}, $c }
  sub project_dir    { $_[0]{dir} }
  sub cluster_status { { public_ip => '10.230.30.51' } }
  sub join_url       { "https://$_[1]:9345" }
  sub distribution   { 'rke2' }
  sub pod_cidr       { '10.42.0.0/16' }
}

# STDOUT and STDERR of $code, and what it returned.
sub captured (&) {
  my ($code) = @_;
  my ($out, $err) = ('', '');
  my @r;
  {
    local *STDOUT; local *STDERR;
    open STDOUT, '>', \$out or die $!;
    open STDERR, '>', \$err or die $!;
    @r = eval { $code->() };
    $r[0] = "died: $@" if $@ && !@r;
  }
  return ($r[0], $out, $err);
}

# --- 1. the first control plane ---------------------------------------------

{
  package ApplyOcp;
  sub new       { my ($c, %a) = @_; bless {%a}, $c }
  sub verbose   { 0 }
  sub config    { $_[0]{config} }
  sub load_file { {} }
  sub dump_file { 1 }
}

sub project {
  my ($yaml) = @_;
  my $dir = path(tempdir(CLEANUP => 1));
  $dir->child('.ocp')->mkpath;
  # dev mode (no keys.yaml): the bootstrap key on disk is used
  $dir->child('.ocp', 'id_ed25519')->spew("fake key\n");
  $dir->child('.ocp', 'id_ed25519.pub')->spew("ssh-ed25519 AAAAdev dev\n");
  $dir->child('ocp.yaml')->spew_utf8($yaml);
  return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

{
  package BootProv;
  sub new                { bless {}, shift }
  sub upload_ssh_key     { }
  sub create_server      { { ip => '10.230.30.51', newly_created => 0 } }
  sub wait_for_running   { $_[1] }
  sub advertised_host    { my ($s, %o) = @_; $o{host} }
  sub cleanup_on_failure { }
}

# bootstrap_control_plane up to OCP::Rex install_server and its task, which
# runs through the Rexfile; the run ends with the task (STOP) or its refusal.
sub bootstrap {
  my ($config, %attr) = @_;
  my $apply = OCP::Cmd::Apply->new(command_chain => [ ApplyOcp->new ], %attr);
  @REX_TASKS = ();
  local $STOP_AFTER{install_rke2_server} = 1;
  no warnings 'redefine';
  local *OCP::Provider::for_spec           = sub { BootProv->new };
  local *OCP::Secrets::ensure_age_key      = sub { 1 };
  local *OCP::SSH::new                     = sub { bless {}, 'OCP::SSH' };
  local *OCP::SSH::wait_for_ssh            = sub { 1 };
  local *OCP::Rex::new                     = sub { my ($c, %a) = @_; bless {%a}, 'OCP::Rex' };
  local *OCP::Rex::_existing_server_token  = sub { undef };
  local *OCP::Rex::run_task                = \&rexfile_run_task;
  my ($r, $out, $err) = captured {
    OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
      $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
      admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' });
    'returned';
  };
  return $r;
}

my $ONE_CP = "name: k445\ncontrol_planes:\n  provider: ssh\n  host: 10.230.30.51\n";

subtest 'the first control plane: the next ocp apply reaches the install, and the sentence says so' => sub {
  my $config = project($ONE_CP);

  my $died = bootstrap($config);
  like $died, qr/\Adied: Rex task 'install_rke2_server' failed: \Q$REFUSAL_LINE\E /,
    'refused: the bootstrap dies with the library\'s refusal';
  is_deeply check_opts(), [ {} ], 'the plain check';
  ok !-e $config->project_dir->child('kubeconfig.yaml'), 'no kubeconfig.yaml written';
  ok !$config->cluster_exists, 'so the cluster does not exist for the next ocp apply';

  # The claim (k445): the first control plane is sent to ocp apply again, and
  # to no OCPNode command -- it has no OCPNode yet.
  my ($sentence) = $died =~ /\Q$REFUSAL_LINE\E (.*)$/;
  like $sentence, qr/--clean_cilium_residue: run ocp apply with it again\./,
    'the sentence: run ocp apply with the switch again';
  unlike $sentence, qr/ocp node (?:add|rm)/, 'and names no ocp node command';

  $died = bootstrap($config, clean_cilium_residue => 1);
  is $died, "died: STOP\n", 'the next ocp apply with the switch: the install task ran through'
    or diag $died;
  is_deeply check_opts(), [ { clean => 1 } ], 'its check cleared the leftovers (clean => 1)';
  is scalar(OCPTest::Rexfile->calls('Rex::Rancher::Server::install_server')), 1,
    'and the server was installed';
};

# Which path ocp apply takes is decided by kubeconfig.yaml alone.
subtest 'ocp apply bootstraps while there is no kubeconfig.yaml, and reconciles once there is' => sub {
  my $config = project($ONE_CP);
  my $file   = $config->file;
  for my $exists (0, 1) {
    $config->project_dir->child('kubeconfig.yaml')->spew("sops: {}\n") if $exists;
    my @path;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::SopsRepair::repair_sops_files        = sub { };
    local *OCP::Cmd::Apply::Bootstrap::ensure_dev_age_key        = sub { };
    local *OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane   = sub { push @path, 'bootstrap'; die "STOP\n" };
    local *OCP::Cmd::Apply::_reconcile_components                = sub { push @path, 'reconcile'; 0 };
    my $apply = OCP::Cmd::Apply->new(command_chain => [ ApplyOcp->new(config => "$file") ],
                                     clean_cilium_residue => 1);
    captured { $apply->execute([], []) };
    is_deeply \@path, [ $exists ? 'reconcile' : 'bootstrap' ],
      $exists ? 'kubeconfig.yaml there: the reconcile path' : 'none: the bootstrap again';
  }
};

# --- 2. a node ocp node add joins ---------------------------------------------

# `ocp node add` with the flags in %attr (name, role, provider, host, ...),
# robocop not running, against $api. Returns its exit code and STDERR. The
# provider is the real one the OCPNodeProvider names (ssh: the machine at
# spec.host), so what the OCPNode records of it is what OCP writes.
sub node_add {
  my ($api, %attr) = @_;
  my $dir = path(tempdir(CLEANUP => 1));
  no warnings 'redefine';
  local *OCP::Cmd::Node::Add::_preflight_host          = sub { 1 };
  local *OCP::Cmd::Node::Add::_config                  = sub { FakeAddConfig->new(dir => $dir) };
  local *OCP::Cmd::Node::Add::cluster_ssh_key          = sub { FakeKey->new };
  local *OCP::Secrets::read_kubeconfig                 = sub { undef };
  local *OCP::SSH::new                                 = sub { my ($c, %a) = @_; bless {%a}, 'OCP::SSH' };
  local *OCP::SSH::wait_for_ssh                        = sub { 1 };
  local *OCP::SSH::run                                 = sub { { stdout => "K10::token\n", stderr => '', exit => 0 } };
  local *OCP::KnownHosts::scan                         = sub { () };
  local *OCP::Rex::new                                 = sub { my ($c, %a) = @_; bless {%a}, 'OCP::Rex' };
  local *OCP::Rex::run_task                            = \&rexfile_run_task;
  # sleep returns at once here: a node that never gets to a verdict would spin
  # through the real 900 s. 10 s is ample for the few passes this takes.
  local $OCP::Node::READY_TIMEOUT                      = 10;
  @REX_TASKS = ();
  my $add = OCP::Cmd::Node::Add->new(k8s => $api, %attr);
  my ($rc, $out, $err) = captured { $add->execute([], []) };
  return ($rc, $err);
}

# `ocp node ls` against $api, as printed: NAME => { column => value }.
sub node_ls {
  my ($api) = @_;
  my ($rc, $out, $err) = captured { OCP::Cmd::Node::Ls->new(k8s => $api)->execute([], []) };
  my ($head, @lines) = split /\n/, $out // '';
  my @cols = split ' ', $head // '';
  my %rows;
  for my $line (@lines) {
    my %row;
    @row{@cols} = split ' ', $line;
    $rows{ $row{NAME} } = \%row;
  }
  return \%rows;
}

# The command the sentence spells out, typed as it says: NAME and the role
# flag as the sentence gives them, --provider and (ssh) --host off the node's
# row of `ocp node ls`, the switch. Empty when the sentence spells out none.
sub typed_from {
  my ($sentence, $row) = @_;
  my ($name, $role) = $sentence =~ m{
    \bnote\ its\ PROVIDER\ and\ IP\ in\ ocp\ node\ ls,\ then\ ocp\ node\ rm\ (\S+)\ --keep_machine
    \ and\ ocp\ node\ add\ \g1(\ --role\ control-plane)?\ --provider\ PROVIDER\ with\ the\ switch,
    \ plus\ --host\ IP\ for\ an\ ssh\ provider\b
  }x or return;
  return (name => $name, ($role ? (role => 'control-plane') : ()),
          provider => $row->{PROVIDER}, host => $row->{IP}, clean_cilium_residue => 1);
}

# A control plane `ocp node add` joins, and a worker -- the worker without
# --role, as node add defaults to it.
my @ADDED = (
  { name => 'synapse', role => 'worker',        host => '10.230.30.50',
    task => 'install_rke2_agent',  lib => 'Rex::Rancher::Agent::install_agent' },
  { name => 'police4', role => 'control-plane', host => '10.230.30.55',
    task => 'install_rke2_server', lib => 'Rex::Rancher::Server::install_server' },
);

for my $n (@ADDED) {
  my $name = $n->{name};
  subtest "ocp node add $name ($n->{role}): Failed stays, and the node add the sentence spells out reaches the install" => sub {
    my $api = MemK8s->new;
    my @flags = (name => $name, ($n->{role} eq 'worker' ? () : (role => $n->{role})),
                 provider => 'ssh-default', host => $n->{host});

    # Run 1, without the switch: refused, the OCPNode Failed.
    my ($rc, $err) = node_add($api, @flags);
    is $rc, 1, 'refused: exit 1';
    is scalar(@REX_TASKS), 1, 'the install task ran';
    is $REX_TASKS[0][0], $n->{task}, "the $n->{role}'s install ($n->{task})";
    ok $REX_TASKS[0][1]{server}, 'a join (handed the server to join)';
    is $api->{crs}{$name}{status}{phase}, 'Failed', 'the OCPNode is Failed';
    my $message = $api->{crs}{$name}{status}{message};
    like $message, qr/\Q$REFUSAL_LINE\E/, 'its message: the library\'s refusal';
    like $err, qr/\[!!\] Failed: \Q$message\E/, 'said on STDERR';

    # The claim (k445): the sentence names the way back for this node, the
    # one walked below -- the OCPNode goes, the machine stays, then node add
    # with this node's role and the provider and host ocp node ls shows.
    my ($sentence) = $message =~ /\Q$REFUSAL_LINE\E (.*)$/;
    like $sentence, qr/this one stays Failed/, 'the sentence: the OCPNode stays Failed';
    my $add = "ocp node add $name" . ($n->{role} eq 'control-plane' ? ' --role control-plane' : '')
            . ' --provider PROVIDER with the switch';
    like $sentence, qr/ocp node rm \Q$name\E --keep_machine and \Q$add\E/,
      "the sentence: ocp node rm $name --keep_machine and $add";
    unlike $sentence, qr/run ocp apply with it again/, 'and not a rerun of ocp apply';

    # Run 2, the same command with the switch: the Failed OCPNode is read back.
    ($rc, $err) = node_add($api, @flags, clean_cilium_residue => 1);
    is $rc, 1, 'the rerun with the switch: exit 1 again';
    is_deeply \@REX_TASKS, [], 'no install task: the switch reaches nothing';
    is $api->{crs}{$name}{status}{phase}, 'Failed', 'the OCPNode stays Failed';
    is $api->{crs}{$name}{status}{message}, $message, 'with its message unchanged';
    like $err, qr/\[!!\] Failed: \Q$message\E/, 'the old refusal, said again';

    # What the sentence has the operator note first.
    my $row = node_ls($api)->{$name};
    is_deeply [ @{$row}{qw(ROLE PHASE PROVIDER IP)} ], [ $n->{role}, 'Failed', 'ssh-default', $n->{host} ],
      'ocp node ls: its role, Failed, PROVIDER ssh-default and IP its host';
    my $spec = dclone($api->{crs}{$name}{spec});

    # `ocp node rm NAME --keep_machine` ends with the OCPNode gone and the
    # machine as it is (OCP::Node->teardown(keep_machine => 1)).
    delete $api->{crs}{$name};

    # Run 3, typed as the sentence says: a new OCPNode, the install, Ready.
    my %typed = typed_from($sentence, $row);
    ok %typed, 'the sentence spells out a node add to type' or return;
    ($rc, $err) = node_add($api, %typed);
    is $rc, 0, 'after the OCPNode is gone, that node add: exit 0' or diag $err;
    is scalar(@REX_TASKS), 1, 'the install task ran';
    is $REX_TASKS[0][0], $n->{task}, "the $n->{role}'s install again";
    ok $REX_TASKS[0][1]{server}, 'a join again';
    is $REX_TASKS[0][1]{clean_cilium_residue}, 1, 'with clean_cilium_residue';
    is_deeply check_opts(), [ { clean => 1 } ], 'its check cleared the leftovers';
    is scalar(OCPTest::Rexfile->calls($n->{lib})), 1, "and $n->{lib} ran";
    is_deeply $api->{crs}{$name}{spec}, $spec, 'the new OCPNode asks for the node the old one did';
    is $api->{crs}{$name}{status}{phase}, 'Ready', 'the node is Ready';
  };
}

# --- 3. a node ocp apply joined -------------------------------------------------

my $HA_YAML = <<'YAML';
name: k445
nocert: true
control_planes:
  - provider: ssh
    host: 10.230.30.51
  - provider: ssh
    host: 10.230.30.53
  - provider: ssh
    host: 10.230.30.54
workers:
  - name: amd
    provider: ssh
    nodes:
      - 10.230.30.50
YAML

# The refusal a joining node's install left in its OCPNode, as OCP::Node
# writes it: the real Rexfile's, for that node.
sub joined_refusal {
  my ($task, $name) = @_;
  my $ok = eval {
    rexfile_run_task(undef, $task, server => 'https://10.230.30.51:9345', token => 't',
      node_name => $name);
    1;
  };
  return "Rex task failed: $@";
}

sub ocpnode {
  my ($name, $role, $phase, $message) = @_;
  return {
    apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
    metadata   => { name => $name, namespace => 'ocp-system' },
    spec       => { role => $role, providerRef => 'ssh-default',
                    ($name =~ /^police/ ? () : (host => '10.230.30.50')) },
    status     => { phase => $phase, (defined $message ? (message => $message) : ()) },
  };
}

subtest 'ocp apply on the cluster that exists: a Failed node is not installed again, switch or not' => sub {
  my $config = project($HA_YAML);
  my $dir    = $config->project_dir;
  # What the first deploy left: police1's kubeconfig.yaml and status, police2
  # and police3 and the worker refused (k8, k26 -- all three through OCP::Node).
  $dir->child('kubeconfig.yaml')->spew("sops: {}\n");
  $dir->child('.ocp', 'status.yaml')->spew(
    "nodes:\n  - name: 10-230-30-51\n    role: control-plane\n    public_ip: 10.230.30.51\n");

  my $police2 = joined_refusal('install_rke2_server', 'police2');
  my $worker  = joined_refusal('install_rke2_agent', '10-230-30-50');
  like $police2, qr/\Q$REFUSAL_LINE\E/, 'police2 was refused (the library\'s words)';
  # The claim (k445): a control plane that joined is sent to node rm/add as
  # well, by its name and as a control plane -- the reconcile path below
  # joins none; the worker by its OCPNode's name, as the worker node add
  # defaults to.
  like $police2, qr/ocp node rm police2 --keep_machine and ocp node add police2 --role control-plane --provider PROVIDER with the switch/,
    'police2\'s sentence: ocp node rm police2 --keep_machine and ocp node add police2 --role control-plane';
  like $worker, qr/ocp node rm 10-230-30-50 --keep_machine and ocp node add 10-230-30-50 --provider PROVIDER with the switch/,
    'the worker\'s sentence: by its OCPNode\'s name, no --role';

  my $api = MemK8s->new;
  $api->{crs}{'10-230-30-51'} = ocpnode('10-230-30-51', 'control-plane', 'Ready');
  $api->{crs}{police2}        = ocpnode('police2', 'control-plane', 'Failed', $police2);
  $api->{crs}{police3}        = ocpnode('police3', 'control-plane', 'Failed', $police2);
  $api->{crs}{'10-230-30-50'} = ocpnode('10-230-30-50', 'worker', 'Failed', $worker);
  my $before = dclone($api->{crs});

  my (@reached, $finished);
  my $record = sub { my ($what, $ret) = @_; sub { push @reached, $what; $ret } };
  my $apply = OCP::Cmd::Apply->new(
    command_chain => [ ApplyOcp->new(config => $config->file . '') ],
    clean_cilium_residue => 1);
  {
    no warnings 'redefine';
    local *OCP::Cmd::Apply::SopsRepair::repair_sops_files = sub { };
    local *OCP::Secrets::read_kubeconfig                  = sub { "apiVersion: v1\nkind: Config\n" };
    local *OCP::Cmd::Apply::_k8s_api                      = sub { $api };
    # The components the reconcile looks after, which have nothing to do with
    # the nodes: answered as up to date.
    local *OCP::Drift::new                                = sub { bless {}, 'OCP::Drift' };
    local *OCP::Drift::detect                             = sub { [] };
    local *OCP::Cmd::Apply::rex_prober                    = sub { undef };
    local *OCP::Cmd::Apply::host_probe_warning            = sub { '' };
    local *OCP::Cmd::Apply::Drift::gpu_dry_run            = sub { () };
    local *OCP::Cmd::Apply::_setup_registry               = sub { 'unchanged' };
    local *OCP::Cmd::Apply::_configure_registry_dns       = sub { 0 };
    local *OCP::Cmd::Apply::_setup_nfd                    = sub { 'unchanged' };
    local *OCP::Cmd::Apply::_setup_gpu_operator           = sub { 'unchanged' };
    local *OCP::Cmd::Apply::AMDGPU::step                  = sub { { changed => 0, failed => [] } };
    local *OCP::Cmd::Apply::_setup_cilium_gateway         = sub { 'unchanged' };
    local *OCP::Cmd::Apply::_ensure_crds                  = sub { 1 };
    local *OCP::Cmd::Apply::CR::warn_install_time_changes = sub { };
    local *OCP::Cmd::Apply::_ensure_providers             = sub { 1 };
    local *OCP::Cmd::Apply::_migrate_legacy_nodes         = sub { 1 };
    local *OCP::Cmd::Apply::_ensure_cp_ocpnode            = sub { 1 };
    local *OCP::Cmd::Apply::_finish_apply                 = sub { $finished = 1; 1 };
    # Every way to a join, recorded: none may be reached.
    local *OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane = $record->('bootstrap', 0);
    local *OCP::Cmd::Apply::Deploy::deploy                     = $record->('deploy', 0);
    local *OCP::Cmd::Apply::Deploy::worker_step                = $record->('worker_step', ());
    local *OCP::Cmd::Apply::CR::ensure_control_plane_ocpnodes  = $record->('control-plane OCPNodes', ());
    local *OCP::Cmd::Apply::CR::ensure_worker_ocpnodes         = $record->('worker OCPNodes', ());
    local *OCP::Cmd::Apply::CR::cli_reconcile_workers          = $record->('cli_reconcile_workers', ());
    local *OCP::Cmd::Apply::CR::drive_workers                  = $record->('drive_workers', ());
    local *OCP::Node::reconcile                                = $record->('OCP::Node reconcile', 0);
    local *OCP::Node::reconcile_until_ready                    = $record->('OCP::Node reconcile_until_ready', 0);
    local *OCP::Rex::run_task                                  = $record->('a Rex task', 0);

    my ($rc, $out, $err) = captured { $apply->execute([], []) };
    ok $finished, 'the reconcile ran to its end' or diag "$rc\n$out\n$err";
    # The stubs above answer every other step as up to date: a step that
    # failed under them would be a harness that no longer fits, not a finding.
    unlike $err, qr/Could not|setup failed|reconcile failed/, 'no other step of the reconcile failed';
    is_deeply \@reached, [], 'with --clean_cilium_residue it reached no join, no OCP::Node and no Rex task';
    is_deeply [ grep { /^ENSURE/ } @{ $api->{writes} } ], [], 'and wrote no OCPNode';
    is_deeply $api->{crs}, $before, 'every OCPNode as it was: police2, police3 and the worker Failed';
    like $err, qr/^  \[!!\] worker 10-230-30-50 is Failed: \Q$worker\E$/m,
      'the Failed worker is named, with its old refusal';
    ok scalar(grep { $_ eq 'worker 10-230-30-50' } @{ $apply->{_failed_components} // [] }),
      'and counted: the run does not complete';
  }
};

# --- 4. those nodes of ocp apply, brought up by the node add the sentence names

subtest 'police2 and a listed worker of ocp apply: the node add the sentence spells out makes the OCPNode apply made, and brings it up' => sub {
  my $config = project($HA_YAML);
  my $api    = MemK8s->new;
  my $apply  = OCP::Cmd::Apply->new(command_chain => [ ApplyOcp->new ]);

  # The OCPNodes the first deploy makes, as it makes them.
  my %made;
  captured {
    $made{ $_->{metadata}{name} } = dclone($_)
      for OCP::Cmd::Apply::CR::ensure_control_plane_ocpnodes($apply, $api, $config),
          OCP::Cmd::Apply::CR::ensure_worker_ocpnodes($apply, $api, $config);
    1;
  };
  is_deeply [ sort keys %made ], [ '10-230-30-50', 'police2', 'police3' ],
    'ocp apply made police2, police3 and the worker 10-230-30-50';

  # And joins them, refused: cli_reconcile_workers, as the first deploy runs it.
  my @results;
  {
    no warnings 'redefine';
    local *OCP::SSH::new          = sub { my ($c, %a) = @_; bless {%a}, 'OCP::SSH' };
    local *OCP::SSH::wait_for_ssh = sub { 1 };
    local *OCP::SSH::run          = sub { { stdout => "K10::token\n", stderr => '', exit => 0 } };
    local *OCP::KnownHosts::scan  = sub { () };
    local *OCP::Rex::new          = sub { my ($c, %a) = @_; bless {%a}, 'OCP::Rex' };
    local *OCP::Rex::run_task     = \&rexfile_run_task;
    local $OCP::Node::READY_TIMEOUT = 10;
    @REX_TASKS = ();
    captured {
      @results = OCP::Cmd::Apply::CR::cli_reconcile_workers($apply, $api, $config,
        [ 'police2', '10-230-30-50' ],
        { ssh_key_path => $config->project_dir->child('.ocp', 'id_ed25519') . '',
          cp_ip => '10.230.30.51' });
      1;
    };
  }
  is_deeply [ map { $_->[0] } @REX_TASKS ], [ 'install_rke2_server', 'install_rke2_agent' ],
    'police2 joined as a server, the worker as an agent';
  is_deeply [ map { "$_->{name} $_->{phase}" } @results ], [ 'police2 Failed', '10-230-30-50 Failed' ],
    'both refused, Failed';

  my $rows = node_ls($api);
  for my $n ([ police2 => 'control-plane', '10.230.30.53', 'install_rke2_server' ],
             [ '10-230-30-50' => 'worker', '10.230.30.50', 'install_rke2_agent' ]) {
    my ($name, $role, $host, $task) = @$n;
    my $message = $api->{crs}{$name}{status}{message};
    like $message, qr/\Q$REFUSAL_LINE\E/, "$name: the library's refusal";
    my ($sentence) = $message =~ /\Q$REFUSAL_LINE\E (.*)$/;

    # The claim (k445): what ocp node ls shows of a node ocp apply made is
    # the --provider and --host node add needs for it: the provider CR apply
    # named, and the host ocp.yaml lists.
    is_deeply [ @{ $rows->{$name} }{qw(ROLE PHASE PROVIDER IP)} ], [ $role, 'Failed', 'ssh-default', $host ],
      "$name in ocp node ls: $role, Failed, ssh-default, $host";

    # `ocp node rm NAME --keep_machine`, then the node add as typed.
    delete $api->{crs}{$name};
    my %typed = typed_from($sentence, $rows->{$name});
    ok %typed, "$name: the sentence spells out a node add to type" or next;
    my ($rc, $err) = node_add($api, %typed);
    is $rc, 0, "$name: that node add, exit 0" or diag $err;
    is_deeply [ map { $_->[0] } @REX_TASKS ], [ $task ], "$name: joined as before ($task)";
    ok $REX_TASKS[0][1]{server}, "$name: a join";
    is_deeply check_opts(), [ { clean => 1 } ], "$name: the check cleared the leftovers";
    is_deeply $api->{crs}{$name}{spec}, $made{$name}{spec},
      "$name: its OCPNode asks for the node ocp apply's did";
    is_deeply $api->{crs}{$name}{metadata}{finalizers}, $made{$name}{metadata}{finalizers},
      "$name: with the finalizers ocp apply's had";
    is $api->{crs}{$name}{status}{phase}, 'Ready', "$name: Ready";
  }
};

done_testing;

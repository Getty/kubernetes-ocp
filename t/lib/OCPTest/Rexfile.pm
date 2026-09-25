package OCPTest::Rexfile;
# ABSTRACT: Load share/Rexfile against recording stubs, for the t/ suite

use strict;
use warnings;
use Carp qw( croak );
use Path::Tiny qw( path );

# share/Rexfile is a Rex script, not a module: it only runs under `rex`, over
# a real connection. Since k155 its tasks are thin wrappers around Rex::Rancher
# and Rex::GPU, so what OCP owns is the parameters it hands those libraries,
# the order of the steps, and the few pieces it still does itself. This loads
# the real Rexfile -- the real `task`/`desc` machinery of Rex, so task names
# and bodies are exactly what `rex -f` would see -- into a sandbox package in
# which every Rex command that would touch a host, and every library entry
# point, is replaced by a recorder. Nothing leaves the process.
#
#   OCPTest::Rexfile->load;
#   OCPTest::Rexfile->reset;
#   local $OCPTest::Rexfile::RUN = sub { my ($cmd) = @_; return ($out, $exit) };
#   my $out = OCPTest::Rexfile->run_task('install_k3s_server', { token => 't' });
#   my ($call) = OCPTest::Rexfile->calls('Rex::Rancher::Server::install_server');
#   my %opts = @{ $call->{args} };
#   my $code = OCPTest::Rexfile->helper('_cilium_opts');

our $SANDBOX = 'OCPTest::Rexfile::Sandbox';

# Every recorded call, in order: { name => 'run' | 'file' | 'Rex::...::fn', args => [...] }
our @CALLS;

# run: ($cmd, %opt) -> ($output, $exit). Default: empty output, exit 0.
our $RUN = sub { return ('', 0) };

# Library calls that die: 'Rex::Rancher::Agent::install_agent' => "message\n"
our %LIB_DIE;

# Host facts the stubs answer from.
our %IS_FILE;
our %CAT;
our %CAN_RUN;
our $OS     = 'Debian';
our $SERVER = '203.0.113.7';

# Tasks do_task runs for real instead of only recording (by name).
our %FOLLOW;

our @LIBRARY = qw(
  Rex::Rancher::Node::prepare_node
  Rex::Rancher::Server::install_server
  Rex::Rancher::Agent::install_agent
  Rex::Rancher::Cilium::install_cilium
  Rex::Rancher::Cilium::upgrade_cilium
  Rex::Rancher::Cilium::ensure_gateway_api_crds
  Rex::GPU::NVIDIA::install_driver
  Rex::GPU::NVIDIA::install_container_toolkit
  Rex::GPU::NVIDIA::verify_nvidia
);

my $loaded;

sub rexfile { path(__FILE__)->parent->parent->parent->parent->child('share', 'Rexfile') }

sub load {
  my ( $class ) = @_;
  return 1 if $loaded;

  # The libraries: recorders standing in for the real modules, so the suite
  # asserts what OCP hands them without needing a host. %INC first, so the
  # Rexfile's `use Rex::Rancher::Server ();` finds them loaded.
  for my $fq (@LIBRARY) {
    my ( $pkg, $fn ) = $fq =~ /^(.+)::([^:]+)$/;
    ( my $file = $pkg ) =~ s{::}{/}g;
    $INC{$file.'.pm'} ||= __FILE__;
    no strict 'refs';
    no warnings 'redefine';
    *{$fq} = sub {
      push @CALLS, { name => $fq, args => [@_] };
      die $LIB_DIE{$fq} if defined $LIB_DIE{$fq};
      return 1;
    };
  }

  # Raw bytes, as rex reads it: the Rexfile has no `use utf8`.
  my $src = $class->rexfile->slurp_raw;
  my $ok = eval "package $SANDBOX;\n#line 1 share/Rexfile\n$src\n;1";
  croak 'share/Rexfile does not load: '.$@ unless $ok;

  my %stub = (
    run => sub {
      my ( $cmd, @opt ) = @_;
      my %o = @opt % 2 ? () : @opt;
      push @CALLS, { name => 'run', args => [ $cmd, \%o ] };
      my ( $out, $exit ) = $RUN->( $cmd, %o );
      $? = $exit // 0;
      return $out // '';
    },
    file => sub {
      my ( $path, %o ) = @_;
      push @CALLS, { name => 'file', args => [ $path, \%o ] };
      return 1;
    },
    is_file => sub { push @CALLS, { name => 'is_file', args => [@_] }; $IS_FILE{ $_[0] } ? 1 : 0 },
    cat     => sub {
      push @CALLS, { name => 'cat', args => [@_] };
      die "cat: $_[0]: no such file\n" unless defined $CAT{ $_[0] };
      return $CAT{ $_[0] };
    },
    can_run => sub { $CAN_RUN{ $_[0] } ? '/usr/bin/'.$_[0] : undef },
    pkg     => sub { push @CALLS, { name => 'pkg', args => [@_] }; 1 },
    update_package_db     => sub { push @CALLS, { name => 'update_package_db', args => [] }; 1 },
    host_entry            => sub { push @CALLS, { name => 'host_entry', args => [@_] }; 1 },
    delete_lines_matching => sub { push @CALLS, { name => 'delete_lines_matching', args => [@_] }; 1 },
    append_if_no_such_line => sub { push @CALLS, { name => 'append_if_no_such_line', args => [@_] }; 1 },
    unlink  => sub { push @CALLS, { name => 'unlink', args => [@_] }; 1 },
    operating_system         => sub { $OS },
    operating_system_version => sub { '13' },
    connection => sub { bless {}, 'OCPTest::Rexfile::Connection' },
    do_task    => sub {
      my ( $task, $params ) = @_;
      push @CALLS, { name => 'do_task', args => [ $task, $params ] };
      return $class->task($task)->($params) if $FOLLOW{$task};
      return 1;
    },
  );
  for my $name (keys %stub) {
    no strict 'refs';
    no warnings qw( redefine prototype );
    *{$SANDBOX.'::'.$name} = $stub{$name};
  }

  return $loaded = 1;
}

sub reset {
  @CALLS = ();
  %LIB_DIE = ();
  %IS_FILE = ();
  %CAT = ();
  %CAN_RUN = ();
  %FOLLOW = ();
  return;
}

# All task names the Rexfile declares, without the sandbox prefix.
sub task_names {
  my ( $class ) = @_;
  $class->load;
  ( my $prefix = $SANDBOX ) =~ s/::/:/g;
  return sort map { s/^\Q$prefix\E://r } grep { /^\Q$prefix\E:/ } Rex::TaskList->create->get_tasks;
}

# A task's code, called as Rex would: with the parameter hashref.
sub task {
  my ( $class, $name ) = @_;
  $class->load;
  ( my $prefix = $SANDBOX ) =~ s/::/:/g;
  my $task = Rex::TaskList->create->get_task($prefix.':'.$name)
    or croak "share/Rexfile has no task $name";
  return $task->code;
}

# Runs a task with STDOUT captured; returns what it printed. Dies as the task dies.
sub run_task {
  my ( $class, $name, $params ) = @_;
  my $code = $class->task($name);
  my $out = '';
  {
    local *STDOUT;
    open STDOUT, '>', \$out or croak "cannot capture STDOUT: $!";
    $code->( $params // {} );
  }
  return $out;
}

sub helper {
  my ( $class, $name ) = @_;
  $class->load;
  my $code = $SANDBOX->can($name) or croak "share/Rexfile has no sub $name";
  return $code;
}

# Recorded calls by name, in order.
sub calls {
  my ( $class, $name ) = @_;
  return grep { $_->{name} eq $name } @CALLS;
}

# The options of the one call to a library function, as a hash; undef if none.
sub lib_opts {
  my ( $class, $fq ) = @_;
  my @c = $class->calls($fq);
  croak "$fq was called ".scalar(@c).' times' if @c > 1;
  return @c ? { @{ $c[0]{args} } } : undef;
}

# Every `run` command, in order.
sub commands { map { $_->{args}[0] } $_[0]->calls('run') }

# Index of the first call matching $pred in @CALLS, or -1.
sub index_of {
  my ( $class, $pred ) = @_;
  for my $i (0 .. $#CALLS) {
    local $_ = $CALLS[$i];
    return $i if $pred->($_);
  }
  return -1;
}

package OCPTest::Rexfile::Connection;
sub server { $OCPTest::Rexfile::SERVER }

1;

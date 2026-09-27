package OCPTest::UninstallHost;
# ABSTRACT: An ExistingHost provider whose "host" is /bin/sh over a PATH of stubs

use Moo;
use Path::Tiny ();

with 'OCP::Role::Provider::ExistingHost';

# OCP::Role::Provider::ExistingHost::delete_server hands the host
# Rex::Rancher::Uninstall's uninstall line through run_command. This consumer
# runs that line for real -- /bin/sh -c, as the SSH channel would, not under
# -e -- with a PATH of nothing but stubs, so a test sees what the uninstall
# does and what delete_server makes of its outcome, and nothing leaves the
# process's temp dir.
#
#   my $h = OCPTest::UninstallHost->new(
#     stubs => { rm => "exit 0\n", ip => "exit 1\n" },   # name => sh body
#     real  => [qw( grep sed )],                          # linked in by name
#   );
#   my $ok = eval { $h->delete_server(undef, host => '10.0.0.5'); 1 };
#   $h->log;      # one line per stub call: "name args"
#   $h->stderr;   # what the line wrote to stderr
#
# A stub body gets $OCP_STUB_LOG, $OCP_STUB_DIR and $OCP_STUB_BIN (the stub
# directory itself, so a stub can remove another one). Paths the line tests
# directly ([ -e /sys/fs/bpf/cilium ]) are the real machine's, which carries
# no Cilium.

has stubs => (is => 'ro', default => sub { {} });
has real  => (is => 'ro', default => sub { [] });
has dir   => (is => 'lazy', builder => sub { Path::Tiny->tempdir });
has sent  => (is => 'rw');
has log    => (is => 'rw', default => '');
has stderr => (is => 'rw', default => '');

sub resolve_host {
    my ($self, %opts) = @_;
    return $opts{host} // '10.0.0.5';
}

sub host_reachable { 1 }

sub bin { $_[0]->dir->child('bin') }

sub run_command {
    my ($self, $host, $cmd) = @_;
    $self->sent($cmd);

    my $bin = $self->bin;
    $bin->mkpath;
    for my $real (@{ $self->real }) {
        my ($path) = grep { -x } map { "$_/$real" } qw( /usr/bin /bin );
        symlink $path, $bin->child($real) if $path;
    }
    my $stubs = $self->stubs;
    for my $name (sort keys %$stubs) {
        my $f = $bin->child($name);
        $f->spew_utf8("#!/bin/sh\necho \"$name \$*\" >> \"\$OCP_STUB_LOG\"\n" . $stubs->{$name});
        $f->chmod(0755);
    }

    my $log = $self->dir->child('log');
    my $err = $self->dir->child('stderr');
    my $status = do {
        local $ENV{PATH}         = "$bin";
        local $ENV{OCP_STUB_LOG} = "$log";
        local $ENV{OCP_STUB_DIR} = $self->dir->stringify;
        local $ENV{OCP_STUB_BIN} = "$bin";
        system('/bin/sh', '-c', '{ ' . $cmd . ' ; } 2>' . $err);
    };
    $self->log($log->exists ? $log->slurp : '');
    $self->stderr($err->exists ? $err->slurp : '');

    return { stdout => '', stderr => $self->stderr, exit => $status >> 8 };
}

1;

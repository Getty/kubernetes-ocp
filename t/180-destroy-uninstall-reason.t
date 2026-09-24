#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Cmd::Destroy;
use OCP::Config;

#
# k180: since k175, OCP::Role::Provider::ExistingHost::delete_server dies
# with the host, the uninstaller's exit code and its stderr. `ocp destroy`
# caught that and printed a fixed "Could not uninstall on X (may already be
# down)" -- the reason was thrown away -- and still ended on "Cluster
# destroyed." with exit 0 while rke2 kept running on the machine.
#
# Decided here:
#
#   * the reason reaches STDERR, as delete_server said it;
#   * every machine is still tried -- one failure does not stop the others;
#   * a machine that keeps its RKE2/K3s install (uninstall failed, or skipped
#     for want of an SSH key) makes the run INCOMPLETE: named at the end on
#     STDERR, no "Cluster destroyed.", exit 1;
#   * the local state IS still removed. An ssh/local machine is not billed
#     through OCP and nothing in .ocp/status.yaml is needed to reach it again
#     (its address is printed, and in ocp.yaml); gating the cleanup on it
#     would make a project whose host is already gone impossible to tear
#     down. That gate stays reserved for a paid server the provider did not
#     delete (k140).
#

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

my @events;

# delete_server dies the way ExistingHost's does for hosts named in {die},
# returns a non-zero exit without dying for hosts in {exit} (the shape a
# provider not built on the role could still hand back), succeeds otherwise.
{
    package FakeProvider;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub list_servers_by_cluster { [] }
    sub resolve_host {
        my ($self, %opts) = @_;
        return '127.0.0.1' if $self->{type} eq 'local';
        die "SSH provider requires 'host'\n" unless $opts{host};
        return $opts{host};
    }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        push @events, [ $self->{type}, $opts{host} ];
        my $host = $opts{host} // '';
        die "Uninstall of RKE2/K3s on $host failed (exit 255):"
          . " ssh: connect to host $host port 22: Connection refused\n"
            if $main::DIE{$host};
        return { stdout => '', stderr => "rke2-uninstall.sh: not found", exit => 127 }
            if $main::EXIT{$host};
        return { stdout => '', stderr => '', exit => 0 };
    }
}

{
    package FakeKey;
    sub new            { bless {}, shift }
    sub path           { '/nonexistent/admin-key' }
    sub migration_hint { "hint\n" }
}

our (%DIE, %EXIT);

my $YAML = <<'YAML';
name: ocpt
control_planes:
  provider: ssh
  host: cp.lan
workers:
  - name: pool
    provider: ssh
    nodes:
      - w1.lan
      - w2.lan
YAML

my $STATUS = <<'YAML';
nodes:
  - name: cp
    provider: ssh
    public_ip: cp.lan
YAML

sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8($YAML);
    $dir->child('.ocp', 'status.yaml')->spew_utf8($STATUS);
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub run_destroy {
    my ($config, %a) = @_;
    @events = ();
    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        force         => 1,
    );
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my @ret = do {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        no warnings 'redefine';
        local *OCP::Provider::for_spec = sub {
            my ($class, $spec) = @_;
            return FakeProvider->new(type => $spec->{provider});
        };
        local *OCP::Secrets::hetzner_token = sub { undef };
        local *OCP::Cmd::Destroy::cluster_ssh_key = $a{no_key}
            ? sub { die "PIN2 required, no terminal\n" }
            : sub { FakeKey->new };
        eval { $cmd->execute([], []) };
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0],
             events => [@events] };
}

subtest 'the uninstaller\'s own reason reaches STDERR' => sub {
    local %DIE = ('w1.lan' => 1);
    my $config = project();
    my $r = run_destroy($config);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{err}, qr/w1\.lan.*exit 255.*Connection refused/s,
        'the reason delete_server gave is printed';
    unlike $r->{out}, qr/Connection refused/, 'and not on STDOUT';

    is_deeply [ map { $_->[1] } @{ $r->{events} } ],
        [ 'w1.lan', 'w2.lan', 'cp.lan' ],
        'the other machines were still uninstalled';
};

subtest 'a machine left with its install makes the run incomplete, exit 1' => sub {
    local %DIE = ('w1.lan' => 1);
    my $config = project();
    my $r = run_destroy($config);

    is $r->{ret}, 1, 'exit 1';
    like $r->{err}, qr/INCOMPLETE/i, 'reported incomplete';
    like $r->{err}, qr/^\s+- w1\.lan\b.*Connection refused/m,
        'the machine is named in the closing list, with its reason';
    unlike $r->{err}, qr/^\s+- w2\.lan/m, 'a machine that was cleaned is not';
    like $r->{err}, qr/rke2-uninstall\.sh/, 'the manual step is named';
    unlike $r->{out}, qr/Cluster destroyed/, 'no success line';

    ok !-f $config->status_file,
        'local state is still removed: an existing host is not a billed server';
};

subtest 'a non-zero exit that did not die is the same failure' => sub {
    local %EXIT = ('w2.lan' => 1);
    my $config = project();
    my $r = run_destroy($config);

    is $r->{ret}, 1, 'exit 1';
    like $r->{err}, qr/w2\.lan.*exit 127.*not found/s,
        'exit code and stderr are printed';
};

subtest 'an uninstall skipped for want of an SSH key is not a clean teardown' => sub {
    my $config = project();
    my $r = run_destroy($config, no_key => 1);

    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 1, 'exit 1';
    like $r->{err}, qr/^\s+- cp\.lan\b.*no SSH key/m,
        'the machines that kept their install are listed';
    unlike $r->{out}, qr/Cluster destroyed/, 'no success line';
};

subtest 'all clean: exit 0, success line' => sub {
    my $config = project();
    my $r = run_destroy($config);
    is $r->{ret}, 0, 'exit 0';
    like $r->{out}, qr/Cluster destroyed/, 'success line';
    is $r->{err}, '', 'nothing on STDERR';
};

done_testing;

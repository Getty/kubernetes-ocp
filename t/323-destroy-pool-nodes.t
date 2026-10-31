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
# k323: `ocp destroy` reads the machines of a worker pool off its nodes:
# list (_spec_worker_entries) and ran no part of validate(). Since k315
# validate() refuses a nodes: entry that names no host, but destroy never
# asked: an ssh pool with a boolean or a list among its nodes died inside
# Perl ("Not a HASH reference"), an entry whose host is a list became a
# machine named ARRAY(0x...), and a hetzner pool's list was taken for host
# names it then listed as "to destroy" and never deleted.
#
# Decided here:
#
#   * a nodes: list destroy reads that validate() refuses stops the teardown
#     before anything is asked or touched -- no secrets read (a PIN), no
#     cluster API, no server deleted, no robocop scale-down, no local state
#     removed -- and says validate()'s own line for it, every one at once;
#   * only that. An ocp.yaml validate() refuses for a key destroy does not
#     read -- a gpu.driver typo, a robocop key a newer validate() refuses, a
#     pool count destroy never reads -- is still torn down. The teardown is
#     the way out of a cluster; it must not wait for an edit to a key it
#     has no use for.
#

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# One log for every fake, so "nothing was touched" covers the secrets read,
# the cluster API, the robocop scale-down and the deletes alike.
my @events;

{
    package FakeProvider;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub list_servers_by_cluster { [] }
    sub resolve_host {
        my ($self, %opts) = @_;
        die "SSH provider requires 'host'\n" unless $opts{host};
        return $opts{host};
    }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        push @events, [ delete => $self->{type}, $id // $opts{host} ];
        return { stdout => '', stderr => '', exit => 0 };
    }
}

{
    package FakeKey;
    sub new            { bless {}, shift }
    sub path           { '/nonexistent/admin-key' }
    sub migration_hint { "hint\n" }
}

{
    package FakeList;
    sub new   { bless { items => [] }, shift }
    sub items { $_[0]{items} }
}
{
    package FakeK8s;
    sub new { bless {}, shift }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list  { push @events, [ 'api list' ]; FakeList->new }
    sub patch { my ($self, $kind, $name) = @_; push @events, [ patch => $kind, $name ]; 1 }
}

my $CP = "control_planes:\n  provider: hetzner\n  server_type: cx32\n  location: fsn1\n";

# The control plane status.yaml records: a teardown that runs deletes it.
my $STATUS = <<'YAML';
nodes:
  - name: police1
    provider: hetzner
    providerId: "111"
    public_ip: 1.1.1.1
YAML

sub project {
    my ($workers, %a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: prod\n$CP" . ($a{extra} // '') . $workers);
    $dir->child('.ocp', 'status.yaml')->spew_utf8($a{status} // $STATUS);
    $dir->child('.ocp', 'deployed.yaml')->spew_utf8("registry: abc\n");
    $dir->child('kubeconfig.yaml')->spew_utf8("sops: encrypted\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub state_files {
    my ($config) = @_;
    return ($config->status_file, $config->deployed_file,
            $config->project_dir->child('kubeconfig.yaml')->stringify);
}

sub run_destroy {
    my ($config) = @_;
    @events = ();
    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        k8s           => FakeK8s->new,
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
        local *OCP::Secrets::hetzner_token = sub { push @events, [ 'secrets read' ]; 'tok' };
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { FakeKey->new };
        eval { $cmd->execute([], []) };
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0],
             events => [@events] };
}

# validate()'s lines about a pool's nodes, for comparing with the refusal. Not
# a key of a machine's that nothing reads (k355): destroy does not read it,
# and it holds up no teardown (the second point above).
sub nodes_lines { grep { /\bnodes\b/ && !/: unknown key / } $_[0]->validate }

# The refusal, whole: validate()'s lines and nothing else touched.
sub refused {
    my ($r, $config, @lines) = @_;
    my $file = $config->file;
    my $n    = @lines;
    is $r->{ex},
        "$file has $n error" . ($n == 1 ? '' : 's') . ":\n"
          . join('', map { "  - $_\n" } @lines)
          . "Nothing was deleted: ocp destroy reads the cluster's name and the machines and "
          . "providers of the control planes and worker pools in ocp.yaml, and checks their "
          . "shape before it touches the cluster or a server. "
          . "Fix the line" . ($n == 1 ? '' : 's') . " above and run it again.\n",
        'refused with validate()\'s line' . ($n == 1 ? '' : 's');
    is_deeply $r->{events}, [],
        'no secrets read, no cluster API, no robocop scale-down, no server deleted';
    ok -f $_, path($_)->basename . ' is kept' for state_files($config);
    is $r->{out}, '', 'nothing on STDOUT';
}

# ------------------------------------------------------- refused

subtest 'an ssh pool with a boolean among its nodes' => sub {
    my $config = project(<<'YAML');
workers:
  - name: edge
    provider: ssh
    nodes: [ w1.lan, true ]
YAML
    my @lines = nodes_lines($config);
    is_deeply \@lines,
        [ "worker pool 'edge': nodes[2] must be a host name or IP address, or a mapping with host, not true" ],
        'the fixture: validate() names nodes[2]';
    my $r = run_destroy($config);
    unlike $r->{ex}, qr/HASH reference/, 'no Perl error';
    refused($r, $config, @lines);
};

subtest 'a list among an ssh pool\'s nodes, and an entry with a list for host' => sub {
    my $config = project(<<'YAML');
workers:
  - name: edge
    provider: ssh
    nodes:
      - [ a.lan, b.lan ]
      - host: [ c.lan ]
YAML
    my @lines = nodes_lines($config);
    is scalar @lines, 2, 'the fixture: validate() names both entries';
    my $r = run_destroy($config);
    unlike $r->{ex}, qr/HASH reference/, 'no Perl error';
    unlike $r->{out}.$r->{err}, qr/ARRAY\(0x/, 'no machine named ARRAY(0x...)';
    refused($r, $config, @lines);
};

subtest 'an entry with no host, and pools that count but list names' => sub {
    # A hetzner or local pool counts its machines (k315); destroy took a list
    # there for host names. t/77 named its local machine that way until k323.
    my $config = project(<<'YAML');
workers:
  - name: edge
    provider: ssh
    nodes:
      - w1.lan
      - name: w2
  - name: big
    provider: hetzner
    server_type: cx22
    location: fsn1
    nodes: [ h1, true ]
  - name: lp
    provider: local
    nodes: [ 127.0.0.1 ]
YAML
    my @lines = nodes_lines($config);
    is_deeply \@lines, [
        "worker pool 'edge': nodes[2] needs a host",
        "worker pool 'big': nodes must be a whole number (how many machines the pool has), not a list",
        "worker pool 'lp': nodes must be a whole number (how many machines the pool has), not a list",
    ], 'the fixture: validate() names all three pools';
    ok scalar(grep { $_ eq 'workers[1].nodes[2].name: unknown key (must be host)' } $config->validate),
        '... and name: as a key nothing reads (k355), which the refusal leaves out';
    my $r = run_destroy($config);
    refused($r, $config, @lines);
};

subtest 'a pool without a name is named by its place, as validate() names it' => sub {
    my $config = project(<<'YAML');
workers:
  - name: big
    provider: hetzner
    server_type: cx22
    location: fsn1
    nodes: 2
  - provider: ssh
    nodes: [ false ]
YAML
    my @lines = nodes_lines($config);
    is_deeply \@lines,
        [ "workers[2]: nodes[1] must be a host name or IP address, or a mapping with host, not false" ],
        'the fixture: validate() says workers[2]';
    refused(run_destroy($config), $config, @lines);
};

subtest 'the no-nodes path is refused the same way, before its question' => sub {
    # Nothing recorded, so a teardown would go the k304 way and offer to
    # remove the local state; the refusal comes first.
    my $config = project(<<'YAML', status => "nodes: []\n");
workers:
  - name: edge
    provider: ssh
    nodes: [ true ]
YAML
    my @lines = nodes_lines($config);
    is scalar @lines, 1, 'the fixture: one line';
    my $r = run_destroy($config);
    refused($r, $config, @lines);
};

subtest 'through run_cli: the line on STDERR, exit 1, STDOUT empty' => sub {
    my $config = project(<<'YAML');
workers:
  - name: edge
    provider: ssh
    nodes: [ w1.lan, true ]
YAML
    my ($line) = nodes_lines($config);
    my ($out, $err, $code) = ('', '');
    @events = ();
    {
        local @ARGV = ('-c', $config->file, 'destroy', '--force');
        local $ENV{HETZNER_API_TOKEN};
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        local *STDERR;
        open STDERR, '>', \$err or die;
        no warnings 'redefine';
        # Tripwires: the refusal comes before any of these.
        local *OCP::Secrets::hetzner_token = sub { push @events, [ 'secrets read' ]; undef };
        local *OCP::Provider::for_spec     = sub { push @events, [ 'provider built' ]; die "reached\n" };
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { push @events, [ 'ssh key' ]; die "reached\n" };
        $code = OCP->run_cli;
    }
    is $code, 1, 'exit 1';
    like $err, qr/^Error: \Q${\ $config->file }\E has 1 error:\n  - \Q$line\E\n/,
        'validate()\'s line on STDERR';
    unlike $err, qr/HASH reference|internal error/, 'no Perl error, no "internal error"';
    is $out, '', 'STDOUT empty';
    is_deeply \@events, [], 'nothing asked, nothing built';
    ok -f $_, path($_)->basename . ' is kept' for state_files($config);
};

# ------------------------------------------------------- not refused

subtest 'validate() errors in keys destroy does not read do not stop it' => sub {
    # gpu.driver and an unknown robocop key (k315) destroy has no use for; a
    # count where validate() wants a whole number, and an ssh pool that
    # counts instead of naming -- destroy reads a pool's machines off a list
    # only, so no count of any shape stands between it and the servers; and
    # a pool whose provider destroy does not know, which it skips unread.
    my $config = project(<<'YAML', extra => "gpu:\n  driver: oprator\nrobocop:\n  foo: 1\n");
workers:
  - name: big
    provider: hetzner
    server_type: cx22
    location: fsn1
    nodes: two
  - name: s
    provider: ssh
    nodes: 3
  - name: v
    provider: vsphere
    nodes: [ a.lan, true ]
YAML
    my @errors = $config->validate;
    is scalar @errors, 5, 'the fixture: validate() refuses it, five lines'
        or diag explain \@errors;

    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    ok scalar(grep { $_->[0] eq 'delete' && $_->[2] eq '111' } @{ $r->{events} }),
        'the control plane is deleted';
    ok !-f $_, path($_)->basename . ' is removed' for state_files($config);
    like $r->{out}, qr/Cluster destroyed\./, 'Cluster destroyed.';
};

subtest 'a well-formed ssh pool list is read and torn down' => sub {
    my $config = project(<<'YAML');
workers:
  - name: edge
    provider: ssh
    nodes:
      - w1.lan
      - host: w2.lan
YAML
    is_deeply [ $config->validate ], [], 'the fixture: validate() has nothing';

    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    is_deeply [ sort map { $_->[2] } grep { $_->[0] eq 'delete' && $_->[1] eq 'ssh' } @{ $r->{events} } ],
        [ 'w1.lan', 'w2.lan' ], 'both machines are uninstalled';
    ok scalar(grep { $_->[0] eq 'delete' && $_->[2] eq '111' } @{ $r->{events} }),
        'the control plane is deleted';
    like $r->{out}, qr/Cluster destroyed\./, 'Cluster destroyed.';
};

done_testing;

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
# k326: `ocp destroy` reads control_planes and workers in two more places
# than k323 gated, and both died inside Perl on a shape validate() has
# refused since k296:
#
#   * a control_planes list entry that is no mapping (`control_planes:
#     [police1]`). The k98 report reads every entry's provider on each run
#     with a Hetzner token, AFTER the deletes and the status cleanup: the
#     servers were gone and status.yaml removed, and the run died there --
#     no "Cluster destroyed.", exit 1, the report of mislabelled servers
#     skipped. The control-plane fallback reads the same entries;
#   * `workers:` that is no list, or a pool that is no mapping: died in
#     _spec_worker_entries, after the secrets read and the OCPNode list.
#
# Decided here: refused up front, like k323's pool nodes: lists, with
# validate()'s line, before a PIN is asked or anything is touched. Not read
# around: an entry that is no mapping names no provider, and destroy never
# guesses one (k116), so it cannot be read as a machine -- only named. A
# string there may be a host someone means; named after the teardown is too
# late for the one case it matters, where that line is the only record of a
# control plane: the run then ends "No nodes to destroy." and offers to
# remove the kubeconfig while that machine may still run.
#
# Only the shape: a control-plane or pool line validate() refuses for what
# destroy reads around or not at all -- an unknown provider, a missing
# server_type or location, more than seven control planes, a count -- is
# still torn down, and the k98 report still runs.
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

# Servers by ocp-cluster label, as the label search finds them.
my %labelled;

{
    package FakeServer;
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub name { $_[0]{name} }
    sub id   { $_[0]{id} }
    sub ipv4 { $_[0]{ipv4} }
}

{
    package FakeProvider;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub list_servers_by_cluster { [ map { FakeServer->new(%$_) } @{ $labelled{$_[1]} // [] } ] }
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

# A server from before k98 under the label the report searches.
my %MISLABELLED = ('hetzner-default' => [ { name => 'old-w1', id => 999, ipv4 => '9.9.9.9' } ]);

sub project {
    my ($yaml, %a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: prod\n$yaml");
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
    @events   = ();
    %labelled = %MISLABELLED;
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

# validate()'s lines about the shapes destroy reads: control_planes and its
# entries, workers and its pools, a pool's nodes.
sub shape_lines {
    grep {
        /^control_planes(?:\[\d+\])?: must be a mapping/
            || /^workers(?:\[\d+\])?: must be a (?:list|mapping)/
            || /: nodes(?:\[\d+\])?(?:\.host)? (?:must|needs)/
    } $_[0]->validate;
}

# The refusal, whole: validate()'s lines and nothing else touched.
sub refused {
    my ($r, $config, @lines) = @_;
    my $file = $config->file;
    my $n    = @lines;
    my $s    = $n == 1 ? '' : 's';
    is $r->{ex},
        "$file has $n error$s:\n"
          . join('', map { "  - $_\n" } @lines)
          . "Nothing was deleted: ocp destroy reads the cluster's name and the machines and "
          . "providers of the control planes and worker pools in ocp.yaml, and checks their "
          . "shape before it touches the cluster or a server. Fix the line$s above and run "
          . "it again.\n",
        "refused with validate()'s line$s";
    unlike $r->{ex}, qr/HASH ref|ARRAY ref|at \S+ line \d+/, 'no Perl error';
    is_deeply $r->{events}, [],
        'no secrets read, no cluster API, no robocop scale-down, no server deleted';
    ok -f $_, path($_)->basename . ' is kept' for state_files($config);
    is $r->{out}, '', 'nothing on STDOUT';
}

# A teardown that ran to the end: deleted, cleaned up, reported.
sub torn_down {
    my ($r, $config) = @_;
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    ok scalar(grep { $_->[0] eq 'delete' && $_->[2] eq '111' } @{ $r->{events} }),
        'the control plane is deleted';
    ok !-f $_, path($_)->basename . ' is removed' for state_files($config);
    like $r->{out}, qr/\nCluster destroyed\.\n\z/, 'ends on Cluster destroyed.';
    like $r->{err}, qr/1 Hetzner server\(s\) carry the label ocp-cluster=hetzner-default/,
        'the k98 report ran';
}

# ------------------------------------------------------- refused

subtest 'a control plane listed as a string: refused before anything is deleted' => sub {
    # The card's case. Before k326: police1 deleted, status.yaml removed,
    # then "Can't use string ("police1") as a HASH ref" in the k98 report.
    my $config = project("control_planes:\n  - police1\n");
    my @lines = shape_lines($config);
    is_deeply \@lines,
        [ "control_planes[1]: must be a mapping (one control plane), not 'police1'" ],
        'the fixture: validate() names control_planes[1]';
    refused(run_destroy($config), $config, @lines);
};

subtest 'control_planes entries that are a list, a boolean, null' => sub {
    my $config = project(<<"YAML");
control_planes:
  - provider: hetzner
    server_type: cx32
    location: fsn1
  - [ a.lan ]
  - true
  - ~
YAML
    my @lines = shape_lines($config);
    is_deeply \@lines, [
        "control_planes[2]: must be a mapping (one control plane), not a list",
        "control_planes[3]: must be a mapping (one control plane), not true",
        "control_planes[4]: must be a mapping (one control plane), not null",
    ], 'the fixture: validate() names the three entries';
    refused(run_destroy($config), $config, @lines);
};

subtest 'control_planes that is neither a mapping nor a list' => sub {
    # Read as one hetzner control plane nobody wrote (k296); a string there
    # is the same host name as in the list.
    for my $value ('police1', 'true') {
        my $config = project("control_planes: $value\n");
        my @lines = shape_lines($config);
        is scalar @lines, 1, "the fixture: validate() refuses control_planes: $value";
        like $lines[0], qr/^control_planes: must be a mapping \(one control plane, or nodes: N of them\) or a list of mappings, not /,
            '... with its shape line';
        refused(run_destroy($config), $config, @lines);
    }
};

subtest 'workers that is no list' => sub {
    # Before k326: "Can't use string ("foo") as an ARRAY ref" inside Perl.
    for my $value ('foo', "\n  name: edge\n  provider: ssh") {
        my $config = project("${CP}workers: $value\n");
        my @lines = shape_lines($config);
        is scalar @lines, 1, 'the fixture: validate() refuses workers';
        like $lines[0], qr/^workers: must be a list of worker pools, not (?:'foo'|a mapping)\z/,
            '... with its shape line';
        refused(run_destroy($config), $config, @lines);
    }
};

subtest 'pools that are no mapping, beside a pool whose nodes: are refused' => sub {
    my $config = project(<<"YAML");
${CP}workers:
  - w1.lan
  - name: edge
    provider: ssh
    nodes: [ true ]
  - [ w2.lan ]
YAML
    my @lines = shape_lines($config);
    is_deeply \@lines, [
        "workers[1]: must be a mapping (a worker pool), not 'w1.lan'",
        "worker pool 'edge': nodes[1] must be a host name or IP address, or a mapping with host, not true",
        "workers[3]: must be a mapping (a worker pool), not a list",
    ], 'the fixture: validate() names all three, in this order';
    refused(run_destroy($config), $config, @lines);
};

subtest 'control planes and pools at once, in validate()\'s order' => sub {
    my $config = project(<<'YAML');
control_planes:
  - police1
workers:
  - false
YAML
    my @lines = shape_lines($config);
    is_deeply \@lines, [
        "control_planes[1]: must be a mapping (one control plane), not 'police1'",
        "workers[1]: must be a mapping (a worker pool), not false",
    ], 'the fixture: validate() names both';
    refused(run_destroy($config), $config, @lines);
};

subtest 'the no-nodes path is refused the same way, before its question' => sub {
    # Nothing recorded: the control-plane fallback would have been the only
    # reader of control_planes[1], and its machine the only one there is.
    my $config = project("control_planes:\n  - cp1.lan\n", status => "nodes: []\n");
    my @lines = shape_lines($config);
    is scalar @lines, 1, 'the fixture: one line';
    refused(run_destroy($config), $config, @lines);
};

subtest 'through run_cli: the line on STDERR, exit 1, STDOUT empty' => sub {
    my $config = project("control_planes:\n  - police1\n");
    my ($line) = shape_lines($config);
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
        local *OCP::Secrets::hetzner_token = sub { push @events, [ 'secrets read' ]; 'tok' };
        local *OCP::Provider::for_spec     = sub { push @events, [ 'provider built' ]; die "reached\n" };
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { push @events, [ 'ssh key' ]; die "reached\n" };
        $code = OCP->run_cli;
    }
    is $code, 1, 'exit 1';
    like $err, qr/^Error: \Q${\ $config->file }\E has 1 error:\n  - \Q$line\E\n/,
        'validate()\'s line on STDERR';
    unlike $err, qr/HASH ref|internal error/, 'no Perl error, no "internal error"';
    is $out, '', 'STDOUT empty';
    is_deeply \@events, [], 'nothing asked, nothing built';
    ok -f $_, path($_)->basename . ' is kept' for state_files($config);
};

# ------------------------------------------------------- not refused

subtest 'control-plane lines validate() refuses for what destroy reads around' => sub {
    # Eight mappings (over etcd's seven), one with a provider destroy does not
    # know, one with a list for provider, one with no server_type or location:
    # every entry a mapping, so the report reads each provider and skips what
    # is not hetzner. A mapping with a nodes: count past the bound. And no
    # control_planes at all, read as one hetzner control plane with nothing
    # set.
    my $list = "control_planes:\n"
        . join('', map { "  - provider: hetzner\n    server_type: cx32\n    location: fsn1\n" } 1 .. 5)
        . "  - provider: vsphere\n"
        . "  - provider: [ hetzner ]\n"
        . "  - provider: hetzner\n";
    my $mapping = "control_planes:\n  provider: hetzner\n  server_type: cx32\n"
        . "  location: fsn1\n  nodes: 9\n";
    for my $yaml ($list, $mapping, '') {
        my $config = project($yaml);
        is_deeply [ shape_lines($config) ], [], 'the fixture: no shape line';
        ok scalar(grep { /^control_planes/ } $config->validate),
            'the fixture: validate() refuses the control planes';
        torn_down(run_destroy($config), $config);
    }
};

subtest 'a well-formed control-plane list is torn down and reported' => sub {
    my $config = project(<<'YAML');
control_planes:
  - provider: hetzner
    server_type: cx32
    location: fsn1
workers:
  - name: big
    provider: hetzner
    server_type: cx22
    location: fsn1
    nodes: 2
YAML
    is_deeply [ $config->validate ], [], 'the fixture: validate() has nothing';
    torn_down(run_destroy($config), $config);
};

done_testing;

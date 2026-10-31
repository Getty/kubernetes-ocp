#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Destroy;
use OCP::Config;

#
# k345: what the last-resort control-plane fallback of `ocp destroy`, and a
# line it says for a skipped pool, still got wrong after k341:
#
#   * a control plane with host: 0 (or '') was listed as a machine named 0.
#     Apply reads such a host as none -- cp_identity names that control plane
#     police1, ensure_control_plane_ocpnodes puts no host on its OCPNode --
#     as k341 made destroy read a pool's;
#   * a hetzner control plane was listed as "Deleting <cluster>-cp-1..." and
#     deleted nothing: the fallback has no server id for it. Its server is
#     one Hetzner created, found by its ocp-cluster label -- the search that
#     runs before the fallback, and that found nothing if the fallback runs
#     -- or not at all. It is said now, not listed: on STDOUT when the search
#     answered, on STDERR when none did (no token, or it failed), because
#     then it may still run. A control plane with no provider is one apply
#     and validate() read as hetzner, and is said the same way;
#   * that left a hetzner-only fallback with nothing to list, so the run takes
#     the "No nodes to destroy." path -- where the k98 report of mislabelled
#     servers did not run. It does now: it ran on this shape before, through
#     the delete line that deleted nothing;
#   * a pool with provider: false was skipped with "invalid provider false";
#     validate() says "provider required".
#

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# One log for every fake: the secrets read, the PIN2 key, the label
# searches, the cluster API, the robocop scale-down and the deletes.
my @events;

# Servers by ocp-cluster label, as the label search finds them; and whether
# that search fails.
my %labelled;
my $search_dies;

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
    sub list_servers_by_cluster {
        my ($self, $label) = @_;
        push @events, [ search => "$label" ];
        die "401 Unauthorized\n" if $search_dies;
        return [ map { FakeServer->new(%$_) } @{ $labelled{$label} // [] } ];
    }
    sub resolve_host {
        my ($self, %opts) = @_;
        return '127.0.0.1' if $self->{type} eq 'local';
        die "SSH provider requires 'host'\n" unless $opts{host};
        return $opts{host};
    }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        push @events, [ delete => $self->{type}, "" . ($id // $opts{host}) ];
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
    # The cluster API: no OCPNodes, no OCPNodeProviders -- or not answering.
    package FakeK8s;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list {
        my ($self, $kind) = @_;
        push @events, [ 'api list', $kind ];
        die "connection refused\n" if $self->{down};
        return FakeList->new;
    }
    sub patch { my ($self, $kind, $name) = @_; push @events, [ patch => $kind, $name ]; 1 }
}

my $HCP = "control_planes:\n  provider: hetzner\n  server_type: cx32\n  location: fsn1\n";

# Nothing recorded: the control-plane fallback is the source left.
sub project {
    my ($yaml, %a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: prod\n$yaml");
    $dir->child('.ocp', 'status.yaml')->spew_utf8($a{status} // "nodes: []\n");
    $dir->child('.ocp', 'deployed.yaml')->spew_utf8("registry: abc\n");
    $dir->child('kubeconfig.yaml')->spew_utf8("sops: encrypted\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub run_destroy {
    my ($config, %a) = @_;
    @events      = ();
    %labelled    = %{ $a{labelled} // {} };
    $search_dies = $a{search_dies};
    my $token    = exists $a{token} ? $a{token} : 'tok';
    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        k8s           => FakeK8s->new(down => $a{api_down}),
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
        local *OCP::Secrets::hetzner_token = sub { push @events, [ 'secrets read' ]; $token };
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { push @events, [ 'ssh key' ]; FakeKey->new };
        eval { $cmd->execute([], []) };
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0], events => [@events] };
}

sub deleted  { [ sort map { "$_->[1] $_->[2]" } grep { $_->[0] eq 'delete' } @{ $_[0]{events} } ] }
sub searched { [ map { $_->[1] } grep { $_->[0] eq 'search' } @{ $_[0]{events} } ] }

my $NO_NODES = "No nodes to destroy.\nRemoved status.yaml.\nRemoved deployed.yaml.\n"
             . "Encrypted kubeconfig removed.\n";

# The line for a hetzner control plane the label search answered for.
sub found_none {
    my ($n) = @_;
    return "control_planes[$n]: a hetzner control plane is found by its ocp-cluster=prod "
         . "label or not at all; no server carries it, nothing to delete.\n";
}

# ...and the one for a hetzner control plane no search answered for.
sub not_searched {
    my ($n, $why, $fix) = @_;
    $fix //= "Put the project's Hetzner token into secrets.yaml";
    return "[!!] control_planes[$n]: a hetzner control plane is found by its ocp-cluster=prod "
         . "label or not at all, and $why -- if it runs, it is NOT torn down.\n"
         . "     $fix and run `ocp destroy` again, or look by hand:\n"
         . "       hcloud server list -l ocp-cluster=prod\n";
}

# ------------------------------------------------------- host: 0 or ''

subtest 'a control plane with host: 0 or \'\' names no machine, as apply reads it' => sub {
    for my $host ('0', "''") {
        my $ssh = project("control_planes:\n  provider: ssh\n  host: $host\n");
        is OCP::Cmd::Apply::Bootstrap::cp_identity($ssh)->{name}, 'police1',
            "the fixture: apply names the ssh control plane with host: $host police1 -- "
            . 'it reads no host';
        my $r = run_destroy($ssh);
        is $r->{ex}, '', "ssh, host: $host -- ran without dying" or diag $r->{ex};
        like $r->{out}, qr/^  - prod-cp-1 \(ssh, -\)$/m,
            "ssh, host: $host -- listed under the fallback's name, with no address";
        unlike $r->{out}, qr/^  - 0 |^Deleting 0\.\.\.$|^  -  \(/m, "ssh, host: $host -- no machine named 0 or ''";
        is_deeply deleted($r), [], "ssh, host: $host -- nothing uninstalled";
        ok !(grep { $_->[0] eq 'ssh key' } @{ $r->{events} }), "ssh, host: $host -- no PIN2 asked";

        # The local provider uninstalls on 127.0.0.1 whatever host it is told,
        # so this one is still torn down (k146) -- under the fallback's name.
        my $local = project("control_planes:\n  provider: local\n  host: $host\n");
        $r = run_destroy($local);
        is $r->{ex}, '', "local, host: $host -- ran without dying" or diag $r->{ex};
        like $r->{out}, qr/^  - prod-cp-1 \(local, -\)$/m, "local, host: $host -- listed as prod-cp-1";
        unlike $r->{out}, qr/^  - 0 |^Deleting 0\.\.\.$|^  -  \(/m, "local, host: $host -- no machine named 0 or ''";
        is_deeply deleted($r), [ 'local 127.0.0.1' ], "local, host: $host -- uninstalled on 127.0.0.1";
        like $r->{out}, qr/\nCluster destroyed\.\n\z/, "local, host: $host -- ends on Cluster destroyed.";
    }
};

# ------------------------------------------------------- a hetzner control plane

subtest 'a hetzner control plane the label search found nothing for: said, not "Deleting"' => sub {
    # The card's case. Before k345: "Nodes to destroy: prod-cp-1 (hetzner, -)",
    # "Deleting prod-cp-1...", nothing deleted, "Cluster destroyed.".
    my $config = project($HCP);
    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    is_deeply searched($r), [ 'prod', 'hetzner-default' ],
        'searched by its label before the fallback, and for the k98 report after it';
    is $r->{out}, found_none(1) . $NO_NODES,
        'on STDOUT: found by label or not at all, none found -- then No nodes to destroy.';
    is $r->{err}, '', 'nothing on STDERR: nothing went wrong';
    is_deeply deleted($r), [], 'nothing deleted';
};

subtest 'the control: the control plane\'s server carries the label, and is deleted by it' => sub {
    my $config = project($HCP);
    my $r = run_destroy($config,
        labelled => { prod => [ { name => 'prod-police1', id => 111, ipv4 => '1.1.1.1' } ] });
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is_deeply deleted($r), [ 'hetzner 111' ], 'deleted by its id';
    like $r->{out}, qr/^Deleting prod-police1\.\.\.$/m, 'under its own name';
    unlike $r->{out}.$r->{err}, qr/control_planes\[1\]|prod-cp-1/,
        'the fallback does not run: something was found';
    like $r->{out}, qr/\nCluster destroyed\.\n\z/, 'ends on Cluster destroyed.';
};

subtest 'no label search answered: said on STDERR, with what it leaves' => sub {
    # No local token and no OCPNodeProvider token: nothing searched for it.
    my $config = project($HCP);
    my $r = run_destroy($config, token => undef);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is_deeply searched($r), [], 'the fixture: no search ran';
    is $r->{err}, not_searched(1, 'no Hetzner token searched for it'),
        'on STDERR: no token searched for it, it may still run, how to find it';
    is $r->{out}, $NO_NODES, 'STDOUT: No nodes to destroy., no Deleting line';
    is_deeply deleted($r), [], 'nothing deleted';

    # The cluster API down as well: its line, then this one. A fresh project
    # for each run: the one above removed the local state.
    $r = run_destroy(project($HCP), token => undef, api_down => 1);
    like $r->{err}, qr/\A\[!!\] Could not read the OCPNodes from the cluster API:\n/,
        'the API line first';
    like $r->{err}, qr/\n\Q${\ not_searched(1, 'no Hetzner token searched for it') }\E\z/,
        'then the control plane\'s';

    # A search that fails answered nothing either -- and says why.
    $r = run_destroy(project($HCP), search_dies => 1);
    is_deeply searched($r), [ 'prod', 'hetzner-default' ],
        'the fixture: the label search ran, and died (as the k98 report\'s did)';
    is $r->{err}, not_searched(1, 'the label search failed: 401 Unauthorized', 'Fix the cause'),
        'on STDERR, with the search\'s error';
    is $r->{out}, $NO_NODES, 'STDOUT: No nodes to destroy.';
};

subtest 'nodes: N is said once; no provider is read as hetzner, as apply reads it' => sub {
    my $shared = project("control_planes:\n  provider: hetzner\n  server_type: cx32\n"
                       . "  location: fsn1\n  nodes: 3\n");
    my $r = run_destroy($shared);
    is $r->{out}, found_none(1) . $NO_NODES, 'nodes: 3 -- one line, as validate() says it once';

    # validate() and apply read a control plane with no provider as hetzner;
    # before k345 the fallback skipped it without a word, even with no token
    # to search for it.
    my $none = project("control_planes:\n  server_type: cx32\n  location: fsn1\n");
    is OCP::Cmd::Apply::Bootstrap::cp_identity($none)->{provider}, 'hetzner',
        'the fixture: apply reads no provider as hetzner';
    $r = run_destroy($none);
    is $r->{out}, found_none(1) . $NO_NODES, 'no provider -- the same line as hetzner';
    $r = run_destroy($none, token => undef);
    is $r->{err}, not_searched(1, 'no Hetzner token searched for it'),
        'no provider, no token -- said on STDERR as for hetzner';
};

subtest 'beside a control plane the fallback lists: that one is torn down, the hetzner one said' => sub {
    my $config = project(<<'YAML');
control_planes:
  - provider: hetzner
    server_type: cx32
    location: fsn1
  - provider: local
YAML
    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{out}, qr/\A\Q${\ found_none(1) }\ECluster: prod\nNodes to destroy:\n  - prod-cp-2 \(local, -\)\n\n/,
        'the hetzner one said, the local one alone listed, numbered as before';
    unlike $r->{out}, qr/^Deleting prod-cp-1/m, 'no Deleting line for the hetzner one';
    is_deeply deleted($r), [ 'local 127.0.0.1' ], 'the local one uninstalled';
    like $r->{out}, qr/\nCluster destroyed\.\n\z/, 'ends on Cluster destroyed.';
};

subtest 'the k98 report still runs when the fallback lists nothing' => sub {
    # Before k345 the delete line that deleted nothing took the run down the
    # main path, which ends on the k98 report. With nothing listed the run
    # ends on "No nodes to destroy." -- which ran no report, and a server
    # mislabelled before k98 went unnamed while it kept billing.
    my $config = project("${HCP}workers:\n  - name: big\n    provider: hetzner\n    nodes: 2\n");
    my $r = run_destroy($config,
        labelled => { 'hetzner-default' => [ { name => 'prod-big-1', id => 333, ipv4 => '3.3.3.3' } ] });
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{err}, qr/^\[!!\] 1 Hetzner server\(s\) carry the label ocp-cluster=hetzner-default and were$/m,
        'the mislabelled server is reported';
    like $r->{err}, qr/^       - prod-big-1 \(id 333, 3\.3\.3\.3\)$/m, 'by name, id and address';
    is_deeply deleted($r), [], 'and, as ever, not deleted';
};

# ------------------------------------------------------- a pool's provider: false

subtest 'a pool with provider: false is skipped in validate()\'s words: provider required' => sub {
    my $config = project(<<'YAML', status => <<'STATUS');
control_planes:
  provider: hetzner
  server_type: cx32
  location: fsn1
workers:
  - name: f
    provider: false
    host: f.lan
  - name: t
    provider: true
    host: t.lan
  - name: v
    provider: vsphere
    host: v.lan
YAML
nodes:
  - name: police1
    provider: hetzner
    providerId: "111"
    public_ip: 1.1.1.1
STATUS
    my @lines = grep { /^worker pool '[ftv]': (?:provider required|invalid provider )/ } $config->validate;
    is_deeply \@lines, [
        "worker pool 'f': provider required",
        "worker pool 't': invalid provider true (must be hetzner, ssh, or local)",
        "worker pool 'v': invalid provider 'vsphere' (must be hetzner, ssh, or local)",
    ], 'the fixture: validate()\'s provider line for each pool';
    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is_deeply [ $r->{err} =~ /^\[!!\] (.*) -- skipped: a machine it names is NOT torn down\.$/mg ],
        \@lines, 'destroy says each in the same words';
    is_deeply deleted($r), [ 'hetzner 111' ], 'no pool host touched';
};

subtest 'a control plane with provider: false: validate() says invalid, and so does destroy' => sub {
    # validate() reads a control plane's provider as hetzner only when it is
    # absent, so false is an invalid provider there, not a missing one.
    my $config = project("control_planes:\n  provider: false\n  host: cp.lan\n");
    my @lines = grep { /^control_planes\[1\]: (?:provider required|invalid provider )/ } $config->validate;
    is_deeply \@lines, [ "control_planes[1]: invalid provider false (must be hetzner, ssh, or local)" ],
        'the fixture: validate()\'s line';
    my $r = run_destroy($config);
    is_deeply [ $r->{err} =~ /^\[!!\] (.*) -- skipped: that control plane is NOT torn down\.$/mg ],
        \@lines, 'destroy says the same';
};

done_testing;

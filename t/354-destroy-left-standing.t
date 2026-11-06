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
# k354: what `ocp destroy` leaves standing on purpose, and how the run ends
# then (the maintainer's decision of 2026-11-06, after k345 point 1):
#
#   * with the cluster API down and a worker pool with provider: local in
#     ocp.yaml, the pool's worker is found by its OCPNode only, and nothing
#     is uninstalled on suspicion (k341). It went unsaid; one STDERR line now
#     says that it is NOT torn down, and the uninstall script to run by hand,
#     picked by the cluster's distribution;
#   * every line that says something is NOT torn down -- a pool or control
#     plane skipped (k341, k353), a hetzner control plane no label search
#     answered for (k345), a label search that failed (k353), an OCPNode of
#     an unknown provider, the k98 report's "NOT deleted" servers, the local
#     pool's line -- ends the run on exit 1, after a closing line, instead of
#     exit 0 and "Cluster destroyed.". What the cleanup removes is unchanged:
#     only a failed provider delete keeps the state (k140), --keep_status
#     keeps status.yaml and deployed.yaml.
#
# Nothing here runs an uninstall: every provider is a fake that records.
#

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# One log for every fake: the secrets read, the label searches, the cluster
# API, the robocop scale-down and the deletes.
my @events;

# Servers by ocp-cluster label; the error a search under a token dies with;
# the provider ids whose delete fails.
my %labelled;
my %search_dies;
my %delete_dies;

{
    package FakeServer;
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub name { $_[0]{name} }
    sub id   { $_[0]{id} }
    sub ipv4 { $_[0]{ipv4} }
}

{
    package FakeProvider;
    sub new   { my ($c, %a) = @_; bless {%a}, $c }
    sub token { $_[0]{token} }
    sub list_servers_by_cluster {
        my ($self, $label) = @_;
        push @events, [ search => "$label", $self->token ];
        my $dies = $search_dies{ $self->token // '' };
        die $dies if defined $dies;
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
        my $what = "" . ($id // $opts{host});
        die "delete of $what failed\n" if defined $id && $delete_dies{$id};
        push @events, [ delete => $self->{type}, $what ];
        return { stdout => '', stderr => '', exit => 0 };
    }
}

{
    package FakeList;
    sub new   { my ($c, @i) = @_; bless { items => [@i] }, $c }
    sub items { $_[0]{items} }
}
{
    # The cluster API: the OCPNodes and OCPNodeProviders it is given -- or
    # not answering.
    package FakeK8s;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list {
        my ($self, $kind) = @_;
        push @events, [ 'api list', $kind ];
        die "connection refused\n" if $self->{down};
        return FakeList->new(@{ $self->{$kind} // [] });
    }
    sub patch { my ($self, $kind, $name) = @_; push @events, [ patch => $kind, $name ]; 1 }
}

my $HCP = "control_planes:\n  provider: hetzner\n  server_type: cx32\n  location: fsn1\n";

# The case of the card: a local pool beside a control plane elsewhere.
my $LOCAL_POOL = "workers:\n  - name: edge\n    provider: local\n";

# police1, a hetzner control plane status.yaml records.
my $POLICE1 = "nodes:\n  - name: police1\n    provider: hetzner\n    providerId: \"111\"\n"
            . "    public_ip: 1.1.1.1\n";

sub project {
    my ($yaml, %a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: prod\n$yaml");
    $dir->child('.ocp', 'status.yaml')->spew_utf8($a{status} // "nodes: []\n");
    $dir->child('.ocp', 'deployed.yaml')->spew_utf8("registry: abc\n");
    $dir->child('kubeconfig.yaml')->spew_utf8("sops: encrypted\n")
        unless $a{no_kubeconfig};
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub run_destroy {
    my ($config, %a) = @_;
    @events      = ();
    %labelled    = %{ $a{labelled}    // {} };
    %search_dies = %{ $a{search_dies} // {} };
    %delete_dies = %{ $a{delete_dies} // {} };
    my $token    = exists $a{token} ? $a{token} : 'tok';
    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        ($a{no_api} ? () : (k8s => FakeK8s->new(
            down            => $a{api_down},
            OCPNode         => $a{ocpnodes} // [],
            OCPNodeProvider => $a{crs}      // [],
        ))),
        force         => 1,
        ($a{keep_status} ? (keep_status => 1) : ()),
    );
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my @ret = do {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        local $ENV{SOPS_AGE_KEY_FILE};
        no warnings 'redefine';
        local *OCP::Provider::for_spec = sub {
            my ($class, $spec) = @_;
            return FakeProvider->new(type => $spec->{provider}, token => $token);
        };
        local *OCP::Provider::from_cr = sub {
            my ($class, $cr) = @_;
            return FakeProvider->new(type => 'hetzner', token => "tok-$cr->{metadata}{name}");
        };
        local *OCP::Secrets::hetzner_token = sub { push @events, [ 'secrets read' ]; $token };
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { die "no ssh key in this test\n" };
        eval { $cmd->execute([], []) };
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0], events => [@events] };
}

sub deleted  { [ sort map { "$_->[1] $_->[2]" } grep { $_->[0] eq 'delete' } @{ $_[0]{events} } ] }

# Every uninstall the run reached for, whatever host: none may be on a guess.
sub uninstalls { [ grep { $_->[0] eq 'delete' && $_->[1] ne 'hetzner' } @{ $_[0]{events} } ] }

sub state_files {
    my ($config) = @_;
    return ($config->status_file, $config->deployed_file,
            $config->project_dir->child('kubeconfig.yaml')->stringify);
}

my $API_DOWN = "[!!] Could not read the OCPNodes from the cluster API:\n"
             . "     connection refused\n"
             . "     Workers come from .ocp/status.yaml, Hetzner labels and the\n"
             . "     hosts of ocp.yaml's ssh pools only; a worker only its OCPNode\n"
             . "     records -- a local pool's, or one added with `ocp node add` --\n"
             . "     may be missed and keep running.\n";

# The line for a local pool's worker, with the script it names.
sub local_line {
    my ($script, $where) = @_;
    $where //= "worker pool 'edge'";
    return "[!!] $where: a local pool's worker is found by its OCPNode only, which could not be read"
         . " -- skipped: its worker, this machine, is NOT torn down;"
         . " to tear it down by hand, run $script here.\n";
}
my $RKE2 = '/usr/local/bin/rke2-uninstall.sh';
my $K3S  = '/usr/local/bin/k3s-agent-uninstall.sh';

# The run's last word when something is left standing.
my $CLOSING = "\n[!!] Teardown INCOMPLETE: the lines above that say NOT torn down\n"
            . "     (or NOT deleted) name what is left standing.\n";

my $POLICE1_OUT = "Cluster: prod\nNodes to destroy:\n  - police1 (hetzner, 1.1.1.1)\n\n"
                . "Deleting police1...\n";
my $CLEANUP = "Removed status.yaml.\nRemoved deployed.yaml.\nEncrypted kubeconfig removed.\n";
my $NO_NODES = "No nodes to destroy.\n$CLEANUP";

# ======================================================= a local pool, the API down

subtest 'the API down, a local pool: said NOT torn down, with the script; nothing uninstalled; exit 1' => sub {
    # The card's case: the control plane elsewhere (police1 at Hetzner), the
    # local pool's worker on this machine. Before k354 not a word said it,
    # and the run ended "Cluster destroyed.", exit 0.
    my $config = project("$HCP$LOCAL_POOL", status => $POLICE1);
    my $r = run_destroy($config, api_down => 1);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{err}, $API_DOWN . local_line($RKE2) . $CLOSING,
        'STDERR: the API down, the pool\'s line with the RKE2 script, the closing line';
    is $r->{out}, $POLICE1_OUT . $CLEANUP, 'STDOUT: the teardown, and no "Cluster destroyed."';
    is_deeply deleted($r), [ 'hetzner 111' ], 'police1 deleted';
    is_deeply uninstalls($r), [], 'nothing uninstalled on suspicion: no uninstall on 127.0.0.1';
    is $r->{ret}, 1, 'exit 1';
    ok !-f $_, path($_)->basename . ' removed, as before' for state_files($config);
};

subtest 'nothing recorded at all: the same line, still nothing uninstalled' => sub {
    # No node on the list: the control-plane fallback runs, and finds a
    # hetzner one by label or not at all. The local pool is not read as a
    # machine to uninstall.
    my $config = project("$HCP$LOCAL_POOL");
    my $r = run_destroy($config, api_down => 1);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{err}, qr/^\Q${\ local_line($RKE2) }\E/m, 'the local pool\'s line';
    is_deeply uninstalls($r), [], 'nothing uninstalled on suspicion';
    is_deeply deleted($r), [], 'nothing deleted';
    like $r->{out}, qr/^\Q$NO_NODES\E\z/m, 'No nodes to destroy., and the cleanup';
    is $r->{ret}, 1, 'exit 1';
};

subtest 'the script by distribution: K3s names its agent\'s; a kubernetes: unread names both' => sub {
    my $config = project("$HCP${LOCAL_POOL}kubernetes:\n  dist: k3s\n", status => $POLICE1);
    my $r = run_destroy($config, api_down => 1);
    is $r->{ex}, '', 'k3s -- ran without dying' or diag $r->{ex};
    like $r->{err}, qr/^\Q${\ local_line($K3S) }\E/m, 'k3s -- k3s-agent-uninstall.sh';
    unlike $r->{err}, qr/rke2-uninstall/, 'k3s -- not the RKE2 script';

    $config = project("$HCP${LOCAL_POOL}kubernetes:\n  dist: rke2\n", status => $POLICE1);
    $r = run_destroy($config, api_down => 1);
    like $r->{err}, qr/^\Q${\ local_line($RKE2) }\E/m, 'rke2 -- rke2-uninstall.sh';

    # kubernetes: k3s is refused by validate(), and destroy does not read it
    # otherwise: no stop, and both scripts, each with its distribution.
    $config = project("$HCP${LOCAL_POOL}kubernetes: k3s\n", status => $POLICE1);
    ok !eval { $config->distribution; 1 }, 'the fixture: the distribution cannot be read';
    $r = run_destroy($config, api_down => 1);
    is $r->{ex}, '', 'unread -- ran without dying' or diag $r->{ex};
    like $r->{err}, qr/^\Q${\ local_line("$RKE2 (RKE2) or $K3S (K3s)") }\E/m, 'unread -- both scripts';
    is_deeply deleted($r), [ 'hetzner 111' ], 'unread -- the teardown went on';
    is $r->{ret}, 1, 'unread -- exit 1';
};

subtest 'two local pools, one with nodes: 0: one line, for the pool that has a worker' => sub {
    my $config = project("${HCP}workers:\n  - name: edge\n    provider: local\n"
                       . "  - name: idle\n    provider: local\n    nodes: 0\n"
                       . "  - provider: local\n    nodes: 2\n", status => $POLICE1);
    my $r = run_destroy($config, api_down => 1);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is_deeply [ $r->{err} =~ /^\[!!\] (.*?): a local pool's worker/mg ], [ "worker pool 'edge'", 'workers[3]' ],
        'edge and the unnamed pool of two said; idle (nodes: 0, no OCPNode) not';
    is $r->{ret}, 1, 'exit 1';
};

# ======================================================= where the local pool is not said

subtest 'not said where the worker is torn down, or nothing says it runs' => sub {
    # The API answers: the worker is found by its OCPNode and uninstalled
    # (t/77). Clean: exit 0, "Cluster destroyed.".
    my $edge = { metadata => { name => 'edge-1' },
                 spec => { role => 'worker', providerRef => 'local-default' }, status => {} };
    my $config = project("$HCP$LOCAL_POOL", status => $POLICE1);
    my $r = run_destroy($config, ocpnodes => [ $edge ]);
    is $r->{ex}, '', 'API up -- ran without dying' or diag $r->{ex};
    is $r->{err}, '', 'API up -- nothing on STDERR';
    is_deeply deleted($r), [ 'hetzner 111', 'local 127.0.0.1' ], 'API up -- the worker uninstalled by its OCPNode';
    like $r->{out}, qr/\nCluster destroyed\.\n\z/, 'API up -- Cluster destroyed.';
    is $r->{ret}, 0, 'API up -- exit 0';

    # A local control plane on the list: its uninstall on 127.0.0.1 runs
    # every RKE2/K3s uninstall script on this machine, the worker's too.
    $config = project("control_planes:\n  provider: local\n$LOCAL_POOL",
                      status => "nodes:\n  - name: police1\n    provider: local\n    public_ip: 10.0.0.5\n");
    $r = run_destroy($config, api_down => 1);
    is $r->{err}, $API_DOWN, 'local CP -- the API down said, no local pool line';
    is_deeply deleted($r), [ 'local 127.0.0.1' ], 'local CP -- this machine uninstalled, once';
    is $r->{ret}, 0, 'local CP -- exit 0';

    # No kubeconfig.yaml: no cluster API was there to read OCPNodes from --
    # the shape a project takes after a teardown, which removes it.
    $config = project("$HCP$LOCAL_POOL", status => $POLICE1, no_kubeconfig => 1);
    $r = run_destroy($config, no_api => 1);
    is $r->{ex}, '', 'no kubeconfig -- ran without dying' or diag $r->{ex};
    is $r->{err}, '', 'no kubeconfig -- nothing on STDERR';
    is $r->{ret}, 0, 'no kubeconfig -- exit 0';
};

# ======================================================= every NOT torn down line: exit 1

# Each case: the fixture, how it is run, and the line it is said with.
my @CASES = (
    [ 'a pool of an unknown provider, beside a recorded control plane',
      [ "${HCP}workers:\n  - name: odd\n    provider: vmware\n", status => $POLICE1 ], [],
      qr/^\[!!\] worker pool 'odd': invalid provider 'vmware' .* -- skipped: a machine it names is NOT torn down\.$/m ],
    [ 'a control plane of an unknown provider, in the fallback',
      [ "control_planes:\n  provider: vmware\n  host: cp.lan\n" ], [],
      qr/^\[!!\] control_planes\[1\]: invalid provider 'vmware' .* -- skipped: that control plane is NOT torn down\.$/m ],
    [ 'an ssh control plane with no host, in the fallback',
      [ "control_planes:\n  provider: ssh\n" ], [],
      qr/^\[!!\] control_planes\[1\]: host required for ssh -- skipped: that control plane is NOT torn down\.$/m ],
    [ 'a hetzner control plane no Hetzner token searched for',
      [ $HCP ], [ token => undef ],
      qr/^\[!!\] control_planes\[1\]: .* and no Hetzner token searched for it -- if it runs, it is NOT torn down\.$/m ],
    [ 'a hetzner control plane whose label search failed',
      [ $HCP ], [ search_dies => { tok => "unable to authenticate\n" } ],
      qr/^\[!!\] control_planes\[1\]: .* and the label search failed: unable to authenticate -- if it runs, it is NOT torn down\.$/m ],
    [ 'a label search that failed while status.yaml found nodes',
      [ $HCP, status => $POLICE1 ], [ search_dies => { tok => "unable to authenticate\n" } ],
      qr/^\[!!\] The label search for ocp-cluster=prod failed: unable to authenticate -- a server only it would find is NOT torn down\.$/m ],
    [ 'an OCPNode of a provider unknown here',
      [ $HCP, status => $POLICE1 ],
      [ ocpnodes => [ { metadata => { name => 'odd-1' },
                        spec => { role => 'worker', providerRef => 'vmware-default' }, status => {} } ] ],
      qr/^\[!!\] OCPNode odd-1: provider 'vmware-default' is unknown here; it is NOT torn down\.$/m ],
    [ 'servers under the old label, which the k98 report names and does not delete',
      [ "${HCP}workers:\n  - name: cloud\n    provider: hetzner\n    nodes: 2\n", status => $POLICE1 ],
      [ labelled => { 'hetzner-default' => [ { name => 'cloud-1', id => 999, ipv4 => '5.5.5.5' } ] } ],
      qr/^     NOT deleted\. They are this cluster's/m ],
    [ 'a local pool with the API down',
      [ "$HCP$LOCAL_POOL", status => $POLICE1 ], [ api_down => 1 ],
      qr/^\Q${\ local_line($RKE2) }\E/m ],
);

for my $case (@CASES) {
    my ($name, $fixture, $run, $line) = @$case;
    subtest "$name: exit 1, the closing line, the cleanup as before" => sub {
        my $config = project(@$fixture);
        my $r = run_destroy($config, @$run);
        is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
        like $r->{err}, $line, 'the line, on STDERR';
        is $r->{ret}, 1, 'exit 1';
        is scalar(() = $r->{err} =~ /Teardown INCOMPLETE/g), 1, 'one closing line';
        like $r->{err}, qr/\Q$CLOSING\E\z/, 'and it is the last thing said';
        unlike $r->{out}, qr/Cluster destroyed/, 'no "Cluster destroyed."';
        like $r->{out}, qr/\Q$CLEANUP\E\z/, 'STDOUT ends on the cleanup';
        ok !-f $_, path($_)->basename . ' removed' for state_files($config);
        is_deeply uninstalls($r), [], 'nothing uninstalled';
    };
}

subtest 'the controls: a run that leaves nothing standing exits 0' => sub {
    # The label search answered for the hetzner control plane: found by its
    # label or not at all, and nothing carries it -- said on STDOUT (k345).
    my $config = project($HCP);
    my $r = run_destroy($config);
    is $r->{err}, '', 'answered search -- nothing on STDERR';
    is $r->{ret}, 0, 'answered search -- exit 0';

    $config = project($HCP, status => $POLICE1);
    $r = run_destroy($config);
    is $r->{err}, '', 'clean -- nothing on STDERR';
    is $r->{out}, "Cluster: prod\nNodes to destroy:\n  - police1 (hetzner, 1.1.1.1)\n\nrobocop stopped.\n"
          . "Deleting police1...\n$CLEANUP\nCluster destroyed.\n", 'clean -- Cluster destroyed.';
    is $r->{ret}, 0, 'clean -- exit 0';
};

# ======================================================= the local state

subtest '--keep_status: status.yaml and deployed.yaml kept, exit 1 all the same' => sub {
    my $config = project("$HCP$LOCAL_POOL", status => $POLICE1);
    my $r = run_destroy($config, api_down => 1, keep_status => 1);
    is $r->{ret}, 1, 'exit 1';
    ok -f $config->status_file,   'status.yaml kept';
    ok -f $config->deployed_file, 'deployed.yaml kept';
    ok !-f $config->project_dir->child('kubeconfig.yaml'), 'the kubeconfig removed, as always';
    is $r->{out}, "${POLICE1_OUT}Encrypted kubeconfig removed.\n", 'only the kubeconfig named';
    like $r->{err}, qr/\Q$CLOSING\E\z/, 'the closing line';

    # Nothing to remove on the no-nodes path: nothing asked, exit 1.
    $config = project("control_planes:\n  provider: vmware\n", no_kubeconfig => 1);
    $r = run_destroy($config, keep_status => 1, no_api => 1);
    is $r->{ex}, '', 'nothing to remove -- ran without dying' or diag $r->{ex};
    is $r->{out}, "No nodes to destroy.\n", 'nothing to remove -- nothing removed';
    like $r->{err}, qr/\Q$CLOSING\E\z/, 'nothing to remove -- the closing line';
    is $r->{ret}, 1, 'nothing to remove -- exit 1';
};

subtest 'beside a failed provider delete: the state kept, as before' => sub {
    my $config = project("${HCP}workers:\n  - name: odd\n    provider: vmware\n", status => $POLICE1);
    my $r = run_destroy($config, delete_dies => { 111 => 1 });
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 1, 'exit 1';
    ok -f $_, path($_)->basename . ' kept' for state_files($config);
    like $r->{err}, qr/Teardown INCOMPLETE: 1 node\(s\) could not be deleted/, 'the failed delete named';
    like $r->{err}, qr/\Q$CLOSING\E\z/, 'and what was left standing, last';
};

# ======================================================= the exit code reaches the shell

subtest 'through run_cli: no age key to open kubeconfig.yaml, a local pool -- exit 1' => sub {
    # The API down as a checkout without the age key leaves it: no cluster
    # API double here, the run as `ocp destroy --force` makes it.
    my $config = project("$HCP$LOCAL_POOL", status => $POLICE1);
    my ($out, $err, $code) = ('', '');
    @events = ();
    %labelled = %search_dies = %delete_dies = ();
    {
        local @ARGV = ('-c', $config->file, 'destroy', '--force');
        local $ENV{HETZNER_API_TOKEN};
        local $ENV{SOPS_AGE_KEY_FILE};
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        local *STDERR;
        open STDERR, '>', \$err or die;
        no warnings 'redefine';
        local *OCP::Secrets::hetzner_token = sub { 'tok' };
        local *OCP::Provider::for_spec = sub {
            my ($class, $spec) = @_;
            return FakeProvider->new(type => $spec->{provider}, token => 'tok');
        };
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { die "no ssh key in this test\n" };
        $code = OCP->run_cli;
    }
    is $code, 1, 'exit 1';
    like $err, qr/^\Q${\ local_line($RKE2) }\E/m, 'the local pool\'s line';
    like $err, qr/\Q$CLOSING\E\z/, 'the closing line';
    is_deeply deleted({ events => \@events }), [ 'hetzner 111' ], 'police1 deleted, nothing uninstalled';
};

done_testing;

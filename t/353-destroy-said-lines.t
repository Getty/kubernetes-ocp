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
# k353: what `ocp destroy` still left unsaid, or said wrong, after k345 and
# k340. Destroy checks only what it reads, in validate()'s words (k323);
# what it skips or cannot reach goes to STDERR with its diagnosis, and STDOUT
# stays the progress report:
#
#   * an ssh control plane with no host was listed in the control-plane
#     fallback, "Deleting prod-cp-1...", and then skipped without a word: an
#     ssh machine is reached at its host and nowhere else. It is said now, in
#     validate()'s line for it, as k341 says a control plane whose provider
#     destroy does not know -- and, like that one, not listed;
#   * provider: '' on a control plane or a worker pool was skipped without a
#     word, while validate() names it;
#   * a Hetzner label search that failed while some other source found nodes
#     -- so the fallback, which says a failed search since k345, did not run
#     -- said nothing: a server only that search would have found kept
#     running. It is said now, with the cause and the hcloud selector;
#   * the warning for a cluster API that does not answer named ocp.yaml as a
#     source of the workers. A local pool's worker is found by its OCPNode
#     alone, never in ocp.yaml;
#   * the fallback read a local control plane's public_ip without the shape
#     check validate() makes since k340: a list became its address,
#     ARRAY(0x...);
#   * the key for the ssh nodes, when it could not be had, was named with
#     the croak location of the refusal: "... at .../Config.pm line N.".
#
# Since k354 every "NOT torn down" line ends the run on exit 1, after a
# closing line, and not on "Cluster destroyed." (t/354 for each of them).
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

# Servers by ocp-cluster label, as the label search finds them; and by
# token, the error a label search under that token dies with.
my %labelled;
my %search_dies;

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
    sub new   { my ($c, @i) = @_; bless { items => [@i] }, $c }
    sub items { $_[0]{items} }
}
{
    # The cluster API: the OCPNodeProviders it is given and no OCPNodes --
    # or not answering.
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

# police1, a hetzner control plane status.yaml records.
my $POLICE1 = "nodes:\n  - name: police1\n    provider: hetzner\n    providerId: \"111\"\n"
            . "    public_ip: 1.1.1.1\n";

# Nothing recorded unless status is given: then the control-plane fallback
# is the source left.
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
    %labelled    = %{ $a{labelled}    // {} };
    %search_dies = %{ $a{search_dies} // {} };
    my $token    = exists $a{token} ? $a{token} : 'tok';
    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        k8s           => FakeK8s->new(down => $a{api_down}, OCPNodeProvider => $a{crs} // []),
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
            return FakeProvider->new(type => $spec->{provider}, token => $token);
        };
        # An OCPNodeProvider's adapter, with a token of its own.
        local *OCP::Provider::from_cr = sub {
            my ($class, $cr) = @_;
            return FakeProvider->new(type => 'hetzner', token => "tok-$cr->{metadata}{name}");
        };
        local *OCP::Secrets::hetzner_token = sub { push @events, [ 'secrets read' ]; $token };
        # The real lookup where a test asks for it: the refusal it dies with is
        # the point there.
        local *OCP::Cmd::Destroy::cluster_ssh_key = $a{real_key}
            ? \&OCP::Cmd::Destroy::cluster_ssh_key
            : sub { push @events, [ 'ssh key' ]; FakeKey->new };
        eval { $cmd->execute([], []) };
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0], events => [@events] };
}

sub deleted  { [ sort map { "$_->[1] $_->[2]" } grep { $_->[0] eq 'delete' } @{ $_[0]{events} } ] }
sub searched { [ map { "$_->[1] $_->[2]" } grep { $_->[0] eq 'search' } @{ $_[0]{events} } ] }

my $NO_NODES = "No nodes to destroy.\nRemoved status.yaml.\nRemoved deployed.yaml.\n"
             . "Encrypted kubeconfig removed.\n";

# validate()'s lines matching $re, which destroy's STDERR line starts with.
sub validate_lines {
    my ($config, $re) = @_;
    return grep { /$re/ } $config->validate;
}

# The line a control plane or pool destroy skips is said with (k341).
sub skipped {
    my ($line, $left) = @_;
    return "[!!] $line -- skipped: $left NOT torn down.\n";
}

# The run's last word when a line said something is NOT torn down (k354).
my $CLOSING = "\n[!!] Teardown INCOMPLETE: the lines above that say NOT torn down\n"
            . "     (or NOT deleted) name what is left standing.\n";

# A label search that failed, as Hetzner fails it: croaked, with a location.
my $CROAKED = "Hetzner API error: unable to authenticate at /src/lib/OCP/Provider/Hetzner.pm line 421.\n";
my $WHY     = 'Hetzner API error: unable to authenticate';

# The lines for the old-label search (k98) under a token that fails: since
# k396 said, where it was taken for one that found nothing. A token that
# fails the cluster's own search fails this one too (t/396).
my $OLD_FAILED = "\n[!!] The search under the old label ocp-cluster=hetzner-default failed: $WHY"
               . " -- a server of this cluster still labelled so is NOT deleted, and not named here.\n"
               . "     Look by hand:\n"
               . "       hcloud server list -l ocp-cluster=hetzner-default\n";

# The lines for a label search that failed where nothing else says it.
sub search_failed {
    my ($with) = @_;
    return "[!!] The label search for ocp-cluster=prod"
         . (defined $with ? " with OCPNodeProvider/$with\'s token" : '')
         . " failed: $WHY -- a server only it would find is NOT torn down.\n"
         . "     Fix the cause and run `ocp destroy` again, or look by hand:\n"
         . "       hcloud server list -l ocp-cluster=prod\n";
}

# ======================================================= an ssh control plane with no host

subtest 'an ssh control plane with no host: validate()\'s line on STDERR, not listed' => sub {
    # The card's case. Before k353: "Nodes to destroy: prod-cp-1 (ssh, -)",
    # "Deleting prod-cp-1...", nothing uninstalled, "Cluster destroyed.",
    # and not a word that the control plane, if it runs, keeps its install.
    for my $host (undef, '0', "''") {
        my $shown  = defined $host ? "host: $host" : 'no host';
        my $config = project("control_planes:\n  provider: ssh\n"
                           . (defined $host ? "  host: $host\n" : ''));
        my @lines = validate_lines($config, qr/host required/);
        is_deeply \@lines, [ 'control_planes[1]: host required for ssh' ],
            "$shown -- the fixture: validate()'s line";

        my $r = run_destroy($config);
        is $r->{ex}, '', "$shown -- ran without dying" or diag $r->{ex};
        is $r->{err}, skipped($lines[0], 'that control plane is') . $CLOSING,
            "$shown -- on STDERR: validate()'s line, and that it is NOT torn down";
        is $r->{out}, $NO_NODES, "$shown -- not listed: No nodes to destroy., no Deleting line";
        is_deeply deleted($r), [], "$shown -- nothing uninstalled";
        ok !(grep { $_->[0] eq 'ssh key' } @{ $r->{events} }), "$shown -- no PIN2 asked";
        is $r->{ret}, 1, "$shown -- exit 1: that control plane is NOT torn down (k354)";
    }
};

subtest 'nodes: N said once; beside it a local control plane is still torn down' => sub {
    my $shared = project("control_planes:\n  provider: ssh\n  nodes: 3\n");
    my $r = run_destroy($shared);
    is $r->{err}, skipped('control_planes[1]: host required for ssh', 'that control plane is') . $CLOSING,
        'nodes: 3 -- said once, as validate() says it once';

    my $list = project("control_planes:\n  - provider: ssh\n  - provider: local\n");
    is_deeply [ validate_lines($list, qr/host required/) ],
        [ 'control_planes[1]: host required for ssh' ], 'the fixture: validate()\'s line';
    $r = run_destroy($list);
    is $r->{err}, skipped('control_planes[1]: host required for ssh', 'that control plane is') . $CLOSING,
        'the ssh one said';
    like $r->{out}, qr/^Nodes to destroy:\n  - prod-cp-2 \(local, -\)\n\n/m,
        'the local one alone listed, numbered as before';
    is_deeply deleted($r), [ 'local 127.0.0.1' ], 'and uninstalled';
    like $r->{out}, qr/\nEncrypted kubeconfig removed\.\n\z/,
        'ends on the cleanup, not on Cluster destroyed.: the ssh one is NOT torn down (k354)';
};

subtest 'the control: an ssh control plane with a host is listed and uninstalled there' => sub {
    my $config = project("control_planes:\n  provider: ssh\n  host: cp1.lan\n");
    my $r = run_destroy($config);
    is $r->{err}, '', 'nothing on STDERR';
    is_deeply deleted($r), [ 'ssh cp1.lan' ], 'uninstalled on its host';
};

# ======================================================= provider: ''

subtest 'a control plane with provider: \'\' is said in validate()\'s words' => sub {
    my $config = project("control_planes:\n  provider: ''\n  host: cp.lan\n");
    my @lines = validate_lines($config, qr/invalid provider|provider required/);
    is_deeply \@lines, [ "control_planes[1]: invalid provider '' (must be hetzner, ssh, or local)" ],
        'the fixture: validate()\'s line';
    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{err}, skipped($lines[0], 'that control plane is') . $CLOSING, 'destroy says the same, on STDERR';
    is $r->{out}, $NO_NODES, 'nothing listed';
    is_deeply deleted($r), [], 'nothing uninstalled';
};

subtest 'a pool with provider: \'\' is said as "provider required"; one with none is not' => sub {
    my $config = project(<<"YAML", status => $POLICE1);
${HCP}workers:
  - name: e
    provider: ''
    host: e.lan
  - name: none
    host: n.lan
YAML
    my @lines = validate_lines($config, qr/provider required/);
    is_deeply \@lines, [ "worker pool 'e': provider required", "worker pool 'none': provider required" ],
        'the fixture: validate() has the same line for both';
    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{err}, skipped($lines[0], 'a machine it names is') . $CLOSING,
        'on STDERR: the pool set to \'\' -- not the one with none, which apply reads as hetzner (k341)';
    is_deeply deleted($r), [ 'hetzner 111' ], 'no pool host touched';
    like $r->{out}, qr/\nEncrypted kubeconfig removed\.\n\z/,
        'ends on the cleanup, not on Cluster destroyed. (k354)';
};

# ======================================================= a failed label search

subtest 'a label search that fails while status.yaml found nodes: said on STDERR' => sub {
    # Some source found nodes, so the control-plane fallback -- which says a
    # failed search since k345 -- does not run. A server only the search
    # would have found went unnamed.
    my $config = project($HCP, status => $POLICE1);
    my $r = run_destroy($config, search_dies => { tok => $CROAKED });
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is_deeply searched($r), [ 'prod tok', 'hetzner-default tok' ],
        'the fixture: the label search ran under the local token, and died';
    is $r->{err}, search_failed() . $OLD_FAILED . $CLOSING,
        'on STDERR: the cause without its croak location, what it leaves, the selector'
      . ' -- and the old-label search under the same token, failed too (k396)';
    unlike $r->{out}, qr/label search|hcloud/, 'nothing of it on STDOUT';
    is_deeply deleted($r), [ 'hetzner 111' ], 'police1 still deleted';
    like $r->{out}, qr/\nEncrypted kubeconfig removed\.\n\z/,
        'ends on the cleanup, not on Cluster destroyed. (k354)';
    is $r->{ret}, 1, 'exit 1: a server only that search would find is NOT torn down (k354)';
};

subtest 'the fallback ran, with no hetzner control plane to say it: said' => sub {
    my $config = project("control_planes:\n  provider: ssh\n  host: cp1.lan\n");
    my $r = run_destroy($config, search_dies => { tok => $CROAKED });
    is $r->{err}, search_failed() . $CLOSING, 'on STDERR';
    is_deeply deleted($r), [ 'ssh cp1.lan' ], 'the control plane still uninstalled';
};

subtest 'the fallback says it for a hetzner control plane: once, without the croak location' => sub {
    my $config = project($HCP);
    my $r = run_destroy($config, search_dies => { tok => $CROAKED });
    is $r->{err},
        "[!!] control_planes[1]: a hetzner control plane is found by its ocp-cluster=prod label "
      . "or not at all, and the label search failed: $WHY -- if it runs, it is NOT torn down.\n"
      . "     Fix the cause and run `ocp destroy` again, or look by hand:\n"
      . "       hcloud server list -l ocp-cluster=prod\n" . $OLD_FAILED . $CLOSING,
        'the k345 line once, the cause as one line -- then the old-label search, failed too (k396)';
    is $r->{out}, $NO_NODES, 'STDOUT: No nodes to destroy.';
};

subtest 'a search under an OCPNodeProvider\'s token fails: said, naming that provider' => sub {
    my @crs = ({ metadata => { name => 'hetzner-b' }, spec => { type => 'hetzner' } });

    # The local token's search answers; police1 is recorded.
    my $config = project($HCP, status => $POLICE1);
    my $r = run_destroy($config, crs => \@crs, search_dies => { 'tok-hetzner-b' => $CROAKED });
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is_deeply [ grep { /^prod / } @{ searched($r) } ], [ 'prod tok', 'prod tok-hetzner-b' ],
        'the fixture: searched under both tokens';
    is $r->{err}, search_failed('hetzner-b') . $CLOSING, 'on STDERR, with the provider whose token failed';
    is_deeply deleted($r), [ 'hetzner 111' ], 'police1 still deleted';

    # Nothing recorded: the fallback says the hetzner control plane on STDOUT
    # -- the local token's search answered -- and the failed one is still
    # said: the fallback's line carries a failure only when no search
    # answered. Since k396 that line says what the answering search found,
    # not "no server carries it": hetzner-b's token was never searched
    # (t/396).
    $config = project($HCP);
    $r = run_destroy($config, crs => \@crs, search_dies => { 'tok-hetzner-b' => $CROAKED });
    like $r->{out}, qr/\Acontrol_planes\[1\]: a hetzner control plane is found by its ocp-cluster=prod label or not at all; no label search that answered found a server carrying it\.\n/,
        'the fallback\'s line, on STDOUT';
    is $r->{err}, search_failed('hetzner-b') . $CLOSING, 'and the failed search on STDERR';
};

# ======================================================= the cluster API down

subtest 'the API-down warning: ocp.yaml is the source of ssh pools\' hosts only' => sub {
    my $config = project($HCP, status => $POLICE1);
    my $r = run_destroy($config, api_down => 1);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{err},
        "[!!] Could not read the OCPNodes from the cluster API:\n"
      . "     connection refused\n"
      . "     Workers come from .ocp/status.yaml, Hetzner labels and the\n"
      . "     hosts of ocp.yaml's ssh pools only; a worker only its OCPNode\n"
      . "     records -- a local pool's, or one added with `ocp node add` --\n"
      . "     may be missed and keep running.\n",
        'a local pool\'s worker is named as one only its OCPNode records, not one of ocp.yaml\'s';
    is_deeply deleted($r), [ 'hetzner 111' ], 'the teardown goes on';
};

# ======================================================= a local control plane's public_ip

subtest 'a local control plane with no host: its public_ip is shape-checked, as the fallback reads it' => sub {
    for my $ip ('[ 10.0.0.5 ]', '{ 10.0.0.5: 1 }', 'true') {
        my $config = project("control_planes:\n  provider: local\n  public_ip: $ip\n");
        my @lines = validate_lines($config, qr/^control_planes\[1\]\.public_ip:/);
        is scalar(@lines), 1, "public_ip: $ip -- the fixture: validate() has one line for it"
            or diag explain [ $config->validate ];
        my $r = run_destroy($config);
        my $file = $config->file;
        is $r->{ex},
            "$file has 1 error:\n  - $lines[0]\n"
          . "Nothing was done: ocp destroy checks what it reads of $file before it asks for a "
          . "PIN or touches the cluster or a machine. Fix the line above and run it again.\n",
            "public_ip: $ip -- refused with validate()'s line";
        is_deeply $r->{events}, [], "public_ip: $ip -- nothing read, asked or deleted";
        ok -f $config->status_file, "public_ip: $ip -- status.yaml kept";
    }

    # Checked with a control plane recorded too: whether the fallback runs is
    # known only after the cluster API and the label search.
    my $config = project("control_planes:\n  provider: local\n  public_ip: [ 10.0.0.5 ]\n",
                         status => $POLICE1);
    my $r = run_destroy($config);
    like $r->{ex}, qr/^  - control_planes\[1\]\.public_ip: must be a string \(an IP address\), not a list$/m,
        'refused with police1 recorded as well';
};

subtest 'a public_ip the fallback does not read is not checked' => sub {
    # A local or ssh control plane with a host is listed by its host; a
    # hetzner one is not listed at all (k345); an ssh one with no host is
    # skipped (above).
    for my $yaml ("control_planes:\n  provider: local\n  host: cp.lan\n  public_ip: [ 10.0.0.5 ]\n",
                  "control_planes:\n  provider: ssh\n  host: cp.lan\n  public_ip: [ 10.0.0.5 ]\n",
                  "control_planes:\n  provider: ssh\n  public_ip: [ 10.0.0.5 ]\n",
                  "${HCP}  public_ip: [ 10.0.0.5 ]\n") {
        my $config = project($yaml);
        my $r = run_destroy($config);
        is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
        unlike $r->{out}.$r->{err}, qr/(?:ARRAY|HASH)\(0x|public_ip/, 'no reference shown, nothing said';
    }
    my $plain = project("control_planes:\n  provider: local\n  public_ip: 10.0.0.5\n");
    my $r = run_destroy($plain);
    like $r->{out}, qr/^  - prod-cp-1 \(local, 10\.0\.0\.5\)$/m, 'a string public_ip is read as before';
    is_deeply deleted($r), [ 'local 127.0.0.1' ], 'and the box uninstalled';
};

# ======================================================= the SSH key that cannot be had

subtest 'the SSH key refusal is named without its croak location' => sub {
    # Dev mode (no keys.yaml): the key is the one ssh.private_key names, and
    # ssh_config refuses a list there with a croak.
    my $config = project("control_planes:\n  provider: ssh\n  host: cp1.lan\n"
                       . "ssh:\n  private_key: [ a, b ]\n",
                         status => "nodes:\n  - name: police1\n    provider: ssh\n"
                                 . "    public_ip: cp1.lan\n");
    my @lines = validate_lines($config, qr/^ssh\.private_key:/);
    is scalar(@lines), 1, 'the fixture: validate()\'s line for ssh.private_key'
        or diag explain [ $config->validate ];

    my $r = run_destroy($config, real_key => 1);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{err},
        qr/^\[!!\] Could not obtain the SSH key for the ssh-provider nodes:\n     \Q$lines[0]\E\n     Their RKE2\/K3s uninstall will be SKIPPED\./m,
        'the refusal in validate()\'s words, on one line';
    unlike $r->{err}, qr/ at \S+ line \d+/, 'no croak location';
    is_deeply deleted($r), [], 'nothing uninstalled without the key';
    is $r->{ret}, 1, 'exit 1, as before: the machine keeps its install (k180)';
};

done_testing;

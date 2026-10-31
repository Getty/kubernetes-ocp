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
# k335: three more keys `ocp destroy` reads went through unchecked after
# k323/k326, each a shape validate() refuses since k305/k315, each exit 0
# with no Perl error and nothing saying anything went wrong:
#
#   * `name: [prod]`. The cluster name is the ocp-cluster label the servers
#     are searched by, and a list searched ocp-cluster=ARRAY(0x...): a server
#     labelled prod that status.yaml does not record was missed, and the run
#     still ended "Cluster destroyed." while it kept billing;
#   * a worker pool's own `host: [a, b]` (k323 covered hosts inside nodes:
#     only), which became one machine named ARRAY(0x...) -- for an ssh pool
#     the run asked for PIN2 to uninstall RKE2 there;
#   * a control plane's `host: [a]`, the same machine in the control-plane
#     fallback.
#
# Decided here: the same up-front refusal as k323/k326, in validate()'s
# words, before a PIN is asked or anything is touched -- name first, then
# the control planes, then the pools, in validate()'s order.
#
# Still only what destroy reads, as destroy reads it:
#
#   * name: a list, a mapping or a boolean. A name validate() calls missing
#     ('', 0) is a label like any other and is searched as written: a
#     cluster applied under it before `ocp apply` validated (k255) carries
#     it, and no other name would find its servers;
#   * a pool's host where it is read: a pool whose provider destroy knows,
#     and whose nodes: is no list (beside a list destroy reads the list and
#     not host, as apply does);
#   * a control plane's host where the fallback reads it: an entry whose
#     provider destroy knows. Checked whether or not the fallback runs on
#     this teardown -- that is known only after the secrets, the cluster
#     API and the Hetzner search, and the refusal comes before all three;
#   * not a pool's or a control plane's server_type, location or image,
#     which destroy does not read at all.
#

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# One log for every fake, so "nothing was touched" covers the secrets read,
# the PIN2 key, the label search, the cluster API, the robocop scale-down and
# the deletes alike.
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
    sub list_servers_by_cluster {
        my ($self, $label) = @_;
        push @events, [ search => "$label" ];
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

# A worker server under the prod label that status.yaml does not record:
# only the label search finds it.
my %PROD = (prod => [ { name => 'prod-w9', id => 222, ipv4 => '2.2.2.2' } ]);

sub project {
    my ($yaml, %a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8('name: ' . ($a{name} // 'prod') . "\n$yaml");
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
    my ($config, %a) = @_;
    @events   = ();
    %labelled = %{ $a{labelled} // {} };
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
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { push @events, [ 'ssh key' ]; FakeKey->new };
        eval { $cmd->execute([], []) };
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0],
             events => [@events] };
}

# The fixture says exactly these lines of validate()'s, in this order, among
# whatever else it says.
sub validate_says {
    my ($config, @lines) = @_;
    my %want = map { ($_ => 1) } @lines;
    is_deeply [ grep { $want{$_} } $config->validate ], \@lines,
        'the fixture: validate() says ' . (@lines == 1 ? 'this line' : 'these lines, in this order')
        or diag explain [ $config->validate ];
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
    unlike $r->{ex}, qr/(?:ARRAY|HASH)\(0x|at \S+ line \d+/, 'no Perl error, no reference shown';
    is_deeply $r->{events}, [],
        'no secrets read, no PIN2 key, no label search, no cluster API, no robocop '
        . 'scale-down, no server deleted';
    ok -f $_, path($_)->basename . ' is kept' for state_files($config);
    is $r->{out}, '', 'nothing on STDOUT';
}

# A teardown that ran to the end: deleted, cleaned up, no machine named after
# a reference.
sub torn_down {
    my ($r, $config) = @_;
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    ok scalar(grep { $_->[0] eq 'delete' && $_->[2] eq '111' } @{ $r->{events} }),
        'the control plane is deleted';
    ok !-f $_, path($_)->basename . ' is removed' for state_files($config);
    like $r->{out}, qr/\nCluster destroyed\.\n\z/, 'ends on Cluster destroyed.';
    unlike $r->{out}.$r->{err}, qr/(?:ARRAY|HASH)\(0x/, 'no machine or label named after a reference';
}

sub deleted { [ sort map { "$_->[1] $_->[2]" } grep { $_->[0] eq 'delete' } @{ $_[0]{events} } ] }

# ------------------------------------------------------- refused: name

subtest 'name: [prod] -- the server under the prod label is no longer missed' => sub {
    # The control: as `name: prod`, the label search finds the server
    # status.yaml does not record, and deletes it.
    my $good = project($CP);
    my $r = run_destroy($good, labelled => \%PROD);
    is_deeply deleted($r), [ 'hetzner 111', 'hetzner 222' ],
        'the control: name: prod finds prod-w9 by its label and deletes it';

    # The card's case. Before k335: ocp-cluster=ARRAY(0x...) searched, prod-w9
    # missed, police1 deleted, "Cluster destroyed.", exit 0 -- and prod-w9
    # kept billing.
    my $config = project($CP, name => '[ prod ]');
    my @lines = ("name: must be a string (the cluster's name), not a list");
    validate_says($config, @lines);
    refused(run_destroy($config, labelled => \%PROD), $config, @lines);
};

subtest 'name as a mapping or a boolean' => sub {
    for my $case ([ '{ prod: 1 }', 'a mapping' ], [ 'true', 'true' ], [ 'false', 'false' ]) {
        my ($name, $shown) = @$case;
        my $config = project($CP, name => $name);
        my @lines = ("name: must be a string (the cluster's name), not $shown");
        validate_says($config, @lines);
        refused(run_destroy($config, labelled => \%PROD), $config, @lines);
    }
};

# ------------------------------------------------------- refused: a pool's host

subtest 'an ssh pool with host: [a, b] -- no machine named ARRAY(0x...), no PIN2' => sub {
    # Before k335: "Deleting ARRAY(0x...)", PIN2 asked for its key, and the
    # uninstall sent to a host of that name; a.lan and b.lan kept theirs.
    my $config = project(<<"YAML");
${CP}workers:
  - name: edge
    provider: ssh
    host: [ a.lan, b.lan ]
YAML
    my @lines = ("worker pool 'edge': host must be a string (a host name or IP address), not a list");
    validate_says($config, @lines);
    refused(run_destroy($config), $config, @lines);
};

subtest 'a pool host of the wrong shape, whatever provider destroy knows' => sub {
    # A hetzner pool's host was listed as a machine to destroy -- beside a
    # count too, which is no list destroy reads instead; a local pool's
    # named the local machine after it. A boolean is a reference too: host:
    # false became a machine named 0.
    my $config = project(<<"YAML");
${CP}workers:
  - name: big
    provider: hetzner
    server_type: cx22
    location: fsn1
    nodes: 2
    host: [ h1 ]
  - name: lp
    provider: local
    host: { a: b }
  - provider: ssh
    host: false
YAML
    my @lines = (
        "worker pool 'big': host must be a string (a host name or IP address), not a list",
        "worker pool 'lp': host must be a string (a host name or IP address), not a mapping",
        "workers[3]: host must be a string (a host name or IP address), not false",
    );
    validate_says($config, @lines);
    refused(run_destroy($config), $config, @lines);
};

# ------------------------------------------------------- refused: a control plane's host

subtest 'a control plane with host: [a] -- no machine named ARRAY(0x...)' => sub {
    # Nothing recorded, so the control-plane fallback is the only source:
    # before k335 it listed ARRAY(0x...), asked for PIN2 and sent the
    # uninstall there.
    my $config = project("control_planes:\n  provider: ssh\n  host: [ cp1.lan ]\n",
                         status => "nodes: []\n");
    my @lines = ("control_planes[1].host: must be a string (a host name or IP address), not a list");
    validate_says($config, @lines);
    refused(run_destroy($config), $config, @lines);
};

subtest 'in the list form, by its place; in nodes: N, once' => sub {
    my $list = project(<<'YAML', status => "nodes: []\n");
control_planes:
  - provider: local
  - provider: ssh
    host: { cp2.lan: 1 }
  - provider: hetzner
    server_type: cx32
    location: fsn1
    host: true
YAML
    my @lines = (
        "control_planes[2].host: must be a string (a host name or IP address), not a mapping",
        "control_planes[3].host: must be a string (a host name or IP address), not true",
    );
    validate_says($list, @lines);
    refused(run_destroy($list), $list, @lines);

    my $mapping = project("control_planes:\n  provider: ssh\n  host: [ cp.lan ]\n  nodes: 3\n",
                          status => "nodes: []\n");
    @lines = ("control_planes[1].host: must be a string (a host name or IP address), not a list");
    validate_says($mapping, @lines);
    refused(run_destroy($mapping), $mapping, @lines);
};

subtest 'refused with a control plane recorded too: the fallback may read it' => sub {
    # Whether the fallback runs is known only after the secrets, the cluster
    # API and the label search; the refusal comes before all three.
    my $config = project("control_planes:\n  provider: ssh\n  host: [ cp1.lan ]\n");
    my @lines = ("control_planes[1].host: must be a string (a host name or IP address), not a list");
    validate_says($config, @lines);
    refused(run_destroy($config), $config, @lines);
};

# ------------------------------------------------------- refused: all at once

subtest 'name, control planes and pools at once, in validate()\'s order' => sub {
    my $config = project(<<'YAML', name => '[ prod ]');
control_planes:
  - police1
  - provider: ssh
    host: [ cp2.lan ]
workers:
  - name: edge
    provider: ssh
    host: [ a.lan ]
  - name: e2
    provider: ssh
    nodes: [ true ]
  - false
YAML
    my @lines = (
        "name: must be a string (the cluster's name), not a list",
        "control_planes[1]: must be a mapping (one control plane), not 'police1'",
        "control_planes[2].host: must be a string (a host name or IP address), not a list",
        "worker pool 'edge': host must be a string (a host name or IP address), not a list",
        "worker pool 'e2': nodes[1] must be a host name or IP address, or a mapping with host, not true",
        "workers[3]: must be a mapping (a worker pool), not false",
    );
    validate_says($config, @lines);
    refused(run_destroy($config), $config, @lines);
};

subtest 'through run_cli: the line on STDERR, exit 1, STDOUT empty' => sub {
    my $config = project($CP, name => '[ prod ]');
    my $line = "name: must be a string (the cluster's name), not a list";
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
    unlike $err, qr/ARRAY\(0x|internal error/, 'no reference shown, no "internal error"';
    is $out, '', 'STDOUT empty';
    is_deeply \@events, [], 'nothing asked, nothing built';
    ok -f $_, path($_)->basename . ' is kept' for state_files($config);
};

# ------------------------------------------------------- not refused

subtest 'a name validate() calls missing is searched as written' => sub {
    # validate() says "name is required" for 0 -- but a cluster applied under
    # it before apply validated (k255) carries ocp-cluster=0, and no name
    # destroy could be told instead would find that server.
    my $config = project($CP, name => '0');
    ok scalar(grep { $_ eq 'name is required' } $config->validate),
        'the fixture: validate() refuses it';
    my $r = run_destroy($config, labelled => { 0 => $PROD{prod} });
    torn_down($r, $config);
    is_deeply deleted($r), [ 'hetzner 111', 'hetzner 222' ],
        'the server labelled 0 is found and deleted';
};

subtest 'a pool host destroy does not read' => sub {
    # Beside a nodes: list destroy reads the list, as apply does; a pool whose
    # provider destroy does not know is skipped unread (k116).
    my $config = project(<<"YAML");
${CP}workers:
  - name: edge
    provider: ssh
    host: [ a.lan ]
    nodes: [ b.lan ]
  - name: v
    provider: vsphere
    host: [ c.lan ]
YAML
    validate_says($config,
        "worker pool 'edge': host must be a string (a host name or IP address), not a list",
        "worker pool 'v': host must be a string (a host name or IP address), not a list",
    );
    my $r = run_destroy($config);
    torn_down($r, $config);
    is_deeply deleted($r), [ 'hetzner 111', 'ssh b.lan' ], 'b.lan is uninstalled, nothing else';
};

subtest 'a control-plane host the fallback does not read' => sub {
    # An entry with a provider destroy does not know, or with none: the
    # fallback skips it unread (k116).
    my $config = project(<<'YAML');
control_planes:
  - provider: hetzner
    server_type: cx32
    location: fsn1
  - provider: vsphere
    host: [ v.lan ]
  - host: [ n.lan ]
YAML
    validate_says($config,
        "control_planes[2].host: must be a string (a host name or IP address), not a list",
        "control_planes[3].host: must be a string (a host name or IP address), not a list",
    );
    torn_down(run_destroy($config), $config);
};

subtest 'server_type, location and image, which destroy does not read' => sub {
    my $config = project(<<'YAML');
control_planes:
  provider: hetzner
  server_type: [ cx32 ]
  location: { fsn1: 1 }
  image: true
workers:
  - name: big
    provider: hetzner
    server_type: [ cx22 ]
    location: [ fsn1 ]
    image: [ debian-13 ]
    nodes: 2
YAML
    validate_says($config,
        "control_planes[1].server_type: must be a string (a Hetzner server type like cx32), not a list",
        "control_planes[1].location: must be a string (a Hetzner location like fsn1), not a mapping",
        "control_planes[1].image: must be a string (an image name like debian-13), not true",
        "worker pool 'big': server_type must be a string (a Hetzner server type like cx32), not a list",
        "worker pool 'big': location must be a string (a Hetzner location like fsn1), not a list",
        "worker pool 'big': image must be a string (an image name like debian-13), not a list",
    );
    torn_down(run_destroy($config), $config);
};

subtest 'well-formed names and hosts are read and torn down' => sub {
    my $pool = project(<<"YAML");
${CP}workers:
  - name: edge
    provider: ssh
    host: w1.lan
YAML
    is_deeply [ $pool->validate ], [], 'the fixture: validate() has nothing';
    my $r = run_destroy($pool, labelled => \%PROD);
    torn_down($r, $pool);
    is_deeply deleted($r), [ 'hetzner 111', 'hetzner 222', 'ssh w1.lan' ],
        'the labelled server is found, the pool host uninstalled';

    # The control-plane fallback, the only source here.
    my $cp = project("control_planes:\n  provider: ssh\n  host: cp1.lan\n", status => "nodes: []\n");
    is_deeply [ $cp->validate ], [], 'the fixture: validate() has nothing';
    $r = run_destroy($cp);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{ret}, 0, 'exit 0';
    is_deeply deleted($r), [ 'ssh cp1.lan' ], 'the control plane\'s host is uninstalled';
    like $r->{out}, qr/\nCluster destroyed\.\n\z/, 'ends on Cluster destroyed.';
};

done_testing;

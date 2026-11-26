#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use Path::Tiny qw(path);

use lib "$FindBin::Bin/../lib";

use OCP;
use OCP::Cmd::Destroy;
use OCP::Config;

#
# k432: how `ocp destroy` merges its node sources, and what it says of them.
#
# The claims:
#   1. a node an earlier source knows without a host (public_ip '-', or none)
#      takes the host a later source knows -- an ocp.yaml pool's -- so its
#      uninstall runs there instead of being skipped for want of a host;
#   2. a status.yaml entry without public_ip is listed with '-', not undef;
#   3. with no label search answering and two failed, both failures are
#      said, not only the first;
#   4. the closing list of machines that keep their install does not say to
#      wait until they are reachable: one there may have no host at all.
#
# execute runs in-process with every provider and the cluster API faked, as
# in t/396. Nothing is ever deleted for real.
#

no warnings 'once';

is path($INC{'OCP/Cmd/Destroy.pm'})->realpath->stringify,
   path("$FindBin::Bin/../lib/OCP/Cmd/Destroy.pm")->realpath->stringify,
   'the Destroy.pm under test is this tree\'s';

umask 022;
delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

my @events;
my %search_dies;

{
    package FakeProvider;
    sub new   { my ($c, %a) = @_; bless {%a}, $c }
    sub token { $_[0]{token} }
    sub list_servers_by_cluster {
        my ($self, $label) = @_;
        my $token = $self->token // '';
        push @events, [ search => "$label", $token ];
        my $dies = $search_dies{"$label $token"};
        die $dies if defined $dies;
        return [];
    }
    sub resolve_host {
        my ($self, %opts) = @_;
        return '127.0.0.1' if $self->{type} eq 'local';
        die "SSH provider requires 'host'\n" unless $opts{host};
        return $opts{host};
    }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        push @events, [ delete => $self->{type}, '' . ($id // $opts{host}) ];
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
    package FakeK8s;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list {
        my ($self, $kind) = @_;
        return FakeList->new(@{ $self->{$kind} // [] });
    }
    sub patch { 1 }
}

my $HCP = "control_planes:\n  provider: hetzner\n  server_type: cx32\n  location: fsn1\n";

my $POOL = "workers:\n  - name: edge\n    provider: ssh\n    nodes: [ w1.lan ]\n";

my $POLICE1 = "  - name: police1\n    provider: hetzner\n    providerId: \"111\"\n"
            . "    public_ip: 1.1.1.1\n";

sub project {
    my ($yaml, %a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: prod\n$yaml");
    $dir->child('.ocp', 'status.yaml')->spew_utf8(
        defined $a{status} ? "nodes:\n$a{status}" : "nodes: []\n");
    $dir->child('.ocp', 'deployed.yaml')->spew_utf8("registry: abc\n");
    $dir->child('kubeconfig.yaml')->spew_utf8("sops: encrypted\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub run_destroy {
    my ($config, %a) = @_;
    @events      = ();
    %search_dies = %{ $a{search_dies} // {} };
    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        k8s           => FakeK8s->new(OCPNodeProvider => $a{crs} // []),
        force         => 1,
    );
    my ($out, $err) = ('', '');
    my @warnings;
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my @ret = do {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        local $SIG{__WARN__} = sub { push @warnings, @_ };
        no warnings 'redefine';
        local *OCP::Provider::for_spec = sub {
            my ($class, $spec) = @_;
            return FakeProvider->new(type => $spec->{provider}, token => 'tok');
        };
        local *OCP::Provider::from_cr = sub {
            my ($class, $cr) = @_;
            return FakeProvider->new(type => 'hetzner', token => 'tok-' . $cr->{metadata}{name});
        };
        local *OCP::Secrets::hetzner_token = sub { 'tok' };
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { FakeKey->new };
        eval { $cmd->execute([], []) };
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0],
             warnings => [@warnings], events => [@events] };
}

sub deleted { [ sort map { "$_->[1] $_->[2]" } grep { $_->[0] eq 'delete' } @{ $_[0]{events} } ] }

my $CROAKED_A = "Hetzner API error: unable to authenticate at /src/lib/OCP/Provider/Hetzner.pm line 421.\n";
my $CROAKED_B = "Hetzner API error: rate limit exceeded at /src/lib/OCP/Provider/Hetzner.pm line 421.\n";

# ---------------------------------------------------------------- claim 1

subtest 'a host a later source knows is not lost to an earlier one without it' => sub {
    # w1 as status.yaml records it, with no host; the ocp.yaml pool names
    # the machine w1.lan -- the same machine, by its first label.
    my $config = project($HCP . $POOL, status => $POLICE1
        . "  - name: w1\n    provider: ssh\n    role: worker\n    public_ip: '-'\n");
    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{out}, qr/^  - w1 \(ssh, w1\.lan\)\n  - police1 \(hetzner, 1\.1\.1\.1\)\n/m,
        'listed once, at the host the pool names';
    like $r->{out}, qr/^  Uninstalling RKE2\/K3s on w1\.lan\.\.\.$/m, 'the uninstall goes there';
    unlike $r->{err}, qr/Skipped|no host recorded/, 'not skipped for want of a host';
    is_deeply deleted($r), [ 'hetzner 111', 'ssh w1.lan' ], 'police1 deleted, w1.lan uninstalled';
    is $r->{ret}, 0, 'exit 0' or diag $r->{err};

    # The same with the entry carrying no public_ip at all.
    $config = project($HCP . $POOL, status => $POLICE1
        . "  - name: w1\n    provider: ssh\n    role: worker\n");
    $r = run_destroy($config);
    is_deeply deleted($r), [ 'hetzner 111', 'ssh w1.lan' ],
        'no public_ip: the pool\'s host is taken too';

    # The control: a host the first source knows is kept, a later source only
    # fills in. The pool's w1.lan matches w1 by name and is merged into it.
    $config = project($HCP . $POOL, status => $POLICE1
        . "  - name: w1\n    provider: ssh\n    role: worker\n    public_ip: 10.0.0.1\n");
    $r = run_destroy($config);
    is_deeply deleted($r), [ 'hetzner 111', 'ssh 10.0.0.1' ],
        'the control: the recorded host is not overwritten'
        or diag explain deleted($r);
};

# ---------------------------------------------------------------- claim 2

subtest 'a status.yaml entry without public_ip is listed with -' => sub {
    my $config = project("control_planes:\n  provider: local\n",
        status => "  - name: cp1\n    provider: local\n    role: control-plane\n");
    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{out}, qr/^  - cp1 \(local, -\)$/m, 'listed with -';
    is_deeply $r->{warnings}, [], 'no uninitialized-value warning' or diag explain $r->{warnings};
    is_deeply deleted($r), [ 'local 127.0.0.1' ], 'the local uninstall still runs';
};

# ---------------------------------------------------------------- claim 3

subtest 'no search answered and two failed: both are said' => sub {
    my @crs = ({ metadata => { name => 'hetzner-b' }, spec => { type => 'hetzner' } });
    my $config = project($HCP);
    my $r = run_destroy($config, crs => \@crs, search_dies => {
        'prod tok'           => $CROAKED_A,
        'prod tok-hetzner-b' => $CROAKED_B,
    });
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is scalar(grep { $_->[0] eq 'search' && $_->[1] eq 'prod' } @{ $r->{events} }), 2,
        'the fixture: both tokens searched the cluster label';
    like $r->{err},
        qr/^\[!!\] control_planes\[1\]: a hetzner control plane is found by its ocp-cluster=prod label or not at all, and the label search failed: Hetzner API error: unable to authenticate -- /m,
        'the first failure, in the fallback\'s line';
    like $r->{err},
        qr/^\[!!\] The label search for ocp-cluster=prod with OCPNodeProvider\/hetzner-b's token failed: Hetzner API error: rate limit exceeded -- a server only it would find is NOT torn down\.$/m,
        'the second failure, said too';
    is scalar(() = $r->{err} =~ /unable to authenticate/g), 1, 'the first is said once';
    is $r->{ret}, 1, 'exit 1';
};

# ---------------------------------------------------------------- claim 4

subtest 'the closing list does not wait for reachability' => sub {
    my $config = project($HCP, status => $POLICE1
        . "  - name: w1\n    provider: ssh\n    role: worker\n    public_ip: '-'\n");
    my $r = run_destroy($config);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{err}, qr/^       - w1: no host recorded$/m, 'the fixture: w1 has no host';
    unlike $r->{err}, qr/reachable/, 'no "once they are reachable"';
    like $r->{err},
        qr/^     Nothing is billed for them through OCP\. To tear them down by hand,\n     run on each of them:\n       rke2-uninstall\.sh /m,
        'the by-hand line instead';
};

done_testing;

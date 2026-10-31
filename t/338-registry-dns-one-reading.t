#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Network;
use OCP::Config;
use OCP::Corefile;
use OCP::Drift;

#
# k338: the registry.local writer (OCP::Cmd::Apply::Network's
# configure_registry_dns) and its drift probe (OCP::Drift's
# registry_dns_drift) read the Corefile differently.
#
# The case that showed it: a Corefile with no server block for the root zone
# but a block of its own for registry.local that maps the name to the control
# plane. Since k328 the writer dies there (no root block to put the record in)
# while the probe, which took a record anywhere in the file, reported nothing.
# One said the step failed, the other that nothing was wrong.
#
# Both now ask one parser the same question: which server block CoreDNS
# answers registry.local from -- the one with the most specific zone that
# covers the name, the root zone as the catch-all -- and what address that
# block maps it to. The writer puts the record only into the root block
# (ADR 0016/0022: it does not maintain a block of its own for the name), so:
#
#   the answering block maps the name to the control plane
#       writer: up to date, nothing written      probe: no drift
#   the answering block is the root block, the record is missing or stale
#       writer: writes it                        probe: drift ocp apply closes
#   any other block answers (wrongly), or none does
#       writer: dies with the cause              probe: drift ocp apply does
#                                                       not close, with a step
#
# "The block CoreDNS answers from" is what ADR 0022 measured: a more specific
# registry.local:53 block shadows the root block's record completely.
#
# k348 closed the cases the two still read differently: the *.server snippets
# a k3s Corefile imports from coredns-custom (they answer like the Corefile's
# own blocks), a CoreDNS ConfigMap without a Corefile key (the probe read the
# next name), a root block running the hosts plugin twice (CoreDNS refuses it;
# the writer repaired it, the probe saw a record), and blocks on another port
# (they answer nothing the cluster asks).
#

my $CP  = '10.230.30.155';
my $OLD = '192.168.1.10';

# The root block of the stock k3s Corefile, cut to what matters here
my $ROOT = <<'COREFILE';
.:53 {
    errors
    hosts /etc/coredns/NodeHosts {
        ttl 60
        reload 15s
        fallthrough
    }
    kubernetes cluster.local in-addr.arpa ip6.arpa
    forward . /etc/resolv.conf
}
COREFILE

my $CLUSTER_LOCAL = <<'COREFILE';
cluster.local:53 {
    errors
    kubernetes cluster.local in-addr.arpa ip6.arpa
}
COREFILE

# A server block for $keys whose hosts plugin maps registry.local to each of
# @addresses -- none: a block that answers for the name and has no record
sub block_for_name {
    my ($keys, @addresses) = @_;
    return "$keys {\n    forward . 1.1.1.1\n}\n" unless @addresses;
    return "$keys {\n    hosts {\n"
         . join('', map { "        $_ registry.local\n" } @addresses)
         . "        fallthrough\n    }\n}\n";
}

sub with_host { OCP::Cmd::Apply::Network::corefile_with_host($_[0], $_[1], 'registry.local') }

# The import of the stock k3s Corefile, outside the root block: the *.server
# keys of the coredns-custom ConfigMap, mounted at /etc/coredns/custom (k348)
my $IMPORT = "import /etc/coredns/custom/*.server\n";
my $K3S    = $ROOT . $IMPORT;

# The hosts block an older OCP added to the root block next to the one the
# distribution runs -- the duplicate CoreDNS refuses to start with (t/39)
sub with_added_hosts {
    my ($corefile, $ip) = @_;
    (my $out = $corefile) =~ s/^(    errors\n)/$1    hosts {\n        $ip registry.local\n        fallthrough\n    }\n/m;
    return $out;
}

# A hosts plugin of the operator's own in the root block, next to the
# distribution's: one more than CoreDNS takes, and not one ocp apply added
sub with_other_hosts {
    my ($corefile) = @_;
    (my $out = $corefile) =~ s/^(    errors\n)/$1    hosts \/etc\/coredns\/extra {\n        fallthrough\n    }\n/m;
    return $out;
}

package FakeCm { sub new { my ($c, $d) = @_; bless { data => $d }, $c } sub data { $_[0]{data} } }

# The ConfigMaps in kube-system by name: a hash is its data, a string what the
# read dies with, any other name a 404. Both call shapes -- the writer's
# get('ConfigMap', $name, ...), the probe's get('ConfigMap', name => $name, ...).
package FakeApi {
    sub new { my ($c, %cm) = @_; bless { cm => { %cm }, reads => [] }, $c }
    sub get {
        my ($self, $kind, @args) = @_;
        my %args = @args % 2 ? (name => @args) : @args;
        push @{ $self->{reads} }, $args{name};
        my $data = $self->{cm}{ $args{name} };
        die "Kubernetes API error (get $kind): 404 $kind $args{name} not found\n" unless defined $data;
        die $data unless ref $data;
        return FakeCm->new($data);
    }
}

package main;

# A project whose control plane is recorded at $CP
my $CONFIG = do {
    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('ocp.yaml')->spew_utf8(<<'YAML');
name: testcluster
kubernetes:
  dist: k3s
control_planes:
  provider: hetzner
  server_type: cx32
YAML
    path($dir)->child('.ocp')->mkpath;
    path($dir)->child('.ocp', 'status.yaml')->spew_utf8(<<"YAML");
nodes:
  - name: police1
    role: control-plane
    public_ip: $CP
YAML
    OCP::Config->new(file => path($dir)->child('ocp.yaml')->stringify);
};

# The API both sides read: coredns holding $corefile, and the ConfigMaps %cm
# (name => data, or what the read dies with), which may replace it
sub api_with {
    my ($corefile, %cm) = @_;
    return FakeApi->new(coredns => { Corefile => $corefile }, %cm);
}

# What configure_registry_dns does with $corefile: { rv, died, written, reads }
sub writer {
    my ($corefile, %cm) = @_;

    my $api   = api_with($corefile, %cm);
    my $apply = bless {}, 'OCP::Cmd::Apply';
    $apply->{_k8s_api} = $api;

    my @applied;
    my ($out, $rv, $died) = ('');
    {
        no warnings 'redefine';
        local *OCP::Cmd::Apply::_server_side_apply = sub { push @applied, $_[2]; 1 };
        open my $fh, '>', \$out or die $!;
        local *STDOUT = $fh;
        $rv   = eval { OCP::Cmd::Apply::Network::configure_registry_dns($apply, $CP) };
        $died = $@;
    }

    return {
        rv      => $rv,
        died    => $died,
        written => @applied ? $applied[0]{data}{Corefile} : undef,
        reads   => $api->{reads},
    };
}

# What registry_dns_drift says about $corefile; with \@reads, the ConfigMaps
# it read land there
sub probe {
    my ($corefile, %cm) = @_;
    my $reads = delete $cm{reads};
    my $api = api_with($corefile, %cm);
    my $p = OCP::Drift->new(config => $CONFIG, api => $api)->registry_dns_drift;
    @$reads = @{ $api->{reads} } if $reads;
    return $p;
}

# The writer's outcome and the probe's, in the same three words
sub writer_verdict {
    my ($w) = @_;
    return $w->{died}                         ? 'not closed by ocp apply'
         : $w->{rv} && defined $w->{written}  ? 'closed by ocp apply'
         : !$w->{rv} && !defined $w->{written} ? 'nothing to do'
         :                                      'confused';
}

sub probe_verdict {
    my ($p) = @_;
    return 'nothing to do' unless $p;
    # What ocp status and the dry run count as closed by `ocp apply`:
    # a remedy, a self-healing entry, or kind missing.
    return $p->{remedy} || $p->{self_healing} || ($p->{kind} // '') eq 'missing'
        ? 'closed by ocp apply'
        : 'not closed by ocp apply';
}

my $THE_CARD = $CLUSTER_LOCAL . block_for_name('registry.local:53', $CP);

# The causes both sides name for the k348 cases
my $SNIPPET     = qr{server block registry\.local:53 \(ConfigMap kube-system/coredns-custom, key registry\.server\)};
my $NO_COREFILE = qr{ConfigMap kube-system/coredns has no Corefile key};
my $TWO_HOSTS   = qr/root block runs the hosts plugin more than once/;

my @CASES = (
    # [ what, Corefile, verdict, the cause both sides name when it is not closed ]
    [ 'root block, no record',                $ROOT,                 'closed by ocp apply' ],
    [ 'root block with the record',           with_host($ROOT, $CP),  'nothing to do' ],
    [ 'root block with a stale record',       with_host($ROOT, $OLD), 'closed by ocp apply' ],

    [ 'k338: no root block, a block of its own with the record', $THE_CARD, 'nothing to do' ],
    [ 'no root block, a block of its own with a stale record',
      $CLUSTER_LOCAL . block_for_name('registry.local:53', $OLD),
      'not closed by ocp apply', qr/registry\.local:53/ ],
    [ 'no root block, a block of its own without a record',
      $CLUSTER_LOCAL . block_for_name('registry.local:53'),
      'not closed by ocp apply', qr/registry\.local:53/ ],
    [ 'no root block, a block for the parent zone with the record',
      $CLUSTER_LOCAL . block_for_name('local', $CP), 'nothing to do' ],
    [ 'no root block, no block for the name', $CLUSTER_LOCAL,
      'not closed by ocp apply', qr/no server block for the root zone/ ],
    [ 'no root block, the record in a block for another zone',
      $CLUSTER_LOCAL . block_for_name('example.com:53', $CP),
      'not closed by ocp apply', qr/no server block for the root zone/ ],
    [ 'an empty Corefile', '',
      'not closed by ocp apply', qr/no server block for the root zone/ ],

    # The more specific block shadows the root block's record (ADR 0022)
    [ 'root block, and a block of its own with the record',
      $ROOT . block_for_name('registry.local:53', $CP), 'nothing to do' ],
    [ 'root block with the record, a block of its own with a stale one',
      with_host($ROOT, $CP) . block_for_name('registry.local:53', $OLD),
      'not closed by ocp apply', qr/registry\.local:53/ ],
    [ 'root block with a stale record, a block of its own with the record',
      with_host($ROOT, $OLD) . block_for_name('registry.local:53', $CP), 'nothing to do' ],

    # k348: the server blocks k3s imports from coredns-custom answer like the
    # Corefile's own. ocp apply does not write there; it says so instead.
    [ 'k348: a coredns-custom snippet with the record',
      $K3S, 'nothing to do', undef,
      { 'coredns-custom' => { 'registry.server' => block_for_name('registry.local:53', $CP) } } ],
    [ 'k348: a coredns-custom snippet with a stale record',
      $K3S, 'not closed by ocp apply', $SNIPPET,
      { 'coredns-custom' => { 'registry.server' => block_for_name('registry.local:53', $OLD) } } ],
    [ 'k348: a coredns-custom snippet without a record',
      $K3S, 'not closed by ocp apply', $SNIPPET,
      { 'coredns-custom' => { 'registry.server' => block_for_name('registry.local:53') } } ],
    [ 'k348: the record in the root block, a stale coredns-custom snippet shadowing it',
      with_host($K3S, $CP), 'not closed by ocp apply', $SNIPPET,
      { 'coredns-custom' => { 'registry.server' => block_for_name('registry.local:53', $OLD) } } ],
    [ 'k348: a coredns-custom snippet for the parent zone, no record in it',
      with_host($K3S, $CP), 'not closed by ocp apply',
      qr{server block local:53 \(ConfigMap kube-system/coredns-custom, key local\.server\)},
      { 'coredns-custom' => { 'local.server' => block_for_name('local:53') } } ],
    [ 'k348: a coredns-custom snippet for another zone',
      $K3S, 'closed by ocp apply', undef,
      { 'coredns-custom' => { 'example.server' => block_for_name('example.com:53', $CP) } } ],
    [ 'k348: a coredns-custom key the import does not name',
      with_host($K3S, $CP), 'nothing to do', undef,
      { 'coredns-custom' => { 'registry.override' => block_for_name('registry.local:53', $OLD) } } ],
    [ 'k348: a Corefile that imports nothing reads no snippet',
      with_host($ROOT, $CP), 'nothing to do', undef,
      { 'coredns-custom' => { 'registry.server' => block_for_name('registry.local:53', $OLD) } } ],
    [ 'k348: no coredns-custom ConfigMap (a 404)', with_host($K3S, $CP), 'nothing to do' ],
    [ 'k348: the root zone answered from a coredns-custom snippet, with the record',
      $CLUSTER_LOCAL . $IMPORT, 'nothing to do', undef,
      { 'coredns-custom' => { 'root.server' => block_for_name('.:53', $CP) } } ],
    [ 'k348: the root zone answered from a coredns-custom snippet, with a stale record',
      $CLUSTER_LOCAL . $IMPORT, 'not closed by ocp apply',
      qr{server block \.:53 \(ConfigMap kube-system/coredns-custom, key root\.server\)},
      { 'coredns-custom' => { 'root.server' => block_for_name('.:53', $OLD) } } ],

    # k348: a CoreDNS ConfigMap without a Corefile key is the one CoreDNS
    # mounts; the next name is not read in its place
    [ 'k348: a CoreDNS ConfigMap without a Corefile key',
      undef, 'not closed by ocp apply', $NO_COREFILE, { coredns => {} } ],
    [ 'k348: one without a Corefile key, the next name with the record',
      undef, 'not closed by ocp apply', $NO_COREFILE,
      { coredns => { NodeHosts => '' }, 'rke2-coredns-rke2-coredns' => { Corefile => with_host($ROOT, $CP) } } ],

    # k348: a root block running the hosts plugin twice is a Corefile CoreDNS
    # refuses. ocp apply removes the block an older ocp added, and only that.
    [ 'k348: the hosts block an older ocp added, with the record',
      with_added_hosts($ROOT, $CP), 'closed by ocp apply' ],
    [ 'k348: the hosts block an older ocp added, with a stale record',
      with_added_hosts($ROOT, $OLD), 'closed by ocp apply' ],
    [ 'k348: two hosts blocks an older ocp added',
      with_added_hosts(with_added_hosts($ROOT, $CP), $CP), 'closed by ocp apply' ],
    [ 'k348: a second hosts plugin of the operator\'s, the record in place',
      with_other_hosts(with_host($ROOT, $CP)), 'not closed by ocp apply', $TWO_HOSTS ],
    [ 'k348: one an older ocp added and one of the operator\'s',
      with_other_hosts(with_added_hosts($ROOT, $CP)), 'not closed by ocp apply', $TWO_HOSTS ],

    # k348: a server block answers the cluster's queries only on plain DNS
    # port 53, where both distributions' Corefiles and the kube-dns Service are
    [ 'k348: a block of its own on another port does not answer',
      with_host($ROOT, $CP) . block_for_name('registry.local:5353', $OLD), 'nothing to do' ],
    [ 'k348: nor one over another transport',
      with_host($ROOT, $CP) . block_for_name('tls://registry.local:853', $OLD), 'nothing to do' ],
    [ 'k348: nor shadows the root block that has no record',
      $ROOT . block_for_name('registry.local:5353', $CP), 'closed by ocp apply' ],
    [ 'k348: a root block on another port is no root block',
      $CLUSTER_LOCAL . ".:5353 {\n    forward . /etc/resolv.conf\n}\n",
      'not closed by ocp apply', qr/no server block for the root zone/ ],
    [ 'k348: dns:// on port 53 is port 53',
      with_host($ROOT, $CP) . block_for_name('dns://registry.local:53', $OLD),
      'not closed by ocp apply', qr{dns://registry\.local:53} ],
);

for my $case (@CASES) {
    my ($what, $corefile, $verdict, $cause, $cm) = @$case;
    my %cm = %{ $cm // {} };

    subtest $what => sub {
        my $w = writer($corefile, %cm);
        my $p = probe($corefile, %cm);

        is probe_verdict($p), writer_verdict($w), 'the writer and the probe agree';
        is writer_verdict($w), $verdict, "and say what CoreDNS does: $verdict";
        diag "writer died: $w->{died}" if $w->{died} && $verdict ne 'not closed by ocp apply';

        if ($verdict eq 'closed by ocp apply') {
            like $p->{message}, qr/ocp apply restores it/, 'the probe says the run restores it';
            is probe($w->{written}, %cm), undef, 'and after the write the probe finds nothing';
        }
        elsif ($verdict eq 'not closed by ocp apply') {
            like $w->{died}, $cause, 'the writer names the cause';
            like $p->{message}, $cause, 'the probe names the same one';
            unlike $p->{message}, qr/ocp apply restores it/, 'and does not promise a restore';
            ok $p->{manual_step}, 'it says what a human does instead';
            is $w->{written}, undef, 'nothing was written';
        }
    };
}

# What the probe reports for the shadowed case is what CoreDNS answers with
subtest 'a stale block of its own is the address the cluster answers with' => sub {
    my $p = probe(with_host($ROOT, $CP) . block_for_name('registry.local:53', $OLD));
    is $p->{actual}, $OLD, 'the block that answers, not the first record in the file';
    is $p->{expected}, $CP, 'the control plane';
};

#
# k348: coredns-custom is read when the Corefile imports from where k3s
# mounts it, and only then -- RKE2's chart Corefile imports nothing, so it
# costs RKE2 no read and needs no switch on the distribution.
#

subtest 'k348: coredns-custom is read only when the Corefile imports it' => sub {
    my %cm = ('coredns-custom' => { 'registry.server' => block_for_name('registry.local:53', $CP) });

    my @reads;
    is writer(with_host($K3S, $CP), %cm)->{reads}[-1], 'coredns-custom', 'the writer reads it for the k3s import';
    probe(with_host($K3S, $CP), %cm, reads => \@reads);
    is $reads[-1], 'coredns-custom', 'and so does the probe';

    ok !(grep { $_ eq 'coredns-custom' } @{ writer(with_host($ROOT, $CP), %cm)->{reads} }),
        'no import: the writer does not read it';
    probe(with_host($ROOT, $CP), %cm, reads => \@reads);
    ok !(grep { $_ eq 'coredns-custom' } @reads), 'nor does the probe';
};

subtest 'k348: a coredns-custom read that fails is no "no snippets"' => sub {
    my %cm = ('coredns-custom' => "Kubernetes API error (get ConfigMap): 403 Forbidden\n");

    my $w = writer(with_host($K3S, $CP), %cm);
    like $w->{died}, qr{\Acould not read ConfigMap kube-system/coredns-custom: .*403},
        'the writer dies with the cause, which the step says on STDERR';
    is $w->{written}, undef, 'and writes nothing';

    my @warn;
    my $p = do { local $SIG{__WARN__} = sub { push @warn, @_ }; probe(with_host($K3S, $CP), %cm) };
    is $p->{kind}, 'error', 'the probe: drift unknown, not "no drift"';
    like $p->{message}, qr{could not read ConfigMap kube-system/coredns-custom, drift unknown: .*403},
        'naming the read and the cause';
    is scalar @warn, 1, 'said once on stderr';
};

#
# One parser, not three readings that happen to agree today.
#
# Overriding the shared reading is the point of these, as with t/39's
# resolver: if either side grows its own copy of it again -- the writer's
# brace loop, the probe's "first record anywhere" -- only one of them follows
# the override, and they fail.
#

subtest 'the writer and the probe find the answering block through OCP::Corefile' => sub {
    my $corefile = with_host($ROOT, $CP);
    is writer_verdict(writer($corefile)), 'nothing to do', 'control: the record is in place';

    no warnings 'redefine';
    local *OCP::Corefile::block_for = sub { return };    # no block answers any name

    is writer_verdict(writer($corefile)), 'not closed by ocp apply', 'the writer follows it';
    is probe_verdict(probe($corefile)),   'not closed by ocp apply', 'and so does the probe';
};

subtest 'the writer and the probe find the record through OCP::Corefile' => sub {
    my $corefile = with_host($ROOT, $CP);

    no warnings 'redefine';
    local *OCP::Corefile::record_index = sub { return };    # no block lists the name

    is writer_verdict(writer($corefile)), 'closed by ocp apply', 'the writer follows it';
    is probe_verdict(probe($corefile)),   'closed by ocp apply', 'and so does the probe';
};

subtest 'k348: the writer and the probe take the snippets from one place' => sub {
    my $corefile = with_host($K3S, $CP);
    is writer_verdict(writer($corefile)), 'nothing to do', 'control: no coredns-custom, the record in place';

    no warnings 'redefine';
    local *OCP::Drift::coredns_custom_files = sub {
        return { '/etc/coredns/custom/registry.server' => block_for_name('registry.local:53', $OLD) };
    };

    is writer_verdict(writer($corefile)), 'not closed by ocp apply', 'the writer follows it';
    is probe_verdict(probe($corefile)),   'not closed by ocp apply', 'and so does the probe';
};

subtest 'k348: the writer and the probe count hosts plugins through OCP::Corefile' => sub {
    my $corefile = with_host($ROOT, $CP);

    no warnings 'redefine';
    local *OCP::Corefile::hosts_lines = sub { return (2, 3) };    # every block runs it twice

    is writer_verdict(writer($corefile)), 'not closed by ocp apply', 'the writer follows it';
    is probe_verdict(probe($corefile)),   'not closed by ocp apply', 'and so does the probe';
};

#
# OCP::Corefile itself
#

subtest 'zone: what a server block key serves' => sub {
    my %zone = (
        '.'                  => '.',
        '.:53'               => '.',
        'dns://.:53'         => '.',
        'registry.local'     => 'registry.local',
        'registry.local:53'  => 'registry.local',
        'Registry.Local.:53' => 'registry.local',
        'tls://local:853'    => 'local',
    );
    for my $key (sort keys %zone) {
        is(scalar OCP::Corefile->new(text => '')->zone($key), $zone{$key}, "$key serves $zone{$key}");
    }
    for my $key ('10.0.0.0/8', ':53', '..', '.local', 'DNS://.:53') {
        is_deeply [ OCP::Corefile->new(text => '')->zone($key) ], [], "$key names no zone";
    }
};

subtest 'blocks of the stock root block' => sub {
    my $blocks = OCP::Corefile->new(text => $ROOT . "import /etc/coredns/custom/*.server\n")->blocks;
    is scalar @$blocks, 1, 'one server block, the import outside it is none';
    is_deeply [ @{ $blocks->[0] }{qw(keys zones root from to)} ], [ ['.:53'], ['.'], 1, 0, 9 ],
        'its keys, zone, root flag and lines';
};

subtest 'block_for: the most specific zone answers' => sub {
    my $own    = block_for_name('registry.local:53', $OLD);
    my $parent = block_for_name('local:53', $CP);

    for my $case ([ 'root first'  => $ROOT . $own ],
                  [ 'root last'   => $own . $ROOT ]) {
        my ($order, $text) = @$case;
        my $cf = OCP::Corefile->new(text => $text);
        is_deeply $cf->block_for('registry.local')->{keys}, ['registry.local:53'], "$order: the block of its own";
        is_deeply $cf->root_block->{keys}, ['.:53'], "$order: the root block is still the root block";
    }

    my $three = OCP::Corefile->new(text => $ROOT . $parent . $own);
    is_deeply $three->block_for('registry.local')->{keys}, ['registry.local:53'], 'the name beats its parent zone';
    is_deeply $three->block_for('other.local')->{keys}, ['local:53'], 'the parent zone answers its other names';
    is_deeply $three->block_for('example.com')->{keys}, ['.:53'], 'and the root zone everything else';
    is_deeply $three->block_for('Registry.Local.')->{keys}, ['registry.local:53'], 'case and trailing dot do not matter';

    my $none = OCP::Corefile->new(text => $CLUSTER_LOCAL . block_for_name('example.com:53', $CP));
    is $none->block_for('registry.local'), undef, 'no zone covers it: no block';
    is $none->root_block, undef, 'and no root block';

    my $tie = OCP::Corefile->new(text => $ROOT . ". {\n    errors\n}\n");
    is $tie->root_block->{from}, 0, 'two root blocks: the first one';

    # k348: a block on another port answers none of the cluster's queries
    my $port = OCP::Corefile->new(text => ".:5353 {\n    errors\n}\n" . $ROOT);
    is $port->root_block->{keys}[0], '.:53', 'the root block on port 53, not the one before it on 5353';
    is_deeply $port->blocks->[0]{zones}, [], 'which serves no zone there';
};

subtest 'k348 on_cluster_port: plain DNS on port 53' => sub {
    my $cf = OCP::Corefile->new(text => '');
    for my $key ('.', '.:53', 'dns://.:53', 'dns://.', 'registry.local', 'registry.local:53') {
        ok $cf->on_cluster_port($key), "$key: yes";
    }
    for my $key ('.:5353', 'registry.local:1053', 'tls://.:853', 'tls://registry.local',
                 'https://.:443', 'grpc://.', ':53') {
        ok !$cf->on_cluster_port($key), "$key: no";
    }
};

subtest 'k348 imports: the files a top-level import reads' => sub {
    my $snippet = block_for_name('registry.local:53', $OLD);
    my %files = (
        '/etc/coredns/custom/b.server'    => $snippet,
        '/etc/coredns/custom/a.server'    => "local:53 {\n    errors\n}\n",
        '/etc/coredns/custom/x.override'  => "    log\n",
        '/elsewhere/c.server'             => "example.com:53 {\n    errors\n}\n",
    );
    my $text = $ROOT;
    $text =~ s/^(    errors\n)/$1    import \/etc\/coredns\/custom\/*.override\n/m;
    $text .= $IMPORT;

    my $own = OCP::Corefile->new(text => $text);
    is_deeply [ $own->import_patterns ], ['/etc/coredns/custom/*.server'],
        'import_patterns: the top-level import, not the one inside the root block';
    is join("\n", @{ $own->lines }), $text, 'no imports given: the lines are the text';

    my $cf = OCP::Corefile->new(text => $text, imports => \%files);
    is_deeply [ map { $_->{keys}[0] } @{ $cf->blocks } ], [ '.:53', 'local:53', 'registry.local:53' ],
        'the *.server files after the import, in name order; nothing else';
    is_deeply [ map { $_->{file} } @{ $cf->blocks } ],
        [ undef, '/etc/coredns/custom/a.server', '/etc/coredns/custom/b.server' ],
        'each block says which file it came from';
    ok !(grep { /log/ } @{ $cf->lines }), 'the import inside the root block is not expanded';
    is $cf->address_of('registry.local'), $OLD, 'the imported block answers with its record';
    is $own->address_of('registry.local'), undef, 'which the text alone does not have';
    is $cf->without_added_hosts('registry.local'), $text, 'without_added_hosts reads the text alone';
};

subtest 'k348 hosts_lines and without_added_hosts' => sub {
    my $one = OCP::Corefile->new(text => with_host($ROOT, $CP));
    is scalar(() = $one->hosts_lines($one->root_block)), 1, 'the distribution\'s hosts plugin';

    my $broken = with_added_hosts($ROOT, $CP);
    my $two = OCP::Corefile->new(text => $broken);
    is_deeply [ $two->hosts_lines($two->root_block) ], [ 2, 6 ], 'and the one an older ocp added';
    is $two->without_added_hosts('registry.local'), $ROOT, 'which goes';
    is $two->without_added_hosts('other.local'), $broken, 'but not for a name it does not list';

    my $other = with_other_hosts($ROOT);
    is(OCP::Corefile->new(text => $other)->without_added_hosts('registry.local'), $other,
        'a hosts plugin that names a file stays');
};

subtest 'address_of reads the block that answers' => sub {
    my $cf = OCP::Corefile->new(text => with_host($ROOT, $CP) . block_for_name('registry.local:53', $OLD));
    is $cf->address_of('registry.local'), $OLD, 'the block of its own, not the first record in the file';
    my %address = (
        'the root block when it is the one'                 => [ with_host($ROOT, $CP), $CP ],
        'a record in a block that does not answer is none'  => [ $CLUSTER_LOCAL . block_for_name('example.com:53', $CP), undef ],
        'no record, no address'                             => [ $ROOT, undef ],
    );
    for my $what (sort keys %address) {
        my ($text, $ip) = @{ $address{$what} };
        is(OCP::Corefile->new(text => $text)->address_of('registry.local'), $ip, $what);
    }
};

subtest 'record: an address, then names' => sub {
    my $cf = OCP::Corefile->new(text => '');
    is_deeply [ $cf->record('        10.0.0.5 registry.local other') ], [qw(10.0.0.5 registry.local other)], 'IPv4';
    is_deeply [ $cf->record('  fd00::5 registry.local') ], [qw(fd00::5 registry.local)], 'IPv6';
    is_deeply [ $cf->record('    cache 30') ], [], 'a plugin with an argument is none';
    is_deeply [ $cf->record('    ttl 60') ], [], 'nor is an option';
    is_deeply [ $cf->record('    add registry.local') ], [], 'a word of hex digits is no address';
    is_deeply [ $cf->record('    10.0.0.5') ], [], 'an address without a name is none';
};

done_testing;

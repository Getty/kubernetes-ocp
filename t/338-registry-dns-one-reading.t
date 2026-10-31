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

package WriterCm  { sub new { my ($c, $d) = @_; bless { data => $d }, $c } sub data { $_[0]{data} } }
package WriterApi {
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub get { $_[0]{cm} }
}

package ProbeApi {
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub get {
        my ($self, $kind, %args) = @_;
        return $self->{cm} if $kind eq 'ConfigMap' && $args{name} eq 'coredns';
        die "Kubernetes API error (get $kind): 404 $kind $args{name} not found\n";
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

# What configure_registry_dns does with $corefile: { rv, died, written }
sub writer {
    my ($corefile) = @_;

    my $apply = bless {}, 'OCP::Cmd::Apply';
    $apply->{_k8s_api} = WriterApi->new(cm => WriterCm->new({ Corefile => $corefile }));

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
    };
}

# What registry_dns_drift says about $corefile
sub probe {
    my ($corefile) = @_;
    my $api = ProbeApi->new(cm => { data => { Corefile => $corefile } });
    return OCP::Drift->new(config => $CONFIG, api => $api)->registry_dns_drift;
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
);

for my $case (@CASES) {
    my ($what, $corefile, $verdict, $cause) = @$case;

    subtest $what => sub {
        my $w = writer($corefile);
        my $p = probe($corefile);

        is probe_verdict($p), writer_verdict($w), 'the writer and the probe agree';
        is writer_verdict($w), $verdict, "and say what CoreDNS does: $verdict";
        diag "writer died: $w->{died}" if $w->{died} && $verdict ne 'not closed by ocp apply';

        if ($verdict eq 'closed by ocp apply') {
            like $p->{message}, qr/ocp apply restores it/, 'the probe says the run restores it';
            is probe($w->{written}), undef, 'and after the write the probe finds nothing';
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

    my $tie = OCP::Corefile->new(text => $ROOT . ".:5353 {\n    errors\n}\n");
    is $tie->root_block->{from}, 0, 'two root blocks: the first one';
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

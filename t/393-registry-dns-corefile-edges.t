#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# Rex puts getcwd/lib in front of @INC when it loads; load it before the
# modules under test, so they come from the tree prove -l points at
use Rex ();

use Cwd qw( getcwd );
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Network;
use OCP::Config;
use OCP::Corefile;
use OCP::Drift;

#
# k393: the Corefile cases the registry.local writer
# (OCP::Cmd::Apply::Network's configure_registry_dns) and its drift probe
# (OCP::Drift's registry_dns_drift) still read wrongly after k348. Both were
# wrong in the same way, so t/338's "they agree" did not notice:
#
#   * a server block that runs the hosts plugin twice is a Corefile CoreDNS
#     refuses ("plugin/hosts: this plugin can only be used once per Server
#     Block"), whichever block it is. Both sides looked only at the root
#     block, and only when the root block answered for registry.local. A
#     doubled root block next to another block that answers, or a doubled
#     block that is not the root block, came out clean or "closed by ocp
#     apply". Nothing resolves from that Corefile.
#   * neither CoreDNS ConfigMap name exists: the writer stops with an error
#     (k319), the probe said nothing.
#   * "which that one shadows", when the Corefile has no root block of its
#     own for the answering block to shadow.
#
# The rule the cases follow is k348's for the root block: ocp apply repairs
# only the hosts block an older ocp added to the root block it writes the
# record into. Every other doubled hosts plugin stays as it is. The writer
# dies naming the block, and the probe gives a spec entry with a manual step.
#

my $CP  = '10.230.30.155';
my $OLD = '192.168.1.10';

my $CWD = getcwd();
like $INC{'OCP/Drift.pm'}, qr{\A(?:\Q$CWD\E/)?lib/OCP/Drift\.pm\z},
    'OCP::Drift comes from the tree under test';
like $INC{'OCP/Corefile.pm'}, qr{\A(?:\Q$CWD\E/)?lib/OCP/Corefile\.pm\z},
    'and so does OCP::Corefile';
like $INC{'OCP/Cmd/Apply/Network.pm'}, qr{\A(?:\Q$CWD\E/)?lib/OCP/Cmd/Apply/Network\.pm\z},
    'and OCP::Cmd::Apply::Network';

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

my $IMPORT = "import /etc/coredns/custom/*.server\n";
my $K3S    = $ROOT . $IMPORT;

# A server block for $keys whose hosts plugin maps registry.local to each of
# @addresses; none: a block with no record
sub block_for_name {
    my ($keys, @addresses) = @_;
    return "$keys {\n    forward . 1.1.1.1\n}\n" unless @addresses;
    return "$keys {\n    hosts {\n"
         . join('', map { "        $_ registry.local\n" } @addresses)
         . "        fallthrough\n    }\n}\n";
}

# A server block for $keys that runs the hosts plugin twice: one for a file,
# one inline mapping registry.local to $ip (none: an inline one without it)
sub doubled_block {
    my ($keys, $ip) = @_;
    return "$keys {\n    hosts /etc/coredns/extra {\n        fallthrough\n    }\n"
         . "    hosts {\n" . (defined $ip ? "        $ip registry.local\n" : '')
         . "        fallthrough\n    }\n}\n";
}

sub with_host { OCP::Cmd::Apply::Network::corefile_with_host($_[0], $_[1], 'registry.local') }

# The hosts block an older OCP added to the root block next to the
# distribution's: the one ocp apply removes (k348)
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

# The ConfigMaps in kube-system by name: a hash is its data, any other name a
# 404. Both call shapes: the writer's get('ConfigMap', $name, ...), the
# probe's get('ConfigMap', name => $name, ...).
package FakeApi {
    sub new { my ($c, %cm) = @_; bless { cm => { %cm } }, $c }
    sub get {
        my ($self, $kind, @args) = @_;
        my %args = @args % 2 ? (name => @args) : @args;
        my $data = $self->{cm}{ $args{name} };
        die "Kubernetes API error (get $kind): 404 $kind $args{name} not found\n" unless defined $data;
        return FakeCm->new($data);
    }
}

package main;

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

# The ConfigMaps both sides read: coredns holding $corefile (undef: no
# coredns ConfigMap at all), and the ConfigMaps %cm
sub cms {
    my ($corefile, %cm) = @_;
    return ((defined $corefile ? (coredns => { Corefile => $corefile }) : ()), %cm);
}

# What configure_registry_dns does: { rv, died, written }
sub writer {
    my $api   = FakeApi->new(cms(@_));
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

    return { rv => $rv, died => $died, written => @applied ? $applied[0]{data}{Corefile} : undef };
}

# What registry_dns_drift says
sub probe {
    my $api = FakeApi->new(cms(@_));
    return OCP::Drift->new(config => $CONFIG, api => $api)->registry_dns_drift;
}

sub writer_verdict {
    my ($w) = @_;
    return $w->{died}                          ? 'not closed by ocp apply'
         : $w->{rv} && defined $w->{written}   ? 'closed by ocp apply'
         : !$w->{rv} && !defined $w->{written} ? 'nothing to do'
         :                                       'confused';
}

sub probe_verdict {
    my ($p) = @_;
    return 'nothing to do' unless $p;
    return OCP::Drift->apply_closes($p) ? 'closed by ocp apply' : 'not closed by ocp apply';
}

my $TWICE    = 'runs the hosts plugin more than once';
my $ROOT_2   = qr/root block \Q$TWICE\E/;
my $LEAVES   = qr/ocp apply leaves that block as it is/;
my $REPAIRS  = qr/ocp apply removes only a hosts block an older ocp added/;
my $SNIPPET  = 'ConfigMap kube-system/coredns-custom';

my @CASES = (
    # [ what, Corefile, verdict, the cause both sides name, what both say ocp
    #   apply does about it, the other ConfigMaps ]

    # Item: a doubled root block while another block answers for the name.
    # The writer does not write then, so it does not repair either.
    [ 'a doubled root block, a block of its own answering with the record',
      with_other_hosts(with_host($ROOT, $CP)) . block_for_name('registry.local:53', $CP),
      'not closed by ocp apply', $ROOT_2, $LEAVES ],
    [ 'the hosts block an older ocp added, a block of its own answering with the record',
      with_added_hosts($ROOT, $CP) . block_for_name('registry.local:53', $CP),
      'not closed by ocp apply', $ROOT_2, $LEAVES ],
    [ 'a doubled root block, a block of its own answering with a stale record',
      with_other_hosts(with_host($ROOT, $CP)) . block_for_name('registry.local:53', $OLD),
      'not closed by ocp apply', $ROOT_2, $LEAVES ],
    [ 'a doubled root block, a coredns-custom snippet answering with the record',
      with_other_hosts(with_host($K3S, $CP)), 'not closed by ocp apply', $ROOT_2, $LEAVES,
      { 'coredns-custom' => { 'registry.server' => block_for_name('registry.local:53', $CP) } } ],

    # Item: a hosts plugin doubled in a server block that is not the root block
    [ 'the record in the root block, another zone\'s block doubled',
      with_host($ROOT, $CP) . doubled_block('cluster.local:53'),
      'not closed by ocp apply', qr/server block cluster\.local:53 \Q$TWICE\E/, $LEAVES ],
    [ 'no record in the root block, another zone\'s block doubled',
      $ROOT . doubled_block('cluster.local:53'),
      'not closed by ocp apply', qr/server block cluster\.local:53 \Q$TWICE\E/, $LEAVES ],
    [ 'a block of its own answering, doubled, with the record',
      with_host($ROOT, $CP) . doubled_block('registry.local:53', $CP),
      'not closed by ocp apply', qr/server block registry\.local:53 \Q$TWICE\E/, $LEAVES ],
    [ 'a doubled block on another port: CoreDNS sets it up all the same',
      with_host($ROOT, $CP) . doubled_block('registry.local:5353', $CP),
      'not closed by ocp apply', qr/server block registry\.local:5353 \Q$TWICE\E/, $LEAVES ],
    [ 'no root block, a doubled block: the refusal, before the missing root block',
      $CLUSTER_LOCAL . doubled_block('example.com:53'),
      'not closed by ocp apply', qr/server block example\.com:53 \Q$TWICE\E/, $LEAVES ],
    [ 'a coredns-custom snippet for another zone, doubled',
      with_host($K3S, $CP), 'not closed by ocp apply',
      qr/server block example\.com:53 \(\Q$SNIPPET\E, key example\.server\) \Q$TWICE\E/, $LEAVES,
      { 'coredns-custom' => { 'example.server' => doubled_block('example.com:53') } } ],
    [ 'a coredns-custom snippet answering, doubled, with the record',
      with_host($K3S, $CP), 'not closed by ocp apply',
      qr/server block registry\.local:53 \(\Q$SNIPPET\E, key registry\.server\) \Q$TWICE\E/, $LEAVES,
      { 'coredns-custom' => { 'registry.server' => doubled_block('registry.local:53', $CP) } } ],
    [ 'the hosts block an older ocp added, and a doubled snippet: the snippet is what stays',
      with_added_hosts($K3S, $CP), 'not closed by ocp apply',
      qr/server block example\.com:53 \(\Q$SNIPPET\E, key example\.server\) \Q$TWICE\E/, $LEAVES,
      { 'coredns-custom' => { 'example.server' => doubled_block('example.com:53') } } ],

    # k348 as it was: the root block answers and the extra block is one an
    # older ocp added, or the operator's own
    [ 'k348 control: the hosts block an older ocp added, nothing else',
      with_added_hosts($ROOT, $CP), 'closed by ocp apply' ],
    [ 'k348 control: a second hosts plugin of the operator\'s in the answering root block',
      with_other_hosts(with_host($ROOT, $CP)), 'not closed by ocp apply', $ROOT_2, $REPAIRS ],
    [ 'control: a single hosts plugin in every block',
      with_host($ROOT, $CP) . block_for_name('example.com:53', $CP), 'nothing to do' ],

    # Item: neither CoreDNS ConfigMap name exists
    [ 'no CoreDNS ConfigMap under either name', undef, 'not closed by ocp apply',
      qr/found no CoreDNS ConfigMap in kube-system \(tried coredns, rke2-coredns-rke2-coredns\)/ ],
);

for my $case (@CASES) {
    my ($what, $corefile, $verdict, $cause, $does, $cm) = @$case;
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
            if ($does) {
                like $w->{died}, $does, 'the writer says what ocp apply does about it';
                like $p->{message}, $does, 'the probe says the same';
            }
            unlike $p->{message}, qr/ocp apply restores it/, 'and does not promise a restore';
            is $p->{kind}, 'spec', 'a spec entry';
            is $p->{remedy}, undef, 'with no remedy';
            ok $p->{manual_step}, 'it says what a human does instead';
            is $w->{written}, undef, 'nothing was written';
        }
    };
}

subtest 'the manual step names the block to fix, and where it is' => sub {
    my $p = probe(with_other_hosts(with_host($ROOT, $CP)) . block_for_name('registry.local:53', $CP));
    is $p->{manual_step},
        'Leave one hosts plugin in the root block of the Corefile in ConfigMap kube-system/coredns, then run ocp apply',
        'the root block of the Corefile';

    $p = probe(with_host($ROOT, $CP) . doubled_block('cluster.local:53'));
    is $p->{manual_step},
        'Leave one hosts plugin in the server block cluster.local:53 of the Corefile in ConfigMap'
        . ' kube-system/coredns, then run ocp apply',
        'another block of the Corefile';

    $p = probe(with_host($K3S, $CP), 'coredns-custom' => { 'example.server' => doubled_block('example.com:53') });
    is $p->{manual_step},
        'Leave one hosts plugin in the server block example.com:53 (ConfigMap kube-system/coredns-custom,'
        . ' key example.server), then run ocp apply',
        'a snippet, by its ConfigMap key';
};

subtest 'no CoreDNS ConfigMap: what the entry says' => sub {
    my $p = probe(undef);
    is $p->{component}, 'registry_dns', 'the registry_dns component';
    is $p->{expected}, $CP, 'expecting the control plane';
    is $p->{actual}, undef, 'nothing is there';
    like $p->{manual_step}, qr/CoreDNS ConfigMap in kube-system, then run ocp apply/, 'and what to do';

    is probe(undef, 'rke2-coredns-rke2-coredns' => { Corefile => with_host($ROOT, $CP) }), undef,
        'control: the RKE2 name with the record is no drift';
};

#
# The shadowing tail: "which that one shadows" only where there is a root
# block of the Corefile's own to shadow.
#

my $NONE    = qr/ocp apply writes the record only into the Corefile's own root block, and there is none/;
my $SHADOWS = qr/ocp apply writes the record only into the root block, which that one shadows/;

for my $case (
    [ 'a coredns-custom snippet brings the only root block, with a stale record',
      $CLUSTER_LOCAL . $IMPORT, 0,
      { 'coredns-custom' => { 'root.server' => block_for_name('.:53', $OLD) } } ],
    [ 'no root block, a block of its own with a stale record',
      $CLUSTER_LOCAL . block_for_name('registry.local:53', $OLD), 0 ],
    [ 'a root block shadowed by a stale block of its own: both sides word it alike',
      with_host($ROOT, $CP) . block_for_name('registry.local:53', $OLD), 1 ],
) {
    my ($what, $corefile, $has_root, $cm) = @$case;
    my $tail = $has_root ? $SHADOWS : $NONE;
    subtest $what => sub {
        my $w = writer($corefile, %{ $cm // {} });
        my $p = probe($corefile, %{ $cm // {} });
        like $w->{died}, $tail, 'the writer says it';
        like $p->{message}, $tail, 'and so does the probe';
        return if $has_root;
        unlike $w->{died}, qr/shadows/, 'the writer claims no shadowing';
        unlike $p->{message}, qr/shadows/, 'nor does the probe';
    };
}

#
# One reading, not two that happen to agree: if either side counts hosts
# plugins its own way again, only one of them follows the override.
#

subtest 'the writer and the probe find a doubled block through OCP::Corefile' => sub {
    plan skip_all => 'OCP::Corefile has no doubled_hosts_block' unless OCP::Corefile->can('doubled_hosts_block');
    my $corefile = with_host($ROOT, $CP);
    is writer_verdict(writer($corefile)), 'nothing to do', 'control: the record in place';

    no warnings 'redefine';
    local *OCP::Corefile::doubled_hosts_block = sub { $_[0]->blocks->[0] };   # the first block, always

    is writer_verdict(writer($corefile)), 'not closed by ocp apply', 'the writer follows it';
    is probe_verdict(probe($corefile)),   'not closed by ocp apply', 'and so does the probe';
};

subtest 'OCP::Corefile doubled_hosts_block' => sub {
    ok(OCP::Corefile->can('doubled_hosts_block'), 'OCP::Corefile has doubled_hosts_block')
        or return;

    is(OCP::Corefile->new(text => with_host($ROOT, $CP) . block_for_name('registry.local:53', $CP))
        ->doubled_hosts_block, undef, 'one hosts plugin per block: none');

    my $cf = OCP::Corefile->new(text => $ROOT . doubled_block('a.example:53') . doubled_block('b.example:53'));
    is_deeply $cf->doubled_hosts_block->{keys}, ['a.example:53'], 'the first doubled block in the file';

    $cf = OCP::Corefile->new(text => $ROOT . doubled_block('tls://registry.local:853'));
    is_deeply $cf->doubled_hosts_block->{keys}, ['tls://registry.local:853'],
        'a block that answers nothing the cluster asks counts too';

    $cf = OCP::Corefile->new(text => $K3S,
        imports => { '/etc/coredns/custom/x.server' => doubled_block('example.com:53') });
    is $cf->doubled_hosts_block->{file}, '/etc/coredns/custom/x.server', 'and an imported one';

    is(OCP::Corefile->new(text => $K3S)->doubled_hosts_block, undef, 'which the text alone does not have');

    $cf = OCP::Corefile->new(text => "example.com:53 {\n    hosts {\n        1.2.3.4 a\n    }\n"
        . "    forward . 1.1.1.1 {\n        hosts_file x\n    }\n}\n");
    is $cf->doubled_hosts_block, undef, 'a line inside another plugin\'s block is no hosts plugin';
};

done_testing;

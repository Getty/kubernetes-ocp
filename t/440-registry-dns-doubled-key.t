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
# k440: two server blocks with the same key -- two .:53, or a coredns-custom
# snippet .:53 next to the Corefile's own -- are a Corefile CoreDNS rejects
# ("cannot serve dns://.:53 - it is already defined"). OCP::Corefile's
# block_for takes the first on that tie (t/338), so the registry.local writer
# wrote its record into the first block and the probe read it back from
# there: "configured", "no drift", and nothing resolved. Now both name the
# key and the two blocks, the writer writes nothing, and the probe gives a
# spec entry with a manual step: ocp apply adds and removes no server block.
#

my $CP = '10.230.30.155';

my $CWD = getcwd();
like $INC{'OCP/Drift.pm'}, qr{\A(?:\Q$CWD\E/)?lib/OCP/Drift\.pm\z},
    'OCP::Drift comes from the tree under test';
like $INC{'OCP/Corefile.pm'}, qr{\A(?:\Q$CWD\E/)?lib/OCP/Corefile\.pm\z},
    'and so does OCP::Corefile';

# The root block of the stock k3s Corefile, cut to what matters here, with
# the record already in it: the writer has nothing to add
my $ROOT = <<"COREFILE";
.:53 {
    errors
    hosts /etc/coredns/NodeHosts {
        $CP registry.local
        ttl 60
        reload 15s
        fallthrough
    }
    kubernetes cluster.local in-addr.arpa ip6.arpa
    forward . /etc/resolv.conf
}
COREFILE

my $K3S = $ROOT . "import /etc/coredns/custom/*.server\n";

# A server block for $keys, with a bind plugin for @bind when given
sub block {
    my ($keys, @bind) = @_;
    return "$keys {\n" . (@bind ? "    bind @bind\n" : '') . "    forward . 1.1.1.1\n}\n";
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

sub cms {
    my ($corefile, %cm) = @_;
    return (coredns => { Corefile => $corefile }, %cm);
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

my $SNIPPET  = 'ConfigMap kube-system/coredns-custom';
my $REJECTED = qr/\Q(a running CoreDNS keeps serving its previous Corefile, a restarted one does not start)\E/;

my @REJECTED_COREFILES = (
    # [ what, Corefile, where both sides say the key stands twice, coredns-custom ]
    [ 'two .:53 blocks in the Corefile, the record in the first',
      $ROOT . block('.:53'),
      qr/defines server block key \.:53 twice, in two server blocks \.:53 \(/ ],
    [ 'the same key written two ways: .:53 and dns://.',
      $ROOT . block('dns://.'),
      qr/defines server block key dns:\/\/\. twice, in the server block \.:53 and the server block dns:\/\/\./ ],
    [ 'a second root block written as .',
      $ROOT . block('.'),
      qr/key \. twice, in the server block \.:53 and the server block \./ ],
    [ 'a coredns-custom snippet .:53 next to the Corefile\'s own',
      $K3S, qr/key \.:53 twice, in the server block \.:53 and the server block \.:53 \(\Q$SNIPPET\E, key extra\.server\)/,
      { 'coredns-custom' => { 'extra.server' => block('.:53') } } ],
    [ 'two snippets for the same zone',
      $K3S, qr/key example\.com:53 twice, in the server block example\.com \(\Q$SNIPPET\E, key a\.server\) and the server block example\.com:53 \(\Q$SNIPPET\E, key b\.server\)/,
      { 'coredns-custom' => { 'a.server' => block('example.com'), 'b.server' => block('example.com:53') } } ],
    [ 'one header listing the key twice',
      $ROOT . block('example.com example.com.:53'),
      qr/key example\.com\.:53 twice, in the header of the server block example\.com example\.com\.:53/ ],
    [ 'two blocks on another port: CoreDNS sets them up all the same',
      $ROOT . block('.:5353') . block('.:5353'),
      qr/key \.:5353 twice, in two server blocks \.:5353/ ],
    [ 'the same bind address in both',
      $ROOT . block('example.com', '10.0.0.1') . block('example.com', '10.0.0.2 10.0.0.1'),
      qr/key example\.com twice/ ],
    [ 'one bound, one listening on every address',
      $ROOT . block('example.com', '10.0.0.1') . block('example.com'),
      qr/key example\.com twice/ ],
);

for my $case (@REJECTED_COREFILES) {
    my ($what, $corefile, $where, $cm) = @$case;
    my %cm = %{ $cm // {} };

    subtest $what => sub {
        my $w = writer($corefile, %cm);
        like $w->{died}, qr/\AConfigMap kube-system\/coredns: CoreDNS rejects its Corefile, as it /,
            'the writer stops, saying CoreDNS rejects the Corefile';
        like $w->{died}, $where, 'and names the key and both blocks';
        like $w->{died}, $REJECTED, 'and what CoreDNS does with it, running or restarted';
        like $w->{died}, qr/; ocp apply leaves it as it is\n\z/, 'and that ocp apply leaves it';
        is $w->{written}, undef, 'nothing was written';

        my $p = probe($corefile, %cm);
        ok $p, 'the probe reports it';
        is $p->{kind}, 'spec', 'as a spec entry';
        is $p->{remedy}, undef, 'with no remedy';
        is $p->{actual}, undef, 'no address read from it';
        like $p->{message}, qr/\Aregistry\.local does not resolve from the CoreDNS Corefile \(expected \Q$CP\E\): CoreDNS rejects it, as it /,
            'the message says nothing resolves and why';
        like $p->{message}, $where, 'naming the same key and blocks as the writer';
        like $p->{message}, $REJECTED, 'and saying the same of what CoreDNS does with it';
        unlike $p->{message}, qr/ocp apply restores it/, 'and does not promise a restore';
        ok !OCP::Drift->apply_closes($p), 'ocp apply does not close it';
        like $p->{manual_step}, qr/\ALeave server block key \S+ in one server block only .*ConfigMap kube-system\/coredns\b.*then run ocp apply\z/,
            'the manual step says what a human does';
    };
}

my @FINE = (
    [ 'control: one root block, another zone', $ROOT . block('example.com:53') ],
    [ 'control: the root zone on another port', $ROOT . block('.:5353') ],
    [ 'control: the same zone bound to separate addresses',
      $ROOT . block('example.com', '10.0.0.1') . block('example.com', '10.0.0.2') ],
    [ 'control: a k3s snippet for another zone',
      $K3S, { 'coredns-custom' => { 'extra.server' => block('example.com:53') } } ],
);

for my $case (@FINE) {
    my ($what, $corefile, $cm) = @$case;
    my %cm = %{ $cm // {} };

    subtest $what => sub {
        my $w = writer($corefile, %cm);
        is $w->{died}, '', 'the writer does not stop';
        is $w->{rv}, 0, 'the record is already there';
        is probe($corefile, %cm), undef, 'and the probe finds nothing';
    };
}

subtest 'OCP::Corefile listener' => sub {
    my $cf = OCP::Corefile->new(text => '');
    is $cf->listener($_), 'dns://.:53', "$_: dns://.:53" for '.', '.:53', 'dns://.', 'dns://.:53', 'DNS://.:53';
    is $cf->listener($_), 'dns://example.com:53', "$_: dns://example.com:53"
        for 'example.com', 'Example.COM.', 'example.com.:53';
    is $cf->listener('.:5353'), 'dns://.:5353', 'another port';
    is $cf->listener('tls://.'), 'tls://.:853', 'another transport, its default port';
};

subtest 'OCP::Corefile doubled_key' => sub {
    is +OCP::Corefile->new(text => $ROOT)->doubled_key, undef, 'one block: none';

    my $twice = OCP::Corefile->new(text => $ROOT . block('.'))->doubled_key;
    is $twice->{key}, '.', 'the key as the second block writes it';
    is_deeply [ map { $_->{from} } @{ $twice->{blocks} } ], [ 0, 11 ], 'the two blocks in file order';

    # The tie rule block_for keeps (t/338): the first block answers. That is
    # the reading doubled_key stands in front of.
    is +OCP::Corefile->new(text => $ROOT . block('.'))->root_block->{from}, 0,
        'block_for still takes the first on a tie';
};

done_testing;

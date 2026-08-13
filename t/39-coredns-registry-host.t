#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP::Cmd::Apply;
use OCP::Config;
use OCP::Drift;

#
# CoreDNS accepts the hosts plugin only once per server block. k3s ships a
# Corefile that already runs it for /etc/coredns/NodeHosts, so the block OCP
# used to splice in for registry.local was a second one — CoreDNS refused to
# start ("plugin/hosts: this plugin can only be used once per Server Block")
# and cluster DNS was dead after every `ocp apply` on k3s.
#
# Both fixtures are the real thing: the k3s one is what k3s v1.36.3+k3s1 puts
# in the coredns ConfigMap, the RKE2 one is what the rke2-coredns chart
# renders. RKE2 has no hosts plugin at all, which is why the bug never showed
# there.
#

my $K3S_COREFILE = <<'COREFILE';
.:53 {
    errors
    health
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
      pods insecure
      fallthrough in-addr.arpa ip6.arpa
    }
    hosts /etc/coredns/NodeHosts {
      ttl 60
      reload 15s
      fallthrough
    }
    prometheus :9153
    cache 30
    loop
    reload
    loadbalance
    import /etc/coredns/custom/*.override
    forward . /etc/resolv.conf
}
import /etc/coredns/custom/*.server
COREFILE

my $RKE2_COREFILE = <<'COREFILE';
.:53 {
    errors
    health  {
        lameduck 5s
    }
    ready
    kubernetes   cluster.local  in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    prometheus   0.0.0.0:9153
    forward   . /etc/resolv.conf
    cache   30
    loop
    reload
    loadbalance
}
COREFILE

sub with_host {
    my ($corefile, $ip) = @_;
    return OCP::Cmd::Apply::_corefile_with_host($corefile, $ip, 'registry.local');
}

# Plugin lines of the root server block, one brace level deep
sub root_plugins {
    my ($corefile) = @_;

    my @plugin;
    my $depth = 0;
    for my $line (split /\n/, $corefile) {
        my $opens  = () = $line =~ /\{/g;
        my $closes = () = $line =~ /\}/g;
        push @plugin, $line if $depth == 1 && $line =~ /\S/;
        $depth += $opens - $closes;
    }
    return @plugin;
}

subtest 'k3s: the record joins the hosts plugin that is already there' => sub {
    my $out = with_host($K3S_COREFILE, '10.230.30.155');

    my @hosts = grep { /^\s*hosts\b/ } root_plugins($out);
    is scalar(@hosts), 1,
        'still exactly one hosts plugin — a second one is the crash';

    like $hosts[0], qr{hosts /etc/coredns/NodeHosts \{},
        'k3s keeps its NodeHosts file, which its own controller writes';

    like $out, qr{hosts /etc/coredns/NodeHosts \{\n\s+10\.230\.30\.155 registry\.local\n},
        'registry.local is an inline entry inside that block';

    like $out, qr/ttl 60/,     'the options of the existing block survive';
    like $out, qr/reload 15s/, 'including the file reload interval';

    like $out, qr{import /etc/coredns/custom/\*\.server},
        'the import outside the server block is untouched';
};

subtest 'rke2: a Corefile without a hosts plugin gets one' => sub {
    my $out = with_host($RKE2_COREFILE, '10.0.0.5');

    my @hosts = grep { /^\s*hosts\b/ } root_plugins($out);
    is scalar(@hosts), 1, 'exactly one hosts plugin';

    like $out, qr{hosts \{\n\s+10\.0\.0\.5 registry\.local\n\s+fallthrough\n\s+\}},
        'a block of its own, falling through for every other name';

    like $out, qr/^\s{4}hosts \{/m,
        'indented like the plugins around it';

    for my $plugin (qw(errors ready kubernetes prometheus forward cache loop reload loadbalance)) {
        like $out, qr/^\s*\Q$plugin\E\b/m, "$plugin is still configured";
    }
};

subtest 'applying it twice changes nothing' => sub {
    for my $case ([k3s => $K3S_COREFILE, '10.230.30.155'], [rke2 => $RKE2_COREFILE, '10.0.0.5']) {
        my ($name, $corefile, $ip) = @$case;

        my $once  = with_host($corefile, $ip);
        my $twice = with_host($once, $ip);

        is $twice, $once, "$name: second run is a no-op";
    }
};

#
# `ocp apply` re-runs against a cluster whose control plane may have moved.
# Leaving the old address in place would point every pod at a node that no
# longer serves the registry.
#

subtest 'a moved control plane updates the address in place' => sub {
    for my $case ([k3s => $K3S_COREFILE], [rke2 => $RKE2_COREFILE]) {
        my ($name, $corefile) = @$case;

        my $old = with_host($corefile, '10.230.30.155');
        my $new = with_host($old, '192.168.1.10');

        like $new, qr/^\s*192\.168\.1\.10 registry\.local$/m,
            "$name: the new address is there";
        unlike $new, qr/10\.230\.30\.155/, "$name: the old one is gone";

        my @hosts = grep { /^\s*hosts\b/ } root_plugins($new);
        is scalar(@hosts), 1, "$name: no second hosts plugin was added";
    }
};

#
# Verbatim from cortex (k3s v1.36.3+k3s1) after an `ocp apply` that shipped
# the bug — CoreDNS was in CrashLoopBackOff with this in the ConfigMap. Note
# where the indentation went: the old patch spliced itself between health and
# ready. Re-running apply has to repair such a cluster, not read its own
# leftover record as "already configured" and leave DNS dead.
#

my $BROKEN_COREFILE = <<'COREFILE';
.:53 {
    errors
    health
      hosts {
        10.230.30.155 registry.local
        fallthrough
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
      pods insecure
      fallthrough in-addr.arpa ip6.arpa
    }
    hosts /etc/coredns/NodeHosts {
      ttl 60
      reload 15s
      fallthrough
    }
    prometheus :9153
    cache 30
    loop
    reload
    loadbalance
    import /etc/coredns/custom/*.override
    forward . /etc/resolv.conf
}
import /etc/coredns/custom/*.server
COREFILE

subtest 'a cluster the bug already broke is repaired' => sub {
    my $out = with_host($BROKEN_COREFILE, '10.230.30.155');

    my @hosts = grep { /^\s*hosts\b/ } root_plugins($out);
    is scalar(@hosts), 1, 'the block that broke CoreDNS is gone';
    like $hosts[0], qr{hosts /etc/coredns/NodeHosts \{},
        'and the one k3s brought is the one that stayed';

    like $out, qr/^\s+10\.230\.30\.155 registry\.local$/m,
        'the record survives, inside that block now';

    is $out, with_host($K3S_COREFILE, '10.230.30.155'),
        'the result is what a cluster that never saw the bug gets';
};

subtest 'a Corefile it cannot place the record in is left alone' => sub {
    my $no_block = "# nothing to patch here\n";
    is with_host($no_block, '10.0.0.5'), $no_block, 'no server block, no change';
};

#
# k3s (like stock Kubernetes) calls the ConfigMap "coredns"; RKE2 installs
# CoreDNS from a Helm chart and calls it rke2-coredns-rke2-coredns. Looking
# only for "coredns" makes this whole step a silent no-op on RKE2.
#

subtest 'the ConfigMap is looked up under both names' => sub {
    my @names = @OCP::Cmd::Apply::COREDNS_CONFIGMAPS;

    ok((grep { $_ eq 'coredns' } @names), 'k3s / stock Kubernetes');
    ok((grep { $_ eq 'rke2-coredns-rke2-coredns' } @names), 'RKE2');

    is_deeply \@names, \@OCP::Drift::COREDNS_CONFIGMAPS,
        'writer and drift probe read the same list, so they cannot look in different places';
};

#
# Drift on the record.
#
# Neither distribution lets OCP own the Corefile: k3s' addon manager restores
# its own whenever it re-applies the coredns addon (an upgrade, a server
# restart — seen on cortex), RKE2's belongs to the rke2-coredns Helm release.
# `ocp apply` writes the record back, so the cluster heals on the next run —
# but between the reset and that run registry.local does not resolve and
# nothing said so. Nothing breaks loudly either: image pulls for
# registry.local go through the containerd mirror to localhost:30501 and never
# ask DNS. That is exactly the kind of gap a drift probe is for.
#

package FakeApi {
    sub new { my ($class, %args) = @_; bless { %args }, $class }

    sub get {
        my ($self, $kind, %args) = @_;
        my $key = join '/', $kind, $args{namespace} // '', $args{name} // '';
        my $obj = $self->{objects}{$key};
        die "$kind $args{name} not found\n" unless $obj;
        return $obj;
    }

    sub list { return { items => [] } }
}

# Enough of the API for _configure_registry_dns to run for real: one ConfigMap
# to read, and a server-side apply that records what it was given.
package WriterCm  { sub new { my ($c, $d) = @_; bless { data => $d }, $c } sub data { $_[0]{data} } }
package WriterRes { sub new { bless {}, shift } sub status { 200 } sub content { '{}' } }
package WriterApi {
    sub new          { my ($c, %a) = @_; bless { applied => [], %a }, $c }
    sub get          { $_[0]{cm} }
    sub expand_class { undef }
    sub _request     { my ($self, undef, undef, $body) = @_;
                       push @{ $self->{applied} }, $body; return WriterRes->new }
}

package main;

my $SPEC = <<'YAML';
name: testcluster
kubernetes:
  distribution: k3s
control_planes:
  provider: hetzner
  server_type: cx32
YAML

# A project with a control plane recorded in .ocp/status.yaml
sub config_at {
    my ($ip) = @_;

    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('ocp.yaml')->spew_utf8($SPEC);
    path($dir)->child('.ocp')->mkpath;
    path($dir)->child('.ocp', 'status.yaml')->spew_utf8(<<"YAML");
nodes:
  - name: cortex
    role: control-plane
    public_ip: $ip
YAML

    return OCP::Config->new(file => path($dir)->child('ocp.yaml')->stringify);
}

# cortex, verbatim: an ssh control plane named by DNS and no node status yet,
# so OCP::Config::cluster_status hands the *name* back as the public_ip
sub config_named {
    my ($host) = @_;

    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('ocp.yaml')->spew_utf8(<<"YAML");
name: cortex
kubernetes:
  dist: k3s
control_planes:
  host: $host
  provider: ssh
YAML
    path($dir)->child('.ocp')->mkpath;
    path($dir)->child('.ocp', 'status.yaml')->spew_utf8("nodes: []\n");

    return OCP::Config->new(file => path($dir)->child('ocp.yaml')->stringify);
}

# One CoreDNS ConfigMap, under the name the given distribution uses
sub probe {
    my (%args) = @_;

    my $name = $args{name} // 'coredns';
    my $api  = FakeApi->new(objects => {
        defined $args{corefile}
            ? ("ConfigMap/kube-system/$name" => { data => { Corefile => $args{corefile} } })
            : (),
    });

    my $config = $args{config} // config_at($args{ip} // '10.230.30.155');

    return OCP::Drift->new(config => $config, api => $api)->registry_dns_drift;
}

# What `ocp apply` actually writes, through the real code path
sub written_corefile {
    my ($corefile, $from) = @_;

    my $apply = bless {}, 'OCP::Cmd::Apply';
    my $api = WriterApi->new(cm => WriterCm->new({ Corefile => $corefile }));
    $apply->{_k8s_api} = $api;

    my $noise = '';
    {
        open my $fh, '>', \$noise or die $!;
        local *STDOUT = $fh;
        $apply->_configure_registry_dns($from);
    }

    return $api->{applied}[0] ? $api->{applied}[0]{data}{Corefile} : $corefile;
}

subtest 'the probe reads back exactly what the patch wrote' => sub {
    for my $case ([k3s => $K3S_COREFILE], [rke2 => $RKE2_COREFILE], [broken => $BROKEN_COREFILE]) {
        my ($name, $corefile) = @$case;

        is OCP::Drift::corefile_host_address(with_host($corefile, '10.230.30.155'), 'registry.local'),
            '10.230.30.155', "$name: the record the writer placed is the one the reader finds";
    }

    for my $case ([k3s => $K3S_COREFILE], [rke2 => $RKE2_COREFILE]) {
        my ($name, $corefile) = @$case;

        is OCP::Drift::corefile_host_address($corefile, 'registry.local'), undef,
            "$name: a Corefile without the record reads as having none";
    }
};

subtest 'plugin lines are not mistaken for records' => sub {
    # `cache 30`, `ttl 60`, `reload 15s`: two tokens, first one not an address
    is OCP::Drift::corefile_host_address($K3S_COREFILE, 'registry.local'), undef,
        'the stock k3s Corefile maps nothing';
    is OCP::Drift::corefile_host_address($K3S_COREFILE, 'cortex'), undef,
        'and NodeHosts lives in its own ConfigMap key, not in the Corefile';
};

subtest 'a Corefile the distribution reset is drift' => sub {
    my $drift = probe(corefile => $K3S_COREFILE);

    ok $drift, 'the missing record is reported';
    is $drift->{kind}, 'missing', 'kind is missing, not spec';
    is $drift->{component}, 'registry_dns', 'names the component';
    is $drift->{expected}, '10.230.30.155', 'expects the control plane address';
    is $drift->{actual}, undef, 'nothing is there';
    is $drift->{remedy}, undef, 'no Rex task fixes this';
    like $drift->{message}, qr/registry\.local is missing from the CoreDNS Corefile/,
        'says what is wrong';
    like $drift->{message}, qr/ocp apply restores it/,
        'and what puts it back, since no remedy runs by itself';
};

subtest 'the record OCP wrote is not drift' => sub {
    is probe(corefile => with_host($K3S_COREFILE, '10.230.30.155')), undef,
        'k3s: patched Corefile is clean';
    is probe(corefile => with_host($RKE2_COREFILE, '10.230.30.155'),
             name     => 'rke2-coredns-rke2-coredns'), undef,
        'rke2: found under the Helm chart name too';
};

subtest 'a record left on the old node is drift as well' => sub {
    my $drift = probe(corefile => with_host($K3S_COREFILE, '192.168.1.10'));

    ok $drift, 'a stale address is reported';
    is $drift->{actual}, '192.168.1.10', 'the address the cluster answers with';
    is $drift->{expected}, '10.230.30.155', 'the address it should answer with';
    like $drift->{message}, qr/resolves to 192\.168\.1\.10, expected 10\.230\.30\.155/,
        'both addresses are in the message';
};

#
# k3s mounts a `coredns-custom` ConfigMap at /etc/coredns/custom (optional,
# verified on the live deployment) and imports `*.server` from it outside the
# root block. A cluster that solved this by hand that way resolves the name
# perfectly well, and must not be reported as drifted.
#
subtest 'a record in a server block of its own counts' => sub {
    my $corefile = $K3S_COREFILE . <<'SNIPPET';
registry.local:53 {
    hosts {
        10.230.30.155 registry.local
    }
}
SNIPPET

    is probe(corefile => $corefile), undef, 'answered is answered, wherever the record sits';
};

subtest 'what the probe stays quiet about' => sub {
    is probe(corefile => undef), undef,
        'no CoreDNS ConfigMap under a name we know: not this probe s business';

    my $api = FakeApi->new(objects => {
        'ConfigMap/kube-system/coredns' => { data => { Corefile => $K3S_COREFILE } },
    });
    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('ocp.yaml')->spew_utf8($SPEC);
    my $unprovisioned = OCP::Config->new(file => path($dir)->child('ocp.yaml')->stringify);

    is(OCP::Drift->new(config => $unprovisioned, api => $api)->registry_dns_drift, undef,
        'no control plane address recorded yet: nothing to compare against');
};

#
# The address has one derivation, not two.
#
# cortex is reached as cortex.ai.citilan.de and answers on 10.230.30.155, and
# its .ocp/status.yaml records no nodes — so cluster_status hands the *name*
# back as the public_ip. A Corefile can only carry an address: `ocp apply`
# resolves the name before writing it. The first version of this probe
# compared the unresolved name against the written address and reported
#
#     [drift] registry.local resolves to 10.230.30.155, expected cortex.ai.citilan.de
#
# on a cluster that was configured correctly — on every `ocp status`, forever.
#
# The fixtures below could not see it, because they carried the same IP on
# both sides. A control plane whose name differs from its address is the
# normal case, not the exception, so that is what these drive.
#
# Overriding the shared resolver is the point of the test, not a shortcut
# around DNS: if either side ever grows its own copy of the resolution again,
# only one of them follows the override and these fail. The name stands in for
# cortex.ai.citilan.de and is deliberately one that cannot resolve anywhere
# (RFC 2606), so what the tests measure is the shared derivation and never the
# DNS of the machine they run on — a re-inlined lookup fails here even where
# the real name happens to resolve.
#

my %HOSTS = ('cortex.ocp.invalid' => '10.230.30.155');

sub with_dns (&) {
    my ($code) = @_;
    no warnings 'redefine';
    local *OCP::Drift::resolve_address = sub {
        my ($value) = @_;
        return undef unless defined $value && length $value;
        return $value if $value =~ /^\d+\.\d+\.\d+\.\d+$/;
        return $HOSTS{$value};
    };
    return $code->();
}

subtest 'a control plane named by DNS is not drift' => sub {
    with_dns {
        my $written = written_corefile($K3S_COREFILE, 'cortex.ocp.invalid');

        like $written, qr/^\s+10\.230\.30\.155 registry\.local$/m,
            'the writer resolves the name and writes the address';

        is probe(corefile => $written, config => config_named('cortex.ocp.invalid')), undef,
            'and the probe, from the same starting value, finds nothing wrong';
    };
};

subtest 'real drift still surfaces behind a DNS name' => sub {
    with_dns {
        my $config = config_named('cortex.ocp.invalid');

        my $gone = probe(corefile => $K3S_COREFILE, config => $config);
        ok $gone, 'a Corefile the distribution reset is still reported';
        is $gone->{expected}, '10.230.30.155',
            'and the expectation is stated as an address, not as the name';
        is $gone->{actual}, undef, 'nothing is there';

        my $stale = probe(corefile => with_host($K3S_COREFILE, '192.168.1.10'), config => $config);
        ok $stale, 'so is a record left on the old node';
        is $stale->{actual}, '192.168.1.10', 'the address the cluster answers with';
        is $stale->{expected}, '10.230.30.155', 'the address it should answer with';
    };
};

subtest 'resolve_address' => sub {
    is OCP::Drift::resolve_address('10.230.30.155'), '10.230.30.155',
        'an address passes through untouched';
    is OCP::Drift::resolve_address('localhost'), '127.0.0.1',
        'a name becomes an address (from /etc/hosts, no network)';
    is OCP::Drift::resolve_address(undef), undef, 'undef is handled';
    is OCP::Drift::resolve_address(''), undef, 'so is empty';
};

subtest 'detect wires the probe in' => sub {
    my $api = FakeApi->new(objects => {
        'ConfigMap/kube-system/coredns' => { data => { Corefile => $K3S_COREFILE } },
    });

    my $drift = OCP::Drift->new(config => config_at('10.230.30.155'), api => $api)->detect;

    ok((grep { $_->{component} eq 'registry_dns' } @$drift),
        'ocp status sees it, not just a direct call');
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Node::Add;
use OCP::SSH;

# k238 (lab round 10, #236a finding B): `ocp node add --host NAME` created the
# OCPNode BEFORE looking at NAME, so a name that does not resolve left a Failed
# OCPNode in the cluster ("nothing changed" held for the machine, not for the
# cluster). Decision: with robocop off (CLI path) the host is checked before any
# cluster write -- 1 resolution (_resolves_here; IPs are not resolved), 2 then,
# without --nowait, the SSH probe (_host_probe_ssh) -- and a failure refuses with
# the OCP::SSH message, exit 1, no OCPNode. With robocop on the OCPNode stays the
# request (robocop resolves in the cluster, k236) and the hint is all there is.
#
# Seams assumed (the implementer provides them):
#   OCP::Cmd::Node::Add::_preflight_host($self, $provider_type)
#   OCP::Cmd::Node::Add::_host_probe_ssh($self, $host)  -- dies with the message
# Refusal contract: execute returns 1 or dies with a "\n"-terminated message
# (bin/ocp prints that); both are read as "exit 1, message on STDERR" below.
# No network, no DNS, no SSH: everything is stubbed.

{ package FakeList; sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
{ package FakeIO;   sub new { bless {}, $_[0] } sub object_to_struct { $_[1] } }
{
    package FakeK8s;
    my $io = FakeIO->new;
    sub new { my ($c, %a) = @_; bless { %a, calls => [], ensured => [], writes => [] }, $c }
    sub k8s { $io }
    sub list { my ($s, $kind) = @_; FakeList->new($kind eq 'OCPNodeProvider' ? $s->{providers} : []) }
    sub get {
        my ($s, $kind, %a) = @_;
        push @{ $s->{calls} }, [ get => $kind ];
        return $s->{providers}[0] if $kind eq 'OCPNodeProvider';
        return $s->{robocop_ready}
            ? { metadata => { name => 'robocop' }, status => { readyReplicas => 1 } } : undef
            if $kind eq 'Deployment';
        return undef;
    }
    # Every write is recorded, in the shared order log too.
    sub ensure {
        my ($s, $cr) = @_;
        push @{ $s->{ensured} }, $cr;
        push @{ $s->{order} }, 'ensure' if $s->{order};
        return $cr;
    }
    for my $w (qw( create update patch delete apply )) {
        no strict 'refs';
        *{$w} = sub { my $s = shift; push @{ $s->{writes} }, [ $w, @_ ]; undef };
    }
}

{ package FakeConfig; sub project_dir { '/nonexistent/project' } }

my $ssh_provider = {
    metadata => { name => 'ssh-a', namespace => 'ocp-system', annotations => {} },
    spec     => { type => 'ssh' },
};
my $local_provider = {
    metadata => { name => 'local-a', namespace => 'ocp-system', annotations => {} },
    spec     => { type => 'local' },
};

# Runs `node add`; returns a hashref: rc, out, err, k8s, order, probes, preflights.
sub add_host {
    my (%o) = @_;
    my @order;
    my $k8s = FakeK8s->new(
        providers     => [ $o{local} ? $local_provider : $ssh_provider ],
        robocop_ready => $o{robocop},
        order         => \@order,
    );
    my $add = OCP::Cmd::Node::Add->new(
        k8s  => $k8s,
        name => 'w1',
        ($o{host}   ? (host   => $o{host}) : ()),
        ($o{nowait} ? (nowait => 1)        : ()),
    );
    my (@probes, @preflights);
    my ($out, $err) = ('', '');
    my $rc;
    {
        no warnings 'redefine';
        local *OCP::Cmd::Node::Add::_resolves_here  = sub { push @order, 'resolve'; $o{resolves} ? 1 : 0 };
        local *OCP::Cmd::Node::Add::_etc_hosts_file = sub { '/nonexistent/hosts' };
        local *OCP::Cmd::Node::Add::_ssh_keys_note  = sub { '' };
        local *OCP::Cmd::Node::Add::_host_probe_ssh = sub {
            my ($self, $host) = @_;
            push @probes, $host;
            push @order, 'probe';
            # k238: rejection_message is an instance method (needs host/user), not a class method
            die OCP::SSH->new(host => $host, user => 'root')->rejection_message if $o{probe_fails};
            return 1;
        };
        local *OCP::Cmd::Node::Add::_config         = sub { bless {}, 'FakeConfig' };
        local *OCP::Cmd::Node::Add::_cli_reconcile  = sub { push @order, 'reconcile'; 1 };
        # case 7: record any call to the preflight instead of running it
        local *OCP::Cmd::Node::Add::_preflight_host = sub { push @preflights, [ @_[1 .. $#_] ]; 1 }
            if $o{spy_preflight};
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rc = eval { $add->execute([], []) };
        if ($@) {
            my $e = $@;
            # a stack trace / unexpected die is NOT the refusal contract
            $err .= (ref $e || $e !~ /\n\z/) ? "UNEXPECTED DIE: $e"
                  : $e;     # what bin/ocp prints for a refusal
            $rc = 1;
        }
    }
    return { rc => $rc, out => $out, err => $err, k8s => $k8s,
             order => \@order, probes => \@probes, preflights => \@preflights };
}

sub no_cluster_write {
    my ($r, $label) = @_;
    is scalar @{ $r->{k8s}{ensured} }, 0, "$label: no \$api->ensure (no OCPNode created)";
    is scalar @{ $r->{k8s}{writes} }, 0, "$label: no other cluster write either";
}

subtest '1: robocop off, name does not resolve: refused, nothing written' => sub {
    my $r = add_host(host => 'gibtsnicht.lab', robocop => 0, resolves => 0);
    is $r->{rc}, 1, 'exit 1';
    like $r->{err}, qr/Name 'gibtsnicht\.lab' does not resolve/, 'STDERR names the host';
    like $r->{err}, qr/on this machine/, 'CLI wording (lookup failed on this machine)';
    unlike $r->{err}, qr/UNEXPECTED DIE/, 'a refusal, not a stack trace';
    no_cluster_write($r, 'refusal');
    is $r->{out}, '', 'STDOUT empty: no node name';
};

subtest '2: same with --nowait' => sub {
    my $r = add_host(host => 'gibtsnicht.lab', robocop => 0, resolves => 0, nowait => 1);
    is $r->{rc}, 1, 'exit 1';
    like $r->{err}, qr/Name 'gibtsnicht\.lab' does not resolve.*on this machine/s, 'message on STDERR';
    unlike $r->{err}, qr/UNEXPECTED DIE/, 'a refusal, not a stack trace';
    no_cluster_write($r, '--nowait');
    is $r->{out}, '', 'STDOUT empty';
    is_deeply $r->{probes}, [], 'no SSH probe with --nowait';
};

subtest '3: robocop off, resolves, SSH probe fails: refused, nothing written' => sub {
    my $r = add_host(host => 'crag.lab', robocop => 0, resolves => 1, probe_fails => 1);
    is $r->{rc}, 1, 'exit 1';
    is_deeply $r->{probes}, ['crag.lab'], 'the probe ran, on the host';
    like $r->{err}, qr/crag\.lab/, 'the probe message is on STDERR';
    unlike $r->{err}, qr/UNEXPECTED DIE/, 'a refusal, not a stack trace';
    no_cluster_write($r, 'probe failure');
    is $r->{out}, '', 'STDOUT empty';
};

subtest '4: robocop off, resolves, probe ok: OCPNode is created' => sub {
    my $r = add_host(host => 'crag.lab', robocop => 0, resolves => 1, nowait => 1);
    is $r->{rc}, 0, 'exit 0';
    is scalar @{ $r->{k8s}{ensured} }, 1, 'ensure exactly once';
    is $r->{k8s}{ensured}[0]{kind}, 'OCPNode', 'it is the OCPNode';
    is $r->{k8s}{ensured}[0]{spec}{host}, 'crag.lab', 'host went to spec';
    is $r->{out}, "w1\n", 'STDOUT is the node name';
    is_deeply $r->{probes}, [], '--nowait: no SSH probe';
    is_deeply [ grep { $_ eq 'resolve' || $_ eq 'ensure' } @{ $r->{order} } ],
        [ 'resolve', 'ensure' ], 'resolution was checked before ensure';

    my $w = add_host(host => 'crag.lab', robocop => 0, resolves => 1);
    is $w->{rc}, 0, 'without --nowait: exit 0';
    is scalar @{ $w->{k8s}{ensured} }, 1, 'ensure exactly once';
    is_deeply $w->{probes}, ['crag.lab'], 'the SSH probe ran';
    is_deeply [ grep { /^(resolve|probe|ensure)$/ } @{ $w->{order} } ],
        [ 'resolve', 'probe', 'ensure' ], 'order: resolve, probe, then ensure';
};

subtest '5: robocop on, name does not resolve: OCPNode is the request' => sub {
    my $r = add_host(host => 'crag.lab', robocop => 1, resolves => 0, nowait => 1);
    is $r->{rc}, 0, 'exit 0, no local abort';
    is scalar @{ $r->{k8s}{ensured} }, 1, 'ensure exactly once';
    like $r->{err}, qr/robocop resolves it inside the cluster/, 'the k236 hint on STDERR';
    unlike $r->{err}, qr/does not resolve: the lookup failed on this machine/, 'no refusal wording';
    is $r->{out}, "w1\n", 'STDOUT is the node name';
    is_deeply $r->{probes}, [], 'no local SSH probe';
};

subtest '6: an IP as --host is not resolved' => sub {
    my $r = add_host(host => '10.0.0.9', robocop => 0, resolves => 0, nowait => 1);
    is $r->{rc}, 0, 'no abort even though the lookup would say no';
    is scalar @{ $r->{k8s}{ensured} }, 1, 'ensure exactly once';
    ok !(grep { $_ eq 'resolve' } @{ $r->{order} }), '_resolves_here was never asked';
    is $r->{out}, "w1\n", 'STDOUT is the node name';
};

subtest '7: no --host: no preflight, ensure as before' => sub {
    my $r = add_host(local => 1, robocop => 0, nowait => 1, spy_preflight => 1);
    is $r->{rc}, 0, 'exit 0';
    is_deeply $r->{preflights}, [], '_preflight_host not called';
    is_deeply $r->{probes}, [], 'no probe';
    ok !(grep { $_ eq 'resolve' } @{ $r->{order} }), 'no resolution';
    is scalar @{ $r->{k8s}{ensured} }, 1, 'ensure exactly once';
};

done_testing;

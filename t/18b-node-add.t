#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();

use lib 'lib';

use OCP::Cmd::Node::Add;
# Loaded by the command anyway; named here because the budget assertions below
# read $OCP::Node::READY_TIMEOUT straight out of it.
use OCP::Node;

sub capture_stdout (&) {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die "open stdout capture: $!";
    local *STDOUT = $fh;
    $code->();
    return $out;
}

sub capture_stderr (&) {
    my ($code) = @_;
    my $err = '';
    open my $fh, '>', \$err or die "open stderr capture: $!";
    local *STDERR = $fh;
    $code->();
    return $err;
}

{
    package FakeList;
    sub new   { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]->{items} }
}

{
    package FakeIO;
    sub new              { bless {}, $_[0] }
    sub object_to_struct { $_[1] }
}

{
    package FakeK8sA;

    my $_io = FakeIO->new;

    sub new {
        my ($class, %args) = @_;
        return bless {
            providers     => $args{providers}     // [],
            deployments   => $args{deployments}   // {},
            calls         => [],
            get_nodes     => $args{get_nodes}     // {},
        }, $class;
    }

    sub k8s { $_io }

    sub list {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['list', $kind, \%args];
        return FakeList->new($self->{providers}) if $kind eq 'OCPNodeProvider';
        return FakeList->new([]);
    }

    sub get {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['get', $kind, \%args];
        my $name = $args{name} // '';

        if ($kind eq 'OCPNodeProvider') {
            for my $p (@{ $self->{providers} }) {
                return $p if $p->{metadata}{name} eq $name;
            }
            die "404: not found OCPNodeProvider/$name\n";
        }

        if ($kind eq 'Deployment') {
            return $self->{deployments}{$name};
        }

        if ($kind eq 'OCPNode') {
            return $self->{get_nodes}{$name};
        }

        return undef;
    }

    sub ensure {
        my ($self, $obj) = @_;
        push @{$self->{calls}}, ['ensure', $obj];
        return $obj;
    }

    sub patch {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['patch', $kind, \%args];
        return {};
    }
}

my $hetzner_provider = {
    metadata => { name => 'hetzner-a', namespace => 'ocp-system', annotations => {} },
    spec     => { type => 'hetzner', hetzner => { location => 'fsn1' } },
};

my $ssh_provider = {
    metadata => { name => 'ssh-a', namespace => 'ocp-system', annotations => {} },
    spec     => { type => 'ssh' },
};

my $default_provider = {
    metadata => {
        name        => 'hetzner-default',
        namespace   => 'ocp-system',
        annotations => { 'ocp.internal/default' => 'true' },
    },
    spec => { type => 'hetzner' },
};

# -------------------------------------------------------------------------

subtest 'resolves single provider implicitly' => sub {
    my $k8s = FakeK8sA->new(providers => [$hetzner_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s  => $k8s,
        name => 'worker-1',
    );

    my $p = $add->_resolve_provider($k8s);
    is $p->{metadata}{name}, 'hetzner-a', 'resolved single provider by name';
};

subtest 'errors on multiple providers without --provider' => sub {
    my $k8s = FakeK8sA->new(providers => [$hetzner_provider, $ssh_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s  => $k8s,
        name => 'worker-1',
    );

    eval { $add->_resolve_provider($k8s) };
    like $@, qr/multiple providers.*--provider required/i,
        'dies with helpful message';
};

subtest 'uses default-annotated provider when multiple' => sub {
    my $k8s = FakeK8sA->new(providers => [$hetzner_provider, $default_provider, $ssh_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s  => $k8s,
        name => 'worker-1',
    );

    my $p = $add->_resolve_provider($k8s);
    is $p->{metadata}{name}, 'hetzner-default', 'picked default-annotated provider';
};

subtest 'rejects --host for hetzner provider' => sub {
    my $k8s = FakeK8sA->new(providers => [$hetzner_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s  => $k8s,
        name => 'worker-1',
        host => '1.2.3.4',
    );

    eval { $add->_validate_flags('hetzner') };
    like $@, qr/--host.*not valid.*hetzner/i, 'hetzner rejects --host';
};

subtest 'rejects --server-type for ssh provider' => sub {
    my $k8s = FakeK8sA->new(providers => [$ssh_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s         => $k8s,
        name        => 'worker-1',
        host        => '1.2.3.4',
        server_type => 'cx32',
    );

    eval { $add->_validate_flags('ssh') };
    like $@, qr/--server-type.*only valid.*hetzner/i, 'ssh rejects --server-type';
};

subtest 'requires --host for ssh provider' => sub {
    my $k8s = FakeK8sA->new(providers => [$ssh_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s  => $k8s,
        name => 'worker-1',
    );

    eval { $add->_validate_flags('ssh') };
    like $@, qr/--host.*required.*ssh/i, 'ssh requires --host';
};

subtest 'writes OCPNode CR via ensure' => sub {
    my $k8s = FakeK8sA->new(
        providers   => [$hetzner_provider],
        deployments => {},
    );
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'worker-1',
        role     => 'worker',
        provider => 'hetzner-a',
        nowait   => 1,
    );

    capture_stdout { $add->execute([], []) };

    my @ensures = grep { $_->[0] eq 'ensure' } @{$k8s->{calls}};
    is scalar @ensures, 1, 'one ensure call';
    my $cr = $ensures[0][1];
    is $cr->{kind},                 'OCPNode',      'kind is OCPNode';
    is $cr->{apiVersion},           'ocp.internal/v1', 'apiVersion correct';
    is $cr->{metadata}{name},       'worker-1',     'name set';
    is $cr->{metadata}{namespace},  'ocp-system',   'namespace ocp-system';
    is $cr->{spec}{role},           'worker',       'role set';
    is $cr->{spec}{providerRef},    'hetzner-a',    'providerRef set';
};

subtest 'with --nowait, returns after CR write' => sub {
    my $k8s = FakeK8sA->new(
        providers   => [$hetzner_provider],
        deployments => {},
    );
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'worker-nw',
        provider => 'hetzner-a',
        nowait   => 1,
    );

    my $stdout = capture_stdout { $add->execute([], []) };
    like $stdout, qr/worker-nw/, 'prints CR name';

    my @gets = grep { $_->[0] eq 'get' && $_->[1] eq 'Deployment' } @{$k8s->{calls}};
    is scalar @gets, 0, 'no Deployment get (exited before Robocop check)';
};

subtest 'detects Robocop readyReplicas >= 1' => sub {
    my $robocop_deploy = {
        metadata => { name => 'robocop', namespace => 'ocp-system' },
        status   => { readyReplicas => 1 },
    };

    my $k8s = FakeK8sA->new(
        providers   => [$hetzner_provider],
        deployments => { robocop => $robocop_deploy },
        get_nodes   => {
            'worker-r' => {
                metadata => { name => 'worker-r', namespace => 'ocp-system' },
                spec     => { role => 'worker', providerRef => 'hetzner-a' },
                status   => { phase => 'Ready' },
            },
        },
    );

    # Patch _poll_until_ready to avoid sleeping
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'worker-r',
        provider => 'hetzner-a',
    );

    my $robocop_ready = $add->_robocop_ready($k8s);
    ok $robocop_ready, 'Robocop detected as ready (readyReplicas=1)';
};

subtest 'Robocop not ready when readyReplicas is 0' => sub {
    my $robocop_deploy = {
        metadata => { name => 'robocop', namespace => 'ocp-system' },
        status   => { readyReplicas => 0 },
    };

    my $k8s = FakeK8sA->new(
        providers   => [$hetzner_provider],
        deployments => { robocop => $robocop_deploy },
    );
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'worker-x',
        provider => 'hetzner-a',
    );

    my $robocop_ready = $add->_robocop_ready($k8s);
    ok !$robocop_ready, 'Robocop not ready when readyReplicas=0';
};

subtest 'Robocop not ready when Deployment absent' => sub {
    my $k8s = FakeK8sA->new(
        providers   => [$hetzner_provider],
        deployments => {},
    );
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'worker-x',
        provider => 'hetzner-a',
    );

    my $robocop_ready = $add->_robocop_ready($k8s);
    ok !$robocop_ready, 'Robocop not ready when Deployment is absent';
};

subtest 'cr spec includes optional fields when provided' => sub {
    my $k8s = FakeK8sA->new(providers => [$hetzner_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s         => $k8s,
        name        => 'gpu-worker',
        role        => 'worker',
        server_type => 'cx52',
        location    => 'nbg1',
        image       => 'debian-12',
        gpu         => 1,
        provider    => 'hetzner-a',
        nowait      => 1,
    );

    capture_stdout { $add->execute([], []) };

    my @ensures = grep { $_->[0] eq 'ensure' } @{$k8s->{calls}};
    my $spec = $ensures[0][1]{spec};
    is $spec->{serverType}, 'cx52',      'serverType in spec';
    is $spec->{location},   'nbg1',      'location in spec';
    is $spec->{image},      'debian-12', 'image in spec';
    ok $spec->{gpu},                     'gpu in spec';
};

subtest 'spec.gpu goes out as a JSON boolean, not an integer' => sub {
    # The OCPNode CRD declares spec.gpu as `type: boolean`. Handing the bare
    # Perl 1 from the MooX::Options flag straight to the API produced
    #   422 ... spec.gpu: Invalid value: "integer": spec.gpu in body must be
    #   of type boolean: "integer"
    # so --gpu could never write a CR at all.
    my $k8s = FakeK8sA->new(providers => [$hetzner_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'gpu-worker',
        provider => 'hetzner-a',
        gpu      => 1,
        nowait   => 1,
    );

    capture_stdout { $add->execute([], []) };

    my ($ensure) = grep { $_->[0] eq 'ensure' } @{$k8s->{calls}};
    my $cr = $ensure->[1];

    isa_ok $cr->{spec}{gpu}, 'JSON::PP::Boolean';

    my $body = JSON::PP->new->canonical->encode($cr);
    like   $body, qr/"gpu"\s*:\s*true/, 'request body carries gpu: true';
    unlike $body, qr/"gpu"\s*:\s*1\b/,  'request body carries no integer gpu';
};

subtest 'cr spec omits optional fields when not provided' => sub {
    my $k8s = FakeK8sA->new(providers => [$hetzner_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'plain-worker',
        provider => 'hetzner-a',
        nowait   => 1,
    );

    capture_stdout { $add->execute([], []) };

    my @ensures = grep { $_->[0] eq 'ensure' } @{$k8s->{calls}};
    my $spec = $ensures[0][1]{spec};
    ok !exists $spec->{serverType}, 'serverType absent from spec';
    ok !exists $spec->{location},   'location absent from spec';
    ok !exists $spec->{image},      'image absent from spec';
    ok !exists $spec->{gpu},        'gpu absent from spec';
    ok !exists $spec->{host},       'host absent from spec';
};

#
# Both wait paths -- the one where robocop does the work and the one where this
# command does it -- can sit here for a quarter of an hour (OCP::Node's
# READY_TIMEOUT, and the sum of waits it is made of, karr #109). They used to do
# it in silence, and answer a budget that ran out with a bare "did not reach
# Ready state" plus an SSH-key hint, which is the wrong diagnosis for a machine
# that is merely still installing.
#
subtest 'the wait says what it is waiting for, once per phase' => sub {
    my $k8s = FakeK8sA->new(providers => [$hetzner_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'worker-p',
        provider => 'hetzner-a',
    );

    my $out = capture_stdout {
        my $r = '';
        $r = $add->_report_phase($r, 'Installing', 'Waiting for address');
        $r = $add->_report_phase($r, 'Installing', 'Waiting for address');
        $r = $add->_report_phase($r, 'Joining', 'RKE2 agent installed');
        $r = $add->_report_phase($r, 'Joining', 'RKE2 agent installed');
    };

    is scalar(() = $out =~ /\[\.\.\]/g), 2,
        'one line per phase, not one per poll';
    like $out, qr/Installing: Waiting for address/,
        'and it carries the message from the CR, which is where the detail is';
    like $out, qr/Joining: RKE2 agent installed/, 'same for the next phase';
};

{
    # Enough of a node to answer the one question these two subtests ask:
    # what did the CLI do with a reconcile that ended without a Ready?
    package FakeWaitNode;
    our ($phase, $verdict) = ('Installing', 0);
    sub reconcile_until_ready {
        my ($self, %opt) = @_;
        $opt{on_phase}->($phase, 'Waiting for SSH') if $opt{on_phase};
        return $verdict;
    }
}

{
    # Config stand-in for _cli_reconcile. By default it has no CP IP, which
    # is what the wait/timeout tests want: the if ($cp_ip) block in
    # _cli_reconcile is skipped, no SSH is opened, and OCP::Node is driven
    # with no join token. Tests that need a CP IP set cluster_status and/or
    # control_planes to whatever shape they want; the regression test for
    # karr #120 sets BOTH with different IPs so a wrong read is impossible
    # to mistake for a correct one.
    package FakeAddConfig;
    sub new {
        my ($c, %a) = @_;
        bless {
            cluster_status => $a{cluster_status} // {},
            control_planes => $a{control_planes} // [],
        }, $c;
    }
    sub cluster_status  { $_[0]->{cluster_status} }
    sub control_planes  { $_[0]->{control_planes} }
    sub distribution    { 'rke2' }
    sub join_url        { my ($s, $host) = @_; "https://$host:9345" }
}

sub cli_reconcile_out {
    my (%over) = @_;
    local $FakeWaitNode::phase   = $over{phase}   // 'Installing';
    local $FakeWaitNode::verdict = $over{verdict} // 0;

    my $k8s = FakeK8sA->new(providers => [$hetzner_provider]);
    my $add = OCP::Cmd::Node::Add->new(k8s => $k8s, name => 'worker-t');
    my $cr  = {
        metadata => { name => 'worker-t', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'hetzner-a' },
    };

    no warnings 'redefine';
    local *OCP::Node::from_cr = sub { bless {}, 'FakeWaitNode' };

    my $err;
    my $out = capture_stdout {
        $err = capture_stderr { $add->_cli_reconcile($cr, $k8s, FakeAddConfig->new, undef) };
    };
    return { out => $out, err => $err };
}

subtest 'running out of budget is reported as that, not as a verdict' => sub {
    # "did not reach Ready state" on its own reads as "this machine is broken".
    # For a budget that expired it is not even a claim about the machine: the
    # install is probably still running, and the CR keeps its phase.
    my $r = cli_reconcile_out(phase => 'Installing', verdict => 0);

    like $r->{out}, qr/\[\.\.\] Installing: Waiting for SSH/,
        'the phase it was waiting in was said as it happened';
    like $r->{err}, qr/Still in phase 'Installing'/,
        'and the give-up line names it rather than leaving the operator guessing';
    like $r->{err}, qr/after \Q$OCP::Node::READY_TIMEOUT\Es/,
        'with the budget that ran out';
    like $r->{err}, qr/continues from there/,
        'and says the run is resumable, because nothing was rolled back';
};

subtest 'a node that reached a verdict is not second-guessed' => sub {
    my $failed = cli_reconcile_out(phase => 'Failed', verdict => 0);
    unlike $failed->{err}, qr/Still in phase/,
        'Failed is OCP::Node speaking; no timeout is invented on top of it';

    my $ready = cli_reconcile_out(phase => 'Ready', verdict => 1);
    is $ready->{err}, '', 'and a worker that came up is told nothing at all';
};

subtest 'both wait paths take their budget from OCP::Node' => sub {
    my $k8s = FakeK8sA->new(providers => [$hetzner_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'worker-b',
        provider => 'hetzner-a',
    );

    # Zero budget: the loop never looks, which is only true if the default is
    # read from the variable rather than written out here as well.
    local $OCP::Node::READY_TIMEOUT = 0;
    is $add->_poll_until_ready($k8s), 0, 'the robocop-side wait honours it';
    is scalar(grep { $_->[0] eq 'get' && $_->[1] eq 'OCPNode' } @{$k8s->{calls}}), 0,
        'and stopped before the first look, so the budget was the shared one';
};

subtest 'errors on no providers' => sub {
    my $k8s = FakeK8sA->new(providers => []);
    my $add = OCP::Cmd::Node::Add->new(
        k8s  => $k8s,
        name => 'worker-1',
    );

    eval { $add->_resolve_provider($k8s) };
    like $@, qr/no.*provider/i, 'dies when no providers exist';
};

subtest 'explicit --provider overrides implicit resolution' => sub {
    my $k8s = FakeK8sA->new(providers => [$hetzner_provider, $default_provider]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'worker-1',
        provider => 'hetzner-a',
    );

    my $p = $add->_resolve_provider($k8s);
    is $p->{metadata}{name}, 'hetzner-a', 'explicit --provider wins over default annotation';
};

#
# The CP address is in two places: ocp.yaml (spec, what the operator wants)
# and .ocp/status.yaml (status, what the cluster actually has). The old code
# read spec first, which is the source of truth for `ocp apply` but the
# wrong source for `ocp node add` -- the SSH call to read the join token
# needs the address that is reachable right now, and on a cluster whose CP
# IP drifted since the last apply the spec IP is the one that does not
# work (karr #120, sibling of karr #98).
#
# These tests pin where _cli_reconcile reads the IP from. The plumbing
# beyond that (OCP::SSH->new, cluster_ssh_key, the run that fetches the
# join token) is stubbed out -- the only question on the table is the
# value of `host` OCP::SSH is constructed with.
#

{
    # OCP::ClusterKey prompts for PIN2 / reads .ocp/id_ed25519. _cli_reconcile
    # only needs `path` and `content` off the key, plus `migration_hint` in
    # the failure path; none of those touch the real filesystem.
    package FakeClusterKey;
    sub new            { bless {}, shift }
    sub path           { '/dev/null' }
    sub content        { "FAKE\n" }
    sub migration_hint { '' }
}

# Capture every OCP::SSH->new call. _cli_reconcile constructs it only inside
# the if ($cp_ip) block, so the count is also a sanity check on whether the
# block ran at all.
our @ssh_calls;
sub reset_ssh_calls { @ssh_calls = () }

sub cli_reconcile_for_ip {
    my (%over) = @_;
    local $FakeWaitNode::phase   = $over{phase}   // 'Installing';
    local $FakeWaitNode::verdict = $over{verdict} // 0;

    my $k8s = FakeK8sA->new(providers => [$hetzner_provider]);
    my $add = OCP::Cmd::Node::Add->new(k8s => $k8s, name => 'worker-t');
    my $cr  = {
        metadata => { name => 'worker-t', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'hetzner-a' },
    };

    no warnings 'redefine';
    local *OCP::Node::from_cr = sub { bless {}, 'FakeWaitNode' };

    # Stub the cluster key + the SSH client. _cli_reconcile's require
    # OCP::SSH has to find the package, so load it first; then replace
    # ->new so every call lands in our capture buffer.
    require OCP::SSH;
    no warnings 'redefine';
    local *OCP::SSH::new = sub {
        my ($c, %a) = @_;
        push @ssh_calls, \%a;
        return bless { %a }, 'FakeSSHForAdd';
    };
    {
        package FakeSSHForAdd;
        sub run { { stdout => "FAKE-JOIN-TOKEN\n", stderr => '', exit => 0 } }
    }
    local *OCP::Cmd::Node::Add::cluster_ssh_key = sub {
        return FakeClusterKey->new;
    };

    my $config = FakeAddConfig->new(
        cluster_status => $over{cluster_status} // {},
    );

    reset_ssh_calls();
    my $out = capture_stdout {
        $add->_cli_reconcile($cr, $k8s, $config, undef);
    };
    return { out => $out };
}

subtest 'CP IP comes from status, not spec' => sub {
    # Spec and status disagree on a CP whose IP drifted since the last
    # `ocp apply`. The SSH call must follow status -- the address that is
    # actually reachable -- not the spec entry the operator typed when the
    # cluster was built (karr #120). Both sources are populated with
    # different IPs so a wrong read is unambiguous.
    my $r = cli_reconcile_for_ip(
        cluster_status => { public_ip => '192.168.1.1', name => 'cp-1' },
        control_planes => [{ public_ip => '10.0.0.1', host => 'spec.example' }],
    );
    is scalar(@ssh_calls), 1, 'one SSH connection was attempted';
    is $ssh_calls[0]{host}, '192.168.1.1',
        'SSH went to the status IP, ignoring the spec one';
};

subtest 'falls back to spec IP when status has no CP row' => sub {
    # First-ever `ocp node add` -- no CP in .ocp/status.yaml. cluster_status
    # returns the spec IP, and SSH must reach it. This is what the old
    # control_planes-based code already did; the regression test pins it so
    # the new cluster_status-based code does not regress the empty-status
    # case.
    my $r = cli_reconcile_for_ip(
        cluster_status => { public_ip => '10.0.0.1' },
        control_planes => [{ public_ip => '10.0.0.1', host => 'spec.example' }],
    );
    is scalar(@ssh_calls), 1, 'one SSH connection was attempted';
    is $ssh_calls[0]{host}, '10.0.0.1',
        'SSH went to the spec IP when status was empty';
};

subtest 'no SSH when neither status nor spec names a CP' => sub {
    # Local provider, no host anywhere. The if ($cp_ip) block must NOT
    # run -- there is nothing to SSH to. Same shape the previous code had:
    # FakeAddConfig with empty control_planes, no SSH attempted.
    my $r = cli_reconcile_for_ip(cluster_status => {});
    is scalar(@ssh_calls), 0, 'no SSH connection attempted';
};

done_testing;

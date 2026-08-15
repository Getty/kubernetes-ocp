#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();

use lib 'lib';

use OCP::Cmd::Node::Add;

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

done_testing;

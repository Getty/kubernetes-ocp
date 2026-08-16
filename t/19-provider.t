#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Provider::Ls;
use OCP::Cmd::Provider::Add;
use OCP::Cmd::Provider::Rm;
use Path::Tiny;

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
    # Minimal IO::K8s-like list wrapper: ->items returns arrayref of hashrefs
    package FakeList;
    sub new  { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]->{items} }
}

{
    # Identity object_to_struct: mock returns hashrefs, so just pass through
    package FakeIO;
    sub new              { bless {}, $_[0] }
    sub object_to_struct { $_[1] }
}

{
    package FakeK8s;

    my $_io = FakeIO->new;

    sub new {
        my ($class, %args) = @_;
        return bless {
            providers => $args{providers} // [],
            nodes     => $args{nodes}     // [],
        }, $class;
    }

    sub k8s  { $_io }

    sub list {
        my ($self, $kind, %args) = @_;
        return FakeList->new($self->{providers}) if $kind eq 'OCPNodeProvider';
        return FakeList->new($self->{nodes})     if $kind eq 'OCPNode';
        return FakeList->new([]);
    }

    # kept for backward compat (not called by Ls any more)
    sub get {
        my ($self, $kind, %args) = @_;
        return { items => $self->{providers} } if $kind eq 'OCPNodeProvider';
        return { items => $self->{nodes} }     if $kind eq 'OCPNode';
        return { items => [] };
    }
}

{
    package FakeK8sP;

    my $_io = FakeIO->new;

    sub new {
        my ($class, %args) = @_;
        return bless {
            providers => $args{providers} // [],
            nodes     => $args{nodes}     // [],
            calls     => [],
        }, $class;
    }

    sub k8s { $_io }

    sub list {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['list', $kind, \%args];
        return FakeList->new($self->{providers}) if $kind eq 'OCPNodeProvider';
        return FakeList->new($self->{nodes})     if $kind eq 'OCPNode';
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
        if ($kind eq 'OCPNode') {
            return FakeList->new($self->{nodes});
        }
        return undef;
    }

    sub ensure { push @{$_[0]->{calls}}, ['ensure', $_[1]]; $_[1] }

    sub patch {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['patch', $kind, \%args];
        return {};
    }

    sub delete {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['delete', $kind, \%args];
        return 1;
    }
}

# --- Ls tests ---

my $fake = FakeK8s->new(
    providers => [
        {
            metadata => {
                name        => 'hetzner-a',
                annotations => { 'ocp.internal/default' => 'true' },
            },
            spec => {
                type    => 'hetzner',
                hetzner => { location => 'fsn1' },
            },
        },
        {
            metadata => { name => 'hetzner-b' },
            spec     => {
                type    => 'hetzner',
                hetzner => { location => 'nbg1' },
            },
        },
        {
            metadata => { name => 'ssh-local' },
            spec     => { type => 'ssh' },
        },
    ],
    nodes => [
        { spec => { providerRef => 'hetzner-a' } },
        { spec => { providerRef => 'hetzner-a' } },
        { spec => { providerRef => 'hetzner-a' } },
        { spec => { providerRef => 'ssh-local' } },
    ],
);

my $ls = OCP::Cmd::Provider::Ls->new(k8s => $fake);
my $stdout = capture_stdout { $ls->execute([], []) };

like $stdout, qr/^NAME/m, 'header present';
like $stdout, qr/hetzner-a\s+hetzner\s+fsn1\s+\*\s+3/, 'hetzner-a row: type, location, default, count';
like $stdout, qr/hetzner-b\s+hetzner\s+nbg1\s+\s*0/, 'hetzner-b row: no default, 0 nodes';
like $stdout, qr/ssh-local\s+ssh\s+\S*\s+\S*\s*1/,   'ssh-local row: 1 node';

# --- Add tests ---

subtest 'add hetzner provider writes Secret + CR' => sub {
    my $tfile = Path::Tiny->tempfile;
    $tfile->spew("hetzner-token-123\n");

    my $k8s = FakeK8sP->new(providers => [], nodes => []);
    my $add = OCP::Cmd::Provider::Add->new(
        k8s         => $k8s,
        name        => 'hetzner-a',
        type        => 'hetzner',
        token_file  => "$tfile",
        location    => 'fsn1',
        server_type => 'cx32',
    );
    capture_stdout { $add->execute([], []) };

    my @ensures = grep { $_->[0] eq 'ensure' } @{$k8s->{calls}};
    is scalar @ensures, 2, 'two ensure calls (Secret + CR)';
    is $ensures[0][1]{kind}, 'Secret',          'first is Secret';
    is $ensures[1][1]{kind}, 'OCPNodeProvider',  'second is OCPNodeProvider';
    is $ensures[1][1]{spec}{hetzner}{location}, 'fsn1', 'location passed through';
    like $ensures[0][1]{data}{token}, qr/\S+/, 'token base64-encoded';
    is $ensures[1][1]{spec}{hetzner}{serverType}, 'cx32', 'serverType passed through';
};

subtest 'add hetzner writes the SSH key name onto the CR' => sub {
    # A provider CR without sshKeyName produces servers with an empty
    # authorized_keys once `ocp node add` reaches it (karr #92). With no
    # project on disk there is nothing to derive from -- the field is then
    # left off rather than guessed, and --ssh-key-name is the way in.
    my $tfile = Path::Tiny->tempfile;
    $tfile->spew("tok\n");

    my $k8s = FakeK8sP->new(providers => [], nodes => []);
    my $add = OCP::Cmd::Provider::Add->new(
        k8s          => $k8s,
        name         => 'hetzner-c',
        type         => 'hetzner',
        token_file   => "$tfile",
        ssh_key_name => 'ocp-cortex-admin',
    );
    capture_stdout { $add->execute([], []) };

    my @ensures = grep { $_->[0] eq 'ensure' } @{$k8s->{calls}};
    is $ensures[1][1]{spec}{hetzner}{sshKeyName}, 'ocp-cortex-admin',
        '--ssh-key-name lands on the CR';
};

subtest 'ssh type rejects --ssh-key-name' => sub {
    eval {
        OCP::Cmd::Provider::Add->new(
            k8s          => FakeK8sP->new,
            name         => 'x',
            type         => 'ssh',
            ssh_key_name => 'ocp-cortex-admin',
        )->execute([], []);
    };
    like $@, qr/--ssh-key-name.*only.*hetzner/i,
        'the flag is hetzner-only, like --location and --image';
};

subtest 'add with --default annotates CR' => sub {
    my $tfile = Path::Tiny->tempfile;
    $tfile->spew("tok\n");

    my $k8s = FakeK8sP->new(providers => [], nodes => []);
    my $add = OCP::Cmd::Provider::Add->new(
        k8s        => $k8s,
        name       => 'hetzner-b',
        type       => 'hetzner',
        token_file => "$tfile",
        default    => 1,
    );
    capture_stdout { $add->execute([], []) };

    my @ensures = grep { $_->[0] eq 'ensure' } @{$k8s->{calls}};
    is scalar @ensures, 2, 'two ensure calls';
    is $ensures[1][1]{metadata}{annotations}{'ocp.internal/default'}, 'true',
        'default annotation set on CR';
};

subtest 'add with --default strips default from other providers' => sub {
    my $tfile = Path::Tiny->tempfile;
    $tfile->spew("tok\n");

    my $existing = {
        metadata => {
            name        => 'old-default',
            annotations => { 'ocp.internal/default' => 'true' },
        },
        spec => { type => 'hetzner', hetzner => { tokenSecretRef => { name => 'x' } } },
    };

    my $k8s = FakeK8sP->new(providers => [$existing], nodes => []);
    my $add = OCP::Cmd::Provider::Add->new(
        k8s        => $k8s,
        name       => 'new-default',
        type       => 'hetzner',
        token_file => "$tfile",
        default    => 1,
    );
    capture_stdout { $add->execute([], []) };

    my @patches = grep { $_->[0] eq 'patch' } @{$k8s->{calls}};
    is scalar @patches, 1, 'one patch call to strip old default';
    my $patched_ann = $patches[0][2]{patch}{metadata}{annotations};
    ok !exists $patched_ann->{'ocp.internal/default'},
        'old default annotation removed';
};

subtest 'rejects --location for ssh type' => sub {
    eval {
        OCP::Cmd::Provider::Add->new(
            k8s      => FakeK8sP->new,
            name     => 'x',
            type     => 'ssh',
            location => 'fsn1',
        )->execute([], []);
    };
    like $@, qr/--location.*only.*hetzner/i, 'ssh rejects --location';
};

subtest 'requires --token-file for hetzner' => sub {
    eval {
        OCP::Cmd::Provider::Add->new(
            k8s  => FakeK8sP->new,
            name => 'x',
            type => 'hetzner',
        )->execute([], []);
    };
    like $@, qr/token-file.*required/i, 'hetzner requires --token-file';
};

subtest 'rm blocks when nodes reference provider' => sub {
    my $k8s = FakeK8sP->new(
        providers => [{ metadata => { name => 'hetzner-a' }, spec => { type => 'hetzner' } }],
        nodes => [
            { metadata => { name => 'worker-1' }, spec => { providerRef => 'hetzner-a' }, status => { phase => 'Ready' } },
            { metadata => { name => 'worker-2' }, spec => { providerRef => 'hetzner-a' }, status => { phase => 'Provisioning' } },
        ],
    );
    my $rm = OCP::Cmd::Provider::Rm->new(k8s => $k8s, name => 'hetzner-a');
    my $stderr = capture_stderr {
        eval { $rm->execute([], []) };
    };
    like $stderr, qr/hetzner-a.*2 referencing nodes/;
    like $stderr, qr/worker-1 \(Ready\)/;
    like $stderr, qr/worker-2 \(Provisioning\)/;
    my @deletes = grep { $_->[0] eq 'delete' } @{$k8s->{calls}};
    is scalar @deletes, 0, 'no delete when references exist';
};

subtest 'rm deletes Secret + CR when no references' => sub {
    my $k8s = FakeK8sP->new(
        providers => [{ metadata => { name => 'hetzner-b' }, spec => { type => 'hetzner' } }],
        nodes => [],
    );
    my $rm = OCP::Cmd::Provider::Rm->new(k8s => $k8s, name => 'hetzner-b');
    capture_stdout { $rm->execute([], []) };
    my @deletes = grep { $_->[0] eq 'delete' } @{$k8s->{calls}};
    is scalar @deletes, 2, 'two deletes (Secret + CR)';
};

subtest 'rm errors on unknown provider' => sub {
    my $k8s = FakeK8sP->new(providers => [], nodes => []);
    my $rm = OCP::Cmd::Provider::Rm->new(k8s => $k8s, name => 'nonexistent');
    eval { $rm->execute([], []) };
    like $@, qr/Unknown provider 'nonexistent'/;

    # The rejection has to say what would have worked, with the type next to
    # the name — naming the type instead of the CR is the mistake that gets
    # made (karr #89, full coverage in t/73-provider-name-vs-type.t).
    my $stocked = FakeK8sP->new(
        providers => [{ metadata => { name => 'ssh-default' }, spec => { type => 'ssh' } }],
        nodes     => [],
    );
    my $rm2 = OCP::Cmd::Provider::Rm->new(k8s => $stocked, name => 'ssh');
    eval { $rm2->execute([], []) };
    like $@, qr/^Available: ssh-default \(type ssh\)$/m,
        'lists the existing providers with their types';
};

subtest 'rm uses typed Kind args (not path=>)' => sub {
    my $k8s = FakeK8sP->new(
        providers => [{ metadata => { name => 'p' }, spec => { type => 'hetzner' } }],
        nodes     => [],
    );
    my $rm = OCP::Cmd::Provider::Rm->new(k8s => $k8s, name => 'p');
    capture_stdout { $rm->execute([], []) };
    my @bad = grep {
        my $args = $_->[2];
        ref $args eq 'HASH' && exists $args->{path};
    } @{$k8s->{calls}};
    is scalar(@bad), 0, 'no path=> usage in rm calls';
    my @typed_kinds = grep { $_->[1] =~ /^(OCPNode|OCPNodeProvider|Secret)$/ } @{$k8s->{calls}};
    ok scalar(@typed_kinds), 'typed Kind strings used';
};

subtest 'ls uses typed Kind args (not path=>)' => sub {
    my $k8s = FakeK8s->new(providers => [], nodes => []);
    my $ls = OCP::Cmd::Provider::Ls->new(k8s => $k8s);
    capture_stdout { $ls->execute([], []) };
    pass 'ls execute completed without path=> calls';
};

done_testing;

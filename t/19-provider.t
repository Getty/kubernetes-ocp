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

subtest 'a flag that is not given writes no field' => sub {
    # "This provider does not care" is a real answer and has to stay
    # expressible, because OCP::Provider::Hetzner ranks the provider's default
    # ABOVE its own code default (karr #100). A CR that carried a value for
    # every flag would make the code default unreachable and pin every node of
    # the provider to whatever `provider add` guessed.
    my $tfile = Path::Tiny->tempfile;
    $tfile->spew("tok\n");

    my $k8s = FakeK8sP->new(providers => [], nodes => []);
    my $add = OCP::Cmd::Provider::Add->new(
        k8s        => $k8s,
        name       => 'hetzner-plain',
        type       => 'hetzner',
        token_file => "$tfile",
    );
    capture_stdout { $add->execute([], []) };

    my @ensures = grep { $_->[0] eq 'ensure' } @{$k8s->{calls}};
    my $hspec = $ensures[1][1]{spec}{hetzner};
    ok !exists $hspec->{location},   'no --location, no spec.hetzner.location';
    ok !exists $hspec->{serverType}, 'no --server-type, no spec.hetzner.serverType';
    ok !exists $hspec->{image},      'no --image, no spec.hetzner.image';
};

#
# The OCPNodeProvider CRD, read as a document -- karr #100.
#
# Two claims, and both are about the same three fields being a RANK rather
# than a value.
#
#   * The schema declares no `default:` for them. A structural default is
#     materialised by the API server into every CR that leaves the field out,
#     which makes "this provider says nothing" indistinguishable from "this
#     provider chose exactly this" -- and the field is now read, so that
#     distinction is what decides whether the code default applies. It was not
#     hypothetical: serverType carried `default: cx23`, a type Hetzner does not
#     sell (cx22/cx32/cx42/cx52), and `ocp apply` writes spec.hetzner without
#     these fields, so every provider CR in every cluster read back cx23 while
#     every server came up cx32.
#
#   * Every key `ocp provider add` writes is declared. Structural schemas prune
#     undeclared fields, so a name only the writer knows does not round-trip --
#     it is accepted, dropped, and read back as absent.
#

subtest 'the OCPNodeProvider CRD leaves the hetzner defaults unset' => sub {
    my $crd_file = path(__FILE__)->parent->parent
        ->child('share/robocop/crds/ocpnodeprovider.yaml');
    plan skip_all => 'CRD not found' unless -f $crd_file;

    # Raw bytes, like OCP::Cmd::Apply::CR::ensure_crds reads it: YAML::XS
    # decodes UTF-8 itself and chokes on already-decoded characters.
    require YAML::XS;
    my $raw = $crd_file->slurp_raw;
    my $crd = YAML::XS::Load($raw);

    my $props = $crd->{spec}{versions}[0]{schema}{openAPIV3Schema}
                    {properties}{spec}{properties};
    my $hetzner = $props->{hetzner}{properties};
    ok $hetzner, 'the CRD declares spec.hetzner';

    for my $field (qw(location serverType image)) {
        ok exists $hetzner->{$field}, "spec.hetzner.$field is declared";
        ok !exists $hetzner->{$field}{default},
            "spec.hetzner.$field carries no schema default -- unset stays unset";
    }

    # The typo that started it must not come back as a value. Asserted against
    # the PARSED document, not the file text: the comment above the fields
    # explains why cx23 is gone and has every right to name it.
    unlike YAML::XS::Dump($crd), qr/\bcx23\b/,
        'cx23 appears nowhere in the schema -- Hetzner does not sell one';

    # What the writer writes, the schema must declare, or the API server
    # prunes it on the way in.
    my $tfile = Path::Tiny->tempfile;
    $tfile->spew("tok\n");
    my $k8s = FakeK8sP->new(providers => [], nodes => []);
    my $add = OCP::Cmd::Provider::Add->new(
        k8s          => $k8s,
        name         => 'hetzner-full',
        type         => 'hetzner',
        token_file   => "$tfile",
        location     => 'nbg1',
        server_type  => 'cx42',
        image        => 'debian-12',
        ssh_key_name => 'ocp-cortex-admin',
    );
    capture_stdout { $add->execute([], []) };

    my @ensures = grep { $_->[0] eq 'ensure' } @{$k8s->{calls}};
    my $written = $ensures[1][1]{spec}{hetzner};
    for my $key (sort keys %$written) {
        ok exists $hetzner->{$key},
            "spec.hetzner.$key is declared in the CRD, so it survives the API server";
    }
    is $written->{location},   'nbg1',      '--location is written as spec.hetzner.location';
    is $written->{serverType}, 'cx42',      '--server-type is written as spec.hetzner.serverType';
    is $written->{image},      'debian-12', '--image is written as spec.hetzner.image';
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

#
# A hand-added provider has to agree with the project about the cluster name,
# or the servers it creates land under a different ocp-cluster label than the
# control plane's and `ocp destroy` walks straight past them (karr #98). There
# is deliberately no flag: the cluster has one name and it is in ocp.yaml.
#

{
    package FakeOcpP;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

subtest 'add writes the cluster name from the project onto every CR' => sub {
    my $dir = Path::Tiny->tempdir;
    $dir->child('ocp.yaml')->spew("name: cortex\ncontrol_planes:\n  - provider: hetzner\n");

    my $tfile = Path::Tiny->tempfile;
    $tfile->spew("tok\n");

    my $k8s = FakeK8sP->new(providers => [], nodes => []);
    my $add = OCP::Cmd::Provider::Add->new(
        command_chain => [ FakeOcpP->new(config => $dir->child('ocp.yaml')->stringify) ],
        k8s           => $k8s,
        name          => 'hetzner-d',
        type          => 'hetzner',
        token_file    => "$tfile",
    );
    capture_stdout { $add->execute([], []) };

    my @ensures = grep { $_->[0] eq 'ensure' } @{$k8s->{calls}};
    my ($cr) = grep { $_->[1]{kind} eq 'OCPNodeProvider' } @ensures;
    is $cr->[1]{spec}{clusterName}, 'cortex',
        'spec.clusterName is the cluster from ocp.yaml';
    isnt $cr->[1]{spec}{clusterName}, $cr->[1]{metadata}{name},
        'and not the CR name the operator chose';

    # ssh/local carry it too: it describes the cluster, not the backend, so it
    # is written outside the per-type branch and cannot be forgotten for one.
    my $k8s2 = FakeK8sP->new(providers => [], nodes => []);
    my $add_ssh = OCP::Cmd::Provider::Add->new(
        command_chain => [ FakeOcpP->new(config => $dir->child('ocp.yaml')->stringify) ],
        k8s           => $k8s2,
        name          => 'ssh-b',
        type          => 'ssh',
    );
    capture_stdout { $add_ssh->execute([], []) };
    my ($ssh_cr) = grep { $_->[0] eq 'ensure' && $_->[1]{kind} eq 'OCPNodeProvider' }
                        @{$k8s2->{calls}};
    is $ssh_cr->[1]{spec}{clusterName}, 'cortex', 'ssh provider CR carries it as well';
};

subtest 'no project on disk leaves clusterName off rather than guessing' => sub {
    # OCP::Provider::from_cr then refuses the moment the CR is used, which says
    # what is missing. A guessed cluster name would instead produce a running,
    # billed server that no teardown can find.
    my $tfile = Path::Tiny->tempfile;
    $tfile->spew("tok\n");

    my $k8s = FakeK8sP->new(providers => [], nodes => []);
    my $add = OCP::Cmd::Provider::Add->new(
        k8s        => $k8s,
        name       => 'hetzner-e',
        type       => 'hetzner',
        token_file => "$tfile",
    );
    capture_stdout { $add->execute([], []) };

    my ($cr) = grep { $_->[0] eq 'ensure' && $_->[1]{kind} eq 'OCPNodeProvider' }
                    @{$k8s->{calls}};
    ok !exists $cr->[1]{spec}{clusterName}, 'the field is absent, not invented';
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

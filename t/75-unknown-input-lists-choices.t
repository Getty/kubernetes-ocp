#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Choices;
use OCP::Cmd::Keys::Show;
use OCP::Cmd::Node::Add;
use OCP::Cmd::Node::Rm;
use OCP::Cmd::SSH;
use OCP::Cmd::Update;
use OCP::Node;
use OCP::Provider;
use OCP::Versions;

#
# THE HOUSE RULE, THIRD ROUND. karr #67 gave unknown SUBCOMMANDS an answer
# ("Unknown command 'x'. Available: ..."), #89 gave unknown PROVIDER NAMES the
# same one. #103 collected six more rejections that only ever said no:
#
#   ocp node rm NAME        -> "Node 'x' not found"
#   ocp ssh --node X        -> "Could not determine host for node: X"
#   ocp keys show --name X  -> "No key named 'X' in keys.yaml."
#   ocp update              -> "Unknown target version: X"
#   an unbuildable provider -> "Unsupported provider: X"
#   ocp node add --role X   -> NOT CHECKED AT ALL: a raw Kubernetes 422
#
# Asserted per case: the output names the valid values, the exit code is not
# 0, and nothing was done to the cluster on the way out. For --role
# additionally that the refusal happens BEFORE any API call, which is the
# whole point of that one — a CLI that forwards a typo to the API server
# explains a 422 to the operator instead of explaining their input.
#
# And asserted once for all of them: it is ONE error picture, the same shape
# `ocp quatschkommando` answers in. Six near-identical messages would be worse
# than the six silences they replace.
#
# The sets themselves are NOT re-listed here. Each is asserted against its
# owner (OCP::Provider for types, OCP::Node for roles, OCP::Versions for
# manifests) and, where a second spelling is unavoidable, against that
# spelling: the OCPNode CRD enum is read off disk and compared. A test that
# wrote the values out again would be the seventh copy of the drift that
# karr #102, #109, #110 and #112 record.
#

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
    package FakeK8s;

    my $_io = FakeIO->new;

    sub new {
        my ($class, %args) = @_;
        return bless {
            nodes     => $args{nodes}     // [],
            providers => $args{providers} // [],
            listable  => defined $args{listable} ? $args{listable} : 1,
            calls     => [],
        }, $class;
    }

    sub k8s { $_io }

    sub list {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['list', $kind, \%args];
        die "503: the API did not answer\n" unless $self->{listable};
        return FakeList->new($self->{nodes})     if $kind eq 'OCPNode';
        return FakeList->new($self->{providers}) if $kind eq 'OCPNodeProvider';
        return FakeList->new([]);
    }

    sub get {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['get', $kind, \%args];
        my $name = $args{name} // '';
        my $from = $kind eq 'OCPNode' ? $self->{nodes} : $self->{providers};
        for my $item (@$from) {
            return $item if $item->{metadata}{name} eq $name;
        }
        die "404: not found $kind/$name\n";
    }

    sub ensure { push @{$_[0]->{calls}}, ['ensure', $_[1]]; $_[1] }
    sub delete { my ($s, $k, %a) = @_; push @{$s->{calls}}, ['delete', $k, \%a]; 1 }

    sub calls       { @{ $_[0]->{calls} } }
    sub calls_of    { my ($s, $v) = @_; grep { $_->[0] eq $v } @{$s->{calls}} }
}

my @NODES = map {
    { metadata => { name => $_->[0], namespace => 'ocp-system' },
      spec     => { role => $_->[1], providerRef => 'ssh-default' },
      status   => { phase => 'Ready' } }
} ( ['cp-lab', 'control-plane'], ['otho-gpu', 'worker'], ['worker-1', 'worker'] );

# STDERR + exit code, through the same path bin/ocp takes: OCP::run_cli hands
# the exception to _report_error and its return value becomes the exit code.
sub reported {
    my ($err) = @_;

    my ($stderr, $rc) = ('', undef);
    {
        open my $fh, '>', \$stderr or die "capture stderr: $!";
        local *STDERR = $fh;
        $rc = OCP::_report_error($err, 0);
    }
    return ($stderr, $rc);
}

# -------------------------------------------------------------------------
# 1. ocp node rm NAME
# -------------------------------------------------------------------------

subtest 'ocp node rm names the nodes this cluster has' => sub {
    my $k8s = FakeK8s->new(nodes => [@NODES]);
    my $rm  = OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'wroker-1');

    eval { $rm->execute([], []) };
    my $err = $@;

    ok $err, 'a node that does not exist is refused';
    like $err, qr/^Unknown node 'wroker-1'\./,
        'names the word that was not understood';
    like $err, qr/^Available: cp-lab, otho-gpu, worker-1$/m,
        'and lists every OCPNode CR, sorted';
    is scalar($k8s->calls_of('delete')), 0, 'nothing was deleted';

    my ($stderr, $rc) = reported($err);
    isnt $rc, 0, 'exit code is not 0';
    like $stderr, qr/^Error: Unknown node 'wroker-1'\./, 'STDERR carries it';
    like $stderr, qr/^Available: cp-lab, /m, 'STDERR carries the listing';
};

subtest 'ocp node rm on a cluster without OCPNodes points at node add' => sub {
    my $k8s = FakeK8s->new(nodes => []);
    my $rm  = OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'worker-1');

    eval { $rm->execute([], []) };

    like $@, qr/^Unknown node 'worker-1'\./, 'still names the input';
    like $@, qr/No OCPNode exists in this cluster/, 'says the cluster has none';
    like $@, qr/'ocp node add'/, 'points at the command that makes one';
    unlike $@, qr/^Available:/m, 'no empty Available: line';
};

subtest 'a listing that cannot be read does not replace the rejection' => sub {
    my $k8s = FakeK8s->new(nodes => [@NODES], listable => 0);
    my $rm  = OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'nope');

    eval { $rm->execute([], []) };

    like $@, qr/^Unknown node 'nope'\./,
        'the message is still the one about the input';
    unlike $@, qr/503/, 'the failed list call does not become the error';
};

# -------------------------------------------------------------------------
# 2. ocp ssh --node NAME
# -------------------------------------------------------------------------

subtest 'ocp ssh names the nodes the Kubernetes API knows' => sub {
    my $ssh = OCP::Cmd::SSH->new(node => 'police1');

    my $err = $ssh->_unknown_node_error('police1', qw(cp-lab otho-gpu));

    like $err, qr/^Unknown node 'police1'\./, 'names the input';
    like $err, qr/^Available: cp-lab, otho-gpu$/m, 'lists what it could reach';

    my ($stderr, $rc) = reported($err);
    isnt $rc, 0, 'exit code is not 0';
    like $stderr, qr/^Error: Unknown node 'police1'\./, 'STDERR carries it';
};

subtest 'a node that IS known but has no address is not called unknown' => sub {
    my $ssh = OCP::Cmd::SSH->new(node => 'cp-lab');

    my $err = $ssh->_unknown_node_error('cp-lab', qw(cp-lab otho-gpu));

    unlike $err, qr/Unknown node/,
        'the name was right; saying otherwise would be false';
    like $err, qr/^Node 'cp-lab' has no address in the Kubernetes API\./,
        'says what is actually missing';
    like $err, qr/--node <ip>/, 'and what to do instead';
};

subtest 'ocp ssh with no readable node list says so' => sub {
    my $ssh = OCP::Cmd::SSH->new(node => 'police1');

    my $err = $ssh->_unknown_node_error('police1');

    like $err, qr/^Unknown node 'police1'\./, 'still names the input';
    like $err, qr/No node list could be read from the Kubernetes API/,
        'says why there is no listing instead of printing an empty one';
    unlike $err, qr/^Available:/m, 'no empty Available: line';
};

# -------------------------------------------------------------------------
# 3. ocp keys show --name / --purpose
#
# The one case with a second rule on top: NAMES AND PURPOSES ONLY. This
# command puts key material on STDOUT and nothing else (karr #84); a listing
# that leaked a key would put it on the diagnostic stream of every terminal
# that ever mistyped a name.
# -------------------------------------------------------------------------

my @FAKE_KEYS = (
    { name => 'admin-ssh-20260815', purpose => 'admin',
      public => 'ssh-ed25519 PUBLICMATERIAL-admin',
      private => 'PRIVATEMATERIAL-admin' },
    { name => 'robo-20260815', purpose => 'automation',
      public => 'ssh-ed25519 PUBLICMATERIAL-robo',
      private => 'PRIVATEMATERIAL-robo' },
    { name => 'admin-ssh-20250101', purpose => 'admin', deprecated => 1,
      public => 'ssh-ed25519 PUBLICMATERIAL-old',
      private => 'PRIVATEMATERIAL-old' },
);

sub keys_show_error {
    my (%args) = @_;

    my $keys = $args{keys} // [@FAKE_KEYS];
    my $dir  = tempdir(CLEANUP => 1);

    my $show = OCP::Cmd::Keys::Show->new(
        command_chain => [ OCP->new(config => path($dir)->child('ocp.yaml')->stringify) ],
        %{ $args{options} // {} },
    );

    my ($out, $diag) = ('', '');
    {
        no warnings 'redefine';
        local *OCP::Keys::has_keys_file     = sub { 1 };
        local *OCP::Keys::list_keys         = sub { $keys };
        local *OCP::Keys::get_key           = sub {
            my ($self, $name) = @_;
            my ($k) = grep { $_->{name} eq $name } @$keys;
            return $k;
        };
        local *OCP::Secrets::ensure_age_key = sub { 1 };

        open my $fh,  '>', \$out  or die "capture stdout: $!";
        open my $efh, '>', \$diag or die "capture stderr: $!";
        my $old = select $fh;
        local *STDERR = $efh;
        eval { $show->execute([], []) };
        select $old;
    }

    return ($@, $out, $diag);
}

subtest 'ocp keys show --name lists the keys, never their material' => sub {
    my ($err, $out, $diag) = keys_show_error(options => { name => 'admin-ssh' });

    like $err, qr/^Unknown key 'admin-ssh'\./, 'names the input';
    like $err, qr/^Available: .*admin-ssh-20260815 \(purpose admin\)/m,
        'lists the key names with their purpose';
    like $err, qr/robo-20260815 \(purpose automation\)/,
        'every key, not only the ones of one purpose';
    like $err, qr/admin-ssh-20250101 \(purpose admin, deprecated\)/,
        'deprecated keys too, marked — --name still finds them';

    my ($stderr, $rc) = reported($err);
    isnt $rc, 0, 'exit code is not 0';

    for my $stream ([STDOUT => $out], [STDERR => "$diag$stderr"]) {
        my ($label, $text) = @$stream;
        unlike $text, qr/PRIVATEMATERIAL/, "$label carries no private key half";
        unlike $text, qr/PUBLICMATERIAL/,  "$label carries no public key half";
        unlike $text, qr/ssh-ed25519/,     "$label carries no key at all";
    }
    is $out, '', 'and STDOUT stays empty, as it is only ever for the key';
};

subtest 'ocp keys show --purpose lists the purposes that would work' => sub {
    my ($err) = keys_show_error(options => { purpose => 'amdin' });

    like $err, qr/^Unknown key purpose 'amdin'\./, 'names the input';
    like $err, qr/^Available: admin, automation$/m,
        'lists the purposes of the keys it would print';
    unlike $err, qr/ssh-ed25519|PUBLICMATERIAL|PRIVATEMATERIAL/,
        'no key material';
};

subtest 'a purpose only deprecated keys carry is not offered' => sub {
    my ($err) = keys_show_error(
        keys    => [ { name => 'old', purpose => 'general', deprecated => 1 },
                     { name => 'now', purpose => 'admin' } ],
        options => { purpose => 'general' },
    );

    like $err, qr/^Unknown key purpose 'general'\./, 'refused';
    like $err, qr/^Available: admin$/m,
        'only purposes that actually resolve — offering "general" would loop';
};

# -------------------------------------------------------------------------
# 4. ocp update
# -------------------------------------------------------------------------

subtest 'ocp update names the versions OCP::Versions carries' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew("name: t\n");
    $dir->child('.ocp', 'status.yaml')->spew("ocpVersion: '0.000'\n");

    my $update = OCP::Cmd::Update->new(
        command_chain => [ OCP->new(config => $dir->child('ocp.yaml')->stringify) ],
    );

    my $err;
    {
        # The only way to reach this rejection: an OCP whose own version has
        # no manifest entry. $target_version is $OCP::VERSION, never operator
        # input — so this fakes the OCP, not the manifest, and the listing
        # below is the real one.
        no warnings 'once';
        local $OCP::VERSION = '9.999';
        my $out = '';
        open my $fh, '>', \$out or die "capture stdout: $!";
        my $old = select $fh;
        eval { $update->execute([], []) };
        $err = $@;
        select $old;
    }

    like $err, qr/^Unknown OCP version '9\.999'\./, 'names the version';
    my $known = join ', ', OCP::Versions->known_versions;
    like $err, qr/^\QAvailable: $known\E$/m,
        'lists exactly what the manifest has, read from the manifest';
    like $err, qr/OCP::Versions carries no component manifest for it/,
        'and says what that actually means';

    my (undef, $rc) = reported($err);
    isnt $rc, 0, 'exit code is not 0';
};

subtest 'known_versions comes from the manifest itself' => sub {
    is_deeply [ OCP::Versions->known_versions ],
              [ sort keys %$OCP::Versions::VERSIONS ],
              'not a second list beside it';
};

# -------------------------------------------------------------------------
# 5. Provider types — the mirror image of karr #89
# -------------------------------------------------------------------------

subtest 'an unbuildable provider type lists the buildable ones' => sub {
    eval { OCP::Provider->for_spec({ provider => 'aws' }) };
    my $for_spec = $@;

    eval { OCP::Provider->from_cr({ metadata => { name => 'x' }, spec => { type => 'aws' } }) };
    my $from_cr = $@;

    like $for_spec, qr/^Unknown provider type 'aws'\./, 'names the type';
    like $for_spec, qr/^Available: hetzner, ssh, local$/m, 'lists what it builds';
    is $from_cr, $for_spec,
        'both entry points give one answer — there is one dispatch';
};

subtest 'ocp node add explains a provider CR with an unknown type' => sub {
    my @broken = ( { metadata => { name => 'legacy-aws', namespace => 'ocp-system' },
                     spec     => { type => 'aws' } } );
    my $k8s = FakeK8s->new(providers => [@broken]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s => $k8s, name => 'w1', role => 'worker', provider => 'legacy-aws',
    );

    eval { $add->execute([], []) };

    like $@, qr/^Unknown provider type 'aws'\./, 'same first line as the factory';
    like $@, qr/^Available: hetzner, ssh, local$/m, 'same listing';
    like $@, qr/OCPNodeProvider 'legacy-aws' declares spec\.type 'aws'/,
        'and names the CR the type came from — the operator never typed it';
    is scalar($k8s->calls_of('ensure')), 0, 'no OCPNode CR is written';
};

subtest 'the type set has ONE source: what OCP::Provider can build' => sub {
    my %expect = (
        hetzner => 'OCP::Provider::Hetzner',
        ssh     => 'OCP::Provider::SSH',
        local   => 'OCP::Provider::Local',
    );

    for my $type (OCP::Provider->types) {
        my $prov = eval {
            OCP::Provider->for_spec({ provider => $type },
                token => 'tok', cluster_name => 'c', ssh_key_path => '/dev/null');
        };
        ok $prov, "$type: a listed type is one _build actually constructs"
            or diag $@;
        isa_ok $prov, $expect{$type}, "$type" if $prov;
    }

    ok !OCP::Provider->known_type('aws'), 'a type it cannot build is not known';
    ok !OCP::Provider->known_type(undef), 'and neither is undef';
    ok(OCP::Provider->known_type('local'), 'local is a provider type OCP has');
};

subtest 'every place that lists provider types reads that one source' => sub {
    my @types = OCP::Provider->types;

    # ocp provider add --type
    my $add_err = do {
        require OCP::Cmd::Provider::Add;
        my $add = OCP::Cmd::Provider::Add->new(name => 'p', type => 'aws');
        eval { $add->_validate_flags };
        $@;
    };
    like $add_err, qr/^Unknown provider type 'aws'\./, 'ocp provider add refuses';
    like $add_err, qr/\Q@{[ OCP::Choices::available(@types) ]}\E/,
        'with the listing built from OCP::Provider->types';

    # ocp.yaml validation keeps its own sentence shape, but not its own list
    require OCP::Config;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew("name: t\ncontrol_planes:\n  - provider: aws\n");
    my @errors = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify)->validate;

    like join("\n", @errors),
         qr/\Qinvalid provider 'aws' (must be @{[ OCP::Choices::or_list(@types) ]})\E/,
        'OCP::Config::validate names the same set as a sentence';
};

# -------------------------------------------------------------------------
# 6. ocp node add --role — refused HERE, not by the API server
# -------------------------------------------------------------------------

subtest 'ocp node add --role quatsch is refused before any API call' => sub {
    my $k8s = FakeK8s->new(nodes => [@NODES], providers => [
        { metadata => { name => 'ssh-default', namespace => 'ocp-system' },
          spec     => { type => 'ssh' } },
    ]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s  => $k8s,
        name => 'otho-gpu',
        role => 'quatsch',
        host => '10.0.0.5',
    );

    eval { $add->execute([], []) };
    my $err = $@;

    ok $err, 'the role is refused';
    like $err, qr/^Unknown role 'quatsch'\./, 'names what was typed';
    like $err, qr/^Available: control-plane, worker$/m, 'and what the roles are';

    # THE ASSERTION THAT COUNTS. Before this, spec.role travelled to the API
    # server, whose OCPNode CRD enum refused it — the operator was shown a
    # 422 about a schema instead of a sentence about their input.
    is scalar($k8s->calls), 0,
        'not one API call was made — no 422 to explain';

    my ($stderr, $rc) = reported($err);
    isnt $rc, 0, 'exit code is not 0';
    like $stderr, qr/^Error: Unknown role 'quatsch'\./, 'STDERR carries it';
};

subtest 'a valid role still gets through' => sub {
    for my $role (OCP::Node->roles) {
        my $k8s = FakeK8s->new(providers => []);
        my $add = OCP::Cmd::Node::Add->new(
            k8s => $k8s, name => 'n1', role => $role, host => '10.0.0.5',
        );

        eval { $add->execute([], []) };

        unlike $@, qr/Unknown role/, "$role passes the role check";
        ok scalar($k8s->calls) > 0, "$role gets as far as the API";
    }
};

subtest 'the CLI roles and the OCPNode CRD enum are the same set' => sub {
    my $crd = YAML::XS::LoadFile('share/robocop/crds/ocpnode.yaml');
    my ($version) = @{ $crd->{spec}{versions} };
    my $enum = $version->{schema}{openAPIV3Schema}
                       {properties}{spec}{properties}{role}{enum};

    ok $enum && @$enum, 'the CRD declares an enum for spec.role';

    # Two spellings of one set, because nothing in a YAML schema can call
    # Perl. This is what keeps them honest: the CLI may not refuse a role the
    # API would accept, and may not accept one the API would refuse with a
    # 422 (karr #103; the same seam #110 records for provider types, where
    # the CRD enum is the side that is short one value).
    is_deeply [ sort @$enum ], [ sort OCP::Node->roles ],
        'OCP::Node->roles is exactly the CRD enum';
};

# -------------------------------------------------------------------------
# One error picture, not six
# -------------------------------------------------------------------------

subtest 'every rejection has the shape ocp quatschkommando answers in' => sub {
    my %message = (
        'unknown command' => do {
            my @argv = ('quatschkommando');
            eval { OCP::_resolve_commands('OCP', \@argv) };
            $@;
        },
        'unknown node' => do {
            my $k8s = FakeK8s->new(nodes => [@NODES]);
            eval { OCP::Cmd::Node::Rm->new(k8s => $k8s, name => 'nope')->execute([], []) };
            $@;
        },
        'unknown node (ssh)' =>
            OCP::Cmd::SSH->new->_unknown_node_error('nope', qw(cp-lab)),
        'unknown key' => (keys_show_error(options => { name => 'nope' }))[0],
        'unknown key purpose' => (keys_show_error(options => { purpose => 'nope' }))[0],
        'unknown provider type' => do {
            eval { OCP::Provider->for_spec({ provider => 'aws' }) };
            $@;
        },
        'unknown role' => OCP::Choices::unknown('role', 'nope', [ OCP::Node->roles ]),
    );

    for my $label (sort keys %message) {
        my $err = $message{$label};
        # `ocp quatschkommando` adds " for 'ocp'." before the newline — the
        # command word is the one input whose rejection has to say where it
        # was not understood. Everything after the quoted word is free.
        like $err, qr/^Unknown [\w ]+ '[^']*'[^\n]*\.\n/,
            "$label: opens by naming what it did not understand";
        like $err, qr/^Available: /m,
            "$label: follows with what would have worked";
        like $err, qr/\n\z/,
            "$label: ends in a newline, so no source location is appended";

        my ($stderr, $rc) = reported($err);
        isnt $rc, 0, "$label: exit code is not 0";
        unlike $stderr, qr/at \S+ line \d+/,
            "$label: no Perl location leaks into the operator-facing message";
    }
};

subtest 'OCP::Choices knows no sets of its own' => sub {
    # The point of the module: it is handed the valid values and stores none.
    # A set written down here would be the copy that drifts (karr #102, #109,
    # #110, #112 are all one number or list in two places).
    my $source = path('lib/OCP/Choices.pm')->slurp_utf8;
    $source =~ s/^__END__.*//ms;   # POD
    $source =~ s/^\s*#.*$//mg;     # comments — they may quote examples

    unlike $source, qr/\bhetzner\b|\bworker\b|\bcontrol-plane\b/,
        'no provider type and no role is named in the code';

    is OCP::Choices::available('a', 'b'), "Available: a, b\n", 'plain choices';
    is OCP::Choices::available(['a', 'note']), "Available: a (note)\n",
        'a choice with the note that says why it is the answer';
    is OCP::Choices::or_list('a'), 'a', 'one choice needs no conjunction';
    is OCP::Choices::or_list('a', 'b'), 'a or b', 'two need no comma';
    is OCP::Choices::or_list('a', 'b', 'c'), 'a, b, or c', 'three do';
    is OCP::Choices::unknown('thing', 'x', []), "Unknown thing 'x'.\n",
        'an empty list with nothing to say prints no empty Available: line';
};

done_testing;

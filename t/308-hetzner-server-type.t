#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Cwd qw(abs_path getcwd);
use File::Temp qw(tempdir);
use FindBin;
use JSON::MaybeXS ();
use MIME::Base64 qw(encode_base64);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';
use lib 't/lib';

use OCP;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Validate;
use OCP::Cmd::Init;
use OCP::Config;
use OCP::Hetzner::Picker;
use OCP::Node;
use OCP::Provider;
use OCP::Provider::Hetzner;
use WWW::Hetzner::HTTPResponse;
use WWW::Hetzner::LWPIO;
use OCPTest::HetznerIO;

#
# k264, k308 (2026-11-06): the Hetzner server type.
#
#   - A control plane's default is cpx22 (OCP::Config's %HETZNER_DEFAULTS,
#     Hetzner catalogue as of 2026-11); it was cpx21.
#   - A worker has none. validate() refuses a hetzner pool without
#     server_type, in a line that says what to add; `ocp init` writes no file
#     validate() refuses; and OCP::Provider::Hetzner::create_server, which
#     fell back to cx32, refuses a node whose OCPNode and OCPNodeProvider name
#     none -- what `ocp node add` without --server-type and robocop reach.
#

note 'OCP::Config from ' . abs_path($INC{'OCP/Config.pm'});
note 'OCP::Provider::Hetzner from ' . abs_path($INC{'OCP/Provider/Hetzner.pm'});

my $tmp = tempdir(CLEANUP => 1);
my $n   = 0;

sub config_for {
    my ($spec) = @_;
    my $file = path($tmp)->child('c' . ++$n . '.yaml');
    $file->spew_utf8(YAML::XS::Dump({ name => 'k308', %$spec }));
    return OCP::Config->new(file => "$file");
}

my %HZ_CP = (control_planes => { provider => 'hetzner', server_type => 'cpx22', location => 'fsn1' });

# ---------------------------------------------------------------- k264

subtest 'the control-plane default is cpx22' => sub {
    is $OCP::Config::HETZNER_DEFAULTS{server_type}, 'cpx22', '%HETZNER_DEFAULTS';

    my $file = path($tmp)->child('written.yaml');
    OCP::Config->write_spec("$file", name => 'k308', provider => 'hetzner');
    my $config = OCP::Config->new(file => "$file");
    is $config->control_planes->[0]{server_type}, 'cpx22', 'what write_spec writes without a choice';
    is_deeply [ $config->validate ], [], 'and validate() takes it';
};

# ---------------------------------------------------------------- k308: validate()

my $REQUIRED = qr/server_type required for hetzner -- a worker pool has no default; add one, e\.g\. server_type: cpx22\z/;

subtest 'validate() refuses a hetzner worker pool without server_type, and says what to add' => sub {
    my $config = config_for({ %HZ_CP, workers => [ { name => 'pool1', provider => 'hetzner', nodes => 2 } ] });
    is_deeply [ $config->validate ],
        [ "worker pool 'pool1': server_type required for hetzner -- a worker pool has no default; "
          . "add one, e.g. server_type: cpx22" ],
        'one line: the pool, the key, an example';
    my ($line) = $config->validate;
    like $line, qr/server_type: \Q$OCP::Config::HETZNER_DEFAULTS{server_type}\E\z/,
        'the example is the control-plane default, one source';

    my $err = eval { OCP::Cmd::Apply::Validate::refuse_invalid_config($config); 1 } ? '' : $@;
    like $err, qr/^  - worker pool 'pool1': server_type required for hetzner/m,
        'ocp apply stops on it before it touches anything';

    my %without = (
        'no server_type'      => {},
        'server_type: ""'     => { server_type => '' },
        'server_type: ~'      => { server_type => undef },
    );
    for my $what (sort keys %without) {
        my @lines = config_for({ %HZ_CP, workers => [ { name => 'p', provider => 'hetzner', %{ $without{$what} } } ] })
            ->validate;
        is scalar(grep { /\Aworker pool 'p': $REQUIRED/ } @lines), 1, "$what: refused";
    }

    my @unnamed = config_for({ %HZ_CP, workers => [ { provider => 'hetzner' } ] })->validate;
    ok scalar(grep { /\Aworkers\[1\]: $REQUIRED/ } @unnamed), 'a pool without a name is named by its place';
};

subtest 'what validate() still takes' => sub {
    is_deeply [ config_for({ %HZ_CP, workers => [ { name => 'p', provider => 'hetzner', server_type => 'cax21',
        nodes => 3 } ] })->validate ], [], 'a hetzner pool with its server_type';

    for my $pool ({ name => 'p', provider => 'ssh', host => 'w1.k308.test' }, { name => 'p', provider => 'local' }) {
        my @lines = config_for({ %HZ_CP, workers => [ $pool ] })->validate;
        is scalar(grep { /server_type required/ } @lines), 0, "$pool->{provider}: names no server type, needs none";
    }

    # A server_type that is no string has its own line, not "required" beside it.
    my @list = config_for({ %HZ_CP, workers => [ { name => 'p', provider => 'hetzner', server_type => [ 'cpx22' ] } ] })
        ->validate;
    is scalar(grep { /server_type must be a string/ } @list), 1, 'a list: its shape line';
    is scalar(grep { /server_type required/ } @list),        0, 'and no second line about it';
};

subtest 'the line is validate()\'s alone: commands that read a pool without it are not stopped' => sub {
    # ocp destroy, ocp status and ocp node ls refuse the lines at the paths
    # they read (spec_errors), not all of validate(). An ocp.yaml from before
    # this change has to stay destroyable.
    my $config = config_for({ %HZ_CP, workers => [ { name => 'pool1', provider => 'hetzner', nodes => 1 } ] });
    is_deeply [ $config->spec_errors('workers', 'workers[*]', 'workers[*].server_type', 'workers[*].nodes') ], [],
        'no line at any pool path';
    ok scalar($config->validate), 'while validate() has one';
};

# ---------------------------------------------------------------- k308: ocp init

my $BIN = "$FindBin::Bin/../bin/ocp";
my $LIB = "$FindBin::Bin/../lib";

sub have { system("command -v $_[0] >/dev/null 2>&1") == 0 }

# What init wrote, held against validate(): no line, and no hetzner pool
# without a server type (init writes no pool today; one it writes must name
# its type).
sub init_output_ok {
    my ($dir, $what) = @_;
    my $file = path($dir)->child('ocp.yaml');
    ok -f $file, "$what: ocp.yaml written" or return;
    my $config = OCP::Config->new(file => "$file");
    is_deeply [ $config->validate ], [], "$what: validate() takes it";
    my @bare = grep { ref eq 'HASH' && ($_->{provider} // '') eq 'hetzner' && !$_->{server_type} }
        @{ ref $config->workers eq 'ARRAY' ? $config->workers : [] };
    is scalar(@bare), 0, "$what: no hetzner pool without a server type";
}

sub run_init {
    my ($args, %opt) = @_;
    my $dir = $opt{dir} // tempdir(CLEANUP => 1);
    my $cwd = getcwd();
    local $ENV{HETZNER_API_TOKEN} = $opt{token} // '';    # never a real one
    chdir $dir or die "chdir: $!";
    # STDIN a pipe: no terminal, the batch path.
    my $out = `echo | $^X -I'$LIB' '$BIN' init --nopassword --nogit --name k308 @$args 2>&1`;
    my $rc  = $? >> 8;
    chdir $cwd or die "chdir back: $!";
    return ($rc, $out, $dir);
}

subtest 'every ocp.yaml ocp init writes without a terminal passes validate()' => sub {
    plan skip_all => 'needs ssh-keygen' unless have('ssh-keygen');

    my @paths = (
        [ 'bare (hetzner)'               => [] ],
        [ '--provider hetzner'           => [ '--provider', 'hetzner' ] ],
        [ '--hetzner, token, no TTY'     => [ '--hetzner' ], token => 'not-a-real-token' ],
        [ '--dist k3s'                   => [ '--dist', 'k3s' ] ],
        [ '--provider ssh --host'        => [ '--provider', 'ssh', '--host', 'cp.k308.test' ] ],
        [ '--provider local'             => [ '--provider', 'local' ] ],
        [ '--provider local --service'   => [ '--provider', 'local', '--service', 'none' ] ],
    );
    for my $p (@paths) {
        my ($what, $args, %opt) = @$p;
        my ($rc, $out, $dir) = run_init($args, %opt);
        is $rc, 0, "$what: init exits 0" or diag $out;
        init_output_ok($dir, $what);
    }

    # --force writes anew over an ocp.yaml validate() refuses since this change.
    my $old = tempdir(CLEANUP => 1);
    path($old)->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({ name => 'k308', %HZ_CP,
        workers => [ { name => 'pool1', provider => 'hetzner', nodes => 2 } ] }));
    my ($rc, $out) = run_init([ '--force' ], dir => $old);
    is $rc, 0, '--force over an old ocp.yaml: init exits 0' or diag $out;
    init_output_ok($old, '--force over an old ocp.yaml');

    # Without --force init keeps ocp.yaml and adds what is missing (system:).
    my $kept = tempdir(CLEANUP => 1);
    path($kept)->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({ name => 'k308', %HZ_CP,
        workers => [ { name => 'pool1', provider => 'hetzner', server_type => 'cpx22', nodes => 2 } ] }));
    ($rc, $out) = run_init([], dir => $kept);
    is $rc, 0, 'an existing ocp.yaml: init exits 0' or diag $out;
    init_output_ok($kept, 'an existing ocp.yaml');
};

subtest 'ocp init --hetzner at a terminal: what the pickers write passes validate()' => sub {
    plan skip_all => 'needs ssh-keygen' unless have('ssh-keygen');

    my $both = [ map { { name => $_, available => JSON::MaybeXS::true, deprecation => undef } } qw( fsn1 hel1 ) ];
    my $type = sub {
        my ($name, $cores, $arch) = @_;
        return { id => 1, name => $name, description => uc $name, cores => $cores, memory => 4, disk => 40,
                 cpu_type => 'shared', architecture => $arch, locations => $both };
    };
    my $location = sub {
        return { id => 1, name => $_[0], description => $_[1], city => $_[1], country => 'DE',
                 network_zone => 'eu-central' };
    };

    for my $case ([ "\n\n" => 'Enter, Enter: the defaults' ], [ "hel1\ncax21\n" => 'hel1 and cax21 by name' ]) {
        my ($input, $what) = @$case;
        my $io = OCPTest::HetznerIO->new(collections => {
            locations    => [ $location->('fsn1', 'Falkenstein'), $location->('hel1', 'Helsinki') ],
            server_types => [ $type->('cpx22', 2, 'x86'), $type->('cax21', 4, 'arm') ],
        });
        my $init = OCP::Cmd::Init->new(
            command_chain => [ OCP->new ],
            nogit         => 1,
            name          => 'k308',
            hetzner       => 1,
            nopassword    => 1,
            _interactive  => 1,
            _picker       => OCP::Hetzner::Picker->new(token => 'fake-token', _cloud => $io->cloud),
        );

        my $dir = tempdir(CLEANUP => 1);
        my $cwd = getcwd();
        local $ENV{HETZNER_API_TOKEN} = 'not-a-real-token';
        chdir $dir or die "chdir: $!";
        my $out = '';
        my $err = do {
            open my $in, '<', \$input or die "stdin: $!";
            open my $fh, '>', \$out   or die "capture: $!";
            local *STDIN  = $in;
            local *STDOUT = $fh;
            eval { $init->execute([], []); 1 } ? '' : $@;
        };
        chdir $cwd or die "chdir back: $!";

        is $err, '', "$what: init completed" or diag $out;
        like $out, qr/\[ok\] Control plane: /, "$what: the pickers ran";
        init_output_ok($dir, $what);
    }
};

# ---------------------------------------------------------------- k308: the provider

# A real Kubernetes::REST on a recording transport, as t/74 has it: OCP::Node
# takes its lease and writes its status through the client as it ships.
package MockResponse {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
    sub headers { {} }
}

package MockTransport {
    my $JSON = JSON::MaybeXS->new(utf8 => 1, canonical => 1, convert_blessed => 1);
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub call {
        my ($self, $req) = @_;
        my $api = $self->{api};
        (my $path = $req->url) =~ s{^https?://[^/]+}{};
        push @{ $api->requests }, { method => $req->method, path => $path, body => $req->content };
        my ($status, $struct) =
              $req->method eq 'PUT' || $req->method eq 'PATCH'      ? (200, $JSON->decode($req->content))
            : $path =~ m{/ocpnodes/[^/]+$}                          ? (200, $api->cr)
            : $path =~ m{/ocpnodeproviders/[^/]+$}                  ? (200, $api->provider_cr)
            : $path =~ m{^/api/v1/namespaces/[^/]+/secrets/[^/]+$}  ? (200, $api->secret)
            :                                                         (404, { message => "unexpected path $path" });
        return MockResponse->new(status => $status, content => $JSON->encode($struct));
    }
}

package StrictK8s {
    use Moo;
    use OCP::K8s;
    extends 'Kubernetes::REST';
    use namespace::clean;    # Moo's `with` would shadow Kubernetes::REST's (k132)

    has requests    => (is => 'ro', default => sub { [] });
    has cr          => (is => 'rw');
    has provider_cr => (is => 'rw');
    has secret      => (is => 'rw');

    sub build {
        my $transport = MockTransport->new;
        my $self = StrictK8s->new(
            server                    => { endpoint => 'https://cluster.invalid:6443' },
            credentials               => { token => 'fake-token' },
            resource_map_from_cluster => 0,
            io                        => $transport,
        );
        $transport->{api} = $self;
        OCP::K8s->register($self);
        return $self;
    }
}

package RecordingApi {
    sub new    { bless { ensured => [] }, $_[0] }
    sub ensure { push @{ $_[0]{ensured} }, $_[1]; $_[1] }
}

package FakeSecrets {
    sub new           { bless {}, $_[0] }
    sub hetzner_token { 'hz-k308' }
}

package main;

subtest 'a worker whose OCPNode and provider name no server type goes Failed, and nothing is created' => sub {
    # The provider CR ocp apply writes: what robocop and `ocp node add` build
    # the adapter from. It carries no server type -- a pool's comes on each of
    # its OCPNodes (worker_ocpnodes), which validate() makes sure of.
    my $config = config_for({ %HZ_CP, workers => [ { name => 'pool1', provider => 'hetzner',
        server_type => 'cax21' } ] });
    my $rec = RecordingApi->new;
    {
        local *STDOUT;
        open STDOUT, '>', \my $sink or die;
        OCP::Cmd::Apply::CR::ensure_provider_cr(undef, $rec, 'hetzner', 'ocp-system', $config, FakeSecrets->new);
    }
    my ($provider_cr) = grep { $_->{kind} eq 'OCPNodeProvider' } @{ $rec->{ensured} };
    ok !exists $provider_cr->{spec}{hetzner}{serverType}, 'the provider CR ocp apply writes names no server type';
    my ($pool_node) = OCP::Cmd::Apply::CR::worker_ocpnodes($config);
    is $pool_node->{spec}{serverType}, 'cax21', 'a pool\'s OCPNode carries the pool\'s';

    # The node `ocp node add w1 --provider hetzner-default` writes without
    # --server-type, reconciled the way robocop and the CLI fallback do.
    my $k8s = StrictK8s::build();
    $k8s->provider_cr($provider_cr);
    $k8s->secret({ apiVersion => 'v1', kind => 'Secret',
        metadata => { name => $provider_cr->{spec}{hetzner}{tokenSecretRef}{name}, namespace => 'ocp-system' },
        data     => { token => encode_base64('hz-k308', '') } });
    $k8s->cr({ apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
        metadata => { name => 'w1', namespace => 'ocp-system', resourceVersion => '1' },
        spec     => { role => 'worker', providerRef => 'hetzner-default' },
        status   => { phase => 'Pending' } });

    my @wire;
    no warnings 'redefine';
    local *WWW::Hetzner::LWPIO::call = sub {
        my ($io, $req) = @_;
        (my $p = $req->url) =~ s{\Ahttps://api\.hetzner\.cloud/v1}{};
        ($p) = split /\?/, $p;
        push @wire, $req->method . " $p";
        return WWW::Hetzner::HTTPResponse->new(status => 200,
            content => JSON::MaybeXS::encode_json({ servers => [] }))
            if $req->method eq 'GET' && $p eq '/servers';
        return WWW::Hetzner::HTTPResponse->new(status => 500, content => '{"error":{"message":"not faked"}}');
    };

    my $fetched = $k8s->k8s->object_to_struct(
        $k8s->get('OCPNodeProvider', 'hetzner-default', namespace => 'ocp-system'));
    my $node = OCP::Node->from_cr($k8s->cr, k8s => $k8s,
        provider => OCP::Provider->from_cr($fetched, k8s => $k8s), reconciler_id => 'robocop');
    is $node->reconcile, 0, 'reconcile reports the node as not done';

    my ($status) = map { JSON::MaybeXS::decode_json($_->{body})->{status} }
        grep { $_->{method} eq 'PATCH' && $_->{path} =~ m{/status$} } @{ $k8s->requests };
    is $status->{phase}, 'Failed', 'the OCPNode goes Failed';
    like $status->{message}, qr/\ARefusing to create Hetzner server 'w1' without a server type/,
        'status.message says what is missing';
    like $status->{message}, qr/spec\.serverType/,         'on the OCPNode';
    like $status->{message}, qr/spec\.hetzner\.serverType/, 'and on the OCPNodeProvider';
    # A Failed OCPNode is left alone by every reconciler: the way out is a
    # fresh one, so the line says to remove the node before adding it again.
    like $status->{message}, qr/ocp node rm w1, then ocp node add w1 --server-type TYPE/,
        'and how to give one: remove the node, add it with a type';
    like $status->{message}, qr/ocp provider add --server-type TYPE/, 'or a provider with one';
    unlike $status->{message}, qr/cx32/,                    'no type of its own';
    is_deeply [ grep { /\APOST / } @wire ], [], 'no server was ordered';
};

subtest 'the provider refuses before anything is created, and only where nothing names a type' => sub {
    my $prov = sub {
        my $io = OCPTest::HetznerIO->new(collections => { servers => [] });
        return (OCP::Provider::Hetzner->new(token => 'fake-token', cluster_name => 'k308',
            ssh_key_name => 'ocp-k308-admin', cloud => $io->cloud, @_), $io);
    };

    my ($p, $io) = $prov->();
    ok !eval { $p->create_server(name => 'w1', node => 'w1', role => 'worker', spec => {}); 1 },
        'no server type at any rank: refused';
    like $@, qr/without a server type/, 'with the line that names it';
    is_deeply [ grep { $_->{method} eq 'POST' } @{ $io->requests } ], [], 'nothing was ordered';

    # Each rank still answers: the named option, the node, the provider.
    for my $case ([ 'option', [], server_type => 'cpx22' ], [ 'node spec', [], spec => { serverType => 'cpx22' } ],
                  [ 'provider', [ default_server_type => 'cpx22' ] ]) {
        my ($what, $build, @call) = @$case;
        my ($q, $qio) = $prov->(@$build);
        # The fake answers no POST; the request going out is the point.
        eval { $q->create_server(name => 'w1', node => 'w1', role => 'worker', @call) };
        my ($post) = grep { $_->{method} eq 'POST' } @{ $qio->requests };
        ok $post, "$what: the create went out";
        unlike $@, qr/without a server type/, "$what: not refused";
    }
};

done_testing;

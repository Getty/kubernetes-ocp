#!/usr/bin/env perl
# karr k401, the follow-ups of the one shape check (k400): what is read of
# ocp.yaml around the check up front, where a raw reader had no net, and the
# one list of what reaching the first control plane reads.
#
# The claims:
#
#   1. init: on an ocp.yaml whose control_planes is [ foo ], or whose first
#      control plane's provider is a list, ocp init --force writes ocp.yaml
#      anew, exit 0, no Perl text -- with --force init reads nothing of the old
#      file (_effective_provider returns before it); without --force init
#      refuses the line in its words before it changes anything
#   2. spec_taints, the net behind the check: a taints: that is no list, and
#      an entry that is no taint, die with validate()'s words as one line
#      without a Perl location -- a string was dropped without a word, an
#      entry croaked, an internal error --, and so does worker_ocpnodes on
#      such a pool instead of making its OCPNode without the taints; an unset
#      taints: and a list of taints give what they gave
#   3. one list for the first control plane:
#      (a) every section and every key of the first control plane that
#          cluster_status and cluster_ssh_key (dev mode) read is in
#          first_control_plane_spec_paths, and nothing else is: a new read
#          there fails here until the list has it
#      (b) node add, update, deploy-robocop and status declare that list,
#          through the helper (what the helper returns shows up); ssh declares
#          cluster_ssh_key_spec_paths through the helper, and no control
#          plane's public_ip or name, which it does not read
#      (c) each of the five refuses a malformed path of the list it declares
#          in its words; ssh does not refuse a public_ip or name
#
# Network-free and cluster-free: no kubeconfig.yaml, no keys.yaml, hosts
# *.invalid, and the prompts and SSH die in each child.

use strict;
use warnings;
use Test::More;

use Path::Tiny qw( path );
use File::Temp qw( tempdir );
use Tie::Hash ();

use lib 'lib';
use lib 't/lib';

# Rex first: it puts the working directory's lib/ in front of @INC, so what
# loads after it is checked below to come from this tree.
use OCP::Rex ();

use OCP;
use OCP::Config;
use OCP::ClusterKey;
use OCP::NodeMeta;
use OCP::Password;
use OCP::Provider::Local;
use OCP::SSH;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::DeployRobocop;
use OCP::Cmd::Init;
use OCP::Cmd::Node::Add;
use OCP::Cmd::SSH;
use OCP::Cmd::Status;
use OCP::Cmd::Update;
use OCPTest::Cli qw( run_ocp );

delete $ENV{SOPS_AGE_KEY_FILE};
delete $ENV{OCP_OPERATOR_KEY};

my $LIB = path('lib')->realpath;
for my $file (qw( OCP/NodeMeta.pm OCP/Role/Cmd.pm OCP/Cmd/Init.pm OCP/Cmd/SSH.pm OCP/Config.pm )) {
    ok $LIB->subsumes(path($INC{$file})->realpath), "$file comes from this tree's lib/"
        or diag $INC{$file};
}

# --- Projects and runs ------------------------------------------------------------

my %BASE = (name => 'k401', control_planes => { provider => 'ssh', host => 'cp.k401.invalid' });

my $ROOT = path(tempdir(CLEANUP => 1));

sub project {
    my ($spec) = @_;
    my $dir = path(tempdir(DIR => "$ROOT"));
    OCP->dump_file($dir->child('ocp.yaml')->stringify, $spec);
    return $dir;
}

sub validate_lines {
    my ($dir) = @_;
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify)->validate;
}

# A child's setup: a prompt or an SSH or Rex run is a die naming it.
sub setup {
    return sub {
        no warnings 'redefine';
        for my $way (qw( OCP::Password::prompt_password OCP::Password::prompt_new_pin
                         OCP::SSH::run OCP::SSH::run_script OCP::SSH::interactive
                         OCP::Rex::run_task )) {
            no strict 'refs';
            *{$way} = sub { die "k401: outside ($way)\n" };
        }
    };
}

my $PERL_TEXT = qr/internal error| at \S+ line \d+|(?:ARRAY|HASH)\(0x/;

sub role_text {
    my ($words, @lines) = @_;
    my $s = @lines == 1 ? '' : 's';
    return "Error: ocp.yaml has " . scalar(@lines) . " error$s:\n"
      . join('', map { "  - $_\n" } @lines)
      . "Nothing was done: $words checks what it reads of ocp.yaml before it asks for a PIN "
      . "or touches the cluster or a machine. Fix the line$s above and run it again.\n";
}

# --- 1. init ------------------------------------------------------------------------

# The bootstrap key is there already, so --nopassword init makes none.
sub init_project {
    my ($spec) = @_;
    my $dir = project($spec);
    $dir->child('.ocp')->mkpath;
    $dir->child('.ocp', 'id_ed25519')->spew("k401 key\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew("ssh-ed25519 AAAAk401 k401\n");
    return $dir;
}

subtest 'init: a first control plane validate() refuses, with and without --force' => sub {
    for my $case ([ 'control_planes: [ foo ]' => [ 'foo' ] ],
                  [ 'a provider that is a list' => [ { provider => [ 'a' ], host => 'cp.k401.invalid' } ] ]) {
        my ($what, $cps) = @$case;

        my $dir = init_project({ %BASE, control_planes => $cps });
        my @lines = validate_lines($dir);
        is scalar(@lines), 1, "$what: validate() has one line" or diag explain \@lines;

        my $r = run_ocp($dir, setup(), qw( init --nogit --nopassword --force ));
        is $r->{exit}, 0, "$what, --force: exit 0" or diag $r->{err};
        unlike "$r->{out}$r->{err}", $PERL_TEXT, "$what, --force: no Perl text";
        unlike $r->{err}, qr/has \d+ errors?:/, "$what, --force: no refusal";
        is ref(OCP->load_file($dir->child('ocp.yaml')->stringify)->{control_planes}), 'HASH',
            "$what, --force: ocp.yaml written anew";

        $dir = init_project({ %BASE, control_planes => $cps });
        my $before = $dir->child('ocp.yaml')->slurp_raw;
        $r = run_ocp($dir, setup(), qw( init --nogit --nopassword ));
        is $r->{err}, role_text('ocp init', @lines), "$what, no --force: refused, in its words";
        is $r->{exit}, 1, "$what, no --force: exit 1";
        is $r->{out}, '', "$what, no --force: nothing on STDOUT";
        is $dir->child('ocp.yaml')->slurp_raw, $before, "$what, no --force: ocp.yaml as it was";
        ok !-e $dir->child('.gitignore'), "$what, no --force: nothing made";
    }
};

# --- 2. spec_taints ---------------------------------------------------------------------

my $NO_LIST = qq{worker pool: taints must be a list like [ "key=value:NoSchedule" ]\n};

subtest 'spec_taints: no list, or no taint, is said as one line' => sub {
    for my $case ([ 'foo' => 'foo' ], [ '{}' => {} ], [ '7' => 7 ]) {
        my ($shown, $taints) = @$case;
        ok !eval { OCP::NodeMeta->spec_taints($taints); 1 }, "taints: $shown dies";
        is $@, $NO_LIST, "taints: $shown: validate()'s words, one line, no Perl location";
    }

    for my $case ([ 'foo', "worker pool: taint 'foo': expected key=value:Effect or key:Effect\n" ],
                  [ 'k=v:Sometimes', "worker pool: taint 'k=v:Sometimes': effect must be "
                                   . "NoSchedule, PreferNoSchedule, NoExecute\n" ],
                  [ [ 'a' ], "worker pool: taint must be a string like key=value:NoSchedule\n" ]) {
        my ($entry, $line) = @$case;
        my $shown = ref $entry ? '[ a ]' : $entry;
        ok !eval { OCP::NodeMeta->spec_taints([ 'k=v:NoSchedule', $entry ]); 1 }, "an entry $shown dies";
        is $@, $line, "an entry $shown: taint_error's reason, one line, no Perl location";
    }

    is_deeply(OCP::NodeMeta->spec_taints(undef), [], 'unset: none');
    is_deeply(OCP::NodeMeta->spec_taints([]), [], 'an empty list: none');
    is_deeply(OCP::NodeMeta->spec_taints([ 'nvidia.com/gpu=present:NoSchedule', 'gpu:NoExecute' ]),
        [ { key => 'nvidia.com/gpu', value => 'present', effect => 'NoSchedule' },
          { key => 'gpu', effect => 'NoExecute' } ],
        'a list of taints: parsed, as before');
};

subtest 'worker_ocpnodes: a pool\'s taints: foo is said, not dropped' => sub {
    my $pool = { name => 'w', provider => 'ssh', host => 'w.k401.invalid' };
    my $dir = project({ %BASE, workers => [ { %$pool, taints => 'foo' } ] });
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
    my @crs = eval { OCP::Cmd::Apply::CR::worker_ocpnodes($config) };
    is $@, $NO_LIST, 'dies with the line';
    is scalar(@crs), 0, 'and makes no OCPNode without its taints';

    $dir = project({ %BASE, workers => [ { %$pool, taints => [ 'gpu:NoSchedule' ] } ] });
    ($crs[0]) = OCP::Cmd::Apply::CR::worker_ocpnodes(
        OCP::Config->new(file => $dir->child('ocp.yaml')->stringify));
    is_deeply $crs[0]{spec}{taints}, [ { key => 'gpu', effect => 'NoSchedule' } ],
        'a list of taints: on the OCPNode, as before';
};

# --- 3. the first control plane ---------------------------------------------------------

my @FIRST = OCP::Role::Cmd->first_control_plane_spec_paths;
my @KEY   = OCP::Role::Cmd->cluster_ssh_key_spec_paths;

# A hash that writes down each key read, under its name.
package ReadProbe {
    our @ISA = ('Tie::ExtraHash');
    our %READ;
    sub TIEHASH { my ($class, $where, $hash) = @_; return bless [ $hash, $where ], $class }
    sub FETCH   { $READ{ $_[0][1] }{ $_[1] } = 1; return $_[0][0]{ $_[1] } }
    sub EXISTS  { $READ{ $_[0][1] }{ $_[1] } = 1; return exists $_[0][0]{ $_[1] } }
}

package main;

# A Config on $cp as the first control plane, the spec and the entry probed.
sub probed_config {
    my ($dir, $cp) = @_;
    tie my %cp, 'ReadProbe', 'cp', { %$cp };
    tie my %spec, 'ReadProbe', 'spec', { name => 'k401', control_planes => [ \%cp ] };
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify, spec => \%spec);
}

subtest 'what cluster_status and cluster_ssh_key read is the list' => sub {
    my $dir = project({ %BASE });
    $dir->child('.ocp')->mkpath;
    $dir->child('.ocp', 'id_ed25519')->spew("k401 key\n");
    local %ReadProbe::READ;

    # Each way cluster_status finds the address: public_ip, host, a local
    # machine's own, none.
    no warnings 'redefine';
    local *OCP::Provider::Local::_default_route_source_ip = sub { '10.0.0.2' };
    for my $cp ({ public_ip => '10.0.0.1', name => 'cp' }, { host => 'cp.k401.invalid' },
                { provider => 'local' }, {}) {
        probed_config($dir, $cp)->cluster_status;
    }
    is probed_config($dir, { provider => 'local' })->cluster_status->{public_ip}, '10.0.0.2',
        'the local branch ran';

    # Dev mode, no keys.yaml: the bootstrap key's paths.
    my $key = OCP::ClusterKey->for_config(probed_config($dir, { provider => 'ssh', host => 'h' }));
    is $key->origin, 'bootstrap', 'cluster_ssh_key: the bootstrap key';

    my %sections = map { /\A([a-z_]+)/ ? ($1 => 1) : () } @FIRST;
    my %keys     = map { /\Acontrol_planes\[1\]\.([a-z_]+)\z/ ? ($1 => 1) : () } @FIRST;
    is_deeply [ sort keys %{ $ReadProbe::READ{spec} } ], [ sort keys %sections ],
        'the sections read are the list\'s: ' . join(', ', sort keys %sections);
    is_deeply [ sort keys %{ $ReadProbe::READ{cp} } ], [ sort keys %keys ],
        'the first control plane\'s keys read are the list\'s: ' . join(', ', sort keys %keys);
    ok((grep { $_ eq 'control_planes' } @FIRST) && (grep { $_ eq 'control_planes[1]' } @FIRST),
        'and the list has control_planes and its first entry');
    is_deeply [ grep { /\Assh/ } @FIRST ], [ @KEY ], 'the key\'s part is cluster_ssh_key_spec_paths';
};

# [ class, how to ask it, the helper it declares through, words, argv ]
my @COMMANDS = (
    [ 'OCP::Cmd::Node::Add',     sub { OCP::Cmd::Node::Add->new(name => 'w1') },
      'first_control_plane_spec_paths', 'ocp node add', [ qw( node add w1 ) ] ],
    [ 'OCP::Cmd::Node::Add',     sub { OCP::Cmd::Node::Add->new(name => 'w1', gpu => 1) },
      'first_control_plane_spec_paths', 'ocp node add', [ qw( node add w1 --gpu ) ] ],
    [ 'OCP::Cmd::Update',        sub { 'OCP::Cmd::Update' },
      'first_control_plane_spec_paths', 'ocp update', [ qw( update ) ] ],
    [ 'OCP::Cmd::DeployRobocop', sub { 'OCP::Cmd::DeployRobocop' },
      'first_control_plane_spec_paths', 'ocp deploy-robocop', [ qw( deploy-robocop ) ] ],
    [ 'OCP::Cmd::Status',        sub { 'OCP::Cmd::Status' },
      'first_control_plane_spec_paths', 'ocp status', [ qw( status ) ] ],
    [ 'OCP::Cmd::SSH',           sub { 'OCP::Cmd::SSH' },
      'cluster_ssh_key_spec_paths', 'ocp ssh', [ qw( ssh --node x ) ] ],
);

subtest 'the commands declare the list through the helper' => sub {
    my $config = OCP::Config->new(file => project({ %BASE })->child('ocp.yaml')->stringify);
    for my $c (@COMMANDS) {
        my ($class, $who, $helper, $words, $argv) = @$c;
        my $what = "@$argv";
        my %declared = map { $_ => 1 } $who->()->spec_paths($config);
        my @want = $helper eq 'first_control_plane_spec_paths' ? @FIRST : @KEY;
        is_deeply [ grep { !$declared{$_} } @want ], [], "$what: declares every path of $helper";

        no strict 'refs';
        no warnings 'redefine';
        local *{"${class}::$helper"} = sub { 'k401-sentinel' };
        ok((grep { $_ eq 'k401-sentinel' } $who->()->spec_paths($config)), "$what: through $helper");
    }

    # The key's part reaches the list through it.
    no warnings 'redefine';
    local *OCP::Cmd::Update::cluster_ssh_key_spec_paths = sub { 'k401-sentinel' };
    ok((grep { $_ eq 'k401-sentinel' } OCP::Cmd::Update->spec_paths($config)),
        'first_control_plane_spec_paths takes the key\'s paths from cluster_ssh_key_spec_paths');

    my @ssh = OCP::Cmd::SSH->spec_paths($config);
    is_deeply [ grep { /\Acontrol_planes\[[^\]]+\]\.(?:public_ip|name)\z/ } @ssh ], [],
        'ssh declares no control plane\'s public_ip or name';
};

# Each path of the list at a value validate() refuses, one line each.
my @MALFORMED = (
    [ 'control_planes',              { control_planes => 'foo' } ],
    [ 'control_planes[1]',           { control_planes => [ 'foo' ] } ],
    [ 'control_planes[1].provider',  { control_planes => [ { provider => [ 'a' ], host => 'cp.k401.invalid' } ] } ],
    [ 'control_planes[1].public_ip', { control_planes => [ { provider => 'ssh', host => 'cp.k401.invalid',
                                                             public_ip => [ 'a' ] } ] } ],
    [ 'control_planes[1].host',      { control_planes => [ { provider => 'ssh', host => [ 'a' ] } ] } ],
    [ 'control_planes[1].name',      { control_planes => [ { provider => 'ssh', host => 'cp.k401.invalid',
                                                             name => [ 'a' ] } ] } ],
    [ 'ssh',                         { ssh => 'foo' } ],
);

subtest 'each command refuses a malformed path of the list, in its words' => sub {
    is_deeply [ sort map { $_->[0] } @MALFORMED ], [ sort @FIRST ], 'a case for every path of the list';

    for my $case (@MALFORMED) {
        my ($path, $spec) = @$case;
        my $dir = project({ %BASE, %$spec });
        my @lines = validate_lines($dir);
        is scalar(@lines), 1, "$path: validate() has one line" or diag explain \@lines;

        for my $c (@COMMANDS) {
            my ($class, $who, $helper, $words, $argv) = @$c;
            my $what = "@$argv, $path";
            my $r = run_ocp($dir, setup(), @$argv);
            if ($class eq 'OCP::Cmd::SSH' && $path =~ /\.(?:public_ip|name)\z/) {
                unlike $r->{err}, qr/has \d+ errors?:/, "$what: no refusal" or diag $r->{err};
                like $r->{err}, qr/No cluster deployed yet/, "$what: on to the cluster" or diag $r->{err};
            }
            else {
                is $r->{err}, role_text($words, @lines), "$what: refused, in its words";
                is $r->{exit}, 1, "$what: exit 1";
            }
            unlike "$r->{out}$r->{err}", $PERL_TEXT, "$what: no Perl text" or diag $r->{err};
        }
    }
};

done_testing;

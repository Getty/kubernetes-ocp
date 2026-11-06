#!/usr/bin/env perl
# karr k361 -- OCP::Cmd::Apply::CR::worker_ocpnodes counted a pool's nodes:
# whatever it was. A list numified to its address and a huge number was taken
# as is: both built OCPNodes until the host ran out of memory. `ocp apply` is
# safe, validate() refuses those pools first; the commands that walk the
# machines without validate() are not -- `ocp keys operator add|rm`, `ocp keys
# secure --drop-bootstrap` (OCP::Role::Cmd::Machines), `ocp node ls` -- and
# k346's gate skips a pool whose provider is unknown or missing.
#
# The claims:
#
#   * a count is taken where validate() takes one: a whole number, on a pool
#     whose provider OCP knows
#   * any other nodes: stands for one worker, as control_planes() reads a
#     count validate() refuses (k296) -- a list, a number that is no whole
#     number, and any nodes: of a pool whose provider is unknown, missing or
#     no string; validate() has a line for every one of them
#   * `ocp keys operator add` over such a pool (fake cluster, fake SSH) walks
#     the machines and ends as it would without the pool
#
# Bounded on purpose: every OCPNode worker_ocpnodes builds passes through
# OCP::NodeMeta->spec_labels once, and the wrapper below dies past $LIMIT. A
# run of the code before the fix (or a mutant) builds at most $LIMIT OCPNodes
# and fails, instead of running the host out of memory; 'the guard is armed'
# proves it counts in that very loop. alarm() is the fuse for time.

use strict;
use warnings;
use Test::More;

use Crypt::Age;
use Cwd qw( getcwd );
use Path::Tiny ();

use lib 'lib';

use OCP;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Keys::Operator::Add;
use OCP::Config;
use OCP::Keys;
use OCP::NodeMeta;
use OCP::Password;
use OCP::Secrets;
use OCP::SSH;

$SIG{ALRM} = sub { die "k361 fuse: the test ran out of time\n" };
alarm 120;

# --- The bound ----------------------------------------------------------------

our $LIMIT = 1000;
our $BUILT = 0;
{
    no warnings 'redefine';
    my $orig = \&OCP::NodeMeta::spec_labels;
    *OCP::NodeMeta::spec_labels = sub {
        die "k361 guard: more than $LIMIT OCPNodes built\n" if ++$BUILT > $LIMIT;
        goto &$orig;
    };
}

# --- worker_ocpnodes ---------------------------------------------------------

my @KEEP;
# ocp.yaml as typed: `nodes: 1e12` is what YAML::XS makes of it, not what
# Perl would dump.
sub config_from_text {
    my ($workers) = @_;
    my $dir = Path::Tiny->tempdir;
    push @KEEP, $dir;
    $dir->child('ocp.yaml')->spew_utf8(
        "name: k361\ncontrol_planes:\n  provider: ssh\n  host: cp.k361.test\nworkers:\n$workers");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub built {
    my ($config) = @_;
    local $BUILT = 0;
    my @crs = eval { OCP::Cmd::Apply::CR::worker_ocpnodes($config) };
    return { died => $@, names => [ map { $_->{metadata}{name} } @crs ],
             refs => [ map { $_->{spec}{providerRef} } @crs ], built => $BUILT };
}

subtest 'the guard is armed: it counts the OCPNodes of that loop' => sub {
    my $r = built(config_from_text("  - name: hz\n    provider: hetzner\n    nodes: $LIMIT\n"));
    is $r->{died}, '', "$LIMIT: no death";
    is scalar @{ $r->{names} }, $LIMIT, "$LIMIT: $LIMIT OCPNodes";
    is $r->{built}, $LIMIT, "$LIMIT: each one counted";

    my $over = $LIMIT + 1;
    $r = built(config_from_text("  - name: hz\n    provider: hetzner\n    nodes: $over\n"));
    is $r->{died}, "k361 guard: more than $LIMIT OCPNodes built\n", "$over: the guard stops it";
};

subtest 'control: a count validate() takes is the count' => sub {
    for my $case ([ 3, [ 'hz-1', 'hz-2', 'hz-3' ] ], [ 0, [] ]) {
        my ($n, $names) = @$case;
        # server_type: validate() requires it of a hetzner pool (k308).
        my $config = config_from_text("  - name: hz\n    provider: hetzner\n    server_type: cpx22\n"
            . "    nodes: $n\n");
        is_deeply [ $config->validate ], [], "nodes: $n -- validate() passes it";
        is_deeply built($config)->{names}, $names, "nodes: $n -- $n OCPNode(s)";
    }
    is_deeply built(config_from_text("  - name: hz\n    provider: hetzner\n"))->{names}, [ 'hz-1' ],
        'no nodes: one, as before';
};

# [ what, the pool as typed, validate()'s line for it, the providerRef ]
my @UNCOUNTED = (
    # The card's two.
    [ 'provider foo, nodes: a list' => "    provider: foo\n    nodes: [ a.k361.test, b.k361.test ]\n",
      qr/\Aworker pool 'p': invalid provider 'foo'/, 'foo-default' ],
    [ 'no provider, nodes: 1e12' => "    nodes: 1e12\n",
      qr/\Aworker pool 'p': provider required/, 'hetzner-default' ],
    # The same count, spelled as a whole number: no provider is no count.
    [ 'no provider, nodes: 1000000000000' => "    nodes: 1000000000000\n",
      qr/\Aworker pool 'p': provider required/, 'hetzner-default' ],
    [ 'provider foo, nodes: 1000000000000' => "    provider: foo\n    nodes: 1000000000000\n",
      qr/\Aworker pool 'p': invalid provider 'foo'/, 'foo-default' ],
    # A provider OCP knows, and a nodes: validate() refuses for it.
    [ 'hetzner, nodes: a list' => "    provider: hetzner\n    nodes: [ a.k361.test, b.k361.test ]\n",
      qr/\Aworker pool 'p': nodes must be a whole number/, 'hetzner-default' ],
    [ 'hetzner, nodes: 1e12' => "    provider: hetzner\n    nodes: 1e12\n",
      qr/\Aworker pool 'p': nodes must be a whole number/, 'hetzner-default' ],
    [ 'hetzner, nodes: two' => "    provider: hetzner\n    nodes: two\n",
      qr/\Aworker pool 'p': nodes must be a whole number/, 'hetzner-default' ],
);

for my $case (@UNCOUNTED) {
    my ($what, $pool, $line) = @$case;
    subtest "$what: one worker, not a count" => sub {
        my $config = config_from_text("  - name: p\n$pool");
        my @lines = $config->validate;
        ok scalar(grep { /$line/ } @lines), 'validate() refuses the pool for it'
            or diag explain \@lines;
        my $r = built($config);
        is $r->{died}, '', 'no death';
        is_deeply $r->{names}, [ 'p-1' ], 'one OCPNode, as control_planes() reads a refused count';
        is_deeply $r->{refs}, [ $case->[3] ], 'of the provider it names, as before';
        ok $r->{built} <= 1, 'nothing more was built';
    };
}

# --- ocp keys operator add (the harness of t/346) ------------------------------

SKIP: {
skip 'needs ssh-keygen', 1 unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{OCP_OPERATOR_KEY};

my $PIN1 = 'pin-one-k361';
my $PIN2 = 'pin-two-k361';

{
    package FakeList;
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }

    # No OCPNode yet; every call recorded.
    package FakeApi;
    sub new    { bless { log => [] }, shift }
    sub list   { push @{ $_[0]{log} }, "list $_[1]"; FakeList->new([]) }
    sub get    { push @{ $_[0]{log} }, "get $_[1]"; die "404 $_[1]\n" }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
}

our @SSH;
no warnings 'redefine';
local *OCP::SSH::run        = sub { push @SSH, $_[0]->host; { exit => 255, stdout => '', stderr => 'refused' } };
local *OCP::SSH::run_script = sub { push @SSH, $_[0]->host; { exit => 255, stdout => '', stderr => 'refused' } };
use warnings 'redefine';

my ($OP_PUB) = Crypt::Age->generate_keypair;
my $OP_SSH   = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK361operatorkey leitstand';
my $PUBFILE  = Path::Tiny->tempfile;
$PUBFILE->spew("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK361secondkey second\n");
my ($NEW_AGE) = Crypt::Age->generate_keypair;

# A secure-mode project as t/346 builds it, with $workers as its pools.
my $secure_project = sub {
    my ($workers) = @_;
    my $origin = Path::Tiny->tempdir;
    my $s = OCP::Secrets->new(project_dir => $origin);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);
    $s->generate_ssh_key;
    my $keys = OCP::Keys->new(project_dir => $origin);
    $keys->add_cluster_keys(pin2 => $PIN2);
    $keys->add_public_key(name => 'leitstand', type => 'ssh_ed25519', purpose => 'operator',
        public => $OP_SSH, age => $OP_PUB);
    $s->create_secrets(hetzner_token => 'hz-k361');
    $s->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");

    my $dir = Path::Tiny->tempdir;
    push @KEEP, $origin, $dir;
    $_->copy($dir->child($_->basename)) for grep { $_->is_file } $origin->children;
    $dir->child('.ocp')->mkpath;
    $origin->child('.ocp', $_)->copy($dir->child('.ocp', $_)) for qw( id_ed25519 id_ed25519.pub );
    $dir->child('ocp.yaml')->spew_utf8(
        "name: k361\ncontrol_planes:\n  provider: ssh\n  host: cp.k361.test\n"
      . "robocop:\n  enabled: true\n  security_level: secret\nworkers:\n$workers");
    return $dir;
};

my $operator_add = sub {
    my ($dir) = @_;
    my $api = FakeApi->new;
    my (@prompts, @walks);
    @SSH = ();
    my $orig = \&OCP::Cmd::Apply::CR::worker_ocpnodes;
    my ($out, $err, $rv) = ('', '');
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    {
        no warnings 'redefine';
        local $OCP::ClusterKey::INTERACTIVE = 1;
        local *OCP::Password::prompt_password = sub {
            push @prompts, $_[0];
            return $_[0] =~ /PIN1/ ? $PIN1 : $PIN2;
        };
        local *OCP::Cmd::Apply::CR::worker_ocpnodes = sub {
            local $BUILT = 0;
            my @crs = $orig->(@_);
            push @walks, { n => scalar @crs, built => $BUILT };
            return @crs;
        };
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval {
            OCP::Cmd::Keys::Operator::Add->new(command_chain => [ $ocp ], k8s => $api,
                name => 'second', ssh_pubkey => "$PUBFILE", age => $NEW_AGE)->execute([], []);
        };
    }
    my $died = $@ // '';
    chdir $cwd or die "chdir back: $!";
    return { out => $out, err => $err, died => $died, rv => $rv, prompts => \@prompts,
             ssh => [ @SSH ], walks => \@walks };
};

for my $case ([ 'provider foo, nodes: a list' =>
                "  - name: foo\n    provider: foo\n    nodes: [ a.k361.test, b.k361.test ]\n" ],
              [ 'no provider, nodes: 1e12' => "  - name: big\n    nodes: 1e12\n" ],
              [ 'no provider, nodes: 1000000000000' => "  - name: big\n    nodes: 1000000000000\n" ]) {
    my ($what, $workers) = @$case;
    subtest "ocp keys operator add over a pool with $what: the walk ends" => sub {
        my $r = $operator_add->($secure_project->($workers));
        unlike $r->{died}, qr/k361 (?:guard|fuse)/, 'no OCPNode storm';
        is $r->{died}, '', 'no death';
        is scalar @{ $r->{walks} }, 1, 'the machines were walked (worker_ocpnodes, once)';
        is_deeply $r->{walks}[0], { n => 1, built => 1 }, 'the pool is one worker';
        is $r->{prompts}[0], 'Enter PIN1 (cluster access): ', 'past the gate, on to PIN1';
        is_deeply $r->{ssh}, [ 'cp.k361.test' ], 'the control plane is the one machine asked';
        is $r->{rv}, 1, 'exit 1: the fake SSH refused the key, as it would without the pool';
        like $r->{err}, qr/could not add the operator key/, 'said on STDERR';
    };
}
}

alarm 0;
done_testing;

#!/usr/bin/env perl
# karr k346 -- `ocp keys operator add|rm` and `ocp keys secure
# --drop-bootstrap` on a project that is secure already walk every machine of
# ocp.yaml (OCP::Role::Cmd::Machines), and do not run validate() (k321). A
# control plane or a pool that is no mapping died there inside Perl ("Not a
# HASH reference ... internal error"), after PIN1, and a host that is a list
# became the machine ARRAY(0x...).
#
# The claims, for each of the three commands:
#
#   * what the machine lookup reads -- control_planes and workers in their
#     shapes, each control plane's host, a pool's nodes and an ssh pool's
#     host as the pool reads them -- is refused with validate()'s own line
#     for it, every line at once in validate()'s order, before PIN1: no
#     prompt, no SSH, no cluster call, no file written, nothing on STDOUT;
#     from bin/ocp on STDERR, exit 1
#   * a line validate() has about a key the lookup does not read (gpu.driver,
#     a host beside a hetzner pool) holds none of them up: they go on to PIN1
#
# A pool that counts its machines (hetzner) is given nodes: 'two', never a
# list: a list there is counted as its address by worker_ocpnodes and runs
# out of memory, which a run without the gate would do here.
#
# Network-free and cluster-free: the project is real (age, SOPS, ssh-keygen),
# the cluster API, SSH and the PIN prompt are fakes that record.

use strict;
use warnings;
use Test::More;

use Crypt::Age;
use Cwd qw( getcwd );
use Path::Tiny ();

use lib 'lib';

use OCP;
use OCP::Cmd::Keys::Operator::Add;
use OCP::Cmd::Keys::Operator::Rm;
use OCP::Cmd::Keys::Secure;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;
use OCP::SSH;

plan skip_all => 'needs ssh-keygen'
    unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{OCP_OPERATOR_KEY};

my $PIN1 = 'pin-one-k346';
my $PIN2 = 'pin-two-k346';

# --- Fakes ----------------------------------------------------------------

package FakeList {
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}

# Every call is recorded; a gate that holds asks none.
package FakeApi {
    sub new { bless { log => [] }, shift }
    sub list   { push @{ $_[0]{log} }, "list $_[1]"; FakeList->new([]) }
    sub get    { push @{ $_[0]{log} }, "get $_[1]"; die "404 $_[1]\n" }
    sub ensure { push @{ $_[0]{log} }, 'ensure'; $_[1] }
    sub patch  { push @{ $_[0]{log} }, 'patch'; 1 }
    sub delete { push @{ $_[0]{log} }, 'delete'; 1 }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
}

package main;

our @SSH;
{
    no warnings 'redefine';
    *OCP::SSH::run        = sub { push @SSH, $_[0]->host; { exit => 255, stdout => '', stderr => 'refused' } };
    *OCP::SSH::run_script = sub { push @SSH, $_[0]->host; { exit => 255, stdout => '', stderr => 'refused' } };
}

# --- Fixtures ---------------------------------------------------------------

my %VALID = (
    name           => 'k346',
    control_planes => { provider => 'ssh', host => 'cp.k346.test' },
    robocop        => { enabled => 1, security_level => 'secret' },
    workers        => [ { name => 'pool', provider => 'ssh', nodes => [ 'w1.k346.test' ] } ],
);

my ($OP_PUB, $OP_SEC) = Crypt::Age->generate_keypair;
my $OP_SSH = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK346operatorkey leitstand';

# A secure-mode project as a checkout has it after `ocp keys secure`: the
# committed files, keys.yaml with the admin (PIN2) and robo keys and the
# operator 'leitstand', the project key behind PIN1 in age.key.enc only, and
# the bootstrap key still in .ocp/. Nothing unlocked: a run that gets past the
# gate asks for PIN1 first.
sub secure_project {
    my (%spec) = @_;
    my $origin = Path::Tiny->tempdir;
    my $s = OCP::Secrets->new(project_dir => $origin);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);
    $s->generate_ssh_key;
    my $keys = OCP::Keys->new(project_dir => $origin);
    $keys->add_cluster_keys(pin2 => $PIN2);
    $keys->add_public_key(name => 'leitstand', type => 'ssh_ed25519', purpose => 'operator',
        public => $OP_SSH, age => $OP_PUB);
    $s->create_secrets(hetzner_token => 'hz-k346');
    $s->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");

    my $dir = Path::Tiny->tempdir;
    $_->copy($dir->child($_->basename)) for grep { $_->is_file } $origin->children;
    $dir->child('.ocp')->mkpath;
    $origin->child('.ocp', $_)->copy($dir->child('.ocp', $_)) for qw( id_ed25519 id_ed25519.pub );
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, { %VALID, %spec });
    return $dir;
}

sub validate_lines {
    my ($dir) = @_;
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify)->validate;
}

sub project_files {
    my ($dir) = @_;
    my %files;
    my $it = $dir->iterator({ recurse => 1 });
    while (defined(my $p = $it->())) {
        $files{ $p->relative($dir)->stringify } = -d $p ? 'dir' : $p->slurp_raw;
    }
    return \%files;
}

# The three commands, in process. Prompts are answered by what they ask for.
# The operator `add` registers: keys of its own.
my $PUBFILE = Path::Tiny->tempfile;
$PUBFILE->spew("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK346secondkey second\n");
my ($NEW_AGE) = Crypt::Age->generate_keypair;

my %RUN = (
    'ocp keys secure --drop-bootstrap' => sub {
        OCP::Cmd::Keys::Secure->new(command_chain => [ $ocp ], drop_bootstrap => 1, k8s => $_[0])
            ->execute([], []);
    },
    'ocp keys operator add' => sub {
        OCP::Cmd::Keys::Operator::Add->new(command_chain => [ $ocp ], k8s => $_[0],
            name => 'second', ssh_pubkey => "$PUBFILE", age => $NEW_AGE)->execute([], []);
    },
    'ocp keys operator rm' => sub {
        OCP::Cmd::Keys::Operator::Rm->new(command_chain => [ $ocp ], k8s => $_[0])
            ->execute([ 'leitstand' ], []);
    },
);
my @COMMANDS = sort keys %RUN;

sub run_in {
    my ($dir, $command) = @_;
    my $api = FakeApi->new;
    my @prompts;
    @SSH = ();

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
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $RUN{$command}->($api) };
    }
    my $died = $@ // '';
    chdir $cwd or die "chdir back: $!";
    return { out => $out, err => $err, died => $died, rv => $rv, prompts => \@prompts,
             ssh => [ @SSH ], api => $api->{log} };
}

# --- What the lookup reads --------------------------------------------------

my %HZ_POOL = (name => 'pool', provider => 'hetzner', server_type => 'cx32', location => 'fsn1');

# [ what, ocp.yaml over %VALID, the start of validate()'s line ]
my @SHAPES = (
    # The card's two.
    [ 'control_planes: [ a host ]' => { control_planes => [ 'cp.k346.test' ] },
      qr/\Acontrol_planes\[1\]: must be a mapping/ ],
    [ 'workers: a host'            => { workers => 'w1.k346.test' },
      qr/\Aworkers: must be a list of worker pools/ ],
    # The same walk, the same read.
    [ 'control_planes: a host'     => { control_planes => 'cp.k346.test' },
      qr/\Acontrol_planes: must be a mapping/ ],
    [ 'workers: [ a host ]'        => { workers => [ 'w1.k346.test' ] },
      qr/\Aworkers\[1\]: must be a mapping/ ],
    [ 'a control plane host: a list' => {
          control_planes => { provider => 'ssh', host => [ 'cp.k346.test', 'cp2.k346.test' ] } },
      qr/\Acontrol_planes\[1\]\.host: must be a string/ ],
    # nodes: 3 is three copies of one entry: its line once, as validate() has it.
    [ 'nodes: 3 copies of a host that is a list' => {
          control_planes => { provider => 'hetzner', server_type => 'cx32', location => 'fsn1',
                              host => [ 'cp.k346.test' ], nodes => 3 } },
      qr/\Acontrol_planes\[1\]\.host: must be a string/ ],
    [ 'an ssh pool host: a list'   => {
          workers => [ { name => 'pool', provider => 'ssh', host => [ 'w1.k346.test' ] } ] },
      qr/\Aworker pool 'pool': host must be a string/ ],
    [ 'an ssh pool nodes entry: a list' => {
          workers => [ { name => 'pool', provider => 'ssh', nodes => [ [ 'w1.k346.test' ] ] } ] },
      qr/\Aworker pool 'pool': nodes\[1\] must be a host name/ ],
    [ 'a hetzner pool nodes: no count' => { workers => [ { %HZ_POOL, nodes => 'two' } ] },
      qr/\Aworker pool 'pool': nodes must be a whole number/ ],
);

for my $case (@SHAPES) {
    my ($what, $spec, $key) = @$case;
    subtest "$what: refused with validate()'s line before anything" => sub {
        my $dir   = secure_project(%$spec);
        my @lines = validate_lines($dir);
        is scalar(@lines), 1, 'validate() has one line, for it' or diag explain \@lines;
        like $lines[0] // '', $key, 'about that key';

        for my $command (@COMMANDS) {
            my $before = project_files($dir);
            my $r = run_in($dir, $command);
            ok !defined $r->{rv}, "$command: refused";
            like $r->{died}, qr/\Aocp\.yaml has 1 error:\n  - \Q$lines[0]\E\n/,
                "$command: validate()'s line";
            like $r->{died}, qr/^Nothing was changed: \Q$command\E reads the machines/m,
                "$command: says nothing changed, and why";
            unlike $r->{died}, qr/ line \d+\.$|internal error/m, "$command: no Perl error";
            is_deeply $r->{prompts}, [], "$command: no PIN asked";
            is_deeply $r->{ssh}, [], "$command: no SSH";
            is_deeply $r->{api}, [], "$command: the cluster not asked";
            is_deeply project_files($dir), $before, "$command: no file written or changed";
            is $r->{out}, '', "$command: nothing on STDOUT";
        }
    };
}

subtest 'every line at once, in validate()\'s order' => sub {
    my $dir = secure_project(control_planes => [ 'cp.k346.test' ], workers => 'w1.k346.test');
    my @lines = validate_lines($dir);
    is scalar(@lines), 2, 'validate() has two lines' or diag explain \@lines;
    for my $command (@COMMANDS) {
        my $r = run_in($dir, $command);
        like $r->{died}, qr/\Aocp\.yaml has 2 errors:\n\Q${\ join '', map { "  - $_\n" } @lines }\E/,
            "$command: both, one after the other";
        like $r->{died}, qr/Fix the lines above/, "$command: lines, plural";
        is_deeply $r->{prompts}, [], "$command: no PIN asked";
    }
};

# --- What it does not read --------------------------------------------------

my @UNREAD = (
    [ 'gpu.driver: oprator'          => { gpu => { driver => 'oprator' } } ],
    [ 'a host beside a hetzner pool' => { workers => [ { %HZ_POOL, nodes => 1, host => 'w1.k346.test' } ] } ],
    # Beside a nodes: list an ssh pool's host is not read, whatever it is.
    [ 'an ssh pool host beside nodes' => {
          workers => [ { name => 'pool', provider => 'ssh', nodes => [ 'w1.k346.test' ],
                         host => [ 'w9.k346.test' ] } ] } ],
);

for my $case (@UNREAD) {
    my ($what, $spec) = @$case;
    subtest "$what: a line the lookup does not read holds nothing up" => sub {
        ok scalar(validate_lines(secure_project(%$spec))), 'validate() refuses ocp.yaml';
        for my $command (@COMMANDS) {
            # One project each: PIN1 caches the key, and the next run would
            # not be asked.
            my $r = run_in(secure_project(%$spec), $command);
            unlike $r->{died}, qr/ocp\.yaml has \d+ error/, "$command: not refused for it";
            is $r->{prompts}[0], 'Enter PIN1 (cluster access): ', "$command: on to PIN1";
        }
    };
}

# --- From bin/ocp ------------------------------------------------------------

subtest 'from bin/ocp: the line on STDERR, exit 1, no PIN read' => sub {
    my $dir = secure_project(control_planes => [ 'cp.k346.test' ]);
    my ($line) = validate_lines($dir);
    my $bin = Path::Tiny::path('bin/ocp')->absolute;
    my $lib = Path::Tiny::path('lib')->absolute;

    for my $case ([ 'ocp keys secure --drop-bootstrap' => 'keys', 'secure', '--drop-bootstrap' ],
                  [ 'ocp keys operator add' => 'keys', 'operator', 'add', '--name', 'second',
                    '--ssh-pubkey', "$PUBFILE", '--age', $NEW_AGE ],
                  [ 'ocp keys operator rm' => 'keys', 'operator', 'rm', 'leitstand' ]) {
        my ($command, @argv) = @$case;
        my $before = project_files($dir);
        my ($out, $err) = map { Path::Tiny->tempfile } 1 .. 2;
        my $pid = fork // die "fork: $!";
        unless ($pid) {
            chdir $dir or die "chdir: $!";
            local $ENV{HOME} = $dir->stringify;
            # --pins-stdin with nothing on STDIN: a PIN asked for dies naming it.
            open STDIN,  '<', '/dev/null' or die;
            open STDOUT, '>', "$out"      or die;
            open STDERR, '>', "$err"      or die;
            exec $^X, "-I$lib", "$bin", @argv, '--pins-stdin' or die "exec: $!";
        }
        waitpid $pid, 0;
        my $rc = $? >> 8;
        my ($o, $e) = ($out->slurp_utf8, $err->slurp_utf8);

        is $rc, 1, "$command: exit 1";
        is $o, '', "$command: nothing on STDOUT";
        like $e, qr/\AError: ocp\.yaml has 1 error:\n  - \Q$line\E\n/, "$command: validate()'s line, on STDERR";
        unlike $e, qr/Enter PIN|STDIN has no line/, "$command: no PIN read";
        unlike $e, qr/internal error|line \d+\./, "$command: no Perl error";
        is_deeply project_files($dir), $before, "$command: no file written or changed";
    }
};

# Last: before the fix there was no gate to call.
subtest 'the gate itself: nothing on a valid ocp.yaml' => sub {
    my $cmd = OCP::Cmd::Keys::Operator::Rm->new(command_chain => [ $ocp ]);
    for my $spec ({}, { control_planes => [ { provider => 'ssh', host => 'a.k346.test' },
                                            { provider => 'ssh', host => 'b.k346.test' } ] },
                  { control_planes => { provider => 'hetzner', server_type => 'cx32',
                                        location => 'fsn1', nodes => 3 } },
                  { workers => [ { %HZ_POOL, nodes => 2 }, { name => 'one', provider => 'ssh',
                                                           host => 'w9.k346.test' } ] },
                  { workers => [] }) {
        my $dir = Path::Tiny->tempdir;
        $ocp->dump_file($dir->child('ocp.yaml')->stringify, { %VALID, %$spec });
        my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
        is_deeply [ $config->validate ], [], 'validate() has nothing';
        is_deeply [ $cmd->_machines_spec_errors($config) ], [], 'nor has the gate';
    }
};

done_testing;

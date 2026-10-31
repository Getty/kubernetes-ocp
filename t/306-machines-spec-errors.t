#!/usr/bin/env perl
# karr k306, step 2b -- `ocp keys operator add|rm` and `ocp keys secure
# --drop-bootstrap` on a project that is secure already walk every machine of
# ocp.yaml (OCP::Role::Cmd::Machines) without validate() (k321), behind a gate
# that refuses what the walk reads (k346). The walk reads each control plane's
# name, and its public_ip as its address where it has no host; the gate
# checked neither. A list there became the machine ARRAY(0x...), which SSH was
# asked to log in to, or -- no control plane recorded in .ocp/status.yaml --
# died inside Perl in cluster_status (" at lib/OCP/Config.pm line N",
# "internal error"), in both cases after PIN1.
#
# The claims, for each of the three commands:
#
#   * a control plane's public_ip (no host beside it) or name that is no
#     string is refused with validate()'s own line for it, before PIN1: no
#     prompt, no SSH, no cluster call, no file written, nothing on STDOUT, no
#     Perl text -- with or without a control plane recorded
#   * from bin/ocp the line is on STDERR, exit 1
#   * the same entry's private_ip, which the walk does not read, holds
#     nothing up: on to PIN1
#
# The line is always the one validate() gives for the file, never spelt here.
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

my $PIN1 = 'pin-one-k306';
my $PIN2 = 'pin-two-k306';

# What no output may carry: Perl's own words, or a reference as text.
my $PERL_TEXT = qr/ at \S+ line \d+|internal error|HASH\(0x|ARRAY\(0x/;

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

# The host each SSH login was asked for, as text.
our @SSH;
{
    no warnings 'redefine';
    *OCP::SSH::run        = sub { push @SSH, '' . $_[0]->host; { exit => 255, stdout => '', stderr => 'refused' } };
    *OCP::SSH::run_script = sub { push @SSH, '' . $_[0]->host; { exit => 255, stdout => '', stderr => 'refused' } };
}

# --- Fixtures ---------------------------------------------------------------

my %VALID = (
    name           => 'k306',
    control_planes => { provider => 'ssh', host => 'cp.k306.test' },
    robocop        => { enabled => 1, security_level => 'secret' },
    workers        => [ { name => 'pool', provider => 'ssh', nodes => [ 'w1.k306.test' ] } ],
);

# A control plane ocp apply has recorded: cluster_status reads it, and the
# spec's first control plane is then not read there.
my $RECORDED = "nodes:\n  - name: police1\n    provider: ssh\n    public_ip: 203.0.113.11\n";

my ($OP_PUB, $OP_SEC) = Crypt::Age->generate_keypair;
my $OP_SSH = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK306operatorkey leitstand';

# A secure-mode project as a checkout has it after `ocp keys secure`: the
# committed files, keys.yaml with the admin (PIN2) and robo keys and the
# operator 'leitstand', the project key behind PIN1 in age.key.enc only, and
# the bootstrap key still in .ocp/. Nothing unlocked: a run that gets past the
# gate asks for PIN1 first. $status, when given, is .ocp/status.yaml.
sub secure_project {
    my ($status, %spec) = @_;
    my $origin = Path::Tiny->tempdir;
    my $s = OCP::Secrets->new(project_dir => $origin);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);
    $s->generate_ssh_key;
    my $keys = OCP::Keys->new(project_dir => $origin);
    $keys->add_cluster_keys(pin2 => $PIN2);
    $keys->add_public_key(name => 'leitstand', type => 'ssh_ed25519', purpose => 'operator',
        public => $OP_SSH, age => $OP_PUB);
    $s->create_secrets(hetzner_token => 'hz-k306');
    $s->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");

    my $dir = Path::Tiny->tempdir;
    $_->copy($dir->child($_->basename)) for grep { $_->is_file } $origin->children;
    $dir->child('.ocp')->mkpath;
    $origin->child('.ocp', $_)->copy($dir->child('.ocp', $_)) for qw( id_ed25519 id_ed25519.pub );
    $dir->child('.ocp', 'status.yaml')->spew_utf8($status) if defined $status;
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
$PUBFILE->spew("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK306secondkey second\n");
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

# --- What the walk reads ----------------------------------------------------

# [ what, ocp.yaml over %VALID, the start of validate()'s line ]
my @SHAPES = (
    # A local control plane has no host: its public_ip is the address read.
    [ 'a control plane public_ip: a list, no host' => {
          control_planes => { provider => 'local', public_ip => [ '203.0.113.10' ] } },
      qr/\Acontrol_planes\[1\]\.public_ip: must be a string/ ],
    [ 'a control plane name: a list' => {
          control_planes => { provider => 'ssh', host => 'cp.k306.test', name => [ 'police1' ] } },
      qr/\Acontrol_planes\[1\]\.name: must be a string/ ],
);

for my $case (@SHAPES) {
    my ($what, $spec, $key) = @$case;
    for my $status ([ 'nothing recorded' => undef ], [ 'a control plane recorded' => $RECORDED ]) {
        my ($recorded, $yaml) = @$status;
        subtest "$what, $recorded: refused with validate()'s line before anything" => sub {
            my @lines = validate_lines(secure_project($yaml, %$spec));
            is scalar(@lines), 1, 'validate() has one line, for it' or diag explain \@lines;
            like $lines[0] // '', $key, 'about that key';

            for my $command (@COMMANDS) {
                # One project each: past the gate, PIN1 would leave the age
                # key unlocked for the next run.
                my $dir    = secure_project($yaml, %$spec);
                my $before = project_files($dir);
                my $r = run_in($dir, $command);
                ok !defined $r->{rv}, "$command: refused";
                like $r->{died}, qr/\Aocp\.yaml has 1 error:\n  - \Q$lines[0]\E\n/,
                    "$command: validate()'s line";
                like $r->{died}, qr/^Nothing was changed: \Q$command\E reads the machines/m,
                    "$command: says nothing changed, and why";
                unlike join("\n", @{$r}{qw( died out err )}, @{ $r->{ssh} }), $PERL_TEXT,
                    "$command: no Perl text, no reference as a machine";
                is_deeply $r->{prompts}, [], "$command: no PIN asked";
                is_deeply $r->{ssh}, [], "$command: no SSH";
                is_deeply $r->{api}, [], "$command: the cluster not asked";
                is_deeply project_files($dir), $before, "$command: no file written or changed";
                is $r->{out}, '', "$command: nothing on STDOUT";
            }
        };
    }
}

# --- What it does not read --------------------------------------------------

subtest 'private_ip: a list, which the walk does not read, holds nothing up' => sub {
    my %spec = (control_planes => { provider => 'ssh', host => 'cp.k306.test',
                                    private_ip => [ '10.0.0.1' ] });
    my @lines = validate_lines(secure_project(undef, %spec));
    like $lines[0] // '', qr/\Acontrol_planes\[1\]\.private_ip: must be a string/,
        'validate() refuses ocp.yaml for it';
    for my $command (@COMMANDS) {
        my $r = run_in(secure_project(undef, %spec), $command);
        unlike $r->{died}, qr/ocp\.yaml has \d+ error/, "$command: not refused for it";
        is $r->{prompts}[0], 'Enter PIN1 (cluster access): ', "$command: on to PIN1";
    }
};

# --- From bin/ocp ------------------------------------------------------------

for my $case (@SHAPES) {
    my ($what, $spec) = @$case;
    subtest "$what, from bin/ocp: the line on STDERR, exit 1, no PIN read" => sub {
        my $dir = secure_project($RECORDED, %$spec);
        my ($line) = validate_lines($dir);
        my $bin = Path::Tiny::path('bin/ocp')->absolute;
        my $lib = Path::Tiny::path('lib')->absolute;
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
            exec $^X, "-I$lib", "$bin", 'keys', 'operator', 'add', '--name', 'second',
                '--ssh-pubkey', "$PUBFILE", '--age', $NEW_AGE, '--pins-stdin' or die "exec: $!";
        }
        waitpid $pid, 0;
        my $rc = $? >> 8;
        my ($o, $e) = ($out->slurp_utf8, $err->slurp_utf8);

        is $rc, 1, 'exit 1';
        is $o, '', 'nothing on STDOUT';
        like $e, qr/\AError: ocp\.yaml has 1 error:\n  - \Q$line\E\n/, "validate()'s line, on STDERR";
        unlike $e, qr/Enter PIN|STDIN has no line/, 'no PIN read';
        unlike $e, $PERL_TEXT, 'no Perl text';
        is_deeply project_files($dir), $before, 'no file written or changed';
    };
}

done_testing;

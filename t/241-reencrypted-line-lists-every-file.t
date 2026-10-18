#!/usr/bin/env perl
# karr k241 (lab round 10, note 47): `ocp keys operator add` / `operator rm`
# printed "[ok] Re-encrypted with a new data key: secrets.yaml, kubeconfig.yaml"
# although keys.yaml was re-encrypted too (add_public_key / delete_key write it
# for the new recipient list before rotate_sops_files looks). The rotation
# message on STDERR names all three. Now:
#
#   - the [ok] line of operator add, operator rm and recipients rm lists every
#     file the command re-encrypted, keys.yaml included;
#   - it is the SAME list as the one in the rotation message ("A, B and C were
#     re-encrypted", STDERR) where there is one (rm, both kinds).
#
# Network-free: OCP::SSH is replaced, ssh-keygen, age and SOPS run for real on
# temp files, the K8s API is a fake (same harness as t/237).

use strict;
use warnings;
use Test::More;

use Cwd qw( getcwd );
use Crypt::Age;
use File::SOPS;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Keys::Operator::Add;
use OCP::Cmd::Keys::Operator::Rm;
use OCP::Cmd::Keys::Recipients::Rm;
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

my $PIN2 = 'pin-two-2';
my @ALL  = qw( keys.yaml secrets.yaml kubeconfig.yaml );

{
    package FakeList;
    sub new   { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]{items} }

    package FakeOperatorApi;
    sub new    { bless {}, shift }
    sub list   { FakeList->new([]) }
    sub get    { die "404\n" }
    sub k8s    { $_[0] }
    sub object_to_struct { $_[1] }
    sub ensure { $_[1] }
}

sub keygen {
    my ($dir, $name) = @_;
    system('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', $name, '-f', $dir->child($name)->stringify) == 0
        or die "ssh-keygen failed\n";
    return $dir->child($name)->stringify;
}

sub secure_project {
    my $dir = path(tempdir(CLEANUP => 1));
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k241',
        control_planes => { provider => 'ssh', host => 'cp.k241.test' },
        robocop        => { enabled => 1, security_level => 'secret' },
    });
    my $secrets = OCP::Secrets->new(project_dir => $dir);
    $secrets->generate_age_key;
    OCP::Keys->new(project_dir => $dir)->add_cluster_keys(pin2 => $PIN2);
    $secrets->create_secrets(hetzner_token => 'hz-token');
    $secrets->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");
    return $dir;
}

sub leitstand {
    my $home = path(tempdir(CLEANUP => 1));
    my ($pub, $sec) = Crypt::Age->generate_keypair;
    my $ssh = keygen($home, 'id_leitstand');
    return { age => $pub, secret => $sec, ssh_pub => "$ssh.pub" };
}

sub run_cmd {
    my ($dir, $class, %opt) = @_;
    my $cmd = $class->new(command_chain => [ $ocp ], %{ $opt{args} // {} });
    my ($out, $err) = ('', '');
    local $OCP::ClusterKey::INTERACTIVE = 1;
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my $rv;
    {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub { $PIN2 };
        local *OCP::SSH::run        = sub { { exit => 0, stdout => '', stderr => '' } };
        local *OCP::SSH::run_script = sub { { exit => 0, stdout => "1\n", stderr => '' } };
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $cmd->execute($opt{argv} // [], []) };
    }
    my $died = $@ // '';
    chdir $cwd or die "chdir back: $!";
    return { out => $out, err => $err, died => $died, rv => $rv };
}

sub operator_add {
    my ($dir, $l) = @_;
    return run_cmd($dir, 'OCP::Cmd::Keys::Operator::Add',
        args => { name => 'leitstand', ssh_pubkey => $l->{ssh_pub}, age => $l->{age},
                  k8s => FakeOperatorApi->new });
}

# The files named by "[ok] Re-encrypted with a new data key: A, B, C".
sub ok_list {
    my ($out) = @_;
    $out =~ /^\[ok\] Re-encrypted with a new data key: (.*)$/m or return;
    return split /, /, $1;
}

# The files named by "... and A, B and C were re-encrypted." (STDERR).
sub rotation_list {
    my ($err) = @_;
    $err =~ /is no longer a recipient and (.+?) (?:was|were) re-encrypted\./ or return;
    return split /, | and /, $1;
}

subtest 'operator add: the [ok] line lists keys.yaml with the other two' => sub {
    my $dir = secure_project();
    my $l   = leitstand();
    my $r   = operator_add($dir, $l);
    is $r->{rv}, 0, 'exit 0' or diag $r->{err}, $r->{died};

    my @listed = ok_list($r->{out});
    ok scalar(@listed), 'a "[ok] Re-encrypted with a new data key:" line exists' or diag $r->{out};
    is_deeply [ sort @listed ], [ sort @ALL ], 'it names keys.yaml, secrets.yaml and kubeconfig.yaml'
        or diag $r->{out};
    is scalar(@listed), scalar(keys %{ { map { $_ => 1 } @listed } }), 'each file once';
};

subtest 'operator rm: the [ok] line lists keys.yaml, and it is the rotation message\'s list' => sub {
    my $dir = secure_project();
    my $l   = leitstand();
    my $add = operator_add($dir, $l);
    die "operator add failed: $add->{died}$add->{err}" unless ($add->{rv} // 1) == 0;

    my $r = run_cmd($dir, 'OCP::Cmd::Keys::Operator::Rm', argv => [ 'leitstand' ],
        args => { k8s => FakeOperatorApi->new });
    is $r->{rv}, 0, 'exit 0' or diag $r->{err}, $r->{died};

    my @listed = ok_list($r->{out});
    my @rotated = rotation_list($r->{err});
    is_deeply [ sort @listed ], [ sort @ALL ], '[ok] line: all three files' or diag $r->{out};
    is_deeply [ sort @rotated ], [ sort @ALL ], 'rotation message: all three files' or diag $r->{err};
    is_deeply \@listed, \@rotated, 'the same list, in the same order';
};

subtest 'operator rm without secrets.yaml/kubeconfig.yaml: keys.yaml alone, in both places' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name => 'k241', control_planes => { provider => 'ssh', host => 'cp.k241.test' } });
    my $secrets = OCP::Secrets->new(project_dir => $dir);
    $secrets->generate_age_key;
    OCP::Keys->new(project_dir => $dir)->add_cluster_keys(pin2 => $PIN2);
    my $l = leitstand();
    my $add = operator_add($dir, $l);
    die "operator add failed: $add->{died}$add->{err}" unless ($add->{rv} // 1) == 0;
    is_deeply [ ok_list($add->{out}) ], ['keys.yaml'], 'add: [ok] line names keys.yaml, the only file';

    my $r = run_cmd($dir, 'OCP::Cmd::Keys::Operator::Rm', argv => [ 'leitstand' ],
        args => { k8s => FakeOperatorApi->new });
    is $r->{rv}, 0, 'exit 0' or diag $r->{err}, $r->{died};
    is_deeply [ ok_list($r->{out}) ], ['keys.yaml'], 'rm: [ok] line names keys.yaml';
    is_deeply [ rotation_list($r->{err}) ], ['keys.yaml'], 'rm: so does the rotation message';
};

subtest 'recipients rm: the [ok] line lists all three and equals the rotation message\'s list' => sub {
    my $dir = secure_project();
    my $l   = leitstand();
    my $add = operator_add($dir, $l);
    die "operator add failed: $add->{died}$add->{err}" unless ($add->{rv} // 1) == 0;

    my $r = run_cmd($dir, 'OCP::Cmd::Keys::Recipients::Rm', argv => [ $l->{age} ]);
    is $r->{rv}, 0, 'exit 0' or diag $r->{err}, $r->{died};

    my @listed  = ok_list($r->{out});
    my @rotated = rotation_list($r->{err});
    is_deeply [ sort @listed ], [ sort @ALL ], '[ok] line: all three files' or diag $r->{out};
    is_deeply \@listed, \@rotated, 'the same list as the rotation message, same order' or diag $r->{err};
};

done_testing;

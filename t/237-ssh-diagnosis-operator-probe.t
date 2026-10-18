#!/usr/bin/env perl
# karr k237 (lab round 8, notes 42-44): three follow-ups of k209 and k216.
#
#   (1) `ocp ssh` explains a refused key with the text OCP::SSH::wait_for_ssh
#       gives (which key, `ocp keys authorized-keys --purpose ...`) -- for an
#       OCPNode and for a control plane/address alike -- and hands the terminal
#       to ssh anyway. A probe that fails for another reason says nothing of
#       keys.
#   (2) The host probes of a Leitstand (operator identity) use the operator key
#       (OCP_OPERATOR_KEY), not the robo key; without the variable the probes
#       are skipped as before; set but unusable is a [WARN], once, not fatal.
#   (3) "A, B and C were re-encrypted": the rotation hint counts the files
#       right and names every one; `operator rm` really re-encrypts
#       secrets.yaml without the operator.
#
# Network-free: OCP::SSH::run and ::interactive are replaced, ssh-keygen, age
# and SOPS run for real on temp files, the K8s API is a fake.

use strict;
use warnings;
use Test::More;

use Cwd qw( getcwd );
use Crypt::Age;
use File::SOPS;
use File::Temp qw( tempdir );
use MIME::Base64 ();
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Apply;
use OCP::Cmd::Keys::Operator::Add;
use OCP::Cmd::Keys::Operator::Rm;
use OCP::Cmd::Keys::Recipients::Rm;
use OCP::Cmd::SSH;
use OCP::Config;
use OCP::Drift;
use OCP::Kubernetes;
use OCP::Keys;
use OCP::Node;
use OCP::Password;
use OCP::Rex;
use OCP::Secrets;
use OCP::SSH;

plan skip_all => 'needs ssh-keygen'
    unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{OCP_OPERATOR_KEY};

my $PIN2 = 'pin-two-2';

sub keygen {
    my ($dir, $name) = @_;
    system('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', $name, '-f', $dir->child($name)->stringify) == 0
        or die "ssh-keygen failed\n";
    return $dir->child($name)->stringify;
}

#
# (1) ocp ssh
#

{
    package FakeIO;
    sub new              { bless {}, shift }
    sub object_to_struct { $_[1] }

    package FakeList;
    sub new   { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]{items} }

    package FakeAPI;
    sub new { my ($c, %a) = @_; bless { ocpnodes => {}, %a }, $c }
    sub k8s          { FakeIO->new }
    sub resource_map { {} }
    sub get {
        my ($self, $kind, %args) = @_;
        return $self->{ocpnodes}{ $args{name} } // die "404 Not Found: $kind $args{name}\n"
            if $kind eq 'OCPNode';
        die "404 Not Found: $kind $args{name}\n";
    }
    sub list { FakeList->new([ values %{ $_[0]{ocpnodes} } ]) }

    package FakeOcp;
    sub new    { bless { config => $_[1] }, $_[0] }
    sub config { $_[0]{config} }
}

my $keydir = path(tempdir(CLEANUP => 1));
my $SSHKEY = keygen($keydir, 'probe-key');
my ($FP)   = `ssh-keygen -lf $SSHKEY.pub` =~ /(SHA256:\S+)/;
my $BOOTSTRAP = $keydir->child('id_ed25519');    # the leftover bootstrap key of migration_hint
$BOOTSTRAP->spew('x');

# The key as OCP::ClusterKey hands it out, without a PIN.
sub cluster_key {
    my ($origin) = @_;
    return bless {
        origin         => $origin,
        name           => $origin eq 'operator' ? 'leitstand' : 'admin-ssh',
        provider       => 'ssh',
        path           => $SSHKEY,
        bootstrap_path => $BOOTSTRAP->stringify,
    }, 'OCP::ClusterKey';
}

my $REFUSED = { exit => 255, stdout => '', stderr => "root\@h: Permission denied (publickey).\n" };
my $TIMEOUT = { exit => 255, stdout => '', stderr => "ssh: connect to host h port 22: Connection timed out\n" };
my $OK      = { exit => 0,   stdout => '', stderr => '' };

# Run `ocp ssh` as far as the hand-over. $o{target} is 'node' (an OCPNode,
# --node crag) or 'cp' (a control plane by name). Returns what was said on
# STDERR, what OCP::SSH was asked to run and the sessions handed over.
sub ocp_ssh {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('kubeconfig.yaml')->spew('x');
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump({ name => 't',
        control_planes => { provider => 'ssh', host => '10.5.10.20' } }));

    my $node_arg = $o{target} eq 'node' ? 'crag' : '10-5-10-20';
    my $cr = { metadata => { name => 'crag', namespace => 'ocp-system' },
               spec     => { role => 'worker', host => 'crag.lab' },
               status   => { phase => 'Ready', publicIP => '10.230.30.54',
                             hostKeys => [ { type => 'ssh-ed25519', key => 'AAAA', fingerprint => 'SHA256:x' } ] } };
    my $api = FakeAPI->new(ocpnodes => { crag => $cr });

    my (@ran, @interactive, @made, $err);
    $err = '';
    my $died;
    {
        no warnings 'redefine';
        my $real_new = \&OCP::SSH::new;
        local *OCP::SSH::new = sub { my $s = $real_new->(@_); push @made, $s; $s };
        local *OCP::SSH::run = sub { my ($s, @c) = @_; push @ran, [ $s->host, @c ]; ref $o{probe} eq 'CODE' ? $o{probe}->() : $o{probe} };
        local *OCP::SSH::interactive = sub { my $s = shift; push @interactive, [ $s->host, @_ ]; 0 };
        local *OCP::Cmd::SSH::_kubernetes = sub { OCP::Kubernetes->new(api => $api) };
        local *OCP::Cmd::SSH::cluster_ssh_key = sub { cluster_key($o{origin} // 'admin') };
        local *OCP::Secrets::ensure_age_key = sub { 1 };
        local *OCP::Node::_scan_host_keys = sub { () };
        local *OCP::KnownHosts::scan      = sub { () };
        local *OCP::K8s::patch_status     = sub { 1 };
        open my $efh, '>', \$err or die;
        local *STDERR = $efh;
        my $cmd = OCP::Cmd::SSH->new(
            node => $node_arg,
            command_chain => [ FakeOcp->new($dir->child('ocp.yaml')->stringify) ],
        );
        eval { $cmd->execute([ '--node', $node_arg ], []); 1 } or $died = $@;
    }
    return { err => $err, died => $died, ran => \@ran, interactive => \@interactive, made => \@made };
}

# What wait_for_ssh says for the same key and host (the text `ocp ssh` must
# share, not merely resemble).
sub wait_message {
    my ($host, $origin) = @_;
    my $key = cluster_key($origin);
    my $ssh = OCP::SSH->new(host => $host, key_file => $key->path, key_label => $key->label,
        ($origin =~ /\A(?:admin|operator)\z/ ? (key_purpose => $origin) : ()));
    no warnings 'redefine';
    local *OCP::SSH::run = sub { $REFUSED };
    eval { $ssh->wait_for_ssh(120, 2) };
    return $@;
}

subtest '(1) ocp ssh to an OCPNode: a refused key is diagnosed like wait_for_ssh, then handed over' => sub {
    my $r = ocp_ssh(target => 'node', origin => 'admin', probe => $REFUSED);

    is $r->{died}, undef, 'the command does not fail' or diag $r->{died};
    my $want = wait_message('10.230.30.54', 'admin');
    like $want, qr/key rejected by 10\.230\.30\.54/, 'sanity: wait_for_ssh text for the node address';
    like $r->{err}, qr/^\[!!\] \Q$want\E/m, 'STDERR holds exactly that text, [!!] in front';
    like $r->{err}, qr/the admin key 'admin-ssh' from keys\.yaml/, 'names the key by its label';
    like $r->{err}, qr/\Q$FP\E/, 'and its fingerprint';
    like $r->{err}, qr/ocp keys authorized-keys --purpose admin \| ssh root\@10\.230\.30\.54/,
        'with the command that puts it on the machine';
    like $r->{err}, qr/Handing over to ssh anyway/, 'says it hands over';
    is_deeply $r->{interactive}, [ [ '10.230.30.54' ] ], 'interactive is called all the same';
    is scalar(@{ $r->{ran} }), 1, 'one probe, the one the host key check needs anyway';
    like $r->{err}, qr/This project still has .*id_ed25519.*ocp keys show --purpose admin/s,
        'the admin key with a bootstrap key lying around also gets the migration hint';
};

subtest '(1) ocp ssh to a control plane / address: the probe is new, the diagnosis the same' => sub {
    my $r = ocp_ssh(target => 'cp', origin => 'operator', probe => $REFUSED);

    is $r->{died}, undef, 'the command does not fail' or diag $r->{died};
    is_deeply $r->{ran}, [ [ '10.5.10.20', 'true' ] ], 'one batch-mode probe of the control plane';
    my $want = wait_message('10.5.10.20', 'operator');
    like $r->{err}, qr/^\[!!\] \Q$want\E/m, 'the wait_for_ssh text';
    like $r->{err}, qr/the operator key 'leitstand'/, 'the operator key by its label';
    like $r->{err}, qr/ocp keys authorized-keys --purpose operator \| ssh root\@10\.5\.10\.20/,
        'purpose operator, not admin';
    unlike $r->{err}, qr/needs both keys, admin and robo/, 'no admin/robo advice for an operator key';
    unlike $r->{err}, qr/ocp keys show --purpose admin/, 'migration_hint is admin-only';
    is_deeply $r->{interactive}, [ [ '10.5.10.20' ] ], 'interactive is called all the same';
};

subtest '(1) a bootstrap-key target is diagnosed too, without a purpose' => sub {
    my $r = ocp_ssh(target => 'cp', origin => 'bootstrap', probe => $REFUSED);
    like $r->{err}, qr/^\[!!\] SSH key rejected by 10\.5\.10\.20.*the bootstrap key \.ocp\/id_ed25519/ms, 'refusal named';
    unlike $r->{err}, qr/authorized-keys --purpose/, 'no purpose to name';
    is scalar(@{ $r->{interactive} }), 1, 'handed over';
};

subtest '(1) no key hint for a timeout, a success or a probe that died' => sub {
    for my $case ([ timeout => $TIMEOUT ], [ ok => $OK ]) {
        my ($label, $probe) = @$case;
        for my $target (qw( node cp )) {
            my $r = ocp_ssh(target => $target, origin => 'admin', probe => $probe);
            unlike $r->{err}, qr/\[!!\]|rejected|Permission denied|authorized-keys|ocp keys show/,
                "$label/$target: nothing about keys, not even the migration hint";
            is scalar(@{ $r->{interactive} }), 1, "$label/$target: ssh is handed the terminal";
        }
    }

    # A probe that dies (no route): the CP path must not turn that into a verdict.
    my $r = ocp_ssh(target => 'cp', origin => 'admin', probe => sub { die "connection refused\n" });
    unlike $r->{err}, qr/\[!!\]|rejected|authorized-keys/, 'a probe that dies says nothing about keys';
    is scalar(@{ $r->{interactive} }), 1, 'and still hands over';
};

#
# (2) the Leitstand's host probes
#

sub secure_project {
    my (%spec) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k237',
        control_planes => { provider => 'ssh', host => 'cp.k237.test' },
        robocop        => { enabled => 1, security_level => 'secret' },
        %spec,
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
    my $id = $home->child('age.key');
    $id->spew("# created: 2026-10-18T00:00:00Z\n# public key: $pub\n$sec\n");
    my $ssh = keygen($home, 'id_leitstand');
    return { age => $pub, secret => $sec, identity => $id->stringify, ssh => $ssh,
             ssh_pub => "$ssh.pub", public => path("$ssh.pub")->slurp =~ s/\s+\z//r };
}

package FakeOperatorApi {
    sub new    { bless {}, shift }
    sub list   { FakeList->new([]) }
    sub get    { die "404\n" }
    sub k8s    { $_[0] }
    sub object_to_struct { $_[1] }
    sub ensure { $_[1] }
}

package main;

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
        # The one machine (the control plane) takes whatever it is told, and
        # answers a key removal with the number of lines it took off.
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
    return { out => $out, err => $err, died => $died, rv => $rv, cmd => $cmd };
}

# A project with a registered operator and no deployed machine (so nothing to
# push a key to), and the Leitstand's checkout of it: committed files only.
sub registered {
    my $dir = secure_project();
    my $l   = leitstand();
    my $r   = run_cmd($dir, 'OCP::Cmd::Keys::Operator::Add',
        args => { name => 'leitstand', ssh_pubkey => $l->{ssh_pub}, age => $l->{age},
                  k8s => FakeOperatorApi->new });
    die "operator add failed: $r->{died}$r->{err}" unless ($r->{rv} // 1) == 0;
    my $clone = path(tempdir(CLEANUP => 1));
    for my $f (qw( ocp.yaml keys.yaml secrets.yaml kubeconfig.yaml .sops.yaml age.key.enc )) {
        $dir->child($f)->copy($clone->child($f)) if -f $dir->child($f);
    }
    return ($dir, $l, $clone);
}

sub opens {
    my ($file, $identity) = @_;
    return eval {
        File::SOPS->decrypt(encrypted => path($file)->slurp, identities => [$identity], format => 'yaml');
        1;
    } ? 1 : 0;
}

sub keys_of {
    my ($dir) = @_;
    my $all = OCP::Keys->new(project_dir => $dir)->list_keys;
    my ($robo) = grep { $_->{purpose} eq 'automation' } @$all;
    return ($robo, $all);
}

# The prober of a command in $clone, with OCP::Rex stubbed to record the key
# file it is handed (and what is in it). Returns { prober, used, warn, cmd }.
sub operator_probe {
    my ($clone, %o) = @_;
    my $config = OCP::Config->new(file => $clone->child('ocp.yaml')->stringify, ocp => $ocp);
    my $cmd = $o{cmd} // OCP::Cmd::Apply->new(command_chain => []);
    my (@used, $err);
    $err = '';
    my $prober;
    {
        no warnings 'redefine';
        local $ENV{SOPS_AGE_KEY_FILE} = $o{identity} if defined $o{identity};
        local $ENV{OCP_OPERATOR_KEY}  = $o{ssh}      if defined $o{ssh};
        local *OCP::Password::prompt_password = sub { die "PIN prompted: $_[0]\n" };
        local $OCP::ClusterKey::INTERACTIVE = 0;
        local *OCP::Rex::run_task = sub {
            my ($rex) = @_;
            push @used, { file => $rex->key_file, content => scalar path($rex->key_file)->slurp };
            return { stdout => '' };
        };
        open my $efh, '>', \$err or die;
        local *STDERR = $efh;
        $prober = $cmd->rex_prober($config);
        $prober->('w1.k237.test', 'detect_legacy_containerd_template', {}) if $prober && !$o{no_run};
    }
    return { prober => $prober, used => \@used, err => $err, cmd => $cmd, config => $config };
}

subtest '(2) operator identity: the probe uses the operator key, not the robo key' => sub {
    my ($dir, $l, $clone) = registered();
    my ($robo) = keys_of($dir);

    # A stray bootstrap key on disk must not win over the operator's.
    $clone->child('.ocp')->mkpath;
    $clone->child('.ocp', 'id_ed25519')->spew("not-the-operators\n");

    my $r = operator_probe($clone, identity => $l->{identity}, ssh => $l->{ssh});
    ok $r->{prober}, 'a prober exists, without a PIN2 and without a prompt';
    is scalar(@{ $r->{used} }), 1, 'and it ran';
    is $r->{used}[0]{content}, path($l->{ssh})->slurp, 'with the operator\'s private key';
    isnt $r->{used}[0]{content}, $robo->{private}, 'not the robo key';
    unlike $r->{used}[0]{content}, qr/not-the-operators/, 'and not the on-disk fallback';
    is $r->{err}, '', 'nothing on STDERR';
    is $r->{cmd}->host_probe_warning(OCP::Drift->new(config => $r->{config})), '',
        'host_probe_warning is empty';
};

subtest '(2) without OCP_OPERATOR_KEY the probes stay skipped, as before' => sub {
    my ($dir, $l, $clone) = registered();

    my $r = operator_probe($clone, identity => $l->{identity});
    ok !$r->{prober}, 'no prober';
    is $r->{err}, '', 'and no complaint: nothing was set';
    like $r->{cmd}->host_probe_warning(OCP::Drift->new(config => $r->{config})),
        qr/\A  \[WARN\] host probes skipped on cp\.k237\.test: no SSH key to probe with that needs no PIN2\n\z/,
        'the old [WARN] line';
};

subtest '(2) no operator identity: OCP_OPERATOR_KEY alone changes nothing' => sub {
    my ($dir, $l, $clone) = registered();
    my $r = operator_probe($clone, ssh => $l->{ssh});    # no SOPS_AGE_KEY_FILE
    ok !$r->{prober}, 'no prober (the identity is the project key\'s, not an operator\'s)';
    is $r->{err}, '', 'no warning either';
};

subtest '(2) set but unusable: [WARN] on STDERR, once, not fatal, probe skipped' => sub {
    my ($dir, $l, $clone) = registered();
    my $other = leitstand();    # a valid ssh key, but not the one keys.yaml has for 'leitstand'

    for my $case ([ 'missing file' => '/nonexistent/id_leitstand', qr/does not exist/ ],
                  [ 'someone else\'s key' => $other->{ssh}, qr/is not it/ ]) {
        my ($label, $file, $why) = @$case;
        my $cmd = OCP::Cmd::Apply->new(command_chain => []);
        my $r = operator_probe($clone, identity => $l->{identity}, ssh => $file, cmd => $cmd);
        ok !$r->{prober}, "$label: no prober (probe skipped), no exception";
        like $r->{err}, qr/\A\[WARN\] OCP_OPERATOR_KEY is set but cannot be used for the host probes: .*$why/,
            "$label: [WARN] with the reason";
        unlike $r->{err}, qr/\n.*\[WARN\]/, "$label: one warning only";

        my $again = operator_probe($clone, identity => $l->{identity}, ssh => $file, cmd => $cmd);
        is $again->{err}, '', "$label: a second probe of the same command does not repeat it";
        like $cmd->host_probe_warning(OCP::Drift->new(config => $r->{config})),
            qr/host probes skipped on cp\.k237\.test: no SSH key/, "$label: the skip is reported";
    }
};

subtest '(2) ClusterKey->operator_probe_key: empty list, key, or (undef, problem), never a prompt' => sub {
    my ($dir, $l, $clone) = registered();
    my $config = OCP::Config->new(file => $clone->child('ocp.yaml')->stringify, ocp => $ocp);
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { die "PIN prompted: $_[0]\n" };
    local $OCP::ClusterKey::INTERACTIVE = 0;

    {
        local $ENV{SOPS_AGE_KEY_FILE} = $l->{identity};
        my @none = OCP::ClusterKey->operator_probe_key($config);
        is scalar(@none), 0, 'OCP_OPERATOR_KEY unset: the empty list';

        local $ENV{OCP_OPERATOR_KEY} = $l->{ssh};
        my @got = OCP::ClusterKey->operator_probe_key($config);
        is scalar(@got), 1, 'set and right: one value';
        is $got[0]->origin, 'operator', 'an operator key';
        is $got[0]->content, path($l->{ssh})->slurp, 'of the file named';

        local $ENV{OCP_OPERATOR_KEY} = '/nonexistent/key';
        my @bad = OCP::ClusterKey->operator_probe_key($config);
        is scalar(@bad), 2, 'set but unusable: two values';
        ok !defined $bad[0], 'undef first';
        like $bad[1], qr/\AThis run decrypts as the operator 'leitstand'.*does not exist\.\z/,
            'then the problem, on one line, without the ERROR: prefix';
        unlike $bad[1], qr/\n|ERROR:/, 'one line';
    }
    {
        local $ENV{OCP_OPERATOR_KEY} = $l->{ssh};
        is scalar(my @x = OCP::ClusterKey->operator_probe_key($config)), 0, 'no operator identity: empty';
    }
    {
        my $dev = path(tempdir(CLEANUP => 1));
        $dev->child('ocp.yaml')->spew(YAML::XS::Dump({ name => 'd', control_planes => { provider => 'ssh', host => 'h' } }));
        local $ENV{OCP_OPERATOR_KEY} = $l->{ssh};
        local $ENV{SOPS_AGE_KEY_FILE} = $l->{identity};
        my $dconfig = OCP::Config->new(file => $dev->child('ocp.yaml')->stringify, ocp => $ocp);
        is scalar(my @y = OCP::ClusterKey->operator_probe_key($dconfig)), 0, 'dev mode (no keys.yaml): empty';
    }
};

#
# (3) the rotation message
#

subtest '(3) reencrypted_clause counts the files right' => sub {
    my $cmd = OCP::Cmd::Keys::Operator::Rm->new(command_chain => [ $ocp ]);
    is $cmd->reencrypted_clause('kubeconfig.yaml'), 'kubeconfig.yaml was re-encrypted', 'one file: was';
    is $cmd->reencrypted_clause('keys.yaml', 'secrets.yaml'), 'keys.yaml and secrets.yaml were re-encrypted',
        'two: A and B were';
    is $cmd->reencrypted_clause('keys.yaml', 'secrets.yaml', 'kubeconfig.yaml'),
        'keys.yaml, secrets.yaml and kubeconfig.yaml were re-encrypted', 'three: A, B and C were';
};

subtest '(3) rotation_hint carries the clause, and none when nothing was rewritten' => sub {
    my ($dir) = registered();
    my $secrets = OCP::Secrets->new(project_dir => $dir);
    my $cmd = OCP::Cmd::Keys::Operator::Rm->new(command_chain => [ $ocp ]);
    like $cmd->rotation_hint($secrets, 'age1x', 'kubeconfig.yaml'),
        qr/\A\n\[!!\] age1x is no longer a recipient and kubeconfig\.yaml was re-encrypted\.\n/,
        'one file: the grammar of the lab note 44';
    like $cmd->rotation_hint($secrets, 'age1x', 'a.yaml', 'b.yaml'),
        qr/ and a\.yaml and b\.yaml were re-encrypted\.\n/, 'two files';
    like $cmd->rotation_hint($secrets, 'age1x'), qr/\A\n\[!!\] age1x is no longer a recipient\.\n/,
        'no file: no clause';
};

subtest '(3) operator rm re-encrypts keys.yaml, secrets.yaml and kubeconfig.yaml and says so' => sub {
    my ($dir, $l) = registered();
    for my $f (qw( keys.yaml secrets.yaml kubeconfig.yaml )) {
        ok opens($dir->child($f), $l->{secret}), "before: $f is open to the Leitstand";
    }
    my $secrets_before = $dir->child('secrets.yaml')->slurp;

    my $r = run_cmd($dir, 'OCP::Cmd::Keys::Operator::Rm', argv => [ 'leitstand' ],
        args => { k8s => FakeOperatorApi->new });
    is $r->{rv}, 0, 'exit 0' or diag $r->{err}, $r->{died};

    for my $f (qw( keys.yaml secrets.yaml kubeconfig.yaml )) {
        ok !opens($dir->child($f), $l->{secret}), "after: $f is closed to the Leitstand";
    }
    isnt $dir->child('secrets.yaml')->slurp, $secrets_before, 'secrets.yaml was rewritten (a new data key)';
    is_deeply(OCP::Secrets->new(project_dir => $dir)->read_all_secrets, { hetzner_token => 'hz-token' },
        'and the project key still reads what it held');

    # keys.yaml is rewritten by delete_key, before rotate_sops_files looks, so
    # reencrypt does not list it; Rm adds it, so STDERR names all three.
    like $r->{out}, qr/Re-encrypted with a new data key: secrets\.yaml, kubeconfig\.yaml\n/, 'STDOUT: what rotate_sops_files rewrote';
    like $r->{err}, qr/\[!!\] age1\S+ is no longer a recipient and keys\.yaml, secrets\.yaml and kubeconfig\.yaml were re-encrypted\.\n/,
        'STDERR: keys.yaml too, A, B and C were';
    unlike $r->{err}, qr/ was re-encrypted/, 'no singular for three files';
};

subtest '(3) operator rm of a project with no secrets.yaml/kubeconfig.yaml: keys.yaml alone, singular' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name => 'k237', control_planes => { provider => 'ssh', host => 'cp.k237.test' } });
    my $secrets = OCP::Secrets->new(project_dir => $dir);
    $secrets->generate_age_key;
    OCP::Keys->new(project_dir => $dir)->add_cluster_keys(pin2 => $PIN2);
    my $l = leitstand();
    my $add = run_cmd($dir, 'OCP::Cmd::Keys::Operator::Add',
        args => { name => 'leitstand', ssh_pubkey => $l->{ssh_pub}, age => $l->{age},
                  k8s => FakeOperatorApi->new });
    die "operator add failed: $add->{died}$add->{err}" unless ($add->{rv} // 1) == 0;

    my $r = run_cmd($dir, 'OCP::Cmd::Keys::Operator::Rm', argv => [ 'leitstand' ],
        args => { k8s => FakeOperatorApi->new });
    is $r->{rv}, 0, 'exit 0' or diag $r->{err}, $r->{died};
    like $r->{err}, qr/\[!!\] age1\S+ is no longer a recipient and keys\.yaml was re-encrypted\.\n/,
        'only keys.yaml exists: singular "was"';
    unlike $r->{err}, qr/ were re-encrypted/, 'and no "were"';
    ok !opens($dir->child('keys.yaml'), $l->{secret}), 'keys.yaml is closed to the Leitstand all the same';
};

subtest '(3) recipients rm names keys.yaml too: rotate_sops_files rewrites it, no delete_key involved' => sub {
    my ($dir, $l) = registered();
    my $r = run_cmd($dir, 'OCP::Cmd::Keys::Recipients::Rm', argv => [ $l->{age} ]);
    is $r->{rv}, 0, 'exit 0' or diag $r->{err}, $r->{died};
    like $r->{out}, qr/Re-encrypted with a new data key: .*keys\.yaml/, 'STDOUT lists keys.yaml';
    like $r->{err}, qr/is no longer a recipient and .*keys\.yaml.* were re-encrypted\./, 'STDERR names keys.yaml';
    for my $f (qw( keys.yaml secrets.yaml kubeconfig.yaml )) {
        ok !opens($dir->child($f), $l->{secret}), "$f is closed to the removed recipient";
    }
};

done_testing;

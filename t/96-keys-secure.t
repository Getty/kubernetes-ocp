#!/usr/bin/env perl
# karr k96 -- `ocp keys secure`: a dev-mode project (no keys.yaml, machines
# trust .ocp/id_ed25519) moves into secure mode without locking itself out.
#
# The claims:
#
#   * the new admin and robo public keys reach every machine -- control planes
#     and the workers the OCPNodes name -- over the bootstrap key, and the
#     admin key is then tried there ALONE (no fallback, ADR 0027)
#   * keys.yaml appears only after every machine passed; until then the new
#     keys sit in .ocp/keys.yaml.pending and the project is dev mode in every
#     file (no age.key.enc either)
#   * a machine that fails is named on STDERR, exit 1, and a second run
#     continues with the SAME staged keys and adds nothing twice
#   * an already-secure project is left alone; --drop-bootstrap removes the
#     bootstrap key's lines with the admin key, only where the admin key works,
#     and never deletes the local file
#   * after the switch robocop's Secret carries the new robo key (one PIN2 for
#     the whole run), a running robocop is restarted; without a cluster that
#     step is skipped with a pointer to `ocp apply`; Hetzner gets both keys
#
# Network-free and cluster-free. The machines are directories with an
# authorized_keys file each: OCP::SSH::run/run_script are replaced by a fake
# that admits a key only when its blob is in that file, and that runs the real
# remote script locally with bash against the directory. keys.yaml, age.key and
# the SSH keys are real (ssh-keygen); the K8s API is a fake.

use strict;
use warnings;
use Test::More;

use Cwd qw( getcwd );
use Crypt::Age;
use MIME::Base64 ();
use Path::Tiny ();

use lib 'lib';

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Keys::Secure;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;
use OCP::SSH;

plan skip_all => 'needs ssh-keygen and bash'
    unless _have('ssh-keygen') && _have('bash');

local @ARGV = ();
my $ocp = OCP->new;

my $PIN1  = 'pin-one-1';
my $PIN2  = 'pin-two-2';
my $TOKEN = 'K10deadbeef::server:cafe';

# --- Fakes ----------------------------------------------------------------

package FakeList {
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}

# Stores what is ensured, serves OCPNodes and pods, records deletes.
package FakeApi {
    sub new {
        my ($class, %opt) = @_;
        my $self = bless { log => [], objects => {}, nodes => $opt{nodes} // [],
                           deleted => [], fail_list => $opt{fail_list} }, $class;
        $self->{objects}{'Deployment/ocp-system/robocop'} = { kind => 'Deployment' }
            if $opt{deployment};
        return $self;
    }

    sub ensure {
        my ($self, $obj) = @_;
        my $key = join '/', $obj->{kind}, $obj->{metadata}{namespace} // '-', $obj->{metadata}{name};
        push @{ $self->{log} }, $key;
        my %stored = %$obj;
        if ($obj->{kind} eq 'Secret' && $obj->{stringData}) {
            delete $stored{stringData};
            $stored{data} = { map {
                $_ => MIME::Base64::encode_base64($obj->{stringData}{$_}, '')
            } keys %{ $obj->{stringData} } };
        }
        $self->{objects}{$key} = \%stored;
        return $obj;
    }

    sub get {
        my ($self, $kind, $name, %opt) = @_;
        my $key = join '/', $kind, $opt{namespace} // '-', $name;
        return $self->{objects}{$key} // die "404 $key\n";
    }

    sub list {
        my ($self, $kind, %opt) = @_;
        die "connection refused\n" if $self->{fail_list};
        return FakeList->new($self->{nodes}) if $kind eq 'OCPNode';
        return FakeList->new([ { metadata => { name => 'robocop-abc' } } ]) if $kind eq 'Pod';
        return FakeList->new([]);
    }

    sub delete {
        my ($self, $kind, %opt) = @_;
        push @{ $self->{deleted} }, "$kind/$opt{name}";
        return 1;
    }

    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub secret           { $_[0]{objects}{'Secret/ocp-system/robocop-credentials'} }
}

package FakeHetzner {
    sub new { bless { uploads => [] }, shift }
    sub upload_ssh_key { push @{ $_[0]{uploads} }, [ $_[1], $_[2] ]; 1 }
}

package main;

# The machines. address => { dir, refuse (no key at all), ignore_writes };
# an alias is a second address for the same hash. @MACHINES lists each once.
our %HOSTS;
our @MACHINES;
our @SSH;           # every connection: { host, kind, what, keys_yaml }
our $PROJECT;       # the project directory of the run in progress

sub add_host {
    my ($address, %opt) = @_;
    my $dir = Path::Tiny->tempdir;
    $dir->child('authorized_keys')->spew($opt{authorized} // '');
    $HOSTS{$address} = { dir => $dir, %opt };
    return $dir;
}

sub authorized { $HOSTS{ $_[0] }{dir}->child('authorized_keys')->slurp }

sub blob_of { (split ' ', $_[0])[1] }

sub count_blob {
    my ($address, $blob) = @_;
    return scalar grep { my @f = split ' '; grep { $_ eq $blob } @f }
        split /\n/, authorized($address);
}

# Which key a connection offers: the .pub beside the key file, as Rex and
# OCP::TempKeyPair keep it.
sub offered {
    my ($ssh) = @_;
    my $pub = Path::Tiny::path($ssh->key_file . '.pub');
    return -f $pub ? blob_of($pub->slurp) : '';
}

{
    no warnings 'redefine';

    my $admit = sub {
        my ($ssh, $what) = @_;
        my $host = $HOSTS{ $ssh->host };
        my $blob = offered($ssh);
        push @SSH, {
            host      => $ssh->host,
            blob      => $blob,
            purpose   => $ssh->key_purpose,
            what      => $what,
            keys_yaml => (-f $PROJECT->child('keys.yaml') ? 1 : 0),
        };
        return { exit => 255, stdout => '', stderr => 'ssh: Could not resolve hostname '.$ssh->host }
            unless $host;
        return { exit => 255, stdout => '', stderr => 'Permission denied (publickey).' }
            if $host->{refuse} || !count_blob($ssh->host, $blob);
        return;
    };

    *OCP::SSH::run = sub {
        my ($self, $cmd) = @_;
        if (my $refused = $admit->($self, $cmd)) { return $refused }
        return { exit => 0, stdout => "$TOKEN\n", stderr => '' } if $cmd =~ /^cat /;
        return { exit => 0, stdout => '', stderr => '' };
    };

    *OCP::SSH::run_script = sub {
        my ($self, $script) = @_;
        if (my $refused = $admit->($self, 'script')) { return $refused }
        my $host = $HOSTS{ $self->host };
        return { exit => 0, stdout => "admin key added\nrobo key added\n", stderr => '' }
            if $host->{ignore_writes};
        my $dir = $host->{dir}->stringify;
        $script =~ s{/root/\.ssh}{$dir}g;
        # qx, not OCP::Exec: IPC::Open3 loses the in-memory STDOUT this test
        # captures the command's output with.
        my $file = Path::Tiny->tempfile;
        $file->spew($script);
        my $errf = Path::Tiny->tempfile;
        my $stdout = qx(bash $file 2>$errf);
        return { exit => $? >> 8, stdout => $stdout, stderr => $errf->slurp };
    };
}

# --- Fixtures ---------------------------------------------------------------

# A dev-mode project as `ocp init --nopassword` leaves it: plain age.key, the
# bootstrap key, no keys.yaml, no age.key.enc.
sub dev_project {
    my (%spec) = @_;
    my $dir = Path::Tiny->tempdir;

    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k96',
        control_planes => { provider => 'ssh', host => 'cp.k96.test' },
        robocop        => { enabled => 1, security_level => 'secret' },
        workers        => [ { name => 'pool', provider => 'ssh',
                              nodes => [ 'w1.k96.test', 'w2.k96.test', 'w3.k96.test' ] } ],
        %spec,
    });

    my $secrets = OCP::Secrets->new(project_dir => $dir);
    $secrets->generate_age_key;
    $secrets->generate_ssh_key;      # .ocp/id_ed25519, the bootstrap key
    return $dir;
}

sub bootstrap_public { $_[0]->child('.ocp', 'id_ed25519.pub')->slurp }

# The OCPNodes of a cluster: the control plane, w1 joined (publicIP), w2 known
# by spec.host only. w3 has none -- an ocp.yaml host not joined yet.
sub cluster_nodes {
    return [
        { metadata => { name => 'cp' }, spec => { role => 'control-plane', host => 'cp.k96.test' },
          status => { publicIP => '10.9.6.1', phase => 'Ready' } },
        { metadata => { name => 'w1' }, spec => { role => 'worker', host => 'w1.k96.test' },
          status => { publicIP => '10.9.6.11', phase => 'Ready' } },
        { metadata => { name => 'w2' }, spec => { role => 'worker', host => 'w2.k96.test' },
          status => { phase => 'Ready' } },
        { metadata => { name => 'hz-1' }, spec => { role => 'worker', providerRef => 'hetzner-default' },
          status => { phase => 'Pending' } },
    ];
}

# The machines of cluster_nodes, each trusting the bootstrap key. The control
# plane answers under its ocp.yaml hostname too: the join token is read from
# there (cluster_status), the keys go to its OCPNode address.
sub cluster_hosts {
    my ($dir) = @_;
    %HOSTS = ();
    @MACHINES = qw( 10.9.6.1 10.9.6.11 w2.k96.test );
    add_host($_, authorized => "# managed by hand\n".bootstrap_public($dir)) for @MACHINES;
    $HOSTS{'cp.k96.test'} = $HOSTS{'10.9.6.1'};
}

# One run of the command. Prompts are answered by what they ask for.
sub run_secure {
    my ($dir, %opt) = @_;

    my $cmd = OCP::Cmd::Keys::Secure->new(
        command_chain => [ $ocp ],
        ($opt{api}  ? (k8s => $opt{api}) : ()),
        ($opt{drop} ? (drop_bootstrap => 1) : ()),
    );
    {
        no warnings 'redefine';
        *OCP::Cmd::Keys::Secure::_hetzner_provider = sub { $opt{hetzner} // FakeHetzner->new };
    }

    my @prompts;
    @SSH = ();
    local $PROJECT = $dir;
    local $OCP::ClusterKey::INTERACTIVE = exists $opt{interactive} ? $opt{interactive} : 1;

    my ($out, $err, $rv) = ('', '');
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub {
            push @prompts, $_[0];
            return $_[0] =~ /PIN1/ ? $PIN1 : ($opt{pin2} // $PIN2);
        };
        local *OCP::Cmd::Keys::Secure::wait_seconds = sub { };
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $cmd->execute([], []) };
    }
    my $died = $@ // '';
    chdir $cwd or die "chdir back: $!";

    return { out => $out, err => $err, died => $died, rv => $rv, prompts => \@prompts,
             ssh => [ @SSH ] };
}

sub staged_keys {
    my ($dir, $file) = @_;
    my $keys = OCP::Keys->new(project_dir => $dir,
        keys_file => Path::Tiny::path($file // $dir->child('keys.yaml')));
    my ($admin) = grep { $_->{purpose} eq 'admin' }      @{ $keys->list_keys };
    my ($robo)  = grep { $_->{purpose} eq 'automation' } @{ $keys->list_keys };
    return ($admin, $robo, $keys);
}

# --- The switch -------------------------------------------------------------

subtest 'success: every machine gets both keys, the admin key is tried, THEN keys.yaml' => sub {
    my $dir = dev_project();
    cluster_hosts($dir);

    # A second age recipient the SOPS files are meant to be readable by: the
    # promoted keys.yaml has to name it, which the staging file's name alone
    # would not have matched.
    my ($extra) = Crypt::Age->generate_keypair;
    OCP::Secrets->new(project_dir => $dir)->set_sops_recipients([ $extra ]);

    my $api = FakeApi->new(nodes => cluster_nodes(), deployment => 1);
    my $r = run_secure($dir, api => $api);

    is $r->{died}, '', 'no exception' or diag $r->{died};
    is $r->{rv}, 0, 'exit 0';
    unlike $r->{err}, qr/\[!!\]/, 'nothing went wrong' or diag $r->{err};

    is_deeply $r->{prompts},
        [ 'Enter PIN1 (cluster access): ', 'Confirm PIN1: ',
          'Enter PIN2 (admin SSH access): ', 'Confirm PIN2: ' ],
        'PIN1 twice, PIN2 twice -- the order --pins-stdin feeds, as in ocp init';

    ok -f $dir->child('keys.yaml'), 'keys.yaml written';
    ok !-f $dir->child('.ocp', 'keys.yaml.pending'), 'the staging file is gone';
    ok -f $dir->child('.ocp', 'id_ed25519'), 'the bootstrap key is still on disk';

    my $age = OCP::Password::decrypt_age_key($dir->child('age.key.enc')->slurp, $PIN1);
    is $age, $dir->child('.ocp', 'age.key')->slurp, 'age.key.enc opens with PIN1 and holds the age key';

    my ($admin, $robo, $keys) = staged_keys($dir);
    ok $admin && $robo, 'keys.yaml holds an admin and a robo key';
    my $private = eval { $keys->get_admin_key($PIN2)->{private} };
    like $private // '', qr/OPENSSH PRIVATE KEY/, 'the admin key opens with PIN2';

    my %bound;
    push @{ $bound{ $_->{file} } }, $_->{recipient}
        for @{ OCP::Secrets->new(project_dir => $dir)->age_key_bindings };
    ok( (grep { $_ eq $extra } @{ $bound{'keys.yaml'} // [] }),
        'keys.yaml is encrypted for the .sops.yaml recipients too' );

    for my $host (@MACHINES) {
        is count_blob($host, blob_of($admin->{public})), 1, "$host: admin key once";
        is count_blob($host, blob_of($robo->{public})),  1, "$host: robo key once";
        is count_blob($host, blob_of(bootstrap_public($dir))), 1, "$host: bootstrap key still there";
        like authorized($host), qr/\A# managed by hand\n/, "$host: what was there stays";
    }

    my @tests = grep { $_->{what} eq 'true' } @{ $r->{ssh} };
    is scalar(@tests), 3, 'the admin key was tried on all three machines';
    is_deeply [ sort map { $_->{host} } @tests ], [ sort @MACHINES ], 'one try each';
    ok !(grep { $_->{blob} ne blob_of($admin->{public}) } @tests),
        'each try offered the admin key and nothing else';
    ok !(grep { $_->{keys_yaml} } grep { $_->{what} !~ /^cat / } @{ $r->{ssh} }),
        'no machine was touched after keys.yaml appeared, except to read the join token';
    ok( (grep { $_->{keys_yaml} && $_->{blob} eq blob_of($admin->{public}) } @{ $r->{ssh} }),
        'the join token was read with the admin key' );

    like $r->{out}, qr/w3 \(w3\.k96\.test\)/, 'the pool host without an OCPNode is named';
    like $r->{out}, qr/ocp keys authorized-keys \| ssh root\@HOST/, 'with the command that gives it both keys';
    like $r->{out}, qr/ocp keys secure --drop-bootstrap/, 'and the bootstrap key is pointed out';

    my $secret = $api->secret;
    ok $secret, 'robocop-credentials written';
    my $robo_priv = $keys->get_automation_key->{private};
    is MIME::Base64::decode_base64($secret->{data}{'robo-ssh-key'}), $robo_priv,
        'with the new robo key';
    is MIME::Base64::decode_base64($secret->{data}{'rke2-token'}), $TOKEN, 'and the join token';
    ok( (grep { $_ eq 'Deployment/ocp-system/robocop' } @{ $api->{log} }), 'Deployment ensured' );
    is_deeply $api->{deleted}, [ 'Pod/robocop-abc' ], 'the running robocop pod was restarted';
    is scalar(@{ $r->{prompts} }), 4, 'and the token read cost no second PIN2';
};

subtest 'a machine fails: no keys.yaml, staging kept, host named, exit 1 -- then a re-run continues' => sub {
    my $dir = dev_project();
    cluster_hosts($dir);
    $HOSTS{'w2.k96.test'}{refuse} = 1;

    my $api = FakeApi->new(nodes => cluster_nodes());
    my $r = run_secure($dir, api => $api);

    is $r->{died}, '', 'no exception' or diag $r->{died};
    is $r->{rv}, 1, 'exit 1';
    like $r->{err}, qr/^\[!!\] w2 \(w2\.k96\.test\): could not add the keys: Permission denied/m,
        'the failed machine is named on STDERR, with the reason';
    like $r->{err}, qr/still in dev mode/, 'the project is said to stay in dev mode';
    like $r->{err}, qr/run 'ocp keys secure' again/, 'and how to continue';
    unlike $r->{out}, qr/\[!!\]/, 'no failure on STDOUT';

    ok !-f $dir->child('keys.yaml'), 'no keys.yaml';
    ok !-f $dir->child('age.key.enc'), 'no age.key.enc either: dev mode in every file';
    my $staging = $dir->child('.ocp', 'keys.yaml.pending');
    ok -f $staging, 'the staged keys are kept';
    ok !$api->secret, 'robocop untouched';

    my ($admin, $robo) = staged_keys($dir, $staging);
    is count_blob('10.9.6.1', blob_of($admin->{public})), 1, 'the machines that passed have the keys';

    # Fixed. The second run takes the staged keys: PIN2 once, to unlock them.
    $HOSTS{'w2.k96.test'}{refuse} = 0;
    my $again = run_secure($dir, api => $api);

    is $again->{rv}, 0, 'the re-run switches' or diag $again->{err}, $again->{died};
    is_deeply $again->{prompts},
        [ 'Enter PIN1 (cluster access): ', 'Confirm PIN1: ', 'Enter PIN2 (admin SSH access): ' ],
        'PIN1 is set now, PIN2 asked once for the staged key';
    like $again->{out}, qr/Continuing with the keys staged/, 'and it says so';

    my ($admin2, $robo2) = staged_keys($dir);
    is $admin2->{public}, $admin->{public}, 'keys.yaml holds the staged admin key, not a new one';
    is $robo2->{public},  $robo->{public},  'and the staged robo key';

    for my $host (@MACHINES) {
        is count_blob($host, blob_of($admin->{public})), 1, "$host: admin key exactly once";
        is count_blob($host, blob_of($robo->{public})),  1, "$host: robo key exactly once";
    }
    like $again->{out}, qr/admin key already there, robo key already there/,
        'a machine that had them is told so, not given a second copy';
};

subtest 'a wrong PIN2 for staged keys stops before any machine is touched' => sub {
    my $dir = dev_project();
    cluster_hosts($dir);
    $HOSTS{'w2.k96.test'}{refuse} = 1;
    my $api = FakeApi->new(nodes => cluster_nodes());
    run_secure($dir, api => $api);

    my $r = run_secure($dir, api => $api, pin2 => 'not-it');
    like $r->{died}, qr/Wrong PIN2 for the staged admin key/, 'refused by name';
    is scalar(@{ $r->{ssh} }), 0, 'no SSH connection';
    ok -f $dir->child('.ocp', 'keys.yaml.pending'), 'staging untouched';
};

subtest 'the admin key refused after a "successful" distribution: no fallback, no switch' => sub {
    my $dir = dev_project();
    cluster_hosts($dir);
    # The script reports success and writes nothing -- e.g. sshd reads another
    # AuthorizedKeysFile. The bootstrap key still works there; the admin key
    # does not, and that has to decide.
    $HOSTS{'10.9.6.11'}{ignore_writes} = 1;

    my $r = run_secure($dir, api => FakeApi->new(nodes => cluster_nodes()));

    is $r->{rv}, 1, 'exit 1';
    like $r->{err}, qr/^\[!!\] w1 \(10\.9\.6\.11\): the admin key is refused: Permission denied/m,
        'the machine is named';
    ok !-f $dir->child('keys.yaml'), 'no keys.yaml';

    my ($admin) = staged_keys($dir, $dir->child('.ocp', 'keys.yaml.pending'));
    my @on_w1 = grep { $_->{host} eq '10.9.6.11' } @{ $r->{ssh} };
    is_deeply [ map { $_->{what} } @on_w1 ], [ 'script', 'true' ],
        'w1: one distribution, one test -- no second attempt';
    is $on_w1[1]{blob}, blob_of($admin->{public}), 'the test offered the admin key';
    is $on_w1[1]{purpose}, 'admin', 'and said it was the admin key';
};

subtest 'already secure: left alone' => sub {
    my $dir = dev_project();
    cluster_hosts($dir);
    my $api = FakeApi->new(nodes => cluster_nodes());
    run_secure($dir, api => $api);
    ok -f $dir->child('keys.yaml'), 'switched';

    my $r = run_secure($dir, api => $api);
    is $r->{rv}, 0, 'exit 0';
    like $r->{out}, qr/^\[ok\] already in secure mode/m, 'says so';
    is_deeply $r->{prompts}, [], 'no prompt';
    is scalar(@{ $r->{ssh} }), 0, 'no SSH';
};

subtest '--drop-bootstrap: removed with the admin key where it works, the file stays' => sub {
    my $dir = dev_project();
    cluster_hosts($dir);
    my $api = FakeApi->new(nodes => cluster_nodes());
    run_secure($dir, api => $api);
    my ($admin, $robo) = staged_keys($dir);
    my $boot = blob_of(bootstrap_public($dir));

    # w1's admin line goes missing; there the bootstrap key must stay.
    my $w1 = $HOSTS{'10.9.6.11'}{dir}->child('authorized_keys');
    my $admin_blob = blob_of($admin->{public});
    $w1->spew(join '', grep { index($_, $admin_blob) < 0 } $w1->lines);

    my $r = run_secure($dir, api => $api, drop => 1);

    is $r->{rv}, 1, 'exit 1: one machine still trusts the bootstrap key';
    is_deeply $r->{prompts}, [ 'Enter PIN2 (admin-key for SSH): ' ],
        'PIN2 once, for the admin key from keys.yaml';

    for my $host ('10.9.6.1', 'w2.k96.test') {
        is count_blob($host, $boot), 0, "$host: bootstrap key removed";
        is count_blob($host, $admin_blob), 1, "$host: admin key kept";
        is count_blob($host, blob_of($robo->{public})), 1, "$host: robo key kept";
        like authorized($host), qr/\A# managed by hand\n/, "$host: other lines kept";
    }
    is count_blob('10.9.6.11', $boot), 1, 'w1: the bootstrap key stays where the admin key is refused';
    like $r->{err}, qr/^\[!!\] w1 \(10\.9\.6\.11\): the admin key is refused/m, 'w1 named';
    like $r->{err}, qr/still opens w1/, 'and that the local key still opens it';
    ok !(grep { $_->{blob} eq $boot } @{ $r->{ssh} }), 'the bootstrap key was never offered';
    ok -f $dir->child('.ocp', 'id_ed25519'), '.ocp/id_ed25519 is not deleted';

    # Fixed: a second run finishes it.
    $w1->append($admin->{public}."\n");
    my $again = run_secure($dir, api => $api, drop => 1);
    is $again->{rv}, 0, 'exit 0';
    is count_blob('10.9.6.11', $boot), 0, 'w1: removed now';
    like $again->{out}, qr/no longer opens any machine of this cluster/, 'the local key is said to be dead';
    like $again->{out}, qr/OCP does not delete it/, 'and left for the operator to delete';
    like $again->{out}, qr/10\.9\.6\.1\): the bootstrap key was not there/, 'machines already done say so';
};

subtest 'no cluster: the control plane only, robocop deferred to ocp apply, --drop-bootstrap in one go' => sub {
    my $dir = dev_project();
    %HOSTS = ();
    @MACHINES = ('cp.k96.test');
    add_host('cp.k96.test', authorized => bootstrap_public($dir));

    my $r = run_secure($dir, drop => 1);

    is $r->{rv}, 0, 'exit 0' or diag $r->{err}, $r->{died};
    ok -f $dir->child('keys.yaml'), 'switched';
    my ($admin, $robo) = staged_keys($dir);
    is count_blob('cp.k96.test', blob_of($admin->{public})), 1, 'the control plane has the admin key';
    is count_blob('cp.k96.test', blob_of(bootstrap_public($dir))), 0, 'and no bootstrap key any more';
    is_deeply [ sort map { $_->{host} } @{ $r->{ssh} } ], [ ('cp.k96.test') x 4 ],
        'the only machine there is: distribute, test, check, remove';
    like $r->{out}, qr/robocop gets its\s+credentials with the first 'ocp apply'/, 'robocop deferred';
    like $r->{out}, qr/w1 \(w1\.k96\.test\), w2 \(w2\.k96\.test\), w3 \(w3\.k96\.test\)/,
        'every pool host is not joined yet';
};

subtest 'never deployed: local switch; Hetzner gets both keys' => sub {
    my $dir = dev_project(
        control_planes => { provider => 'hetzner', location => 'fsn1' },
        workers        => [],
    );
    OCP::Secrets->new(project_dir => $dir)->set_hetzner_token('hz-token');
    %HOSTS = ();

    my $hz = FakeHetzner->new;
    my $r = run_secure($dir, hetzner => $hz);

    is $r->{rv}, 0, 'exit 0' or diag $r->{err}, $r->{died};
    like $r->{out}, qr/No machine has been deployed yet: the switch is local/, 'local';
    is scalar(@{ $r->{ssh} }), 0, 'no SSH';
    ok -f $dir->child('keys.yaml'), 'switched';
    unlike $r->{out}, qr/--drop-bootstrap/, 'no bootstrap key to point at';

    my ($admin, $robo) = staged_keys($dir);
    is_deeply $hz->{uploads},
        [ [ 'ocp-k96-admin', $admin->{public} ], [ 'ocp-k96-robo', $robo->{public} ] ],
        'admin and robo key stored under the names servers are created with';
};

subtest 'Hetzner without a token: deferred when nothing is deployed, an error when it is' => sub {
    my %hz = (control_planes => { provider => 'hetzner', location => 'fsn1' }, workers => []);

    my $fresh = dev_project(%hz);
    %HOSTS = ();
    my $r = run_secure($fresh);
    is $r->{rv}, 0, 'never deployed: exit 0' or diag $r->{err};
    like $r->{out}, qr/first 'ocp apply' stores the keys there/, 'the first apply uploads them';

    my $deployed = dev_project(%hz, robocop => { enabled => 0 });
    my $r2 = run_secure($deployed, api => FakeApi->new(nodes => []));
    is $r2->{rv}, 1, 'deployed: exit 1';
    ok -f $deployed->child('keys.yaml'), 'the switch itself stands';
    like $r2->{err}, qr/^\[!!\] Hetzner is in use, but secrets\.yaml holds no Hetzner token/m,
        'said on STDERR';
    like $r2->{err}, qr/ocp-k96-admin.*\n.*ocp-k96-robo/s, 'with the key names to use';
    like $r2->{out}, qr/robocop is not enabled/, 'robocop disabled: skipped with a word';
};

subtest 'a kubeconfig whose cluster does not answer stops before any prompt' => sub {
    my $dir = dev_project();
    cluster_hosts($dir);
    my $r = run_secure($dir, api => FakeApi->new(fail_list => 1));
    like $r->{died}, qr/Could not read the OCPNodes/, 'dies naming it';
    like $r->{died}, qr/Nothing was changed/, 'and that nothing changed';
    is_deeply $r->{prompts}, [], 'no PIN asked';
    ok !-f $dir->child('.ocp', 'keys.yaml.pending'), 'nothing staged';
};

subtest 'no terminal and no --pins-stdin: refused before anything' => sub {
    my $dir = dev_project();
    cluster_hosts($dir);
    my $r = run_secure($dir, api => FakeApi->new(nodes => cluster_nodes()), interactive => 0);
    like $r->{died}, qr/no\s+terminal to ask on/, 'refused';
    like $r->{died}, qr/--pins-stdin/, 'naming the way to feed PINs';
    is_deeply $r->{prompts}, [], 'nothing asked';
    is scalar(@{ $r->{ssh} }), 0, 'nothing touched';
};

subtest 'dispatches as `ocp keys secure`' => sub {
    my @argv = ('keys', 'secure', '--drop-bootstrap');
    eval { OCP::_resolve_commands('OCP', \@argv) };
    is $@, '', 'resolves';
    is_deeply \@argv, [ 'keys', 'secure', '--drop-bootstrap' ], 'unchanged';
};

sub _have { system("command -v $_[0] >/dev/null 2>&1") == 0 }

done_testing;

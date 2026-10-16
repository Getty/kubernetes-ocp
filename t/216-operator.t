#!/usr/bin/env perl
# karr k216 -- a Leitstand runs `ocp apply` unattended: its own age identity
# (SOPS_AGE_KEY_FILE), its own SSH key (OCP_OPERATOR_KEY), no PIN.
#
# The claims:
#
#   (a) SOPS_AGE_KEY_FILE is the identity of every decrypt -- no PIN1, nothing
#       written to .ocp/ -- and under it the project's recipient is read off
#       the committed files, never taken from that identity: a write stays
#       encrypted for the project key. When the files cannot tell, the write
#       refuses. The private keys inside keys.yaml stay closed to another
#       identity, with a message instead of age's.
#   (b) `ocp keys operator add` records the operator (no private half, its
#       age recipient) and makes it a SOPS recipient; OCP::ClusterKey picks
#       the operator key under that identity, without PIN2.
#   (c) the operator's public key reaches every machine first (admin key), a
#       machine that refuses stops the record; `rm` takes it off again and the
#       record goes even when a machine is down.
#   (d) robocop's Secret: kept with a warning when it exists, a named failure
#       when it does not; inject needs the public half only.
#
# Network-free and cluster-free, the way t/96 is: machines are directories
# with an authorized_keys each, OCP::SSH runs the real remote script locally
# against them and admits a key only when its blob is there. age keys, SOPS
# files and SSH keys (ssh-keygen) are real; the K8s API is a fake.

use strict;
use warnings;
use Test::More;

use Cwd qw( getcwd );
use Crypt::Age;
use File::SOPS;
use MIME::Base64 ();
use Path::Tiny ();

use lib 'lib';

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Deploy;
use OCP::Cmd::Keys::AuthorizedKeys;
use OCP::Cmd::Keys::Operator::Add;
use OCP::Cmd::Keys::Operator::Rm;
use OCP::Cmd::InjectKey;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;
use OCP::SSH;

plan skip_all => 'needs ssh-keygen and bash'
    unless _have('ssh-keygen') && _have('bash');

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{OCP_OPERATOR_KEY};

my $PIN2  = 'pin-two-2';
my $TOKEN = 'K10deadbeef::server:cafe';

# --- Fakes ----------------------------------------------------------------

package FakeList {
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}

package FakeApi {
    sub new {
        my ($class, %opt) = @_;
        return bless { log => [], objects => {}, nodes => $opt{nodes} // [] }, $class;
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
        my ($self, $kind) = @_;
        return FakeList->new($kind eq 'OCPNode' ? $self->{nodes} : []);
    }

    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub secret           { $_[0]{objects}{'Secret/ocp-system/robocop-credentials'} }
}

package FakeOCP {
    sub new     { bless { config => $_[1] }, $_[0] }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

package main;

# The machines: address => { dir, refuse }. An alias shares the hash.
our %HOSTS;
our @SSH;

sub add_host {
    my ($address, %opt) = @_;
    my $dir = Path::Tiny->tempdir;
    $dir->child('authorized_keys')->spew($opt{authorized} // '');
    $HOSTS{$address} = { dir => $dir, %opt };
    return $dir;
}

sub authorized { $HOSTS{ $_[0] }{dir}->child('authorized_keys')->slurp }
sub blob_of    { (split ' ', $_[0])[1] }

sub count_blob {
    my ($address, $blob) = @_;
    return scalar grep { my @f = split ' '; grep { $_ eq $blob } @f }
        split /\n/, authorized($address);
}

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
        push @SSH, { host => $ssh->host, blob => $blob, what => $what };
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
        my $dir = $HOSTS{ $self->host }{dir}->stringify;
        $script =~ s{/root/\.ssh}{$dir}g;
        my $file = Path::Tiny->tempfile;
        $file->spew($script);
        my $errf = Path::Tiny->tempfile;
        my $stdout = qx(bash $file 2>$errf);
        return { exit => $? >> 8, stdout => $stdout, stderr => $errf->slurp };
    };
}

# --- Fixtures ---------------------------------------------------------------

# A secure-mode project: project age key unlocked in .ocp/, keys.yaml with a
# real admin (PIN2) and robo key, secrets.yaml, kubeconfig.yaml, robocop on.
sub secure_project {
    my (%spec) = @_;
    my $dir = Path::Tiny->tempdir;

    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k216',
        control_planes => { provider => 'ssh', host => 'cp.k216.test' },
        robocop        => { enabled => 1, security_level => 'secret' },
        workers        => [ { name => 'pool', provider => 'ssh',
                              nodes => [ 'w1.k216.test', 'w2.k216.test' ] } ],
        %spec,
    });

    my $secrets = OCP::Secrets->new(project_dir => $dir);
    $secrets->generate_age_key;
    OCP::Keys->new(project_dir => $dir)->add_cluster_keys(pin2 => $PIN2);
    $secrets->create_secrets(hetzner_token => 'hz-token');
    $secrets->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");
    return $dir;
}

sub project_key   { $_[0]->child('.ocp', 'age.key')->slurp =~ s/\s+\z//r }
sub project_pub   { $_[0]->child('.ocp', 'age.pub')->slurp =~ s/\s+\z//r }

sub keys_of {
    my ($dir) = @_;
    my $all = OCP::Keys->new(project_dir => $dir)->list_keys;
    my ($admin) = grep { $_->{purpose} eq 'admin' }      @$all;
    my ($robo)  = grep { $_->{purpose} eq 'automation' } @$all;
    return ($admin, $robo, $all);
}

# A Leitstand: an age identity file as age-keygen writes it, and an SSH key.
sub leitstand {
    my $home = Path::Tiny->tempdir;
    my ($pub, $sec) = Crypt::Age->generate_keypair;
    my $id = $home->child('age.key');
    $id->spew("# created: 2026-10-16T00:00:00Z\n# public key: $pub\n$sec\n");
    my $ssh = $home->child('id_leitstand');
    system('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'leitstand',
        '-f', $ssh->stringify) == 0 or die "ssh-keygen failed\n";
    return {
        home       => $home,
        age        => $pub,
        secret     => $sec,
        identity   => $id->stringify,
        ssh        => $ssh->stringify,
        ssh_pub    => "$ssh.pub",
        public     => $ssh->sibling('id_leitstand.pub')->slurp =~ s/\s+\z//r,
    };
}

# What the Leitstand's checkout has: the committed files, no .ocp/.
sub clone_of {
    my ($dir) = @_;
    my $clone = Path::Tiny->tempdir;
    for my $f (qw( ocp.yaml keys.yaml secrets.yaml kubeconfig.yaml .sops.yaml age.key.enc )) {
        $dir->child($f)->copy($clone->child($f)) if -f $dir->child($f);
    }
    return $clone;
}

sub bound {
    my ($dir, $file) = @_;
    return [ sort map { $_->{recipient} } grep { $_->{file} eq $file }
             @{ OCP::Secrets->new(project_dir => $dir)->age_key_bindings } ];
}

sub opens {
    my ($file, $identity) = @_;
    return eval {
        File::SOPS->decrypt(encrypted => Path::Tiny::path($file)->slurp,
            identities => [$identity], format => 'yaml');
        1;
    } ? 1 : 0;
}

# The cluster: a control plane and two workers, each trusting the admin key.
sub cluster_nodes {
    return [
        { metadata => { name => 'cp' }, spec => { role => 'control-plane', host => 'cp.k216.test' },
          status => { publicIP => '10.2.16.1', phase => 'Ready' } },
        { metadata => { name => 'w1' }, spec => { role => 'worker', host => 'w1.k216.test' },
          status => { publicIP => '10.2.16.11', phase => 'Ready' } },
        { metadata => { name => 'w2' }, spec => { role => 'worker', host => 'w2.k216.test' },
          status => { phase => 'Ready' } },
    ];
}
our @MACHINES = qw( 10.2.16.1 10.2.16.11 w2.k216.test );

sub cluster_hosts {
    my ($dir) = @_;
    my ($admin, $robo) = keys_of($dir);
    %HOSTS = ();
    add_host($_, authorized => "# by hand\n$admin->{public}\n$robo->{public}\n") for @MACHINES;
    $HOSTS{'cp.k216.test'} = $HOSTS{'10.2.16.1'};
}

# One command run in $dir, prompts answered and recorded, output captured.
sub run_cmd {
    my ($dir, $class, %opt) = @_;

    my $cmd = $class->new(
        command_chain => [ $ocp ],
        %{ $opt{args} // {} },
    );

    my @prompts;
    @SSH = ();
    local $OCP::ClusterKey::INTERACTIVE = exists $opt{interactive} ? $opt{interactive} : 1;

    my ($out, $err, $rv) = ('', '');
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub {
            push @prompts, $_[0];
            die "unexpected prompt: $_[0]\n" if $opt{no_prompt};
            return $opt{pin2} // $PIN2;
        };
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $cmd->execute($opt{argv} // [], []) };
    }
    my $died = $@ // '';
    chdir $cwd or die "chdir back: $!";

    return { out => $out, err => $err, died => $died, rv => $rv, prompts => \@prompts,
             ssh => [ @SSH ], cmd => $cmd };
}

sub operator_add {
    my ($dir, $l, %opt) = @_;
    return run_cmd($dir, 'OCP::Cmd::Keys::Operator::Add',
        args => { name => $opt{name} // 'leitstand', ssh_pubkey => $opt{ssh_pubkey} // $l->{ssh_pub},
                  age => $opt{age} // $l->{age},
                  k8s => $opt{api} // FakeApi->new(nodes => cluster_nodes()) },
        %opt);
}

# --- (a) SOPS_AGE_KEY_FILE --------------------------------------------------

subtest '(a) SOPS_AGE_KEY_FILE holding the project key: no PIN1, .ocp/ untouched' => sub {
    my $dir = secure_project();
    my $tmp = Path::Tiny->tempdir;
    my $key = $tmp->child('project.key');
    $key->spew("# public key: ".project_pub($dir)."\n".project_key($dir)."\n");

    # A clone: age.key.enc would want PIN1; there is no .ocp/ at all.
    my $secrets = OCP::Secrets->new(project_dir => $dir);
    $secrets->encrypt_age_key_with_password('pin-one-1');
    my $clone = clone_of($dir);

    local $ENV{SOPS_AGE_KEY_FILE} = $key->stringify;
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { die "PIN prompted: $_[0]\n" };

    my $s = OCP::Secrets->new(project_dir => $clone);
    ok $s->ensure_age_key, 'ensure_age_key: done, without a prompt';
    is $s->read_secret('hetzner_token'), 'hz-token', 'secrets.yaml decrypts';
    like $s->read_kubeconfig, qr/kind: Config/, 'kubeconfig.yaml decrypts';
    my ($admin) = keys_of($clone);
    is( OCP::Keys->new(project_dir => $clone)->get_admin_key($PIN2)->{name}, $admin->{name},
        'the admin key opens: this identity IS the project key' );

    $s->save_kubeconfig("apiVersion: v1\nkind: Config\n");
    is_deeply bound($clone, 'kubeconfig.yaml'), [ project_pub($dir) ],
        'a write is encrypted for the project key';
    ok !-e $clone->child('.ocp'), 'nothing written to .ocp/: no age.key, no age.pub';
    is $key->slurp, "# public key: ".project_pub($dir)."\n".project_key($dir)."\n",
        'the identity file is unchanged';
};

subtest '(a) a Leitstand identity: reads the SOPS files, the project key stays a recipient' => sub {
    my $dir = secure_project();
    my $l   = leitstand();
    my $s   = OCP::Secrets->new(project_dir => $dir);
    $s->set_sops_recipients([ $l->{age} ]);
    $s->rotate_sops_files;
    my $proj = project_pub($dir);

    my $clone = clone_of($dir);
    local $ENV{SOPS_AGE_KEY_FILE} = $l->{identity};
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { die "PIN prompted: $_[0]\n" };

    my $ls = OCP::Secrets->new(project_dir => $clone);
    $ls->ensure_age_key;
    is $ls->read_secret('hetzner_token'), 'hz-token', 'secrets.yaml decrypts with its identity';
    is $ls->age_recipient, $proj, 'the project recipient, read off the files';
    is( OCP::Secrets->new(project_dir => $clone)->identity_opens_private_keys, 0,
        'and its identity does not open the private keys' );

    $ls->save_kubeconfig("apiVersion: v1\nkind: Config\nusers: []\n");
    $ls->update_secret(extra => 'x');
    for my $f (qw( kubeconfig.yaml secrets.yaml )) {
        is_deeply bound($clone, $f), [ sort $proj, $l->{age} ], "$f: still the project key and the Leitstand";
        ok opens($clone->child($f), project_key($dir)), "$f: the project key opens it";
    }
    ok !-e $clone->child('.ocp'), 'nothing written to .ocp/';

    my $err = eval { OCP::Keys->new(project_dir => $clone)->get_automation_key; 1 } ? '' : $@;
    like $err, qr/opens for the project key alone/, 'the robo private key: refused by name';
    like $err, qr/SOPS_AGE_KEY_FILE/, 'naming the variable';
    unlike $err, qr/no identity|could not decrypt/i, 'not age\'s own message';
};

subtest '(a) when the files cannot tell which recipient is the project key, writes refuse' => sub {
    my $dir = secure_project();
    my $l   = leitstand();
    my ($x_pub) = Crypt::Age->generate_keypair;
    my $s   = OCP::Secrets->new(project_dir => $dir);
    $s->set_sops_recipients([ $l->{age}, $x_pub ]);
    $s->rotate_sops_files;

    my $clone  = clone_of($dir);
    my $before = $clone->child('kubeconfig.yaml')->slurp;
    local $ENV{SOPS_AGE_KEY_FILE} = $l->{identity};

    my $ls = OCP::Secrets->new(project_dir => $clone);
    is $ls->age_recipient, undef, 'no answer: two recipients could be it';
    ok !eval { $ls->save_kubeconfig("apiVersion: v1\nkind: Config\n"); 1 }, 'the write refuses';
    like $@, qr/Which age recipient is this project's own key/, 'saying why';
    like $@, qr/\Q$x_pub\E/, 'naming the candidates';
    like $@, qr{\.ocp/age\.pub}, 'and the way out';
    is $clone->child('kubeconfig.yaml')->slurp, $before, 'nothing was written';

    $clone->child('.ocp')->mkpath;
    $clone->child('.ocp', 'age.pub')->spew(project_pub($dir)."\n");
    ok eval { $ls->save_kubeconfig("apiVersion: v1\nkind: Config\n"); 1 }, 'with .ocp/age.pub it writes'
        or diag $@;
    ok opens($clone->child('kubeconfig.yaml'), project_key($dir)), 'for the project key';
};

subtest '(a) a missing file, or an identity the project does not know' => sub {
    my $dir = secure_project();

    local $ENV{SOPS_AGE_KEY_FILE} = '/nonexistent/k216/age.key';
    my $s = OCP::Secrets->new(project_dir => $dir);
    ok !eval { $s->read_secret('hetzner_token'); 1 }, 'a missing file fails';
    like $@, qr{SOPS_AGE_KEY_FILE is set to /nonexistent/k216/age\.key, and there is no such file},
        'naming the variable and the file';

    my $l = leitstand();
    local $ENV{SOPS_AGE_KEY_FILE} = $l->{identity};
    ok !eval { OCP::Secrets->new(project_dir => $dir)->ensure_age_key; 1 }, 'a stranger fails';
    like $@, qr/does not belong to this project.*SOPS_AGE_KEY_FILE/s, 'with the recipients named';
    is project_key($dir), project_key($dir), '.ocp/age.key still there';
};

# --- (b)/(c) operator add ---------------------------------------------------

subtest '(b)(c) operator add: on every machine first, then keys.yaml and the recipients' => sub {
    my $dir = secure_project();
    cluster_hosts($dir);
    my $l = leitstand();

    my $r = operator_add($dir, $l);
    is $r->{died}, '', 'no exception' or diag $r->{died};
    is $r->{rv}, 0, 'exit 0' or diag $r->{err};
    is_deeply $r->{prompts}, [ 'Enter PIN2 (admin-key for SSH): ' ], 'PIN2 once, for the admin key';

    for my $host (@MACHINES) {
        is count_blob($host, blob_of($l->{public})), 1, "$host: the operator key, once";
        like authorized($host), qr/\A# by hand\n/, "$host: what was there stays";
    }

    my (undef, undef, $all) = keys_of($dir);
    my ($entry) = grep { $_->{name} eq 'leitstand' } @$all;
    ok $entry, 'keys.yaml has the operator';
    is $entry->{purpose}, 'operator', 'purpose operator';
    is $entry->{age}, $l->{age}, 'with its age recipient';
    is $entry->{public}, $l->{public}, 'and its public key';
    ok !exists $entry->{private}, 'and no private half';
    is $entry->{deprecated}, 0, 'not deprecated';
    is $entry->{type}, 'ssh_ed25519', 'typed like the other SSH keys';

    my @extras = OCP::Secrets->new(project_dir => $dir)->extra_recipients;
    is_deeply \@extras, [ $l->{age} ], 'its age recipient is in .sops.yaml';
    for my $f (qw( keys.yaml secrets.yaml kubeconfig.yaml )) {
        ok opens($dir->child($f), $l->{secret}), "$f opens for the Leitstand";
    }

    my $again = operator_add($dir, $l);
    is $again->{rv}, 0, 'the same add again: fine' or diag $again->{err}, $again->{died};
    like $again->{out}, qr/operator 'leitstand' key already there/, 'the machines say so';
    like $again->{out}, qr/already has the operator 'leitstand'/, 'and keys.yaml';
    is count_blob($_, blob_of($l->{public})), 1, "$_: still once" for @MACHINES;
    is scalar(grep { $_->{name} eq 'leitstand' } @{ (keys_of($dir))[2] }), 1, 'one entry';
};

subtest '(b) operator add refuses before any PIN, and on clashes' => sub {
    my $dir = secure_project();
    cluster_hosts($dir);
    my $l = leitstand();

    for my $bad ('Leitstand', '-x', 'a_b', 'x' x 64) {
        my $r = operator_add($dir, $l, name => $bad);
        like $r->{died}, qr/Not an operator name: '\Q$bad\E'/, "'$bad' is refused";
        is_deeply $r->{prompts}, [], 'before any prompt';
    }
    my $r = operator_add($dir, $l, age => 'age1nonsense');
    like $r->{died}, qr/--age: not an age recipient/, 'a bad age recipient';
    $r = operator_add($dir, $l, ssh_pubkey => $l->{ssh});
    like $r->{died}, qr/PRIVATE key/, 'a private key file is refused';
    $r = operator_add($dir, $l, age => project_pub($dir));
    like $r->{died}, qr/is the project key itself/, 'the project key is no operator';
    my ($admin) = keys_of($dir);
    $r = operator_add($dir, $l, name => $admin->{name});
    like $r->{died}, qr/already a key in keys\.yaml, of purpose admin/, 'a name the admin key has';

    is operator_add($dir, $l)->{rv}, 0, 'registered';
    my $other = leitstand();
    $r = operator_add($dir, $other);
    like $r->{died}, qr/already registered, with other keys/, 'same name, other keys';
    $r = operator_add($dir, $other, name => 'second', age => $l->{age});
    like $r->{died}, qr/already the age recipient of the operator 'leitstand'/, 'its age recipient taken';
    $r = operator_add($dir, $other, name => 'second', ssh_pubkey => $l->{ssh_pub});
    like $r->{died}, qr/That SSH key is already in keys\.yaml as 'leitstand'/, 'its SSH key taken';
};

subtest '(c) a machine refuses: named, nothing recorded, exit 1 -- a re-run finishes' => sub {
    my $dir = secure_project();
    cluster_hosts($dir);
    $HOSTS{'10.2.16.11'}{refuse} = 1;
    my $l = leitstand();

    my $r = operator_add($dir, $l);
    is $r->{rv}, 1, 'exit 1';
    like $r->{err}, qr/^\[!!\] w1 \(10\.2\.16\.11\): could not add the operator key: Permission denied/m,
        'the machine, on STDERR';
    like $r->{err}, qr/Not registered/, 'nothing recorded';
    ok !(grep { $_->{name} eq 'leitstand' } @{ (keys_of($dir))[2] }), 'no keys.yaml entry';
    is_deeply [ OCP::Secrets->new(project_dir => $dir)->extra_recipients ], [], 'no recipient';
    is count_blob('10.2.16.1', blob_of($l->{public})), 1, 'the others have the key';

    $HOSTS{'10.2.16.11'}{refuse} = 0;
    my $again = operator_add($dir, $l);
    is $again->{rv}, 0, 'the re-run registers' or diag $again->{err};
    is count_blob($_, blob_of($l->{public})), 1, "$_: once" for @MACHINES;
};

# --- (b) the operator at work -----------------------------------------------

# A project with the Leitstand registered, and its checkout.
sub registered {
    my $dir = secure_project();
    cluster_hosts($dir);
    my $l = leitstand();
    my $r = operator_add($dir, $l);
    die "operator add failed: $r->{died}$r->{err}" unless ($r->{rv} // 1) == 0;
    return ($dir, $l, clone_of($dir));
}

subtest '(b) ClusterKey: the operator key under its identity, no PIN2' => sub {
    my ($dir, $l, $clone) = registered();
    my $config = OCP::Config->new(file => $clone->child('ocp.yaml')->stringify, ocp => $ocp);

    local $ENV{SOPS_AGE_KEY_FILE} = $l->{identity};
    local $ENV{OCP_OPERATOR_KEY}  = $l->{ssh};
    local $OCP::ClusterKey::INTERACTIVE = 0;
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { die "PIN prompted: $_[0]\n" };

    is_deeply [ (OCP::ClusterKey->identity_of($config))[0] ], [ 'operator' ], 'identity_of: operator';
    my $key = OCP::ClusterKey->for_config($config);
    is $key->origin, 'operator', 'origin operator';
    is $key->label, "the operator key 'leitstand'", 'labelled by name';
    is $key->content, Path::Tiny::path($l->{ssh})->slurp, 'its private key';
    is blob_of(Path::Tiny::path($key->public_path)->slurp), blob_of($l->{public}), '.pub beside it';
    ok $key->is_temporary, 'a temp copy';
    is $key->migration_hint, '', 'migration_hint stays admin-only';
    ok !-e $clone->child('.ocp'), 'nothing in .ocp/';

    {
        local $ENV{OCP_OPERATOR_KEY};
        ok !eval { OCP::ClusterKey->for_config($config); 1 }, 'without OCP_OPERATOR_KEY: no key';
        like $@, qr/operator 'leitstand'.*OCP_OPERATOR_KEY, the path to its private half, is not set/s,
            'said by name';
    }
    {
        my $other = leitstand();
        local $ENV{OCP_OPERATOR_KEY} = $other->{ssh};
        ok !eval { OCP::ClusterKey->for_config($config); 1 }, 'another SSH key: refused';
        like $@, qr/is not it\..*keys\.yaml has for 'leitstand'/s, 'naming both';
    }
    {
        local $ENV{OCP_OPERATOR_KEY} = '/nonexistent/key';
        ok !eval { OCP::ClusterKey->for_config($config); 1 }, 'a missing file';
        like $@, qr{/nonexistent/key, which does not exist}, 'named';
    }
};

subtest '(b) another recipient that is no operator: refused by name, no prompt' => sub {
    my $dir = secure_project();
    my $l   = leitstand();
    my $s   = OCP::Secrets->new(project_dir => $dir);
    $s->set_sops_recipients([ $l->{age} ]);
    $s->rotate_sops_files;
    my $clone  = clone_of($dir);
    my $config = OCP::Config->new(file => $clone->child('ocp.yaml')->stringify, ocp => $ocp);

    local $ENV{SOPS_AGE_KEY_FILE} = $l->{identity};
    local $OCP::ClusterKey::INTERACTIVE = 1;
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { die "PIN prompted: $_[0]\n" };

    ok !eval { OCP::ClusterKey->for_config($config); 1 }, 'no key';
    like $@, qr/not the project key,\s+and no operator in keys\.yaml names it/, 'why';
    like $@, qr/ocp keys operator add .*--age \Q$l->{age}\E/, 'and how to register it';
    unlike $@, qr/PIN prompted/, 'without asking for PIN2';
};

subtest '(b) PIN2 approval and a first deploy are not the operator\'s' => sub {
    my ($dir, $l, $clone) = registered();
    my $config = OCP::Config->new(file => $clone->child('ocp.yaml')->stringify, ocp => $ocp);

    local $ENV{SOPS_AGE_KEY_FILE} = $l->{identity};
    local $ENV{OCP_OPERATOR_KEY}  = $l->{ssh};
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { die "PIN prompted: $_[0]\n" };

    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new('ocp.yaml') ]);
    ok !eval { $apply->require_admin_approval($config, 'Injecting the robo key into robocop'); 1 },
        'require_admin_approval refuses';
    like $@, qr/Injecting the robo key into robocop is admin-gated.*operator 'leitstand'/s, 'by name';
    unlike $@, qr/PIN prompted/, 'without a prompt';

    $clone->child('kubeconfig.yaml')->remove;   # no cluster yet
    my $cwd = getcwd();
    chdir $clone or die $!;
    my $out = '';
    my $ok = eval {
        open my $fh, '>', \$out or die $!;
        local *STDOUT = $fh;
        $apply->execute([], []);
        1;
    };
    my $err = $@;
    chdir $cwd or die $!;
    ok !$ok, 'a first apply under the operator identity refuses';
    like $err, qr/no cluster yet.*operator 'leitstand'.*project key \(PIN1 \+ PIN2\)/s,
        'saying whose job the first deploy is';
    unlike $err, qr/PIN prompted/, 'before any prompt';
};

# --- (b) authorized-keys ----------------------------------------------------

subtest '(b) authorized-keys: all carries the operators, --purpose operator alone' => sub {
    my ($dir, $l) = registered();
    my ($admin, $robo) = keys_of($dir);

    my $r = run_cmd($dir, 'OCP::Cmd::Keys::AuthorizedKeys');
    is $r->{rv}, 0, 'exit 0' or diag $r->{died};
    is $r->{out}, "$admin->{public}\n$robo->{public}\n$l->{public}\n",
        'admin, robo, then the operator -- STDOUT only lines';
    like $r->{err}, qr/leitstand \(operator, an operator/, 'named on STDERR';

    $r = run_cmd($dir, 'OCP::Cmd::Keys::AuthorizedKeys', args => { purpose => 'operator' });
    is $r->{out}, "$l->{public}\n", '--purpose operator: the operator keys';

    my $plain = secure_project();
    $r = run_cmd($plain, 'OCP::Cmd::Keys::AuthorizedKeys');
    is $r->{rv}, 0, 'without operators, all is still complete';
    is scalar(split /\n/, $r->{out}), 2, 'admin and robo';
    $r = run_cmd($plain, 'OCP::Cmd::Keys::AuthorizedKeys', args => { purpose => 'operator' });
    like $r->{died}, qr/No operator key \(purpose operator\)/, '--purpose operator without one: an error';
};

# --- (d) robocop credentials ------------------------------------------------

sub robocop_run {
    my ($clone, $l, %opt) = @_;
    my $config = OCP::Config->new(file => $clone->child('ocp.yaml')->stringify, ocp => $ocp);
    my $api    = $opt{api} // FakeApi->new;
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new('ocp.yaml') ]);

    local $ENV{SOPS_AGE_KEY_FILE} = $l->{identity};
    local $ENV{OCP_OPERATOR_KEY}  = $l->{ssh};
    no warnings qw( redefine once );
    local *OCP::Password::prompt_password = sub { die "PIN prompted: $_[0]\n" };
    local *OCP::Cmd::Apply::_wait_robocop_ready = sub { 1 };

    my ($out, $err, $step) = ('', '');
    {
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $step = OCP::Cmd::Apply::Deploy::robocop_step($apply, $api, $config, {
            cp_ip   => '10.2.16.1',
            secrets => OCP::Secrets->new(project_dir => $clone),
        });
    }
    return { step => $step, out => $out, err => $err, api => $api };
}

subtest '(d) the Secret exists: [WARN], left as it is, the Deployment still rolled out' => sub {
    my ($dir, $l, $clone) = registered();
    my $api = FakeApi->new;
    $api->ensure({ apiVersion => 'v1', kind => 'Secret',
        metadata => { name => 'robocop-credentials', namespace => 'ocp-system' },
        stringData => { 'robo-ssh-key' => 'OLD', 'server-url' => 'x', 'rke2-token' => 't' } });
    my $before = { %{ $api->secret->{data} } };
    $api->{log} = [];

    my $r = robocop_run($clone, $l, api => $api);
    isnt $r->{step}{state}, 'failed', 'robocop is not failed' or diag $r->{err};
    like $r->{err}, qr/\[WARN\] Secret\/robocop-credentials is left as it is/, '[WARN] on STDERR';
    like $r->{err}, qr/ocp deploy-robocop.*project key/s, 'with the way to refresh it';
    is_deeply $api->secret->{data}, $before, 'the Secret is unchanged';
    ok !(grep { m{^Secret/} } @{ $api->{log} }), 'and not written';
    ok( (grep { $_ eq 'Deployment/ocp-system/robocop' } @{ $api->{log} }), 'the Deployment is ensured' );
    unlike $r->{out}, qr/left as it is/, 'nothing of it on STDOUT';
};

subtest '(d) the Secret is missing: failed, with the reason' => sub {
    my ($dir, $l, $clone) = registered();
    my $r = robocop_run($clone, $l);
    is $r->{step}{state}, 'failed', 'robocop step failed (apply exits 1)';
    like $r->{err}, qr/robocop-credentials does not exist, and this run cannot write it/, 'why';
    like $r->{err}, qr/once with the project key/, 'and who can';
    ok !$r->{api}->secret, 'no Secret';
    unlike $r->{err}, qr/PIN prompted/, 'no prompt';
};

subtest '(d) inject: the public half is enough -- written with the operator key' => sub {
    my ($dir, $l, $clone) = registered();
    my $yaml = $ocp->load($clone->child('ocp.yaml')->slurp);
    $yaml->{robocop}{security_level} = 'inject';
    $ocp->dump_file($clone->child('ocp.yaml')->stringify, $yaml);
    my ($admin, $robo) = keys_of($dir);

    @SSH = ();
    my $r = robocop_run($clone, $l);
    isnt $r->{step}{state}, 'failed', 'not failed' or diag $r->{err};
    my $data = $r->{api}->secret->{data};
    is MIME::Base64::decode_base64($data->{'robo-ssh-public-key'}), $robo->{public}, 'the robo public key';
    is MIME::Base64::decode_base64($data->{'rke2-token'}), $TOKEN, 'and the token';
    is( (grep { $_->{what} =~ /^cat / } @SSH)[0]{blob}, blob_of($l->{public}),
        'read with the operator key' );
};

# --- (c) operator rm --------------------------------------------------------

subtest '(c) operator rm: off every machine, out of keys.yaml and .sops.yaml' => sub {
    my ($dir, $l) = registered();

    my $r = run_cmd($dir, 'OCP::Cmd::Keys::Operator::Rm', argv => [ 'leitstand' ],
        args => { k8s => FakeApi->new(nodes => cluster_nodes()) });
    is $r->{rv}, 0, 'exit 0' or diag $r->{err}, $r->{died};
    is count_blob($_, blob_of($l->{public})), 0, "$_: the operator key is gone" for @MACHINES;
    like authorized('10.2.16.1'), qr/\A# by hand\n/, 'the rest stays';
    ok !(grep { $_->{name} eq 'leitstand' } @{ (keys_of($dir))[2] }), 'keys.yaml: gone';
    is_deeply [ OCP::Secrets->new(project_dir => $dir)->extra_recipients ], [], '.sops.yaml: gone';
    for my $f (qw( keys.yaml secrets.yaml kubeconfig.yaml )) {
        ok !opens($dir->child($f), $l->{secret}), "$f: closed to the Leitstand";
    }
    like $r->{err}, qr/is no longer a recipient.*Rotate what those held/s, 'the rotation hint, STDERR';

    my $again = run_cmd($dir, 'OCP::Cmd::Keys::Operator::Rm', argv => [ 'leitstand' ],
        args => { k8s => FakeApi->new(nodes => cluster_nodes()) });
    like $again->{died}, qr/Unknown operator 'leitstand'/, 'a second rm: unknown';
};

subtest '(c) operator rm with a machine down: the record goes, the machine is named' => sub {
    my ($dir, $l) = registered();
    $HOSTS{'10.2.16.11'}{refuse} = 1;

    my $r = run_cmd($dir, 'OCP::Cmd::Keys::Operator::Rm', argv => [ 'leitstand' ],
        args => { k8s => FakeApi->new(nodes => cluster_nodes()) });
    is $r->{rv}, 1, 'exit 1';
    like $r->{err}, qr/^\[!!\] w1 \(10\.2\.16\.11\): could not remove the operator key/m, 'named';
    like $r->{err}, qr/STILL in authorized_keys on:\n  w1 \(10\.2\.16\.11\)/, 'where it still is';
    like $r->{err}, qr/grep -vF '\Q@{[ blob_of($l->{public}) ]}\E'/, 'and how to take it off by hand';
    is count_blob('10.2.16.11', blob_of($l->{public})), 1, 'still on w1';
    is count_blob('10.2.16.1', blob_of($l->{public})), 0, 'gone elsewhere';
    ok !(grep { $_->{name} eq 'leitstand' } @{ (keys_of($dir))[2] }), 'keys.yaml: gone anyway';
    ok !opens($dir->child('secrets.yaml'), $l->{secret}), 'and the recipient too';
};

subtest 'dispatches as `ocp keys operator add|rm`' => sub {
    my @argv = ('keys', 'operator', 'add', '--name', 'x');
    eval { OCP::_resolve_commands('OCP', \@argv) };
    is $@, '', 'add resolves';
    @argv = ('keys', 'operator', 'nope');
    eval { OCP::_resolve_commands('OCP', \@argv) };
    like $@, qr/^Available: add, rm$/m, 'the subcommands';
};

sub _have { system("command -v $_[0] >/dev/null 2>&1") == 0 }

done_testing;

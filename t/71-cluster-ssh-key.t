#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Destroy;
use OCP::Cmd::Node::Add;
use OCP::Cmd::SSH;
use OCP::Cmd::Update;
use OCP::Config;

#
# Which private key reaches this cluster's machines?
#
# THE ANSWER, since the two-tier decision: the MODE decides, not the provider.
# Secure mode has robo (automation, no PIN2) and admin (age + PIN2) and
# nothing else, so every machine — Hetzner or pre-existing ssh host — is
# reached with the admin key. The bootstrap key .ocp/id_ed25519 belongs to
# --nopassword dev mode alone.
#
# That reverses one half of karr #87 while keeping the other. #87 fixed four
# places that answered "$config->ssh_private_key_path" for machines that had
# never seen that key:
#
#   OCP::Cmd::Update            (two Rex call sites)
#   OCP::Cmd::Node::Add         (join token off the CP, then the new worker)
#   OCP::Cmd::Apply::Drift      (run_remedy, the reconcile path's Rex task)
#   OCP::Cmd::Destroy           (the ssh branch — left alone at the time)
#
# Destroy is now in the same boat as the rest, and that is the delicate one:
# its key lookup can prompt for PIN2 and can therefore FAIL, while the loop it
# guards deletes paid Hetzner servers. The teardown tests below assert that a
# failed lookup costs an uninstall script, never a server.
#
# What is asserted here is the choice itself, not the SSH that follows it:
# which key is reached for, that the temp file holding a decrypted private key
# does not survive the run, and that nothing waits on a password prompt that
# no one can see.
#
# The key store is stubbed on purpose. t/69 already covers real key
# generation end to end through `ocp init`; repeating it here would make a
# selection test depend on ssh-keygen and age.
#

my $ADMIN = {
    name    => 'admin-ssh',
    purpose => 'admin',
    private => "-----BEGIN OPENSSH PRIVATE KEY-----\nADMINKEYMATERIAL\n",
    public  => 'ssh-ed25519 AAAAadminpublic admin@ocp',
};

my $BOOTSTRAP_PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----\nBOOTSTRAPKEY\n";

my $PROMPTS = 0;

# A project directory. `secure` writes keys.yaml, whose mere presence is how
# every caller in this distribution detects secure mode. `bootstrap_key`
# defaults to on even for secure + hetzner, where `ocp init` would not create
# one: a leftover from an older init, or a file someone dropped in by hand,
# must not be able to win over the admin key. Cases that need the realistic
# post-#85 layout pass bootstrap_key => 0.
sub project {
    my (%args) = @_;

    my $provider  = $args{provider} // 'hetzner';
    my $secure    = exists $args{secure} ? $args{secure} : 1;
    my $bootstrap = exists $args{bootstrap_key} ? $args{bootstrap_key} : 1;

    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;

    my $addr = $provider eq 'ssh' ? "  host: 1.2.3.4\n" : "  public_ip: 1.2.3.4\n";
    $dir->child('ocp.yaml')->spew_utf8(<<"YAML");
name: keytest
control_planes:
  provider: $provider
$addr
YAML

    $dir->child('keys.yaml')->spew_utf8("keys: []\n") if $secure;

    if ($bootstrap) {
        $dir->child('.ocp', 'id_ed25519')->spew_utf8($BOOTSTRAP_PRIVATE);
        $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    }

    # `nodes` writes .ocp/status.yaml, which is where `ocp destroy` reads its
    # target list from. The default shape is the mixed cluster that makes the
    # teardown ordering matter: one PAID Hetzner server plus one pre-existing
    # ssh machine. 'hetzner-only' drops the second.
    if (my $nodes = $args{nodes}) {
        my $ssh_node = $nodes eq 'hetzner-only' ? '' : <<'YAML';
  - name: worker-1
    provider: ssh
    public_ip: 5.6.7.8
YAML
        $dir->child('.ocp', 'status.yaml')->spew_utf8(<<"YAML");
nodes:
  - name: police1
    provider: hetzner
    providerId: 4711
    public_ip: 1.2.3.4
$ssh_node
YAML
    }

    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# Stand in for the key store and the terminal. $PROMPTS counts PIN2 prompts,
# which is the measurement several claims below rest on.
sub with_key_store {
    my ($code, %opt) = @_;

    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { $PROMPTS++; 'test-pin-2' };
    local *OCP::Keys::get_admin_key       = sub { $opt{no_admin} ? undef : $ADMIN };
    local *OCP::Secrets::ensure_age_key   = sub { 1 };
    local $OCP::ClusterKey::INTERACTIVE   = exists $opt{interactive} ? $opt{interactive} : 1;

    $PROMPTS = 0;
    return $code->();
}

sub capture {
    my ($code) = @_;
    my $out = '';
    open my $fh, '>', \$out or die "capture: $!";
    my $old = select $fh;
    my @r = eval { $code->() };
    my $err = $@;
    select $old;
    close $fh;
    return ($out, $err, @r);
}

# ------------------------------------------------------- which key, and why

subtest 'secure mode + hetzner reaches the admin key, never .ocp/id_ed25519' => sub {
    my $config = project(provider => 'hetzner');

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) });
    });
    is $err, '', 'no error' or diag $out;

    is $key->origin, 'admin', 'the admin key was chosen';
    is $PROMPTS, 1, 'and it cost exactly one PIN2 prompt';

    isnt $key->path, $config->ssh_private_key_path,
        'the path is NOT .ocp/id_ed25519 — even though that file exists here';
    is $key->content, $ADMIN->{private},
        'what is in the file is the decrypted admin private key';

    ok -f $key->public_path, 'the public half sits next to it';
    is path($key->public_path)->slurp, $ADMIN->{public},
        'and is the admin public key — OCP::Rex points REX_PUBLIC_KEY at it';
    is $key->public_path, $key->path . '.pub',
        'at exactly the name OCP::Rex derives, key_file . ".pub"';

    ok $key->is_temporary, 'it knows it owns these files';
    like $out, qr/trust the admin/,
        'the operator is told why a password is suddenly wanted';
};

subtest 'the realistic post-#85 layout: no bootstrap key on disk at all' => sub {
    # This is what a secure Hetzner project actually looks like today. The
    # old code died here with "cannot read SSH key"; nothing should now.
    my $config = project(provider => 'hetzner', bootstrap_key => 0);
    ok !-f $config->ssh_private_key_path, 'no .ocp/id_ed25519, as ocp init leaves it';

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) });
    });
    is $err, '', 'the missing bootstrap key is no longer an obstacle' or diag $out;
    is $key->origin, 'admin', 'because that path does not want it';
};

subtest 'secure mode + provider ssh reaches the admin key as well' => sub {
    # The reversal. A pre-existing machine used to be described as trusting
    # "what the operator put in authorized_keys", and that was read as "the
    # bootstrap key". What the operator puts there is now the ADMIN public
    # key — `ocp keys show --purpose admin` prints it, and `ocp init` prints
    # it too (t/69). Same key as Hetzner gets through the API, so the same
    # private key opens both.
    #
    # bootstrap_key defaults to on in project(), so this also asserts that a
    # leftover .ocp/id_ed25519 does NOT win. No silent fallback: a machine
    # that only has the old key must fail visibly, not quietly keep working
    # on a tier that was removed.
    my $config = project(provider => 'ssh');
    ok -f $config->ssh_private_key_path, 'a bootstrap key is lying around';

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) });
    });
    is $err, '', 'secure + ssh: no error' or diag $out;

    is $key->origin, 'admin', 'secure + ssh: the admin key, like every other provider';
    isnt $key->path, $config->ssh_private_key_path,
        'secure + ssh: not .ocp/id_ed25519, even though it is right there';
    is $key->content, $ADMIN->{private}, 'secure + ssh: the admin private half';
    is $PROMPTS, 1, 'secure + ssh: which costs one PIN2 prompt, as elsewhere';
};

subtest 'dev mode + provider ssh keeps the bootstrap key' => sub {
    my $config = project(provider => 'ssh', secure => 0);

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) });
    });
    is $err, '', 'dev + ssh: no error' or diag $out;

    is $key->origin, 'bootstrap', 'dev + ssh: the bootstrap key';
    is $key->path, $config->ssh_private_key_path,
        'dev + ssh: literally .ocp/id_ed25519';
    is $PROMPTS, 0, 'dev + ssh: and no PIN2 prompt';
    ok !$key->is_temporary, 'dev + ssh: nothing temporary to clean up';
    is $out, '', 'dev + ssh: nothing printed — this path is unchanged';
};

subtest 'dev mode uses the bootstrap key on every provider' => sub {
    # OCP::Cmd::Apply's --nopassword path builds a fake admin_key out of this
    # very file and uploads its public half where the admin key would go.
    # Gating on the provider instead of the mode would break that.
    for my $provider (qw(hetzner ssh local)) {
        my $config = project(provider => $provider, secure => 0);

        my ($out, $err, $key) = capture(sub {
            with_key_store(sub { OCP::ClusterKey->for_config($config) });
        });
        is $err, '', "dev + $provider: no error" or diag $out;
        is $key->origin, 'bootstrap', "dev + $provider: bootstrap key";
        is $key->path, $config->ssh_private_key_path, "dev + $provider: same path as before";
        is $PROMPTS, 0, "dev + $provider: no prompt — dev mode has no PIN at all";
    }
};

subtest 'the per-machine provider override no longer changes the key' => sub {
    # `ocp destroy` on a mixed cluster passes provider => 'ssh' for an ssh
    # worker under a Hetzner control plane. That used to switch the answer to
    # the bootstrap key. It does not any more — one cluster, one key — and the
    # override survives only to name the right provider in messages. Asserted
    # because a caller reading the old behaviour into this argument would
    # hand Rex a key the machine rejects.
    my $config = project(provider => 'hetzner');

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub {
            OCP::ClusterKey->for_config($config, provider => 'ssh');
        });
    });
    is $err, '', 'no error' or diag $out;
    is $key->origin, 'admin', 'still the admin key, override or not';
    like $out, qr/provider 'ssh'/, 'the override only picks the name in the message';

    # In dev mode the override is equally inert, from the other side.
    my $dev = project(provider => 'hetzner', secure => 0);
    my (undef, $dev_err, $dev_key) = capture(sub {
        with_key_store(sub {
            OCP::ClusterKey->for_config($dev, provider => 'ssh');
        });
    });
    is $dev_err, '', 'dev mode: no error';
    is $dev_key->origin, 'bootstrap', 'dev mode: the one key it has';
};

subtest 'a missing bootstrap key is named, not left to Rex to discover' => sub {
    my $config = project(provider => 'ssh', secure => 0, bootstrap_key => 0);

    my ($out, $err) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) });
    });
    like $err, qr/not found/, 'it dies';
    like $err, qr/id_ed25519/, 'naming the file it wanted';
    like $err, qr/ocp init/, 'and what creates it';
};

# ---------------------------------------------- the migration, as a diagnosis

subtest 'a leftover bootstrap key in secure mode produces a migration hint' => sub {
    # The cp-lab case: six machines whose authorized_keys carry the BOOTSTRAP
    # public key, because that is what OCP told the operator to install at the
    # time. After the decision, OCP offers only the admin key and those
    # machines refuse it. Nothing can detect that in advance, so the one thing
    # OCP owes the operator is a readable explanation at the point of failure.
    my $config = project(provider => 'ssh');

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) });
    });
    is $err, '', 'the key itself resolves fine' or diag $out;

    my $hint = $key->migration_hint;
    ok $hint, 'there is a hint to give';
    like $hint, qr/\Q${\ $config->ssh_private_key_path }\E/,
        'it names the leftover key it saw';
    like $hint, qr/ocp keys show --purpose admin/, 'and the command to run';
    like $hint, qr/authorized_keys/, 'and where the output goes';
    like $hint, qr/not before it|advance|sooner/,
        'and says plainly that nothing could have warned earlier';

    # The refusal to paper over it, stated as a test: the hint has to say
    # there is no fallback, because an operator staring at a locked-out
    # cluster will look for one.
    like $hint, qr/Nothing here falls back to the bootstrap key/,
        'it rules a fallback out in as many words';
};

subtest 'no hint where there is nothing to migrate' => sub {
    # A project with no bootstrap key on disk was never authorised with one.
    my $clean = project(provider => 'hetzner', bootstrap_key => 0);
    my (undef, undef, $key) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($clean) });
    });
    is $key->migration_hint, '', 'secure + no leftover: silent';

    # And dev mode is not a migration at all: the bootstrap key is current
    # there, not legacy.
    my $dev = project(provider => 'ssh', secure => 0);
    my (undef, undef, $dev_key) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($dev) });
    });
    is $dev_key->migration_hint, '', 'dev mode: silent';
};

subtest 'a wrong PIN2 is an error, not an empty key' => sub {
    my $config = project(provider => 'hetzner');

    my ($out, $err) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) }, no_admin => 1);
    });
    like $err, qr/Wrong PIN2 or no admin-key/, 'said plainly';
};

# ----------------------------------------------- the temp file does not stay

subtest 'the temp key pair goes away when the key object does' => sub {
    my $config = project(provider => 'hetzner');

    my ($priv, $pub);
    {
        my ($out, $err, $key) = capture(sub {
            with_key_store(sub { OCP::ClusterKey->for_config($config) });
        });
        ($priv, $pub) = ($key->path, $key->public_path);
        ok -f $priv, 'private key file exists while the object is alive';
        ok -f $pub,  'so does the public half';
    }

    ok !-e $priv, 'private key file is gone once the object leaves scope';
    ok !-e $pub,  'and so is the public half — the old code leaked this one';
};

subtest 'a die between acquire and use still cleans up' => sub {
    # The case that matters: an SSH failure, a Rex task blowing up, a wrong
    # kubeconfig. Whatever unwinds the stack must not leave a readable
    # private key behind in /tmp.
    my $config = project(provider => 'hetzner');

    my ($priv, $pub);
    my $err = do {
        local $@;
        eval {
            my ($out, $e, $key) = capture(sub {
                with_key_store(sub { OCP::ClusterKey->for_config($config) });
            });
            ($priv, $pub) = ($key->path, $key->public_path);
            die "the step that used the key failed\n";
        };
        $@;
    };

    like $err, qr/the step that used the key failed/, 'the failure propagated';
    ok $priv && !-e $priv, 'and the private key file did not survive it';
    ok $pub  && !-e $pub,  'nor the public half';
};

subtest 'cleanup is explicit as well as automatic, and idempotent' => sub {
    my $config = project(provider => 'hetzner');

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) });
    });
    my $priv = $key->path;

    $key->cleanup;
    ok !-e $priv, 'cleanup removed the file';

    my $again = eval { $key->cleanup; 1 };
    ok $again, 'calling it twice is not an error';
};

subtest 'the bootstrap key is never deleted by cleanup' => sub {
    # It belongs to the project, not to us. Deleting it would lock the
    # operator out of every machine that has its public half authorised.
    my $config = project(provider => 'ssh');

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) });
    });
    $key->cleanup;
    undef $key;

    ok -f $config->ssh_private_key_path,
        '.ocp/id_ed25519 is still there afterwards';
    is path($config->ssh_private_key_path)->slurp, $BOOTSTRAP_PRIVATE,
        'byte for byte';
};

# -------------------------------------------------- nobody at the keyboard

subtest 'no terminal means a named failure, never a silent wait' => sub {
    # `ocp apply` from cron, or anything with STDIN on a pipe. Term::ReadKey
    # would sit there with echo off and no visible prompt.
    my $config = project(provider => 'hetzner');

    my ($out, $err) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) }, interactive => 0);
    });

    like $err, qr/PIN2/, 'it says which secret it wanted';
    like $err, qr/no terminal/, 'and why it could not ask';
    is $PROMPTS, 0, 'crucially, it never called the prompt at all';
};

subtest 'a supplied PIN2 works without a terminal' => sub {
    my $config = project(provider => 'hetzner');

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub {
            OCP::ClusterKey->for_config($config, pin2 => 'given');
        }, interactive => 0);
    });
    is $err, '', 'no error' or diag $out;
    is $key->origin, 'admin', 'the admin key came out';
    is $PROMPTS, 0, 'without prompting';
};

subtest 'an already-unlocked admin key skips the prompt entirely' => sub {
    # `ocp apply` asks for PIN2 once at the top, because it also has to
    # upload the public half before the server exists. Asking again inside
    # bootstrap_control_plane would be a second prompt for the same secret.
    my $config = project(provider => 'hetzner');

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub {
            OCP::ClusterKey->for_config($config, admin_key => $ADMIN);
        }, interactive => 0);
    });
    is $err, '', 'no error' or diag $out;
    is $key->origin, 'admin', 'still the admin key';
    is $key->content, $ADMIN->{private}, 'the one that was handed in';
    is $PROMPTS, 0, 'and no prompt, in either mode of interactivity';
};

# ---------------------------------------------------------------- ocp update

{
    package FakeOcp;
    sub new     { my ($class, %args) = @_; bless {%args}, $class }
    sub verbose { 0 }
    # `ocp destroy` reads the ocp.yaml path off the root command object.
    sub config  { $_[0]{config} }
}

# Stands in for both real providers. Records what was deleted and with which
# key, and slurps the key material at CALL time: a temp admin key does not
# outlive the command object that owns it, so reading it afterwards would
# always find nothing.
{
    package FakeProvider;
    sub new { my ($class, %args) = @_; bless {%args}, $class }
    sub list_servers_by_cluster { [] }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        push @{ $self->{deleted} }, {
            type     => $self->{type},
            id       => $id,
            host     => $opts{host},
            key      => $self->{key},
            material => ($self->{key} && -f $self->{key}
                            ? Path::Tiny::path($self->{key})->slurp : undef),
        };
        return { stdout => '', stderr => '', exit => 0 };
    }
}

# Run a coderef with OCP::Rex captured. Returns the recorded calls.
sub with_rex {
    my ($code) = @_;
    my @calls;
    no warnings 'redefine';
    local *OCP::Rex::new = sub { my ($c, %a) = @_; bless {%a}, $c };
    local *OCP::Rex::run_task = sub {
        my ($self, $task, %p) = @_;
        # Slurp at call time, not afterwards: a temp admin key is unlinked
        # the moment the command object that owns it goes away, which is
        # itself something these tests assert.
        push @calls, {
            key      => $self->{key_file},
            material => (-f $self->{key_file} ? path($self->{key_file})->slurp : undef),
            host     => $self->{host},
            task     => $task,
            %p,
        };
        return 1;
    };
    $code->();
    return \@calls;
}

subtest 'ocp update on secure + hetzner drives Rex with the admin key' => sub {
    my $config = project(provider => 'hetzner');
    my $update = OCP::Cmd::Update->new(command_chain => [ FakeOcp->new ]);

    my ($out, $err, $calls) = capture(sub {
        with_key_store(sub {
            with_rex(sub {
                $update->_update_cilium($config, '1.19.2');
                $update->_update_via_rex($config, 'cert_manager', '1.16.0',
                    'upgrade_cert_manager');
            });
        });
    });
    is $err, '', 'both updates ran' or diag $out;

    is scalar @$calls, 2, 'two Rex tasks';
    isnt $calls->[0]{key}, $config->ssh_private_key_path,
        'cilium did not use .ocp/id_ed25519';
    is $calls->[0]{material}, $ADMIN->{private},
        'it used the admin key';
    is $calls->[1]{key}, $calls->[0]{key},
        'and the second component used the very same file';

    is $PROMPTS, 1,
        'one PIN2 for the whole update, not one per component';

    is $calls->[0]{host}, '1.2.3.4', 'against the control plane';
};

subtest 'ocp update on secure + ssh now takes the admin key too' => sub {
    my $config = project(provider => 'ssh');
    my $update = OCP::Cmd::Update->new(command_chain => [ FakeOcp->new ]);

    my ($out, $err, $calls) = capture(sub {
        with_key_store(sub {
            with_rex(sub { $update->_update_cilium($config, '1.19.2') });
        });
    });
    is $err, '', 'secure + ssh: ran' or diag $out;
    isnt $calls->[0]{key}, $config->ssh_private_key_path,
        'secure + ssh: not .ocp/id_ed25519 any more';
    is $calls->[0]{material}, $ADMIN->{private}, 'secure + ssh: the admin key';
    is $PROMPTS, 1, 'secure + ssh: which is why it now prompts once';
};

subtest 'ocp update in dev mode is unchanged' => sub {
    for my $provider (qw(hetzner ssh)) {
        my $config = project(provider => $provider, secure => 0);
        my $update = OCP::Cmd::Update->new(command_chain => [ FakeOcp->new ]);

        my ($out, $err, $calls) = capture(sub {
            with_key_store(sub {
                with_rex(sub { $update->_update_cilium($config, '1.19.2') });
            });
        });
        is $err, '', "dev + $provider: ran" or diag $out;
        is $calls->[0]{key}, $config->ssh_private_key_path,
            "dev + $provider: still .ocp/id_ed25519";
        is $PROMPTS, 0, "dev + $provider: still no PIN2 prompt";
    }
};

subtest 'the update temp key is gone when the command object is' => sub {
    my $config = project(provider => 'hetzner');

    my $used;
    {
        my $update = OCP::Cmd::Update->new(command_chain => [ FakeOcp->new ]);
        my ($out, $err, $calls) = capture(sub {
            with_key_store(sub {
                with_rex(sub { $update->_update_cilium($config, '1.19.2') });
            });
        });
        $used = $calls->[0]{key};
        ok -f $used, 'the key file was real while the command ran';
    }
    ok !-e $used, 'and does not outlive the command';
    ok !-e "$used.pub", 'public half neither';
};

# -------------------------------------------------------------- ocp node add

{
    package FakeNodeApi;
    sub new  { bless {}, shift }
    sub get  { die "404\n" }        # no OCPNodeProvider: not what is under test
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }
}

# Declared rather than conjured by the local *GLOB = sub assignments below,
# so `perl -w` does not read them as typos.
{
    package FakeNode;
    sub reconcile_until_ready { 1 }
}
{
    package FakeDrift;
    sub detect { [] }
}

# _cli_reconcile reads the join token off the control plane over SSH, then
# hands the same key material to OCP::Node for the machine being added.
#
# `ready` drives what OCP::Node reports back. It defaults to success, which is
# what the key-selection subtests below want; the migration subtests set it to
# 0, because the diagnosis only exists for the machine that did not answer.
# STDERR is captured separately from the selected handle `capture` swaps: the
# hint belongs next to the failure line `ocp node add` prints, which is there.
sub node_add_key {
    my ($config, %opt) = @_;

    my $ready = exists $opt{ready} ? $opt{ready} : 1;

    my (%seen);
    my $add = OCP::Cmd::Node::Add->new(
        command_chain => [ FakeOcp->new ],
        name          => 'worker-1',
    );

    no warnings 'redefine';
    local *OCP::SSH::new = sub {
        my ($c, %a) = @_;
        $seen{ssh_key_file} = $a{key_file};
        # Read it here: a temp admin key does not outlive the command object.
        $seen{ssh_key_material} = -f $a{key_file} ? path($a{key_file})->slurp : undef;
        bless {}, $c;
    };
    local *OCP::SSH::run = sub { { stdout => "K10::token\n" } };
    local *OCP::Node::from_cr = sub {
        my ($c, $cr, %a) = @_;
        $seen{node_ssh_key} = $a{ssh_key};
        bless {}, 'FakeNode';
    };
    local *FakeNode::reconcile_until_ready = sub { $ready };

    my $cr = {
        metadata => { name => 'worker-1', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'hetzner-a' },
    };

    my $stderr = '';
    open my $errfh, '>', \$stderr or die "stderr capture: $!";

    my ($out, $err, $rv);
    {
        local *STDERR = $errfh;
        ($out, $err, $rv) = capture(sub {
            with_key_store(sub {
                $add->_cli_reconcile($cr, FakeNodeApi->new, $config, undef);
            });
        });
    }
    close $errfh;

    return { %seen, out => $out, err => $err, stderr => $stderr, rv => $rv };
}

subtest 'ocp node add on secure + hetzner uses the admin key for both halves' => sub {
    my $config = project(provider => 'hetzner');
    my $r = node_add_key($config);
    is $r->{err}, '', 'the CLI reconcile path ran' or diag $r->{out};

    isnt $r->{ssh_key_file}, $config->ssh_private_key_path,
        'the control-plane SSH did not use .ocp/id_ed25519';
    is $r->{ssh_key_material}, $ADMIN->{private},
        'it used the admin key to read the join token';
    is $r->{node_ssh_key}, $ADMIN->{private},
        'and handed OCP::Node the same key material for the new machine';
    is $PROMPTS, 1, 'one prompt for both uses';
};

subtest 'ocp node add on secure + ssh uses the admin key for both halves' => sub {
    my $config = project(provider => 'ssh');
    my $r = node_add_key($config);
    is $r->{err}, '', 'ran' or diag $r->{out};

    isnt $r->{ssh_key_file}, $config->ssh_private_key_path,
        'not the bootstrap key any more';
    is $r->{ssh_key_material}, $ADMIN->{private}, 'the admin key reads the join token';
    is $r->{node_ssh_key}, $ADMIN->{private}, 'and goes on to the new machine';
    is $PROMPTS, 1, 'one prompt for both uses';
};

subtest 'ocp node add in dev mode is unchanged' => sub {
    my $config = project(provider => 'ssh', secure => 0);
    my $r = node_add_key($config);
    is $r->{err}, '', 'ran' or diag $r->{out};

    is $r->{ssh_key_file}, $config->ssh_private_key_path, 'still the bootstrap key';
    is $r->{node_ssh_key}, $BOOTSTRAP_PRIVATE, 'and its material goes to OCP::Node';
    is $PROMPTS, 0, 'no prompt';
};

# ------------------------------------ a worker that will not answer, explained
#
# The gap karr #97 names. ADR 0027 took the bootstrap key out of secure mode,
# so a machine authorised before that carries the bootstrap PUBLIC key and
# refuses the admin key OCP now offers. `ocp apply`, `ocp ssh`, `ocp destroy`
# and the join-token step of `ocp node add` all say so; the WORKER never did,
# because its connection happens inside OCP::Node.
#
# OCP::Node is trigger-neutral on purpose — robocop runs the same class in the
# cluster, where `ocp keys show` is not a command anyone can type — so the fix
# is that the CLI paths driving it report for themselves. These subtests are
# the claim that they do, and that they stay quiet for everyone the migration
# does not concern.

subtest 'a worker that never came up says why, where there is a why' => sub {
    my $config = project(provider => 'ssh');
    my $r = node_add_key($config, ready => 0);

    is $r->{err}, '', 'the reconcile ran to a verdict' or diag $r->{out};

    ok defined $r->{rv} && !$r->{rv},
        'and the verdict is still failure — a hint does not rescue a worker';

    like $r->{stderr}, qr/ocp keys show --purpose admin/,
        'the operator is told which command prints the key to install';
    like $r->{stderr}, qr/authorized_keys/, 'and where it goes on the machine';
    like $r->{stderr}, qr/\Q${\ $config->ssh_private_key_path }\E/,
        'having named the leftover key that is the evidence';
    like $r->{stderr}, qr/not before it|advance|sooner/,
        'and it does not pretend anything could have checked beforehand';
    like $r->{stderr}, qr/Nothing here falls back to the bootstrap key/,
        'diagnosis only: no fallback to the key those machines do trust';
};

subtest 'a worker failure with nothing to migrate stays a plain failure' => sub {
    # The other half, and the reason this is gated at all: for every project
    # the migration does not concern, the paragraph is noise. No bootstrap key
    # on disk means this cluster was never authorised with one.
    my $config = project(provider => 'hetzner', bootstrap_key => 0);
    my $r = node_add_key($config, ready => 0);

    is $r->{err}, '', 'ran' or diag $r->{out};
    ok defined $r->{rv} && !$r->{rv}, 'still a failure';
    is $r->{stderr}, '', 'and nothing is said about a migration that does not apply';
};

subtest 'a worker that came up is told nothing at all' => sub {
    # Even in the project that has every ingredient for the hint. Success is
    # proof the machine accepted the key, which is the opposite of the claim.
    my $config = project(provider => 'ssh');
    my $r = node_add_key($config, ready => 1);

    ok $r->{rv}, 'the worker reached Ready';
    is $r->{stderr}, '', 'so there is nothing to diagnose';
};

subtest 'dev mode has no migration to report' => sub {
    # The bootstrap key is dev mode's current key, not a leftover.
    my $config = project(provider => 'ssh', secure => 0);
    my $r = node_add_key($config, ready => 0);

    ok defined $r->{rv} && !$r->{rv}, 'the worker failed';
    is $r->{stderr}, '', 'and no migration is invented for it';
};

# ------------------------------------------ the workers `ocp apply` brings up
#
# The other CLI caller of OCP::Node, and the harder one: it is handed only
# $deps->{ssh_key_path}, and a path cannot answer "was this the admin key".
# The OCP::ClusterKey itself comes off the command object, where
# OCP::Cmd::Apply::Bootstrap::setup_ssh_key parks it — the same cache that
# keeps `ocp update` down to one PIN2 prompt. These subtests drive that route,
# not a shortcut around it.

{
    package FakeApplyApi;
    sub new  { bless {}, shift }
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }

    sub get {
        my ($self, $kind, $name, %a) = @_;
        return {
            metadata => { name => $name, namespace => 'ocp-system' },
            spec     => { role => 'worker', providerRef => 'ssh-default' },
            status   => {},
        } if $kind eq 'OCPNode';
        return {
            metadata => { name => 'ssh-default', namespace => 'ocp-system' },
            spec     => { type => 'ssh' },
        } if $kind eq 'OCPNodeProvider';
        return undef;
    }
}

{
    package FakeWorkerProvider;
}
{
    package FakeWorkerNode;
    sub phase { 'Failed' }
    sub reconcile_until_ready { 0 }
}

# One CLI-fallback worker rollout, as OCP::Cmd::Apply::Deploy drives it.
# `warm` decides whether bootstrap already picked the cluster key and left it
# on the command object, which is what production always does.
sub apply_workers {
    my ($config, %opt) = @_;

    my $names = $opt{names} // ['worker-1'];
    my $ready = $opt{ready} // 0;
    my $warm  = exists $opt{warm} ? $opt{warm} : 1;

    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);

    no warnings 'redefine';
    local *OCP::SSH::new          = sub { bless {}, $_[0] };
    local *OCP::SSH::run          = sub { { stdout => "K10::token\n" } };
    local *OCP::Provider::from_cr = sub { bless {}, 'FakeWorkerProvider' };
    local *OCP::Node::from_cr     = sub { bless {}, 'FakeWorkerNode' };
    local *FakeWorkerNode::reconcile_until_ready = sub { $ready };

    my ($out, $err, @results) = capture(sub {
        with_key_store(sub {
            # The production route to the key: bootstrap picks it, parks it on
            # the command object and passes the PATH on to the deploy step.
            my $path = $warm
                ? OCP::Cmd::Apply::Bootstrap::setup_ssh_key($apply, $config)->path
                : $config->ssh_private_key_path;

            OCP::Cmd::Apply::CR::cli_reconcile_workers(
                $apply, FakeApplyApi->new, $config, $names,
                { ssh_key_path => $path, cp_ip => '1.2.3.4' },
            );
        });
    });

    return { out => $out, err => $err, results => \@results };
}

# How often the diagnosis appears in a run's output.
sub hint_count {
    my ($text) = @_;
    my $n = () = $text =~ /ocp keys show --purpose admin/g;
    return $n;
}

subtest 'ocp apply explains a worker that would not take the admin key' => sub {
    my $config = project(provider => 'ssh');
    my $r = apply_workers($config);

    is $r->{err}, '', 'the rollout ran' or diag $r->{out};

    is scalar @{$r->{results}}, 1, 'one worker was reported on';
    is $r->{results}[0]{phase}, 'Failed',
        'and it is still Failed — the hint changes nothing about the outcome';

    is hint_count($r->{out}), 1, 'the diagnosis was given';
    like $r->{out}, qr/authorized_keys/, 'naming where the key goes';
    like $r->{out}, qr/Nothing here falls back to the bootstrap key/,
        'and refusing the fallback in as many words';
};

subtest 'five unreachable workers are five failures, not five essays' => sub {
    my $config = project(provider => 'ssh');
    my $r = apply_workers($config, names => [map { "worker-$_" } 1 .. 5]);

    is $r->{err}, '', 'ran' or diag $r->{out};
    is scalar @{$r->{results}}, 5, 'all five were attempted';
    is scalar(grep { $_->{phase} eq 'Failed' } @{$r->{results}}), 5,
        'all five failed, each on its own row';
    is hint_count($r->{out}), 1, 'and the explanation appears exactly once';
};

subtest 'ocp apply says nothing where there is nothing to migrate' => sub {
    my $config = project(provider => 'hetzner', bootstrap_key => 0);
    my $r = apply_workers($config);

    is $r->{err}, '', 'ran' or diag $r->{out};
    is $r->{results}[0]{phase}, 'Failed', 'the worker still failed';
    is hint_count($r->{out}), 0,
        'without a leftover bootstrap key there is no claim to make';
};

subtest 'workers that came up get no diagnosis' => sub {
    my $config = project(provider => 'ssh');
    my $r = apply_workers($config, names => ['w1', 'w2'], ready => 1);

    is $r->{err}, '', 'ran' or diag $r->{out};
    is scalar(grep { $_->{phase} eq 'Ready' } @{$r->{results}}), 2, 'both Ready';
    is hint_count($r->{out}), 0, 'and nothing was explained';
};

subtest 'the diagnosis never builds a key, so it never prompts' => sub {
    # The structural half of the fix. cli_reconcile_workers reaches for the key
    # the command ALREADY has; asking OCP::ClusterKey to build one would stop a
    # worker rollout on a PIN2 prompt purely to decide whether to print a
    # paragraph. Cold cache: the hint is lost, the run is not interrupted.
    my $config = project(provider => 'ssh');
    my $r = apply_workers($config, warm => 0);

    is $r->{err}, '', 'ran' or diag $r->{out};
    is $r->{results}[0]{phase}, 'Failed', 'the worker still failed';
    is $PROMPTS, 0, 'and nothing asked for PIN2 on the way to a message';
    is hint_count($r->{out}), 0, 'no key on the command object, no guess';
};

# --------------------------------------------------- the reconcile-path remedy

my $CILIUM_DRIFT = {
    kind      => 'version',
    component => 'cilium',
    label     => 'Cilium',
    expected  => '1.19.2',
    actual    => '1.18.0',
    message   => 'Cilium runs 1.18.0, expected 1.19.2',
    remedy    => { type => 'rex', task => 'upgrade_cilium',
                   params => { version => '1.19.2' } },
};

subtest 'the reconcile remedy reaches the admin key on secure + hetzner' => sub {
    # This is the path that could never repair anything there: it read
    # .ocp/id_ed25519, found nothing, and declined every single time.
    my $config = project(provider => 'hetzner', bootstrap_key => 0);
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);

    my ($out, $err, $calls) = capture(sub {
        with_key_store(sub {
            with_rex(sub { $apply->_run_remedy($config, $CILIUM_DRIFT) });
        });
    });
    is $err, '', 'no error' or diag $out;

    is scalar @$calls, 1, 'the Rex task ran';
    is $calls->[0]{task}, 'upgrade_cilium', 'the one the remedy named';
    is $calls->[0]{material}, $ADMIN->{private}, 'with the admin key';
    is $PROMPTS, 1, 'having asked for PIN2 once, at the point of use';
};

subtest 'no terminal: the remedy declines out loud instead of hanging' => sub {
    my $config = project(provider => 'hetzner', bootstrap_key => 0);
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);

    my $ran;
    my ($out, $err) = capture(sub {
        with_key_store(sub {
            with_rex(sub { $ran = $apply->_run_remedy($config, $CILIUM_DRIFT) });
        }, interactive => 0);
    });

    is $err, '', 'it did not die — one bad entry must not end the reconcile';
    ok defined $ran && !$ran, 'and it reports that it did not run';
    is $PROMPTS, 0, 'nothing waited on a password nobody could see';

    like $out, qr/NOT run/, 'the output says the task did not run';
    like $out, qr/Cilium/, 'names what is therefore still drifted';
    like $out, qr/ocp update --component cilium/,
        'and points at the interactive command that can do it';
};

subtest 'a run with nothing to repair never asks for anything' => sub {
    # The price of the late lookup, stated as a test: `ocp apply` against a
    # healthy cluster must stay exactly as promptless as it was before #87.
    my $config = project(provider => 'hetzner');
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);

    my ($out, $err, $ran) = capture(sub {
        with_key_store(sub {
            $apply->_run_remedy($config, { component => 'rke2', remedy => undef });
        });
    });
    ok !$ran, 'an entry without a remedy does nothing';
    is $PROMPTS, 0, 'and asks for nothing';
    is $out, '', 'silently, as before';
};

# ----------------------------------------------------------------- ocp ssh
#
# karr #94 was the mirror image of #87: `ocp ssh` demanded PIN2 and used the
# admin key unconditionally, which was wrong for `provider: ssh` machines
# because they trusted the bootstrap key. The two-tier decision dissolves the
# ticket by making the premise false — those machines trust the admin key now
# — but the command still has to go through OCP::ClusterKey rather than
# hand-rolling the unlock, because the OTHER half of #94 was real: in a
# --nopassword project there is no keys.yaml, so the PIN2 prompt could only
# ever end in "Wrong PIN2 or no admin-key found".

# Run OCP::Cmd::SSH::execute with the exec at the end stubbed out.
sub run_ocp_ssh {
    my ($config, %opt) = @_;

    $config->project_dir->child('kubeconfig.yaml')->spew_utf8("apiVersion: v1\n");

    my %seen;
    my $cmd = OCP::Cmd::SSH->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        node          => $opt{node} // '9.9.9.9',
    );

    my ($out, $err) = capture(sub {
        with_key_store(sub {
            no warnings 'redefine';
            local *OCP::SSH::new = sub {
                my ($class, %args) = @_;
                $seen{host} = $args{host};
                $seen{key}  = $args{key_file};
                $seen{material} = (-f $args{key_file}
                    ? path($args{key_file})->slurp : undef);
                bless {}, $class;
            };
            local *OCP::SSH::is_reachable = sub { $opt{reachable} // 1 };
            local *OCP::SSH::interactive  = sub { $seen{connected} = 1 };
            $cmd->execute([], []);
        }, %opt);
    });

    return { %seen, out => $out, err => $err };
}

subtest 'ocp ssh on a secure ssh-provider cluster uses the admin key' => sub {
    # The #94 resolution: PIN2 here is no longer theatre, because the machine
    # really does trust that key.
    my $config = project(provider => 'ssh');

    my $r = run_ocp_ssh($config);
    is $r->{err}, '', 'it connected' or diag $r->{out};
    ok $r->{connected}, 'the interactive session was handed over';

    isnt $r->{key}, $config->ssh_private_key_path, 'not the bootstrap key';
    is $r->{material}, $ADMIN->{private}, 'the admin key';
    is $PROMPTS, 1, 'one PIN2 prompt, which is the point of this command';
};

subtest 'ocp ssh in dev mode connects without asking for a PIN2 it has no use for' => sub {
    # This used to prompt for PIN2 in a project with no keys.yaml at all and
    # then die on its own prompt.
    my $config = project(provider => 'ssh', secure => 0);

    my $r = run_ocp_ssh($config);
    is $r->{err}, '', 'it connected' or diag $r->{out};
    is $r->{key}, $config->ssh_private_key_path, 'with .ocp/id_ed25519';
    is $PROMPTS, 0, 'and asked for nothing';
};

subtest 'ocp ssh diagnoses a refused admin key instead of just exec-ing' => sub {
    # ->interactive execs, so nothing after it can report anything. Where a
    # leftover bootstrap key makes a lockout plausible, the command probes
    # first and explains — then hands over anyway rather than blocking.
    my $config = project(provider => 'ssh');

    my $r = run_ocp_ssh($config, reachable => 0);
    is $r->{err}, '', 'it did not refuse to run' or diag $r->{out};
    ok $r->{connected}, 'ssh still got the terminal';

    like $r->{out}, qr/did not accept the admin key/, 'it says what happened';
    like $r->{out}, qr/ocp keys show --purpose admin/, 'and what to do about it';
};

# ------------------------------------------------------------- ocp destroy
#
# The dangerous one. Destroy's ssh branch used to read the bootstrap key
# straight off disk — a lookup that could not fail. It now needs the admin
# key, which means PIN2, which means it CAN fail: wrong PIN, no terminal, no
# keys.yaml. The loop it sits in deletes paid Hetzner servers.
#
# So the rule these tests hold: a key that cannot be obtained costs the
# uninstall script on the ssh machines and NOTHING else. Every Hetzner server
# still goes through the API, which needs no SSH at all.

# Run OCP::Cmd::Destroy::execute against a project, with both providers
# faked. Returns what was deleted, through which provider, with which key.
sub run_destroy {
    my ($config, %opt) = @_;

    my @deleted;
    my $destroy = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        force         => 1,       # no confirmation prompt in a test
    );

    my ($out, $err) = capture(sub {
        with_key_store(sub {
            no warnings 'redefine';
            local *OCP::Secrets::hetzner_token = sub { 'test-token' };
            local *OCP::Provider::for_spec = sub {
                my ($class, $spec, %args) = @_;
                return FakeProvider->new(
                    type    => $spec->{provider},
                    key     => $args{ssh_key_path},
                    deleted => \@deleted,
                );
            };
            $destroy->execute([], []);
        }, %opt);
    });

    return { out => $out, err => $err, deleted => \@deleted };
}

subtest 'destroy on secure + mixed cluster uses the admin key for ssh nodes' => sub {
    my $config = project(provider => 'hetzner', nodes => 1);

    my $r = run_destroy($config);
    is $r->{err}, '', 'the teardown ran' or diag $r->{out};

    my ($hetzner) = grep { $_->{type} eq 'hetzner' } @{ $r->{deleted} };
    my ($ssh)     = grep { $_->{type} eq 'ssh' }     @{ $r->{deleted} };

    ok $hetzner, 'the Hetzner server was deleted';
    is $hetzner->{id}, 4711, 'by provider id, through the API';
    is $hetzner->{key}, undef, 'with no SSH key involved at all';

    ok $ssh, 'the ssh machine was uninstalled';
    isnt $ssh->{key}, $config->ssh_private_key_path,
        'not with .ocp/id_ed25519';
    is $ssh->{material}, $ADMIN->{private},
        'but with the admin key, like every other command';
    is $PROMPTS, 1, 'one PIN2 prompt for the whole teardown';
};

subtest 'a key that cannot be obtained never costs a Hetzner server' => sub {
    # The failure this whole arrangement exists for. no_admin makes the
    # lookup die exactly where a wrong PIN2 would.
    my $config = project(provider => 'hetzner', nodes => 1);

    my $r = run_destroy($config, no_admin => 1);
    is $r->{err}, '', 'the teardown did NOT abort' or diag $r->{out};

    my ($hetzner) = grep { $_->{type} eq 'hetzner' } @{ $r->{deleted} };
    ok $hetzner, 'the paid server was still deleted';
    is $hetzner->{id}, 4711, 'the one recorded in status.yaml';

    ok !(grep { $_->{type} eq 'ssh' } @{ $r->{deleted} }),
        'the ssh uninstall was skipped, since there was no key to do it with';

    like $r->{out}, qr/Could not obtain the SSH key/,
        'the operator is told what failed';
    like $r->{out}, qr/deleted through the provider API/,
        'and that nothing chargeable was left behind';
    like $r->{out}, qr/rke2-uninstall\.sh/,
        'with the manual step named for the machines that kept their install';
};

subtest 'no terminal is the same story, not a hang and not an abort' => sub {
    # `ocp destroy --force` from a script: PIN2 cannot be asked for at all.
    my $config = project(provider => 'hetzner', nodes => 1);

    my $r = run_destroy($config, interactive => 0);
    is $r->{err}, '', 'still no abort' or diag $r->{out};
    is $PROMPTS, 0, 'and nothing waited on an invisible password';

    ok scalar(grep { $_->{type} eq 'hetzner' } @{ $r->{deleted} }),
        'the server is gone';
    ok !(grep { $_->{type} eq 'ssh' } @{ $r->{deleted} }),
        'the uninstall is not';
};

subtest 'a Hetzner-only teardown asks for nothing' => sub {
    # The cost of moving the lookup out of the loop would be a PIN2 prompt on
    # every destroy. It is gated on there actually being an ssh node.
    my $config = project(provider => 'hetzner', nodes => 'hetzner-only');

    my $r = run_destroy($config);
    is $r->{err}, '', 'ran' or diag $r->{out};
    is $PROMPTS, 0, 'no PIN2 prompt where no SSH connection is made';
    unlike $r->{out}, qr/Could not obtain the SSH key/,
        'and no warning about a key nobody wanted';
    ok scalar(grep { $_->{type} eq 'hetzner' } @{ $r->{deleted} }), 'server deleted';
};

subtest 'destroy in dev mode is unchanged' => sub {
    my $config = project(provider => 'hetzner', secure => 0, nodes => 1);

    my $r = run_destroy($config);
    is $r->{err}, '', 'ran' or diag $r->{out};
    is $PROMPTS, 0, 'no prompt';

    my ($ssh) = grep { $_->{type} eq 'ssh' } @{ $r->{deleted} };
    is $ssh->{key}, $config->ssh_private_key_path,
        'the ssh machine is still reached with .ocp/id_ed25519';
};

# ------------------------------------------------- `ocp status` stays read-only

subtest 'the read-only paths cannot acquire a key, so they cannot prompt' => sub {
    # `ocp status` and OCP::Drift answer entirely from the Kubernetes API.
    # #87 must not have given either of them a reason to want a password:
    # a read command that prompts is a read command that gets avoided.
    for my $file (qw(lib/OCP/Cmd/Status.pm lib/OCP/Drift.pm)) {
        my $source = path($file)->slurp;
        unlike $source, qr/cluster_ssh_key|ClusterKey|ssh_private_key_path/,
            "$file asks for no SSH key";
        unlike $source, qr/OCP::Rex|OCP::SSH|prompt_password/,
            "$file opens no SSH connection and prompts for nothing";
    }

    # And the dry run stops before the only step on the reconcile path that
    # could want one.
    my $drift = path('lib/OCP/Cmd/Apply/Drift.pm')->slurp;
    my ($reconcile) = $drift =~ /sub reconcile_components \{(.*?)\n\}/ms;
    ok $reconcile, 'found reconcile_components';
    like $reconcile, qr/return dry_run_report.*if \$self->dry_run/,
        'the dry run returns before the remedy loop';

    my ($dry) = $drift =~ /sub dry_run_report \{(.*?)\n\}/ms;
    unlike $dry, qr/run_remedy|cluster_ssh_key/,
        'and reports without ever asking for a key';
};

# --------------------------------------- an unrepaired finding is not silence

subtest 'a declined remedy is not summarised as "up to date"' => sub {
    # The #43/#46 failure mode, in the place #87 makes reachable: drift is
    # detected, the repair cannot run, and the closing line speaks for the
    # whole run anyway.
    my $config = project(provider => 'hetzner', bootstrap_key => 0);
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    $apply->{_k8s_api} = FakeNodeApi->new;

    my @writers = qw(
        _setup_registry _configure_registry_dns _setup_nfd _setup_gpu_operator
        _apply_cert_manager _wait_cert_manager_and_create_issuers
        _save_deployed_hash _setup_cilium_gateway _setup_lb_ipam _ensure_crds
        _ensure_providers _migrate_legacy_nodes _ensure_cp_ocpnode
        _load_deployed_hashes _resource_exists _report_component
    );

    my ($out, $err) = capture(sub {
        no strict 'refs';
        no warnings 'redefine';
        local *OCP::Cmd::Apply::_k8s_api = sub { $_[0]{_k8s_api} };
        local *OCP::Secrets::read_kubeconfig = sub { "apiVersion: v1\n" };
        local *OCP::Drift::new = sub { bless {}, 'FakeDrift' };
        local *FakeDrift::detect = sub { [ $CILIUM_DRIFT ] };
        # Every write the reconcile path owns is a no-op here; the claim is
        # about the closing verdict, not about the components.
        for my $w (@writers) {
            no warnings 'redefine';
            *{"OCP::Cmd::Apply::$w"} = sub { 0 };
        }
        OCP::Cmd::Apply::Drift::reconcile_components($apply, $config);
    });

    like $out, qr/\[drift\]/, 'the drift was reported';
    like $out, qr/NOT run/, 'and the failure to repair it was reported';

    unlike $out, qr/All \d+ component\(s\) up to date/,
        'the summary does NOT claim everything is fine';
    like $out, qr/did NOT bring the cluster back to spec/,
        'it says the opposite, in as many words';
    like $out, qr/left as they were: Cilium/,
        'naming what is still wrong';
};

done_testing;

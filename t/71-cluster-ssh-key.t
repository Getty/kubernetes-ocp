#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Node::Add;
use OCP::Cmd::Update;
use OCP::Config;

#
# karr #87: which private key reaches this cluster's machines?
#
# Four places answered "$config->ssh_private_key_path" — .ocp/id_ed25519 —
# without asking who created the machine:
#
#   OCP::Cmd::Update            (two Rex call sites)
#   OCP::Cmd::Node::Add         (join token off the CP, then the new worker)
#   OCP::Cmd::Apply::Drift      (run_remedy, the reconcile path's Rex task)
#   OCP::Cmd::Destroy           (the ssh branch — the one that was right)
#
# On a Hetzner machine that key was never distributed. OCP uploads the ADMIN
# public key through the provider API before the server exists, and since #85
# `ocp init` does not even create a bootstrap key for secure + hetzner. So
# every one of those paths reached for a file that is not there, on the one
# provider/mode combination where it mattered.
#
# What is asserted here is the choice itself, not the SSH that follows it:
# the admin key is reached for, the bootstrap key is left alone where it is
# still correct, the temp file holding a decrypted private key does not
# survive the run, and nothing waits on a password prompt that no one can see.
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

subtest 'provider ssh keeps the bootstrap key, in secure mode too' => sub {
    # #85 healed this path. #87 must not touch it: a pre-existing machine
    # trusts what the operator put in authorized_keys, which is this file.
    for my $secure (1, 0) {
        my $label = $secure ? 'secure' : 'dev';
        my $config = project(provider => 'ssh', secure => $secure);

        my ($out, $err, $key) = capture(sub {
            with_key_store(sub { OCP::ClusterKey->for_config($config) });
        });
        is $err, '', "$label + ssh: no error" or diag $out;

        is $key->origin, 'bootstrap', "$label + ssh: the bootstrap key";
        is $key->path, $config->ssh_private_key_path,
            "$label + ssh: literally .ocp/id_ed25519";
        is $PROMPTS, 0, "$label + ssh: and no PIN2 prompt";
        ok !$key->is_temporary, "$label + ssh: nothing temporary to clean up";
        is $out, '', "$label + ssh: nothing printed — this path is unchanged";
    }
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

subtest 'the provider can be overridden per machine, not per cluster' => sub {
    # `ocp destroy` on a mixed cluster: the control plane is Hetzner, but an
    # ssh worker is a pre-existing machine and trusts the bootstrap key.
    my $config = project(provider => 'hetzner');

    my ($out, $err, $key) = capture(sub {
        with_key_store(sub {
            OCP::ClusterKey->for_config($config, provider => 'ssh');
        });
    });
    is $err, '', 'no error' or diag $out;
    is $key->origin, 'bootstrap', 'the override decides, not control_planes[0]';
    is $PROMPTS, 0, 'and it costs nothing';
};

subtest 'a missing bootstrap key is named, not left to Rex to discover' => sub {
    my $config = project(provider => 'ssh', bootstrap_key => 0);

    my ($out, $err) = capture(sub {
        with_key_store(sub { OCP::ClusterKey->for_config($config) });
    });
    like $err, qr/not found/, 'it dies';
    like $err, qr/id_ed25519/, 'naming the file it wanted';
    like $err, qr/ocp init/, 'and what creates it';
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
    sub new     { bless {}, shift }
    sub verbose { 0 }
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

subtest 'ocp update on provider ssh and in dev mode is unchanged' => sub {
    for my $case (
        { provider => 'ssh',     secure => 1, label => 'secure + ssh' },
        { provider => 'hetzner', secure => 0, label => 'dev + hetzner' },
    ) {
        my $config = project(provider => $case->{provider}, secure => $case->{secure});
        my $update = OCP::Cmd::Update->new(command_chain => [ FakeOcp->new ]);

        my ($out, $err, $calls) = capture(sub {
            with_key_store(sub {
                with_rex(sub { $update->_update_cilium($config, '1.19.2') });
            });
        });
        is $err, '', "$case->{label}: ran" or diag $out;
        is $calls->[0]{key}, $config->ssh_private_key_path,
            "$case->{label}: still .ocp/id_ed25519";
        is $PROMPTS, 0, "$case->{label}: still no PIN2 prompt";
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
sub node_add_key {
    my ($config) = @_;

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
    local *FakeNode::reconcile_until_ready = sub { 1 };

    my $cr = {
        metadata => { name => 'worker-1', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'hetzner-a' },
    };

    my ($out, $err) = capture(sub {
        with_key_store(sub {
            $add->_cli_reconcile($cr, FakeNodeApi->new, $config, undef);
        });
    });

    return { %seen, out => $out, err => $err };
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

subtest 'ocp node add on provider ssh is unchanged' => sub {
    my $config = project(provider => 'ssh');
    my $r = node_add_key($config);
    is $r->{err}, '', 'ran' or diag $r->{out};

    is $r->{ssh_key_file}, $config->ssh_private_key_path, 'still the bootstrap key';
    is $r->{node_ssh_key}, $BOOTSTRAP_PRIVATE, 'and its material goes to OCP::Node';
    is $PROMPTS, 0, 'no prompt';
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

# ------------------------------------------------------------- ocp destroy

subtest 'ocp destroy still uses the bootstrap key, and only for ssh nodes' => sub {
    # #87 listed Destroy.pm as a fourth site. It is not one: the branch that
    # reads the key is guarded on the NODE's provider being ssh, and such a
    # machine is pre-existing whatever the control plane runs on. A Hetzner
    # node leaves through the API and never touches a key file.
    # Comments stripped: the claim is about what the branches DO. The comment
    # explaining why this file was left alone names ClusterKey, and matching
    # it would be matching the explanation rather than the code.
    my $source = join "\n",
        grep { !/^\s*#/ }
        split /\n/, path('lib/OCP/Cmd/Destroy.pm')->slurp;

    my $ssh_head     = quotemeta q{elsif ($node->{provider} eq 'ssh'};
    my $hetzner_head = quotemeta q{if ($node->{provider} eq 'hetzner'};

    my ($branch) = $source =~ /$ssh_head (.*?) ^\s{8}\}/msx;
    ok $branch, 'found the ssh teardown branch';
    like $branch, qr/ssh_private_key_path/,
        'it still reaches for the bootstrap key';
    unlike $branch, qr/cluster_ssh_key|ClusterKey/,
        'and deliberately not for the cluster-wide answer';

    my ($hetzner) = $source =~ /$hetzner_head (.*?) \Qelsif\E/msx;
    ok $hetzner, 'found the hetzner teardown branch';
    unlike $hetzner, qr/ssh_private_key_path|key_file|ClusterKey/,
        'which touches no SSH key at all — it deletes through the provider API';

    # The other half of why it must not become fatal: each delete is guarded
    # so a machine that is already gone does not abort the run and strand
    # paid servers.
    like $source, qr/eval \{ \$ssh_prov->delete_server/,
        'the ssh delete is still best-effort';
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

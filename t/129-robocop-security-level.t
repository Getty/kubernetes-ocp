#!/usr/bin/env perl
# karr k129 -- robocop.security_level: how the private robo (automation) SSH
# key AND the RKE2 join token are delivered into the cluster (Weg A: the token
# is read off the control-plane disk over SSH at deploy time and put in the
# Secret, because no K8s Secret holds it).
#
# Network-free and cluster-free: no socket ever opens. The K8s api is a fake
# that records every ensure() call; keys.yaml/secrets.yaml/age.key are real
# (built in a temp project dir) so the decrypt path is exercised for real. The
# PIN2 prompt is stubbed on OCP::Password::prompt_password, the SSH token read
# on OCP::SSH::run, and OCP::ClusterKey is put in interactive mode so the
# secure-mode admin-key unlock runs under prove without a tty.

use strict;
use warnings;
use Test::More;

use Path::Tiny ();

use lib 'lib';

use OCP;
use OCP::Config;
use OCP::Keys;
use OCP::Secrets;
use OCP::Password;
use OCP::SSH;
use OCP::ClusterKey;
use OCP::Cmd::DeployRobocop;

local @ARGV = ();
my $ocp = OCP->new;

# Opaque key material -- OCP::Keys encrypts/decrypts arbitrary strings, so the
# exact bytes coming back out is what the Secret must carry.
my $ROBO_PRIV  = "-----BEGIN OPENSSH PRIVATE KEY-----\nROBOAUTOMATIONKEY\n-----END OPENSSH PRIVATE KEY-----\n";
my $ADMIN_PRIV = "-----BEGIN OPENSSH PRIVATE KEY-----\nADMINHUMANKEY\n-----END OPENSSH PRIVATE KEY-----\n";
my $PIN2       = 'correct-horse';
my $TOKEN      = 'K10deadbeefcafe::server:0123456789abcdef';

# --- Fakes ----------------------------------------------------------------

# Records every ensure() call; hands the object straight back like the real one.
package FakeApi {
    sub new     { bless { ensured => [] }, shift }
    sub ensure  { push @{ $_[0]{ensured} }, $_[1]; return $_[1] }
    sub ensured { $_[0]{ensured} }
}

# Minimal OCP root: the command reaches ->ocp->config (path) and ->verbose.
package FakeOCP {
    sub new     { my ($c, %a) = @_; bless { %a }, $c }
    sub config  { $_[0]{config} }
    sub verbose { 0 }
}

package main;

# A secure-mode project: keys.yaml with a robo (automation) and an admin key,
# a real age key, and an ssh control plane so cluster_status resolves a host.
sub make_project {
    my (%opt) = @_;
    my $dir = Path::Tiny->tempdir;

    my $spec = { name => 'test' };
    $spec->{control_planes} = $opt{no_host}
        ? { provider => 'ssh' }
        : { provider => 'ssh', host => 'police1' };
    $spec->{kubernetes} = { dist => $opt{dist} } if defined $opt{dist};
    $spec->{robocop}    = { security_level => $opt{level} } if defined $opt{level};
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, $spec);

    my $secrets = OCP::Secrets->new(project_dir => $dir);
    $secrets->generate_age_key;

    my $keys = OCP::Keys->new(project_dir => $dir);
    $keys->add_key(
        name    => 'robo-ssh',
        type    => 'ssh_ed25519',
        private => $ROBO_PRIV,
        public  => 'ssh-ed25519 AAAArobo robo',
        purpose => 'automation',
    );
    $keys->add_key(
        name    => 'admin-ssh',
        type    => 'ssh_ed25519',
        private => $ADMIN_PRIV,
        public  => 'ssh-ed25519 AAAAadmin admin',
        purpose => 'admin',
        pin2    => $PIN2,
    );

    return $dir;
}

sub config_for {
    my ($dir) = @_;
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify, ocp => $ocp);
}

sub secret_of {
    my ($api) = @_;
    my ($secret) = grep { ($_->{kind} // '') eq 'Secret' } @{ $api->ensured };
    return $secret;
}

# ==========================================================================
# Config: the field, its default, and validation
# ==========================================================================

subtest 'security_level default is secret' => sub {
    my $dir = make_project();
    is config_for($dir)->robocop_security_level, 'secret',
        'no robocop mapping -> secret';

    my $dir2 = make_project(level => 'secret_approved');
    is config_for($dir2)->robocop_security_level, 'secret_approved',
        'mapping value is read back';
};

subtest 'all three levels are accepted' => sub {
    for my $lvl (qw(secret secret_approved inject)) {
        my $dir = make_project(level => $lvl);
        is config_for($dir)->robocop_security_level, $lvl, "$lvl accepted";
    }
};

subtest 'an unknown level is refused, listing the valid ones' => sub {
    my $dir = make_project(level => 'plaintext');
    my $cfg = config_for($dir);

    eval { $cfg->robocop_security_level };
    my $err = $@;
    ok $err, 'accessor croaks on an unknown level';
    like $err, qr/secret/,          'names secret';
    like $err, qr/secret_approved/, 'names secret_approved';
    like $err, qr/inject/,          'names inject';
    like $err, qr/plaintext/,       'quotes the bad value';

    my @errors = $cfg->validate;
    ok scalar(grep { /security_level/ } @errors),
        'validate() also reports it, report-only';
};

subtest 'robocop mapping still drives robocop_enabled' => sub {
    my $dir = make_project(level => 'secret');
    ok config_for($dir)->robocop_enabled,
        'a robocop mapping means robocop is configured';

    # explicit enabled:false inside the mapping still wins
    my $d2 = Path::Tiny->tempdir;
    $ocp->dump_file($d2->child('ocp.yaml')->stringify, {
        name           => 'test',
        control_planes => { provider => 'hetzner', location => 'fsn1', server_type => 'cx32' },
        robocop        => { enabled => 0, security_level => 'secret' },
    });
    ok !config_for($d2)->robocop_enabled,
        'enabled:false in the mapping wins over hetzner auto-on';
};

# ==========================================================================
# DeployRobocop: the credentials Secret per level (Weg A -- 3 keys)
# ==========================================================================

# Build the command and run one credentials-apply with the PIN2 prompt and the
# SSH token read stubbed. Counts prompts and records the remote command.
sub apply_credentials {
    my (%opt) = @_;
    my $dir     = $opt{dir};
    my $cfg     = config_for($dir);
    my $secrets = OCP::Secrets->new(project_dir => $dir);
    my $api     = FakeApi->new;

    my $cmd = OCP::Cmd::DeployRobocop->new(command_chain => [ FakeOCP->new ]);

    my $token = exists $opt{token} ? $opt{token} : $TOKEN;
    my $prompts = 0;
    my @ssh_cmds;

    no warnings 'redefine';
    local $OCP::ClusterKey::INTERACTIVE = 1;
    local *OCP::Password::prompt_password = sub {
        $prompts++;
        return exists $opt{pin2} ? $opt{pin2} : $PIN2;
    };
    local *OCP::SSH::run = sub {
        my ($self, $command) = @_;
        push @ssh_cmds, $command;
        return { stdout => (defined $token ? "$token\n" : ''), stderr => '', exit => 0 };
    };

    # Silence OCP::ClusterKey's narration (STDOUT) so the test output stays clean.
    my $sink = '';
    open my $out_fh, '>', \$sink or die $!;
    local *STDOUT = $out_fh;

    my $err = '';
    eval {
        $cmd->_apply_credentials_secret($api, $cfg, $secrets,
            $cfg->robocop_security_level);
        1;
    } or $err = $@;

    return {
        api      => $api,
        prompts  => $prompts,
        ssh_cmds => \@ssh_cmds,
        error    => $err,
    };
}

subtest 'secret: three keys land, token read off the CP over SSH' => sub {
    my $dir = make_project(level => 'secret');
    my $r   = apply_credentials(dir => $dir);

    is $r->{error}, '', 'no error';

    my $secret = secret_of($r->{api});
    ok $secret, 'a Secret was ensured';
    is $secret->{metadata}{name},      'robocop-credentials', 'secret name';
    is $secret->{metadata}{namespace}, 'ocp-system',          'secret namespace';

    is $secret->{stringData}{'robo-ssh-key'}, $ROBO_PRIV,
        'robo-ssh-key is the decrypted PRIVATE robo key';
    is $secret->{stringData}{'server-url'}, 'https://police1:9345',
        'server-url is the RKE2 join URL';
    is $secret->{stringData}{'rke2-token'}, $TOKEN,
        'rke2-token is the token read over SSH';

    is_deeply [ sort keys %{ $secret->{stringData} } ],
        [ 'rke2-token', 'robo-ssh-key', 'server-url' ],
        'exactly the three contract keys';
    unlike $secret->{stringData}{'robo-ssh-key'}, qr/ADMIN/,
        'the admin key is not what got written';

    is $r->{ssh_cmds}[0], 'cat /var/lib/rancher/rke2/server/node-token',
        'the token was read from the rke2 node-token path';
};

subtest 'k3s: the token path follows the distribution' => sub {
    my $dir = make_project(level => 'secret', dist => 'k3s');
    my $r   = apply_credentials(dir => $dir);

    is $r->{error}, '', 'no error';
    is $r->{ssh_cmds}[0], 'cat /var/lib/rancher/k3s/server/node-token',
        'k3s reads from the k3s node-token path';
};

subtest 'secret_approved: same Secret, gated behind ONE PIN2 (no double prompt)' => sub {
    my $dir = make_project(level => 'secret_approved');
    my $r   = apply_credentials(dir => $dir);

    is $r->{error}, '', 'no error with the right PIN2';
    is $r->{prompts}, 1,
        'PIN2 is asked exactly once -- the approval is reused for the SSH read';

    my $secret = secret_of($r->{api});
    ok $secret, 'the Secret was written';
    is $secret->{stringData}{'robo-ssh-key'}, $ROBO_PRIV, 'robo key present';
    is $secret->{stringData}{'server-url'},   'https://police1:9345', 'server-url present';
    is $secret->{stringData}{'rke2-token'},   $TOKEN, 'rke2-token present';
};

subtest 'secret_approved: wrong PIN2 refuses, writes nothing, reads nothing' => sub {
    my $dir = make_project(level => 'secret_approved');
    my $r   = apply_credentials(dir => $dir, pin2 => 'wrong-pin');

    ok $r->{error}, 'a wrong PIN2 dies';
    ok $r->{prompts} >= 1, 'it did prompt';
    ok !secret_of($r->{api}), 'nothing was written to the cluster';
    is scalar(@{ $r->{ssh_cmds} }), 0,
        'and the control plane was never even contacted -- the gate is first';
    is scalar(@{ $r->{api}->ensured }), 0, 'not even the namespace was ensured';
};

subtest 'token read fails: die loud, write nothing' => sub {
    my $dir = make_project(level => 'secret');
    my $r   = apply_credentials(dir => $dir, token => undef);   # empty stdout

    ok $r->{error}, 'an empty/failed token read dies';
    like $r->{error}, qr/join token/i, 'names the join token';
    like $r->{error}, qr/police1/,     'names the control plane';
    ok !secret_of($r->{api}), 'and no Secret was written';
};

subtest 'no control-plane address: die before any prompt or SSH' => sub {
    my $dir = make_project(level => 'secret', no_host => 1);
    my $r   = apply_credentials(dir => $dir);

    ok $r->{error}, 'dies when there is no host to reach';
    like $r->{error}, qr/control-plane address/i, 'names what is missing';
    is $r->{prompts}, 0, 'no PIN2 was asked -- nothing to reach';
    is scalar(@{ $r->{ssh_cmds} }), 0, 'no SSH attempted';
};

# ==========================================================================
# inject: accepted by config, refused by the deploy path
# ==========================================================================

subtest 'inject: execute dies cleanly, touches no cluster' => sub {
    my $dir = make_project(level => 'inject');

    my $cmd = OCP::Cmd::DeployRobocop->new(
        command_chain => [ FakeOCP->new(config => $dir->child('ocp.yaml')->stringify) ],
    );

    my $err = '';
    eval { $cmd->execute(undef, []); 1 } or $err = $@;

    ok $err, 'execute dies for inject';
    like $err, qr/\Qrobocop.security_level 'inject' is not yet available (k2)\E/,
        'with the exact k2 message';
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# k156: the cluster join token never lands on an installer command line.
#
# The k3s tasks used to hand the token to the installer as an environment
# assignment in front of `sh`:
#
#   curl -sfL https://get.k3s.io | K3S_TOKEN=<token> sh -s - server ...
#
# That line is a process command line on the node (`ps` shows it to every local
# user for as long as the installer runs), and the installer copies every K3S_*
# variable into k3s(.agent).service.env, so the token also stayed on disk next to
# the unit. The fix follows Rex::Rancher (rex-rancher f361cff, 3c515c4): the
# token goes into /etc/rancher/k3s/config.yaml only, written 0600 root:root
# BEFORE the installer runs, and the installer gets an explicit `server` /
# `agent` argument, so its "K3S_URL set but no K3S_TOKEN" guard never fires.
#
# The RKE2 tasks already kept the token in config.yaml, but wrote it with Rex's
# plain `file` -- umask mode, 0644 on a stock host. They now go through the same
# 0600 writer.
#
# Network-free and Rex-session-free, following t/68 and t/85: the pure helpers
# are lifted out of the Rexfile and run against stubs; the wiring inside the
# task bodies (which needs a real Rex session) is asserted against the source.
# Whether k3s actually joins with a token it only finds in config.yaml is a
# real-host question and is NOT claimed here.
#

my $root    = path(__FILE__)->parent->parent;
my $rexfile = $root->child('share/Rexfile');

plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

my $src = $rexfile->slurp_utf8;

my $TOKEN = 'K10deadbeef::server:s3cr3t-token-value-0123456789';

# --- lift the helpers out of the Rexfile -----------------------------------

my @subs;
for my $name (qw( _k3s_install_cmd _write_secret_file )) {
    my ($body) = $src =~ /^(sub \Q$name\E \{.*?^\})/ms;
    ok defined $body, "share/Rexfile defines $name"
        or BAIL_OUT("k156 fix absent: $name is not in the Rexfile");
    push @subs, $body;
}

# run / file stand in for Rex::Commands::Run / ::File and record the order of
# operations; get_tmp_file_name mirrors Rex's own naming (.rex.tmp.<name>).
my $stubs = <<'PERL';
package Rex::Commands::File;
sub get_tmp_file_name {
    my ($f) = @_;
    my ($dir, $base) = $f =~ m{^(.*)/([^/]+)$};
    return "$dir/.rex.tmp.$base";
}
package RexfileTokenCmdline;
our @OPS;
sub run  { push @OPS, [ run => $_[0] ]; return '' }
sub file { my ($p, %o) = @_; push @OPS, [ file => $p, $o{content} ]; return 1 }
PERL

ok eval("$stubs\n" . join("\n", @subs) . "\n1;"),
    'the lifted helpers compile against run/file stubs'
    or BAIL_OUT("cannot compile the lifted helpers: $@");

my $cmd   = RexfileTokenCmdline->can('_k3s_install_cmd');
my $write = RexfileTokenCmdline->can('_write_secret_file');

# --- the installer command carries no token --------------------------------

subtest 'k3s server install command: no token, explicit server' => sub {
    my $c = $cmd->(role => 'server', version => 'v1.33.1+k3s1', node_name => 'police1');
    unlike $c, qr/K3S_TOKEN/,         'no K3S_TOKEN assignment';
    unlike $c, qr/\Q$TOKEN\E/,        'the token value is nowhere on the line';
    like   $c, qr/\bsh -s - server\b/, 'explicit server argument to the installer';
    like   $c, qr/INSTALL_K3S_VERSION=v1\.33\.1\+k3s1 /, 'version pin kept';
    like   $c, qr/K3S_NODE_NAME=police1 /, 'node name kept';
    like   $c, qr/--disable=traefik --disable=servicelb --write-kubeconfig-mode=644/,
        'server flags kept';
    unlike $c, qr/K3S_URL/, 'no K3S_URL on a server install';
};

subtest 'k3s agent install command: no token, explicit agent' => sub {
    my $c = $cmd->(role => 'agent', server => 'https://10.0.0.1:6443', node_name => 'worker-1');
    unlike $c, qr/K3S_TOKEN/,        'no K3S_TOKEN assignment';
    like   $c, qr/K3S_URL=https:\/\/10\.0\.0\.1:6443 /, 'K3S_URL still set (not a secret)';
    like   $c, qr/\bsh -s - agent$/, 'explicit agent argument, so the URL-without-token guard stays quiet';
    unlike $c, qr/INSTALL_K3S_VERSION/, 'no version pin when none was given';
};

subtest 'an unknown role is refused, not guessed' => sub {
    ok !eval { $cmd->(role => 'bogus'); 1 }, 'dies';
    like $@, qr/role/, 'and says why';
};

# --- the secret file writer: 0600 before and after --------------------------

subtest '_write_secret_file pre-creates the tmp file 0600 and re-asserts the mode' => sub {
    @RexfileTokenCmdline::OPS = ();
    $write->('/etc/rancher/k3s/config.yaml', "token: $TOKEN\n");
    my @ops = @RexfileTokenCmdline::OPS;
    is scalar(@ops), 3, 'three operations' or diag explain \@ops;

    is_deeply $ops[0],
        [ run => 'install -m 600 -o root -g root /dev/null /etc/rancher/k3s/.rex.tmp.config.yaml' ],
        "1: Rex's tmp file is created 0600 root:root before any content lands";
    is_deeply $ops[1], [ file => '/etc/rancher/k3s/config.yaml', "token: $TOKEN\n" ],
        '2: then the content is written through Rex file';
    is_deeply $ops[2], [ run => 'chown root:root /etc/rancher/k3s/config.yaml && chmod 600 /etc/rancher/k3s/config.yaml' ],
        '3: then the target is forced to 0600 root:root (fixes an unchanged 0644 file too)';

    for my $op (grep { $_->[0] eq 'run' } @ops) {
        unlike $op->[1], qr/\Q$TOKEN\E/, "no token on the command line: $op->[1]";
    }
};

# --- the tasks wire it: token to config.yaml, nothing on the command line ---

sub task_body {
    my ($name) = @_;
    my ($body) = $src =~ /^task "\Q$name\E", sub \{\n(.*?)\n\};$/ms;
    return $body;
}

(my $code = $src) =~ s/^\s*#.*\n//mg;   # comments may name it; code may not
unlike $code, qr/K3S_TOKEN/, 'K3S_TOKEN appears nowhere in the Rexfile code';

for my $role (qw( server agent )) {
    subtest "install_k3s_$role writes the token to config.yaml before installing" => sub {
        my $body = task_body("install_k3s_$role");
        ok defined $body, 'task found' or return;

        my $write_at = index $body, '_write_secret_file("/etc/rancher/k3s/config.yaml", "token: $token\n")';
        my $run_at   = index $body, 'run _k3s_install_cmd(';
        ok $write_at >= 0, 'token goes to /etc/rancher/k3s/config.yaml through the 0600 writer';
        ok $run_at   >= 0, "installer command comes from _k3s_install_cmd(role => '$role')";
        like $body, qr/_k3s_install_cmd\(\s*role\s*=>\s*'\Q$role\E'/, "with role $role";
        ok $write_at >= 0 && $run_at > $write_at, 'config.yaml is written BEFORE the installer runs';
        unlike $body, qr/_k3s_install_cmd\([^)]*token/s, 'the token is not passed to the command builder';
    };
}

for my $role (qw( server agent )) {
    subtest "install_rke2_$role writes config.yaml 0600" => sub {
        my $body = task_body("install_rke2_$role");
        ok defined $body, 'task found' or return;
        like $body, qr{_write_secret_file\("/etc/rancher/rke2/config\.yaml", \$config\)},
            'config.yaml (holds the token) goes through the 0600 writer';
        unlike $body, qr{file "/etc/rancher/rke2/config\.yaml"},
            'no plain Rex file write of config.yaml left';
        like $body, qr/token: \$token/, 'the token is in the config content';
        unlike $body, qr/INSTALL_RKE2_\w+=\$token|\$token[^\n]*\bsh -/,
            'the token is not on the installer line';
    };
}

subtest 'k154 token reuse is intact' => sub {
    like task_body('install_k3s_server'),
        qr/\$params->\{token\}\s*\|\|\s*_existing_server_token\(\s*'k3s'\s*\)\s*\|\|\s*_generate_token\(\)/,
        'k3s server still reuses the on-disk token before generating';
};

done_testing;

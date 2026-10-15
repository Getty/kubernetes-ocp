use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';
use OCP::Rex;

#
# k200 (lab 2026-10-15, cp-lab): a re-bootstrap restarted rke2-server
# ("changed since it started: /etc/rancher/rke2/config.yaml") although nothing
# about the cluster changed. The fresh bootstrap had written the 48-character
# token OCP generates into config.yaml; RKE2 keeps the same secret in
# server/token in its full form, K10<ca-hash>::server:<secret>.
# _existing_server_token read server/token, so the re-bootstrap wrote the long
# form over the short one: same secret, different config.yaml, one restart.
# The token the server was started with is the one in config.yaml -- it wins;
# server/token is only the fallback for a config.yaml without one.
#

my $tmp = path(tempdir(CLEANUP => 1));
my $key = $tmp->child('id_ed25519');
$key->spew('fake key');
path("$key.pub")->spew('fake pub');

my $SHORT = 'a' x 48;
my $LONG  = 'K10' . ('f' x 64) . '::server:' . $SHORT;

sub token_with {
    my (%files) = @_;
    my @cmds;
    no warnings 'redefine';
    local *OCP::SSH::new = sub { my ($c, %a) = @_; bless { %a }, $c };
    local *OCP::SSH::run = sub {
        my ($self, $cmd) = @_;
        push @cmds, $cmd;
        for my $f (sort keys %files) {
            return { stdout => $files{$f}, stderr => '', exit => 0 } if index($cmd, $f) >= 0;
        }
        return { stdout => '', stderr => 'No such file', exit => 1 };
    };
    my $rex = OCP::Rex->new(host => '10.0.0.1', key_file => $key->stringify);
    return ($rex->_existing_server_token($files{_dist} // 'rke2'), \@cmds);
}

subtest 'the token in config.yaml wins over server/token' => sub {
    my ($t) = token_with(
        '/etc/rancher/rke2/config.yaml'      => "cni: none\ntoken: $SHORT\nnode-name: cp-lab\n",
        '/var/lib/rancher/rke2/server/token' => "$LONG\n",
    );
    is $t, $SHORT, 'config.yaml stays as it is: no restart for the same secret';
};

subtest 'a quoted token in config.yaml' => sub {
    my ($t) = token_with(
        '/etc/rancher/rke2/config.yaml'      => "token: \"$SHORT\"\n",
        '/var/lib/rancher/rke2/server/token' => "$LONG\n",
    );
    is $t, $SHORT, 'YAML quoting is not part of the token';
};

subtest 'config.yaml without a token falls back to server/token' => sub {
    my ($t) = token_with(
        '/etc/rancher/rke2/config.yaml'      => "cni: none\n",
        '/var/lib/rancher/rke2/server/token' => "$LONG\n",
    );
    is $t, $LONG, 'the on-disk token, as before (k150)';
};

subtest 'k3s reads its own config.yaml' => sub {
    my ($t, $cmds) = token_with(
        _dist                               => 'k3s',
        '/etc/rancher/k3s/config.yaml'      => "token: $SHORT\n",
        '/var/lib/rancher/k3s/server/token' => "$LONG\n",
    );
    is $t, $SHORT, 'k3s config token';
};

done_testing;

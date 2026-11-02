#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use IO::Socket::INET ();
use Path::Tiny qw( path );

use lib 'lib';

use Kubernetes::REST::APIError ();
use OCP;
use OCP::Cmd::Health;
use OCP::ErrorLine;
use OCP::Kubernetes;
use OCP::Password;
use OCP::Secrets;

#
# k399 (Part B of the one-place-per-concern design): every command that talks
# to the cluster API gets its client from one place, OCP::Role::Cmd. Until
# now sixteen files built one, each reading kubeconfig.yaml itself and each
# deciding itself whether to unlock the key first (k370, k375, k382); only
# health, node ls and provider ls checked the API once before their first
# call. The claims, one subtest each:
#   1. cluster_api, required: no kubeconfig.yaml is OCP::Secrets' refusal; an
#      API that does not answer is the one line naming the server, a user
#      error;
#   2. cluster_api, optional: no kubeconfig.yaml is (undef, undef) -- nothing
#      to say; an API that does not answer is (undef, that line, without its
#      newline and without a leading ERROR:);
#   3. a key problem is no unreachable API, optional or not: a wrong PIN1, and
#      no key at all, die in OCP::Secrets' words (k382);
#   4. a second call returns the client of the first: one build, the same
#      object -- but an optional call that failed keeps nothing, so the next
#      one builds and checks again;
#   5. connect_cluster_api tells the renderer its server: an APIError that
#      escapes a command names the server of the last client built, so a
#      rebuild on a new kubeconfig (ocp apply after bootstrap) names the new
#      one;
#   6. from bin/ocp, every command in the closed-port table, against an API
#      that does not answer: STDERR is exactly the one line naming the server,
#      no Perl location and no "internal error" anywhere, exit 1 (k389).
#

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};

my $PIN1   = 'pin1-k399';
my $PROMPT = 'Enter PIN1 (cluster access): ';

# Local ports nothing listens on: bound and never listening, held for the
# whole test, so no other process can take them and every connect is refused.
sub closed_port {
    my $sock = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Proto     => 'tcp',
    ) or BAIL_OUT("cannot bind a local port: $!");
    return $sock;
}
my $closed  = closed_port();
my $closed2 = closed_port();
my $server  = 'https://127.0.0.1:' . $closed->sockport;
my $server2 = 'https://127.0.0.1:' . $closed2->sockport;

sub kubeconfig_for {
    my ($at) = @_;
    return join "\n",
        'apiVersion: v1', 'kind: Config', 'current-context: k399',
        'clusters:', '- name: k399', '  cluster:', "    server: $at",
        '    insecure-skip-tls-verify: true',
        'users:', '- name: k399', '  user:', '    token: t',
        'contexts:', '- name: k399', '  context:', '    cluster: k399', '    user: k399', '';
}

# A deployed project as the machine that made it has it: the project key in
# .ocp/ (and behind PIN1 in age.key.enc with pin1 => ...), kubeconfig.yaml
# encrypted to it and naming the closed port (none with kubeconfig => 0), an
# ocp.yaml for an ssh control plane.
sub project {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($o{pin1}) if defined $o{pin1};
    $s->save_kubeconfig(kubeconfig_for($server))
        unless defined $o{kubeconfig} && !$o{kubeconfig};
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k399',
        control_planes => { provider => 'ssh', host => 'cp.k399.invalid' },
    });
    return $dir;
}

# What a clone gets: every committed file, no .ocp/.
sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

# The root command object, as far as cluster_api asks it: where ocp.yaml is.
{
    package Local::OCP;
    sub new     { bless { config => $_[1] }, $_[0] }
    sub config  { $_[0]{config} }
    sub verbose { 0 }
}

# A command in $dir. ocp health will do: every command consumes the role.
sub command_in {
    my ($dir) = @_;
    return OCP::Cmd::Health->new(
        command_chain => [ Local::OCP->new($dir->child('ocp.yaml')->stringify) ]);
}

# A 599 as Kubernetes::REST throws it, with the location croak would add.
my $e599 = Kubernetes::REST::APIError->new(code => 599, body => "Connection refused\n",
    _location => ' at lib/Kubernetes/REST.pm line 1546.');

my $unreachable = qr{The cluster API at https://127\.0\.0\.1:\d+ could not be reached: .+};

#### 1, 2: required and optional

subtest 'cluster_api, required' => sub {
    my $none = command_in(project(kubeconfig => 0));
    ok !eval { $none->cluster_api; 1 }, 'no kubeconfig.yaml: dies';
    is $@, OCP::Secrets->no_kubeconfig_refusal, "no kubeconfig.yaml: OCP::Secrets' refusal";

    my $down = command_in(project());
    ok !eval { $down->cluster_api; 1 }, 'the API does not answer: dies';
    like $@, qr{\A$unreachable\n\z}, 'the API does not answer: one line naming the server';
    like $@, qr{\Q$server\E}, 'the server of the kubeconfig';
    OCP::ErrorLine::set_cluster_endpoint(undef);
};

subtest 'cluster_api, optional' => sub {
    my @none = command_in(project(kubeconfig => 0))->cluster_api(optional => 1);
    is_deeply \@none, [ undef, undef ], 'no kubeconfig.yaml: (undef, undef), nothing to say';

    my ($api, $why) = command_in(project())->cluster_api(optional => 1);
    is $api, undef, 'the API does not answer: no client';
    like $why, qr{\A$unreachable\z}, 'the API does not answer: the line, without its newline';
    OCP::ErrorLine::set_cluster_endpoint(undef);

    # A failure that is no APIError comes as it was said, minus OCP's prefix.
    no warnings 'redefine';
    local *OCP::Cmd::Health::reach_cluster_api = sub { die "ERROR: no answer from k399\n" };
    (undef, $why) = command_in(project())->cluster_api(optional => 1);
    is $why, 'no answer from k399', 'the line without a leading ERROR:';
    OCP::ErrorLine::set_cluster_endpoint(undef);
};

#### 3: a key problem stops the command

subtest 'optional, a wrong PIN1: dies in OCP::Secrets\' words (k382)' => sub {
    my $clone = clone_of(project(pin1 => $PIN1));
    ok !-e $clone->child('.ocp', 'age.key'), 'precondition: no .ocp/age.key';
    ok -f $clone->child('age.key.enc'),      'precondition: age.key.enc';

    my $cmd = command_in($clone);
    local $OCP::Password::PINS_STDIN = 1;
    open my $in, '<', \"not-the-pin\n" or die "stdin: $!";
    local *STDIN = $in;
    my $stderr = '';
    my (@got, $died);
    {
        local *STDERR;
        open STDERR, '>', \$stderr or die "stderr: $!";
        $died = !eval { @got = $cmd->cluster_api(optional => 1); 1 };
    }
    ok $died, 'dies: no (undef, reason) for a key problem' or diag explain \@got;
    is $@, OCP::Secrets->_wrong_pin1_refusal, "OCP::Secrets' wrong-PIN1 text, unchanged";
    like $stderr, qr/\Q$PROMPT\E/, 'PIN1 was asked';
    ok !-e $clone->child('.ocp', 'age.key'), 'no key written';
};

subtest 'optional, no key at all: dies with the no-age-key refusal' => sub {
    my $clone = clone_of(project());
    ok !-e $clone->child('.ocp', 'age.key'), 'precondition: no .ocp/age.key';
    ok !-e $clone->child('age.key.enc'),     'precondition: no age.key.enc';
    ok -f $clone->child('kubeconfig.yaml'),  'precondition: kubeconfig.yaml';
    local $ENV{SOPS_AGE_KEY_FILE};
    delete $ENV{SOPS_AGE_KEY_FILE};

    my @got;
    ok !eval { @got = command_in($clone)->cluster_api(optional => 1); 1 },
        'dies: no (undef, reason) for no key' or diag explain \@got;
    is $@, OCP::Secrets->_no_age_key_refusal('kubeconfig.yaml'),
        "OCP::Secrets' no-age-key text, unchanged";
};

#### 4: one build per command

subtest 'a second call: the client of the first, built once' => sub {
    my $cmd = command_in(project());

    # Moo's constructor exists before it is wrapped, so the wrapper is not
    # replaced by the constructor being generated on its first call.
    OCP::Kubernetes->new(kubeconfig => '');
    my $new   = \&OCP::Kubernetes::new;
    my $built = 0;
    no warnings 'redefine';
    local *OCP::Kubernetes::new = sub { $built++; goto &$new };
    # The closed port answers nothing; the check is not what this is about.
    local *OCP::Cmd::Health::reach_cluster_api = sub { $_[1] };

    my $first  = $cmd->cluster_api;
    my $second = $cmd->cluster_api;
    is $built, 1, 'built once';
    ok $first, 'a client';
    is $second, $first, 'the same object';
    OCP::ErrorLine::set_cluster_endpoint(undef);
};

subtest 'optional, closed port twice: the second call builds again' => sub {
    my $cmd = command_in(project());

    OCP::Kubernetes->new(kubeconfig => '');
    my $new   = \&OCP::Kubernetes::new;
    my $built = 0;
    no warnings 'redefine';
    local *OCP::Kubernetes::new = sub { $built++; goto &$new };

    my ($api1, $why1) = $cmd->cluster_api(optional => 1);
    my ($api2, $why2) = $cmd->cluster_api(optional => 1);
    is $built, 2, 'built twice: nothing unchecked was kept';
    is $api1, undef, 'first call: no client';
    is $api2, undef, 'second call: no client either, not the unchecked one';
    like $why1, qr{\A$unreachable\z}, 'first call: the line';
    like $why2, qr{\A$unreachable\z}, 'second call: the line again';
    OCP::ErrorLine::set_cluster_endpoint(undef);
};

#### 5: the renderer names the server

subtest 'connect_cluster_api: the renderer names the last server' => sub {
    is OCP::ErrorLine::user_line($e599), 'The cluster API could not be reached: Connection refused',
        'before any client: no server';
    my $cmd = OCP::Cmd::Health->new;
    $cmd->connect_cluster_api(kubeconfig_for($server));
    is OCP::ErrorLine::user_line($e599),
        "The cluster API at $server could not be reached: Connection refused",
        'one client: its server';
    $cmd->connect_cluster_api(kubeconfig_for($server2));
    is OCP::ErrorLine::user_line($e599),
        "The cluster API at $server2 could not be reached: Connection refused",
        'rebuilt on a new kubeconfig: the new server, not the stale one';
    OCP::ErrorLine::set_cluster_endpoint(undef);
    is OCP::ErrorLine::user_line($e599), 'The cluster API could not be reached: Connection refused',
        'reset: no server';
};

#### 6: the closed-port table, from bin/ocp

my $bin = path('bin/ocp')->absolute;
my $lib = path('lib')->absolute;

# bin/ocp in the project dir, STDIN empty and --pins-stdin, so a prompt that
# should not come ends the run instead of waiting.
sub run_ocp {
    my ($dir, @argv) = @_;
    my ($in, $out, $err) = map { Path::Tiny->tempfile } 1 .. 3;
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        open STDIN,  '<', "$in"  or die;
        open STDOUT, '>', "$out" or die;
        open STDERR, '>', "$err" or die;
        alarm 120;
        exec $^X, "-I$lib", "$bin", @argv, '--pins-stdin' or die "exec: $!";
    }
    waitpid $pid, 0;
    return ($?, $out->slurp_utf8, $err->slurp_utf8);
}

# One row per command that takes its client from cluster_api: its words, then
# the fewest arguments that get it to the API.
my @closed_port = (
    [ 'node add',        'w-k399' ],
    [ 'node rm',         'w-k399' ],
    [ 'node trust-host', 'w-k399' ],
    [ 'provider add',    '--name', 'p-k399', '--type', 'ssh' ],
    [ 'provider rm',     'p-k399' ],
    [ 'deploy-image',    '--image', 'ghcr.io/k399/robocop:1' ],
    [ 'deploy-robocop' ],
    [ 'kubeconfig',      '--readonly' ],
);

for my $row (@closed_port) {
    my ($words, @args) = @$row;
    subtest "ocp $words, the API does not answer" => sub {
        my ($status, $out, $err) = run_ocp(project(), split(/ /, $words), @args);
        like $err, qr{\AError: $unreachable\n\z}, 'STDERR: the one line naming the server';
        like $err, qr{\Q$server\E}, 'the server of the kubeconfig';
        unlike "$out$err", qr/ at \S+ line \d+/, 'no Perl location';
        unlike "$out$err", qr/internal error/i,  'no "internal error"';
        is $status >> 8, 1, 'exit 1';
    };
}

done_testing;

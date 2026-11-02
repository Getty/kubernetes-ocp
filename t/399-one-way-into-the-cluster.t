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
#      no Perl location and no "internal error" anywhere, exit 1 (k389);
#   7. destroy and the machines role on optional mode: destroy says once why
#      it goes on without the API -- one that does not answer, or no key at
#      all to open kubeconfig.yaml (k396, from k382) -- and tears down what
#      it knows; its robocop warning says the error in one line; keys secure
#      stops on OCPNodes it cannot read, naming the server.
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


#### 7: destroy and the machines role on optional mode

{
    # The machines, as destroy reaches them: no server under any label, and an
    # uninstall that only records where it ran.
    package Local::Provider;
    sub new   { my ($c, %a) = @_; bless {%a}, $c }
    sub token { $_[0]{token} }
    sub list_servers_by_cluster { [] }
    sub resolve_host {
        my ($self, %o) = @_;
        return $o{host} // die "SSH provider requires 'host'\n";
    }
    sub delete_server {
        my ($self, $id, %o) = @_;
        push @main::deleted, "$self->{type} " . ($id // $o{host});
        return { stdout => '', stderr => '', exit => 0 };
    }

    package Local::Key;
    sub new            { bless {}, shift }
    sub path           { '/nonexistent/admin-key' }
    sub migration_hint { "hint\n" }

    # A cluster API handed in: no OCPNodes, no OCPNodeProviders, and a robocop
    # scale-down that dies as the transport does.
    package Local::K8s;
    sub new              { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub list             { Local::List->new }
    sub patch            { die $_[0]{patch_dies} }

    package Local::List;
    sub new   { bless {}, shift }
    sub items { [] }
}
our @deleted;

# ocp destroy --force in $dir, its machines faked; the token from
# HETZNER_API_TOKEN when the caller set it, else a fake read.
sub run_destroy {
    my ($dir, %o) = @_;
    @deleted = ();
    require OCP::Cmd::Destroy;
    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ Local::OCP->new($dir->child('ocp.yaml')->stringify) ],
        force         => 1,
        ($o{k8s} ? (k8s => $o{k8s}) : ()),
    );
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my $died = do {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        no warnings qw( redefine once );
        local *OCP::Provider::for_spec = sub {
            my ($class, $spec) = @_;
            return Local::Provider->new(type => $spec->{provider}, token => 'tok');
        };
        local *OCP::Secrets::hetzner_token = sub { 'tok' } unless $ENV{HETZNER_API_TOKEN};
        local *OCP::Cmd::Destroy::cluster_ssh_key = sub { Local::Key->new };
        eval { $cmd->execute([], []); 1 } ? '' : $@;
    };
    return { out => $out, err => $err, died => $died };
}

my $OCPNODES_UNREAD = qr/^\[!!\] Could not read the OCPNodes from the cluster API:$/m;

subtest 'ocp destroy, the API does not answer: why, once, and the teardown goes on' => sub {
    my $r = run_destroy(project());
    is $r->{died}, '', 'ran without dying';
    like $r->{err}, qr{\A\[!!\] Could not read the OCPNodes from the cluster API:\n     $unreachable\n},
        'in the words of an OCPNode list that failed, the line naming the server';
    is scalar(() = $r->{err} =~ /could not be reached/g), 1, 'said once';
    like $r->{err}, qr/\Q$server\E/, 'the server of the kubeconfig';
    unlike "$r->{out}$r->{err}", qr/ at \S+ line \d+/, 'no Perl location';
    is_deeply \@deleted, [ 'ssh cp.k399.invalid' ], 'the teardown went on: the control plane uninstalled';
    OCP::ErrorLine::set_cluster_endpoint(undef);
};

subtest 'ocp destroy, kubeconfig.yaml, no key at all, HETZNER_API_TOKEN set: why, once (k396)' => sub {
    my $clone = clone_of(project());
    ok !-e $clone->child('.ocp'),        'precondition: no .ocp/';
    ok !-e $clone->child('age.key.enc'), 'precondition: no age.key.enc';
    local $ENV{HETZNER_API_TOKEN} = 'hzTOKEN-k399-env-0123456789';
    local $ENV{SOPS_AGE_KEY_FILE};
    delete $ENV{SOPS_AGE_KEY_FILE};
    my $r = run_destroy($clone);
    is $r->{died}, '', 'ran without dying: a missing key is a missing API here (k382)';
    is scalar(() = $r->{err} =~ /$OCPNODES_UNREAD/g), 1, 'the API line, once';
    is scalar(() = $r->{err} =~ /no age key/g), 1, 'why, once: no key opens kubeconfig.yaml';
    like $r->{err}, qr/no age key to open kubeconfig\.yaml.*\n.*goes on without it/,
        'and that destroy goes on without the API';
    unlike $r->{err}, qr/check out age\.key\.enc/, "not OCP::Secrets' refusal: nothing stops";
    unlike "$r->{out}$r->{err}", qr/ at \S+ line \d+/, 'no Perl location';
    is_deeply \@deleted, [ 'ssh cp.k399.invalid' ], 'the teardown went on';
};

subtest 'ocp destroy, robocop not stopped: the error in one line (k396)' => sub {
    OCP::ErrorLine::set_cluster_endpoint(undef);
    my $r = run_destroy(project(), k8s => Local::K8s->new(patch_dies => $e599));
    is $r->{died}, '', 'ran without dying';
    like $r->{err},
        qr/^  Warning: could not stop robocop \(The cluster API could not be reached: Connection refused\); it may re-provision a worker\.$/m,
        'the warning says the error in its one line';
    unlike $r->{err}, qr/ at \S+ line \d+/, 'no Perl location';
};

subtest 'ocp keys secure, the API does not answer: its OCPNodes line, naming the server' => sub {
    my ($status, $out, $err) = run_ocp(project(), 'keys', 'secure');
    like $err, qr{^Error: Could not read the OCPNodes from the cluster API: $unreachable$}m,
        'the line it says for OCPNodes it cannot read, with the line naming the server';
    like $err, qr/\Q$server\E/, 'the server of the kubeconfig';
    like $err, qr/Nothing was changed/, 'and that nothing changed';
    unlike "$out$err", qr/ at \S+ line \d+/, 'no Perl location';
    unlike "$out$err", qr/internal error/i,  'no "internal error"';
    is $status >> 8, 1, 'exit 1';
};

done_testing;

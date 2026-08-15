#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Cwd qw(getcwd);
use FindBin;

use OCP::Cmd::Init;
use OCP::Config;
use OCP::Hetzner::Picker;

# `ocp init` is the one command that has to work before anything else does,
# and it is the one command no test ever ran. Three things had drifted:
#
#   - the provider default was ssh while the option help said hetzner, so a
#     bare `ocp init` died on a missing --host instead of scaffolding
#   - --single was declared, referenced nowhere, and passed by xt/smoke.sh
#   - the generated .gitignore still carried .kube/, from back when the
#     kubeconfig was written into the project
#
# The last one is the dangerous shape: an over-broad entry here silently
# keeps an encrypted file out of the repo, and that only surfaces when a
# colleague clones the project and cannot reach the cluster. Hence the
# git check-ignore assertion below rather than a regex over the text.

my $BIN = "$FindBin::Bin/../bin/ocp";
my $LIB = "$FindBin::Bin/../lib";

# Run bin/ocp in a fresh project directory. Always --nopassword: the default
# path prompts for PIN1/PIN2 and would hang the suite.
sub run_init {
    my (@args) = @_;
    my $dir = tempdir(CLEANUP => 1);
    my $cwd = getcwd();

    local $ENV{HETZNER_API_TOKEN} = '';    # never inherit a real token

    chdir $dir or die "chdir: $!";
    my $out = `$^X -I'$LIB' '$BIN' init --nopassword @args 2>&1`;
    my $rc  = $? >> 8;
    chdir $cwd or die "chdir back: $!";

    return ($rc, $out, path($dir));
}

subtest 'the default provider is the one the option help advertises' => sub {
    is(OCP::Cmd::Init->new->_provider, 'hetzner',
        'no --provider means hetzner');
    is(OCP::Cmd::Init->new(provider => 'ssh')->_provider, 'ssh',
        '--provider still wins');
    is(OCP::Cmd::Init->new(hetzner => 1)->_provider, 'hetzner',
        '--hetzner is about the token, not about overriding the provider');

    my %declared = OCP::Cmd::Init->_options_data;
    like $declared{provider}{doc}, qr/hetzner \(default\)/,
        'the option help names hetzner as the default';
};

subtest 'a bare ocp init scaffolds instead of dying' => sub {
    plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

    my ($rc, $out, $dir) = run_init('--nogit', '--name', 'bare');

    is $rc, 0, 'exits 0 with no flags but --name'
        or diag $out;

    my $spec = $dir->child('ocp.yaml')->slurp;
    like $spec, qr/provider: hetzner/, 'ocp.yaml names the hetzner provider';
    like $out, qr/API Token Required/,
        'and says a token is still missing rather than leaving it for apply';
};

subtest 'ssh without a host names every way out' => sub {
    plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

    my ($rc, $out) = run_init('--nogit', '--provider', 'ssh');

    is $rc, 1, '--provider ssh without --host still fails';
    like $out, qr/--host yourserver\.com/, 'points at --host';
    like $out, qr/--provider local/,       'offers local';
    like $out, qr/the default provider/,   'offers the hetzner default';
};

subtest 'the generated .gitignore keeps encrypted files committable' => sub {
    plan skip_all => 'needs git and ssh-keygen'
        unless _have('git') && _have('ssh-keygen');

    my ($rc, $out, $dir) = run_init('--name', 'ignored');
    is $rc, 0, 'init succeeded' or diag $out;

    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";

    # check-ignore echoes back only the paths git would ignore.
    my @encrypted = qw(keys.yaml secrets.yaml age.key.enc kubeconfig.yaml);
    my $swallowed = `git check-ignore @encrypted 2>/dev/null`;
    my $state     = `git check-ignore .ocp/age.key 2>/dev/null`;

    chdir $cwd or die "chdir back: $!";

    is $swallowed, '', 'no encrypted file is ignored — all four must reach git';
    like $state, qr{\.ocp/age\.key}, 'decrypted state under .ocp/ stays out';

    my $content = $dir->child('.gitignore')->slurp;
    unlike $content, qr{\.kube/}, 'no .kube/ — nothing writes a project-local one';
};

subtest 'an existing .gitignore only gains .ocp/' => sub {
    plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('.gitignore')->spew("*.log\n");

    my $cwd = getcwd();
    local $ENV{HETZNER_API_TOKEN} = '';
    chdir $dir or die "chdir: $!";
    my $out = `$^X -I'$LIB' '$BIN' init --nopassword --name kept 2>&1`;
    chdir $cwd or die "chdir back: $!";

    my $content = path($dir)->child('.gitignore')->slurp;
    like $content, qr/^\*\.log$/m, 'what was there is left alone' or diag $out;
    like $content, qr{^\.ocp/$}m,  '.ocp/ appended';
    unlike $content, qr{\.kube/},  '.kube/ is not appended either';
};

subtest '--single is gone, and so is its caller' => sub {
    ok(!OCP::Cmd::Init->can('single'), 'the dead option is removed');

    my %declared = OCP::Cmd::Init->_options_data;
    ok(!exists $declared{single}, 'and it is no longer declared as an option');

    # A fresh init writes one control plane and no workers, which is what
    # OCP::Config::single_node already derives — the flag had nothing to set.
    my $smoke = path("$FindBin::Bin/../xt/smoke.sh");
  SKIP: {
        skip 'no xt/smoke.sh', 1 unless -f $smoke;
        unlike $smoke->slurp, qr/--single/,
            'xt/smoke.sh no longer passes it (MooX::Options would reject it)';
    }
};

# -------------------------------------------------------------------------
# OCP::Hetzner::Picker built two ready-made picker lists that nothing ever
# called, so `ocp init --hetzner` asked for a token and then wrote the
# hardcoded cpx21/fsn1 anyway. The lists are wired into the token step now.
# What has to stay true: the defaults are still the answer to a bare Enter,
# and a run with nobody at the keyboard must not stop to ask.

{
    package FakeLocation;
    sub new { my ($class, %a) = @_; bless {%a}, $class }
    for my $field (qw(name city country)) {
        no strict 'refs';
        *{"FakeLocation::$field"} = sub { $_[0]{$field} };
    }
}

{
    package FakeType;
    sub new { my ($class, %a) = @_; bless {%a}, $class }
    for my $field (qw(name cores memory disk cpu_type architecture deprecated)) {
        no strict 'refs';
        *{"FakeType::$field"} = sub { $_[0]{$field} };
    }
}

sub fake_picker {
    return OCP::Hetzner::Picker->new(
        token      => 'fake',
        _locations => [
            FakeLocation->new(name => 'fsn1', city => 'Falkenstein', country => 'DE'),
            FakeLocation->new(name => 'hel1', city => 'Helsinki',    country => 'FI'),
        ],
        _server_types => [
            FakeType->new(name => 'cpx21', cores => 3, memory => 4, disk => 80,
                cpu_type => 'shared', architecture => 'x86', deprecated => 0),
            FakeType->new(name => 'cax21', cores => 4, memory => 8, disk => 80,
                cpu_type => 'shared', architecture => 'arm', deprecated => 0),
        ],
    );
}

# Run the picker step against a scripted STDIN and swallow its output.
sub pick_with {
    my ($input, %args) = @_;

    my $init = OCP::Cmd::Init->new(
        _picker      => fake_picker(),
        _interactive => 1,
        %args,
    );

    open my $in,  '<', \$input or die "stdin: $!";
    my $captured = '';
    open my $out, '>', \$captured or die "stdout: $!";
    {
        local *STDIN  = $in;
        local *STDOUT = $out;
        $init->_prompt_hetzner_control_plane(undef);
    }

    return ($init, $captured);
}

subtest 'the picker preselects what a non-interactive init would write' => sub {
    my ($init, $out) = pick_with("\n\n");

    is $init->_location,    $OCP::Config::HETZNER_DEFAULTS{location},
        'Enter keeps the default location';
    is $init->_server_type, $OCP::Config::HETZNER_DEFAULTS{server_type},
        'Enter keeps the default server type';
    like $out, qr/fsn1.*\[default\]/, 'the default is marked in the list';
    like $out, qr/\bcax21\b/,
        'ARM types are offered too — server_type_options lists both arches';
};

subtest 'a choice is taken by number or by name' => sub {
    my ($by_number) = pick_with("2\n2\n");
    is $by_number->_location,    'hel1',  'location chosen by list number';
    is $by_number->_server_type, 'cax21', 'server type chosen by list number';

    my ($by_name) = pick_with("hel1\ncax21\n");
    is $by_name->_location,    'hel1',  'location chosen by value';
    is $by_name->_server_type, 'cax21', 'server type chosen by value';

    my ($garbage, $out) = pick_with("nirgendwo\n\n");
    is $garbage->_location, $OCP::Config::HETZNER_DEFAULTS{location},
        'an answer that is not on the list falls back to the default';
    like $out, qr/not on the list/, 'and says so instead of failing';
};

subtest 'without a terminal nothing is asked' => sub {
    my $init = OCP::Cmd::Init->new(
        _picker      => fake_picker(),
        _interactive => 0,
    );
    $init->_prompt_hetzner_control_plane(undef);

    is $init->_location,    undef, 'no location picked';
    is $init->_server_type, undef, 'no server type picked';
};

subtest 'a picked location and server type reach ocp.yaml' => sub {
    my $file = path(tempdir(CLEANUP => 1))->child('ocp.yaml');

    OCP::Config->write_spec("$file",
        name        => 'picked',
        provider    => 'hetzner',
        location    => 'hel1',
        server_type => 'cax21',
    );

    my $spec = $file->slurp;
    like $spec, qr/location: hel1/,      'the picked location is written';
    like $spec, qr/server_type: cax21/,  'the picked server type is written';
    like $spec, qr/image: debian-13/,    'the untouched default is still there';
};

subtest 'ocp init --hetzner does not stop for a picker in a batch run' => sub {
    plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

    my $dir = tempdir(CLEANUP => 1);
    my $cwd = getcwd();

    # The token check is satisfied from the environment, so the pickers are
    # the only thing left that could ask a question. STDIN is a pipe here —
    # the shape of every CI run and of the suite itself.
    local $ENV{HETZNER_API_TOKEN} = 'not-a-real-token';

    chdir $dir or die "chdir: $!";
    my $out = `echo | $^X -I'$LIB' '$BIN' init --nopassword --nogit --hetzner --name batch 2>&1`;
    my $rc  = $? >> 8;
    chdir $cwd or die "chdir back: $!";

    is $rc, 0, 'init --hetzner completes with no terminal attached' or diag $out;
    unlike $out, qr/Control plane placement/, 'no picker was printed';

    my $spec = path($dir)->child('ocp.yaml')->slurp;
    like $spec, qr/server_type: cpx21/, 'server_type stays at the default';
    like $spec, qr/location: fsn1/,     'location stays at the default';
};

sub _have {
    my ($cmd) = @_;
    return system("command -v $cmd >/dev/null 2>&1") == 0;
}

done_testing;

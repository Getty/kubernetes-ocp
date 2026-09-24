#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Cwd qw(getcwd);

use OCP;
use OCP::Password;
use OCP::ClusterKey;
use OCP::Config;
use OCP::Keys;
use OCP::Secrets;
use OCP::Cmd::Init;
use OCP::Cmd::Apply;
use OCP::Cmd::InjectKey;

# k166 — `--pins-stdin`: every PIN prompt reads the next line of STDIN
# instead of the terminal, in prompt order, so `ocp apply --pins-stdin <
# <(pass show ocp/x)` runs without a human. A PIN never travels in argv or
# the environment (ps, /proc/PID/environ, shell history — cf. k156); STDIN
# from a file or a process substitution is the one channel that is neither.
#
# The claims:
#
#   * each prompt consumes exactly one line, in the order the prompts come;
#     only the trailing newline is stripped — whitespace is part of a PIN
#   * a missing line is a loud death on STDERR naming the PIN that was
#     expected — never undef, which callers would read as "wrong PIN", and
#     never a quiet fallback to the terminal (Term::ReadKey is not touched)
#   * the prompt text still goes to STDERR, so STDOUT stays the payload
#   * the flag is a MooX::Options option on every command (OCP::Role::Cmd)
#   * the "no terminal, refuse before asking" guard in OCP::ClusterKey counts
#     --pins-stdin as someone to ask
#   * secure-mode `ocp init` runs end to end off STDIN: PIN1, confirm, PIN2,
#     confirm — and the PINs it stored are the ones that were fed

# Feed $input as STDIN, capture STDOUT and STDERR, run $code in pins mode.
sub with_stdin {
    my ($input, $code, %opt) = @_;

    my ($out, $err) = ('', '');
    open my $in,  '<', \$input or die "stdin: $!";
    open my $ofh, '>', \$out   or die "stdout: $!";
    open my $efh, '>', \$err   or die "stderr: $!";

    local $OCP::Password::PINS_STDIN = exists $opt{pins_stdin} ? $opt{pins_stdin} : 1;
    local *STDIN  = $in;
    local *STDERR = $efh;
    my $old = select $ofh;
    my @r = eval { $code->() };
    my $died = $@;
    select $old;

    return { out => $out, err => $err, died => $died, result => \@r };
}

# Term::ReadKey is how the terminal is read. In pins mode it must never be
# reached — not even to fall back after STDIN ran dry.
my $TTY_READS = 0;
{
    no warnings 'redefine';
    *OCP::Password::ReadMode = sub { $TTY_READS++; return };
    *OCP::Password::ReadLine = sub { $TTY_READS++; return 'from-the-tty' };
}

subtest 'prompts consume STDIN lines in prompt order' => sub {
    $TTY_READS = 0;
    my $r = with_stdin("first\nsecond\n third \n", sub {
        return (
            OCP::Password::prompt_password('Enter PIN1 (cluster access): '),
            OCP::Password::prompt_password('Enter PIN2 (admin-key): '),
            OCP::Password::prompt_password('Confirm PIN2: '),
        );
    });

    is $r->{died}, '', 'no error';
    is_deeply $r->{result}, [ 'first', 'second', ' third ' ],
        'one line per prompt, in order; only the newline is stripped';
    is $TTY_READS, 0, 'the terminal was never read';

    like $r->{err}, qr/Enter PIN1 \(cluster access\): .*Enter PIN2 \(admin-key\): .*Confirm PIN2: /s,
        'the prompts still go to STDERR, in order';
    is $r->{out}, '', 'nothing on STDOUT — the payload channel stays clean';
    unlike $r->{err}, qr/first|second|third/, 'no PIN is echoed anywhere';
};

subtest 'a line without a trailing newline (last line of a file) is still a PIN' => sub {
    my $r = with_stdin("only", sub {
        OCP::Password::prompt_password('Enter PIN1 (cluster access): ');
    });
    is $r->{died}, '', 'no error';
    is_deeply $r->{result}, ['only'], 'read as is';
};

subtest 'an empty line is an empty PIN, not the end of input' => sub {
    my $r = with_stdin("\nnext\n", sub {
        return (
            OCP::Password::prompt_password('Enter PIN1 (cluster access): '),
            OCP::Password::prompt_password('Confirm PIN1: '),
        );
    });
    is $r->{died}, '', 'no error';
    is_deeply $r->{result}, [ '', 'next' ],
        'the empty line is consumed as "" and the next prompt gets the next line';
};

subtest 'EOF dies loudly, naming the PIN that was expected' => sub {
    $TTY_READS = 0;
    my $r = with_stdin("pin1\n", sub {
        OCP::Password::prompt_password('Enter PIN1 (cluster access): ');
        OCP::Password::prompt_password('Enter PIN2 (admin-key): ');
        fail 'must not get past the missing line';
    });

    like $r->{died}, qr/--pins-stdin/, 'the death names the flag';
    like $r->{died}, qr/Enter PIN2 \(admin-key\)/,
        'and the PIN that had no line';
    unlike $r->{died}, qr/Enter PIN1/, 'not the one that was answered';
    like $r->{died}, qr/\n\z/, 'a user-facing message, not an internal error';
    is $TTY_READS, 0, 'no fallback to the terminal after STDIN ran dry';

    my $empty = with_stdin('', sub {
        OCP::Password::prompt_password('Confirm PIN1: ');
    });
    like $empty->{died}, qr/Confirm PIN1/, 'an empty STDIN dies at the first prompt';
};

subtest 'without --pins-stdin the terminal path is unchanged' => sub {
    $TTY_READS = 0;
    my $r = with_stdin("not-this\n", sub {
        OCP::Password::prompt_password('Enter PIN1 (cluster access): ');
    }, pins_stdin => 0);
    is $r->{died}, '', 'no error';
    is_deeply $r->{result}, ['from-the-tty'], 'read through Term::ReadKey';
    ok $TTY_READS > 0, 'which was reached';
};

subtest '--pins-stdin is an option on every command' => sub {
    local $OCP::Password::PINS_STDIN;

    # Every class that consumes OCP::Role::Cmd, found in the source rather
    # than listed, so a new command cannot quietly miss the flag.
    my @classes;
    path('lib/OCP/Cmd')->visit(sub {
        my ($file) = @_;
        return unless $file =~ /\.pm\z/;
        return unless $file->slurp_utf8 =~ /^with 'OCP::Role::Cmd'/m;
        (my $class = $file->relative('lib')) =~ s{/}{::}g;
        $class =~ s/\.pm\z//;
        push @classes, $class;
    }, { recurse => 1 });
    ok @classes > 10, 'found the command classes (' . scalar(@classes) . ')';

    for my $class (sort @classes) {
        (my $file = "$class.pm") =~ s{::}{/}g;
        require $file;
        my %data = $class->_options_data;
        ok exists $data{pins_stdin}, "$class takes --pins-stdin";
    }

    {
        local @ARGV = ('--pins-stdin');
        my $apply = OCP::Cmd::Apply->new_with_options(command_chain => [OCP->new]);
        ok $apply->pins_stdin, '--pins-stdin parses';
        ok $OCP::Password::PINS_STDIN, 'and switches OCP::Password to STDIN';
    }

    {
        local $OCP::Password::PINS_STDIN;
        local @ARGV = ();
        my $apply = OCP::Cmd::Apply->new_with_options(command_chain => [OCP->new]);
        ok !$apply->pins_stdin, 'off by default';
        ok !$OCP::Password::PINS_STDIN, 'and OCP::Password stays on the terminal';
    }
};

subtest 'ClusterKey: --pins-stdin counts as someone to ask' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8("name: t\ncontrol_planes:\n  provider: hetzner\n");
    my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);

    my $got_pin;
    no warnings 'redefine';
    local *OCP::Secrets::ensure_age_key = sub { 1 };
    local *OCP::Keys::get_admin_key     = sub { $got_pin = $_[1]; { name => 'admin' } };
    local $OCP::ClusterKey::INTERACTIVE;   # ask the terminal, which is a pipe here

    my $r = with_stdin("pin-two\n", sub {
        OCP::ClusterKey::_unlock_admin_key($config, 'hetzner', reason => 'test');
    });
    is $r->{died}, '', 'no "there is no terminal to ask on" refusal';
    is $got_pin, 'pin-two', 'PIN2 came from STDIN';

    my $off = with_stdin("pin-two\n", sub {
        OCP::ClusterKey::_unlock_admin_key($config, 'hetzner', reason => 'test');
    }, pins_stdin => 0);
    like $off->{died}, qr/no terminal to ask on/,
        'without the flag a piped STDIN is still refused before asking';
};

subtest 'secure-mode ocp init runs non-interactively off STDIN' => sub {
    plan skip_all => 'needs ssh-keygen'
        unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

    my $dir = tempdir(CLEANUP => 1);
    my $cwd = getcwd();

    my $init = OCP::Cmd::Init->new(
        command_chain => [OCP->new],
        nogit         => 1,
        name          => 'pinsstdin',
        provider      => 'ssh',
        host          => '10.0.0.1',
        pins_stdin    => 1,
    );

    chdir $dir or die "chdir: $!";
    my $r = with_stdin("one-1\none-1\ntwo-2\ntwo-2\n", sub { $init->execute([], []) });
    chdir $cwd or die "chdir back: $!";

    is $r->{died}, '', 'init completed' or diag $r->{out}, $r->{err};
    like $r->{err}, qr/Enter PIN1.*Confirm PIN1.*Enter PIN2.*Confirm PIN2/s,
        'four prompts, in that order, all on STDERR';

    my $secrets = OCP::Secrets->new(project_dir => path($dir));
    ok $secrets->has_age_key_enc, 'age.key.enc written';
    my $age_key = eval {
        OCP::Password::decrypt_age_key(path($dir)->child('age.key.enc')->slurp, 'one-1')
    };
    ok $age_key, 'and it opens with the PIN1 fed on line 1' or diag $@;

    my $admin = do {
        my $here = getcwd();
        chdir $dir or die;
        my $k = eval { OCP::Keys->new(project_dir => path('.'))->get_admin_key('two-2') };
        chdir $here or die;
        $k;
    };
    ok $admin, 'the admin key opens with the PIN2 fed on line 3';
};

subtest 'secure-mode init: a mismatched confirmation line still refuses' => sub {
    plan skip_all => 'needs ssh-keygen'
        unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

    my $dir = tempdir(CLEANUP => 1);
    my $cwd = getcwd();
    my $init = OCP::Cmd::Init->new(
        command_chain => [OCP->new],
        nogit => 1, name => 'mismatch', provider => 'ssh', host => '10.0.0.1',
        pins_stdin => 1,
    );
    chdir $dir or die "chdir: $!";
    my $r = with_stdin("one-1\nother\n", sub { $init->execute([], []) });
    chdir $cwd or die "chdir back: $!";

    like $r->{died}, qr/PIN1 passwords don't match/, 'refused';
};

# The Hetzner token prompt is hidden input through the same function, so under
# --pins-stdin it is the next line too -- never a TTY read after the PINs.
subtest 'init --hetzner: the token is the next STDIN line' => sub {
    plan skip_all => 'needs ssh-keygen'
        unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

    local $ENV{HETZNER_API_TOKEN} = '';
    my $cwd = getcwd();

    my $dir = tempdir(CLEANUP => 1);
    my $init = OCP::Cmd::Init->new(
        command_chain => [OCP->new], nogit => 1, name => 'tok',
        hetzner => 1, nopassword => 1, _interactive => 0, pins_stdin => 1,
    );
    chdir $dir or die "chdir: $!";
    my $r = with_stdin("token-line\n", sub { $init->execute([], []) });
    chdir $cwd or die "chdir back: $!";

    is $r->{died}, '', 'init completed' or diag $r->{out};
    is(OCP::Secrets->new(project_dir => path($dir))->hetzner_token, 'token-line',
        'the stored token is the STDIN line');

    my $dir2 = tempdir(CLEANUP => 1);
    my $init2 = OCP::Cmd::Init->new(
        command_chain => [OCP->new], nogit => 1, name => 'tok',
        hetzner => 1, nopassword => 1, _interactive => 0, pins_stdin => 1,
    );
    chdir $dir2 or die "chdir: $!";
    my $r2 = with_stdin('', sub { $init2->execute([], []) });
    chdir $cwd or die "chdir back: $!";
    like $r2->{died}, qr/no line left for 'Enter Hetzner API token'/,
        'a missing token line dies by name';
};

done_testing;

#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS qw(encode_json);
use Module::Runtime qw(use_module);
use Path::Tiny qw(path);
use POSIX ();

use lib 'lib';

use WWW::Hetzner::HTTPResponse;
use WWW::Hetzner::LWPIO;

use OCP;
use OCP::Password;
use OCP::Secrets;

#
# k383: since k370, `ocp hetzner list` without HETZNER_API_TOKEN reads the
# token out of secrets.yaml, and on a clone -- no .ocp/, the project key
# behind PIN1 in age.key.enc -- that asks for PIN1 first. Every other command
# that can ask for a PIN takes --pins-stdin (k166) from OCP::Role::Cmd;
# OCP::Cmd::Hetzner::List did not consume that role, so
# `ocp hetzner list --pins-stdin` died "Unknown option: pins-stdin" and the
# PIN1 could only come from a terminal.
#
# The claims:
#   1. every command reachable from `ocp` takes --pins-stdin -- derived from
#      the command map, so a command that never consumes OCP::Role::Cmd is
#      seen too (t/95 lists the classes that consume it, which is how this
#      one went unnoticed);
#   2. `ocp hetzner list --pins-stdin` on a clone, PIN1 the one line on STDIN:
#      PIN1 is asked on STDERR and read off STDIN, never the terminal, the
#      token comes out of secrets.yaml, the listing goes out with it and is
#      printed, and the unlocked key is cached in .ocp/ as on every command;
#   3. the semantics are the option's own: a STDIN with no line left for
#      PIN1 is a refusal that names the prompt -- not a "wrong PIN1", not a
#      fallback to the terminal -- and nothing reaches the API.
#
# The wire is the only fake, as in t/373: the client is the real
# WWW::Hetzner::Cloud the command builds from the token it read. It answers
# the listing only when the request carries the token from secrets.yaml.
#

no warnings 'once';

umask 022;

delete local $ENV{HETZNER_API_TOKEN};
delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};

my $PIN1   = 'pin1-k383';
my $TOKEN  = 'hzTOKEN-k383-secrets-0123456789';
my $PROMPT = 'Enter PIN1 (cluster access): ';

local @ARGV = ();
my $ocp = OCP->new;

# ---------------------------------------------------------------- claim 1

subtest 'every command reachable from ocp takes --pins-stdin' => sub {
    my @todo = values %{ OCP::_command_map('OCP') };
    my %seen;
    while (my $class = shift @todo) {
        next if $seen{$class}++;
        use_module($class);
        push @todo, values %{ OCP::_command_map($class) };
    }
    ok exists $seen{'OCP::Cmd::Hetzner::List'}, 'the walk reaches ocp hetzner list';
    ok keys(%seen) > 10, 'and the other commands (' . keys(%seen) . ')';

    for my $class (sort keys %seen) {
        my %data = $class->_options_data;
        ok exists $data{pins_stdin}, "$class takes --pins-stdin";
    }
};

# ---------------------------------------------------------------- fixture

# A secure-mode project as the machine that made it has it: the project key in
# .ocp/ and behind PIN1 in age.key.enc, the Hetzner token in secrets.yaml, an
# ocp.yaml. A clone gets the committed files and no .ocp/.
sub origin {
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);
    $s->create_secrets(hetzner_token => $TOKEN);
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k383',
        control_planes => { provider => 'ssh', host => 'cp.k383.invalid' },
    });
    return $dir;
}

sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

my $origin = origin();
ok -f $origin->child('age.key.enc'), 'fixture: age.key.enc';
ok -f $origin->child('secrets.yaml'), 'fixture: secrets.yaml';

# ---------------------------------------------------------------- the run

our $LOG;               # file the child writes what happened on the side to

sub note_side {
    open my $fh, '>>', $LOG or die "log: $!";
    print {$fh} "@_\n";
    close $fh;
}

# The listing, answered only for the token in secrets.yaml; anything else is
# refused as the API refuses it.
sub wire {
    my ($io, $req) = @_;
    (my $path = $req->url) =~ s{\Ahttps://api\.hetzner\.cloud/v1}{};
    ($path) = split /\?/, $path;
    my $auth = $req->headers->{Authorization} // '';
    note_side('REQUEST', $req->method, $path, $auth);

    return WWW::Hetzner::HTTPResponse->new(status => 401, content => "Unauthorized\n")
        unless $req->method eq 'GET' && $path eq '/servers' && $auth eq "Bearer $TOKEN";

    return WWW::Hetzner::HTTPResponse->new(status => 200, content => encode_json({
        servers => [ {
            id          => 383,
            name        => 'k383-police1',
            status      => 'running',
            public_net  => { ipv4 => { ip => '203.0.113.83' } },
            server_type => { id => 1, name => 'cx22' },
            location    => { name => 'fsn1' },
            image       => { name => 'debian-13' },
            labels      => { 'ocp-cluster' => 'k383' },
        } ],
        meta => { pagination => { page => 1, next_page => undef } },
    }));
}

# `ocp @argv` the way bin/ocp runs it -- OCP->run_cli -- in a child, so its
# working directory, its exit and the process-wide PIN switch stay there: in
# $dir, $stdin as STDIN, the wire fake, the terminal reads counted.
sub run_ocp {
    my ($dir, $stdin, @argv) = @_;
    my ($in, $out, $err, $log) = map { Path::Tiny->tempfile } 1 .. 4;
    $in->spew($stdin);

    my $pid = fork // die "fork: $!";
    unless ($pid) {
        local $LOG = "$log";
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        open STDIN,  '<', "$in"  or die;
        open STDOUT, '>', "$out" or die;
        open STDERR, '>', "$err" or die;
        alarm 120;
        no warnings 'redefine';
        *WWW::Hetzner::LWPIO::call = \&wire;
        *OCP::Password::ReadMode   = sub { note_side('TERMINAL', 'ReadMode'); return };
        *OCP::Password::ReadLine   = sub { note_side('TERMINAL', 'ReadLine'); return };
        @ARGV = @argv;
        my $code = OCP->run_cli;
        close STDOUT;
        close STDERR;
        POSIX::_exit($code);
    }
    waitpid $pid, 0;
    my $st = $?;
    my @side = -s $log ? $log->lines_utf8({ chomp => 1 }) : ();
    return {
        signal   => $st & 127,
        exit     => $st >> 8,
        out      => $out->slurp_utf8,
        err      => $err->slurp_utf8,
        requests => [ grep { /\AREQUEST / } @side ],
        terminal => [ grep { /\ATERMINAL / } @side ],
    };
}

# ---------------------------------------------------------------- claim 2

subtest 'ocp hetzner list --pins-stdin on a clone: PIN1 off STDIN, the listing' => sub {
    my $clone = clone_of($origin);
    ok !-e $clone->child('.ocp'), 'the clone has no .ocp/';

    my $r = run_ocp($clone, "$PIN1\n", 'hetzner', 'list', '--pins-stdin');
    is $r->{signal}, 0, 'no signal (alarm)';
    is $r->{exit}, 0, 'exit 0' or diag "STDERR:\n$r->{err}";
    unlike $r->{err}, qr/Unknown option/, 'the option is known';
    like $r->{err}, qr/\Q$PROMPT\E/, 'PIN1 asked, on STDERR';
    is_deeply $r->{terminal}, [], 'and read off STDIN: the terminal is never touched';
    is_deeply $r->{requests}, [ "REQUEST GET /servers Bearer $TOKEN" ],
        'the listing went out with the token from secrets.yaml';
    like $r->{out}, qr/^383\s+k383-police1\s+running\s+203\.0\.113\.83\s+cx22\s+ocp-cluster=k383$/m,
        'and the listing is on STDOUT';
    unlike $r->{out}, qr/PIN1/, 'the prompt is not';
    unlike "$r->{out}$r->{err}", qr/\Q$TOKEN\E/, 'the token is printed nowhere';
    ok -f $clone->child('.ocp', 'age.key'), 'the unlocked key is cached in .ocp/';

    # The same option as everywhere: the underscored spelling, after --label.
    my $again = run_ocp(clone_of($origin), "$PIN1\n",
        'hetzner', 'list', '--label', 'ocp-cluster=k383', '--pins_stdin');
    is $again->{exit}, 0, '--label ... --pins_stdin: exit 0' or diag "STDERR:\n$again->{err}";
    like $again->{out}, qr/k383-police1/, '--label ... --pins_stdin: the listing';
    is_deeply $again->{terminal}, [], '--label ... --pins_stdin: no terminal';
};

# ---------------------------------------------------------------- claim 3

subtest 'ocp hetzner list --pins-stdin with no line for PIN1: refused by name' => sub {
    my $clone = clone_of($origin);
    my $r = run_ocp($clone, '', 'hetzner', 'list', '--pins-stdin');
    is $r->{signal}, 0, 'no signal (alarm)';
    isnt $r->{exit}, 0, 'exit non-zero';
    like $r->{err}, qr/^Error: --pins-stdin: STDIN has no line left for 'Enter PIN1 \(cluster access\)'\./m,
        'the refusal names the option and the prompt';
    unlike $r->{err}, qr/internal error| line \d+\./, 'no Perl error text';
    is_deeply $r->{terminal}, [], 'no fallback to the terminal';
    is_deeply $r->{requests}, [], 'nothing reaches the API';
    is $r->{out}, '', 'nothing on STDOUT';
    ok !-e $clone->child('.ocp', 'age.key'), 'nothing cached';
};

done_testing;

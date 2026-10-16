#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Cwd qw(getcwd);

use lib 'lib';

use OCP;
use OCP::Cmd::Init;
use OCP::Cmd::Keys::AuthorizedKeys;
use OCP::Cmd::Node::Add;
use OCP::Keys;
use OCP::Node;
use OCP::SSH;

#
# k209: in secure mode two keys reach a cluster's machines. robocop joins and
# tears down workers with the robo key (purpose automation); the CLI -- `ocp
# node rm`, `ocp ssh`, a join from `ocp node add` -- with the admin key. So an
# ssh-provider worker needs BOTH public keys in authorized_keys, and nothing
# said so: `ocp init` called the admin key "all of it", OCP::ClusterKey "always
# admin", and a refused robocop join advised `ocp inject-key`, which writes no
# authorized_keys anywhere. Live: a robocop join went through on the robo key,
# `ocp node rm` was refused and left the node Failed with rke2 still running.
#
# What this file holds the code to:
#
#   * `ocp keys authorized-keys` prints exactly the authorized_keys lines --
#     admin + robo by default -- on STDOUT, everything else on STDERR, PIN1 at
#     most and never PIN2; dev mode's single key for any purpose.
#   * a refused key whose purpose is known names the missing key and the
#     command that installs it, and the two-key rule; OCP::Node hands the
#     purpose on, the CLI paths say admin, robocop says automation.
#   * `ocp init` and `ocp node add` say the rule before it bites.
#

plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

my $PIN = 'test-pin-1234';

# One secure-mode project for the command tests: real keys.yaml, real age key.
my $project = run_init(provider => 'ssh', host => 'cp.example.test');
is $project->{err}, '', 'secure init completed' or diag $project->{out};

my $keys = OCP::Keys->new(project_dir => $project->{dir});
my ($ADMIN) = grep { ($_->{purpose} // '') eq 'admin' }      @{ $keys->list_keys };
my ($ROBO)  = grep { ($_->{purpose} // '') eq 'automation' } @{ $keys->list_keys };
ok $ADMIN && $ROBO, 'init wrote an admin and a robo key';

# --------------------------------------------------------- the command

subtest 'default: admin + robo, and nothing but the two lines on STDOUT' => sub {
    my $r = run_cmd($project->{dir});

    is $r->{err}, '', 'it succeeds';
    is $r->{rv}, 0, 'and returns 0';
    is $r->{out}, $ADMIN->{public} . "\n" . $ROBO->{public} . "\n",
        'STDOUT is exactly the admin then the robo public key -- pipeable into authorized_keys';
    like $r->{diag}, qr/\Q$ADMIN->{name}\E \(admin, /, 'the admin key is named on STDERR';
    like $r->{diag}, qr/\Q$ROBO->{name}\E \(automation, .*robocop/,
        'and the robo key, with what it is for';
    unlike $r->{diag}, qr/ssh-ed25519/, 'no key material on STDERR';
};

subtest '--purpose admin and --purpose automation pick one key each' => sub {
    my $admin = run_cmd($project->{dir}, purpose => 'admin');
    is $admin->{out}, $ADMIN->{public} . "\n", 'admin: the admin key alone';

    my $robo = run_cmd($project->{dir}, purpose => 'automation');
    is $robo->{out}, $ROBO->{public} . "\n", 'automation: the robo key alone';

    my $all = run_cmd($project->{dir}, purpose => 'all');
    is $all->{out}, $admin->{out} . $robo->{out}, 'all: both, admin first';
};

subtest 'never PIN2, and PIN1 only when age.key is locked' => sub {
    my $r = run_cmd($project->{dir});
    is_deeply $r->{prompts}, [], 'age.key unlocked: no prompt at all';

    $project->{dir}->child('.ocp', 'age.key')->remove;
    my $locked = run_cmd($project->{dir});
    is $locked->{err}, '', 'with age.key locked it still works' or diag $locked->{err};
    is scalar @{ $locked->{prompts} }, 1, 'one prompt';
    like $locked->{prompts}[0], qr/PIN1/, 'and it is PIN1';
    unlike join('', @{ $locked->{prompts} }), qr/PIN2/, 'never PIN2';
    is $locked->{out}, $r->{out}, 'same lines as before';

    # Public halves only, ever: the PIN2-protected private half of the admin
    # key and the robo private key are nowhere in the output.
    for my $key ($ADMIN, $ROBO) {
        my $private = $keys->decrypt_key($key->{name},
            $key->{purpose} eq 'automation' ? () : $PIN)->{private};
        unlike $r->{out} . $r->{diag}, qr/\Q$private\E/,
            "no private half of $key->{name}";
    }
};

subtest 'an unknown purpose is refused before anything is unlocked' => sub {
    $project->{dir}->child('.ocp', 'age.key')->remove;
    my $r = run_cmd($project->{dir}, purpose => 'general');

    like $r->{err}, qr/^Unknown key purpose 'general'\.\n/, 'names what it did not understand';
    like $r->{err}, qr/^Available: admin, all, automation$/m, 'and what would have worked';
    is $r->{out}, '', 'nothing on STDOUT';
    is_deeply $r->{prompts}, [], 'a typo costs no PIN1 prompt';

    # Unlock again for what follows.
    run_cmd($project->{dir}, purpose => 'admin');
    ok -f $project->{dir}->child('.ocp', 'age.key'), 'age.key is back';
};

subtest 'dispatches as `ocp keys authorized-keys`, and only there' => sub {
    my @argv = ('keys', 'authorized-keys', '--purpose', 'admin');
    eval { OCP::_resolve_commands('OCP', \@argv) };
    is $@, '', 'resolves';
    is_deeply \@argv, [ 'keys', 'authorizedkeys', '--purpose', 'admin' ],
        'to the command MooX::Cmd knows as authorizedkeys';

    my @typo = ('keys', 'nope');
    eval { OCP::_resolve_commands('OCP', \@typo) };
    like $@, qr/^Available: authorized-keys, recipients, secure, show$/m,
        'a wrong word under keys lists it in its readable spelling';

    my @root = ('authorized-keys');
    eval { OCP::_resolve_commands('OCP', \@root) };
    like $@, qr/^Unknown command 'authorized-keys' for 'ocp'\./,
        'the alias belongs to `ocp keys`, not to the root';

    my @old = ('deploy-image');
    eval { OCP::_resolve_commands('OCP', \@old) };
    is_deeply \@old, ['deployimage'], 'root aliases still resolve';
};

subtest 'dev mode: the one key there is, for any purpose, once' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('.ocp', 'id_ed25519.pub')->spew("ssh-ed25519 AAAAdev dev\n");

    for my $purpose (undef, qw(admin automation all)) {
        my $label = $purpose // 'default';
        my $r = run_cmd($dir, defined $purpose ? (purpose => $purpose) : ());
        is $r->{err}, '', "$label: succeeds";
        is $r->{out}, "ssh-ed25519 AAAAdev dev\n", "$label: the bootstrap public key, once";
        like $r->{diag}, qr/Dev mode .*only key/s, "$label: STDERR says dev mode has only this key";
        is_deeply $r->{prompts}, [], "$label: no prompt";
    }

    $dir->child('.ocp', 'id_ed25519.pub')->remove;
    my $none = run_cmd($dir);
    like $none->{err}, qr/id_ed25519\.pub/, 'no key at all: says which file is missing';
    is $none->{out}, '', 'and prints nothing';
};

subtest 'a missing key fails by name and prints nothing' => sub {
    # Last on the shared project: it removes the robo key.
    ok $keys->delete_key($ROBO->{name}), 'robo key removed from keys.yaml';

    my $r = run_cmd($project->{dir});
    like $r->{err}, qr/No robo key \(purpose automation\)/, 'names the missing key';
    like $r->{err}, qr/Nothing was printed/, 'and that nothing was printed';
    is $r->{out}, '', 'not even the admin key that does exist -- half a set looks complete';

    my $admin = run_cmd($project->{dir}, purpose => 'admin');
    is $admin->{out}, $ADMIN->{public} . "\n", '--purpose admin still works';

    my ($stderr, $rc) = reported($r->{err});
    isnt $rc, 0, 'the CLI exits non-zero';
};

# --------------------------------------------- the refusal names the key

sub refusal {
    my (%args) = @_;
    my $ssh = OCP::SSH->new(host => 'crag.example', user => 'root',
        key_file => '/nonexistent/key', %args);
    no warnings 'redefine';
    local *OCP::SSH::run = sub { { exit => 255, stdout => '',
        stderr => "root\@crag.example: Permission denied (publickey).\n" } };
    eval { $ssh->wait_for_ssh(120, 2) };
    return $@;
}

subtest 'robocop refused: the robo key, the command, both keys' => sub {
    my $err = refusal(key_label => 'the robo key', key_purpose => 'automation');

    like $err, qr/key rejected by crag\.example: user root with the robo key/,
        'still names host, user and key (k204, k226)';
    like $err, qr/the robo key \(purpose automation\), which robocop joins/,
        'names the missing key and who uses it';
    like $err, qr{ocp keys authorized-keys --purpose automation \| ssh root\@crag\.example 'cat >> ~/\.ssh/authorized_keys'},
        'and the command that installs it on this host';
    like $err, qr/needs both keys, admin and robo/, 'states the two-key rule';
    like $err, qr/'ocp keys authorized-keys' without --purpose prints both/,
        'and how to print both';
    unlike $err, qr/inject-key/, 'no inject-key: it writes no authorized_keys';
};

subtest 'CLI refused: the admin key' => sub {
    my $err = refusal(key_purpose => 'admin');
    like $err, qr/the admin key \(purpose admin\), which ocp apply, ocp ssh and ocp node add\/rm/,
        'names the admin key and who uses it';
    like $err, qr/ocp keys authorized-keys --purpose admin \| ssh root\@crag\.example/,
        'and the command for it';
    like $err, qr/needs both keys/, 'states the two-key rule';
    unlike $err, qr/inject-key/, 'no inject-key';
};

subtest 'no purpose: the message is what it was' => sub {
    my $err = refusal();
    like $err, qr/Add the public key there \(ocp inject-key, or by hand\) and run again\.\n\z/,
        'unchanged for a caller that does not say (dev mode bootstrap key)';
    unlike $err, qr/authorized-keys/, 'no purpose-specific advice';

    ok !eval { OCP::SSH->new(host => 'h', key_purpose => 'general'); 1 },
        'a purpose that is not admin or automation is refused';
    like $@, qr/key_purpose must be admin or automation/, 'by name';
};

# ------------------------------------- the purpose travels Node -> SSH

{
    package FakeSSH209;
    our %args;
    sub new { my ($c, %a) = @_; %args = %a; bless {%a}, $c }
    sub wait_for_ssh { die "refused\n" }
}

subtest 'OCP::Node hands ssh_key_purpose to OCP::SSH as key_purpose' => sub {
    my $build = sub {
        my $node = OCP::Node->new(
            cr  => { metadata => { name => 'w1', namespace => 'ocp-system' },
                     spec     => { role => 'worker', providerRef => 'ssh-default',
                                   host => '10.0.0.5' },
                     status   => { phase => 'Installing' } },
            k8s => bless({}, 'NoK8s'),
            ssh_key   => 'K',
            ssh_class => 'FakeSSH209',
            rex_class => 'FakeSSH209',
            @_,
        );
        no warnings 'redefine';
        local *OCP::Node::_resolve_host = sub { '10.0.0.5' };
        my $status;
        local *OCP::Node::_patch_status = sub { my ($s, %p) = @_; $status = \%p };
        %FakeSSH209::args = ();
        $node->_install_kubernetes;
        return $status;
    };

    my $status = $build->(ssh_key_label => 'the robo key', ssh_key_purpose => 'automation');
    is $FakeSSH209::args{key_purpose}, 'automation', 'robocop: automation reaches OCP::SSH';
    is $FakeSSH209::args{key_label}, 'the robo key', 'next to the label';
    is $status->{phase}, 'Failed', 'the refusal still fails the node';

    $build->(ssh_key_purpose => 'admin');
    is $FakeSSH209::args{key_purpose}, 'admin', 'CLI: admin reaches OCP::SSH';

    $build->();
    ok !exists $FakeSSH209::args{key_purpose}, 'none given, none passed -- OCP::SSH keeps the generic text';
};

subtest 'who passes which purpose' => sub {
    # robocop holds the robo key; both of its from_cr sites say so. Only those
    # lines are touched in the controller (its lease logic is k171's).
    my $rc = path('lib/OCP/Robocop/Controller.pm')->slurp_utf8;
    is scalar(() = $rc =~ /ssh_key_label => 'the robo key',\n\s*ssh_key_purpose => 'automation',/g), 2,
        'robocop: automation, at both OCP::Node sites';

    # The CLI paths hold an OCP::ClusterKey: admin in secure mode, the
    # bootstrap key (no purpose) in dev mode.
    for my $file (qw( lib/OCP/Cmd/Node/Add.pm lib/OCP/Cmd/Apply/CR.pm )) {
        like path($file)->slurp_utf8,
            qr/\$key && \$key->origin eq 'admin' \? \(ssh_key_purpose => 'admin'\) : \(\)/,
            "$file: admin when the key is the admin key";
    }
    like path('lib/OCP/Cmd/Apply/Bootstrap.pm')->slurp_utf8,
        qr/\$key->origin eq 'admin' \? \(key_purpose => 'admin'\) : \(\)/,
        'Bootstrap: admin on the control plane wait';
};

# --------------------------------------------------- said before it bites

subtest 'ocp init (secure + ssh) names both keys and the command' => sub {
    my $out = $project->{out};
    unlike $out, qr/That one key is all of it/, 'the old claim is gone';
    like $out, qr/Every ssh worker needs BOTH/, 'workers need both keys';
    like $out, qr/robo\s+robocop, which joins and tears down workers/, 'names the robo key and its user';
    like $out, qr/control plane needs this one/, 'the control plane needs the admin key';
    like $out, qr/^  ocp keys authorized-keys\s+# admin \+ robo/m, 'the command for a worker';
    like $out, qr/^  ocp keys authorized-keys --purpose admin\s+# admin/m, 'and for a control plane';
    unlike $out, qr/ocp keys show --purpose admin/, 'no longer the main hint';
};

{
    package FakeList209;
    sub new   { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]{items} }

    package FakeIO209;
    sub new              { bless {}, $_[0] }
    sub object_to_struct { $_[1] }

    package FakeK8s209;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s     { FakeIO209->new }
    sub list    { FakeList209->new($_[0]{providers}) }
    sub get     { my ($s, $kind, %a) = @_;
                  ($kind eq 'OCPNodeProvider') ? $s->{providers}[0] : undef }
    sub ensure  { $_[1] }
}

sub node_add {
    my (%arg) = @_;

    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('keys.yaml')->spew("sops: {}\n") if $arg{secure};

    my $provider = {
        metadata => { name => "$arg{type}-a", namespace => 'ocp-system', annotations => {} },
        spec     => { type => $arg{type} },
    };
    my $add = OCP::Cmd::Node::Add->new(
        command_chain => [OCP->new],
        k8s           => FakeK8s209->new(providers => [$provider]),
        name          => 'crag',
        ($arg{type} eq 'ssh' ? (host => 'crag.example') : ()),
        ($arg{nowait} ? (nowait => 1) : ()),
    );

    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my ($out, $diag, $rv) = ('', '');
    {
        no warnings 'redefine';
        local *OCP::Cmd::Node::Add::_robocop_ready = sub { 0 };
        local *OCP::Cmd::Node::Add::_cli_reconcile = sub { 1 };
        open my $fh,  '>', \$out  or die $!;
        open my $efh, '>', \$diag or die $!;
        local *STDOUT = $fh;
        local *STDERR = $efh;
        $rv = eval { $add->execute([], []) };
    }
    my $err = $@;
    chdir $cwd or die "chdir back: $!";

    return { out => $out, diag => $diag, err => $err, rv => $rv };
}

subtest 'ocp node add on an ssh provider in secure mode says both keys first' => sub {
    my $r = node_add(type => 'ssh', secure => 1);
    is $r->{err}, '', 'ran' or diag $r->{err};
    like $r->{out}, qr/^  \[\.\.\] Host crag\.example needs both public keys in root's authorized_keys/m,
        'an [..] line on STDOUT names the host and the rule';
    like $r->{out}, qr/robo for robocop, admin for the CLI and `ocp node rm`\. `ocp keys authorized-keys` prints both\./,
        'which key for whom, and the command';
    like $r->{out}, qr/\[\.\.\] Host crag.*\n(?s:.*)is Ready/, 'before the join, not after';

    my $nowait = node_add(type => 'ssh', secure => 1, nowait => 1);
    is $nowait->{out}, "crag\n", '--nowait: STDOUT stays the node name alone';
    like $nowait->{diag}, qr/needs both public keys/, 'the note goes to STDERR there';

    my $dev = node_add(type => 'ssh');
    unlike $dev->{out} . $dev->{diag}, qr/both public keys/, 'dev mode: one key, nothing to say';

    my $hetzner = node_add(type => 'hetzner', secure => 1);
    unlike $hetzner->{out} . $hetzner->{diag}, qr/both public keys/,
        'Hetzner: the API uploads both, nothing to say';
};

# --------------------------------------------------------------- helpers

sub run_init {
    my (%args) = @_;

    my $dir = tempdir(CLEANUP => 1);
    my $init = OCP::Cmd::Init->new(
        command_chain => [OCP->new],
        nogit         => 1,
        name          => 'k209',
        _interactive  => 0,
        %args,
    );

    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my ($out, $diag) = ('', '');
    {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub { $PIN };
        open my $fh,  '>', \$out  or die $!;
        open my $efh, '>', \$diag or die $!;
        local *STDOUT = $fh;
        local *STDERR = $efh;
        eval { $init->execute([], []) };
    }
    my $err = $@ // '';
    chdir $cwd or die "chdir back: $!";

    return { dir => path($dir), out => $out, err => $err };
}

# Run the command in $dir. Prompts are recorded by their text, so "never PIN2"
# is a check on what was asked, not just on how often.
sub run_cmd {
    my ($dir, %args) = @_;

    my $cmd = OCP::Cmd::Keys::AuthorizedKeys->new(command_chain => [OCP->new], %args);

    my @prompts;
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my ($out, $diag, $rv) = ('', '');
    {
        no warnings 'redefine';
        local *OCP::Password::prompt_password = sub { push @prompts, $_[0]; $PIN };
        open my $fh,  '>', \$out  or die $!;
        open my $efh, '>', \$diag or die $!;
        local *STDOUT = $fh;
        local *STDERR = $efh;
        $rv = eval { $cmd->execute([], []) };
    }
    my $err = $@ // '';
    chdir $cwd or die "chdir back: $!";

    return { out => $out, diag => $diag, err => $err, rv => $rv, prompts => \@prompts };
}

# What OCP::run_cli makes of an error: (stderr, exit code).
sub reported {
    my ($err) = @_;
    my $stderr = '';
    my $rc;
    {
        open my $fh, '>', \$stderr or die $!;
        local *STDERR = $fh;
        $rc = OCP::_report_error($err, 0);
    }
    return ($stderr, $rc);
}

sub _have {
    my ($cmd) = @_;
    return system("command -v $cmd >/dev/null 2>&1") == 0;
}

done_testing;

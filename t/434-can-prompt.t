#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP::ClusterKey;
use OCP::Cmd::Destroy;
use OCP::Cmd::Keys::Secure;
use OCP::Password;
use OCP::Secrets;

#
# k434: whether a PIN can be asked was decided in three copies of one rule --
# OCP::ClusterKey's PIN2 guard (_unlock_admin_key), ocp destroy's PIN1 unlock
# (_ssh_key_age_key) and ocp keys secure (_can_prompt). Now there is one
# predicate, OCP::ClusterKey->can_prompt, and every one of them asks it.
#
# The claims:
#   1. the rule itself: $OCP::ClusterKey::INTERACTIVE when defined (0 too),
#      else --pins-stdin, else a terminal on STDIN;
#   2. each consumer follows the predicate and nothing else: with
#      $INTERACTIVE saying the opposite of what can_prompt is made to answer,
#      the consumer goes the predicate's way. A copy of the rule left behind
#      in any of them fails here.
#

no warnings qw( once redefine );

delete local $ENV{SOPS_AGE_KEY_FILE};

# STDIN is no terminal for the whole test, as under a pipe.
open my $null, '<', '/dev/null' or die "open /dev/null: $!";
open STDIN, '<&', $null or die "dup STDIN: $!";

subtest 'the rule' => sub {
    local $OCP::Password::PINS_STDIN;
    local $OCP::ClusterKey::INTERACTIVE;
    ok(!OCP::ClusterKey->can_prompt, 'no terminal, no --pins-stdin: nobody to ask');

    local $OCP::Password::PINS_STDIN = 1;
    ok(OCP::ClusterKey->can_prompt, '--pins-stdin is somebody to ask');

    local $OCP::ClusterKey::INTERACTIVE = 0;
    ok(!OCP::ClusterKey->can_prompt, '$INTERACTIVE = 0 wins over --pins-stdin');

    local $OCP::Password::PINS_STDIN;
    local $OCP::ClusterKey::INTERACTIVE = 1;
    ok(OCP::ClusterKey->can_prompt, '$INTERACTIVE = 1 wins over no terminal');
};

# A predicate that answers $answer, whatever $INTERACTIVE says.
sub forced {
    my ($answer, $code) = @_;
    local *OCP::ClusterKey::can_prompt = sub { $answer };
    local $OCP::ClusterKey::INTERACTIVE = $answer ? 0 : 1;
    local $OCP::Password::PINS_STDIN;
    return $code->();
}

{
    package FakeConfig;
    sub new { bless { dir => $_[1] }, $_[0] }
    sub project_dir { $_[0]{dir} }
}

subtest 'ocp destroy unlocks PIN1 by the predicate' => sub {
    # keys.yaml, the project key only behind PIN1 in age.key.enc: the case
    # that asks.
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('keys.yaml')->spew("x\n");
    $dir->child('age.key.enc')->spew("x\n");
    my $config = FakeConfig->new($dir);

    my $asked = 0;
    local *OCP::Secrets::ensure_age_key = sub { $asked++ };

    forced(1, sub { OCP::Cmd::Destroy::_ssh_key_age_key(undef, $config) });
    is $asked, 1, 'can_prompt true: PIN1 is asked';

    $asked = 0;
    forced(0, sub { OCP::Cmd::Destroy::_ssh_key_age_key(undef, $config) });
    is $asked, 0, 'can_prompt false: no PIN1 asked';
};

subtest 'the PIN2 guard asks the predicate' => sub {
    my $config = FakeConfig->new(path(tempdir(CLEANUP => 1)));

    my $err = forced(0, sub {
        eval { OCP::ClusterKey::_unlock_admin_key($config, 'ssh', reason => 'k434'); 1 }
            ? '' : $@;
    });
    like $err, qr/there is no terminal to ask on/, 'can_prompt false: refused before the prompt';

    my $past = forced(1, sub {
        local *OCP::Secrets::ensure_age_key = sub { die "past the guard\n" };
        eval { OCP::ClusterKey::_unlock_admin_key($config, 'ssh', reason => 'k434'); 1 }
            ? '' : $@;
    });
    is $past, "past the guard\n", 'can_prompt true: on to the unlock';

    my $override = forced(1, sub {
        eval { OCP::ClusterKey::_unlock_admin_key($config, 'ssh', interactive => 0); 1 }
            ? '' : $@;
    });
    like $override, qr/no terminal to ask on/, 'interactive => 0 still overrides the predicate';
};

subtest 'ocp keys secure asks the predicate' => sub {
    my $self = bless {}, 'OCP::Cmd::Keys::Secure';
    ok  forced(1, sub { $self->_can_prompt }), 'can_prompt true';
    ok !forced(0, sub { $self->_can_prompt }), 'can_prompt false';
};

done_testing;

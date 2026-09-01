use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Apply;

#
# `ocp apply` deploys only the first control plane (police1). OCP::Config
# normalises `control_planes` (array form, or `nodes: N`) into an N-element
# arrayref, so a multi-CP spec used to print "Count: N" and silently deploy
# one — the contradiction k8 is about. The interim guard (the full,
# RKE2-only multi-CP feature is tracked separately) is warn-and-proceed:
#
#   * more than one CP configured  -> a loud STDERR warning, and the STDOUT
#     banner no longer implies N are deployed;
#   * exactly one CP               -> unchanged, and no warning at all.
#
# The single-CP path is the one that works today and must stay silent.
#

package FakeConfig {
    sub new { my ($c, @cps) = @_; bless { cps => [@cps] }, $c }
    sub control_planes { $_[0]{cps} }
}

package main;

# Run $code with STDOUT and STDERR captured separately.
sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die $!;
    open my $efh, '>', \$err or die $!;
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $code->();
    }
    return ($out, $err);
}

subtest 'a single control plane stays silent' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my ($out, $err) = capture {
        $apply->_announce_control_planes(
            FakeConfig->new({ provider => 'hetzner' }), 3);
    };

    is $err, '', 'no warning is emitted for a single control plane';
    like $out, qr/Step 3: Deploy control plane/, 'the deploy banner is printed';
    like $out, qr/Count: 1/, 'the honest count for a single CP is reported';
    unlike $out, qr/not yet supported/i,
        'and STDOUT says nothing about an unsupported feature';
};

subtest 'more than one control plane warns on STDERR and proceeds honestly' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my ($out, $err) = capture {
        $apply->_announce_control_planes(
            FakeConfig->new(
                { provider => 'hetzner' },
                { provider => 'hetzner' },
                { provider => 'hetzner' },
            ), 3);
    };

    # The diagnosis belongs on STDERR, never on the STDOUT progress channel.
    like $err, qr/3 control planes/, 'the warning names the configured count';
    like $err, qr/police1/,          'and says what actually gets deployed';
    like $err, qr/not yet supported/i,
        'and that multi-CP is not yet supported';

    # STDOUT must no longer imply that all three are deployed.
    unlike $out, qr/Count: 3/,
        'the STDOUT banner no longer implies N control planes are deployed';
    like $out, qr/deploying 1 \(police1\)/,
        'STDOUT is honest that exactly one is deployed';
};

subtest 'the warning is a warning, not a die — apply proceeds' => sub {
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my $ret;
    my ($out, $err) = capture {
        $ret = $apply->_announce_control_planes(
            FakeConfig->new(
                { provider => 'hetzner' },
                { provider => 'hetzner' },
            ), 2);
    };

    is $ret, 2, 'returns the configured count and returns normally (warn-and-proceed)';
    like $out, qr/Step 2: Deploy control plane/, 'and still prints the banner';
};

done_testing;

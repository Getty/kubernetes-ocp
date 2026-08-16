#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::Cmd::Apply;

#
# _create_cert_issuers used to print the planned issuer list unconditionally
# and send failures to warn() on stderr. A bootstrap where the ClusterIssuer
# CRD was not registered yet therefore announced
#
#     ClusterIssuers created: selfsigned-issuer
#
# while creating nothing at all, and the run looked clean in the log. The
# missing issuer only surfaced later, when a certificate failed to be signed.
#

package FakeApi {
    sub new { bless { }, shift }
}

# Drive _create_cert_issuers with a controllable _server_side_apply.
sub run_issuers {
    my (%opt) = @_;
    my @applied;
    my $out = '';

    no warnings 'redefine';
    local *OCP::Cmd::Apply::_server_side_apply = sub {
        my ($self, $api, $resource) = @_;
        my $name = $resource->{metadata}{name};
        die "webhook not ready\n" if $opt{fail};
        push @applied, $name;
        return 1;
    };
    local *OCP::Cmd::Apply::_k8s_api = sub { FakeApi->new };
    # Keep the test fast: the retry path waits between attempts via
    # OCP::Role::Cmd::wait_seconds (karr #102). That method is the one seam
    # every Apply::* module's retry/poll delay goes through, reached by
    # dispatch on $self — mocking it here works regardless of which module
    # under lib/OCP/Cmd/Apply/ actually calls it. A `local *OCP::Cmd::Apply::
    # sleep` mock used to sit here instead; it aimed at a `sleep` sub that
    # was never called (the retry loop lives in Apply::Network, which calls
    # the CORE::sleep builtin, not a package-qualified one), so the test
    # spent 100+ real seconds asleep despite the mock being green.
    local *OCP::Cmd::Apply::wait_seconds = sub { 1 };

    my $apply = bless {}, 'OCP::Cmd::Apply';
    my $config = bless { ssl_email => '' }, 'FakeConfig';

    open my $fh, '>', \$out or die;
    my $old = select $fh;
    my $died = !eval { $apply->_create_cert_issuers($config); 1 };
    my $err  = $@;
    select $old;
    close $fh;

    return { output => $out, died => $died, error => $err, applied => \@applied };
}

package FakeConfig {
    sub ssl_email { '' }
}

subtest 'success reports the issuer' => sub {
    my $r = run_issuers(fail => 0);

    ok !$r->{died}, 'a successful run does not die';
    is_deeply $r->{applied}, ['selfsigned-issuer'], 'the issuer was applied';
    like $r->{output}, qr/ClusterIssuers created: selfsigned-issuer/,
        'and is reported as created';
};

subtest 'failure is neither silent nor reported as success' => sub {
    my $r = run_issuers(fail => 1);

    is_deeply $r->{applied}, [], 'nothing was applied';

    unlike $r->{output}, qr/ClusterIssuers created: \S/,
        'does NOT claim to have created an issuer';
    like $r->{output}, qr/\[FAILED\] ClusterIssuer selfsigned-issuer/,
        'names the issuer that failed, on stdout where the run is being read';
    ok $r->{died}, 'and the step fails instead of continuing quietly';
    like $r->{error}, qr/selfsigned-issuer/, 'the exception names it too';
};

done_testing;

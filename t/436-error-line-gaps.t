#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Kubernetes::REST::APIError;

use lib 'lib';

use OCP::ErrorLine;
use OCP::Cmd::Apply::K8s;
use OCP::Cmd::Destroy;
use OCP::Drift;

#
# k436: three gaps in OCP::ErrorLine that k403 found and left.
#
#   1. one_line took " at FILE line N." only. Once a line was read from a
#      filehandle -- the PINs --pins-stdin reads -- Perl appends
#      ", <STDIN> line N." to the location, and that remnant stood in every
#      WARN and !! line. It goes now, as OCP.pm's _clean_message takes it.
#   2. OCP::Cmd::Apply::K8s crd_get holds the raw HTTP response, not an
#      APIError, so one_line could not see a 599: LWP's text said its reason
#      twice. The first line of a 599's body stands for it.
#   3. "user_line(err) // one_line(err)" stood written out in OCP::Drift and
#      twice in ocp destroy; OCP::ErrorLine::cause_line is it, once.
#

my $LOCATION = qr/ at \S+ line \d+/;

# --- 1. the filehandle remnant -------------------------------------------------

subtest 'one_line: Perl\'s location after a line read from a filehandle goes whole' => sub {
    open my $fh, '<', \"PIN1\nPIN2\n" or die;
    my $pin  = <$fh>;
    my $died = do { local $@; eval { die 'wrong PIN' }; $@ };
    like $died, qr/ line \d+, <\$fh> line 1\.\n\z/, 'Perl puts the filehandle into the location';
    is OCP::ErrorLine::one_line($died), 'wrong PIN', 'one_line: no remnant of it';

    $pin = <$fh>;
    my $inner = do { local $@; eval { die 'inner' }; $@ };
    my $outer = do { local $@; eval { die "outer: $inner" }; $@ };
    close $fh;
    is OCP::ErrorLine::one_line($outer), 'outer: inner', 'two such locations: both go';

    local $/ = \4;   # a record read: Perl says "chunk N."
    open $fh, '<', \"abcdefgh" or die;
    my $rec  = <$fh>;
    my $chunk = do { local $@; eval { die 'boom' }; $@ };
    close $fh;
    like $chunk, qr/, <\$fh> chunk 1\.\n\z/, 'a record read says chunk';
    is OCP::ErrorLine::one_line($chunk), 'boom', 'one_line: no remnant of that either';
};

# --- 2. crd_get: a 599 says its reason once --------------------------------------

{
    package Resp;
    sub new     { my ($c, $s, $b) = @_; bless { status => $s, content => $b }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }

    package RawApi;
    sub new      { my ($c, $r) = @_; bless { r => $r }, $c }
    sub _request { $_[0]{r} }
}

subtest 'crd_get: a 599 says LWP\'s reason once' => sub {
    my $path = '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';
    my $lwp  = "Can't connect to 10.0.0.1:6443 (Connection refused)\n\n"
             . "Connection refused at /usr/share/perl5/LWP/Protocol/http.pm line 50.";
    eval { OCP::Cmd::Apply::K8s::crd_get({}, RawApi->new(Resp->new(599, $lwp)), $path) };
    is $@, "GET $path failed: HTTP 599 Can't connect to 10.0.0.1:6443 (Connection refused)\n",
        'the first line of the body, said once, no location';

    eval { OCP::Cmd::Apply::K8s::crd_get({}, RawApi->new(Resp->new(599, "\n")), $path) };
    is $@, "GET $path failed: HTTP 599 \n", 'a 599 without a reason: nothing invented';

    eval { OCP::Cmd::Apply::K8s::crd_get({}, RawApi->new(Resp->new(500, "first\nsecond")), $path) };
    is $@, "GET $path failed: HTTP 500 first second\n", 'an answer: its body whole, as one line';
};

# --- 3. cause_line ---------------------------------------------------------------

{
    package Thrower;
    sub api_error { Kubernetes::REST::APIError->throw(@_) }
}

my $E403 = do { local $@; eval { Thrower::api_error(context => 'list OCPNode', code => 403,
    body => '{"kind":"Status","reason":"Forbidden","message":"ocpnodes is forbidden","code":403}') }; $@ };
my $CROAK = do { local $@; eval { die "the client broke\n  second line" }; $@ };

subtest 'cause_line: user_line when it has one, else one_line' => sub {
    OCP::ErrorLine::set_cluster_endpoint('https://10.0.0.1:6443');
    is OCP::ErrorLine::cause_line($E403),
        'The cluster API at https://10.0.0.1:6443 denied the request (403 Forbidden): ocpnodes is forbidden',
        'an APIError: the line naming the server';
    is OCP::ErrorLine::cause_line($CROAK), 'the client broke second line', 'anything else: one_line';
    is OCP::ErrorLine::cause_line(undef, empty => 'no answer'), 'no answer', 'empty goes to one_line';
    is OCP::ErrorLine::cause_line('token s3cr3t-t0ken-here', mask => 's3cr3t-t0ken-here'),
        'token ********', 'mask goes to one_line';
    OCP::ErrorLine::set_cluster_endpoint(undef);
};

subtest 'the three places say it through cause_line' => sub {
    my @seen;
    no warnings 'redefine';
    local *OCP::ErrorLine::cause_line = sub { push @seen, [ @_ ]; 'SAID' };

    is OCP::Drift::_failed_line($E403), 'SAID', 'OCP::Drift _failed_line';

    {
        package ListDies;
        sub new  { bless {}, shift }
        sub list { die $E403 }
    }
    my $destroy = bless { _api_down => 0 }, 'OCP::Cmd::Destroy';
    my @unread;
    local *OCP::Cmd::Destroy::_say_ocpnodes_unread = sub { shift; push @unread, @_ };
    local *OCP::Cmd::Destroy::_api_down            = sub { };
    OCP::Cmd::Destroy::_ocpnode_entries($destroy, ListDies->new);
    is_deeply \@unread, [ 'SAID' ], 'ocp destroy: the OCPNode list that failed';
    is_deeply [ @{ $seen[-1] }[1, 2] ], [ empty => 'no answer' ], '... with its empty';

    my %err;
    local *OCP::Cmd::Destroy::_provider_crs     = sub { { h1 => { metadata => { name => 'h1' },
        spec => { type => 'hetzner', clusterName => 'c' } } } };
    local *OCP::Cmd::Destroy::_cr_hetzner_error = sub { \%err };
    local *OCP::Provider::from_cr               = sub { die $CROAK };
    OCP::Cmd::Destroy::_build_cr_hetzner($destroy, undef, undef);
    is_deeply \%err, { h1 => 'SAID' }, 'ocp destroy: the provider CR without an adapter';
    is_deeply [ @{ $seen[-1] }[1, 2] ], [ empty => 'no adapter' ], '... with its empty';
};

done_testing;

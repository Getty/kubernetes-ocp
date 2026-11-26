#!/usr/bin/env perl
# karr k464 -- the last causes said by hand go through OCP::ErrorLine::cause_line.
#
# cause_line (k436) is user_line // one_line: an exception it knows -- a
# Kubernetes::REST::APIError -- as the line naming what the API did, anything
# else as one line without its source location. Two places in the apply lane
# still said a cause another way:
#
#   * ensure_cp_ocpnode's status write (OCP::Cmd::Apply::CR) used one_line:
#     an APIError from patch_status read as Kubernetes::REST's own text, the
#     raw Status JSON body in the [WARN] line
#   * robocop_dry_run (OCP::Cmd::Apply::Drift) printed its two causes raw,
#     chomped: an APIError as its raw text, a croak with its " at FILE line N."
#
# The claims: each says the APIError as the cluster API's line, and anything
# else without the location -- on STDERR, and in the dry run's error entries.
# Destroy's _stop_robocop and Role::Cmd's cluster_api / provider_crs wrote
# cause_line out by hand: the same text, pinned in t/399 and t/433.
#
# Network-free and cluster-free: fakes answer the reads and writes.

use strict;
use warnings;
use Test::More;

use Kubernetes::REST::APIError;
use Path::Tiny ();
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Apply::K8s;
use OCP::Config;
use OCP::ErrorLine;

local @ARGV = ();
my $ocp = OCP->new;

# No cluster client was built: the line says "The cluster API", no server.
OCP::ErrorLine::set_cluster_endpoint(undef);

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, out => $out, err => $err, died => $died };
}

# What Kubernetes::REST dies with for an HTTP error status.
sub api_error {
    my ($code, $reason, $context) = @_;
    return Kubernetes::REST::APIError->new(
        code    => $code,
        context => $context // 'get',
        body    => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}),
    );
}

{
    package FakeApi;
    sub new              { my ($c, %a) = @_; bless { %a }, $c }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub ensure           { $_[1] }
    sub get {
        my ($s, $kind, $name) = @_;
        return { metadata => { name => $name },
                 status   => { addresses  => [ { type => 'InternalIP', address => '10.0.0.7' } ],
                               conditions => [ { type => 'Ready', status => 'True' } ] } };
    }
    sub patch_status { die $_[0]{status_error} if $_[0]{status_error}; 1 }

    package FakeSelf;
    sub new { bless {}, shift }

    package FakeOCP;
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub load_file { undef }
    sub dump_file { 1 }
}

# --- ensure_cp_ocpnode: the status write ---------------------------------------

subtest 'ensure_cp_ocpnode: a status write the API refused is said by the API line' => sub {
    my $ensure = sub {
        my ($api) = @_;
        return capture { OCP::Cmd::Apply::CR::ensure_cp_ocpnode(FakeSelf->new, $api,
            { name => 'police1', provider => 'ssh', host => 'police1.k464.test' }); 1 };
    };

    my $r = $ensure->(FakeApi->new);
    is $r->{died}, '', 'control: no death' or diag $r->{died};
    is $r->{err}, '', 'control: nothing on STDERR';

    $r = $ensure->(FakeApi->new(status_error => api_error(403, 'Forbidden', 'patch_status')));
    is $r->{died}, '', '403: no death';
    is $r->{err},
        "  [WARN] ensured OCPNode/police1, but its status stayed unwritten: "
      . "The cluster API denied the request (403 Forbidden)\n",
        '403: the cause as the API line';
    unlike $r->{err}, qr/"kind":"Status"|Kubernetes API error| line \d+/,
        '403: no raw Status body, no Kubernetes::REST text, no source location';
};

# --- robocop_dry_run: its two causes -------------------------------------------

my @KEEP;
sub config_for {
    my $dir = Path::Tiny->tempdir;
    push @KEEP, $dir;
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({
        name           => 'k464',
        control_planes => { provider => 'ssh', host => 'police1.k464.test' },
    }));
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify, ocp => $ocp);
}

subtest 'robocop_dry_run: each cause in one line -- no raw APIError, no location' => sub {
    my $config = config_for();
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    $apply->{_k8s_api} = FakeApi->new;

    no warnings 'redefine';
    # The Secret's state dies with what the API answered, unwrapped -- as
    # anything past read_or_absent may (the age key, the robo key).
    local *OCP::Cmd::Apply::_robocop_credentials_state = sub { die api_error(403, 'Forbidden') };
    # The Deployment read dies with a croak's source location on it.
    local *OCP::Cmd::Apply::K8s::read_or_absent =
        sub { die "could not read Deployment ocp-system/robocop: boom at lib/Fake.pm line 12.\n" };

    my $r = capture { [ OCP::Cmd::Apply::Drift::robocop_dry_run($apply, $config, '10.0.0.1') ] };
    is $r->{died}, '', 'the dry run goes on' or diag $r->{died};

    my $secret_cause = 'The cluster API denied the request (403 Forbidden)';
    my $deploy_cause = 'could not read Deployment ocp-system/robocop: boom';
    is $r->{err},
        "  [!!] Secret/robocop-credentials not checked: $secret_cause\n"
      . "  [!!] Deployment/robocop not checked: $deploy_cause\n",
        'STDERR: both causes, each one line';

    my @entries = @{ $r->{rv} // [] };
    is scalar @entries, 2, 'two error entries';
    is $entries[0]{cause},   $secret_cause, 'the Secret entry carries the API line';
    is $entries[0]{message}, "Secret/robocop-credentials: $secret_cause", 'and its message';
    is $entries[1]{cause},   $deploy_cause, 'the Deployment entry carries the cause without its location';
    is $entries[1]{message}, "Deployment/robocop: $deploy_cause", 'and its message';
};

done_testing;

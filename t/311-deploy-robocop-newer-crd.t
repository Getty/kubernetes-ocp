#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use Path::Tiny ();
use Storable qw(dclone);
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::DeployRobocop;
use OCP::Config;

#
# k311: since k291, `ocp apply` (OCP::Cmd::Apply::CR::ensure_crds) leaves a
# cluster CRD that declares fields this ocp's does not -- one a newer ocp
# installed -- as it is, so the API server does not drop those fields from
# every OCPNode. `ocp deploy-robocop` wrote the OCPNode/OCPNodeProvider CRDs
# with ensure() and no such check: an older ocp running it wrote the newer
# CRD over.
#
# The claims here:
#   1. deploy-robocop leaves a newer CRD as it is, with the very [skip] line
#      ensure_crds says -- one judgement (OCP::Cmd::Apply::CR::skip_newer_crd,
#      by OCP::Drift->crd_schema_diff), not a copy -- and still applies the
#      rest of its manifests.
#   2. An older CRD is updated with this ocp's, an absent one (a 404) is
#      installed, the same one is written as before.
#   3. A CRD that cannot be read is not written over blind: deploy-robocop
#      dies with the cause. Only a 404 is "not there" (k269).
#

my $CRD_BASE = '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/';
my $NODE_CRD = 'ocpnodes.ocp.internal';
my $PROV_CRD = 'ocpnodeproviders.ocp.internal';

my %SHIPPED = map { $_->{metadata}{name} => $_ }
    grep { ref $_ eq 'HASH' && ($_->{kind} // '') eq 'CustomResourceDefinition' }
    map { YAML::XS::LoadFile("$_") } sort(Path::Tiny::path('share/robocop/crds')->children(qr/\.ya?ml\z/));

sub v1_props {
    my ($crd, $part) = @_;
    my ($v1) = grep { $_->{name} eq 'v1' } @{ $crd->{spec}{versions} };
    return $v1->{schema}{openAPIV3Schema}{properties}{$part}{properties};
}

# As the apiserver hands a CRD back: JSON, with what it adds on its own.
sub stored {
    my ($crd) = @_;
    my $copy = JSON::PP::decode_json(JSON::PP::encode_json($crd));
    $copy->{spec}{conversion} = { strategy => 'None' };
    $copy->{metadata}{resourceVersion} = '4711';
    $copy->{status} = { acceptedNames => { kind => $crd->{spec}{names}{kind} }, storedVersions => ['v1'] };
    return $copy;
}

# The OCPNode CRD of an OCP from before k254: no nodeIP in spec or status.
my $OLD_NODE = dclone($SHIPPED{$NODE_CRD});
delete v1_props($OLD_NODE, $_)->{nodeIP} for qw(spec status);

# One from an OCP newer than this one: a spec and a status field more.
my $NEWER_NODE = dclone($SHIPPED{$NODE_CRD});
v1_props($NEWER_NODE, 'spec')->{zone}        = { type => 'string' };
v1_props($NEWER_NODE, 'status')->{drainedAt} = { type => 'string', format => 'date-time' };

package FakeResponse {
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }

# A cluster's CRDs by name, served over _request the way the apiserver answers
# a raw GET; a CRD it does not have is a 404. raw_fail answers a name with
# [ status, body ], or dies with a string (no response at all). ensure()
# (deploy-robocop's write) and a raw PATCH (ensure_crds' server-side apply)
# are recorded; there are no robocop pods to retire.
package FakeApi {
    sub new { my ($c, %a) = @_; bless { crds => {}, raw_fail => {}, reads => [], writes => [], %a }, $c }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub expand_class     { undef }
    sub list             { FakeList->new([]) }
    sub ensure {
        my ($self, $doc) = @_;
        push @{ $self->{writes} }, [ ensure => "$doc->{kind}/$doc->{metadata}{name}", $doc ];
        return $doc;
    }
    sub _request {
        my ($self, $method, $path, $body) = @_;
        if ($method ne 'GET') {
            push @{ $self->{writes} }, [ $method => "$body->{kind}/$body->{metadata}{name}", $body ];
            return FakeResponse->new(200, '{}');
        }
        push @{ $self->{reads} }, $path;
        my ($name) = $path =~ m{/customresourcedefinitions/([^/]+)\z}
            or return FakeResponse->new(404, '{"kind":"Status","code":404}');
        if (my $fail = $self->{raw_fail}{$name}) {
            die $fail unless ref $fail;
            return FakeResponse->new(@$fail);
        }
        my $crd = $self->{crds}{$name}
            or return FakeResponse->new(404, '{"kind":"Status","reason":"NotFound","code":404}');
        return FakeResponse->new(200, JSON::PP->new->canonical->utf8->encode($crd));
    }
    sub written { [ map { $_->[1] } @{ $_[0]{writes} } ] }
}

package FakeOCP {
    sub new     { bless {}, shift }
    sub config  { 'x' }
    sub verbose { 0 }
}

package main;

my @KEEP;

sub config {
    my $dir = Path::Tiny->tempdir;
    push @KEEP, $dir;
    $dir->child('ocp.yaml')->spew(<<'YAML');
name: amdlab
kubernetes:
  dist: rke2
control_planes:
  provider: ssh
  host: otho.ocp.invalid
YAML
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# The cluster's CRDs: the shipped ones, then what %crds says (undef: absent).
sub cluster {
    my (%crds) = @_;
    my %have = map { $_ => stored($SHIPPED{$_}) } keys %SHIPPED;
    for my $name (keys %crds) {
        defined $crds{$name} ? ($have{$name} = stored($crds{$name})) : delete $have{$name};
    }
    return \%have;
}

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $o;
        local *STDERR = $e;
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, out => $out, err => $err, died => $died };
}

# `ocp deploy-robocop`'s manifest step against $api.
sub deploy {
    my ($api) = @_;
    my $config = config();
    return capture {
        OCP::Cmd::DeployRobocop->new(command_chain => [ FakeOCP->new ])->_apply_manifests($api, $config);
    };
}

# `ocp apply`'s CRD step against $api.
sub ensure_crds {
    my ($api) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_find_share_dir = sub { Path::Tiny::path('share') };
    return capture { OCP::Cmd::Apply::CR::ensure_crds($apply, $api) };
}

sub skip_lines { [ grep { /\[skip\]/ } split /\n/, $_[0] ] }

my $NEWER_SKIP = "  [skip] CustomResourceDefinition/$NODE_CRD is newer than this ocp"
    . ' (it declares spec.zone, status.drainedAt); left as it is';

#### the premise

subtest 'premise: both CRDs are shipped, the newer one declares two fields more' => sub {
    ok exists $SHIPPED{$_}, "$_ is shipped" for $NODE_CRD, $PROV_CRD;
    ok !v1_props($SHIPPED{$NODE_CRD}, 'spec')->{zone}, 'shipped: no spec.zone';
    ok !v1_props($OLD_NODE, $_)->{nodeIP}, "old: no $_.nodeIP" for qw(spec status);
};

#### 1. a newer CRD

subtest 'k311: deploy-robocop leaves a newer CRD as it is' => sub {
    my $api = FakeApi->new(crds => cluster($NODE_CRD => $NEWER_NODE));
    my $r = deploy($api);
    is $r->{died}, '', 'no death';
    is_deeply [ grep { /^CustomResourceDefinition\// } @{ $api->written } ],
        [ "CustomResourceDefinition/$PROV_CRD" ],
        'only the provider CRD is written; the newer OCPNode CRD is not written over';
    like $r->{out}, qr/^\Q$NEWER_SKIP\E$/m, 'said on STDOUT, with the fields';
    unlike $r->{out}, qr/\[ok\] ensured CustomResourceDefinition\/\Q$NODE_CRD\E/, 'not claimed as ensured';
    ok scalar(grep { $_ eq 'Deployment/robocop' } @{ $api->written }),
        'the rest of the manifests still goes out';
    is $r->{err}, '', 'nothing on STDERR: a newer CRD is no error';
};

subtest 'the same line ocp apply says: one judgement, two callers' => sub {
    my $deploy = deploy(FakeApi->new(crds => cluster($NODE_CRD => $NEWER_NODE)));
    my $apply  = ensure_crds(FakeApi->new(crds => cluster($NODE_CRD => $NEWER_NODE)));
    is $apply->{died}, '', 'ensure_crds ran';
    is_deeply skip_lines($deploy->{out}), skip_lines($apply->{out}), 'deploy-robocop and ensure_crds say the same';
    is_deeply skip_lines($deploy->{out}), [ $NEWER_SKIP ], 'and it is the one line';
};

# A copy in deploy-robocop would say the same line today and drift from it
# tomorrow. Both writers ask the one helper: told to leave a CRD alone that
# the cluster has as shipped, each leaves it alone.
subtest 'both writers ask OCP::Cmd::Apply::CR::skip_newer_crd, and do what it says' => sub {
    my @asked;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::CR::skip_newer_crd = sub {
        my ($self, $api, $doc) = @_;
        push @asked, "$doc->{kind}/$doc->{metadata}{name}";
        return $doc->{metadata}{name} eq $NODE_CRD ? 1 : 0;
    };
    for my $step ([ 'deploy-robocop' => \&deploy ], [ 'ensure_crds' => \&ensure_crds ]) {
        my ($who, $run) = @$step;
        @asked = ();
        my $api = FakeApi->new(crds => cluster());
        my $r = $run->($api);
        is $r->{died}, '', "$who ran";
        is_deeply [ sort grep { /^CustomResourceDefinition\// } @asked ],
            [ "CustomResourceDefinition/$PROV_CRD", "CustomResourceDefinition/$NODE_CRD" ],
            "$who asked it about each CRD";
        is_deeply [ grep { /\Q$NODE_CRD\E/ } @{ $api->written } ], [], "$who leaves the one it was told to";
        ok scalar(grep { $_ eq "CustomResourceDefinition/$PROV_CRD" } @{ $api->written }),
            "$who writes the other";
    }
};

#### 2. older, absent, the same

subtest 'an older CRD is updated, an absent one installed' => sub {
    my $api = FakeApi->new(crds => cluster($NODE_CRD => $OLD_NODE, $PROV_CRD => undef));
    my $r = deploy($api);
    is $r->{died}, '', 'no death';
    my %crd = map { $_->[1] => $_->[2] } grep { $_->[1] =~ /^CustomResourceDefinition\// } @{ $api->{writes} };
    is_deeply [ sort keys %crd ],
        [ "CustomResourceDefinition/$PROV_CRD", "CustomResourceDefinition/$NODE_CRD" ], 'both CRDs written';
    is_deeply $crd{"CustomResourceDefinition/$NODE_CRD"}, $SHIPPED{$NODE_CRD},
        "the older one with this ocp's schema";
    like $r->{out}, qr/\[ok\] ensured CustomResourceDefinition\/\Q$NODE_CRD\E/, 'said';
    unlike $r->{out}, qr/\[skip\]/, 'nothing skipped';
    is_deeply [ sort @{ $api->{reads} } ], [ sort map { $CRD_BASE . $_ } $NODE_CRD, $PROV_CRD ],
        'each CRD read once before it is written';
};

subtest 'the same CRDs: written as before' => sub {
    my $api = FakeApi->new(crds => cluster());
    my $r = deploy($api);
    is $r->{died}, '', 'no death';
    is scalar(grep { /^CustomResourceDefinition\// } @{ $api->written }), 2, 'both CRDs written';
    unlike $r->{out}, qr/\[skip\]/, 'nothing skipped';
};

#### 3. unreadable

for my $case (
    [ '403',                 [ 403, 'forbidden' ],          qr/\AGET \Q$CRD_BASE$NODE_CRD\E failed: HTTP 403 forbidden/ ],
    [ '500',                 [ 500, 'etcdserver: timeout' ], qr/\AGET \Q$CRD_BASE$NODE_CRD\E failed: HTTP 500 etcdserver: timeout/ ],
    [ 'a transport failure', "connect: Connection refused\n", qr/\AGET \Q$CRD_BASE$NODE_CRD\E failed: connect: Connection refused/ ],
    [ 'an undecodable body', [ 200, 'not json' ],           qr/\AGET \Q$CRD_BASE$NODE_CRD\E: the answer is no JSON/ ],
) {
    my ($what, $fail, $cause) = @$case;
    subtest "a CRD that cannot be read ($what) is not written over blind" => sub {
        my $api = FakeApi->new(crds => cluster(), raw_fail => { $NODE_CRD => $fail });
        my $r = deploy($api);
        like $r->{died}, $cause, 'deploy-robocop dies with the cause';
        is_deeply [ grep { /\Q$NODE_CRD\E/ } @{ $api->written } ], [], 'nothing written for it';
        unlike $r->{out}, qr/\[ok\] ensured CustomResourceDefinition\/\Q$NODE_CRD\E/, 'not claimed as ensured';
    };
}

done_testing;

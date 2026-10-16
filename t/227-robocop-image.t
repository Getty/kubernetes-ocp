#!/usr/bin/env perl
# karr k227 point 3 -- `ocp apply` must not silently put robocop back on
# :latest. The image is a setting of ocp.yaml (robocop.image); without it,
# robocop runs the version of the CLI that applied it; `ocp deploy-image` is a
# one-off override and says so; apply says when it replaces a live image.

use strict;
use warnings;
use Test::More;
use Path::Tiny ();
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Config;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::DeployRobocop;
use OCP::Robocop::Manifest;

local @ARGV = ();
my $ocp = OCP->new;
my @KEEP;

sub config_for {
    my (%opt) = @_;
    my $dir  = Path::Tiny->tempdir;
    my $spec = { name => 'test', control_planes => { provider => 'ssh', host => 'police1' } };
    $spec->{robocop} = { image => $opt{image} } if exists $opt{image};
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump($spec));
    push @KEEP, $dir;
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub deployment_doc {
    my ($doc) = grep { ref $_ eq 'HASH' && ($_->{kind} // '') eq 'Deployment' }
        YAML::XS::LoadFile('share/robocop/deployment.yaml');
    return $doc;
}

sub image_of { $_[0]{spec}{template}{spec}{containers}[0]{image} }

sub quietly (&) {
    my ($code) = @_;
    my $sink = '';
    open my $fh, '>', \$sink or die $!;
    local *STDOUT = $fh;
    $code->();
    return $sink;
}

package FakeApi {
    sub new     { my ($c, %a) = @_; bless { ensured => [], %a }, $c }
    sub ensure  { push @{ $_[0]{ensured} }, $_[1]; $_[1] }
    sub get     { my $s = shift; die "404\n" unless $s->{live}; $s->{live} }
    sub list    { bless { items => [] }, 'FakeEmptyList' }
    sub k8s     { $_[0] }
    sub object_to_struct { $_[1] }
}
package FakeEmptyList { sub items { $_[0]{items} } }
package FakeShareCmd {
    sub new             { bless {}, shift }
    sub _find_share_dir { Path::Tiny::path('share') }
}
package main;

subtest 'Config: robocop.image is optional and validated' => sub {
    is config_for()->robocop_image, undef, 'unset';
    is config_for(image => 'reg.example:5000/ocp:1.2.3')->robocop_image,
        'reg.example:5000/ocp:1.2.3', 'repo:tag with a registry port';
    my $dg = 'ocp@sha256:' . ('a' x 64);
    is config_for(image => $dg)->robocop_image, $dg, 'digest form';

    for my $bad ('', 'raudssus/ocp', 'has space:1', 'ocp@sha256:abc', [ 'x' ]) {
        my $c = config_for(image => $bad);
        eval { $c->robocop_image };
        like $@, qr/^robocop\.image: /, 'accessor croaks on ' . (ref $bad ? 'a list' : "'$bad'");
        my @errs = grep { /^robocop\.image/ } $c->validate;
        is scalar @errs, 1, '...and validate reports it';
    }
};

subtest 'Manifest: image from ocp.yaml, else the CLI version, else :latest with a notice' => sub {
    local $OCP::VERSION = '0.123';
    my $c = config_for();
    is image_of(OCP::Robocop::Manifest->for_config(deployment_doc(), $c)),
        'raudssus/ocp:0.123', 'no key: the version of the running CLI';
    is(OCP::Robocop::Manifest->image_notice($c), undef, 'no notice on a release');

    my $set = config_for(image => 'reg.example/ocp:pinned');
    is image_of(OCP::Robocop::Manifest->for_config(deployment_doc(), $set)),
        'reg.example/ocp:pinned', 'robocop.image wins';

    local $OCP::VERSION = '0.001';
    is image_of(OCP::Robocop::Manifest->for_config(deployment_doc(), $c)),
        'raudssus/ocp:latest', 'development checkout: :latest';
    like(OCP::Robocop::Manifest->image_notice($c), qr/^\[WARN\].*raudssus\/ocp:latest.*robocop\.image/,
        'and it says so');
    is(OCP::Robocop::Manifest->image_notice($set), undef, 'no notice when the image is set');
};

subtest 'apply says when it replaces a different live image, and warns once on a dev checkout' => sub {
    local $OCP::VERSION = '0.123';
    my $live = { kind => 'Deployment', metadata => { name => 'robocop' },
        spec => { template => { spec => { containers => [
            { name => 'controller', image => 'registry.local/ocp:lab-abc' } ] } } } };
    my $api = FakeApi->new(live => $live);
    my $out = quietly { OCP::Cmd::Apply::CR::ensure_robocop(FakeShareCmd->new, $api, config_for()) };
    like $out, qr{\[\.\.\] robocop image registry\.local/ocp:lab-abc -> raudssus/ocp:0\.123},
        'the replaced image is told';
    my ($dep) = grep { $_->{kind} eq 'Deployment' } @{ $api->{ensured} };
    is image_of($dep), 'raudssus/ocp:0.123', 'and the Deployment carries the spec image';

    my $same = FakeApi->new(live => { %$live, spec => { template => { spec => { containers => [
        { name => 'controller', image => 'raudssus/ocp:0.123' } ] } } } });
    unlike quietly { OCP::Cmd::Apply::CR::ensure_robocop(FakeShareCmd->new, $same, config_for()) },
        qr/robocop image .* -> /, 'nothing to tell when it is the same';

    local $OCP::VERSION = '0.001';
    my $out2 = quietly { OCP::Cmd::Apply::CR::ensure_robocop(FakeShareCmd->new, FakeApi->new, config_for()) };
    is scalar(() = $out2 =~ /\[WARN\]/g), 1, 'dev checkout: one [WARN]';

    my $out3 = quietly { OCP::Cmd::DeployRobocop->new(command_chain => [ bless {}, 'FakeOCP' ])
        ->_apply_manifests(FakeApi->new, config_for()) };
    like $out3, qr/\[WARN\].*robocop\.image/, 'deploy-robocop warns too';
};

done_testing;

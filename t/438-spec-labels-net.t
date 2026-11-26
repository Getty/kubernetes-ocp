#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw( tempdir );
use YAML::XS ();

use lib 'lib';

use OCP::NodeMeta;
use OCP::Config;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Keys::AuthorizedKeys;
use OCP::Cmd::Node::Rm;

#
# k438, found by k401:
#
#   1. OCP::NodeMeta::spec_labels dropped, without a word, a pool's labels:
#      that is no mapping and every value that is no string -- the shape
#      spec_taints had before k401. Now it is the same net behind the check
#      every command runs first (k400): the first of label_errors' lines,
#      validate()'s words, under "worker pool: labels", one line, no Perl
#      source location.
#   2. ocp node rm and ocp keys authorized-keys declared ssh by hand for what
#      cluster_ssh_key reads; they declare it through
#      OCP::Role::Cmd::cluster_ssh_key_spec_paths now, as ocp ssh does since
#      k401, so a new read there reaches their declarations as well.
#

# --- 1. spec_labels --------------------------------------------------------------

subtest 'spec_labels: no mapping, or no label, is said as one line' => sub {
    my $NO_MAPPING = "worker pool: labels: must be a mapping of label => value\n";
    for my $case ([ 'foo' => 'foo' ], [ '[ a ]' => [ 'a' ] ], [ '7' => 7 ]) {
        my ($shown, $labels) = @$case;
        ok !eval { OCP::NodeMeta->spec_labels($labels); 1 }, "labels: $shown dies";
        is $@, $NO_MAPPING, "labels: $shown: validate()'s words, one line, no Perl location";
    }

    my $bool = YAML::XS::Load("v: true\n")->{v};
    for my $case (
        [ 'a list value', { tier => [ 'a' ] },
          "worker pool: labels.tier: value must be a string (quote true, false and numbers)\n" ],
        [ 'a mapping value', { tier => { a => 1 } },
          "worker pool: labels.tier: value must be a string (quote true, false and numbers)\n" ],
        [ 'an unquoted true', { gpu => $bool },
          "worker pool: labels.gpu: value must be a string (quote true, false and numbers)\n" ],
        [ 'a null value', { tier => undef },
          "worker pool: labels.tier: value must be a string (quote true, false and numbers)\n" ],
        [ 'a bad value', { tier => 'a b' },
          "worker pool: labels.tier: 'a b' is not a valid label value\n" ],
        [ 'a bad key', { '-x' => 'a' },
          "worker pool: labels: '-x' is not a valid label key\n" ],
    ) {
        my ($what, $labels, $line) = @$case;
        ok !eval { OCP::NodeMeta->spec_labels({ ok => 'yes', %$labels }); 1 }, "$what dies";
        is $@, $line, "$what: label_errors' reason, one line, no Perl location";
    }

    is_deeply(OCP::NodeMeta->spec_labels(undef), {}, 'unset: none');
    is_deeply(OCP::NodeMeta->spec_labels({}), {}, 'an empty mapping: none');
    is_deeply(OCP::NodeMeta->spec_labels({ tier => 'gpu', 'example.com/rack' => '7', n => 3 }),
        { tier => 'gpu', 'example.com/rack' => '7', n => '3' },
        'a mapping of labels: as strings, as before');
};

my $ROOT = tempdir;
my $N    = 0;
sub project {
    my ($spec) = @_;
    my $dir = $ROOT->child('p' . ++$N);
    $dir->mkpath;
    $dir->child('ocp.yaml')->spew(YAML::XS::Dump($spec));
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my %BASE = (name => 'k438', control_planes => { provider => 'ssh', host => 'cp.k438.invalid' });
my $POOL = { name => 'w', provider => 'ssh', host => 'w.k438.invalid' };

subtest 'worker_ocpnodes: a pool\'s labels: foo is said, not dropped' => sub {
    my $config = project({ %BASE, workers => [ { %$POOL, labels => 'foo' } ] });
    my @crs = eval { OCP::Cmd::Apply::CR::worker_ocpnodes($config) };
    is $@, "worker pool: labels: must be a mapping of label => value\n", 'dies with the line';
    is scalar(@crs), 0, 'and makes no OCPNode without its labels';

    $config = project({ %BASE, workers => [ { %$POOL, labels => { tier => 'gpu' } } ] });
    my ($cr) = OCP::Cmd::Apply::CR::worker_ocpnodes($config);
    is_deeply $cr->{spec}{labels}, { tier => 'gpu' }, 'a mapping of labels: on the OCPNode, as before';
};

# --- 2. the key's paths through the helper ------------------------------------------

subtest 'node rm and keys authorized-keys declare through cluster_ssh_key_spec_paths' => sub {
    my $config = project({ %BASE });
    my @KEY = OCP::Role::Cmd->cluster_ssh_key_spec_paths;

    for my $c ([ 'OCP::Cmd::Node::Rm',             sub { OCP::Cmd::Node::Rm->new(name => 'w1') } ],
               [ 'OCP::Cmd::Keys::AuthorizedKeys', sub { OCP::Cmd::Keys::AuthorizedKeys->new } ]) {
        my ($class, $new) = @$c;
        is_deeply [ $new->()->spec_paths($config) ], \@KEY, "$class: the key's paths";

        no strict 'refs';
        no warnings 'redefine';
        local *{"${class}::cluster_ssh_key_spec_paths"} = sub { 'k438-sentinel' };
        is_deeply [ $new->()->spec_paths($config) ], [ 'k438-sentinel' ],
            "$class: through cluster_ssh_key_spec_paths";
    }

    is_deeply [ OCP::Cmd::Node::Rm->new(name => 'w1', keep_machine => 1)->spec_paths($config) ], [],
        'node rm --keep-machine: nothing, as before';
    is_deeply [ OCP::Cmd::Keys::AuthorizedKeys->new(purpose => 'operator')->spec_paths($config) ], [],
        'keys authorized-keys --purpose operator: nothing, as before';
};

done_testing;

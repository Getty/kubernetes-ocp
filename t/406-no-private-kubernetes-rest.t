#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

use Kubernetes::REST ();

#
# k406: OCP::Kubernetes::register_resource_providers and OCP::K8s::register
# register their providers through Kubernetes::REST's add_provider (1.111, the
# pinned version). Before that they pushed onto $api->with and dropped an
# inner IO::K8s that was already built with ->_clear_k8s, behind ->_has_k8s and
# two ->can probes: private methods of another distribution, which a release
# may rename or remove without a word.
#
# The claims:
#   1. no code under lib/ or bin/ calls ->_clear_k8s or ->_has_k8s, or probes
#      for them with ->can;
#   2. in general: no code calls, or probes for, a private method of
#      Kubernetes::REST -- a name the loaded Kubernetes::REST defines with a
#      leading underscore and OCP does not define itself (OCP::NodeMeta has its
#      own _json) -- except the names in %ESCAPE, and every name in %ESCAPE is
#      still in use, so the list cannot outlive its reason.
#   3. a CustomResourceDefinition is read with a typed get, not through the
#      escape (k471): no code names the customresourcedefinitions path, and
#      OCP::Drift::_read_crd and OCP::Cmd::Apply::K8s::crd_read call no
#      _request.
#
# Code only: POD, full-line comments and everything after __END__ are not
# calls. A method called through a variable ($api->$name) is not seen. Claim 2
# matches by method name, not by receiver: a call on an object of OCP's own
# with a name only Kubernetes::REST defines would be reported too, and would
# need its name defined in OCP or a closer look.
#

# What OCP still calls on purpose, with the reason.
my %ESCAPE = (
    _request        => 'the raw request escape: server-side apply of a manifest, the'
                     . ' custom-resource reads of OCP::Cmd::Apply::K8s::crd_get (Gateway,'
                     . ' ClusterPolicy, ResourceSlice, LB-IPAM pools), the robocop pod DELETE'
                     . ' with a grace period (k420). Not the CRDs themselves: those are a typed'
                     . ' get since k471 (claim 3)',
);

my @files = sort { "$a" cmp "$b" } ( modules_under('lib'), path('bin')->children );

sub modules_under {
    my ($dir) = @_;
    my @out;
    my $iter = path($dir)->iterator({ recurse => 1 });
    while (my $p = $iter->()) { push @out, $p if $p->is_file && $p =~ /\.pm\z/ }
    return @out;
}

# [line number, text] for every line of code in $file.
sub code_lines {
    my ($file) = @_;
    my ($n, $pod, @code) = (0, 0);
    for my $line ($file->lines_raw({ chomp => 1 })) {
        $n++;
        last if $line =~ /^__(?:END|DATA)__\b/;
        if ($line =~ /^=(\w+)/) { $pod = $1 ne 'cut'; next }
        next if $pod || $line =~ /^\s*#/;
        push @code, [ $n, $line ];
    }
    return @code;
}

my %code = map { ("$_" => [ code_lines($_) ]) } @files;

# Every ->_name call and every ->can('_name') probe, as "file:line" by name.
my %used;
for my $file (sort keys %code) {
    for my $l (@{ $code{$file} }) {
        my ($n, $text) = @$l;
        push @{ $used{$1} }, "$file:$n" while $text =~ /->\s*(_\w+)/g;
        push @{ $used{$1} }, "$file:$n" while $text =~ /->\s*can\(\s*['"](_\w+)['"]/g;
    }
}

ok @files > 10 && (grep { $_ eq 'lib/OCP/Kubernetes.pm' } keys %code)
    && (grep { $_ eq 'bin/robocop' } keys %code),
    'the scan reads lib/ and bin/' or diag explain [ sort keys %code ];

subtest 'nothing calls or probes _clear_k8s or _has_k8s' => sub {
    for my $name (qw(_clear_k8s _has_k8s)) {
        is_deeply $used{$name} // [], [], "no ->$name" or diag explain $used{$name};
    }
};

# k420: _build_path and _check_response left the escape list -- OCP calls the
# public build_path, and the patch_status fallback that called both is gone.
# Claim 2 holds them to that; this names them, so a rename in Kubernetes::REST
# that dropped them from %private cannot make that claim pass vacuously.
subtest 'the private twins of a public method stay out' => sub {
    is_deeply $used{$_} // [], [], "no ->$_" or diag explain $used{$_}
        for qw(_build_path _check_response);
};

subtest 'a CRD is read typed, not through the escape (k471)' => sub {
    my @raw = map { my $f = $_; map { "$f:$_->[0]" } grep { $_->[1] =~ m{/customresourcedefinitions/} } @{ $code{$f} } }
        sort keys %code;
    is_deeply \@raw, [], 'no code builds a customresourcedefinitions path' or diag join "\n", @raw;

    # The body of each reader, from its sub line to the next one.
    for my $reader ([ 'lib/OCP/Drift.pm', qr/^sub (?:_read_crd|cluster_crd)\b/ ],
                    [ 'lib/OCP/Cmd/Apply/K8s.pm', qr/^sub crd_read\b/ ]) {
        my ($file, $start) = @$reader;
        my ($in, @body);
        for my $l (@{ $code{$file} }) {
            $in = $l->[1] =~ $start ? 1 : $l->[1] =~ /^sub / ? 0 : $in;
            push @body, $l->[1] if $in;
        }
        ok @body, "$file: the reader is there";
        ok !grep({ /->\s*_request\b/ } @body), "$file: it calls no _request";
    }
};

subtest 'no private method of Kubernetes::REST but the escape' => sub {
    my %private = do {
        no strict 'refs';
        map { ($_ => 1) } grep { /^_/ && defined &{"Kubernetes::REST::$_"} }
            keys %{'Kubernetes::REST::'};
    };
    ok $private{_clear_k8s} && $private{_has_k8s} && $private{_request},
        'Kubernetes::REST still has the private names this scan is about';

    # The names OCP defines itself: subs, attributes, and the accessors and
    # builders Moo generates for them.
    my %own;
    for my $l (map { @$_ } values %code) {
        my $text = $l->[1];
        $own{$1}++ while $text =~ /\bsub\s+(_\w+)/g;
        $own{$1}++ while $text =~ /\bhas\s+['"]?\+?(_\w+)/g;
        $own{"_build_$1"}++, $own{"_set_$1"}++ while $text =~ /\bhas\s+['"]?\+?(\w+)/g;
        $own{$1}++ while $text =~ /\b(?:predicate|clearer|builder|reader|writer)\s*=>\s*['"](_\w+)/g;
    }

    my @found = map { my $name = $_; map { "$_ ->$name" } @{ $used{$name} } }
        grep { $private{$_} && !$own{$_} && !$ESCAPE{$_} } sort keys %used;
    is_deeply \@found, [], 'none called' or diag join "\n", @found;

    for my $name (sort keys %ESCAPE) {
        ok $private{$name}, "$name is still a private method of Kubernetes::REST";
        ok $used{$name}, "$name is still called ($ESCAPE{$name})";
    }
};

done_testing;

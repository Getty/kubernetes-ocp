#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Apply::CR;

#
# k356: four [WARN]s in OCP::Cmd::Apply::CR said that something went wrong,
# on STDOUT. The output-channel rule (.claude/rules/ocp-rules.md, the t/107
# pattern) puts what went wrong on STDERR, with its cause, and keeps STDOUT for
# the progress report:
#
#   ensure_cp_ocpnode                 its status stayed unwritten
#   migrate_legacy_nodes              a migrated OCPNode's status stayed unwritten
#   retire_unannotated_robocop_pods   the pods could not be listed
#                                     a pod could not be deleted
#
# Each case below pins the [WARN] line on STDERR, cause included, and the
# STDOUT narrative around it as it was: [ok], [migrated] and [..] lines, and
# nothing of the failure.
#
# k363: the cause is said by OCP::ErrorLine::one_line -- one line, without a
# Perl source location, wherever in it one stood. Each [WARN] printed the raw
# $@ before: a croak's " at FILE line N." at its end, and a die that wraps
# another kept the inner one in the middle. The ensure_cp_ocpnode Node read
# (k330) is its sub's other [WARN].
#

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

{
    package FakeList;
    sub new   { my ($c, @i) = @_; bless { items => [@i] }, $c }
    sub items { $_[0]{items} }

    package FakeResp;
    sub new    { bless { status => $_[1] }, $_[0] }
    sub status { $_[0]{status} }

    # get: a Node it was given, the error in {get_dies}{name}, else a 404.
    # list: what it was given for the kind, or the error in
    # {list_dies}{kind}. patch_status dies with
    # {status_dies}{name}; _request (the pod DELETE) answers {delete}{name},
    # an HTTP status, or dies with it when it is a string.
    package Api;
    sub new {
        my ($c, %a) = @_;
        bless { nodes => {}, get_dies => {}, lists => {}, list_dies => {}, status_dies => {}, delete => {},
                ensured => [], statuses => {}, requests => [], %a }, $c;
    }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub get {
        my ($s, $kind, $name) = @_;
        die $s->{get_dies}{$name} if $s->{get_dies}{$name};
        return $s->{nodes}{$name} if $kind eq 'Node' && $s->{nodes}{$name};
        die "Kubernetes API error (get $kind): 404 NotFound\n";
    }
    sub list {
        my ($s, $kind) = @_;
        die $s->{list_dies}{$kind} if $s->{list_dies}{$kind};
        return FakeList->new(@{ $s->{lists}{$kind} // [] });
    }
    sub ensure {
        my ($s, $doc) = @_;
        push @{ $s->{ensured} }, "$doc->{kind}/$doc->{metadata}{name}";
        return $doc;
    }
    sub patch_status {
        my ($s, $kind, %a) = @_;
        die $s->{status_dies}{$a{name}} if $s->{status_dies}{$a{name}};
        $s->{statuses}{"$kind/$a{name}"} = $a{patch}{status};
        return 1;
    }
    sub _request {
        my ($s, $method, $path) = @_;
        push @{ $s->{requests} }, "$method $path";
        my ($name) = $path =~ m{/([^/]+)\z};
        my $answer = $s->{delete}{$name} // 200;
        die $answer if $answer =~ /\D/;
        return FakeResp->new($answer);
    }
}

my $FORBIDDEN = "Kubernetes API error (patch status OCPNode): 403 Forbidden at Fake line 1.\n";
my $INTERNAL  = "Kubernetes API error (patch status OCPNode): 500 InternalError at Fake line 1.\n";

# A die that wraps another: the inner location stands in the middle (k363).
my $WRAPPED   = "the request failed: Kubernetes API error: 403 Forbidden at Fake line 1.\n"
              . "retried once, refused again at Fake line 2.\n";

# What each [WARN] says of them (k363): one line, no location.
my %SAID = (
    $FORBIDDEN => "Kubernetes API error (patch status OCPNode): 403 Forbidden\n",
    $INTERNAL  => "Kubernetes API error (patch status OCPNode): 500 InternalError\n",
    $WRAPPED   => "the request failed: Kubernetes API error: 403 Forbidden"
                . " retried once, refused again\n",
);

# --- 1. ensure_cp_ocpnode --------------------------------------------------------

sub cp_ocpnode {
    my (%a) = @_;
    my $api = Api->new(%a);
    my $r = capture { OCP::Cmd::Apply::CR::ensure_cp_ocpnode(undef, $api,
        { name => 'police1', provider => 'ssh', host => 'police1.k356.test' }); 1 };
    $r->{api} = $api;
    return $r;
}

subtest 'k356 ensure_cp_ocpnode: an unwritten status is a [WARN] on STDERR, with its cause' => sub {
    my $r = cp_ocpnode();
    is $r->{out}, "  [ok] ensured OCPNode/police1 (control-plane, Ready)\n", 'control: the [ok] line on STDOUT';
    is $r->{err}, '', 'control: nothing on STDERR';

    $r = cp_ocpnode(status_dies => { police1 => $FORBIDDEN });
    is $r->{died}, '', 'no death -- the CR is observational';
    is_deeply $r->{api}{ensured}, [ 'OCPNode/police1' ], 'the CR is ensured';
    is $r->{err}, "  [WARN] ensured OCPNode/police1, but its status stayed unwritten: $SAID{$FORBIDDEN}",
        'the [WARN] on STDERR, with the cause, without its location (k363)';
    is $r->{out}, '', 'nothing on STDOUT: no [WARN], and no [ok] claiming Ready';

    $r = cp_ocpnode(status_dies => { police1 => $WRAPPED });
    is $r->{err}, "  [WARN] ensured OCPNode/police1, but its status stayed unwritten: $SAID{$WRAPPED}",
        'a wrapped cause: one line, the location in the middle gone too (k363)';
};

subtest 'k363 ensure_cp_ocpnode: a Node it could not read is said in one line, without a location' => sub {
    my $r = cp_ocpnode(get_dies => { police1 => $WRAPPED });
    is $r->{died}, '', 'no death';
    is $r->{err}, "  [WARN] OCPNode/police1 keeps the address it has: could not read Node 'police1': "
        . $SAID{$WRAPPED},
        'the [WARN] on STDERR: read_or_absent\'s words, the cause in one line, no location';
    is $r->{out}, "  [ok] ensured OCPNode/police1 (control-plane, Ready)\n", 'STDOUT as before';
};

# --- 2. migrate_legacy_nodes -----------------------------------------------------

sub node_at {
    my ($name, $ip, $cp) = @_;
    return { metadata => { name => $name,
                           ($cp ? (labels => { 'node-role.kubernetes.io/control-plane' => 'true' }) : ()) },
             status   => { addresses => [ { type => 'InternalIP', address => $ip } ] } };
}

sub migrate {
    my (%a) = @_;
    my $api = Api->new(lists => { OCPNode => [], Node => [ node_at('old1', '10.0.0.9'),
                                                           node_at('old2', '10.0.0.8', 1) ] }, %a);
    my $r = capture { OCP::Cmd::Apply::CR::migrate_legacy_nodes(undef, $api); 1 };
    $r->{api} = $api;
    return $r;
}

my $MIGRATED = "  [migrated] old1 (worker, 10.0.0.9)\n  [migrated] old2 (control-plane, 10.0.0.8)\n";

subtest 'k356 migrate_legacy_nodes: a migrated OCPNode\'s unwritten status is a [WARN] on STDERR' => sub {
    my $r = migrate();
    is $r->{out}, $MIGRATED, 'control: one [migrated] line per Node on STDOUT';
    is $r->{err}, '', 'control: nothing on STDERR';

    $r = migrate(status_dies => { old1 => $INTERNAL });
    is $r->{died}, '', 'no death';
    is $r->{err}, "  [WARN] status for migrated OCPNode/old1 stayed unwritten: $SAID{$INTERNAL}",
        'the [WARN] on STDERR, with the cause, without its location (k363)';
    is $r->{out}, $MIGRATED, 'STDOUT as without the failure: both [migrated] lines, no [WARN]';
    ok $r->{api}{statuses}{'OCPNode/old2'}, 'the next Node is still migrated with its status';

    $r = migrate(status_dies => { old1 => $WRAPPED });
    is $r->{err}, "  [WARN] status for migrated OCPNode/old1 stayed unwritten: $SAID{$WRAPPED}",
        'a wrapped cause: one line, the location in the middle gone too (k363)';
};

# --- 3. retire_unannotated_robocop_pods ------------------------------------------

sub retire {
    my (%a) = @_;
    my $api = Api->new(lists => { Pod => [ { metadata => { name => 'robocop-a' } },
                                           { metadata => { name => 'robocop-b' } } ] }, %a);
    my $r = capture { OCP::Cmd::Apply::CR::retire_unannotated_robocop_pods(undef, $api); 1 };
    $r->{api} = $api;
    return $r;
}

sub deleted {
    my ($name) = @_;
    return "  [..] robocop pod $name predates SIGTERM handling; deleted with a 30 s grace period (one-time transition)\n";
}

subtest 'k356 retire_unannotated_robocop_pods: a list it could not read is a [WARN] on STDERR' => sub {
    my $r = retire(list_dies => { Pod => "Kubernetes API error (list Pod): 403 Forbidden at Fake line 1.\n" });
    is $r->{died}, '', 'no death -- best effort';
    is_deeply $r->{api}{requests}, [], 'nothing deleted';
    is $r->{err},
        "  [WARN] could not check for robocop pods without SIGTERM handling: "
      . "Kubernetes API error (list Pod): 403 Forbidden\n",
        'the [WARN] on STDERR, with the cause, without its location (k363)';
    is $r->{out}, '', 'nothing on STDOUT';

    $r = retire(list_dies => { Pod => $WRAPPED });
    is $r->{err}, "  [WARN] could not check for robocop pods without SIGTERM handling: $SAID{$WRAPPED}",
        'a wrapped cause: one line, the location in the middle gone too (k363)';
};

subtest 'k356 retire_unannotated_robocop_pods: a pod it could not delete is a [WARN] on STDERR' => sub {
    my $r = retire();
    is $r->{out}, deleted('robocop-a') . deleted('robocop-b'), 'control: one [..] line per pod on STDOUT';
    is $r->{err}, '', 'control: nothing on STDERR';

    $r = retire(delete => { 'robocop-b' => 404 });
    is $r->{out}, deleted('robocop-a') . deleted('robocop-b'), '404: a pod gone already counts as deleted';
    is $r->{err}, '', '404: nothing on STDERR';

    $r = retire(delete => { 'robocop-a' => 403 });
    is $r->{died}, '', 'refused: no death -- best effort';
    is $r->{err}, "  [WARN] could not delete robocop pod robocop-a (no SIGTERM handling): HTTP 403\n",
        'refused: the [WARN] on STDERR, with the HTTP status';
    is $r->{out}, deleted('robocop-b'), 'refused: STDOUT keeps the pod that was deleted, and no [WARN]';

    $r = retire(delete => { 'robocop-b' => "connection refused at Fake line 1.\n" });
    is $r->{err}, "  [WARN] could not delete robocop pod robocop-b (no SIGTERM handling): connection refused\n",
        'request died: the [WARN] on STDERR, with what it died of, without its location (k363)';
    is $r->{out}, deleted('robocop-a'), 'request died: STDOUT keeps the pod that was deleted, and no [WARN]';

    $r = retire(delete => { 'robocop-b' => $WRAPPED });
    is $r->{err}, "  [WARN] could not delete robocop pod robocop-b (no SIGTERM handling): $SAID{$WRAPPED}",
        'request died of a wrapped cause: one line, the location in the middle gone too (k363)';
};

done_testing;

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

    # get: a Node it was given, else a 404. list: what it was given for the
    # kind, or the error in {list_dies}{kind}. patch_status dies with
    # {status_dies}{name}; _request (the pod DELETE) answers {delete}{name},
    # an HTTP status, or dies with it when it is a string.
    package Api;
    sub new {
        my ($c, %a) = @_;
        bless { nodes => {}, lists => {}, list_dies => {}, status_dies => {}, delete => {},
                ensured => [], statuses => {}, requests => [], %a }, $c;
    }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub get {
        my ($s, $kind, $name) = @_;
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
    is $r->{err}, "  [WARN] ensured OCPNode/police1, but its status stayed unwritten: $FORBIDDEN",
        'the [WARN] on STDERR, with the cause';
    is $r->{out}, '', 'nothing on STDOUT: no [WARN], and no [ok] claiming Ready';
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
    is $r->{err}, "  [WARN] status for migrated OCPNode/old1 stayed unwritten: $INTERNAL",
        'the [WARN] on STDERR, with the cause';
    is $r->{out}, $MIGRATED, 'STDOUT as without the failure: both [migrated] lines, no [WARN]';
    ok $r->{api}{statuses}{'OCPNode/old2'}, 'the next Node is still migrated with its status';
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
      . "Kubernetes API error (list Pod): 403 Forbidden at Fake line 1.\n",
        'the [WARN] on STDERR, with the cause';
    is $r->{out}, '', 'nothing on STDOUT';
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
    is $r->{err}, "  [WARN] could not delete robocop pod robocop-b (no SIGTERM handling): connection refused at Fake line 1.\n",
        'request died: the [WARN] on STDERR, with what it died of';
    is $r->{out}, deleted('robocop-a'), 'request died: STDOUT keeps the pod that was deleted, and no [WARN]';
};

done_testing;

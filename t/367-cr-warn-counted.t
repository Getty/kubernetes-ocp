#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny ();
use YAML::XS ();

use lib 'lib';

use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;

#
# k367: six [WARN]s of OCP::Cmd::Apply::CR name a failure on STDERR (k356,
# k330), but none of them was recorded in {_apply_warnings} -- so the closing
# banner said "CONTROL PLANE DEPLOYED SUCCESSFULLY!" under them. The not-Ready
# worker (check_worker_phases, k234) is the model: its [WARN] pushes a tag,
# and the banner reads WITH WARNINGS. The exit code stays 0 -- only a failed
# component or an unhealthy core moves it (OCP::Cmd::Apply::Health::finish).
#
#   ensure_cp_ocpnode                 the Node could not be read (k330)
#                                     its status stayed unwritten (k356)
#   migrate_legacy_nodes              a migrated OCPNode's status stayed unwritten (k356)
#   retire_unannotated_robocop_pods   the pods could not be listed (k356)
#                                     a pod could not be deleted (k356)
#   ensure_robocop                    the running image could not be read (k330)
#
# Each case runs the site with a real OCP::Cmd::Apply object, checks its
# [WARN] reached STDERR, then hands the same object to the single exit
# (_finish_apply) over a clean health check: banner and exit code. Each site's
# run without the failure is the control -- SUCCESSFULLY, exit 0.
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

    # get: the object in {objects}{"Kind/name"}, the error in
    # {get_dies}{"Kind/name"}, else a 404. list: what it was given for the
    # kind, or the error in {list_dies}{kind}. patch_status dies with
    # {status_dies}{name}; _request (the pod DELETE) answers {delete}{name},
    # an HTTP status, or dies with it when it is a string.
    package Api;
    sub new {
        my ($c, %a) = @_;
        bless { objects => {}, get_dies => {}, lists => {}, list_dies => {}, status_dies => {},
                delete => {}, %a }, $c;
    }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub get {
        my ($s, $kind, $name) = @_;
        die $s->{get_dies}{"$kind/$name"} if $s->{get_dies}{"$kind/$name"};
        return $s->{objects}{"$kind/$name"} if $s->{objects}{"$kind/$name"};
        die Kubernetes::REST::APIError->new(code => 404, context => 'get',
            body => '{"kind":"Status","reason":"NotFound","code":404}');
    }
    sub list {
        my ($s, $kind) = @_;
        die $s->{list_dies}{$kind} if $s->{list_dies}{$kind};
        return FakeList->new(@{ $s->{lists}{$kind} // [] });
    }
    sub ensure { $_[1] }
    sub patch_status {
        my ($s, $kind, %a) = @_;
        die $s->{status_dies}{$a{name}} if $s->{status_dies}{$a{name}};
        return 1;
    }
    sub _request {
        my ($s, $method, $path) = @_;
        my ($name) = $path =~ m{/([^/]+)\z};
        my $answer = $s->{delete}{$name} // 200;
        die $answer if $answer =~ /\D/;
        return FakeResp->new($answer);
    }

    package Fake::Config;
    sub name    { 'k367' }
    sub api_url { 'https://x:6443' }
}

require Kubernetes::REST::APIError;
sub refused {
    my ($code, $reason, $context) = @_;
    return Kubernetes::REST::APIError->new(code => $code, context => $context,
        body => qq({"kind":"Status","reason":"$reason","code":$code}));
}

my $CLEAN = { critical => [], warnings => [], starting => [] };

# The verdict of the single exit for $apply over a clean health check: the
# banner text and the exit code.
sub verdict {
    my ($apply) = @_;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_check_cluster_health = sub { $CLEAN };
    local *OCP::Cmd::Apply::_stamp_ocp_version    = sub { };
    my $r = capture { $apply->_finish_apply(config => bless({}, 'Fake::Config'), api => undef) };
    die "finish died: $r->{died}" if $r->{died};
    my ($banner) = $r->{out} =~ /^║  (.*?) *║$/m;
    return { rc => $r->{rv}, banner => $banner // '' };
}

my $WARNED = 'CONTROL PLANE DEPLOYED — WITH WARNINGS';
my $CLEAN_BANNER = 'CONTROL PLANE DEPLOYED SUCCESSFULLY!';

# Runs $site with a fresh OCP::Cmd::Apply, then the exit over it.
sub run_site {
    my ($site) = @_;
    my $apply = bless {}, 'OCP::Cmd::Apply';
    my $r = capture { $site->($apply); 1 };
    $r->{verdict} = verdict($apply);
    return $r;
}

sub counted {
    my ($r, $warn, $what) = @_;
    is $r->{died}, '', "$what: no death";
    like $r->{err}, $warn, "$what: the [WARN] on STDERR";
    is $r->{verdict}{banner}, $WARNED, "$what: the banner reads WITH WARNINGS";
    is $r->{verdict}{rc}, 0, "$what: the exit code stays 0";
}

sub clean {
    my ($r, $what) = @_;
    is $r->{died}, '', "$what: no death";
    is $r->{err}, '', "$what: nothing on STDERR";
    is $r->{verdict}{banner}, $CLEAN_BANNER, "$what: SUCCESSFULLY";
    is $r->{verdict}{rc}, 0, "$what: exit 0";
}

subtest 'control: an untouched apply object ends in SUCCESSFULLY, exit 0' => sub {
    my $v = verdict(bless {}, 'OCP::Cmd::Apply');
    is $v->{banner}, $CLEAN_BANNER, 'SUCCESSFULLY';
    is $v->{rc}, 0, 'exit 0';
};

# --- ensure_cp_ocpnode -----------------------------------------------------------

sub cp_ocpnode {
    my (%a) = @_;
    my $api = Api->new(%a);
    return run_site(sub { OCP::Cmd::Apply::CR::ensure_cp_ocpnode($_[0], $api,
        { name => 'police1', provider => 'ssh', host => 'police1.k367.test' }) });
}

subtest 'k367 ensure_cp_ocpnode: a Node it could not read is counted (k330)' => sub {
    clean(cp_ocpnode(), 'control, Node 404');
    counted(cp_ocpnode(get_dies => { 'Node/police1' => refused(403, 'Forbidden', 'get') }),
        qr/\[WARN\] OCPNode\/police1 keeps the address it has: .*\b403\b/s, 'Node read 403');
};

subtest 'k367 ensure_cp_ocpnode: an unwritten status is counted (k356)' => sub {
    counted(cp_ocpnode(status_dies => { police1 => "Kubernetes API error (patch status OCPNode): 403 Forbidden\n" }),
        qr/\[WARN\] ensured OCPNode\/police1, but its status stayed unwritten: .*403 Forbidden/,
        'status write 403');
};

# --- migrate_legacy_nodes --------------------------------------------------------

sub migrate {
    my (%a) = @_;
    my $api = Api->new(lists => { OCPNode => [],
        Node => [ { metadata => { name => 'old1' },
                    status   => { addresses => [ { type => 'InternalIP', address => '10.0.0.9' } ] } } ] }, %a);
    return run_site(sub { OCP::Cmd::Apply::CR::migrate_legacy_nodes($_[0], $api) });
}

subtest 'k367 migrate_legacy_nodes: a migrated OCPNode\'s unwritten status is counted (k356)' => sub {
    clean(migrate(), 'control');
    counted(migrate(status_dies => { old1 => "Kubernetes API error (patch status OCPNode): 500 InternalError\n" }),
        qr/\[WARN\] status for migrated OCPNode\/old1 stayed unwritten: .*500 InternalError/,
        'status write 500');
};

# --- retire_unannotated_robocop_pods ---------------------------------------------

sub retire {
    my (%a) = @_;
    my $api = Api->new(lists => { Pod => [ { metadata => { name => 'robocop-a' } } ] }, %a);
    return run_site(sub { OCP::Cmd::Apply::CR::retire_unannotated_robocop_pods($_[0], $api) });
}

subtest 'k367 retire_unannotated_robocop_pods: a list it could not read is counted (k356)' => sub {
    clean(retire(), 'control, the pod deleted');
    counted(retire(list_dies => { Pod => "Kubernetes API error (list Pod): 403 Forbidden\n" }),
        qr/\[WARN\] could not check for robocop pods without SIGTERM handling: .*403 Forbidden/,
        'list 403');
};

subtest 'k367 retire_unannotated_robocop_pods: a pod it could not delete is counted (k356)' => sub {
    clean(retire(delete => { 'robocop-a' => 404 }), 'control, the pod gone already (404)');
    counted(retire(delete => { 'robocop-a' => 403 }),
        qr/\[WARN\] could not delete robocop pod robocop-a \(no SIGTERM handling\): HTTP 403/,
        'delete 403');
    counted(retire(delete => { 'robocop-a' => "connection refused\n" }),
        qr/\[WARN\] could not delete robocop pod robocop-a \(no SIGTERM handling\): connection refused/,
        'delete died');
};

# --- ensure_robocop: the running image (k227) ------------------------------------

my @KEEP;
sub config_for {
    my $dir = Path::Tiny->tempdir;
    push @KEEP, $dir;
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({
        name           => 'k367',
        control_planes => { provider => 'ssh', host => 'police1.k367.test' },
    }));
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub roll_out {
    my (%a) = @_;
    my $api = Api->new(%a);
    my $config = config_for();
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_find_share_dir = sub { Path::Tiny::path('share') };
    return run_site(sub { OCP::Cmd::Apply::CR::ensure_robocop($_[0], $api, $config) });
}

subtest 'k367 ensure_robocop: a running image it could not read is counted (k330)' => sub {
    my $r = roll_out();
    clean($r, 'control, no Deployment yet (404)');
    like $r->{out}, qr/\[ok\] ensured Deployment\/robocop/, 'control: the Deployment is written';

    counted(roll_out(get_dies => { 'Deployment/robocop' => refused(500, 'InternalError', 'get') }),
        qr/\[WARN\] robocop image \S+, not compared with the running one: .*\b500\b/s,
        'Deployment read 500');
};

done_testing;

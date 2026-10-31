#!/usr/bin/env perl
use strict;
use warnings;

# The waits below run against a clock this file moves (FakeSelf::wait_seconds
# advances $NOW): installed before OCP::Cmd::Apply::CR is compiled, with the
# empty prototype of the builtin so `time + $timeout` still parses as a sum.
our $NOW;
BEGIN { *CORE::GLOBAL::time = sub () { defined $main::NOW ? $main::NOW : CORE::time() } }

use Test::More;
use Kubernetes::REST::APIError;
use Path::Tiny ();
use Scalar::Util qw(blessed);
use YAML::XS ();

use lib 'lib';

use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Robocop::Manifest;

#
# k330, the CR layer's part of k319: reads in OCP::Cmd::Apply::CR that took a
# failure for "not there", or lost its cause. Only a 404 is absent; a 403, a
# 500 says nothing about the object and is named with its cause -- a read
# asked once dies with it (its step reports it) or, where the read only adds
# to what is written anyway, is a [WARN] on STDERR; a wait reads again and
# names the last read's why when it runs out (OCP::Cmd::Apply::K8s,
# read_or_absent / read_or_why).
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

# What Kubernetes::REST dies with for an HTTP error status (as in t/25, t/319).
sub api_error {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(
        code    => $code,
        context => 'get',
        body    => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}),
    );
}
my @REFUSALS = ([403, 'Forbidden'], [500, 'InternalError']);

# The next answer of a queue, the last one repeating.
sub next_answer { my ($q) = @_; @$q > 1 ? shift @$q : $q->[0] }

{
    package FakeList;
    sub new   { my ($c, @i) = @_; bless { items => [@i] }, $c }
    sub items { $_[0]{items} }

    package FakeStatus;
    sub readyReplicas { $_[0]{readyReplicas} }

    # A robocop Deployment as get() answers it: a struct that also has ->status.
    package FakeDeployment;
    sub status { bless { %{ $_[0]{status} // {} } }, 'FakeStatus' }

    # Every read answers from { "get Kind/name" | "list Kind" => [ queue ] }:
    # an object, or the error it dies with. A read with no answer is a 404.
    package ReadApi;
    sub new {
        my ($c, %a) = @_;
        bless { answers => {}, calls => [], ensured => [], status => {}, conflicts => 0, %a }, $c;
    }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub _answer {
        my ($s, $key) = @_;
        push @{ $s->{calls} }, $key;
        my $q = $s->{answers}{$key} or die main::api_error(404, 'NotFound');
        my $a = main::next_answer($q);
        die $a if Scalar::Util::blessed($a) && $a->isa('Kubernetes::REST::APIError');
        return $a;
    }
    sub get {
        my ($s, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : undef;
        my %o = @rest;
        $name //= $o{name};
        return $s->_answer("get $kind/$name");
    }
    sub list { my ($s, $kind) = @_; $s->_answer("list $kind") }
    sub ensure {
        my ($s, $doc) = @_;
        push @{ $s->{ensured} }, "$doc->{kind}/$doc->{metadata}{name}";
        return $doc;
    }
    sub patch_status {
        my ($s, $kind, %a) = @_;
        $s->{status}{"$kind/$a{name}"} = $a{patch}{status};
        return 1;
    }
    # The OCPNode merge patch of sync_worker_meta: $s->{conflicts} 409s first.
    sub patch {
        my ($s, $kind, %a) = @_;
        push @{ $s->{calls} }, "patch $kind/$a{name}";
        die main::api_error(409, 'Conflict') if $s->{conflicts}-- > 0;
        return { metadata => { name => $a{name} }, spec => $a{patch}{spec}, status => {} };
    }

    package FakeSelf;
    sub new             { bless { waited => 0 }, shift }
    sub wait_seconds    { $_[0]{waited} += $_[1]; $main::NOW += $_[1] }
    sub _find_share_dir { Path::Tiny::path('share') }

    package FakeOCP;
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub load_file { undef }
    sub dump_file { 1 }
}

my @KEEP;
sub config_for {
    my ($spec) = @_;
    my $dir = Path::Tiny->tempdir;
    push @KEEP, $dir;
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({
        name           => 'k330',
        control_planes => { provider => 'ssh', host => 'police1.k330.test' },
        %{ $spec // {} },
    }));
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# One ssh worker, w1, with a pool label its OCPNode does not have yet.
my $POOL = { workers => [ { name => 'lab', provider => 'ssh', host => 'w1.k330.test',
                            labels => { tier => 'gpu' } } ] };

sub ocpnode_w1 {
    my (%status) = @_;
    return {
        apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
        metadata   => { name => 'w1', namespace => 'ocp-system', resourceVersion => 1 },
        spec       => { role => 'worker', providerRef => 'ssh-default', host => 'w1.k330.test' },
        status     => { phase => 'Pending', %status },
    };
}

sub node_at {
    my ($name, $ip) = @_;
    return { metadata => { name => $name },
             status   => { addresses => [ { type => 'InternalIP', address => $ip } ] } };
}

sub robocop_deployment {
    my ($image, $ready) = @_;
    return bless {
        metadata => { name => 'robocop', namespace => 'ocp-system' },
        spec     => { template => { spec => { containers => [ { name => 'controller', image => $image } ] } } },
        status   => { readyReplicas => $ready },
    }, 'FakeDeployment';
}

# --- 1. ensure_cp_ocpnode: the Node's address (k8s_node_ip) -------------------

sub cp_ocpnode {
    my (@answer) = @_;
    my $api = ReadApi->new(answers => { @answer ? ('get Node/police1' => [ @answer ]) : () });
    my $r = capture { OCP::Cmd::Apply::CR::ensure_cp_ocpnode(FakeSelf->new, $api,
        { name => 'police1', provider => 'ssh', host => 'police1.k330.test' }); 1 };
    $r->{status} = $api->{status}{'OCPNode/police1'};
    return $r;
}

subtest 'k330 k8s_node_ip: only a 404 is a Node not registered' => sub {
    is OCP::Cmd::Apply::CR::k8s_node_ip(undef, ReadApi->new, 'police1'), undef, '404: undef';
    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        my $api = ReadApi->new(answers => { 'get Node/police1' => [ api_error($code, $reason) ] });
        my $r = capture { OCP::Cmd::Apply::CR::k8s_node_ip(undef, $api, 'police1') };
        like $r->{died}, qr/\Acould not read Node 'police1': .*\b$code\b.*\n\z/s,
            "$code: dies with the cause, it is no Node not there";
    }
};

subtest 'k330 ensure_cp_ocpnode: a failed Node read keeps the recorded address, said on STDERR' => sub {
    my $r = cp_ocpnode(node_at('police1', '10.0.0.7'));
    is $r->{status}{publicIP}, '10.0.0.7', 'control: the Node\'s address';
    is $r->{err}, '', 'control: nothing on STDERR';

    $r = cp_ocpnode();
    is $r->{died}, '', '404: no death';
    is $r->{status}{publicIP}, 'police1.k330.test', '404: the configured host, as before';
    is $r->{err}, '', '404: nothing on STDERR';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = cp_ocpnode(api_error($code, $reason));
        is $r->{died}, '', "$code: no death -- the CR is observational";
        is $r->{status}{phase}, 'Ready', "$code: the status is still written";
        ok !exists $r->{status}{publicIP},
            "$code: without publicIP, so the merge patch keeps the recorded one (not the configured host)";
        like $r->{err}, qr/\A  \[WARN\] OCPNode\/police1 keeps the address it has: could not read Node 'police1': .*\b$code\b.*\n\z/s,
            "$code: the cause on STDERR";
        like $r->{out}, qr/\[ok\] ensured OCPNode\/police1 \(control-plane, Ready\)/, "$code: the CR is ensured";
        unlike $r->{out}, qr/WARN/, "$code: nothing of it on STDOUT";
    }
};

# --- 2. migrate_legacy_nodes ---------------------------------------------------

sub migrate {
    my (%answers) = @_;
    my $api = ReadApi->new(answers => { %answers });
    my $r = capture { OCP::Cmd::Apply::CR::migrate_legacy_nodes(FakeSelf->new, $api); 1 };
    $r->{ensured} = $api->{ensured};
    return $r;
}

subtest 'k330 migrate_legacy_nodes: a failed list is no "nothing to migrate"' => sub {
    my $r = migrate('list OCPNode' => [ FakeList->new ],
                    'list Node'    => [ FakeList->new(node_at('old', '10.0.0.9')) ]);
    is_deeply $r->{ensured}, [ 'OCPNodeProvider/legacy', 'OCPNode/old' ], 'control: the untracked Node is migrated';

    $r = migrate();
    is $r->{died}, '', 'OCPNode list 404 (no CRD yet): no death';
    is_deeply $r->{ensured}, [], 'OCPNode list 404: nothing written';
    is $r->{err}, '', 'OCPNode list 404: nothing on STDERR';

    $r = migrate('list OCPNode' => [ FakeList->new ]);
    is $r->{died}, '', 'Node list 404: no death';
    is_deeply $r->{ensured}, [], 'Node list 404: nothing written';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = migrate('list OCPNode' => [ api_error($code, $reason) ],
                     'list Node'    => [ FakeList->new(node_at('old', '10.0.0.9')) ]);
        like $r->{died}, qr/\Acould not read OCPNodes in ocp-system: .*\b$code\b.*\n\z/s,
            "OCPNode list $code: dies with the cause (its step reports it)";
        is_deeply $r->{ensured}, [], "OCPNode list $code: nothing written";

        $r = migrate('list OCPNode' => [ FakeList->new ], 'list Node' => [ api_error($code, $reason) ]);
        like $r->{died}, qr/\Acould not read Nodes: .*\b$code\b.*\n\z/s, "Node list $code: dies with the cause";
        is_deeply $r->{ensured}, [], "Node list $code: nothing written";
    }
};

# --- 3. sync_worker_meta: the re-read after a 409 -------------------------------

sub sync {
    my (@reread) = @_;
    my $api = ReadApi->new(conflicts => 1, answers => {
        'list OCPNode' => [ FakeList->new(ocpnode_w1()) ],
        @reread ? ('get OCPNode/w1' => [ @reread ]) : (),
    });
    my $r = capture { OCP::Cmd::Apply::CR::sync_worker_meta(undef, $api, config_for($POOL)) };
    $r->{patches} = scalar grep { /^patch / } @{ $api->{calls} };
    return $r;
}

subtest 'k330 sync_worker_meta: the re-read after a conflict says its own failure' => sub {
    my $r = sync(ocpnode_w1());
    is $r->{died}, '', 'control: no death';
    is_deeply $r->{rv}, { patched => [ 'w1' ], failed => [] }, 'control: 409, re-read, patched';

    $r = sync();
    is_deeply $r->{rv}, { patched => [], failed => [] },
        '404 on the re-read: the OCPNode is gone, nothing to patch and nothing failed';
    is $r->{patches}, 1, '404: not patched again';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = sync(api_error($code, $reason));
        is_deeply $r->{rv}{patched}, [], "$code: not patched";
        is scalar @{ $r->{rv}{failed} }, 1, "$code: one failure";
        like $r->{rv}{failed}[0], qr/\Aw1: could not read OCPNode ocp-system\/w1: .*\b$code\b/,
            "$code: named with the re-read's cause";
        unlike $r->{rv}{failed}[0], qr/\b409\b/, "$code: not with the 409 it was re-read for";
    }
};

# --- 4. ensure_robocop: the image it replaces (k227) -----------------------------

sub roll_out {
    my (@answer) = @_;
    my $config = config_for();
    my $api = ReadApi->new(answers => {
        'list Pod' => [ FakeList->new ],
        @answer ? ('get Deployment/robocop' => [ @answer ]) : (),
    });
    my $r = capture { OCP::Cmd::Apply::CR::ensure_robocop(FakeSelf->new, $api, $config); 1 };
    $r->{ensured} = $api->{ensured};
    $r->{want}    = OCP::Robocop::Manifest->image($config);
    return $r;
}

subtest 'k330 ensure_robocop: a running image it cannot read is said, not taken for none' => sub {
    my $r = roll_out(robocop_deployment('reg.k330.test/ocp:0.1', 1));
    like $r->{out}, qr/\[\.\.\] robocop image reg\.k330\.test\/ocp:0\.1 -> \Q$r->{want}\E\n/,
        'control: the replaced image is said';

    $r = roll_out();
    is $r->{died}, '', '404: no death';
    unlike $r->{out}, qr/robocop image .* ->/, '404: nothing replaced, nothing said';
    is $r->{err}, '', '404: nothing on STDERR';
    ok scalar(grep { $_ eq 'Deployment/robocop' } @{ $r->{ensured} }), '404: the Deployment is written';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = roll_out(api_error($code, $reason));
        is $r->{died}, '', "$code: no death -- the read only adds a line";
        like $r->{err},
            qr/\A  \[WARN\] robocop image \Q$r->{want}\E, not compared with the running one: could not read Deployment ocp-system\/robocop: .*\b$code\b.*\n\z/s,
            "$code: the cause on STDERR";
        ok scalar(grep { $_ eq 'Deployment/robocop' } @{ $r->{ensured} }), "$code: the Deployment is written";
    }
};

# --- 5. wait_robocop_ready -------------------------------------------------------

sub wait_ready {
    my ($timeout, @answer) = @_;
    my $api = ReadApi->new(answers => { @answer ? ('get Deployment/robocop' => [ @answer ]) : () });
    local $NOW = 1_000_000;
    my $r = capture { OCP::Cmd::Apply::CR::wait_robocop_ready(FakeSelf->new, $api, $timeout) };
    return $r;
}

subtest 'k330 wait_robocop_ready: running out on a failed read names it on STDERR' => sub {
    my $r = wait_ready(0, robocop_deployment('x', 1));
    is $r->{rv}, 1, 'control: ready';
    is $r->{err}, '', 'control: nothing on STDERR';

    $r = wait_ready(0, robocop_deployment('x', 0));
    is $r->{rv}, 0, 'not ready: 0';
    is $r->{err}, '', 'not ready: the callers say so, nothing here';

    $r = wait_ready(0);
    is $r->{rv}, 0, '404: not ready';
    is $r->{err}, "  [WARN] robocop not seen ready: Deployment ocp-system/robocop not found\n",
        '404: said as what it is -- no Deployment right after it was written';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = wait_ready(0, api_error($code, $reason));
        is $r->{rv}, 0, "$code: not ready";
        like $r->{err}, qr/\A  \[WARN\] robocop not seen ready: could not read Deployment ocp-system\/robocop: .*\b$code\b.*\n\z/s,
            "$code: the cause on STDERR";

        $r = wait_ready(60, api_error($code, $reason), robocop_deployment('x', 1));
        is $r->{rv}, 1, "$code, then ready: ready";
        is $r->{err}, '', "$code, then ready: nothing said";

        $r = wait_ready(10, api_error($code, $reason), robocop_deployment('x', 0));
        is $r->{rv}, 0, "$code, then not ready: not ready";
        is $r->{err}, '', "$code, then not ready: the last read worked, nothing said";
    }
};

# --- 6. poll_nodes_until_terminal (robocop drives the workers) ----------------

sub poll {
    my (@answer) = @_;
    my $api = ReadApi->new(answers => { @answer ? ('get OCPNode/w1' => [ @answer ]) : () });
    local $NOW = 1_000_000;
    my @rows;
    my $r = capture { @rows = OCP::Cmd::Apply::CR::poll_nodes_until_terminal(FakeSelf->new, $api, ['w1'], 600); 1 };
    $r->{row} = $rows[0];
    return $r;
}

subtest 'k330 poll_nodes_until_terminal: a timeout names the last read\'s why' => sub {
    my $r = poll(ocpnode_w1(phase => 'Ready', message => 'up'));
    is_deeply $r->{row}, { name => 'w1', phase => 'Ready', message => 'up' }, 'control: Ready';

    $r = poll(ocpnode_w1());
    is_deeply $r->{row}, { name => 'w1', phase => 'Unknown', message => 'timed out waiting for phase (after 600s)' },
        'Pending throughout: timed out, nothing to add';

    $r = poll();
    is $r->{row}{phase}, 'Unknown', '404 throughout: timed out';
    is $r->{row}{message}, 'timed out waiting for phase (after 600s); OCPNode ocp-system/w1 not found',
        '404 throughout: the OCPNode not there, said';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = poll(api_error($code, $reason));
        is $r->{row}{phase}, 'Unknown', "$code throughout: timed out";
        like $r->{row}{message},
            qr/\Atimed out waiting for phase \(after 600s\); could not read OCPNode ocp-system\/w1: .*\b$code\b/,
            "$code throughout: with the cause";

        $r = poll(api_error($code, $reason), ocpnode_w1(phase => 'Ready', message => 'up'));
        is_deeply $r->{row}, { name => 'w1', phase => 'Ready', message => 'up' }, "$code, then Ready: Ready";

        $r = poll(api_error($code, $reason), ocpnode_w1());
        is $r->{row}{message}, 'timed out waiting for phase (after 600s)',
            "$code, then Pending: the last read worked, nothing to add";
    }
    is $r->{err}, '', 'the rows carry it, nothing on STDERR';
};

# --- 7. cli_reconcile_workers (the CLI drives the workers) ----------------------

sub cli_drive {
    my (@answer) = @_;
    my $config = config_for($POOL);
    my $api = ReadApi->new(answers => { @answer ? ('get OCPNode/w1' => [ @answer ]) : () });
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    no warnings 'redefine';
    local *OCP::SSH::new = sub { bless {}, 'OCP::SSH' };
    local *OCP::SSH::run = sub { { stdout => "K10jointoken\n" } };
    my @rows;
    my $r = capture { @rows = OCP::Cmd::Apply::CR::cli_reconcile_workers($apply, $api, $config, ['w1'],
        { ssh_key_path => '/nonexistent', cp_ip => '10.0.0.1' }); 1 };
    $r->{row}   = $rows[0];
    $r->{calls} = $api->{calls};
    return $r;
}

subtest 'k330 cli_reconcile_workers: an OCPNode it cannot read is no "CR not found"' => sub {
    my $r = cli_drive();
    is $r->{died}, '', '404: no death' or diag $r->{died};
    is_deeply $r->{row}, { name => 'w1', phase => 'Failed', message => 'CR not found after ensure' },
        '404: the CR not found, as before';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = cli_drive(api_error($code, $reason));
        is $r->{row}{phase}, 'Failed', "$code: Failed";
        like $r->{row}{message}, qr/\Acould not read OCPNode ocp-system\/w1: .*\b$code\b/, "$code: with the cause";
        unlike $r->{row}{message}, qr/not found/, "$code: not as a CR not found";
        ok !scalar(grep { /^get OCPNodeProvider/ } @{ $r->{calls} }), "$code: nothing past the read";
    }
};

done_testing;

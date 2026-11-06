#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Kubernetes::REST::APIError;
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Config;
use OCP::Secrets;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Health;

#
# k327: the first deploy waits up to 600s for police1's Node to turn Ready.
# When it did not, two [WARN]s went to STDOUT, and an SSH fallback ran
# /var/lib/rancher/rke2/bin/kubectl with /etc/rancher/rke2/rke2.yaml on the
# node -- on k3s too, which has neither -- and `cilium status` with the same
# rke2.yaml. What it found only chose the next line to print; the bootstrap
# went on either way. Now a Node not seen Ready is one line on STDERR that
# says why: the Ready condition's status, reason and message from the last
# Node list, or that list's failure (k319). Nothing runs over SSH after the
# wait, on either distribution. A failed API connectivity check is a [WARN]
# on STDERR with its cause too.
#
# k336 (the maintainer's call, 2026-11-06): a control plane not Ready after
# the wait is a failed component, as a police2+ that did not join and a
# worker short of Ready have been since k226. Its line is an [!!], it is
# counted as "control plane NAME" -- the name unready_nodes gives police2+ --
# and the run ends APPLY INCOMPLETE and non-zero. Until then it was a [WARN],
# and a run that got past it ended SUCCESSFULLY with exit 0. The bootstrap
# still goes on and returns what the steps after it need, as the deploy goes
# on after a police2+ that did not join.
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

# What Kubernetes::REST dies with for an HTTP error status (as in t/25).
sub api_error {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(
        code    => $code,
        context => 'get',
        body    => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}),
    );
}

# The next answer of a queue, the last one repeating.
sub next_answer { my ($q) = @_; @$q > 1 ? shift @$q : $q->[0] }

# The kubelet's words for a node whose CNI is not up, and for one that went
# silent.
my $CNI_DOWN = 'container runtime network not ready: NetworkReady=false '
             . 'reason:NetworkPluginNotReady message:Network plugin returns error: '
             . 'cni plugin not initialized';

{
    package BootOcp;
    sub new { bless {}, shift } sub verbose { 0 }
    package BootProv;
    sub new                { bless {}, shift }
    sub upload_ssh_key     { }
    sub create_server      { { ip => 'otho.lab', newly_created => 0 } }
    sub wait_for_running   { $_[1] }
    sub advertised_host    { my ($s, %o) = @_; $o{host} }
    sub cleanup_on_failure { }
    package BootCond;
    sub new     { my ($c, %a) = @_; bless { %a }, $c }
    sub type    { $_[0]{type} }
    sub status  { $_[0]{status} }
    sub reason  { $_[0]{reason} }
    sub message { $_[0]{message} }
    package BootStatus;
    sub new        { bless { c => $_[1] }, $_[0] }
    sub conditions { $_[0]{c} }
    package BootNode;
    sub new    { bless { c => $_[1] }, $_[0] }
    sub status { BootStatus->new($_[0]{c}) }
    package BootList;
    sub new   { my ($c, @n) = @_; bless { n => [ @n ] }, $c }
    sub items { $_[0]{n} }
    package BootIO;
    sub new { bless {}, shift } sub object_to_struct { +{ metadata => { name => 'otho' } } }
    # list('Node') answers from {nodes}, the last answer repeating: an
    # arrayref of Ready-condition hashes for one Node ('True' and 'False' are
    # short for a Ready condition with that status and nothing else), 'none'
    # for an empty list, or what the list dies with. _request (the
    # connectivity check) dies with {request_dies} when set.
    package BootApi;
    sub new { my ($c, %a) = @_; bless { lists => 0, %a }, $c }
    sub _request { my ($self) = @_; die $self->{request_dies} if $self->{request_dies}; 1 }
    sub k8s      { BootIO->new }
    sub list {
        my ($self) = @_;
        $self->{lists}++;
        my $answer = main::next_answer($self->{nodes});
        die $answer if ref $answer && ref $answer ne 'ARRAY';
        return BootList->new if $answer eq 'none';
        $answer = [ { type => 'Ready', status => $answer } ] unless ref $answer;
        return BootList->new(BootNode->new([ map { BootCond->new(%$_) } @$answer ]));
    }
}

sub boot_config {
    my ($dist) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(
        "name: amdlab\ncontrol_planes:\n  provider: ssh\n  host: otho.lab\n"
      . ($dist ? "kubernetes:\n  dist: $dist\n" : ''));
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# bootstrap_control_plane up to its return, with the Node list answering
# from $opt{nodes}. Records every command run over SSH: the SSH wait is
# stubbed apart, so each one is a command the bootstrap ran on the node.
sub bootstrap {
    my (%opt) = @_;
    my $api    = BootApi->new(nodes => $opt{nodes}, request_dies => $opt{request_dies});
    my $config = boot_config($opt{dist});
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ BootOcp->new ]);
    my @ssh_runs;
    no warnings 'redefine';
    local *OCP::Provider::for_spec       = sub { BootProv->new };
    local *OCP::Cmd::Apply::_k8s_api     = sub { $api };
    local *OCP::Secrets::save_kubeconfig = sub { 1 };
    local *OCP::Secrets::ensure_age_key  = sub { 1 };
    local *OCP::SSH::new                 = sub { bless {}, 'OCP::SSH' };
    local *OCP::SSH::wait_for_ssh        = sub { 1 };
    local *OCP::SSH::run                 = sub { push @ssh_runs, $_[1]; { stdout => "otho   Ready\n" } };
    local *OCP::Rex::new                 = sub { bless {}, 'OCP::Rex' };
    local *OCP::Rex::install_server      = sub { { kubeconfig => "apiVersion: v1\n" } };
    local *OCP::Cmd::Apply::wait_seconds = sub { };
    my $r = capture { OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
        $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
        admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
    ) };
    $r->{lists}    = $api->{lists};
    $r->{ssh_runs} = \@ssh_runs;
    # What the run counts as failed so far, and what Health::finish needs to
    # end it (k336).
    $r->{failed}   = $apply->{_failed_components} // [];
    @$r{qw( apply config api )} = ($apply, $config, $api);
    return $r;
}

# The single exit of `ocp apply` after that bootstrap, with a pod scan that
# finds nothing wrong: what the run ends with when no later step failed.
sub finish_after {
    my ($b) = @_;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_check_cluster_health = sub { +{ critical => [], warnings => [], starting => [] } };
    local *OCP::Cmd::Apply::_stamp_ocp_version    = sub { };
    return capture { OCP::Cmd::Apply::Health::finish($b->{apply},
        config  => $b->{config},
        api     => $b->{api},
        step    => 9,
        cp_name => $b->{rv}{cp_name},
        cp_ip   => $b->{rv}{cp_ip},
    ) };
}

my $NOT_SEEN = '  [!!] Node otho not seen Ready within 600s';

subtest 'k327: a Node not Ready after the wait is one [!!] on STDERR, with the Ready condition' => sub {
    my $r = bootstrap(nodes => [ 'True' ]);
    is $r->{died}, '', 'control: bootstrap ran' or return diag $r->{died};
    like $r->{out}, qr/\[ok\] Node is Ready after ~10s/, 'control: Ready at once';
    is $r->{err}, '', 'control: nothing on STDERR';
    is_deeply $r->{ssh_runs}, [], 'control: nothing run over SSH';

    $r = bootstrap(nodes => [ [
        { type => 'MemoryPressure', status => 'False', reason => 'KubeletHasSufficientMemory',
          message => 'kubelet has sufficient memory available' },
        { type => 'Ready', status => 'False', reason => 'KubeletNotReady', message => $CNI_DOWN },
    ] ]);
    is $r->{died}, '', 'not Ready: the bootstrap goes on, as before';
    is ref $r->{rv}, 'HASH', 'not Ready: and returns what the deploy steps after it need';
    is $r->{lists}, 60, 'not Ready: listed for the whole wait';
    is $r->{err}, "$NOT_SEEN: Ready is False (KubeletNotReady: $CNI_DOWN)\n",
        'not Ready: one line on STDERR, the Ready condition -- not the one listed before it';
    unlike $r->{out}, qr/WARN|\[!!\]|not seen Ready|via SSH|genuinely/, 'not Ready: nothing of it on STDOUT';
    like $r->{out}, qr{\(60/60\) status='False'}, 'not Ready: the wait itself is still progress on STDOUT';
    is_deeply $r->{ssh_runs}, [], 'not Ready: nothing run over SSH -- no kubectl, no cilium status';

    $r = bootstrap(nodes => [ [ { type => 'Ready', status => 'Unknown', reason => 'NodeStatusUnknown',
                                  message => 'Kubelet stopped posting node status.' } ] ]);
    is $r->{err}, "$NOT_SEEN: Ready is Unknown (NodeStatusUnknown: Kubelet stopped posting node status.)\n",
        'Ready Unknown: the status as it is, with the reason and message';

    $r = bootstrap(nodes => [ 'False' ]);
    is $r->{err}, "$NOT_SEEN: Ready is False\n", 'Ready False with no reason or message: the status alone';

    $r = bootstrap(nodes => [ [ { type => 'Ready', status => 'False', message => $CNI_DOWN } ] ]);
    is $r->{err}, "$NOT_SEEN: Ready is False ($CNI_DOWN)\n", 'a message without a reason: the message';

    $r = bootstrap(nodes => [ [ { type => 'MemoryPressure', status => 'False' } ] ]);
    is $r->{err}, "$NOT_SEEN: it reports no Ready condition\n", 'no Ready condition: said so';

    $r = bootstrap(nodes => [ 'none' ]);
    is $r->{err}, "$NOT_SEEN: no Node listed\n", 'an empty Node list: said so';

    $r = bootstrap(nodes => [ api_error(404, 'NotFound') ]);
    is $r->{err}, "$NOT_SEEN: no Node listed\n", 'a 404 throughout: nothing listed, no read failure';

    $r = bootstrap(nodes => [ [ { type => 'Ready', status => 'False', reason => 'KubeletNotReady', message => $CNI_DOWN } ],
                              'True' ]);
    like $r->{out}, qr/\[ok\] Node is Ready after ~20s/, 'not Ready once, then Ready: Ready';
    is $r->{err}, '', 'not Ready once, then Ready: nothing on STDERR';
};

subtest 'k336: a control plane not Ready after the wait is a failed component' => sub {
    my $r = bootstrap(nodes => [ 'True' ]);
    is $r->{died}, '', 'control: bootstrap ran' or return diag $r->{died};
    is_deeply $r->{failed}, [], 'control: a Ready control plane counts as nothing';
    my $f = finish_after($r);
    is $f->{died}, '', 'control: finish ran' or return diag $f->{died};
    is $f->{rv}, 0, 'control: exit 0';
    like $f->{out}, qr/CONTROL PLANE DEPLOYED SUCCESSFULLY!/, 'control: the success banner';
    is $f->{err}, '', 'control: nothing on STDERR';

    $r = bootstrap(nodes => [ [ { type => 'Ready', status => 'False', reason => 'KubeletNotReady', message => $CNI_DOWN } ] ]);
    is $r->{died}, '', 'not Ready: the bootstrap goes on' or return diag $r->{died};
    is ref $r->{rv}, 'HASH', 'not Ready: and returns what the steps after it need';
    is $r->{rv}{cp_name}, 'otho', 'not Ready: the control plane it names';
    is_deeply $r->{failed}, [ 'control plane otho' ],
        'not Ready: counted once, under the name a police2+ that did not join gets';
    is_deeply $r->{failed}, [ OCP::Cmd::Apply::CR::unready_nodes(undef, [ { name => 'otho', phase => 'Joining' } ], 'control plane') ],
        'not Ready: ... the same name unready_nodes gives a control plane';
    like $r->{err}, qr/\A\Q$NOT_SEEN\E: Ready is False \(KubeletNotReady: /,
        'not Ready: the [!!] line names the node and the kubelet\'s reason';

    $f = finish_after($r);
    is $f->{died}, '', 'not Ready: finish ran' or return diag $f->{died};
    is $f->{rv}, 1, 'not Ready: exit non-zero';
    like $f->{out}, qr/APPLY INCOMPLETE/, 'not Ready: the banner reads APPLY INCOMPLETE';
    unlike $f->{out}, qr/SUCCESSFULLY|WITH WARNINGS/, 'not Ready: no success banner, no mere warning';
    like $f->{err}, qr/^Apply did not complete: control plane otho failed\.$/m,
        'not Ready: the closing line on STDERR names it';

    for my $quiet ([ 'no Node listed' => 'none' ], [ 'a 403 throughout' => api_error(403, 'Forbidden') ]) {
        my ($what, $answer) = @$quiet;
        $r = bootstrap(nodes => [ $answer ]);
        is_deeply $r->{failed}, [ 'control plane otho' ], "$what: counted the same";
        is finish_after($r)->{rv}, 1, "$what: exit non-zero";
    }

    $r = bootstrap(nodes => [ 'False', 'True' ]);
    is_deeply $r->{failed}, [], 'not Ready once, then Ready within the wait: nothing counted';
    is finish_after($r)->{rv}, 0, 'not Ready once, then Ready within the wait: exit 0';

    $r = bootstrap(nodes => [ 'True' ], request_dies => "Connection refused at 10.0.0.1:6443\n");
    is_deeply $r->{failed}, [], 'an unreachable connectivity check, then Ready: a [WARN] alone, not counted';
};

subtest 'k327: a Node list that failed last is that line, with the cause' => sub {
    for my $refusal ([403, 'Forbidden'], [500, 'InternalError']) {
        my ($code, $reason) = @$refusal;
        my $r = bootstrap(nodes => [ api_error($code, $reason) ]);
        is $r->{died}, '', "$code throughout: the bootstrap goes on";
        like $r->{err},
            qr{\A\Q$NOT_SEEN\E; the last read failed: could not read Nodes: Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "$code throughout: one line on STDERR, the cause";
        is_deeply $r->{ssh_runs}, [], "$code throughout: nothing run over SSH";

        $r = bootstrap(nodes => [ api_error($code, $reason), 'False' ]);
        is $r->{err}, "$NOT_SEEN: Ready is False\n", "$code, then not Ready: the last read decides";

        $r = bootstrap(nodes => [ 'False', api_error($code, $reason) ]);
        like $r->{err}, qr{\A\Q$NOT_SEEN\E; the last read failed: could not read Nodes: .*$code}s,
            "not Ready, then $code: the failed read, not the earlier Ready condition";
    }
};

subtest 'k327: on k3s nothing reaches for RKE2 paths' => sub {
    for my $dist (qw( k3s rke2 )) {
        my $r = bootstrap(dist => $dist, nodes => [ 'False' ]);
        is $r->{died}, '', "$dist: bootstrap ran" or next;
        is_deeply $r->{ssh_runs}, [], "$dist: nothing run over SSH after the wait";
        unlike join("\n", @{ $r->{ssh_runs} }, $r->{out}, $r->{err}), qr{/var/lib/rancher|/etc/rancher|kubectl},
            "$dist: no node path and no kubectl, run or printed";
        is $r->{err}, "$NOT_SEEN: Ready is False\n", "$dist: the same [!!]";
    }
};

subtest 'k327: the API connectivity check says its failure on STDERR' => sub {
    my $r = bootstrap(nodes => [ 'True' ], request_dies => "Connection refused at 10.0.0.1:6443\n");
    is $r->{died}, '', 'the bootstrap goes on to the wait';
    is $r->{err}, "  [WARN] API server may not be reachable: Connection refused at 10.0.0.1:6443\n",
        'one line on STDERR, with the cause';
    unlike $r->{out}, qr/WARNING|may not be reachable|Connection refused/, 'nothing of it on STDOUT';
    like $r->{out}, qr/\[ok\] Node is Ready after ~10s/, 'and the wait decides';

    $r = bootstrap(nodes => [ 'True' ]);
    like $r->{out}, qr/API server reachable/, 'control: a reachable API server is progress on STDOUT';
};

subtest 'k327: node_not_ready_why' => sub {
    my $why = \&OCP::Cmd::Apply::Bootstrap::node_not_ready_why;
    is $why->(undef, "could not read Nodes: boom\n"), '; the last read failed: could not read Nodes: boom',
        'a failed read wins, its newline dropped';
    is $why->(BootList->new(BootNode->new([ BootCond->new(type => 'Ready', status => 'True') ])),
              "could not read Nodes: boom\n"),
        '; the last read failed: could not read Nodes: boom', '... over any list';
    is $why->(undef, ''), ': no Node listed', 'undef (a 404), no failure: no Node listed';
    is $why->(BootList->new(BootNode->new([])), undef), ': it reports no Ready condition', 'no conditions';
    is $why->(BootList->new(BootNode->new([ BootCond->new(type => 'Ready', status => 'False', reason => 'R', message => '') ])), undef),
        ': Ready is False (R)', 'an empty message is left out';
};

done_testing;

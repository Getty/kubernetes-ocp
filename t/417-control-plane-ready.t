#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Config;
use OCP::Secrets;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Health;

#
# k417 (the maintainer's call of 2026-11-08), four points:
#
#   1. The reconcile path judges every control plane once -- Ready, or a
#      counted failed component -- with the proof the first deploy's wait
#      uses. Until then a rerun after a bootstrap whose police1 never got
#      Ready could end SUCCESSFULLY over it.
#   2. ensure_cp_ocpnode wrote phase Ready unconditionally. It now writes
#      Ready only when the Node is Ready, Joining with the reason otherwise.
#   3. The bootstrap's Ready wait and node_not_ready_why judged the first
#      Node listed. They now judge the Node named after the control plane.
#   4. On a control plane the bootstrap did not see Ready, a deploy step that
#      must succeed (the registry) ended the run "Error: ..." before the
#      banner, naming the registry, not the node. The run now ends at the
#      banner, APPLY INCOMPLETE, the control plane named first.
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
    package T::Ocp;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }

    # IO::K8s-shaped Node objects, as list('Node') returns them.
    package T::Cond;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub type    { $_[0]{type} }
    sub status  { $_[0]{status} }
    sub reason  { $_[0]{reason} }
    sub message { $_[0]{message} }
    package T::Meta;
    sub name { $_[0]{name} }
    package T::NodeStatus;
    sub conditions { $_[0]{c} }
    package T::Node;
    # T::Node->new(NAME, READY) -- READY 'True', 'False', ... or undef for no
    # Ready condition.
    sub new {
        my ($c, $name, $ready, %more) = @_;
        bless { name => $name,
                c => [ defined $ready ? T::Cond->new(type => 'Ready', status => $ready, %more) : () ] }, $c;
    }
    sub metadata { bless { name => $_[0]{name} }, 'T::Meta' }
    sub status   { bless { c => $_[0]{c} }, 'T::NodeStatus' }
    sub struct {
        my ($s) = @_;
        return { metadata => { name => $s->{name} },
                 status   => { conditions => [ map { +{ %$_ } } @{ $s->{c} } ] } };
    }
    package T::Prov;
    sub new                { bless {}, shift }
    sub upload_ssh_key     { }
    sub create_server      { { ip => 'otho.lab', newly_created => 0 } }
    sub wait_for_running   { $_[1] }
    sub advertised_host    { my ($s, %o) = @_; $o{host} }
    sub cleanup_on_failure { }
    package T::List;
    sub new   { my ($c, @i) = @_; bless { items => [@i] }, $c }
    sub items { $_[0]{items} }
    package T::IO;
    sub new { bless {}, shift }
    sub object_to_struct { my ($s, $o) = @_; ref $o eq 'T::Node' ? $o->struct : $o }

    # list('Node') answers from {nodes}: a queue of arrayrefs of T::Node, the
    # last one repeating. list('OCPNode') answers {ocpnodes}. get('Node', N)
    # answers the struct of the Node called N in the current answer, or 404s.
    package T::Api;
    sub new { my ($c, %a) = @_; bless { node_lists => 0, ensured => [], status => {}, ocpnodes => [], %a }, $c }
    sub k8s { T::IO->new }
    sub _nodes { my ($s) = @_; my $q = $s->{nodes}; @$q > 1 ? shift @$q : $q->[0] }
    sub list {
        my ($s, $kind) = @_;
        return T::List->new(@{ $s->{ocpnodes} }) if $kind eq 'OCPNode';
        $s->{node_lists}++;
        return T::List->new(@{ $s->_nodes });
    }
    sub get {
        my ($s, $kind, $name) = @_;
        # The bootstrap's connectivity check reads the kube-system Namespace (k420).
        return { metadata => { name => $name } } if $kind eq 'Namespace';
        my ($n) = grep { $_->{name} eq $name } @{ $s->{nodes}[0] };
        die Kubernetes::REST::APIError->new(code => 404, context => 'get',
            body => '{"kind":"Status","reason":"NotFound","code":404}') unless $n;
        return $n->struct;
    }
    sub ensure { my ($s, $o) = @_; push @{ $s->{ensured} }, "$o->{kind}/$o->{metadata}{name}"; $o }
    sub patch_status {
        my ($s, $kind, %a) = @_;
        $s->{status}{"$kind/$a{name}"} = $a{patch}{status};
        return 1;
    }
}
use Kubernetes::REST::APIError;

sub project {
    my ($yaml) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    $dir->child('ocp.yaml')->spew_utf8($yaml);
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my $SSH_CP = "name: amdlab\ncontrol_planes:\n  provider: ssh\n  host: otho.lab\n";
my $HA     = "name: ha\ncontrol_planes:\n  provider: hetzner\n  location: fsn1\n  server_type: cx32\n  nodes: 3\n";
my $HA_K3S = $HA . "kubernetes:\n  dist: k3s\n";

my $CNI_DOWN = 'container runtime network not ready: cni plugin not initialized';

# --- 3. the bootstrap's wait judges the Node named after the control plane ---

sub bootstrap {
    my (%opt) = @_;
    my $api    = T::Api->new(nodes => $opt{nodes});
    my $config = project($SSH_CP);
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ T::Ocp->new ]);
    no warnings 'redefine';
    local *OCP::Provider::for_spec       = sub { T::Prov->new };
    local *OCP::Cmd::Apply::_k8s_api     = sub { $api };
    local *OCP::Secrets::save_kubeconfig = sub { 1 };
    local *OCP::SSH::new                 = sub { bless {}, 'OCP::SSH' };
    local *OCP::SSH::wait_for_ssh        = sub { 1 };
    local *OCP::SSH::run                 = sub { { stdout => '' } };
    local *OCP::Rex::new                 = sub { bless {}, 'OCP::Rex' };
    local *OCP::Rex::install_server      = sub { { kubeconfig => "apiVersion: v1\n" } };
    local *OCP::Cmd::Apply::wait_seconds = sub { };
    my $r = capture { OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
        $apply, $config, OCP::Secrets->new(project_dir => $config->project_dir),
        admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
    ) };
    $r->{failed} = $apply->{_failed_components} // [];
    $r->{lists}  = $api->{node_lists};
    return $r;
}

subtest 'k417 point 3: the bootstrap wait judges otho, not the first Node listed' => sub {
    my $r = bootstrap(nodes => [ [ T::Node->new('otho', 'True') ] ]);
    is $r->{died}, '', 'control: bootstrap ran' or return diag $r->{died};
    like $r->{out}, qr/\[ok\] Node is Ready after ~10s/, 'control: its own Node Ready, at once';
    is_deeply $r->{failed}, [], 'control: nothing counted';
    ok $r->{rv}{ready}, 'control: returned ready';

    # Another Node listed first, Ready; otho not Ready. The first Node used to
    # decide: Ready after 10 s, nothing counted.
    $r = bootstrap(nodes => [ [ T::Node->new('other', 'True'),
                                T::Node->new('otho', 'False', reason => 'KubeletNotReady', message => $CNI_DOWN) ] ]);
    is $r->{died}, '', 'a Ready Node listed first: bootstrap ran' or return diag $r->{died};
    unlike $r->{out}, qr/Node is Ready/, '... otho is not called Ready';
    is $r->{lists}, 60, '... it is waited for the whole wait';
    is $r->{err}, "  [!!] Node otho not seen Ready within 600s: Ready is False (KubeletNotReady: $CNI_DOWN)\n",
        '... the [!!] says what otho\'s Ready condition said, not the first Node\'s';
    is_deeply $r->{failed}, [ 'control plane otho' ], '... counted';
    ok !$r->{rv}{ready}, '... returned not ready';

    # The other way round: a NotReady Node listed first, otho Ready.
    $r = bootstrap(nodes => [ [ T::Node->new('other', 'False'), T::Node->new('otho', 'True') ] ]);
    like $r->{out}, qr/\[ok\] Node is Ready after ~10s/, 'a NotReady Node listed first: otho is Ready';
    is $r->{err}, '', '... nothing on STDERR';
    is_deeply $r->{failed}, [], '... nothing counted';

    # Nodes listed, none of them otho.
    $r = bootstrap(nodes => [ [ T::Node->new('other', 'True'), T::Node->new('else', 'True') ] ]);
    is $r->{err}, "  [!!] Node otho not seen Ready within 600s: no Node named otho listed (listed: other, else)\n",
        'no Node named otho: said, with what was listed';
    is_deeply $r->{failed}, [ 'control plane otho' ], '... counted';
};

subtest 'k417 point 3: node_not_ready_why looks the Node up by name' => sub {
    my $why  = \&OCP::Cmd::Apply::Bootstrap::node_not_ready_why;
    my $list = T::List->new(T::Node->new('a', 'True'), T::Node->new('b', 'Unknown', reason => 'NodeStatusUnknown'));
    is $why->($list, '', 'b'), ': Ready is Unknown (NodeStatusUnknown)', 'b: its own condition, not a\'s';
    is $why->($list, '', 'c'), ': no Node named c listed (listed: a, b)', 'c: not listed, and what was';
    is $why->(T::List->new, '', 'a'), ': no Node listed', 'an empty list';
    is $why->(T::List->new(T::Node->new('a', undef)), '', 'a'), ': it reports no Ready condition', 'no Ready condition';
};

subtest 'k417: wait_nodes_ready -- several Nodes, by name' => sub {
    my $apply = OCP::Cmd::Apply->new(command_chain => [ T::Ocp->new ]);
    no warnings 'redefine';
    my $waited = 0;
    local *OCP::Cmd::Apply::wait_seconds = sub { $waited += $_[1] };
    my $api = T::Api->new(nodes => [
        [ T::Node->new('police1', 'True'), T::Node->new('police2', 'False') ],
        [ T::Node->new('police1', 'True'), T::Node->new('police2', 'True') ],
    ]);
    my $r = capture { OCP::Cmd::Apply::Bootstrap::wait_nodes_ready($apply, $api, [ 'police1', 'police2' ]) };
    is_deeply $r->{rv}{ready_after}, { police1 => 10, police2 => 20 }, 'each when it turned Ready';
    is_deeply $r->{rv}{why}, {}, 'nothing left to explain';
    is $api->{node_lists}, 2, 'two lists, then done';
    is $waited, 10, 'one wait between them';
    like $r->{out}, qr{\(1/60\) status='police2=False'}, 'progress names the one still waited for';
};

# --- 2. ensure_cp_ocpnode writes the phase the Node has ----------------------

sub cp_ocpnode {
    my (@nodes) = @_;
    my $api = T::Api->new(nodes => [ [ @nodes ] ]);
    my $self = bless {}, 'OCP::Cmd::Apply';
    my $r = capture { OCP::Cmd::Apply::CR::ensure_cp_ocpnode($self, $api,
        { name => 'police1', provider => 'hetzner', host => '10.0.0.1' }); 1 };
    $r->{status} = $api->{status}{'OCPNode/police1'};
    $r->{self}   = $self;
    return $r;
}

subtest 'k417 point 2: the control plane\'s OCPNode is Ready only over a Ready Node' => sub {
    my $r = cp_ocpnode(T::Node->new('police1', 'True'));
    is $r->{died}, '', 'control: ran' or return diag $r->{died};
    is $r->{status}{phase}, 'Ready', 'a Ready Node: phase Ready';
    ok exists $r->{status}{message} && !defined $r->{status}{message},
        '... and a message an earlier write left is dropped (null in the merge patch)';
    like $r->{out}, qr{\[ok\] ensured OCPNode/police1 \(control-plane, Ready\)}, '... said so';

    $r = cp_ocpnode(T::Node->new('police1', 'False', reason => 'KubeletNotReady', message => $CNI_DOWN));
    is $r->{status}{phase}, 'Joining', 'a NotReady Node: not Ready -- Joining';
    is $r->{status}{message}, "Node police1 not Ready: Ready is False (KubeletNotReady: $CNI_DOWN)",
        '... with the reason in status.message';
    like $r->{out}, qr{\[ok\] ensured OCPNode/police1 \(control-plane, Joining\)}, '... and STDOUT claims no Ready';
    unlike $r->{out}, qr/control-plane, Ready/, '... none at all';
    ok !$r->{self}{_failed_components}, '... and counts nothing: the wait judges the node';

    $r = cp_ocpnode(T::Node->new('police9', 'True'));
    is $r->{status}{phase}, 'Joining', 'no Node by its name (another one Ready): Joining';
    is $r->{status}{message}, 'Node police1 not Ready: no Node named police1', '... and why';
    is $r->{status}{publicIP}, '10.0.0.1', '... the configured host as its address, as before';

    $r = cp_ocpnode(T::Node->new('police1', undef));
    is $r->{status}{phase}, 'Joining', 'a Node with no Ready condition: Joining';
};

# --- 1. the reconcile path judges every control plane ------------------------

sub judge {
    my (%opt) = @_;
    my $api = T::Api->new(nodes => $opt{nodes}, ocpnodes => $opt{ocpnodes} // []);
    my $apply = OCP::Cmd::Apply->new(command_chain => [ T::Ocp->new ]);
    $apply->{_failed_components} = [ @{ $opt{failed} } ] if $opt{failed};
    no warnings 'redefine';
    local *OCP::Cmd::Apply::wait_seconds = sub { };
    my $r = capture { [ OCP::Cmd::Apply::CR::check_control_plane_ready($apply, $api, project($opt{yaml} // $HA)) ] };
    $r->{failed} = $apply->{_failed_components} // [];
    $r->{lists}  = $api->{node_lists};
    return $r;
}

subtest 'k417 point 1: check_control_plane_ready' => sub {
    my @all_ready = map { T::Node->new("police$_", 'True') } 1 .. 3;
    my $r = judge(nodes => [ [ @all_ready ] ]);
    is $r->{died}, '', 'control: ran' or return diag $r->{died};
    is_deeply $r->{rv}, [], 'all three Ready: none returned';
    is $r->{lists}, 1, '... one Node list, no wait';
    like $r->{out}, qr/\[ok\] control plane police1 is Ready\n.*police2 is Ready\n.*police3 is Ready/s,
        '... each said on STDOUT';
    is $r->{err}, '', '... nothing on STDERR';
    is_deeply $r->{failed}, [], '... nothing counted';

    $r = judge(nodes => [ [ T::Node->new('police1', 'False', reason => 'KubeletNotReady', message => $CNI_DOWN),
                            T::Node->new('police2', 'True'), T::Node->new('police3', 'True') ] ]);
    is_deeply $r->{rv}, [ 'police1' ], 'police1 NotReady: returned';
    is $r->{lists}, 60, '... after the same wait as the bootstrap: 60 lists';
    is $r->{err}, "  [!!] Node police1 not seen Ready within 600s: Ready is False (KubeletNotReady: $CNI_DOWN)\n",
        '... the bootstrap\'s [!!] line, with the Ready condition';
    is_deeply $r->{failed}, [ 'control plane police1' ], '... counted under the bootstrap\'s name';
    like $r->{out}, qr/\[ok\] control plane police2 is Ready/, '... the others still Ready';

    $r = judge(nodes => [ [ T::Node->new('police1', 'False'), @all_ready[1, 2] ], [ @all_ready ] ]);
    is_deeply $r->{rv}, [], 'NotReady once, then Ready within the wait: nothing returned';
    is_deeply $r->{failed}, [], '... nothing counted';

    $r = judge(nodes => [ [ @all_ready[0, 1] ] ]);
    is_deeply $r->{rv}, [ 'police3' ], 'police3 has no Node: not Ready';
    like $r->{err}, qr/Node police3 not seen Ready within 600s: no Node named police3 listed/, '... said why';

    $r = judge(nodes => [ [ @all_ready[0, 1] ] ],
               ocpnodes => [ { metadata => { name => 'police3' }, spec => { role => 'control-plane' },
                               status => { phase => 'Failed' } } ]);
    is_deeply $r->{rv}, [], 'police3 Failed: left to check_control_plane_phases, not waited for';
    is $r->{lists}, 1, '... one list';
    is $r->{err}, '', '... nothing said here';

    $r = judge(yaml => $HA_K3S, nodes => [ [ $all_ready[0] ] ]);
    is_deeply $r->{rv}, [], 'k3s: police1 only -- k3s builds no police2+ (k8)';
    unlike $r->{out}, qr/police2/, '... police2 not looked for';

    $r = judge(nodes => [ [ T::Node->new('police1', 'False'), @all_ready[1, 2] ] ],
               failed => [ 'control plane police1' ]);
    is_deeply $r->{failed}, [ 'control plane police1' ], 'counted once, also when already counted';
};

subtest 'k417 point 1: reconcile_components runs the judgement, before the registry' => sub {
    my $src = path('lib/OCP/Cmd/Apply/Drift.pm')->slurp_utf8;
    my ($body) = $src =~ /^sub reconcile_components \{\n(.*?)\n\}$/ms;
    ok defined $body, 'reconcile_components found' or return;
    my $judge = index $body, 'check_control_plane_ready(';
    my $reg   = index $body, '_setup_registry(';
    ok $judge >= 0, 'it calls check_control_plane_ready';
    ok $judge < $reg, '... before the registry step';
    like $body, qr/unless \(\(\$self->only \/\/ ''\) eq 'workers'\) \{\n\s+\$checked\+\+;\n\s+print "  \[\.\.\] Checking control planes are Ready/,
        '... not with --only workers, as the phase check';
};

# --- 4. a must-succeed step after a NotReady bootstrap -----------------------

sub first_deploy {
    my (%opt) = @_;
    my $config = project($SSH_CP);
    my $api    = T::Api->new(nodes => [ [] ]);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::SopsRepair::repair_sops_files      = sub { };
    local *OCP::Cmd::Apply::Bootstrap::ensure_dev_age_key      = sub { };
    local *OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane = sub {
        my ($self) = @_;
        push @{ $self->{_failed_components} }, 'control plane otho' unless $opt{ready};
        return { api => $api, cp_name => 'otho', cp_ip => '10.0.0.1', ready => $opt{ready} };
    };
    local *OCP::Cmd::Apply::Deploy::deploy = sub {
        die "Registry pods not ready after 120s\n" if $opt{dies};
        return 9;
    };
    local *OCP::Cmd::Apply::_check_cluster_health = sub { +{ critical => [], warnings => [], starting => [] } };
    local *OCP::Cmd::Apply::_stamp_ocp_version    = sub { };
    my $apply = OCP::Cmd::Apply->new(command_chain => [ T::Ocp->new(config => $config->file . '') ]);
    return capture { $apply->execute([], []) };
}

subtest 'k417 point 4: the registry dying on a NotReady control plane ends at the banner' => sub {
    my $r = first_deploy(ready => 1, dies => 1);
    is $r->{died}, "Registry pods not ready after 120s\n",
        'control: on a Ready control plane the step\'s death is its own, as before';

    $r = first_deploy(ready => 0, dies => 1);
    is $r->{died}, '', 'NotReady control plane: the run does not die' or return diag $r->{died};
    is $r->{rv}, 1, '... exit non-zero';
    like $r->{out}, qr/APPLY INCOMPLETE/, '... the banner reads APPLY INCOMPLETE';
    unlike $r->{out}, qr/SUCCESSFULLY/, '... no success';
    like $r->{err}, qr/^  \[!!\] Deploy stopped: Registry pods not ready after 120s$/m,
        '... the step\'s error, one [!!] line';
    like $r->{err}, qr/control plane otho was not seen Ready/, '... said to follow from the node';
    like $r->{err}, qr/^Apply did not complete: control plane otho, deploy steps failed\.$/m,
        '... the closing line names the control plane first';

    $r = first_deploy(ready => 0, dies => 0);
    is $r->{rv}, 1, 'NotReady control plane, the deploy went through: still incomplete (k336)';
    unlike $r->{err}, qr/Deploy stopped/, '... and nothing stopped';
};

done_testing;

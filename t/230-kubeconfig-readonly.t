#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use MIME::Base64 qw(encode_base64);
use Cwd qw(getcwd);

use lib 'lib';
use OCP;
use OCP::Cmd::Kubeconfig;
use OCP::ReadonlyKubeconfig;

{
    package FakeResp;
    sub new     { bless { s => $_[1] }, $_[0] }
    sub status  { $_[0]{s} }
    sub content { '' }
}
{
    package FakeIO;
    sub new              { bless {}, $_[0] }
    sub object_to_struct { $_[1] }
}
{
    # Stores what Server-Side Apply sends, like the API server would.
    package FakeApi;
    sub new { my ($c, %a) = @_; bless { objs => {}, applies => 0, deletes => [], %a }, $c }
    sub k8s { FakeIO->new }
    sub _request {
        my ($self, $method, $path, $res, %o) = @_;
        die "expected PATCH\n" unless $method eq 'PATCH';
        die "expected apply\n" unless $o{content_type} eq 'application/apply-patch+yaml';
        $self->{applies}++;
        my $key = "$res->{kind}/$res->{metadata}{name}";
        $self->{paths}{$key} = $path;
        $self->{objs}{$key} = $res;
        if ($res->{kind} eq 'Secret' && !$self->{no_controller}) {
            $self->{objs}{$key}{data}{token} //= MIME::Base64::encode_base64('tok-' . $res->{metadata}{name}, '');
        }
        return FakeResp->new(200);
    }
    sub get {
        my ($self, $kind, %a) = @_;
        my $o = $self->{objs}{"$kind/$a{name}"} or die "404 not found $kind/$a{name}\n";
        return $o;
    }
    sub delete {
        my ($self, $kind, %a) = @_;
        my $key = "$kind/$a{name}";
        die "404 not found $key\n" unless delete $self->{objs}{$key};
        push @{$self->{deletes}}, $key;
    }
}

my $ADMIN = <<'YAML';
apiVersion: v1
kind: Config
clusters:
- name: default
  cluster:
    server: https://1.2.3.4:6443
    certificate-authority-data: Q0FEQVRB
users:
- name: default
  user:
    client-certificate-data: AAAA
    client-key-data: BBBB
contexts:
- name: default
  context: {cluster: default, user: default}
current-context: default
YAML

sub cmd {
    my (%a) = @_;
    return OCP::Cmd::Kubeconfig->new(
        k8s => FakeApi->new, admin_kubeconfig => $ADMIN, cluster_name => 'mycl', %a);
}

sub run {
    my ($c) = @_;
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die; open my $e, '>', \$err or die;
    my $rc;
    { local *STDOUT = $o; local *STDERR = $e; $rc = $c->_readonly($c->_check_options); }
    return ($out, $err, $rc);
}

# --- created objects
{
    my $c = cmd(readonly => 1);
    my ($out, $err) = run($c);
    my $o = $c->k8s->{objs};

    ok $o->{'ServiceAccount/ocp-readonly-leitstand'}, 'ServiceAccount, default name leitstand';
    is $o->{'ServiceAccount/ocp-readonly-leitstand'}{metadata}{namespace}, 'ocp-system', 'in ocp-system';

    my $view = $o->{'ClusterRoleBinding/ocp-readonly-leitstand-view'};
    is $view->{roleRef}{name}, 'view', 'binding to built-in view';
    is $view->{roleRef}{kind}, 'ClusterRole', '... a ClusterRole';
    is_deeply $view->{subjects}, [{kind => 'ServiceAccount', name => 'ocp-readonly-leitstand', namespace => 'ocp-system'}], 'subject';

    my $role = $o->{'ClusterRole/ocp-readonly'};
    is_deeply [map { @{$_->{verbs}} } @{$role->{rules}}], [qw(get list watch get list watch)], 'verbs are read-only';
    is_deeply $role->{rules}[0]{resources}, ['nodes'], 'nodes';
    is_deeply $role->{rules}[1]{apiGroups}, ['ocp.internal'], 'ocp.internal';
    is_deeply $role->{rules}[1]{resources}, [qw(ocpnodes ocpnodeproviders)], 'OCP CRDs';
    is $o->{'ClusterRoleBinding/ocp-readonly-leitstand'}{roleRef}{name}, 'ocp-readonly', 'binding to ocp-readonly';

    my $s = $o->{'Secret/ocp-readonly-leitstand-token'};
    is $s->{type}, 'kubernetes.io/service-account-token', 'secret type';
    is $s->{metadata}{annotations}{'kubernetes.io/service-account.name'}, 'ocp-readonly-leitstand', 'annotation';
    is $c->k8s->{paths}{'ClusterRole/ocp-readonly'}, '/apis/rbac.authorization.k8s.io/v1/clusterroles/ocp-readonly', 'cluster-scoped path';

    # --- kubeconfig on STDOUT
    my $kc = OCP->load($out);
    is $kc->{clusters}[0]{name}, 'mycl', 'cluster named after the cluster';
    is $kc->{clusters}[0]{cluster}{server}, 'https://1.2.3.4:6443', 'server from admin kubeconfig';
    is $kc->{clusters}[0]{cluster}{'certificate-authority-data'}, 'Q0FEQVRB', 'CA from admin kubeconfig';
    is $kc->{users}[0]{name}, 'ocp-readonly-leitstand', 'user name';
    is $kc->{users}[0]{user}{token}, 'tok-ocp-readonly-leitstand-token', 'decoded token';
    is $kc->{'current-context'}, 'mycl', 'current-context';
    unlike $out, qr/client-key-data|BBBB|client-certificate/, 'no admin credential in the output';
    like $err, qr/--revoke --name leitstand/, 'hint on STDERR';
    unlike $err, qr/tok-/, 'token not on STDERR';

    # --- idempotent
    my ($out2) = run($c);
    is $out2, $out, 'second call: same kubeconfig, same token';
    is scalar(keys %$o), 5, 'no new objects (SA, CR, 2 CRB, Secret)';
}

# --- --server names the address the reader reaches
{
    my ($out) = run(cmd(readonly => 1, server => 'https://cp-lab.ai.citilan.de:6443'));
    my $kc = OCP->load($out);
    is $kc->{clusters}[0]{cluster}{server}, 'https://cp-lab.ai.citilan.de:6443', '--server replaces the admin server';
    is $kc->{clusters}[0]{cluster}{'certificate-authority-data'}, 'Q0FEQVRB', 'the CA stays';
    ok !eval { cmd(server => 'https://x:6443')->_check_options; 1 }, '--server without --readonly';
    like $@, qr/--server only works together with --readonly/, 'is refused';
}

# --- nothing on disk
{
    my $dir = tempdir(CLEANUP => 1);
    my $old = getcwd; chdir $dir;
    run(cmd(readonly => 1, name => 'pulse'));
    my @files = glob("$dir/* $dir/.??*");
    chdir $old;
    is scalar(@files), 0, 'nothing written to the working directory';
}

# --- revoke
{
    my $c = cmd(readonly => 1, name => 'pulse');
    run($c);
    my $r = cmd(readonly => 1, revoke => 1, name => 'pulse', k8s => $c->k8s);
    my ($out, $err) = run($r);
    is $out, '', 'revoke prints nothing on STDOUT';
    like $err, qr/Revoked 'ocp-readonly-pulse'/, 'revoke message on STDERR';
    is_deeply [sort keys %{$c->k8s->{objs}}], ['ClusterRole/ocp-readonly'], 'only the shared ClusterRole stays';
    ($out, $err) = run($r);
    like $err, qr/Nothing to revoke/, 'second revoke is fine';
}

# --- option conflicts and name validation
{
    for my $o (qw(export output refresh)) {
        eval { cmd(readonly => 1, $o => 1)->_check_options };
        like $@, qr/cannot be combined with --$o/, "--readonly with --$o refused";
    }
    eval { cmd(revoke => 1)->_check_options };
    like $@, qr/--revoke only works together with --readonly/, '--revoke alone';
    eval { cmd(name => 'x')->_check_options };
    like $@, qr/--name only works together with --readonly/, '--name alone';
    for my $bad ('Foo', 'a_b', '-a', 'a-', 'a.b', 'x' x 33, '') {
        eval { cmd(readonly => 1, name => $bad)->_check_options };
        like $@, qr/Invalid --name|needs a value/, "name '$bad' refused";
    }
    is eval { cmd(readonly => 1, name => 'citiai-admin')->_check_options }, 'citiai-admin', 'valid name accepted';
}

# --- token controller never answers
{
    my $api = FakeApi->new(no_controller => 1);
    eval { OCP::ReadonlyKubeconfig->ensure($api, 'x', timeout => 0) };
    like $@, qr/token controller has not filled Secret ocp-system\/ocp-readonly-x-token/, 'clear timeout error';
}

done_testing;

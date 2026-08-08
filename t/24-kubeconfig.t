#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Kubeconfig;

# What RKE2/K3s hand out: everything named 'default'.
my $RKE2 = <<'YAML';
apiVersion: v1
kind: Config
clusters:
- name: default
  cluster:
    server: https://1.2.3.4:6443
    insecure-skip-tls-verify: true
users:
- name: default
  user:
    client-certificate-data: AAAA
    client-key-data: BBBB
contexts:
- name: default
  context:
    cluster: default
    user: default
current-context: default
YAML

# An unrelated cluster already in the user's kubeconfig.
my $EXISTING = <<'YAML';
apiVersion: v1
kind: Config
clusters:
- name: work
  cluster:
    server: https://work.example.com:6443
users:
- name: work
  user:
    token: sekrit
contexts:
- name: work
  context:
    cluster: work
    user: work
current-context: work
YAML

#
# Test: rename_entries
#

{
    my $kc = OCP::Kubeconfig->parse($RKE2);
    my $ctx = OCP::Kubeconfig->rename_entries($kc, 'mycluster');

    is($ctx, 'mycluster', 'returns the new context name');
    is($kc->{clusters}[0]{name}, 'mycluster', 'cluster renamed');
    is($kc->{users}[0]{name}, 'mycluster', 'user renamed');
    is($kc->{contexts}[0]{name}, 'mycluster', 'context renamed');
    is($kc->{contexts}[0]{context}{cluster}, 'mycluster', 'context cluster ref rewired');
    is($kc->{contexts}[0]{context}{user}, 'mycluster', 'context user ref rewired');
    is($kc->{'current-context'}, 'mycluster', 'current-context set');
    is($kc->{clusters}[0]{cluster}{server}, 'https://1.2.3.4:6443', 'server untouched');
}

{
    my $kc = OCP::Kubeconfig->parse(<<'YAML');
apiVersion: v1
kind: Config
clusters:
- name: a
  cluster:
    server: https://a:6443
- name: b
  cluster:
    server: https://b:6443
users:
- name: a
  user: {}
- name: b
  user: {}
contexts:
- name: a
  context:
    cluster: a
    user: a
- name: b
  context:
    cluster: b
    user: b
YAML

    OCP::Kubeconfig->rename_entries($kc, 'multi');
    is($kc->{clusters}[0]{name}, 'multi-a', 'multiple clusters get prefixed');
    is($kc->{clusters}[1]{name}, 'multi-b', 'second cluster prefixed');
    is($kc->{contexts}[1]{context}{cluster}, 'multi-b', 'refs follow the prefix');
    is($kc->{'current-context'}, 'multi-a', 'current-context is the first context');
}

{
    my $kc = OCP::Kubeconfig->parse($RKE2);
    eval { OCP::Kubeconfig->rename_entries($kc, '') };
    like($@, qr/name required/, 'rename without a name is refused');
}

#
# Test: merge keeps unrelated entries
#

{
    my $base     = OCP::Kubeconfig->parse($EXISTING);
    my $incoming = OCP::Kubeconfig->parse($RKE2);
    OCP::Kubeconfig->rename_entries($incoming, 'mycluster');

    my $merged = OCP::Kubeconfig->merge($base, $incoming);

    my @clusters = map { $_->{name} } @{$merged->{clusters}};
    is_deeply(\@clusters, ['work', 'mycluster'], 'existing cluster kept, new one appended');
    is($merged->{'current-context'}, 'mycluster', 'current-context switches to the new cluster');

    my ($work) = grep { $_->{name} eq 'work' } @{$merged->{clusters}};
    is($work->{cluster}{server}, 'https://work.example.com:6443', 'unrelated cluster untouched');
}

{
    # Re-exporting the same cluster replaces its entry instead of duplicating
    my $incoming = OCP::Kubeconfig->parse($RKE2);
    OCP::Kubeconfig->rename_entries($incoming, 'mycluster');
    my $first = OCP::Kubeconfig->merge({}, $incoming);

    my $updated = OCP::Kubeconfig->parse($RKE2);
    $updated->{clusters}[0]{cluster}{server} = 'https://9.9.9.9:6443';
    OCP::Kubeconfig->rename_entries($updated, 'mycluster');
    my $second = OCP::Kubeconfig->merge($first, $updated);

    is(scalar @{$second->{clusters}}, 1, 'no duplicate cluster entry');
    is($second->{clusters}[0]{cluster}{server}, 'https://9.9.9.9:6443', 'entry updated in place');
}

#
# Test: export writes, backs up and stays parseable
#

{
    my $dir    = tempdir(CLEANUP => 1);
    my $target = path($dir)->child('kube', 'config');
    $target->parent->mkpath;
    $target->spew_utf8($EXISTING);

    my $result = OCP::Kubeconfig->export(
        kubeconfig => $RKE2,
        name       => 'mycluster',
        target     => "$target",
    );

    is($result->{target}, "$target", 'target reported back');
    is($result->{context}, 'mycluster', 'context reported back');
    is($result->{backup}, "$target.ocp-bak", 'backup path reported back');
    ok(-f "$target.ocp-bak", 'backup written');

    my $written = OCP::Kubeconfig->parse($target->slurp_utf8);
    my @contexts = sort map { $_->{name} } @{$written->{contexts}};
    is_deeply(\@contexts, ['mycluster', 'work'], 'both contexts present after export');

    my $mode = sprintf '%04o', (stat "$target")[2] & 07777;
    is($mode, '0600', 'target is not world readable');

    # YAML booleans must survive as booleans — kubectl rejects 1/0 here
    like($target->slurp_utf8, qr/insecure-skip-tls-verify:\s*true/,
        'boolean stays a boolean');
}

{
    my $dir    = tempdir(CLEANUP => 1);
    my $target = path($dir)->child('config');

    my $result = OCP::Kubeconfig->export(
        kubeconfig => $RKE2,
        name       => 'fresh',
        target     => "$target",
    );

    is($result->{backup}, undef, 'no backup when there was no file');
    ok(-f $target, 'target created');
}

#
# Test: default_target
#

{
    local $ENV{KUBECONFIG} = '/tmp/first:/tmp/second';
    is(OCP::Kubeconfig->default_target, '/tmp/first', 'KUBECONFIG wins, first entry only');

    local $ENV{KUBECONFIG} = '';
    local $ENV{HOME} = '/home/someone';
    is(OCP::Kubeconfig->default_target, '/home/someone/.kube/config', 'falls back to ~/.kube/config');
}

done_testing;

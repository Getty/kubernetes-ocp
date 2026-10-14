#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';
use OCP::Kubernetes;

# k205: robocop joins a worker without Rex::Rancher's version-skew check because
# it has no kubeconfig file. The service account becomes one.

my $dir = path(tempdir(CLEANUP => 1));
$dir->child('token')->spew('tok');
$dir->child('ca.crt')->spew('ca');

my $kc = OCP::Kubernetes->in_cluster_kubeconfig(dir => "$dir", host => '10.43.0.1', port => 443);
ok $kc, 'a kubeconfig comes back';
my $y = YAML::XS::Load($kc);
is $y->{clusters}[0]{cluster}{server}, 'https://10.43.0.1:443', 'server from the service env';
is $y->{clusters}[0]{cluster}{'certificate-authority'}, "$dir/ca.crt", 'CA by path';
is $y->{users}[0]{user}{tokenFile}, "$dir/token", 'token by path, so a rotation is followed';
is $y->{'current-context'}, 'in-cluster', 'current context set';

my $v6 = OCP::Kubernetes->in_cluster_kubeconfig(dir => "$dir", host => 'fd00::1', port => 443);
like $v6, qr{server: https://\[fd00::1\]:443}, 'an IPv6 service address is bracketed';

is( OCP::Kubernetes->in_cluster_kubeconfig(dir => "$dir", host => ''), undef, 'no host: undef' );
is( OCP::Kubernetes->in_cluster_kubeconfig(dir => '/nonexistent', host => '10.43.0.1'), undef,
    'no service account files: undef (outside a pod)' );

done_testing;

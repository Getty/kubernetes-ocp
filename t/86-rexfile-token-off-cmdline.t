#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

use lib 't/lib';
use OCPTest::Rexfile;

#
# k156: the cluster join token never lands on an installer command line.
#
# The k3s tasks once handed the token to the installer as an environment
# assignment in front of `sh` (`curl ... | K3S_TOKEN=<token> sh -s - server`).
# That line is a process command line on the node (`ps` shows it to every local
# user for as long as the installer runs), and the installer copies every K3S_*
# variable into k3s(.agent).service.env, so the token also stayed on disk next
# to the unit. The fix followed Rex::Rancher: the token goes into
# /etc/rancher/<dist>/config.yaml only, written 0600 root:root BEFORE the
# installer runs.
#
# Since k155 the install is Rex::Rancher's, so that guarantee is the library's
# and is held against the real library in t/155-rex-libraries.t (its installer
# lines carry no token, config.yaml goes through its 0600 writer). What stays
# OCP's and is held here: the token travels as a library option only -- no
# command the Rexfile runs itself contains it, on any install task -- and the
# Rexfile code has no K3S_TOKEN of its own.
#
# Whether k3s actually joins with a token it only finds in config.yaml is a
# real-host question and is NOT claimed here.
#

my $TOKEN = 'K10deadbeef::server:s3cr3t-token-value-0123456789';

(my $code = OCPTest::Rexfile->rexfile->slurp_utf8) =~ s/^\s*#.*\n//mg;   # comments may name it
unlike $code, qr/K3S_TOKEN/, 'K3S_TOKEN appears nowhere in the Rexfile code';

for my $task (qw( install_k3s_server install_k3s_agent install_rke2_server install_rke2_agent )) {
    subtest "$task: the token reaches the library, and no command line" => sub {
        OCPTest::Rexfile->reset;
        OCPTest::Rexfile->run_task($task, { token => $TOKEN, server => 'https://10.0.0.1:9345' });

        my $fn = $task =~ /server$/ ? 'Rex::Rancher::Server::install_server'
                                    : 'Rex::Rancher::Agent::install_agent';
        my $o = OCPTest::Rexfile->lib_opts($fn);
        is $o && $o->{token}, $TOKEN, "handed to $fn";

        my @leaks = grep { index($_, $TOKEN) >= 0 } OCPTest::Rexfile->commands;
        is scalar(@leaks), 0, 'no command the Rexfile runs carries the token'
            or diag "@leaks";
        my @files = grep { index($_->{args}[1]{content} // '', $TOKEN) >= 0 } OCPTest::Rexfile->calls('file');
        is scalar(@files), 0, 'and the Rexfile writes no file with it itself (the library does, 0600)';
    };
}

done_testing;

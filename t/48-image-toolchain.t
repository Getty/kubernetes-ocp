#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# The image build used to spend more time bootstrapping a Perl toolchain than
# installing OCP's actual dependencies: 169s compiling perl from source and
# 366s on `cpan -i App::cpanminus App::cpm && cpanm --n Net::SSLeay && cpanm
# LWP::Protocol::https` — the last of which ran the full test suite of every
# dependency it dragged in. Both layers ran before a single line of cpanfile
# was read, and in CI they ran once per architecture (karr #48).
#
# The official perl image already carries perl, cpanm, cpm and a working
# Net::SSLeay, so both layers went away. This suite keeps them from growing
# back, and — more importantly — pins the one thing that made the old layer
# load-bearing rather than merely slow.
#

my $root = path(__FILE__)->parent->parent;

subtest 'the base image is a pinned, prebuilt perl' => sub {
    my $file = $root->child('Dockerfile');
    plan skip_all => 'Dockerfile not found' unless -f $file;

    # ok() rather than like()/unlike(): on failure those dump the whole
    # haystack into the diagnostics, and the haystacks here are files.
    my $df = $file->slurp_utf8;

    ok $df =~ m{^FROM \s+ perl:(\d+\.\d+\.\d+)\S* \s+ AS \s+ ocp-base}mx,
        'the base is an official perl image pinned to an exact patch version';

    ok $df !~ m{\./Configure}, 'perl is not compiled from source';
    ok $df !~ m{cpan\.org/src/}, 'no perl tarball is fetched by hand';

    ok $df !~ m{\bcpan \s+ -i\b}x,
        'the slow CPAN client does not bootstrap the toolchain';
};

#
# This is the assertion that matters for correctness rather than speed.
#
# WWW::Hetzner talks to api.hetzner.cloud through LWP::UserAgent, and LWP
# refuses https unless LWP::Protocol::https is installed. Nothing in lib/ ever
# names that module, so it reads as unused and is exactly the kind of line a
# later cleanup deletes — at which point every Hetzner API call fails at
# runtime, in the image only, with a "protocol scheme not supported" that
# points nowhere near the cpanfile.
#
# It used to be cpanm'd into the system perl by the Dockerfile, i.e. the one
# module standing between OCP and the provider API was the one module the
# snapshot did not describe.
#
subtest 'the https protocol handler is a declared, pinned dependency' => sub {
    my $cpanfile = $root->child('cpanfile');
    my $snapshot = $root->child('cpanfile.snapshot');

    plan skip_all => 'cpanfile not found' unless -f $cpanfile;

    ok $cpanfile->slurp_utf8 =~ m{^requires \s+ 'LWP::Protocol::https'}mx,
        'cpanfile declares LWP::Protocol::https';

    SKIP: {
        skip 'cpanfile.snapshot not found', 1 unless -f $snapshot;

        ok $snapshot->slurp_utf8 =~ m{^\s+LWP-Protocol-https-\d}m,
            'and the snapshot pins it, so the image does not resolve it fresh';
    }
};

done_testing;

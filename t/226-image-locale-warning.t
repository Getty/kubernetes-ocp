#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# k226, lab 2026-10-15/16: the README alias passes the host's LANG into the
# container (-e LANG, for `ocp init`'s locale detection), the image generates
# en_US.UTF-8 only, and every perl started there -- ocp and each rex child --
# printed "perl: warning: Setting locale failed" on STDERR before any OCP code
# ran. No Perl code can catch a warning perl gives at startup; the image's
# environment has to: PERL_BADLANG=0.
#

my $root = path(__FILE__)->parent->parent;

subtest 'the Dockerfile silences the startup locale warning' => sub {
    my $file = $root->child('Dockerfile');
    plan skip_all => 'Dockerfile not found' unless -f $file;
    my $df = $file->slurp_utf8;

    ok $df =~ m{^ENV \s+ PERL_BADLANG=0 \s*$}mx, 'ENV PERL_BADLANG=0';
    ok $df =~ m{^ENV \s+ LANG=en_US\.UTF-8 \s*$}mx, 'the image default stays en_US.UTF-8';
};

subtest 'inside the image: a foreign LANG starts perl quietly' => sub {
    plan skip_all => 'not inside the OCP image' unless -d '/opt/ocp/install/perl5';
    is $ENV{PERL_BADLANG}, '0', 'the environment carries it';
    my $err = `env LANG=de_DE.UTF-8 LC_ALL= $^X -e 1 2>&1`;
    unlike $err, qr/Setting locale failed/, 'no locale warning for a locale the image lacks';
};

done_testing;

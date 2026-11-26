#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use JSON::MaybeXS ();
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';
use OCP;
use OCP::Secrets;

#
# k416: OCP::Secrets decides "is this SOPS file's lastmodified bare?" by
# asking File::SOPS->has_bare_lastmodified (0.006) instead of a regex of its
# own. The claims:
#
#   1. every spelling of a bare timestamp File::SOPS warns about counts --
#      the block form OCP's regex knew, and the ones a hand edit produces that
#      it missed: the value on the next line, an explicit `? lastmodified`
#      key, and a flow-style sops mapping;
#   2. each of those is repaired by repair_sops_lastmodified, values intact,
#      and is no longer bare afterwards (a second run is a no-op);
#   3. a quoted or !!str-tagged value, or a `lastmodified` outside the root
#      sops mapping, is not bare;
#   4. a file YAML::XS cannot read is not bare either: the check croaks on it,
#      and OCP answers 0 there -- neither bare_sops_lastmodified_files (the
#      dry run's list) nor repair_sops_lastmodified dies, and the file is left
#      as it was for the run's own read to refuse.
#

local @ARGV = ();
my $ocp = OCP->new;

delete $ENV{SOPS_AGE_KEY_FILE};

my $warn_qr = qr/time\.Time|PLAIN scalar/;
# The timestamp the file was written with: the MAC is bound to it, so a
# respelling keeps it and only changes how the YAML writes it.
my $TS;

# A dev-mode project: the age key in .ocp/, a token in secrets.yaml.
sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->create_secrets(hetzner_token => 'token-k416');
    return ($dir, $s);
}

# secrets.yaml with its quoted `lastmodified: "..."` line handed to $edit,
# which returns the document to write instead. The parsed value stays the
# same string, so the MAC holds: only the YAML spelling changes.
sub respell {
    my ($dir, $edit) = @_;
    my $file = $dir->child('secrets.yaml');
    my $raw  = $file->slurp_raw;
    ($TS) = $raw =~ /^[ \t]+lastmodified:[ \t]+"([^"\n]+)"[ \t]*$/m
        or die 'no quoted lastmodified in secrets.yaml';
    $file->spew_raw($edit->($raw));
    return $file;
}

# The root sops mapping, rewritten as one flow mapping, lastmodified bare.
sub flow_sops {
    my ($raw) = @_;
    my ($head, $block) = $raw =~ /\A(.*?^)sops:[ \t]*\n((?:[ \t][^\n]*\n?|\n)*)/ms
        or die 'no sops block';
    my $sops = YAML::XS::Load("sops:\n$block")->{sops};
    $sops->{lastmodified} = '@TS@';
    my $flow = JSON::MaybeXS->new(canonical => 1)->encode($sops);
    $flow =~ s/"\@TS\@"/$TS/ or die 'no placeholder';
    my $tail = substr $raw, length($head) + length("sops:\n") + length($block);
    return $head.'sops: '.$flow."\n".$tail;
}

my %bare = (
    'block, same line' => sub { $_[0] =~ s/lastmodified: "\Q$TS\E"/lastmodified: $TS/r },
    'value on the next line' => sub {
        $_[0] =~ s/^([ \t]+)lastmodified: "\Q$TS\E"/$1lastmodified:\n$1$1$TS/mr;
    },
    'explicit ? key' => sub {
        $_[0] =~ s/^([ \t]+)lastmodified: "\Q$TS\E"/$1? lastmodified\n$1: $TS/mr;
    },
    'flow-style sops mapping' => sub { flow_sops($_[0]) },
);

my %not_bare = (
    'double-quoted'    => sub { $_[0] },
    'single-quoted'    => sub { $_[0] =~ s/lastmodified: "\Q$TS\E"/lastmodified: '$TS'/r },
    '!!str tagged'     => sub { $_[0] =~ s/lastmodified: "\Q$TS\E"/lastmodified: !!str $TS/r },
    'outside sops:'    => sub { "lastmodified: $TS\n".$_[0] },
);

# repair_sops_lastmodified with STDOUT caught and File::SOPS's word about the
# bare timestamp it read dropped: (repaired names, stdout, other warnings).
sub repair {
    my ($s) = @_;
    my ($out, @warned) = ('');
    my @done = do {
        open my $fh, '>', \$out or die;
        local *STDOUT = $fh;
        local $SIG{__WARN__} = sub { push @warned, $_[0] unless $_[0] =~ $warn_qr };
        $s->repair_sops_lastmodified;
    };
    return (\@done, $out, \@warned);
}

for my $shape (sort keys %bare) {
    subtest "bare: $shape" => sub {
        my ($dir, $s) = project();
        my $file = respell($dir, $bare{$shape});
        unlike $file->slurp_raw, qr/lastmodified: "/, 'precondition: no quoted lastmodified left';

        is_deeply [ $s->bare_sops_lastmodified_files ], [ 'secrets.yaml' ],
            'bare_sops_lastmodified_files names it';

        my ($done, $out, $warned) = repair($s);
        is_deeply $done, [ 'secrets.yaml' ], 'repair_sops_lastmodified repairs it';
        like $out, qr/^\[ok\] Repaired secrets\.yaml:/m, 'with its [ok] line';
        is_deeply $warned, [], 'and no other warning';

        is_deeply [ $s->bare_sops_lastmodified_files ], [], 'after which it is no longer bare';
        is $s->read_all_secrets->{hetzner_token}, 'token-k416', 'the value intact (MAC verified)';
        is_deeply [ (repair($s))[0] ], [ [] ], 'a second repair is a no-op';
    };
}

for my $shape (sort keys %not_bare) {
    subtest "not bare: $shape" => sub {
        my ($dir, $s) = project();
        my $file   = respell($dir, $not_bare{$shape});
        my $before = $file->slurp_raw;

        is_deeply [ $s->bare_sops_lastmodified_files ], [], 'bare_sops_lastmodified_files: none';
        is_deeply [ (repair($s))[0] ], [ [] ], 'repair_sops_lastmodified: nothing';
        is $file->slurp_raw, $before, 'the file byte for byte as it was';
    };
}

subtest 'unreadable YAML: not bare, nothing dies, nothing written' => sub {
    my ($dir, $s) = project();
    my $file = $dir->child('secrets.yaml');
    $file->spew_raw("hetzner_token: [\nsops:\n    lastmodified: 2026-11-26T10:00:00Z\n");
    my $before = $file->slurp_raw;

    my @named = eval { $s->bare_sops_lastmodified_files };
    is $@, '', 'bare_sops_lastmodified_files does not die';
    is_deeply \@named, [], 'and names nothing';

    my ($done, $out, $warned) = eval { repair($s) };
    is $@, '', 'repair_sops_lastmodified does not die';
    is_deeply $done, [], 'repairs nothing';
    is $out, '', 'says nothing on STDOUT';
    is $file->slurp_raw, $before, 'the file as it was';
    ok !eval { $s->read_all_secrets; 1 }, 'the run\'s own read is what refuses it';
};

subtest 'sops reads a repaired flow-style file' => sub {
    plan skip_all => 'not inside the OCP image' unless -x '/usr/local/bin/sops';
    my ($dir, $s) = project();
    respell($dir, $bare{'flow-style sops mapping'});
    repair($s);
    local $ENV{SOPS_AGE_KEY_FILE} = $dir->child('.ocp/age.key')->stringify;
    system('sops -d '.$dir->child('secrets.yaml').' >/dev/null 2>&1');
    is $? >> 8, 0, 'sops -d exits 0';
};

done_testing;

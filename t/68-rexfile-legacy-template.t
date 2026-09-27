#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::Rexfile;
use OCP::Drift;

#
# The pre-k23 containerd config template, the read-only probe that reports it
# and the Rex task that removes it.
#
# OCP used to write /var/lib/rancher/rke2/agent/etc/containerd/config.toml.tmpl
# with two lines in it: an imports line pointing at /etc/containerd/conf.d and
# `version = 2`. k23 deleted the code. It did not delete the file, and
# nothing else does either -- RKE2 and k3s render config.toml from a template
# they find on every service start, INSTEAD of the config they generate
# themselves, so a host bootstrapped before that fix keeps running containerd
# off the two-liner no matter how often OCP is upgraded (k45, measured on
# cortex before its teardown).
#
# Since k196 the installs no longer run the task: Rex::Rancher's install_server
# and install_agent remove such a template themselves, right before the service
# starts (rex-rancher k72). The task stays as OCP::Drift's remedy for a cluster
# that is only ever upgraded, next to the read-only probe
# (t/71-drift-rex-probe.t), and both now take the decision from the library
# (k196 part 2, option A): Rex::Rancher::Distribution's
# is_bare_template_output decides what the probe reports, and its
# remove_bare_containerd_template removes it -- the same decision the installs
# remove by. OCP keeps no copy of the two-liner and no path list of its own.
#
# Removal is still by CONTENT, never by path: somebody may have put their own
# template there, and theirs has to survive. Up to k196 that decision was
# OCP's own byte-exact comparison (trailing whitespace aside); the library's
# is "blank lines and comments aside, exactly an `imports =` and a
# `version = 2` line", so a bare template with another import glob counts as
# well now. Everything else that OCP kept, the library keeps too. Here with the
# real library's decision (it is pure), and the Rexfile against recorders
# (t/lib/OCPTest/Rexfile.pm); that remove_bare_containerd_template removes the
# two-liner and keeps the rest on a host is held against the real library in
# t/155-rex-libraries.t.
#

# Byte for byte what the deleted _configure_nvidia_containerd wrote: 56 bytes,
# the size measured on cortex in k45.
my $LEGACY = qq{imports = ["/etc/containerd/conf.d/*.toml"]\nversion = 2\n};

OCPTest::Rexfile->load;
my @DISTS = map { Rex::Rancher::Distribution->new_for($_) } qw( rke2 k3s );
my %TMPL  = map { $_->name => $_->containerd_dir . '/config.toml.tmpl' } @DISTS;

# --- what counts as the template ---------------------------------------------

subtest 'the library recognises the template OCP used to write' => sub {
    is length($LEGACY), 56, 'the fixture is the 56-byte two-liner';
    for my $d (@DISTS) {
        ok $d->is_bare_template_output($LEGACY), $d->name . ': the two-liner itself';
        ok $d->is_bare_template_output($LEGACY =~ s/\n\z//r),
            $d->name . ': the same content without a trailing newline';
    }
};

subtest 'anything else is somebody else\'s template and stays' => sub {
    my %other = (
        'a real custom template (has the base include)' =>
            qq{{{ template "base" . }}\n$LEGACY},
        'a different containerd config version' =>
            qq{imports = ["/etc/containerd/conf.d/*.toml"]\nversion = 3\n},
        'the two lines plus an extra directive' =>
            qq{${LEGACY}root = "/var/lib/containerd"\n},
        'only the imports line' =>
            qq{imports = ["/etc/containerd/conf.d/*.toml"]\n},
        'a full generated config' =>
            qq{version = 2\n[plugins]\n  [plugins."io.containerd.grpc.v1.cri"]\n    sandbox_image = "x"\n},
        'an empty file' => '',
    );
    my $d = $DISTS[0];
    ok !$d->is_bare_template_output($other{$_}), "left alone: $_" for sort keys %other;
    ok !$d->is_bare_template_output(undef), 'left alone: unreadable file (undef content)';

    # Widened from OCP's own byte-exact check: a bare template is bare
    # whichever conf.d it imports -- it replaces the generated config just the
    # same.
    ok $d->is_bare_template_output(qq{imports = ["/etc/containerd/mine.d/*.toml"]\nversion = 2\n}),
        'another import glob with nothing else is the same bare template';
};

subtest 'both distributions are covered' => sub {
    is_deeply [ sort values %TMPL ], [ sort
        '/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl',
        '/var/lib/rancher/rke2/agent/etc/containerd/config.toml.tmpl',
    ], 'the rke2 and the k3s template path';
};

# --- the probe ---------------------------------------------------------------

# The probe on a host whose templates are %content (distribution => content;
# missing: no file). Returns what it printed and the commands it ran.
sub probe {
    my (%content) = @_;
    OCPTest::Rexfile->reset;
    my %by_path = map { $TMPL{$_} => $content{$_} } keys %content;
    local $OCPTest::Rexfile::RUN = sub {
        my ($cmd) = @_;
        my ($path) = $cmd =~ /^cat (\S+) 2>\/dev\/null$/ or return ('', 0);
        return defined $by_path{$path} ? ($by_path{$path}, 0) : ('', 1);
    };
    my $out = OCPTest::Rexfile->run_task('detect_legacy_containerd_template');
    return ($out, [ OCPTest::Rexfile->commands ]);
}

subtest 'the probe reports the template where it is, per distribution' => sub {
    my ($out) = probe(rke2 => $LEGACY);
    is $out, "$OCP::Drift::REX_DRIFT_MARKER $TMPL{rke2}\n",
        'rke2: one line with the marker OCP::Drift matches, naming the file';

    ($out) = probe(k3s => $LEGACY);
    is $out, "$OCP::Drift::REX_DRIFT_MARKER $TMPL{k3s}\n", 'k3s the same';
};

subtest 'the probe is silent where there is nothing of the kind, and only reads' => sub {
    my ($out, $cmds) = probe();
    is $out, '', 'no template: silence';
    is_deeply [ sort @$cmds ], [ sort map { "cat $_ 2>/dev/null" } values %TMPL ],
        'it ran nothing but a cat of each template';

    ($out) = probe(rke2 => qq{{{ template "base" . }}\n$LEGACY});
    is $out, '', 'a real custom template: silence';
};

# --- the remedy --------------------------------------------------------------

subtest 'the remedy has the library remove it, for every distribution' => sub {
    OCPTest::Rexfile->reset;
    my %removes = (rke2 => 1, k3s => 0);
    local $OCPTest::Rexfile::LIB_CODE{'Rex::Rancher::Distribution::remove_bare_containerd_template'} =
        sub { $removes{ $_[0]->name } };
    my $out = OCPTest::Rexfile->run_task('cleanup_legacy_containerd_template');

    my @calls = OCPTest::Rexfile->calls('Rex::Rancher::Distribution::remove_bare_containerd_template');
    is_deeply [ sort map { $_->{args}[0]->name } @calls ], [qw( k3s rke2 )],
        'remove_bare_containerd_template for rke2 and k3s';
    my $rke2_dir = $DISTS[0]->containerd_dir;
    like $out, qr/Removed the bare containerd template in \Q$rke2_dir\E/,
        'what was removed is said, naming where';
    unlike $out, qr{/k3s/}, 'what was not is left to the library\'s own log line';

    is_deeply [ OCPTest::Rexfile->commands ], [],
        'and nothing of its own: no restart -- containerd keeps its config.toml until the next start';
};

subtest 'a removal that fails fails the remedy' => sub {
    OCPTest::Rexfile->reset;
    local $OCPTest::Rexfile::LIB_DIE{'Rex::Rancher::Distribution::remove_bare_containerd_template'} =
        "Could not remove $TMPL{rke2}, the bare containerd template ...\n";
    ok !eval { OCPTest::Rexfile->run_task('cleanup_legacy_containerd_template'); 1 }, 'dies';
    like $@, qr/Could not remove/, 'with the library\'s reason';
};

subtest 'the installs leave it to Rex::Rancher, for both distributions and both roles' => sub {
    # Up to k196 prepare_node ran the task before every install. Now the
    # library removes the template itself, right before the service is
    # (re)started -- the only moment at which an inherited template can still
    # be thrown away instead of rendered.
    for my $install (qw(
        install_rke2_server install_rke2_agent
        install_k3s_server  install_k3s_agent
    )) {
        OCPTest::Rexfile->reset;
        OCPTest::Rexfile->run_task($install, { token => 't', server => 'https://x:9345' });
        ok !(grep { $_->{args}[0] eq 'cleanup_legacy_containerd_template' } OCPTest::Rexfile->calls('do_task')),
            "$install does not run the cleanup task";
        is scalar(grep { $_->{name} =~ /^Rex::Rancher::(?:Server::install_server|Agent::install_agent)$/ }
                       @OCPTest::Rexfile::CALLS), 1,
            "$install installs through Rex::Rancher, which removes the template before the start";
    }
};

done_testing;

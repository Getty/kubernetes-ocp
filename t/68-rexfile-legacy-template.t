#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# The pre-#23 containerd config template, and the Rex task that removes it.
#
# OCP used to write /var/lib/rancher/rke2/agent/etc/containerd/config.toml.tmpl
# with two lines in it: an imports line pointing at /etc/containerd/conf.d and
# `version = 2`. karr #23 deleted the code. It did not delete the file, and
# nothing else does either -- RKE2 and k3s render config.toml from a template
# they find on every service start, INSTEAD of the config they generate
# themselves, so a host bootstrapped before that fix keeps running containerd
# off the two-liner no matter how often OCP is upgraded (karr #45, measured on
# cortex before its teardown).
#
# The task therefore removes by CONTENT, never by path: somebody may have put
# their own template there, and theirs has to survive. That decision is the
# thing worth testing, so the Rexfile keeps it in two plain subs with no Rex
# in them, and this file lifts those subs out of the Rexfile and runs them.
# Everything here is text and eval -- no network, no host, no Rex session.
#

my $root    = path(__FILE__)->parent->parent;
my $rexfile = $root->child('share/Rexfile');

plan skip_all => 'share/Rexfile not found' unless -f $rexfile;

my $src = $rexfile->slurp_utf8;

# --- lift the decision out of the Rexfile ----------------------------------

my @wanted = qw(
    _legacy_containerd_template
    _is_legacy_containerd_template
    _legacy_containerd_template_paths
);

my @subs;
for my $name (@wanted) {
    my ($body) = $src =~ /^(sub \Q$name\E \{.*?^\})/ms;
    ok defined $body, "share/Rexfile defines $name"
        or BAIL_OUT("cannot test a decision that is not there: $name");
    push @subs, $body;
}

my $pkg = 'RexfileLegacyTemplate';
ok eval("package $pkg; " . join("\n", @subs) . "\n1;"),
    'the three subs compile on their own -- they carry no Rex dependency'
    or diag $@;

my $known = $pkg->can('_legacy_containerd_template')->();
my $is    = $pkg->can('_is_legacy_containerd_template');
my @paths = $pkg->can('_legacy_containerd_template_paths')->();

# --- what the task is allowed to delete ------------------------------------

subtest 'the known content is exactly what OCP used to write' => sub {
    is $known, qq{imports = ["/etc/containerd/conf.d/*.toml"]\nversion = 2\n},
        'byte for byte the content of the deleted _configure_nvidia_containerd';
    is length($known), 56,
        'and 56 bytes -- the size measured on cortex in karr #45';
};

subtest 'only that exact content is recognised' => sub {
    ok $is->($known), 'the two-liner itself';
    ok $is->("imports = [\"/etc/containerd/conf.d/*.toml\"]\nversion = 2"),
        'the same content without a trailing newline';
};

subtest 'anything else is somebody elses template and stays' => sub {
    my %other = (
        'a real custom template (has the base include)' =>
            qq{{{ template "base" . }}\nimports = ["/etc/containerd/conf.d/*.toml"]\nversion = 2\n},
        'a different import glob' =>
            qq{imports = ["/etc/containerd/mine.d/*.toml"]\nversion = 2\n},
        'a different containerd config version' =>
            qq{imports = ["/etc/containerd/conf.d/*.toml"]\nversion = 3\n},
        'our two lines plus an extra directive' =>
            qq{imports = ["/etc/containerd/conf.d/*.toml"]\nversion = 2\nroot = "/var/lib/containerd"\n},
        'only the imports line' =>
            qq{imports = ["/etc/containerd/conf.d/*.toml"]\n},
        'a full generated config' =>
            qq{version = 2\n[plugins]\n  [plugins."io.containerd.grpc.v1.cri"]\n    sandbox_image = "x"\n},
        'an empty file' => '',
    );

    ok !$is->($other{$_}), "left alone: $_" for sort keys %other;
    ok !$is->(undef), 'left alone: unreadable file (undef content)';
};

subtest 'both distributions are covered' => sub {
    is scalar @paths, 2, 'two paths';
    is_deeply [sort @paths], [sort
        '/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl',
        '/var/lib/rancher/rke2/agent/etc/containerd/config.toml.tmpl',
    ], 'the rke2 and the k3s template path';

    like $_, qr{/agent/etc/containerd/config\.toml\.tmpl$},
        "$_ is the template the agent renders" for @paths;
};

# --- the task itself --------------------------------------------------------

my ($task) = $src =~ /^task "cleanup_legacy_containerd_template", sub \{\n(.*?)\n\};$/ms;

subtest 'the task exists and deletes only behind the content check' => sub {
    ok defined $task, 'task "cleanup_legacy_containerd_template" is defined'
        or return;

    like $src, qr/^desc "[^"]*";\ntask "cleanup_legacy_containerd_template"/m,
        'and carries a desc, so `rex -T` lists it';

    like $task, qr/_legacy_containerd_template_paths/,
        'it walks both template paths';
    like $task, qr/next unless is_file/,
        'a path that does not exist is skipped without a word';

    my $guard  = index $task, '_is_legacy_containerd_template';
    my $remove = index $task, 'unlink';
    cmp_ok $guard,  '>=', 0, 'the content check is in the task';
    cmp_ok $remove, '>=', 0, 'and so is the removal';
    cmp_ok $guard,  '<',  $remove,
        'the check comes first -- nothing is unlinked before the content matched';

    like $task, qr/unless \s* \( \s* _is_legacy_containerd_template .*? \bnext\b/xs,
        'a non-matching file leaves the loop body before the unlink';
};

subtest 'both outcomes end up in the log' => sub {
    ok defined $task, 'task body available' or return;

    like $task, qr/say "Keeping \$path/,
        'a template that is kept says so, naming the file';
    like $task, qr/say "Removed obsolete containerd template \$path/,
        'a template that is removed says so, naming the file';
};

subtest 'every bootstrap runs it, for both distributions and both roles' => sub {
    # prepare_node is the one task all four install tasks call first, and it
    # runs before the service is (re)started -- the only moment at which an
    # inherited template can still be thrown away instead of rendered.
    my ($prepare) = $src =~ /^task "prepare_node", sub \{\n(.*?)\n\};$/ms;
    ok defined $prepare, 'prepare_node found';
    like $prepare, qr/do_task "cleanup_legacy_containerd_template"/,
        'prepare_node runs the cleanup';

    for my $install (qw(
        install_rke2_server install_rke2_agent
        install_k3s_server  install_k3s_agent
    )) {
        my ($body) = $src =~ /^task "\Q$install\E", sub \{\n(.*?)\n\};$/ms;
        ok defined $body, "$install found" or next;
        like $body, qr/do_task "prepare_node"/,
            "$install goes through prepare_node, so it inherits the cleanup";
    }
};

done_testing;

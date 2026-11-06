package OCP::Config;
# ABSTRACT: OCP configuration and status management

use Moo;
use OCP;
use OCP::Choices;
use OCP::NodeMeta;
use OCP::Provider;
use OCP::StateDir;
use JSON::MaybeXS;
use Path::Tiny qw(path);
use Carp qw(croak);
use Socket ();
use YAML::XS ();

# The Hetzner control-plane defaults a fresh spec gets. Kept here because two
# places need the same three values: write_spec falls back to them, and the
# pickers in OCP::Cmd::Init preselect them so pressing Enter reproduces
# exactly what a non-interactive init would have written.
#
# Control planes only: a Hetzner worker pool names its own server_type, and
# validate() refuses one without (k308). server_type: Hetzner catalogue, as of
# 2026-11 (k264).
our %HETZNER_DEFAULTS = (
    server_type => 'cpx22',
    location    => 'fsn1',
    image       => 'debian-13',
);

has ocp => (
    is      => 'lazy',
    default => sub { OCP->instance },
);

# Config file path (ocp.yaml)
has file => (
    is       => 'ro',
    required => 1,
);

# Project directory (derived from config file)
has project_dir => (
    is      => 'lazy',
    builder => sub { path(shift->file)->parent },
);

# Spec data (from ocp.yaml)
has spec => (
    is        => 'lazy',
    builder   => '_load_spec',
    predicate => '_has_spec',
);

# ocp.yaml as YAML::XS reads it, whatever its shape (k340); spec is this once
# it is a mapping. Without a file, the spec a fresh project starts from.
has _file_spec => (
    is       => 'lazy',
    init_arg => undef,
);

#
# Loaders
#

sub _build__file_spec {
    my ($self) = @_;
    return $self->_default_spec unless -f $self->file;
    return $self->ocp->load_file($self->file);
}

# An ocp.yaml that is empty or no mapping stops here, in validate()'s line
# (k340): read on, every accessor died inside Perl ("Not a HASH reference"),
# and every command -- destroy and apply alike -- ended on "This is an
# internal error". A die with a newline, not croak: this is the user's file
# refusing, and OCP::run_cli reads a located error as an internal one (as
# OCP::Rex's failed task does).
sub _load_spec {
    my ($self) = @_;
    my $err = $self->_spec_error;
    die "$err\n" if defined $err;
    return $self->_file_spec;
}

# Refuses with validate()'s lines for what an accessor reads, joined as one
# line, or returns when there is none (an undef is none). A die with a
# newline, as _load_spec dies, not croak (k379): a croak's " at FILE line N."
# is what OCP::run_cli calls an internal error, and a command that reads
# without validate() first -- ocp update on gpu: false -- said that about a
# line of the user's ocp.yaml.
sub _refuse {
    my @lines = grep { defined } @_;
    return unless @lines;
    die join('; ', @lines) . "\n";
}

# What is wrong with ocp.yaml as a whole, one line naming the file, or undef.
sub _spec_error {
    my ($self) = @_;
    my $spec = $self->_has_spec ? $self->spec : $self->_file_spec;
    return undef if ref $spec eq 'HASH';
    my $what = 'a mapping (name, control_planes and the other settings)';
    return defined $spec ? $self->file . ": must be $what, not " . _shown_value($spec)
                         : $self->file . " is empty: it must be $what";
}

sub _default_spec {
    return {
        name => 'mycluster',
        kubernetes => {
            dist    => 'rke2',  # or 'k3s'
            version => '',      # latest if empty
        },
        control_planes => {
            provider => 'hetzner',
            %HETZNER_DEFAULTS,
        },
        workers => [],
        ssh => {
            private_key => '.ocp/id_ed25519',
            public_key  => '.ocp/id_ed25519.pub',
        },
    };
}

#
# Spec accessors
#

sub name { shift->spec->{name} // 'mycluster' }

# The name this cluster's admin public key carries in a provider's key store.
#
# Bootstrap uploads the key under this name before the control plane exists
# (OCP::Provider::Hetzner::upload_ssh_key is an ensure; ssh/local ignore it),
# and every server created for the cluster afterwards has to reference the
# very same one -- a Hetzner worker created with a different name, or with
# none, boots with an empty authorized_keys and is unreachable for good
# (k92).
#
# It lives here because OCP::Config is the only place that knows the cluster
# name in both modes: secure mode uploads the PIN2-protected admin key,
# --nopassword mode uploads the bootstrap key, and both land under this name.
# Two hand-written copies of the string is exactly how the worker path and
# the bootstrap path would drift apart again.
sub admin_ssh_key_name { 'ocp-' . shift->name . '-admin' }

# The name this cluster's robo (automation) public key carries in a provider's
# key store, mirroring admin_ssh_key_name. Bootstrap uploads the robo public
# half beside the admin one so that every Hetzner machine trusts the key
# robocop holds -- otherwise a worker robocop provisions has only the admin key
# in authorized_keys and refuses the robo key, so its install never connects
# and the node goes Failed (k101, variant a). Only the PUBLIC half travels
# to the provider, and it sits behind the age layer alone, so no PIN2 is
# involved -- the age-encrypted robo tier ADR 0006/0027 deliberately keep.
#
# Lives here for the same reason as admin_ssh_key_name: OCP::Config is the one
# place that knows the cluster name, so the bootstrap path and the (later)
# worker path derive the identical string instead of drifting apart.
sub robo_ssh_key_name { 'ocp-' . shift->name . '-robo' }

# kubernetes: (k340). A kubernetes: that is no mapping is refused here in
# validate()'s words, as gpu_config refuses a gpu: of the wrong shape: read
# on, distribution and version died inside Perl on a string.
#
# So is a key in it that is neither of these two (k355), as gpu_config
# refuses one under gpu: (k331). kubernetes: { distribution: k3s } -- the
# name the Rex tasks and robocop give it -- was read by nothing, and the
# cluster was RKE2.
our @KUBERNETES_KEYS = qw( dist version );

# The distributions OCP installs: OCP::Rex picks the k3s tasks for k3s and the
# RKE2 ones for anything else, so dist: rke3 installed RKE2 -- and went out to
# robocop as OCP_DISTRIBUTION=rke3, which it refuses. `ocp init --dist` and
# robocop's OCP_DISTRIBUTION take this list too (k355).
our @DISTRIBUTIONS = qw( rke2 k3s );

sub kubernetes {
    my ($self) = @_;
    my $k8s = $self->spec->{kubernetes};
    _refuse(_kubernetes_shape_error($k8s));
    _refuse(_kubernetes_unknown_keys($k8s));
    return $k8s // {};
}

# What is wrong with the value of kubernetes:, or undef. kubernetes: k3s is
# the likely slip, and the line says what was meant.
sub _kubernetes_shape_error {
    my ($k8s) = @_;
    return undef if !defined $k8s || ref $k8s eq 'HASH';
    return 'kubernetes: must be a mapping (' . join(', ', @KUBERNETES_KEYS) . '), not ' . _shown_value($k8s)
        . (_is_choice($k8s, @DISTRIBUTIONS) ? "; write kubernetes: { dist: $k8s }" : '');
}

# A key of kubernetes: that is neither dist nor version, one line each (k355).
# distribution: with a distribution OCP installs says what was meant, as
# kubernetes: k3s does.
sub _kubernetes_unknown_keys {
    my ($k8s) = @_;
    return () unless ref $k8s eq 'HASH';
    my $dist = $k8s->{distribution};
    return _entry_unknown_keys('kubernetes', $k8s, {
            distribution => defined $dist && _is_choice($dist, @DISTRIBUTIONS)
                ? "write kubernetes: { dist: $dist }" : undef,
        }, @KUBERNETES_KEYS);
}

# kubernetes.version's line, or undef (k355): one release, handed to the
# installer as is, or empty (or absent) for the one OCP::Versions pins. A list
# passed for being true, and went to the installer as a list; a boolean
# is no release either.
#
# Nor is a release of the other distribution (k376): v1.36.4+k3s1 under dist:
# rke2, or under no dist, which is rke2, went to the installer as is, which
# fails on it only on the machine, after a server was bought. $dist is
# kubernetes.dist as ocp.yaml has it.
sub _version_error {
    my ($version, $dist) = @_;
    my $err = _not_a_string($version, 'a release like v1.36.4+rke2r1 or v1.36.4+k3s1; '
        . 'empty for the one OCP pins') // return _release_error($version, $dist);
    return "kubernetes.version: $err";
}

# The suffix each distribution tags its releases with, a number after it:
# v1.36.4+rke2r1 is an RKE2 release, v1.36.4+k3s1 a k3s one.
our %RELEASE_SUFFIX = ( rke2 => '+rke2r', k3s => '+k3s' );

# kubernetes.version's line when it ends in the other distribution's suffix,
# or undef (k376). Only that is refused, by the maintainer's decision: a
# version with no suffix (v1.31.3) and every other form go to the installer as
# before. Beside a dist that is none, whose release it must be is not known,
# and the dist's own line says what is wrong.
sub _release_error {
    my ($version, $dist) = @_;
    my $set = defined $dist;
    $dist //= 'rke2';
    return undef if !defined $version || !_is_choice($dist, @DISTRIBUTIONS);
    my ($other) = grep {
        $_ ne $dist && defined $RELEASE_SUFFIX{$_} && $version =~ /\Q$RELEASE_SUFFIX{$_}\E[0-9]+\z/
    } @DISTRIBUTIONS or return undef;
    my $like = defined $RELEASE_SUFFIX{$dist} ? ' (like v1.36.4' . $RELEASE_SUFFIX{$dist} . '1)' : '';
    return 'kubernetes.version: ' . _shown_value($version) . " is a release of $other, but kubernetes.dist is "
        . $dist . ($set ? '' : ' (not set, the default)')
        . "; write a release of $dist$like, or set kubernetes.dist to $other";
}

# kubernetes.dist's line, or undef: absent is rke2.
sub _dist_error {
    my ($dist) = @_;
    return undef if !defined $dist || _is_choice($dist, @DISTRIBUTIONS);
    return 'kubernetes.dist: invalid value ' . _shown_value($dist)
        . ' (must be ' . OCP::Choices::or_list(@DISTRIBUTIONS) . ')';
}

# Every line under kubernetes:, at its path (k400).
sub _kubernetes_lines {
    my ($k8s) = @_;
    return _tagged(kubernetes => _kubernetes_shape_error($k8s) // ()) unless ref $k8s eq 'HASH';
    return _tagged(kubernetes =>
        _dist_error($k8s->{dist}) // (),
        _version_error($k8s->{version}, $k8s->{dist}) // (),
        _kubernetes_unknown_keys($k8s),
    );
}

# The most control planes `nodes: N` stands for (k305). Every RKE2/K3s
# server is an etcd member, and etcd advises no more than seven: a write
# waits for a majority of them, so each member past that slows every write
# and buys a failure tolerance no one runs (etcd FAQ, "What is maximum
# cluster size?"; 1, 3, 5 and 7 are the sizes in use). It is also what keeps
# control_planes() from taking a nodes: of 10^12 as a repeat count. Since
# k315 it bounds the list form too.
#
# An even count (2, 4, 6) tolerates no more failures than one less does, but
# it works, so it is no refusal; and validate() returns errors only, with no
# channel for a warning. Left for a ticket (k315's notes), not invented here.
our $MAX_CONTROL_PLANE_NODES = 7;

sub control_planes {
    my ($self) = @_;
    my $raw = $self->spec->{control_planes};

    # Array form: one entry per control plane
    return $raw if ref $raw eq 'ARRAY';

    # Hash form: single CP, or `nodes: N` for N identical CPs
    if (ref $raw eq 'HASH') {
        my %cp = %$raw;
        my $count = delete $cp{nodes} // 1;

        # A nodes: that is no whole number, or more than the bound, stands
        # for one control plane, so its entry is still read once; validate()
        # refuses it (k296, k305). Taken as a repeat count, a list numifies
        # to its address and asks for some 10^14 copies, and 10^12 runs out
        # of memory just the same.
        $count = 1 unless _is_whole_number($count) && $count <= $MAX_CONTROL_PLANE_NODES;
        return [(%cp ? \%cp : {}) x $count];
    }

    return [{}];  # Default: 1 empty CP
}

sub workers { shift->spec->{workers} // [] }

# ssh: (k340), the bootstrap key's two paths. An ssh: that is no mapping, or a
# path that is no string, is refused here in validate()'s words: read on, a
# string died inside Perl where ocp destroy (and apply in dev mode) fetched
# the key, and a list was the path ARRAY(0x...).
our @SSH_KEYS = (
    [ private_key => 'a path like .ocp/id_ed25519' ],
    [ public_key  => 'a path like .ocp/id_ed25519.pub' ],
);

sub ssh_config {
    my ($self) = @_;
    _refuse(_ssh_errors($self->spec->{ssh}));
    return $self->spec->{ssh} // {};
}

# What is wrong with ssh:, one line each, or nothing: validate() lists the
# lines and ssh_config refuses on them, so the two cannot disagree.
sub _ssh_errors {
    my ($ssh) = @_;
    return _section_string_errors(ssh => $ssh, @SSH_KEYS);
}

# ssh: (k340), the lines ssh_config refuses on, at its path (k400). A key that
# is neither path (k355) is validate()'s alone, as a pool's are (k347): ssh: {
# privat_key: ... } left the default key in force, but ocp destroy reads ssh:
# in dev mode (OCP::ClusterKey), and refused there it skips the uninstall on
# the ssh machines.
sub _ssh_lines {
    my ($ssh) = @_;
    return (
        _tagged(ssh => _ssh_errors($ssh)),
        _tagged(undef, ref $ssh eq 'HASH' ? _unknown_keys('ssh', $ssh, map { $_->[0] } @SSH_KEYS) : ()),
    );
}

sub single_node {
    my $self = shift;
    my $cps = $self->control_planes;
    my $workers = $self->workers;
    return (scalar(@$cps) <= 1 && scalar(@$workers) == 0);
}

# Refused in validate()'s words (k340): every reader asks this -- ocp apply,
# ocp keys secure, ocp node add, ocp update, the robocop Deployment's
# OCP_DISTRIBUTION -- and none of them may read the one ocp.yaml another way
# than validate() does.
sub distribution {
    my ($self) = @_;
    my $dist = $self->kubernetes->{dist};
    _refuse(_dist_error($dist));
    return $dist // 'rke2';
}

# Refused in validate()'s words (k355), as distribution is: ocp apply, ocp
# update and ocp status read it. A release of the other distribution is
# version's line too (k376); distribution reads on over it.
sub version {
    my $self = shift;
    my $k8s = $self->kubernetes;
    _refuse(_version_error($k8s->{version}, $k8s->{dist}));
    return $k8s->{version} // '';
}

# RKE2 keeps its registration endpoint on a supervisor port of its own,
# next to the apiserver on 6443. k3s serves both from 6443. An agent that
# is pointed at the wrong one never joins.
sub supervisor_port { shift->distribution eq 'k3s' ? 6443 : 9345 }

# The address workers join the control plane at: the public_ip ocp.yaml pins,
# else the host the provider advertised. The reconcile path has always read
# public_ip // host (cluster_status); bootstrap handed the advertised host on,
# which for the ssh provider is `host` -- so a CP with `host: cp.vm` and a
# public_ip had its first-apply workers join via a hostname they could not use,
# and its later ones via the IP (k185).
sub join_host {
    my ($self, $advertised) = @_;
    my $ip = $self->_first_cp_string(($self->control_planes->[0] // {}), 'public_ip');
    return defined $ip && length $ip ? $ip : $advertised;
}

sub join_url {
    my ($self, $host) = @_;
    return sprintf 'https://%s:%d', $host, $self->supervisor_port;
}

sub api_url {
    my ($self, $host) = @_;
    return "https://$host:6443";
}

# Add-on flags (default: enabled, set to true to disable)
sub no_cert { my ($self) = @_; return $self->_switch('nocert', $self->spec) }

# robocop may be a scalar toggle (robocop: true) or a mapping that also
# carries security_level (robocop: { enabled: true, security_level: secret }).
#
#   scalar         → that boolean
#   mapping        → its `enabled` key when set, else on: writing a robocop
#                    mapping at all is an explicit opt-in (as gpu: is), and
#                    enabled:false is how you keep the mapping but turn it off
#   absent         → the hetzner auto-on rule
#
# Anything else is refused in validate()'s words (k315): read on, robocop: no
# was a string Perl calls true, and robocop: { enable: false } a mapping
# without enabled -- both turned robocop on. A refusal rather than off, as
# gpu_config and robocop_security_level do: every reader of the switch asks
# this method (ocp apply, ocp keys secure, the health gate), and none of them
# may read the one ocp.yaml another way than validate() does -- not even in
# the safe direction, where robocop: yes would mean off.
sub robocop_enabled {
    my $self = shift;
    my $val = $self->spec->{robocop};

    _refuse(_robocop_errors($val));

    if (ref $val eq 'HASH') {
        return $val->{enabled} ? 1 : 0 if defined $val->{enabled};
        return 1;
    }
    return $val ? 1 : 0 if defined $val;

    return 1 if $self->_any_hetzner_provider;
    return 0;
}

# The keys of the mapping form, as the robocop: line and an unknown key name them.
our @ROBOCOP_KEYS = qw( enabled security_level image );

# What is wrong with robocop: as a switch, one line each, or nothing (k305,
# k315): validate() lists the lines and robocop_enabled refuses on them, so
# the two cannot disagree. security_level and image have accessors and lines
# of their own.
sub _robocop_errors {
    my ($val) = @_;
    return () if !defined $val || _is_switch($val);
    return 'robocop: must be true, false or a mapping (' . join(', ', @ROBOCOP_KEYS) . '), not '
        . _shown_value($val) . _boolean_hint('robocop', $val)
        unless ref $val eq 'HASH';

    return (
        _switch_error('robocop.enabled', $val->{enabled}) // (),
        _unknown_keys('robocop', $val, @ROBOCOP_KEYS),
    );
}

# A true or false as robocop: takes it (k315): a YAML boolean, or 1 or 0 --
# how a spec written from Perl spells one, and what robocop: 1 always meant.
# No other string: Perl calls 'no' true.
sub _is_switch {
    my ($value) = @_;
    return 1 if JSON::MaybeXS::is_bool($value);
    return defined $value && !ref $value && $value =~ /\A[01]\z/ ? 1 : 0;
}

# "; write KEY: false" for a string that spells a boolean in YAML 1.1's words
# -- no, off, n, a quoted or capitalised false -- which YAML::XS reads as the
# string it is; only a bare true and false are booleans. The gpu: false hint's
# twin: say what was meant where that is plain, and nothing where it is not.
sub _boolean_hint {
    my ($key, $value) = @_;
    return '' if ref $value || !defined $value;
    my $meant = $value =~ /\A(?:y|yes|true|on)\z/i  ? 'true'
              : $value =~ /\A(?:n|no|false|off)\z/i ? 'false'
              :                                        undef;
    return defined $meant ? "; write $key: $meant" : '';
}

# The other on/off switches of ocp.yaml (k320), by key path, with what an
# absent one means. Each is true or false as robocop: is (_is_switch), and
# nothing else: Perl calls a string true, so gpu: { enabled: no } turned the
# GPU stack on, lbipam: off LB-IPAM, and nocert: no left cert-manager out.
# validate() lists a line for each that is neither, and its accessor refuses
# with that line (_switch): ocp update, ocp node add and ocp status' drift
# check read them without validate(), and none of them may read one another
# way than validate() does.
our %SWITCH_DEFAULTS = (
    'gpu.enabled'        => 1,
    'gpu.toolkit'        => 1,
    'gpu.amd.labeller'   => 1,
    'gpu.amd.metrics'    => 0,
    'gpu.amd.integrated' => 0,
    'lbipam'             => 0,
    'nocert'             => 0,
    'system.ntp'         => 1,
);

# The switch at $path as its accessor returns it: 0 or 1, the default when
# absent. $in is the mapping that holds it, as the accessor has it -- the
# gpu_config and gpu_amd_config that refuse a gpu: or gpu.amd: of the wrong
# shape in their own words. Refuses with validate()'s line on anything else.
sub _switch {
    my ($self, $path, $in) = @_;
    my ($key) = $path =~ /([^.]+)\z/;
    my $value = $in->{$key};
    _refuse(_switch_error($path, $value));
    return defined $value ? ($value ? 1 : 0) : $SWITCH_DEFAULTS{$path};
}

# "PATH: must be true or false, not X" for a switch that is neither, with the
# hint for a string that spells one (k315, k320); undef for true, false, 1, 0
# and absent. robocop.enabled's line too.
sub _switch_error {
    my ($path, $value) = @_;
    return undef if !defined $value || _is_switch($value);
    my ($key) = $path =~ /([^.]+)\z/;
    return "$path: must be true or false, not " . _shown_value($value) . _boolean_hint($key, $value);
}

=method robocop_arch_warning

Returns a C<[WARN]> line when robocop is enabled but no control plane can run
its image, undef otherwise (k197). The robocop image is amd64 only; when every
control plane is a Hetzner CAX (ARM) server the pod stays Pending and no
worker joins through robocop. A warning, never a refusal: a mixed cluster, an
amd64 control plane or C<robocop: false> say nothing.

=cut

sub robocop_arch_warning {
    my ($self) = @_;
    return unless $self->robocop_enabled;

    my @cps = @{ $self->control_planes };
    return unless @cps;
    for my $cp (@cps) {
        return unless ref $cp eq 'HASH'
            && ($cp->{provider} // '') eq 'hetzner'
            && ($cp->{server_type} // '') =~ /^cax/i;
    }

    return '[WARN] robocop image is amd64 only, but every control plane is an ARM server (cax*): '
        . 'the robocop pod stays Pending and worker joins through robocop do not run. '
        . 'Set `robocop: false` or add an amd64 control plane (cpx/cx).';
}

# How the private robo (automation) SSH key reaches the cluster (k129),
# read from `robocop.security_level` (the mapping form of the robocop key):
#
#   secret           `ocp deploy-robocop` decrypts the robo key with PIN1 and
#                    writes it into a K8s Secret; a pod restart self-heals.
#   secret_approved  as secret, but writing the Secret is gated behind PIN2.
#   inject           in-memory, never persisted (k2): the Secret carries only
#                    the public half; `ocp inject-key` (PIN2) hands the private
#                    key to the running pod over a port-forward, and a pod
#                    restart needs a new injection.
#
# Default secret: an automation controller must survive pod restarts
# unattended, so the key has to rest in the cluster.
our @ROBOCOP_SECURITY_LEVELS = qw( secret secret_approved inject );

# Refuses an unknown value — the accessor is the point of use (DeployRobocop),
# and a typo there must not silently fall back to a level the operator did not
# ask for, exactly as gpu_driver refuses an unknown driver. validate() carries
# the report-only twin for `ocp apply`.
sub robocop_security_level {
    my ($self) = @_;

    my $level = $self->_raw_robocop_security_level // 'secret';

    _refuse("robocop.security_level must be "
        . OCP::Choices::or_list(@ROBOCOP_SECURITY_LEVELS)
        . ", not " . _shown_value($level))
        unless _is_choice($level, @ROBOCOP_SECURITY_LEVELS);

    return $level;
}

sub _raw_robocop_security_level {
    my ($self) = @_;
    my $val = $self->spec->{robocop};
    return ref $val eq 'HASH' ? $val->{security_level} : undef;
}

# robocop.image (k227): the image the robocop Deployment runs, in the mapping
# form of the robocop key. Undef when not set -- OCP::Robocop::Manifest then
# names the CLI's own version. `ocp apply` writes the Deployment on every run,
# so this is where a non-default image has to live to survive it;
# `ocp deploy-image` alone is a one-off override.
sub robocop_image {
    my ($self) = @_;
    my $val = $self->spec->{robocop};
    return undef unless ref $val eq 'HASH' && defined $val->{image};
    my $err = _image_ref_error($val->{image});
    _refuse("robocop.image: $err") if $err;
    return $val->{image};
}

# A reference as docker writes it: repo:tag or repo@sha256:<64 hex>. No
# implicit tag -- the same rule `ocp deploy-image` has.
sub _image_ref_error {
    my ($ref) = @_;
    return "must be an image reference like raudssus/ocp:1.2.3, not "
        . _shown_value($ref) if ref $ref;
    return "must not be empty" unless length($ref // '');
    return "must not contain whitespace ('$ref')" if $ref =~ /\s/;
    return undef if $ref =~ m{\A[^@\s]+\@sha256:[0-9a-f]{64}\z};
    return undef if $ref =~ m{\A(?:[^/\s]+/)*[^/:\s@]+:[^/:\s@]+\z};
    return "needs a tag or a digest, like raudssus/ocp:1.2.3 or repo\@sha256:<64 hex> ('$ref')";
}

# Every line under robocop:, each at its path (k400): robocop as a list, a
# string, a robocop.enabled that is neither true nor false, or a key of the
# mapping that is none of its three, each read as true and turned robocop on
# (k305, k315) -- the lines robocop_enabled refuses on; security_level and
# image at their own paths.
sub _robocop_lines {
    my ($self) = @_;
    my $robocop = $self->spec->{robocop};
    my @lines = _tagged(robocop => _robocop_errors($robocop));

    # robocop.security_level, report-only (k129). The accessor refuses; here
    # we collect one line so `ocp apply` lists it with every other config error.
    my $rl = $self->_raw_robocop_security_level;
    if (defined $rl && !_is_choice($rl, @ROBOCOP_SECURITY_LEVELS)) {
        push @lines, _tagged('robocop.security_level' => "robocop.security_level: invalid value "
            . _shown_value($rl) . " (must be " . OCP::Choices::or_list(@ROBOCOP_SECURITY_LEVELS) . ")");
    }

    # robocop.image, report-only (k227), same reason as security_level above.
    if (ref $robocop eq 'HASH' && defined $robocop->{image}) {
        my $ie = _image_ref_error($robocop->{image});
        push @lines, _tagged('robocop.image' => "robocop.image: $ie") if $ie;
    }

    return @lines;
}

sub _any_hetzner_provider {
    my $self = shift;
    for my $cp (@{$self->control_planes}) {
        return 1 if ($cp->{provider} // '') eq 'hetzner';
    }
    for my $pool (@{$self->workers}) {
        return 1 if ($pool->{provider} // '') eq 'hetzner';
    }
    return 0;
}

# Opt-in flags (default: disabled, set to true to enable)
# lbipam is opt-in because its default behaviour (pool = host public IP
# + L2 announcement) makes Cilium hijack ARP for the host IP, which breaks
# host-bound ports like sshd and kube-apiserver. Enable only when you have
# a proper design for exposing LoadBalancer services.
sub lbipam { my ($self) = @_; return $self->_switch('lbipam', $self->spec) }

# Registry configuration. A registry: that is no mapping, or a key in it
# that is no string, is refused here in validate()'s words (k379), as ssh:
# is: validate() passed both, and read on, a string died inside Perl ("Can't
# use string as a HASH ref") and a list was printed as ARRAY(0x...).
our @REGISTRY_KEYS = (
    [ cache    => 'a URL like http://cache.example:5000' ],
    [ upstream => 'a URL like http://registry.example:5000' ],
    [ name     => 'a host name like ocp.internal' ],
);

sub registry_config {
    my ($self) = @_;
    _refuse(_registry_errors($self->spec->{registry}));
    return $self->spec->{registry} // {};
}

# What is wrong with registry:, one line each, or nothing: validate() lists
# the lines and registry_config refuses on them, so the two cannot disagree.
sub _registry_errors {
    my ($registry) = @_;
    return _section_string_errors(registry => $registry, @REGISTRY_KEYS);
}

sub registry_cache       { shift->registry_config->{cache} // '' }
sub registry_upstream    { shift->registry_config->{upstream} // '' }
sub registry_name        { shift->registry_config->{name} // 'ocp.internal' }
sub has_external_cache   { shift->registry_cache ne '' }
sub has_external_upstream { shift->registry_upstream ne '' }

# Network configuration — the Cilium LB-IPAM pool and L2 announcement policy
# (k127). All optional; a cluster that sets nothing keeps the historical
# single-node behaviour (pool = node IP /32, announce on every node).
#
#   network:
#     lb_pool:
#       start: 10.230.30.240      # a range, as the citiai cluster uses,
#       stop:  10.230.30.249      # ... or:
#       cidr:  10.230.30.240/28   # a block (mutually exclusive with start/stop)
#     l2:
#       node_selector:            # limit announcement to labelled nodes instead
#         ai.citilan.de/l2-announce: "true"   # of trusting interface names
#       interfaces:               # override the built-in (anchored) regexes
#         - "^eth[0-9]+$"
#
# A network: that is no mapping is refused here in validate()'s words
# (k379): read on, pod_cidr died inside Perl on a string where ocp update,
# ocp node add, ocp status and ocp deploy-robocop (OCP_POD_CIDR) read it
# without validate() first. What is wrong inside the mapping its accessors
# refuse at their own paths (k400): pod_cidr, lb_pool_config, l2_config.
sub network_config {
    my ($self) = @_;
    my $net = $self->spec->{network};
    _refuse(_network_shape_error($net));
    return $net // {};
}

# validate()'s line for a network: that is no mapping, or undef.
sub _network_shape_error {
    my ($net) = @_;
    return undef if !defined $net || ref $net eq 'HASH';
    return 'network: must be a mapping';
}

# The keys the accessors here read under network:, and so the keys validate()
# takes there (k292): anything else is a typo whose default stays in force.
our @NETWORK_KEYS = qw( pod_cidr lb_pool l2 );
our @LB_POOL_KEYS = qw( cidr start stop );
our @L2_KEYS      = qw( node_selector interfaces );

# lb_pool, refused in validate()'s lines at network.lb_pool (k400): read on,
# lb_pool: foo died inside Perl in lb_pool_blocks.
sub lb_pool_config {
    my ($self) = @_;
    _refuse($self->spec_errors('network.lb_pool'));
    return $self->network_config->{lb_pool} // {};
}

# The CiliumLoadBalancerIPPool blocks list, or undef when no pool is
# configured — the caller then falls back to the node IP, but only on a
# single-node cluster.
sub lb_pool_blocks {
    my $self = shift;
    my $p = $self->lb_pool_config;
    return undef unless %$p;
    return [{ cidr => $p->{cidr} }] if defined $p->{cidr};
    return [{ start => $p->{start}, stop => $p->{stop} }];
}

# The pod network (k182): the cluster-cidr RKE2/k3s are installed with and
# the cluster pool Cilium's IPAM hands out, which must agree. The default is
# the built-in cluster-cidr of both distributions; Cilium's own default,
# 10.0.0.0/8, overlaps most host LANs and is what an RKE2 cluster ran before.
# Only read at install time: a running cluster keeps its pool, and OCP::Drift
# reports a difference instead of moving it.
#
#   network:
#     pod_cidr: 10.42.0.0/16
our $DEFAULT_POD_CIDR = '10.42.0.0/16';

# The service network OCP never changes: RKE2's and k3s' built-in
# service-cidr. The pod CIDR must stay clear of it.
our $SERVICE_CIDR = '10.43.0.0/16';

# Refused in validate()'s lines at network.pod_cidr (k400) -- no IPv4 CIDR,
# host bits set, too small -- where ocp update, ocp node add, ocp status and
# ocp deploy-robocop read it without validate() first. An overlap is no
# refusal here, see _pod_cidr_lines.
sub pod_cidr {
    my ($self) = @_;
    _refuse($self->spec_errors('network.pod_cidr'));
    return $self->network_config->{pod_cidr} // $DEFAULT_POD_CIDR;
}

sub pod_cidr_is_set {
    my ($self) = @_;
    _refuse($self->spec_errors('network.pod_cidr'));
    return defined $self->network_config->{pod_cidr};
}

# l2, refused in validate()'s lines at network.l2 (k400), as lb_pool is: read
# on, l2: foo died inside Perl in l2_interfaces and l2_node_selector.
sub l2_config {
    my ($self) = @_;
    _refuse($self->spec_errors('network.l2'));
    return $self->network_config->{l2} // {};
}

sub l2_node_selector { shift->l2_config->{node_selector} // {} }

# The interface-name regexes for CiliumL2AnnouncementPolicy, when
# network.l2.interfaces sets none. Cilium compiles them as Go (RE2) regexes,
# so there is no lookahead to say "but not that one" -- the exclusion has to
# be spelled into the character class.
#
# The en* pattern leaves out every predictable name that carries an "n": in
# systemd's naming scheme the only "n" after the "en" prefix is the
# n<phys_port_name> suffix, which switchdev-capable NICs (Mellanox/NVIDIA
# ConnectX and the like) get -- the QSFP/RoCE fabric between brain and cortex
# is enp1s0f0np0. Announcing ARP for LoadBalancer IPs there answers on a
# fabric no client sits on (k210). Capital P (PCI domain, enP7s7 on a GB10)
# and a VLAN suffix (enP7s7.30) are allowed: that is the LAN port of the same
# machine. A fabric NIC that comes without the suffix still matches; set
# network.l2.interfaces or l2.node_selector on such a cluster.
our $DEFAULT_L2_INTERFACES = [ '^eth[0-9]+(\\.[0-9]+)?$', '^en[a-mo-zP0-9]+(\\.[0-9]+)?$' ];

sub l2_interfaces {
    my $self = shift;
    my $i = $self->l2_config->{interfaces};
    return $i if ref $i eq 'ARRAY' && @$i;
    return [ @$DEFAULT_L2_INTERFACES ];
}

# Cilium's own Helm values (k210), for what OCP has no key of its own for --
# above all `devices`, the interfaces Cilium attaches its datapath to, which
# Cilium otherwise picks itself and which then include a fabric NIC.
#
#   cilium:
#     devices: [ "enP7s7.30" ]      # Helm `devices`
#     helm_values:                  # anything else, deep-merged over what
#       bpf: { masquerade: true }   # Rex::Rancher::Cilium generates
#
# devices is the short form of helm_values.devices; setting both is an error.
# The values travel to install_cilium and, so an upgrade keeps them, to every
# upgrade_cilium. OCP's own choices (ipam, gatewayAPI, k8sServiceHost) stay
# OCP's: a contradicting ipam.mode dies in Rex::Rancher::Cilium before the
# host is touched.
#
# A cilium: that is no mapping is refused here in validate()'s words (k379):
# read on, ocp update upgraded Cilium without the values, as if ocp.yaml set
# none. What is wrong inside the mapping is validate()'s alone, as under
# network:.
sub cilium_config {
    my ($self) = @_;
    my $c = $self->spec->{cilium};
    _refuse(_cilium_shape_error($c));
    return $c // {};
}

# validate()'s line for a cilium: that is no mapping, or undef.
sub _cilium_shape_error {
    my ($c) = @_;
    return undef if !defined $c || ref $c eq 'HASH';
    return 'cilium: must be a mapping (devices, helm_values)';
}

# The merged Helm values, {} when ocp.yaml sets none.
sub cilium_helm_values {
    my $self = shift;
    my $c = $self->cilium_config;
    my %values = ref $c->{helm_values} eq 'HASH' ? %{ $c->{helm_values} } : ();
    $values{devices} = [ @{ $c->{devices} } ] if ref $c->{devices} eq 'ARRAY';
    return \%values;
}

# SSL configuration (for cert-manager). Refused in validate()'s words when
# it is no mapping or its email no string (k379), as registry: is.
our @SSL_KEYS = (
    [ email => 'an address like admin@example.com' ],
);

sub ssl_config {
    my ($self) = @_;
    _refuse(_ssl_errors($self->spec->{ssl}));
    return $self->spec->{ssl} // {};
}
sub ssl_email { shift->ssl_config->{email} // '' }

# What is wrong with ssl:, one line each, or nothing: validate() lists the
# lines and ssl_config refuses on them.
sub _ssl_errors {
    my ($ssl) = @_;
    return _section_string_errors(ssl => $ssl, @SSL_KEYS);
}

# The lines for a section whose keys are each one string -- ssh: (k340),
# registry: and ssl: (k379): the mapping it must be, naming the keys, or one
# line per key that is no string.
sub _section_string_errors {
    my ($section, $map, @keys) = @_;
    return () unless defined $map;
    return "$section: must be a mapping (" . join(', ', map { $_->[0] } @keys) . '), not ' . _shown_value($map)
        unless ref $map eq 'HASH';
    return map {
        my ($key, $what) = @$_;
        my $err = _not_a_string($map->{$key}, $what);
        defined $err ? "$section.$key: $err" : ();
    } @keys;
}

# System configuration (timezone, locale, NTP): what every node is set up
# with, the control planes by the bootstrap and the workers through the
# provider CR. The keys its accessors read, and so the keys validate() takes
# there (k331): anything else is a typo whose default stays in force --
# system: { time_zone: Europe/Berlin } left every node on UTC.
our @SYSTEM_KEYS = qw( timezone locale ntp );

# A system: that is no mapping, or a key in it that is none of the three, is
# refused here in validate()'s words (k331): read on, timezone, locale and
# ntp_enabled died inside Perl on a string ("Can't use string as a HASH
# ref"), and validate() said nothing.
sub system_config {
    my ($self) = @_;
    _refuse(_system_errors($self->spec->{system}));
    return $self->spec->{system} // {};
}

# timezone and locale are one name each (k340): a list passed, and reached
# the Rexfile and the provider CR, whose CRD types both as strings.
our @SYSTEM_STRINGS = (
    [ timezone => 'a time zone like Europe/Berlin' ],
    [ locale   => 'a locale like en_US.UTF-8' ],
);

# What is wrong with system:, one line each, or nothing: validate() lists the
# lines and system_config refuses on them, so the two cannot disagree.
sub _system_errors {
    my ($system) = @_;
    return () unless defined $system;
    return 'system: must be a mapping (' . join(', ', @SYSTEM_KEYS) . '), not ' . _shown_value($system)
        unless ref $system eq 'HASH';
    return (
        (map {
            my ($key, $what) = @$_;
            my $err = _not_a_string($system->{$key}, $what);
            defined $err ? "system.$key: $err" : ();
        } @SYSTEM_STRINGS),
        _unknown_keys('system', $system, @SYSTEM_KEYS),
    );
}

sub timezone      { shift->system_config->{timezone} // 'UTC' }
sub locale        { shift->system_config->{locale} // 'en_US.UTF-8' }
sub ntp_enabled   { my ($self) = @_; return $self->_switch('system.ntp', $self->system_config) }

# GPU configuration
#
# Three independent facts, each one switch:
#
#   enabled  Whether OCP touches the GPU at all. Off means Rex skips hardware
#            detection on every node and no GPU Operator is deployed.
#   driver   Who installs the kernel driver. 'host' lets Rex do it and pins
#            the operator's driver DaemonSet off; 'operator' is the reverse —
#            Rex leaves the host alone entirely, because the operator that
#            brings the driver brings the container toolkit with it.
#   toolkit  Whether the operator installs the NVIDIA container toolkit. Vendor
#            images ship it: on a DGX the runtime is in /usr/bin before OCP
#            arrives, and NVIDIA's guidance for those hosts is
#            toolkit.enabled=false alongside driver.enabled=false, so that the
#            toolkit DaemonSet does not rewrite a containerd config that
#            already works.
#
# A gpu: that is no mapping is refused here in validate()'s words (k296):
# read on, every accessor below died inside Perl ("Can't use string as a
# HASH ref"), and taken for absent, gpu: false would mean enabled.
#
# So is a key in it that is none of these four (k331), as robocop_enabled
# refuses one under robocop: (k315). gpu: { enable: false } is a mapping
# without enabled, which is on: every reader asks an accessor below -- ocp
# update and ocp node add without validate() -- and none of them may read
# the one ocp.yaml another way than validate() does.
our @GPU_KEYS = qw( enabled driver toolkit amd );

sub gpu_config {
    my ($self) = @_;
    my $gpu = $self->spec->{gpu} // {};
    my $err = _gpu_shape_error($gpu);
    _refuse("gpu $err") if defined $err;
    _refuse(_unknown_keys('gpu', $gpu, @GPU_KEYS));
    return $gpu;
}

# What is wrong with the value of gpu:, or undef. robocop: takes a boolean,
# so gpu: false is the likely slip, and the line says what was meant.
sub _gpu_shape_error {
    my ($gpu) = @_;
    return undef if !defined $gpu || ref $gpu eq 'HASH';
    return 'must be a mapping, not ' . _shown_value($gpu)
        . (JSON::MaybeXS::is_bool($gpu)
            ? '; write gpu: { enabled: ' . ($gpu ? 'true' : 'false') . ' }' : '');
}

# Normalised to 0/1: these travel to the Rexfile as JSON and into a
# ClusterPolicy as a YAML boolean, and YAML::XS hands back JSON::PP::Boolean
# objects that neither destination should have to know about. Anything but
# true or false is refused (_switch, k320).
sub gpu_enabled { my ($self) = @_; return $self->_switch('gpu.enabled', $self->gpu_config) }
sub gpu_toolkit { my ($self) = @_; return $self->_switch('gpu.toolkit', $self->gpu_config) }

our @GPU_DRIVERS = qw( host operator );

sub gpu_driver {
    my ($self) = @_;
    my $driver = $self->gpu_config->{driver} // 'host';

    # A typo here would silently fall back to 'host' and leave the operator's
    # driver DaemonSet disabled on a cluster that was configured for it.
    _refuse("gpu.driver must be 'host' or 'operator', not " . _shown_value($driver))
        unless _is_choice($driver, @GPU_DRIVERS);

    return $driver;
}

# gpu.amd (k250): the Kubernetes side of an AMD GPU node. gpu.driver stays
# vendor-neutral (who installs the kernel driver); everything here is about
# what the cluster runs on AMD nodes once the driver is there. Absent means
# the defaults.
#
#   allocation       how an AMD node's GPUs are handed out by default:
#                    device-plugin (amd.com/gpu), dra (ResourceClaims against
#                    DeviceClass gpu.amd.com) or none. A node overrides it with
#                    the $AMD_GPU_ALLOCATION_LABEL label, so one cluster offers
#                    both paths; which workload gets which is not OCP's call.
#   resource_naming  single or mixed, handed to the device plugin as is.
#   labeller         AMD's node labeller (amd.com/gpu.* labels) on AMD nodes.
#   metrics          AMD's device-metrics-exporter. Off by default: upstream
#                    serves Instinct and Radeon AI only, not Ryzen APUs.
#   integrated       set up integrated AMD GPUs (the iGPU of a Ryzen CPU or
#                    APU) on every node. Off by default: detection runs on
#                    every node, control planes included, and a Hetzner AX42
#                    has a Phoenix iGPU nobody asked OCP to drive. A node
#                    joined with `ocp node add --gpu` opts in on its own
#                    (OCP::Node ORs the two).
our @GPU_AMD_ALLOCATIONS     = qw( device-plugin dra none );
our @GPU_AMD_RESOURCE_NAMING = qw( single mixed );
our @GPU_AMD_KEYS            = qw( allocation resource_naming labeller metrics integrated );

# The node labels that go with gpu.amd, named once for every reader and writer
# (the stack's affinity terms, ocp status, the Rexfile through its params).
#
#   $AMD_GPU_PRESENT_LABEL     'true' on a node where the host step accepted at
#                              least one AMD GPU. The cluster stack selects on
#                              it rather than on NFD's pci-*_1002 labels, which
#                              cannot tell an iGPU the integrated gate skipped
#                              from one OCP set up.
#   $AMD_GPU_ALLOCATION_LABEL  per-node override of gpu.amd.allocation, same
#                              values; set with `ocp node add --label` or by
#                              the GPU management system.
#   $AMD_GPU_GFX_TARGET_LABEL  the node's gfx target (gfx1151), which nothing
#                              upstream publishes. A node with more than one
#                              target gets one label per target instead, this
#                              key plus ".<gfx>", valued with the count.
our $AMD_GPU_PRESENT_LABEL    = 'ocp.internal/amd-gpu.present';
our $AMD_GPU_ALLOCATION_LABEL = 'ocp.internal/amd-gpu.allocation';
our $AMD_GPU_GFX_TARGET_LABEL = 'ocp.internal/amd-gpu.gfx-target';

# The names the AMD stack shows in the cluster, named once for everything
# that reads them back (ocp apply's readiness wait, ocp status). The stack
# itself is written by Rex::Rancher::K8s.
#
#   $AMD_GPU_RESOURCE         the device plugin's extended resource.
#   $AMD_GPU_RESOURCE_PREFIX  where resource_naming: mixed puts the
#                             partitioned resources (amd.com/<partition>).
#   $AMD_GPU_DRA_DRIVER       the DRA driver's name on its ResourceSlices,
#                             and its DeviceClass.
our $AMD_GPU_RESOURCE        = 'amd.com/gpu';
our $AMD_GPU_RESOURCE_PREFIX = 'amd.com/';
our $AMD_GPU_DRA_DRIVER      = 'gpu.amd.com';

# A key of gpu.amd that is none of its five is refused here in validate()'s
# words too (k331): gpu.amd: { alocation: dra } left device-plugin in force
# for every reader that did not ask validate() first.
sub gpu_amd_config {
    my ($self) = @_;
    my $amd = $self->gpu_config->{amd};
    return {} unless defined $amd;
    _refuse('gpu.amd must be a mapping ('.OCP::Choices::or_list(@GPU_AMD_KEYS).')')
        unless ref $amd eq 'HASH';
    _refuse(_unknown_keys('gpu.amd', $amd, @GPU_AMD_KEYS));
    return $amd;
}

# Refuse an unknown value, as gpu_driver does: a typo would otherwise mean
# the default in silence, and the wrong allocation path on every AMD node.
sub gpu_amd_allocation {
    my ($self) = @_;
    return $self->_gpu_amd_choice('allocation', 'device-plugin', @GPU_AMD_ALLOCATIONS);
}

sub gpu_amd_resource_naming {
    my ($self) = @_;
    return $self->_gpu_amd_choice('resource_naming', 'single', @GPU_AMD_RESOURCE_NAMING);
}

# 0/1 for the same reason gpu_toolkit is, and refused the same way.
sub gpu_amd_labeller   { my ($self) = @_; return $self->_switch('gpu.amd.labeller',   $self->gpu_amd_config) }
sub gpu_amd_metrics    { my ($self) = @_; return $self->_switch('gpu.amd.metrics',    $self->gpu_amd_config) }
sub gpu_amd_integrated { my ($self) = @_; return $self->_switch('gpu.amd.integrated', $self->gpu_amd_config) }

sub _gpu_amd_choice {
    my ($self, $key, $default, @choices) = @_;
    my $value = $self->gpu_amd_config->{$key} // $default;
    _refuse("gpu.amd.$key must be ".OCP::Choices::or_list(@choices)
        .", not "._shown_value($value))
        unless _is_choice($value, @choices);
    return $value;
}

# Whether $value is one of @choices. A reference never is: a list, a mapping,
# or a YAML boolean, which is a JSON::PP::Boolean. Until OCP::BooleanEq
# corrected the eq overload Cpanel::JSON::XS gives that class (k316),
# `'secret' eq $true` was true for any string Perl calls true, and this guard
# alone kept `true` from being every choice (k305, k314). It stays, so the
# answer does not hang on that overload.
sub _is_choice {
    my ($value, @choices) = @_;
    return 0 if ref $value;
    return grep({ $_ eq $value } @choices) ? 1 : 0;
}

# 0, 1, 2, ... as YAML gives them: a plain scalar, no sign, no fraction. A
# boolean is a reference and no number.
sub _is_whole_number {
    my ($value) = @_;
    return defined $value && !ref $value && $value =~ /\A[0-9]+\z/ ? 1 : 0;
}

# A value as an error message quotes it. YAML hands `false` back as a boolean
# object, which would otherwise read as '0'.
sub _shown_value {
    my ($value) = @_;
    return !defined $value                ? 'null'
         : JSON::MaybeXS::is_bool($value) ? ($value ? 'true' : 'false')
         : ref $value eq 'HASH'           ? 'a mapping'
         : ref $value eq 'ARRAY'          ? 'a list'
         :                                  "'$value'";
}

#
# Status file (.ocp/status.yaml)
#

sub status_file {
    my ($self) = @_;
    return $self->project_dir->child('.ocp', 'status.yaml')->stringify;
}

# Manifest hashes of the components last rolled out (.ocp/deployed.yaml).
# Cluster state, kept locally: it describes THIS cluster and nothing else, so
# it dies with the cluster (ADR 0004). The path lives here because two
# commands need it — apply writes it, destroy removes it — and a second
# spelling of it is how it survived a destroy in the first place: the next
# apply then compared against the state of a cluster that no longer existed
# and skipped components that were gone.
sub deployed_file {
    my ($self) = @_;
    return $self->project_dir->child('.ocp', 'deployed.yaml')->stringify;
}

# Runtime status (.ocp/status.yaml). Loaded once and kept, so callers can
# mutate it and persist with save_status.
has status => (
    is      => 'lazy',
    builder => '_load_status',
);

sub _load_status {
    my ($self) = @_;
    my $file = $self->status_file;
    return {} unless -f $file;
    return $self->ocp->load_file($file) // {};
}

sub nodes_status {
    my ($self) = @_;
    return $self->status->{nodes} //= [];
}

# The control plane we can reach: the recorded node status if we have one,
# otherwise whatever the spec pins.
sub cluster_status {
    my ($self) = @_;

    for my $node (@{ $self->nodes_status }) {
        next if ($node->{role} // 'control-plane') =~ /worker/;
        my $ip = $node->{public_ip};
        return $node if defined $ip && length $ip && $ip ne '-';
    }

    my $cp = $self->control_planes->[0] // {};
    my $ip = $self->_first_cp_string($cp, 'public_ip') // $self->_first_cp_string($cp, 'host');

    # A local control plane resolves its own address rather than the operator
    # pinning it. The machine ocp runs on IS the control plane, so its provider
    # reports the routable IP bootstrap already advertised in the tls-san, the
    # kubeconfig server endpoint and the CP OCPNode (advertised_host, k138) --
    # falling back to 127.0.0.1 when no route can be found. Without this a local
    # cluster returned no address here, and every reader -- the reconcile-path
    # drift remedies, `ocp node add`'s worker join URL, `ocp update`, `ocp
    # deploy-robocop` -- reported "no control plane address known" unless
    # control_planes.public_ip was set by hand (k152). ssh pins host and hetzner
    # pins public_ip in the spec, so neither ever reaches this branch.
    if (!(defined $ip && length $ip) && ($cp->{provider} // '') eq 'local') {
        $ip = OCP::Provider->for_spec($cp)->advertised_host;
    }

    # Its name, refused as validate() refuses it (k355).
    return {} unless defined $ip && length $ip;
    return { name => $self->_first_cp_string($cp, 'name') // 'cp-1', public_ip => $ip };
}

sub set_status {
    my ($self, $key, $value) = @_;
    $self->status->{$key} = $value;
    return $value;
}

sub save_status {
    my ($self) = @_;
    return $self->_save_status($self->status);
}

#
# Cluster existence check (BITSOW!)
#

sub cluster_exists {
    my ($self) = @_;
    return -f $self->project_dir->child('kubeconfig.yaml');
}

#
# SSH key helpers
#

sub ssh_private_key_path {
    my ($self) = @_;
    my $key_path = $self->ssh_config->{private_key} // '.ocp/id_ed25519';
    return $self->_resolve_path($key_path);
}

sub ssh_public_key_path {
    my ($self) = @_;
    my $key_path = $self->ssh_config->{public_key} // '.ocp/id_ed25519.pub';
    return $self->_resolve_path($key_path);
}

sub ssh_public_key {
    my ($self) = @_;
    my $path = $self->ssh_public_key_path;
    return path($path)->slurp if -f $path;
    return undef;
}

sub _resolve_path {
    my ($self, $p) = @_;
    $p =~ s/^~/$ENV{HOME}/;
    # Relative paths are relative to project dir
    return $p if $p =~ m{^/};
    return $self->project_dir->child($p)->stringify;
}

#
# Validation
#

# The keys of a control plane and of a worker pool that name one thing each
# (k315, k322), with what that is, as a line says it.
our @ONE_NAME_KEYS = (
    [ host        => 'a host name or IP address' ],
    [ server_type => 'a Hetzner server type like cx32' ],
    [ location    => 'a Hetzner location like fsn1' ],
    [ image       => 'an image name like debian-13' ],
);

# A control plane's own addresses (k340), one each as host is: public_ip is
# the address workers join at (join_host) and the cluster is reached at
# (cluster_status); private_ip is held against the cluster networks.
our @CP_ADDRESS_KEYS = (
    [ public_ip  => 'an IP address' ],
    [ private_ip => 'an IP address' ],
);

# A control plane's name (k355), one as its host is: OCP::Drift matches it
# against the recorded control planes and labels their spec drift with it,
# and cluster_status hands it on. A list matched none of them, and the drift
# of its pinned public_ip went unsaid.
our @CP_NAME_KEYS = (
    [ name => "the control plane's name, like police1" ],
);

# "control_planes[N].KEY: must be a string (WHAT), not ..." for the control
# plane $cp at place $idx, or undef (k315, k340, k355).
sub _cp_string_error {
    my ($cp, $idx, $key) = @_;
    my ($what) = map { $_->[1] } grep { $_->[0] eq $key } @ONE_NAME_KEYS, @CP_ADDRESS_KEYS, @CP_NAME_KEYS;
    my $err = _not_a_string($cp->{$key}, $what);
    return defined $err ? "control_planes[$idx].$key: $err" : undef;
}

# The first control plane's $key -- its address, as join_host and
# cluster_status read it, or its name -- refused in validate()'s words when it
# is no string (k340, k355): read on, a list was the address workers joined
# at, ARRAY(0x...).
sub _first_cp_string {
    my ($self, $cp, $key) = @_;
    _refuse(_cp_string_error($cp, 1, $key));
    return $cp->{$key};
}

# The keys a control plane and a worker pool are read for (k347), and so the
# keys validate() takes there: any other is a typo nothing reads. A pool's
# count: has been read by no `ocp apply` since a5a598d -- the pool got the
# one machine a pool without nodes: gets -- and passed without a word.
#
# A control plane's: provider, host, server_type, location and image (the
# bootstrap, ensure_control_plane_ocpnodes), public_ip (join_host,
# cluster_status, cp_tls_sans, OCP::Drift), private_ip (held against the
# cluster networks), node_ip (cp_node_ip, the join CRs), name (OCP::Drift's
# spec drift, cluster_status), and nodes in the mapping form, which
# control_planes reads and a list entry does not.
#
# Not service (k357): `ocp init --provider local --service systemd` wrote it,
# and nothing read it. It is refused with a hint that it can go.
our @CONTROL_PLANE_KEYS = qw( provider host public_ip private_ip node_ip server_type location image
                              name );

# A pool's: what worker_ocpnodes makes its OCPNodes of, as ocp destroy, ocp
# status and ocp node ls read them too. node_ip is refused on a pool by a
# line of its own, so it is not one of them, nor an unknown key there.
our @POOL_KEYS = qw( name provider nodes host server_type location image labels taints );

# A mapping in an ssh pool's nodes: list (k355): worker_ocpnodes reads its
# host and nothing else -- the worker is named after it --, as ocp destroy
# does. node_ip has its line, as on the pool.
our @POOL_NODE_KEYS = qw( host );

# One line per key of a control plane or pool $entry that is none of @known
# (k347), in _unknown_keys' words, with $hints->{$key} after it where a key
# was likely meant as another.
sub _entry_unknown_keys {
    my ($path, $entry, $hints, @known) = @_;
    my %known = map { $_ => 1 } @known;
    return map {
        my ($line) = _unknown_keys($path, { $_ => 1 }, @known);
        defined $hints->{$_} ? "$line; $hints->{$_}" : $line;
    } grep { !$known{$_} } sort keys %$entry;
}

sub validate {
    my ($self) = @_;

    # An ocp.yaml that is empty or no mapping holds no key to check (k340):
    # its line is the only one, the one every other reader stops with.
    my $spec_err = $self->_spec_error;
    return ($spec_err) if defined $spec_err;

    return _lines_of($self->_spec_lines);
}

# validate()'s lines, every one, as [ tag, line ] in its order (k400): the one
# list validate() and spec_errors both read, so that their order cannot
# differ. Each block is a producer; the tag is the key path spec_errors finds
# the line at, undef for a line that is validate()'s alone.
sub _spec_lines {
    my ($self) = @_;
    my $spec = $self->spec;

    # The network the pod CIDR and the service network are held against.
    my $net = ref $spec->{network} eq 'HASH' ? $spec->{network} : {};

    return (
        # The name, the control planes, gpu: and the worker pools: k306.
        $self->_name_lines,

        # kubernetes: and its dist (k340), the lines kubernetes and
        # distribution refuse on. dist: rke3 passed, installed RKE2 and told
        # robocop rke3. Its version and a key that is neither (k355), the
        # lines version and kubernetes refuse on.
        _kubernetes_lines($spec->{kubernetes}),

        $self->_control_plane_lines,

        _network_lines($spec->{network}),
        _tagged(cilium => $self->_validate_cilium),
        $self->_gpu_lines,

        # registry: and ssl: (k379), the lines registry_config and
        # ssl_config refuse on.
        _tagged(registry => _registry_errors($spec->{registry})),
        _tagged(ssl      => _ssl_errors($spec->{ssl})),

        # system: (k331), the lines system_config refuses on.
        _tagged(system => _system_errors($spec->{system})),

        _ssh_lines($spec->{ssh}),

        $self->_switch_lines,

        $self->_pod_cidr_lines($net),
        _tagged(undef, $self->_validate_service_cidr($net)),

        $self->_robocop_lines,

        $self->_worker_lines,
    );
}

=method spec_errors

    my @lines = $config->spec_errors('control_planes', 'control_planes[*]');
    my @lines = $config->spec_errors("workers[$n].nodes", "workers[$n].host");

The lines C<validate> has at the key paths named, in its words and its
order, each line once; none when nothing is wrong there (k306). For a
command that reads part of F<ocp.yaml> without running all of
C<validate>: it refuses on what it reads, and on nothing it does not.

The key paths, C<I> an entry's place counted from 1, or C<*> for every entry
C<validate> checks (with C<nodes: N> the control planes are one entry,
said once):

    name                         a name that is no string
    kubernetes                   every line under kubernetes:
    control_planes               control_planes that is neither form
    control_planes[I]            an entry that is no mapping
    control_planes[I].provider   a provider OCP does not know
    control_planes[I].KEY        KEY no string: host, public_ip, private_ip,
                                 server_type, location, image, name
    network                      network: no mapping, or a key of it OCP
                                 does not know
    network.pod_cidr             no IPv4 CIDR, host bits set, too small
    network.lb_pool              every line under lb_pool:
    network.l2                   every line under l2:
    cilium                       every line under cilium:
    gpu                          every line under gpu:, its switches with it
    registry                     every line under registry:
    ssl                          every line under ssl:
    system                       every line under system:, ntp with them
    ssh                          ssh: no mapping, or a path that is no string
    lbipam                       lbipam neither true nor false
    nocert                       nocert neither true nor false
    robocop                      robocop: as the switch it is: its shape,
                                 enabled, a key OCP does not know
    robocop.security_level       a level OCP does not know
    robocop.image                no image reference
    workers                      workers that is no list
    workers[I]                   a pool that is no mapping
    workers[I].name              a pool name that is no string
    workers[I].provider          a provider missing, or one OCP does not know
    workers[I].nodes             nodes: as the pool's provider reads it
    workers[I].KEY               KEY no string: host (on a pool that takes
                                 one), server_type, location, image
    workers[I].labels            the pool's labels
    workers[I].taints            the pool's taints

A path is the lines about its key and no more: C<network> is not the lines
under C<lb_pool:>, C<robocop> not its C<security_level>. Under a section or
an entry that has a line of its own shape, a path has none: C<validate>
reads no further there either. Nor has an entry past the last one.

Not at any path, C<validate>'s alone: a name missing, the cluster's or a
pool's; a key nothing reads of an entry, a pool, a pool's machine (k347) or
C<ssh:> (k355); what a provider requires; the bounds of C<control_planes>;
every C<node_ip>; an ssh pool that names its machines both ways, or
neither; a host on a pool that takes none; and where the pod CIDR or the
service network overlaps an address (k400) -- that is about the other
sections' addresses, and a running cluster whose default pod CIDR overlaps
a node address must not stop every command that reads C<network:>. A path
outside these croaks. An F<ocp.yaml> that is empty or no mapping stops it
with its line, as it stops every reader.

C<validate> and C<spec_errors> read one list of C<validate>'s lines, each
with the path it is at (k400), so their order cannot differ.

=cut

# The paths spec_errors answers for under a control plane and a pool (k306),
# and the sections and keys that are one path each (k400).
my @CP_PATH_KEYS   = ('provider', map { $_->[0] } @ONE_NAME_KEYS, @CP_ADDRESS_KEYS, @CP_NAME_KEYS);
my @POOL_PATH_KEYS = (qw( name provider nodes ), (map { $_->[0] } @ONE_NAME_KEYS), qw( labels taints ));
my @SECTION_PATHS  = qw( name kubernetes control_planes network network.pod_cidr network.lb_pool network.l2
                         cilium gpu registry ssl system ssh lbipam nocert robocop robocop.security_level
                         robocop.image workers );

sub spec_errors {
    my ($self, @paths) = @_;

    # The tags asked for, as regexes.
    my @want = map {
        _spec_path($_)
            // croak 'spec_errors: no key path ' . _shown_value($_) . ' (see OCP::Config/spec_errors)';
    } @paths;
    return () unless @want;

    # In validate()'s order, from validate()'s own list.
    return map { $_->[1] }
        grep { my $tag = $_->[0]; defined $tag && grep { $tag =~ $_ } @want } $self->_spec_lines;
}

# A regex for the tags a key path stands for, or undef for a path spec_errors
# does not answer for.
sub _spec_path {
    my ($path) = @_;
    return undef if !defined $path || ref $path;
    return qr/\A\Q$path\E\z/ if grep { $path eq $_ } @SECTION_PATHS;
    my ($section, $i, $key) = $path =~ /\A(control_planes|workers)\[(\*|[1-9][0-9]*)\](?:\.([a-z_]+))?\z/
        or return undef;
    return undef if defined $key
        && !grep { $_ eq $key } ($section eq 'workers' ? @POOL_PATH_KEYS : @CP_PATH_KEYS);
    my $index = $i eq '*' ? '[0-9]+' : $i;
    my $tail  = defined $key ? "\\.$key" : '';
    return qr/\A$section\[$index\]$tail\z/;
}

# The producers (k306): validate()'s lines of one block, in its order, as
# [ tag, line ] -- the tag the key path spec_errors finds the line at, undef
# for a line that is validate()'s alone.
sub _lines_of { return map { $_->[1] } @_ }
sub _tagged   { my ($tag, @lines) = @_; return map { [ $tag, $_ ] } @lines }

# A name that is a list or mapping passed (k305), and every key name the
# cluster derives from it said ARRAY(0x...). "name is required" is
# validate()'s alone: ocp destroy searches a name like '' as the label it is
# (k335).
sub _name_lines {
    my ($self) = @_;
    return _tagged(name => "name: must be a string (the cluster's name), not "
        . _shown_value($self->spec->{name})) if ref $self->spec->{name};
    return $self->name && $self->name =~ /\S/ ? () : _tagged(undef, "name is required");
}

sub _control_plane_lines {
    my ($self) = @_;
    my @lines;

    my $cps = $self->control_planes;

    # The shape first (k296). A control_planes that is neither form would be
    # read as one hetzner control plane with nothing set, and refused for
    # what nobody wrote; a list entry that is no mapping died inside Perl.
    my $raw_cps = $self->spec->{control_planes};
    if (defined $raw_cps && ref $raw_cps ne 'HASH' && ref $raw_cps ne 'ARRAY') {
        push @lines, _tagged(control_planes => "control_planes: must be a mapping (one control plane, "
            . "or nodes: N of them) or a list of mappings, not " . _shown_value($raw_cps));
        $cps = [];
    }
    push @lines, _tagged(undef, "control_planes: must list at least one control plane, not an empty list")
        if ref $raw_cps eq 'ARRAY' && !@$raw_cps;
    my $etcd_bound = "every control plane is an etcd member, and etcd advises no more "
        . "than $MAX_CONTROL_PLANE_NODES";
    if (ref $raw_cps eq 'HASH' && defined(my $nodes = $raw_cps->{nodes})) {
        my $whole = _is_whole_number($nodes);
        push @lines, _tagged(undef, "control_planes.nodes: must be a whole number from 1 to "
            . "$MAX_CONTROL_PLANE_NODES, not " . _shown_value($nodes)
            . ($whole && $nodes > $MAX_CONTROL_PLANE_NODES ? "; $etcd_bound" : ''))
            unless $whole && $nodes >= 1 && $nodes <= $MAX_CONTROL_PLANE_NODES;
    }
    # The list form holds no more than nodes: may stand for (k315): the bound
    # is etcd's, whichever way the control planes are written. Its entries are
    # still checked below.
    push @lines, _tagged(undef, "control_planes: must list at most $MAX_CONTROL_PLANE_NODES control "
        . "planes, not " . scalar(@$raw_cps) . "; $etcd_bound")
        if ref $raw_cps eq 'ARRAY' && @$raw_cps > $MAX_CONTROL_PLANE_NODES;

    # The mapping form with `nodes: N` is N copies of one entry (see
    # control_planes), so a node_ip there would be every one of them's (k254).
    # Refused once, not per copy; its syntax is not worth a line then.
    my $shared  = $self->_control_planes_shared;
    push @lines, _tagged(undef, "control_planes: node_ip with nodes: " . scalar(@$cps)
        . " would give all " . scalar(@$cps) . " control planes the same address; "
        . "list them one by one (control_planes: as a list), each with its own node_ip")
        if $shared && defined $raw_cps->{node_ip};

    # The entries are checked one by one -- but with nodes: N they are N
    # copies of one, whose lines were said N times over (k322): once is enough.
    my %node_ip_at;    # address (as an IP) => the control plane that has it
    for my $i (0 .. ($shared ? 0 : $#$cps)) {
        my $cp = $cps->[$i];
        my $idx = $i + 1;
        my $at  = "control_planes[$idx]";
        unless (ref $cp eq 'HASH') {
            push @lines, _tagged($at => "$at: must be a mapping (one control plane), not "
                . _shown_value($cp));
            next;
        }
        my $prov = $cp->{provider} // 'hetzner';

        # A key nothing reads (k347). nodes: is the mapping form's, which
        # control_planes takes out of each copy; in a list entry nothing
        # reads it.
        my $mapping = ref $raw_cps eq 'HASH';
        my $one_each = 'a list has one entry per control plane';
        push @lines, _tagged(undef, _entry_unknown_keys($at, $cp, {
                count => 'count is read by nothing -- '
                    . ($mapping ? 'how many control planes there are is nodes: N' : $one_each),
                nodes => "nodes: N is read on a control_planes mapping only -- $one_each",
                service => 'service is gone (ocp init wrote it, nothing read it) -- delete it',
            }, @CONTROL_PLANE_KEYS, ($mapping ? 'nodes' : ())));

        # The wording this rejection has always had; the SET behind it now
        # comes from the factory that builds those providers instead of being
        # spelled out a second time here (k103). Same three words, one
        # source -- a fourth provider type appears in this message the moment
        # OCP::Provider can construct it.
        # !ref: a boolean is no provider, whatever eq on it says; see
        # _is_choice (k305, k314).
        unless (!ref $prov && OCP::Provider->known_type($prov)) {
            push @lines, _tagged("$at.provider" => "$at: invalid provider " . _shown_value($prov)
                . " (must be " . OCP::Choices::or_list(OCP::Provider->types) . ")");
        }

        # host, server_type, location and image (k315, k322): one name each,
        # which the provider is handed and the OCPNode's spec carries as is. A
        # list passed for being true, and named the machine ARRAY(0x...). One
        # line for the shape, not a "required" beside it.
        # public_ip and private_ip (k340) the same way, and name (k355).
        my %malformed;
        for my $s (@ONE_NAME_KEYS, @CP_ADDRESS_KEYS, @CP_NAME_KEYS) {
            my $key  = $s->[0];
            my $line = _cp_string_error($cp, $idx, $key) // next;
            push @lines, _tagged("$at.$key" => $line);
            $malformed{$key} = 1;
        }

        if ($prov eq 'hetzner') {
            push @lines, _tagged(undef, "$at: server_type required for hetzner")
                unless $cp->{server_type} || $malformed{server_type};
            push @lines, _tagged(undef, "$at: location required for hetzner")
                unless $cp->{location} || $malformed{location};
        }

        if ($prov eq 'ssh') {
            push @lines, _tagged(undef, "$at: host required for ssh")
                unless $cp->{host} || $malformed{host};
        }

        # node_ip (k254): the address this control plane registers by, in the
        # words `ocp node add --node_ip` and an OCPNode's spec.nodeIP are
        # refused with.
        if (!$shared && defined $cp->{node_ip}) {
            my $err = OCP::Choices::node_ip_error($cp->{node_ip});
            push @lines, _tagged(undef, "$at.node_ip: $err") if defined $err;
            push @lines, _tagged(undef, $self->_node_ip_clashes($cp->{node_ip}, $idx, \%node_ip_at))
                unless defined $err;
        }
    }

    return @lines;
}

# gpu:, but for its switches (_switch_lines).
sub _gpu_lines {
    my ($self) = @_;
    my $gpu_err = _gpu_shape_error($self->spec->{gpu});
    return _tagged(gpu =>
        (defined $gpu_err ? "gpu: $gpu_err" : ()),
        # A key of gpu: that is none of its four (k331), the lines gpu_config
        # refuses on.
        (ref $self->spec->{gpu} eq 'HASH' ? _unknown_keys('gpu', $self->spec->{gpu}, @GPU_KEYS) : ()),
        $self->_validate_gpu_driver,
        $self->_validate_gpu_amd,
    );
}

# The switches (k320): true or false, as robocop: is; each line is its
# accessor's refusal too (_switch). Read through mappings only: a gpu: or
# gpu.amd: that is none has its own line (_gpu_lines). Each is at the path of
# its section (k400): those under gpu: at gpu, system.ntp at system, lbipam
# and nocert at their own.
sub _switch_lines {
    my ($self) = @_;
    my @lines;
    for my $path (sort keys %SWITCH_DEFAULTS) {
        my $value = $self->spec;
        $value = ref $value eq 'HASH' ? $value->{$_} : undef for split /\./, $path;
        my $err = _switch_error($path, $value);
        my ($section) = $path =~ /\A([^.]+)/;
        push @lines, _tagged($section => $err) if defined $err;
    }
    return @lines;
}

sub _worker_lines {
    my ($self) = @_;
    my @lines;

    # A workers that is no list, or an entry that is no mapping, died inside
    # Perl (k296).
    my $workers = $self->spec->{workers} // [];
    if (ref $workers ne 'ARRAY') {
        push @lines, _tagged(workers => "workers: must be a list of worker pools, not "
            . _shown_value($workers));
        $workers = [];
    }
    my $pool_n = 0;
    for my $w (@$workers) {
        $pool_n++;
        my $at = "workers[$pool_n]";
        unless (ref $w eq 'HASH') {
            push @lines, _tagged($at => "$at: must be a mapping (a worker pool), not " . _shown_value($w));
            next;
        }
        if (ref $w->{name}) {
            push @lines, _tagged("$at.name" => "$at.name: must be a string (the pool's name), not "
                . _shown_value($w->{name}));
        }
        else {
            push @lines, _tagged(undef, "worker pool: name required") unless $w->{name};
        }
        my $where = $self->_pool_where($w, $pool_n);
        my $wprov = $w->{provider} // '';
        if ($wprov eq '') {
            push @lines, _tagged("$at.provider" => "$where: provider required");
        } elsif (ref $wprov || !OCP::Provider->known_type($wprov)) {
            # Same set, same source as the control-plane check above --
            # spelling the regex here again is what k103 deleted for
            # the control planes and what k110 made stale (k115).
            push @lines, _tagged("$at.provider" => "$where: invalid provider " . _shown_value($wprov)
                . " (must be " . OCP::Choices::or_list(OCP::Provider->types) . ")");
        }

        # A key nothing reads (k347); node_ip has its line below. count: was
        # how a5a598d's builds counted a pool's machines.
        my %keys = %$w;
        delete $keys{node_ip};
        my $ssh_pool = !ref $wprov && $wprov eq 'ssh';
        push @lines, _tagged(undef, _entry_unknown_keys($at, \%keys, {
                count => 'count is read by nothing -- ' . ($ssh_pool
                    ? 'an ssh pool names its machines: host for one, or nodes, a list of hosts'
                    : 'write nodes: N, how many machines the pool has; without nodes it has one'),
            }, @POOL_KEYS));

        # host, server_type, location and image (k315, k322): one name each,
        # which worker_ocpnodes copies into every OCPNode of the pool. A host
        # beside a pool that takes none has one line, whatever its shape
        # (k331): see _pool_host_error.
        my %malformed;
        for my $s (@ONE_NAME_KEYS) {
            my ($key, $what) = @$s;
            next if $key eq 'host' && !$self->_pool_takes_host($w);
            if (defined(my $err = _not_a_string($w->{$key}, $what))) {
                push @lines, _tagged("$at.$key" => "$where: $key $err");
                $malformed{$key} = 1;
            }
        }

        # A Hetzner pool names its server type (k308): there is no worker
        # default, and OCP::Provider::Hetzner::create_server refuses a node
        # whose OCPNode and provider name none. What a provider requires, at
        # no path, as a control plane's server_type is (_control_plane_lines).
        push @lines, _tagged(undef, "$where: server_type required for hetzner -- a worker pool has "
            . "no default; add one, e.g. server_type: $HETZNER_DEFAULTS{server_type}")
            if !ref $wprov && $wprov eq 'hetzner' && !$w->{server_type} && !$malformed{server_type};

        # nodes (k315), see _pool_nodes_errors. Which nodes: a pool takes
        # hangs on its provider, so only a known one is asked. An ssh pool's
        # host beside it is validate()'s own (k322), see
        # _ssh_pool_machines_errors.
        push @lines, _tagged("$at.nodes" => $self->_pool_nodes_errors($w, $where))
            if !ref $wprov && $wprov ne '' && OCP::Provider->known_type($wprov);
        push @lines, _tagged(undef, $self->_ssh_pool_machines_errors($w, $where))
            if !ref $wprov && $wprov eq 'ssh';
        push @lines, _tagged(undef, $self->_pool_host_error($w, $where) // ());

        # labels / taints (k211): what the pool's OCPNodes carry, each at its
        # path (k400).
        push @lines, _tagged("$at.labels" => OCP::NodeMeta->label_errors("$where: labels", $w->{labels}))
            if defined $w->{labels};
        if (defined(my $taints = $w->{taints})) {
            if (ref $taints ne 'ARRAY') {
                push @lines, _tagged("$at.taints"
                    => "$where: taints must be a list like [ \"key=value:NoSchedule\" ]");
            }
            else {
                for my $t (@$taints) {
                    my $err = OCP::NodeMeta->taint_error($t);
                    push @lines, _tagged("$at.taints" => "$where: $err") if defined $err;
                }
            }
        }

        # node_ip (k254) is one machine's address, so a pool takes none; nor
        # does an entry of its nodes list, which apply does not read it from.
        # Refused rather than ignored: ignored, the node would join on its
        # default route's address, which is what node_ip is there to prevent.
        my $per_node = 'set it per node: ocp node add NAME --node_ip ADDRESS, '
            . 'or spec.nodeIP on its OCPNode';
        push @lines, _tagged(undef, "$where: node_ip cannot be set on a pool, one address cannot be "
            . "every machine's; $per_node")
            if defined $w->{node_ip};
        if (ref $w->{nodes} eq 'ARRAY') {
            for my $n (0 .. $#{ $w->{nodes} }) {
                my $entry = $w->{nodes}[$n];
                next unless ref $entry eq 'HASH';
                push @lines, _tagged(undef, "$where: nodes[" . ($n + 1) . "].node_ip is not read from "
                    . "a pool's nodes; $per_node")
                    if defined $entry->{node_ip};

                # A key of an ssh pool's machine that nothing reads (k355).
                # validate()'s alone, as the pool's are (k347): ocp destroy
                # reads the machines without it (k323). Any other pool's nodes
                # is a count, and a list there has its line.
                my %keys = %$entry;
                delete $keys{node_ip};
                push @lines, _tagged(undef, _entry_unknown_keys("$at.nodes[" . ($n + 1) . "]", \%keys, {},
                    @POOL_NODE_KEYS)) if $ssh_pool;
            }
        }
    }

    return @lines;
}

# The mapping form with nodes: N > 1, one entry standing for N control planes
# (see control_planes). A node_ip there is refused once (k254) and counted
# for nothing else.
sub _control_planes_shared {
    my ($self) = @_;
    return ref $self->spec->{control_planes} eq 'HASH' && @{ $self->control_planes } > 1 ? 1 : 0;
}

# How an error line names worker pool $n (1-based): by its name, or by its
# place when it has none a line can quote, as a control plane is named
# (k305) -- not "worker pool 'ARRAY(0x...)'", not "worker pool ''".
sub _pool_where {
    my ($self, $pool, $n) = @_;
    my $name = $pool->{name};
    return defined $name && !ref $name && length $name ? "worker pool '$name'" : "workers[$n]";
}

# A pool's nodes: as worker_ocpnodes (OCP::Cmd::Apply::CR) reads it (k315),
# one line per problem. An ssh pool names its machines -- host: for one, or
# nodes: a list of hosts, each a host name or address or a mapping with host
# -- and every other provider counts them, nodes: N. Counted, a list
# numified to its address and ran out of memory building OCPNodes; named, a
# boolean died inside Perl ("Not a HASH reference"), and a count named no
# machine at all. Only for a pool whose provider is known. An entry Perl
# calls false (0) names no machine either: worker_ocpnodes reads it so (k322).
sub _pool_nodes_errors {
    my ($self, $pool, $where) = @_;
    my $nodes = $pool->{nodes};
    return () unless defined $nodes;

    if ($pool->{provider} ne 'ssh') {
        return () if _is_whole_number($nodes);
        return "$where: nodes must be a whole number (how many machines the pool has), not "
            . _shown_value($nodes);
    }

    return "$where: nodes must be a list of hosts for an ssh pool (each a host name or IP "
        . "address, or a mapping with host), not " . _shown_value($nodes)
        unless ref $nodes eq 'ARRAY';

    my @errors;
    for my $n (1 .. @$nodes) {
        my $entry = $nodes->[$n - 1];
        if (ref $entry eq 'HASH') {
            my $host = $entry->{host};
            if (defined(my $err = _not_a_string($host, 'a host name or IP address'))) {
                push @errors, "$where: nodes[$n].host $err";
            }
            elsif (!$host) {
                push @errors, "$where: nodes[$n] needs a host";
            }
        }
        elsif (ref $entry || !$entry) {
            push @errors, "$where: nodes[$n] must be a host name or IP address, or a mapping "
                . "with host, not " . _shown_value($entry);
        }
    }
    return @errors;
}

# An ssh pool names its machines one way (k322): host for one, or nodes for a
# list. With neither, worker_ocpnodes made no OCPNode, and nothing said so;
# with both, it reads nodes and drops host, so a host beside nodes: [] was no
# worker either. nodes: [] alone passes: it says the pool has none yet, as
# nodes: 0 does for a pool that counts its machines. A host is read as
# worker_ocpnodes reads it -- one Perl calls false ('', 0) names no machine --
# and one of the wrong shape has its own line, so counts as set here.
#
# validate()'s alone, not _pool_nodes_errors': ocp destroy asks that one for
# how it reads the machines (k323), and reads host beside nodes as apply
# does, not at all -- no reason to stand between a cluster and its teardown.
sub _ssh_pool_machines_errors {
    my ($self, $pool, $where) = @_;
    my ($host, $nodes) = @{$pool}{qw( host nodes )};
    my $has_host = ref $host || $host;

    return $has_host ? () : "$where: an ssh pool needs host (one machine) or nodes (a list of "
        . "machines); with neither it gets no worker -- nodes: [] says it has none yet"
        unless defined $nodes;
    return "$where: an ssh pool takes host (one machine) or nodes (a list of machines), not both; "
        . "beside nodes, host is not read"
        if $has_host && ref $nodes eq 'ARRAY';
    return ();
}

# Whether a pool names its machines by host (k331). An ssh pool does; a pool
# of any other provider OCP knows does not: worker_ocpnodes reads host for an
# ssh pool only, and puts none on the OCPNodes of any other. A pool whose
# provider is unknown has that line, and is read as it always was.
sub _pool_takes_host {
    my ($self, $pool) = @_;
    my $prov = $pool->{provider};
    return 1 if ref $prov || !OCP::Provider->known_type($prov);
    return $prov eq 'ssh' ? 1 : 0;
}

# A host beside a pool that takes none (k331), or undef. It named no machine,
# and nothing said so: a hetzner pool's machines are servers Hetzner creates,
# at addresses Hetzner hands out, and a local pool is the machine ocp runs on,
# which its provider reaches at 127.0.0.1 whatever it is told. Refused
# whatever it is, as `ocp init --host` is beside any provider but ssh (k124):
# nothing reads it, so its shape is no line of its own. Null is absent.
sub _pool_host_error {
    my ($self, $pool, $where) = @_;
    return undef if !defined $pool->{host} || $self->_pool_takes_host($pool);
    my $prov = $pool->{provider};
    my $what = $prov eq 'hetzner' ? ', whose servers Hetzner creates at the addresses it hands out'
             : $prov eq 'local'   ? ', which is the machine ocp runs on'
             :                      '';
    my $fix  = $prov eq 'local' ? 'remove host, or name another machine in an ssh pool' : 'remove host';
    return "$where: host is read for an ssh pool only, and names no machine of a $prov pool$what -- $fix";
}

# "must be a string (WHAT), not a list" for a list, a mapping or a boolean,
# else undef (k315): host, server_type, location and image are one name each.
sub _not_a_string {
    my ($value, $what) = @_;
    return undef unless ref $value;
    return "must be a string ($what), not " . _shown_value($value);
}

# Two control planes with one node-ip register at one address (k254), as the
# mapping form with nodes: N would. Compared address by address and as IPs,
# so '10.0.0.1,fd00::1' clashes with '10.0.0.1', and 'FD00::1' is 'fd00::1'.
# $seen maps each address to the first control plane that has it; one line
# per earlier control plane this one shares an address with.
sub _node_ip_clashes {
    my ($self, $node_ip, $idx, $seen) = @_;
    my %with;
    for my $part (split /,/, $node_ip) {
        my $key = $self->_node_ip_key($part);
        if (defined(my $other = $seen->{$key})) { push @{ $with{$other} }, $part }
        else                                    { $seen->{$key} = $idx }
    }
    return map {
        "control_planes[$idx].node_ip: " . join(' and ', @{ $with{$_} })
            . (@{ $with{$_} } > 1 ? ' are' : ' is')
            . " control_planes[$_].node_ip too; two control planes cannot register at one address"
    } sort { $a <=> $b } keys %with;
}

# An IP in one spelling: the packed address, as OCP::Node->node_ip_mismatch
# compares them. Only for values node_ip_error passed, so always an IP.
sub _node_ip_key {
    my ($self, $ip) = @_;
    for my $af (Socket::AF_INET(), Socket::AF_INET6()) {
        my $packed = Socket::inet_pton($af, $ip);
        return $af . ':' . $packed if defined $packed;
    }
    return $ip;
}

# network.lb_pool / network.l2 validation (k127). Report-only: returns
# validate()'s lines under network:, each at its path (k400) -- network:'s
# shape and its unknown keys at network, the rest at network.lb_pool and
# network.l2, the lines lb_pool_config and l2_config refuse on.
sub _network_lines {
    my ($net) = @_;
    return () unless defined $net;
    my $shape = _network_shape_error($net);
    return _tagged(network => $shape) if defined $shape;

    return (
        _tagged(network => _unknown_keys('network', $net, @NETWORK_KEYS)),
        _tagged('network.lb_pool' => _lb_pool_errors($net->{lb_pool})),
        _tagged('network.l2'      => _l2_errors($net->{l2})),
    );
}

# The lines under network.lb_pool, or nothing.
sub _lb_pool_errors {
    my ($pool) = @_;
    my @errors;
    if (defined $pool) {
        if (ref $pool ne 'HASH') {
            push @errors, "network.lb_pool: must be a mapping (cidr, or start+stop)";
        }
        else {
            push @errors, _unknown_keys('network.lb_pool', $pool, @LB_POOL_KEYS);
            my $has_cidr  = defined $pool->{cidr};
            my $has_start = defined $pool->{start};
            my $has_stop  = defined $pool->{stop};

            if ($has_cidr && ($has_start || $has_stop)) {
                push @errors, "network.lb_pool: use either cidr or start+stop, not both";
            }
            elsif ($has_cidr) {
                push @errors, "network.lb_pool.cidr: " . _shown_value($pool->{cidr}) . " is not an IPv4 CIDR (e.g. 10.0.0.240/28)"
                    unless _looks_like_cidr($pool->{cidr});
            }
            elsif ($has_start || $has_stop) {
                push @errors, "network.lb_pool: start and stop must both be set"
                    unless $has_start && $has_stop;
                push @errors, "network.lb_pool.start: " . _shown_value($pool->{start}) . " is not an IPv4 address"
                    if $has_start && !_looks_like_ipv4($pool->{start});
                push @errors, "network.lb_pool.stop: " . _shown_value($pool->{stop}) . " is not an IPv4 address"
                    if $has_stop && !_looks_like_ipv4($pool->{stop});

                # Compared as addresses: 10.0.0.9 comes before 10.0.0.10.
                # Equal is a pool of one.
                push @errors, "network.lb_pool: start '$pool->{start}' is after stop "
                    . "'$pool->{stop}' (the pool runs from start up to stop)"
                    if _looks_like_ipv4($pool->{start}) && _looks_like_ipv4($pool->{stop})
                    && (_cidr_range("$pool->{start}/32"))[0] > (_cidr_range("$pool->{stop}/32"))[0];
            }
            else {
                push @errors, "network.lb_pool: needs cidr or start+stop";
            }
        }
    }
    return @errors;
}

# The lines under network.l2, or nothing.
sub _l2_errors {
    my ($l2) = @_;
    my @errors;
    if (defined $l2) {
        if (ref $l2 ne 'HASH') {
            push @errors, "network.l2: must be a mapping";
        }
        else {
            push @errors, _unknown_keys('network.l2', $l2, @L2_KEYS);
            if (defined(my $ns = $l2->{node_selector})) {
                if (ref $ns ne 'HASH' || !%$ns) {
                    push @errors, "network.l2.node_selector: must be a non-empty mapping of label => value";
                }
                else {
                    for my $k (sort keys %$ns) {
                        push @errors, "network.l2.node_selector.$k: value must be a scalar"
                            if ref $ns->{$k};
                    }
                }
            }
            if (defined(my $if = $l2->{interfaces})) {
                if (ref $if ne 'ARRAY' || !@$if) {
                    push @errors, "network.l2.interfaces: must be a non-empty list of interface-name regexes";
                }
                elsif (grep { ref $_ } @$if) {
                    push @errors, "network.l2.interfaces: entries must be strings";
                }
            }
        }
    }

    return @errors;
}

# One line per key of $map that is not one of @known, sorted, in the words
# cilium.* and gpu.amd.* are refused in (k292).
sub _unknown_keys {
    my ($path, $map, @known) = @_;
    my %known = map { $_ => 1 } @known;
    return map { "$path.$_: unknown key (must be " . OCP::Choices::or_list(@known) . ')' }
        grep { !$known{$_} } sort keys %$map;
}

# cilium: (k210). Report-only, same contract as validate().
sub _validate_cilium {
    my ($self) = @_;
    my $c = $self->spec->{cilium};
    return () unless defined $c;
    my $shape = _cilium_shape_error($c);
    return ($shape) if defined $shape;

    my @errors;
    for my $k (sort keys %$c) {
        push @errors, "cilium.$k: unknown key (must be "
            . OCP::Choices::or_list(qw( devices helm_values )) . ")"
            unless $k eq 'devices' || $k eq 'helm_values';
    }
    if (defined(my $d = $c->{devices})) {
        if (ref $d ne 'ARRAY' || !@$d) {
            push @errors, "cilium.devices: must be a non-empty list of interface names";
        }
        elsif (grep { ref $_ || !defined $_ || !length $_ } @$d) {
            push @errors, "cilium.devices: entries must be interface names (strings)";
        }
    }
    if (defined(my $hv = $c->{helm_values})) {
        if (ref $hv ne 'HASH') {
            push @errors, "cilium.helm_values: must be a mapping of Helm values";
        }
        elsif (defined $c->{devices} && exists $hv->{devices}) {
            push @errors, "cilium.devices and cilium.helm_values.devices: set one of them, not both";
        }
    }
    return @errors;
}

# gpu.driver (k255). Report-only, same contract as validate(); gpu_driver
# refuses the same values, but only where a GPU node is set up -- after a
# control plane was built.
sub _validate_gpu_driver {
    my ($self) = @_;
    my $gpu = $self->spec->{gpu};
    return () unless ref $gpu eq 'HASH' && defined $gpu->{driver};
    return () if _is_choice($gpu->{driver}, @GPU_DRIVERS);
    return ('gpu.driver: invalid value '._shown_value($gpu->{driver})
        .' (must be '.OCP::Choices::or_list(@GPU_DRIVERS).')');
}

# gpu.amd (k250). Report-only, same contract as validate(); the accessors
# refuse the same values at the point of use. An unknown key is reported
# too: a misspelt `alocation` would otherwise leave the default in force.
sub _validate_gpu_amd {
    my ($self) = @_;
    my $gpu = $self->spec->{gpu};
    return () unless ref $gpu eq 'HASH' && defined $gpu->{amd};

    my $amd = $gpu->{amd};
    my $keys = OCP::Choices::or_list(@GPU_AMD_KEYS);
    return ("gpu.amd: must be a mapping ($keys)") unless ref $amd eq 'HASH';

    # The lines gpu_amd_config refuses on (k331).
    my @errors = _unknown_keys('gpu.amd', $amd, @GPU_AMD_KEYS);

    my %choices = (
        allocation      => \@GPU_AMD_ALLOCATIONS,
        resource_naming => \@GPU_AMD_RESOURCE_NAMING,
    );
    for my $k (sort keys %choices) {
        my $v = $amd->{$k};
        next if !defined $v || _is_choice($v, @{ $choices{$k} });
        push @errors, "gpu.amd.$k: invalid value "._shown_value($v)
            .' (must be '.OCP::Choices::or_list(@{ $choices{$k} }).')';
    }
    return @errors;
}

# network.pod_cidr (k182). Checked whether set or not: the default can
# collide with a node address just as well, and then the error has to say it
# was the default that did.
#
# A pod CIDR that is none -- no IPv4 CIDR, host bits set, too small -- is at
# network.pod_cidr (k400), the line pod_cidr refuses on. An overlap is
# validate()'s alone: it is about the addresses of other sections, and a
# running cluster whose default pod CIDR overlaps a node address must not
# stop every command that reads the pod CIDR.
sub _pod_cidr_lines {
    my ($self, $net) = @_;
    my $set  = defined $net->{pod_cidr};
    my $cidr = $set ? $net->{pod_cidr} : $DEFAULT_POD_CIDR;
    my $what = $set ? "network.pod_cidr: '$cidr'" : "network.pod_cidr (default $cidr)";

    return _tagged('network.pod_cidr' => "network.pod_cidr: " . _shown_value($cidr)
        . " is not an IPv4 CIDR (e.g. 10.42.0.0/16)")
        unless _looks_like_cidr($cidr);

    my ($net_ip, $bits) = _cidr_range($cidr);
    my $canonical = _int_to_ipv4($net_ip) . "/$bits";
    return _tagged('network.pod_cidr' => "$what has host bits set; the network address is $canonical")
        unless $cidr eq $canonical;

    # Cilium's cluster pool gives every node a /24 out of this.
    return _tagged('network.pod_cidr' => "$what is too small: Cilium gives every node a /24 of it, "
        . "so the pod CIDR needs a shorter prefix than /24 (e.g. /16)")
        if $bits >= 24;

    my @taken = ([ "the service network $SERVICE_CIDR", $SERVICE_CIDR ], $self->_taken_addresses($net));

    my $hint = $set ? '' : ' -- set network.pod_cidr to a range nothing else uses';
    my @errors;
    for my $t (@taken) {
        push @errors, "$what overlaps $t->[0]$hint"
            if _cidrs_overlap($cidr, $t->[1]);
    }
    return _tagged(undef, @errors);
}

# The service network (k299): RKE2's and K3s's built-in service-cidr, which
# ocp.yaml has no key for. Held against the addresses the pod CIDR is held
# against, in the same words: one of them inside it can be handed to a
# Service as its ClusterIP. Checked whatever the pod CIDR is.
sub _validate_service_cidr {
    my ($self, $net) = @_;
    my $what = "the service network (default $SERVICE_CIDR)";
    my $hint = ' -- ocp.yaml has no key to move it; use an address outside it';
    return map { "$what overlaps $_->[0]$hint" }
        grep { _cidrs_overlap($SERVICE_CIDR, $_->[1]) } $self->_taken_addresses($net);
}

# The addresses ocp.yaml names that a cluster network must stay clear of
# (k182, k279, k299), as [ what, CIDR ]: each control plane's host,
# public_ip, private_ip and node_ip, each host of a worker pool that takes
# one (k331), the LB pool. An address that is no IPv4 literal is not counted
# -- a host name is not resolved, a refused node_ip has its own line.
sub _taken_addresses {
    my ($self, $net) = @_;
    my @taken;
    my $cps = $self->control_planes;

    # nodes: N is N copies of one entry, held against the networks once (k322).
    for my $i (0 .. ($self->_control_planes_shared ? 0 : $#$cps)) {
        next unless ref $cps->[$i] eq 'HASH';    # validate() has its line (k296)
        for my $key (qw( host public_ip private_ip )) {
            my $addr = $cps->[$i]{$key};
            push @taken, [ "control_planes[" . ($i + 1) . "].$key $addr", "$addr/32" ]
                if _looks_like_ipv4($addr);
        }

        # node_ip (k279), the address the node registers by: each part, the
        # IPv4 one, as both networks held against it are IPv4. Only a value
        # validate() accepted counts; a refused one has its own line already.
        my $node_ip = $cps->[$i]{node_ip};
        next if !defined $node_ip || $self->_control_planes_shared
            || defined OCP::Choices::node_ip_error($node_ip);
        push @taken, map { [ "control_planes[" . ($i + 1) . "].node_ip $_", "$_/32" ] }
            grep { _looks_like_ipv4($_) } split /,/, $node_ip;
    }
    my $workers = $self->workers;
    my @pools = ref $workers eq 'ARRAY' ? @$workers : ();
    for my $n (1 .. @pools) {
        my $pool = $pools[$n - 1];
        next unless ref $pool eq 'HASH';

        # A pool that takes no host names no machine by one (k331): its host,
        # and a nodes list that is no count, have their lines and are no
        # machine's address.
        next unless $self->_pool_takes_host($pool);
        my @hosts = ($pool->{host},
            map { ref $_ eq 'HASH' ? $_->{host} : $_ } @{ ref $pool->{nodes} eq 'ARRAY' ? $pool->{nodes} : [] });
        my $where = $self->_pool_where($pool, $n);
        push @taken, map { [ "$where host $_", "$_/32" ] } grep { _looks_like_ipv4($_) } @hosts;
    }
    if (ref(my $lb = $net->{lb_pool}) eq 'HASH') {
        push @taken, [ "network.lb_pool $lb->{cidr}", $lb->{cidr} ] if _looks_like_cidr($lb->{cidr});
        for my $key (qw( start stop )) {
            push @taken, [ "network.lb_pool.$key $lb->{$key}", "$lb->{$key}/32" ]
                if _looks_like_ipv4($lb->{$key});
        }
    }
    return @taken;
}

# (network address as an integer, prefix length) of a valid IPv4 CIDR.
sub _cidr_range {
    my ($ip, $bits) = split m{/}, shift;
    my $n = 0;
    $n = $n * 256 + $_ for split /\./, $ip;
    my $mask = $bits ? (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF : 0;
    return ($n & $mask, $bits);
}

sub _int_to_ipv4 {
    my $n = shift;
    return join '.', map { ($n >> $_) & 255 } 24, 16, 8, 0;
}

# Two blocks overlap when one contains the other's network address under the
# shorter of the two prefixes.
sub _cidrs_overlap {
    my ($a, $b) = @_;
    my ($an, $ab) = _cidr_range($a);
    my ($bn, $bb) = _cidr_range($b);
    my $bits = $ab < $bb ? $ab : $bb;
    my $mask = $bits ? (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF : 0;
    return (($an & $mask) == ($bn & $mask)) ? 1 : 0;
}

sub _looks_like_ipv4 {
    my $ip = shift;
    return 0 unless defined $ip && !ref $ip;
    return 0 unless $ip =~ /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/;
    return 0 if grep { $_ > 255 } ($1, $2, $3, $4);
    return 1;
}

sub _looks_like_cidr {
    my $c = shift;
    return 0 unless defined $c && !ref $c;
    return 0 unless $c =~ m{^(.+)/([0-9]{1,2})$};
    my ($ip, $bits) = ($1, $2);
    return 0 if $bits > 32;
    return _looks_like_ipv4($ip);
}

#
# Status write methods
#

sub save_node_status {
    my ($self, $node) = @_;

    my $nodes = $self->nodes_status;

    # Upsert by name
    my $found = 0;
    for my $existing (@$nodes) {
        if ($existing->{name} eq $node->{name}) {
            %$existing = %$node;
            $found = 1;
            last;
        }
    }
    push @$nodes, $node unless $found;

    $self->save_status;
}

sub _save_status {
    my ($self, $status) = @_;
    my $file = path($self->status_file);
    OCP::StateDir::make_parent($file);    # .ocp/, with its .gitignore (k371)
    $self->ocp->dump_file($file->stringify, $status);
}

#
# Class methods for initialization
#

sub write_spec {
    my ($class, $file, %opts) = @_;

    my $spec = {
        name => $opts{name} // 'mycluster',
        kubernetes => {
            dist => $opts{dist} // 'rke2',
        },
        ssh => {
            private_key => $opts{ssh_private_key} // '.ocp/id_ed25519',
            public_key  => $opts{ssh_public_key} // '.ocp/id_ed25519.pub',
        },
    };

    # Only add version if specified
    if ($opts{version}) {
        $spec->{kubernetes}{version} = $opts{version};
    }

    # Only add workers if specified
    if ($opts{workers} && @{$opts{workers}}) {
        $spec->{workers} = $opts{workers};
    }

    # System config (timezone, locale, ntp)
    if ($opts{system} && ref $opts{system} eq 'HASH' && %{$opts{system}}) {
        $spec->{system} = $opts{system};
    }

    # Control planes: compact where possible
    # 1 CP → Hash, N identical CPs → Hash + nodes, mixed → Array
    if ($opts{control_planes} && ref $opts{control_planes} eq 'ARRAY') {
        $spec->{control_planes} = _compact_control_planes($opts{control_planes});
    } else {
        my $provider = $opts{provider} // 'hetzner';

        if ($provider eq 'hetzner') {
            $spec->{control_planes} = {
                provider    => 'hetzner',
                server_type => $opts{server_type} // $HETZNER_DEFAULTS{server_type},
                location    => $opts{location}    // $HETZNER_DEFAULTS{location},
                image       => $opts{image}       // $HETZNER_DEFAULTS{image},
            };
        } elsif ($provider eq 'ssh') {
            my $cp = { provider => 'ssh' };
            $cp->{host} = $opts{host} if $opts{host};
            $spec->{control_planes} = $cp;
        } elsif ($provider eq 'local') {
            $spec->{control_planes} = { provider => 'local' };
        }
    }

    OCP->instance->dump_file($file, $spec);
}

sub _compact_control_planes {
    my ($control_planes) = @_;
    return $control_planes->[0] if @$control_planes == 1;

    # Check if all entries are identical → Hash + nodes
    # canonical sorts keys, so two hashes with the same content compare equal
    # regardless of insertion order.
    my $json = JSON::MaybeXS->new(canonical => 1, convert_blessed => 1);

    my $first = $json->encode($control_planes->[0]);
    my $all_same = 1;
    for my $i (1 .. $#$control_planes) {
        if ($json->encode($control_planes->[$i]) ne $first) {
            $all_same = 0;
            last;
        }
    }

    if ($all_same) {
        my %cp = %{$control_planes->[0]};
        $cp{nodes} = scalar @$control_planes;
        return \%cp;
    }

    return $control_planes;
}

1;

__END__

=head1 SYNOPSIS

    use OCP::Config;

    my $config = OCP::Config->new(file => 'ocp.yaml');

    # Read spec
    print $config->name;
    my $cp = $config->control_planes;

    # Read/write status
    $config->set_status(phase => 'Running');
    $config->add_node_status({ name => 'cp-1', ... });
    $config->save_status;

=head1 DESCRIPTION

OCP::Config manages two files:

=over 4

=item * C<ocp.yaml> - Cluster specification (what you want)

=item * C<.ocp/status.yaml> - Cluster status (what exists)

=back

The spec file is meant to be version controlled. The status file is
meant to be gitignored as it changes frequently during operations.

=head2 control_planes[].node_ip

    control_planes:
      - provider: ssh
        host: otho.lab
        node_ip: 10.230.30.52          # or "10.230.30.52,fd00::52"

The address a control plane registers as its C<InternalIP> -- RKE2's and
K3s's C<node-ip> (k254). Without it the node registers the address of its
default route, which on a multi-homed host (a second NIC, a VLAN) may be one
the other nodes cannot reach: the node shows Ready while Cilium's tunnel to it
is broken. One IPv4 or IPv6 literal, or one of each joined by a comma for
dual-stack; C<validate> refuses anything else with the line
L<OCP::Choices/node_ip_error> gives, prefixed C<control_planes[N].node_ip: >.
It is never guessed: unset, no node-ip is passed at all.

Only where it names one machine:

=over 4

=item * the mapping form of C<control_planes> takes it as long as it is one
control plane; with C<nodes: N> above 1 it would be every copy's address and
is refused -- list the control planes one by one instead;

=item * in the list form, no two control planes may share an address. They
are compared address by address and as IPs, so C<10.0.0.1,fd00::1> clashes
with C<10.0.0.1>, and C<FD00::1> with C<fd00::1>; the line names both
entries;

=item * its IPv4 address, either part of a dual-stack value, must lie outside
C<network.pod_cidr> (default C<10.42.0.0/16>): it is a node address like
C<host> and C<public_ip>, and refused in the same words when the pod CIDR
contains it (k279);

=item * a C<workers> pool takes none, and neither does an entry of a pool's
C<nodes> list. Both are refused rather than ignored, and the line points to
C<ocp node add NAME --node_ip ADDRESS> or C<spec.nodeIP> on the OCPNode.

=back

=cut

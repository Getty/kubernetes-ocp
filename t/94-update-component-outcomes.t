#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

BEGIN { $ENV{ANSI_COLORS_DISABLED} = 1 }

use OCP;
use OCP::Cmd::Update;
use OCP::Config;
use OCP::Drift;
use OCP::Rex;
use OCP::Versions;

#
# k165: every component in the OCP::Versions manifest has an explicit outcome
# in `ocp update`.
#
# Before, a component without an _update_<comp> method fell back to a Rex task
# update_<comp> that share/Rexfile did not have (cilium_cli, nfd, the GPU
# stack), the loop ran _update_rke2 on k3s clusters and _update_k3s on RKE2
# ones, and both of those died by design. So any pin bump outside cilium and
# cert-manager broke the run, and `ocp update --force` could never succeed.
#
# The outcomes asserted here, per component:
#
#   rex     a Rex task that exists in share/Rexfile, driven with the drift
#           remedy params (cilium, cert_manager, gateway_api)
#   skip    a STDOUT note saying why nothing runs (cilium_cli moves with
#           cilium, the other distribution, cert-manager under nocert)
#   apply   a STDOUT note that `ocp apply` rolls the new pin out, because the
#           version lives in a manifest apply re-applies (NFD, GPU stack)
#   refuse  a STDERR refusal before anything changes: the cluster's own
#           distribution when its pin moved and ocp.yaml does not pin
#           kubernetes.version (a node-by-node upgrade is not ocp update's)
#
# Mock-based: OCP::Rex is replaced by a recorder, no SSH, no cluster.
#

my $CURRENT = $OCP::VERSION;
my %PINS    = %{ OCP::Versions->get_versions($CURRENT)->{components} };

my $rexfile = path(__FILE__)->parent->parent->child('share/Rexfile')->slurp_utf8;
my %REX_TASK = map { $_ => 1 } $rexfile =~ /^task\s+"([^"]+)"/mg;

{
    package FakeOcp;
    sub new     { my ($class, %args) = @_; bless {%args}, $class }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# A deployed dev-mode project: kubeconfig.yaml (cluster_exists), a status file
# stamped with $args{from} (default: this OCP), and the bootstrap key that dev
# mode reaches the control plane with.
sub project {
    my (%args) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;

    my $k8s = '';
    if ($args{dist} || $args{version}) {
        $k8s = "kubernetes:\n";
        $k8s .= "  dist: $args{dist}\n"       if $args{dist};
        $k8s .= "  version: $args{version}\n" if $args{version};
    }
    my $nocert = $args{nocert} ? "nocert: true\n" : '';
    my $gpu    = $args{no_gpu} ? "gpu:\n  enabled: false\n" : '';
    $dir->child('ocp.yaml')->spew_utf8(<<"YAML");
name: updatetest
control_planes:
  provider: hetzner
  public_ip: 1.2.3.4
$k8s$nocert$gpu
YAML
    $dir->child('kubeconfig.yaml')->spew_utf8("encrypted-placeholder\n");
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nBOOT\n");
    my $from = $args{from} // $CURRENT;
    $dir->child('.ocp', 'status.yaml')->spew_utf8(<<"YAML");
ocpVersion: '$from'
nodes:
  - name: police1
    provider: hetzner
    public_ip: 1.2.3.4
YAML
    return $dir->child('ocp.yaml')->stringify;
}

# An older manifest, '0.000', that differs from this OCP's in %bump.
sub with_old_manifest {
    my ($bump, $code) = @_;
    my %old = %PINS;
    $old{$_} = $bump->{$_} for keys %$bump;
    local $OCP::Versions::VERSIONS = {
        %$OCP::Versions::VERSIONS,
        '0.000' => { components => \%old },
    };
    return $code->();
}

# Run `ocp update` with %opt against $file. Returns exit code, STDOUT, STDERR,
# and the Rex tasks it ran.
sub run_update {
    my ($file, %opt) = @_;
    my @calls;
    my ($out, $err) = ('', '');
    my $rc;
    {
        no warnings 'redefine';
        local *OCP::Rex::new = sub { my ($c, %a) = @_; bless {%a}, $c };
        local *OCP::Rex::run_task = sub {
            my ($self, $task, %p) = @_;
            push @calls, { task => $task, %p };
            die "boom from $task\n" if $opt{fail_task} && $opt{fail_task} eq $task;
            return 1;
        };
        my %args = map { $_ => $opt{$_} } grep { $_ ne 'fail_task' } keys %opt;
        my $cmd = OCP::Cmd::Update->new(
            command_chain => [ FakeOcp->new(config => $file) ],
            %args,
        );
        local *STDOUT;
        local *STDERR;
        open STDOUT, '>', \$out or die $!;
        open STDERR, '>', \$err or die $!;
        $rc = eval { $cmd->execute([], []) };
        $err .= "DIED: $@" if $@;
    }
    return ($rc, $out, $err, \@calls);
}

sub tasks { [ map { $_->{task} } @{ $_[0] } ] }

sub stamped {
    my ($file) = @_;
    return OCP::Config->new(file => $file)->status->{ocpVersion};
}

# ----------------------------------------------------------------- --force

for my $dist (qw( rke2 k3s )) {
    subtest "--force on a $dist cluster runs end to end" => sub {
        my $file = project(dist => $dist);
        my ($rc, $out, $err, $calls) = run_update($file, force => 1);

        is $rc, 0, 'exit 0' or diag "OUT:\n$out\nERR:\n$err";
        is $err, '', 'nothing on STDERR';
        is_deeply tasks($calls), [qw( upgrade_cert_manager upgrade_cilium )],
            'cert-manager and Cilium are upgraded; the Gateway API CRDs ride along with Cilium';
        ok $REX_TASK{$_}, "$_ exists in share/Rexfile" for @{ tasks($calls) };
        is $_->{distribution}, $dist, "$_->{task} gets the distribution" for @$calls;

        my $other = $dist eq 'rke2' ? 'k3s' : 'rke2';
        like $out, qr/^\s*$other\b.*not relevant for $dist/m, "$other: skipped, not relevant";
        like $out, qr/^\s*$dist\b.*does not reinstall/m, "$dist: unchanged pin, not reinstalled";
        like $out, qr/^\s*cilium_cli\b.*with cilium/m,      'cilium_cli: moves with cilium';
        like $out, qr/^\s*gateway_api\b.*with cilium/m,     'gateway_api: applied with cilium';
        for my $comp (qw( nfd gpu_operator nvidia_toolkit nvidia_driver
                          nvidia_device_plugin dcgm_exporter nvidia_dcgm )) {
            like $out, qr/^\s*$comp\b.*ocp apply/m, "$comp: rolled out by ocp apply";
        }
        is stamped($file), $CURRENT, 'the version stamp stays';
    };
}

# ----------------------------------------------------------- single bumps

subtest 'a gateway_api-only bump runs update_gateway_api with the remedy params' => sub {
    with_old_manifest({ gateway_api => 'v1.5.0' }, sub {
        my $file = project(from => '0.000', dist => 'k3s');
        my ($rc, $out, $err, $calls) = run_update($file);
        is $rc, 0, 'exit 0' or diag "OUT:\n$out\nERR:\n$err";
        is_deeply tasks($calls), ['update_gateway_api'], 'the gateway_api task, nothing else';
        my %got = %{ $calls->[0] };
        delete $got{task};
        is_deeply \%got,
            OCP::Drift->remedy_params(OCP::Config->new(file => $file), 'gateway_api', $PINS{gateway_api}),
            'exactly what the drift remedy passes';
        is stamped($file), $CURRENT, 'stamped';
    });
};

subtest 'a cilium_cli-only bump points at the cilium upgrade' => sub {
    with_old_manifest({ cilium_cli => 'v0.1.0' }, sub {
        my $file = project(from => '0.000');
        my ($rc, $out, $err, $calls) = run_update($file);
        is $rc, 0, 'exit 0' or diag "OUT:\n$out\nERR:\n$err";
        is_deeply tasks($calls), [], 'no Rex task: the CLI has none of its own';
        like $out, qr/ocp update --component cilium --force/, 'says how to refresh it';
        is $err, '', 'nothing on STDERR';
    });
};

subtest 'NFD and GPU stack bumps are left to ocp apply' => sub {
    with_old_manifest({ nfd => 'v0.1.0', gpu_operator => 'v1.0.0' }, sub {
        my $file = project(from => '0.000');
        my ($rc, $out, $err, $calls) = run_update($file);
        is $rc, 0, 'exit 0' or diag "OUT:\n$out\nERR:\n$err";
        is_deeply tasks($calls), [], 'no Rex task';
        like $out, qr/Run 'ocp apply'.*\bgpu_operator\b.*\bnfd\b/s,
            'a closing line names what ocp apply still has to roll out';
        is $err, '', 'nothing on STDERR';
        is stamped($file), $CURRENT, 'stamped';
    });
};

subtest 'GPU stack disabled: skipped, not sent to apply' => sub {
    with_old_manifest({ gpu_operator => 'v1.0.0' }, sub {
        my $file = project(from => '0.000', no_gpu => 1);
        my ($rc, $out, $err, $calls) = run_update($file);
        is $rc, 0, 'exit 0' or diag "OUT:\n$out\nERR:\n$err";
        like $out, qr/gpu_operator\b.*gpu\.enabled: false/, 'says why';
        unlike $out, qr/Run 'ocp apply'/, 'no apply hint';
    });
};

subtest 'nocert: cert-manager is skipped' => sub {
    my $file = project(nocert => 1);
    my ($rc, $out, $err, $calls) = run_update($file, force => 1, component => 'cert_manager');
    is $rc, 0, 'exit 0' or diag "OUT:\n$out\nERR:\n$err";
    is_deeply tasks($calls), [], 'no upgrade_cert_manager';
    like $out, qr/cert_manager\b.*nocert/, 'says why';
};

# --------------------------------------------------------- distributions

subtest 'a moved pin of the cluster\'s own distribution is refused' => sub {
    with_old_manifest({ rke2 => 'v1.30.0+rke2r1', cilium => '1.0.0' }, sub {
        my $file = project(from => '0.000');
        my ($rc, $out, $err, $calls) = run_update($file);
        is $rc, 1, 'exit 1';
        is_deeply tasks($calls), [], 'nothing ran, not even Cilium';
        like $err, qr/rke2.*v1\.30\.0\+rke2r1.*\Q$PINS{rke2}\E/s, 'STDERR names the move';
        like $err, qr{docs\.rke2\.io/upgrade},  'points at the upgrade docs';
        like $err, qr/kubernetes\.version/,     'and at the ocp.yaml pin that ends it';
        like $err, qr/Nothing was changed/,     'says nothing changed';
        like $out, qr/^\s*rke2\b.*refused/m, 'the plan marks it';
        unlike $out, qr/docs\.rke2|kubernetes\.version/, 'but the refusal itself is not on STDOUT';
        is stamped($file), '0.000', 'not stamped';
    });
};

subtest 'the same move with kubernetes.version pinned is a skip' => sub {
    with_old_manifest({ k3s => 'v1.30.0+k3s1' }, sub {
        my $file = project(from => '0.000', dist => 'k3s', version => 'v1.30.0+k3s1');
        my ($rc, $out, $err, $calls) = run_update($file);
        is $rc, 0, 'exit 0' or diag "OUT:\n$out\nERR:\n$err";
        like $out, qr/k3s\b.*kubernetes\.version/, 'says the ocp.yaml pin decides';
        is $err, '', 'nothing on STDERR';
        is stamped($file), $CURRENT, 'stamped';
    });
};

subtest 'the other distribution\'s pin moving is irrelevant' => sub {
    with_old_manifest({ rke2 => 'v1.30.0+rke2r1' }, sub {
        my $file = project(from => '0.000', dist => 'k3s');
        my ($rc, $out, $err, $calls) = run_update($file);
        is $rc, 0, 'exit 0' or diag "OUT:\n$out\nERR:\n$err";
        like $out, qr/rke2\b.*not relevant for k3s/, 'skipped';
        is $err, '', 'nothing on STDERR';
    });
};

# ----------------------------------------------------------- the planner

subtest 'every manifest component has a known outcome' => sub {
    my $cmd = OCP::Cmd::Update->new(command_chain => [ FakeOcp->new ]);
    for my $dist (qw( rke2 k3s )) {
        my $config  = OCP::Config->new(file => project(dist => $dist));
        my %planned = map { $_ => 1 } keys %PINS;
        for my $comp (sort keys %PINS) {
            for my $with_cilium (0, 1) {
                local $planned{cilium} = $with_cilium;
                my $plan = $cmd->_plan_component($config,
                    { component => $comp, from => $PINS{$comp}, to => $PINS{$comp} }, \%planned);
                isnt $plan->{action}, 'refuse', "$dist/$comp: not refused under --force";
                ok $REX_TASK{ $plan->{task} }, "$dist/$comp: $plan->{task} is in share/Rexfile"
                    if $plan->{action} eq 'rex';
                ok length $plan->{note}, "$dist/$comp: $plan->{action} says why"
                    if $plan->{action} ne 'rex';
            }
        }
    }
    my $config = OCP::Config->new(file => project());
    my $plan = $cmd->_plan_component($config,
        { component => 'brand_new', from => 'a', to => 'b' }, {});
    is $plan->{action}, 'refuse', 'a component ocp update does not know is refused';
    like $plan->{note}, qr/no updater/, 'and says so';
};

# ---------------------------------------------------------------- failure

subtest 'a failing Rex task is reported on STDERR' => sub {
    my $file = project();
    my ($rc, $out, $err, $calls) = run_update($file, force => 1, fail_task => 'upgrade_cilium');
    is $rc, 1, 'exit 1';
    like $err, qr/Failed to update cilium: boom from upgrade_cilium/, 'on STDERR';
    unlike $out, qr/Failed to update/, 'not on STDOUT';
};

done_testing;

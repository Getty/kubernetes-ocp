#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Kubernetes::REST::APIError;
use Path::Tiny ();
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Config;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::AMDGPU;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Deploy;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Apply::K8s;

#
# k435: k403 took the Perl source location out of the read helpers and the
# [!!] lines of the reconcile's component steps. These still printed the
# raw cause -- croak's " at FILE line N.", Kubernetes::REST's, a 599's LWP
# text with its reason twice and LWP's own location, over several lines:
#
#   OCP::Cmd::Apply::Drift   [WARN] registry.local DNS, [WARN] NFD, [!!]
#                            LB-IPAM, [!!] node CR reconcile, [!!] worker
#                            phases; the GPU reads of the dry run
#   OCP::Cmd::Apply::Deploy  [WARN] registry.local DNS, [!!] GPU Operator
#                            (deploy and after the join), [!!] LB-IPAM,
#                            [!!] robocop deploy
#   OCP::Cmd::Apply::AMDGPU  [!!] AMD GPU stack / component setup, [!!] not
#                            checked (dry run), [!!] not checked after the
#                            worker join
#   OCP::Cmd::Apply::K8s     resource_exists, poll_deployment_ready
#
# Each now says its cause through OCP::ErrorLine::one_line: one line, no
# location, a 599 said once. The words around the cause are as they were;
# the cause's own words are asserted by what they must and must not hold,
# not pinned (k437 rewords an API error in the apply lane).
#

# Rex (through OCP::Rex) puts getcwd/lib first in @INC: the modules under
# test must come from this tree's lib/.
for my $m (qw( OCP/Cmd/Apply/K8s.pm OCP/Cmd/Apply/Drift.pm OCP/Cmd/Apply/Deploy.pm OCP/Cmd/Apply/AMDGPU.pm )) {
    is Path::Tiny::path($INC{$m})->realpath->stringify, Path::Tiny::path("lib/$m")->realpath->stringify,
        "$m: from the tree under test" or BAIL_OUT("$m loaded from $INC{$m}");
}

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, out => $out, err => $err, died => $died };
}

my $LOCATION = qr/ line \d+\./;

{
    package Thrower;
    sub api_error { Kubernetes::REST::APIError->throw(@_) }
}
sub thrown {
    my (%a) = @_;
    return do { local $@; eval { Thrower::api_error(context => 'get Deployment', %a) }; $@ };
}

my $LWP = "Can't connect to 10.0.0.1:6443 (Connection refused)\n\n"
        . "Connection refused at /usr/share/perl5/LWP/Protocol/http.pm line 50.";

my $E403  = thrown(code => 403, body => '{"kind":"Status","reason":"Forbidden","message":"no","code":403}');
my $E599  = thrown(code => 599, body => $LWP);
my $E404  = thrown(code => 404, body => '{"kind":"Status","reason":"NotFound","code":404}');
my $CROAK = do { local $@; eval { die "the client broke\n  over a second line at here line 3.\n  x" }; $@ };

like "$E403",  qr/$LOCATION\n\z/, 'the 403 carries a location, as Kubernetes::REST throws it';
like "$CROAK", qr/$LOCATION\n\z/, 'the croak too, over several lines';

my %ERR = (403 => $E403, 599 => $E599, croak => $CROAK);

# What the cause must say, and that it is said once.
my %WORDS = (
    403   => qr/403/,
    599   => qr/\QCan't connect to 10.0.0.1:6443 (Connection refused)\E/,
    croak => qr/the client broke over a second line x/,
);

# $text holds $prefix with a cause after it: one line, the cause's words,
# no location, a 599's reason once.
sub said_once {
    my ($text, $prefix, $k, $name) = @_;
    subtest $name => sub {
        my @lines = grep { /\Q$prefix\E/ } split /\n/, $text;
        is scalar @lines, 1, 'one line' or diag $text;
        my $line = $lines[0] // '';
        like $line, qr/\Q$prefix\E.*$WORDS{$k}/, 'with its cause';
        unlike $line, $LOCATION, 'without a Perl source location';
        is scalar(() = $line =~ /Connection refused/g), ($k eq '599' ? 1 : 0), 'a 599\'s reason once';
        unlike $text, qr/^\s*(?:over a second|x$|Connection refused)/m, 'nothing of it on a line of its own';
    };
}

# --- OCP::Cmd::Apply::K8s -------------------------------------------------------

{
    package GetApi;
    sub new { my ($c, $e) = @_; bless { e => $e }, $c }
    sub get { die $_[0]{e} }

    package Waiter;
    sub new          { bless {}, shift }
    sub wait_seconds { }
}

subtest 'K8s: resource_exists and poll_deployment_ready die with the cause in one line' => sub {
    for my $k (sort keys %ERR) {
        eval { OCP::Cmd::Apply::K8s::resource_exists(Waiter->new, GetApi->new($ERR{$k}),
            'Deployment', 'gpu-operator', namespace => 'gpu-operator') };
        said_once($@, 'could not read Deployment gpu-operator/gpu-operator: ', $k, "resource_exists, $k");
        like $@, qr/\n\z/, "resource_exists, $k: a user error, newline-terminated";

        eval { OCP::Cmd::Apply::K8s::poll_deployment_ready(Waiter->new, GetApi->new($ERR{$k}),
            'robocop', 'ocp-system', 5) };
        said_once($@, 'the last read failed: ', $k, "poll_deployment_ready, $k");
    }
    is OCP::Cmd::Apply::K8s::resource_exists(Waiter->new, GetApi->new($E404), 'Deployment', 'x'), 0,
        'a 404 is still absent';
};

# --- OCP::Cmd::Apply::Drift: the reconcile -------------------------------------

my @KEEP;
sub config_for {
    my ($spec) = @_;
    my $dir = Path::Tiny->tempdir;
    push @KEEP, $dir;
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({
        name           => 'k435',
        control_planes => { provider => 'ssh', host => 'police1.k435.test' },
        %{ $spec // {} },
    }));
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

{
    package FakeOcp;
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    sub load_file { undef }
    sub dump_file { 1 }

    package FakeDrift;
    sub detect { [] }
}

my $WORKERS = { workers => [ { name => 'pool', provider => 'ssh', nodes => [ 'w1.k435.test' ] } ],
                lbipam  => JSON::PP::true() };

sub run_reconcile {
    my ($err) = @_;
    my $config = config_for($WORKERS);
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    $apply->{_k8s_api} = bless {}, 'NoApi';
    my $dies = sub { die $err };

    no warnings qw( redefine once );
    local *OCP::Secrets::read_kubeconfig          = sub { "apiVersion: v1\n" };
    local *OCP::Drift::new                        = sub { bless {}, 'FakeDrift' };
    local *OCP::Cmd::Apply::_k8s_api              = sub { $_[0]{_k8s_api} };
    local *OCP::Cmd::Apply::rex_prober            = sub { undef };
    local *OCP::Cmd::Apply::host_probe_warning    = sub { '' };
    local *OCP::Cmd::Apply::_setup_registry       = sub { 'unchanged' };
    local *OCP::Cmd::Apply::_configure_registry_dns = $dies;
    local *OCP::Cmd::Apply::_setup_nfd            = $dies;
    local *OCP::Cmd::Apply::_setup_gpu_operator   = sub { 'skipped' };
    local *OCP::Cmd::Apply::AMDGPU::step          = sub { { changed => 0, failed => [] } };
    local *OCP::Cmd::Apply::_load_deployed_hashes = sub { {} };
    local *OCP::Cmd::Apply::_resource_exists      = sub { 1 };
    local *OCP::Cmd::Apply::_setup_cilium_gateway = sub { 'unchanged' };
    local *OCP::Cmd::Apply::_setup_lb_ipam        = $dies;
    local *OCP::Cmd::Apply::_ensure_crds          = $dies;
    local *OCP::Cmd::Apply::CR::missing_worker_ocpnodes       = sub { () };
    local *OCP::Cmd::Apply::CR::check_worker_phases           = $dies;
    local *OCP::Cmd::Apply::CR::sync_worker_meta              = sub { { patched => [], failed => [] } };
    local *OCP::Cmd::Apply::CR::warn_unlisted_failed_ocpnodes = sub { };
    local *OCP::Cmd::Apply::CR::check_control_plane_phases    = sub { };
    # NoApi lists no Node; the control planes' Ready wait (k417) is t/417's,
    # and would poll it 60 x 10 s here.
    local *OCP::Cmd::Apply::CR::check_control_plane_ready     = sub { () };

    return capture { OCP::Cmd::Apply::Drift::reconcile_components($apply, $config); 1 };
}

subtest 'reconcile: the [WARN] and [!!] lines say their cause in one line' => sub {
    for my $k (sort keys %ERR) {
        my $r = run_reconcile($ERR{$k});
        is $r->{died}, '', "$k: the reconcile ran to its end" or diag $r->{died};
        said_once($r->{err}, "  [WARN] registry.local DNS setup failed: ", $k, "$k: registry.local DNS");
        said_once($r->{err}, "  [WARN] NFD setup failed: ",                $k, "$k: NFD");
        said_once($r->{err}, "  [!!] LB-IPAM setup failed: ",              $k, "$k: LB-IPAM");
        said_once($r->{err}, "  [!!] node CR reconcile failed: ",          $k, "$k: node CRs");
        said_once($r->{err}, "  [!!] Could not check worker phases: ",     $k, "$k: worker phases");
        unlike $r->{err}, $LOCATION, "$k: no location anywhere on STDERR";
    }
};

# --- OCP::Cmd::Apply::Drift: the GPU reads of the dry run -----------------------

{
    package GpuConfig;
    sub new         { bless {}, shift }
    sub gpu_enabled { 1 }
}

subtest 'dry run: a GPU read that failed is said in one line' => sub {
    for my $k (sort keys %ERR) {
        my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
        no warnings qw( redefine once );
        local *OCP::Cmd::Apply::_k8s_api        = sub { bless {}, 'NoApi' };
        local *OCP::Cmd::Apply::_resource_exists = sub { 1 };
        local *OCP::Drift::nvidia_gpu_nodes      = sub { die $ERR{$k} };
        my @found;
        my $r = capture { @found = OCP::Cmd::Apply::Drift::gpu_dry_run($apply, GpuConfig->new) };
        said_once($r->{err}, '  [!!] GPU Operator not checked: ', $k, "$k: on STDERR");
        unlike $found[0]{cause}, qr/$LOCATION|\n/, "$k: the entry's cause too";
    }
};

# --- OCP::Cmd::Apply::Deploy ---------------------------------------------------------

{
    package CrApi;
    sub new { bless {}, shift }
}

sub run_deploy {
    my ($err) = @_;
    my $config = config_for({ nocert => JSON::PP::true(), lbipam => JSON::PP::true() });
    my $apply  = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
    my $done   = sub { 'unchanged' };
    my $dies   = sub { die $err };
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_setup_registry                       = $done;
    local *OCP::Cmd::Apply::_configure_registry_dns               = $dies;
    local *OCP::Cmd::Apply::_setup_nfd                            = $done;
    local *OCP::Cmd::Apply::_setup_gpu_operator                   = $dies;
    local *OCP::Cmd::Apply::_report_component                     = $done;
    local *OCP::Cmd::Apply::_wait_cert_manager_and_create_issuers = $done;
    local *OCP::Cmd::Apply::_save_deployed_hash                   = $done;
    local *OCP::Cmd::Apply::_setup_cilium_gateway                 = $done;
    local *OCP::Cmd::Apply::_setup_lb_ipam                        = $dies;
    local *OCP::Cmd::Apply::_ensure_crds                          = sub { die "STOP\n" };
    local *OCP::Cmd::Apply::AMDGPU::step = sub { { failed => [] } };
    return capture { OCP::Cmd::Apply::Deploy::deploy($apply, {
        config => $config, api => CrApi->new, cp_name => 'police1', cp_ip => '10.0.0.1',
        provider => 'ssh', ssh_key_path => '/nonexistent', deploy_step => 2,
    }) };
}

subtest 'deploy: the [WARN] and [!!] lines say their cause in one line' => sub {
    for my $k (sort keys %ERR) {
        my $r = run_deploy($ERR{$k});
        is $r->{died}, "STOP\n", "$k: deploy reached the CR layer" or diag $r->{died};
        said_once($r->{err}, '  [WARN] registry.local DNS setup failed: ', $k, "$k: registry.local DNS");
        said_once($r->{err}, '  [!!] GPU Operator setup failed: ',         $k, "$k: GPU Operator");
        said_once($r->{err}, '  [!!] LB-IPAM setup failed: ',              $k, "$k: LB-IPAM");
        unlike $r->{err}, $LOCATION, "$k: no location anywhere on STDERR";
    }
};

subtest 'deploy: the GPU Operator after the worker join' => sub {
    for my $k (sort keys %ERR) {
        my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
        no warnings 'redefine';
        local *OCP::Cmd::Apply::_setup_gpu_operator_after_join = sub { die $ERR{$k} };
        my $r = capture { OCP::Cmd::Apply::Deploy::gpu_after_join($apply, undef,
            [ { name => 'w1', phase => 'Ready' } ]) };
        is $r->{rv}, 0, "$k: a failed check";
        said_once($r->{err}, '  [!!] GPU Operator setup failed: ', $k, "$k: said in one line");
    }
};

subtest 'deploy: robocop deploy failed' => sub {
    for my $k (sort keys %ERR) {
        my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
        no warnings 'redefine';
        local *OCP::Cmd::Apply::_ensure_robocop_credentials = sub { die $ERR{$k} };
        my $r = capture { OCP::Cmd::Apply::Deploy::robocop_step($apply, GetApi->new($E404),
            config_for(), { cp_ip => '10.0.0.1' }) };
        is $r->{rv}{state}, 'failed', "$k: the step failed";
        said_once($r->{err}, '  [!!] robocop deploy failed: ', $k, "$k: said in one line");
    }
};

# --- OCP::Cmd::Apply::AMDGPU --------------------------------------------------------

{
    package StructDies;
    sub new              { my ($c, $e) = @_; bless { e => $e }, $c }
    sub get              { bless {}, 'Obj' }
    sub k8s              { $_[0] }
    sub object_to_struct { die $_[0]{e} }
}

subtest 'AMD GPU stack: every [!!] says its cause in one line' => sub {
    for my $k (sort keys %ERR) {
        my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]);
        no warnings 'redefine';

        my $r = do {
            local *OCP::Cmd::Apply::AMDGPU::setup = sub { die $ERR{$k} };
            capture { OCP::Cmd::Apply::AMDGPU::step($apply, undef) };
        };
        is_deeply $r->{rv}{failed}, [ 'AMD GPU stack' ], "$k: the stack failed";
        said_once($r->{err}, '  [!!] AMD GPU stack setup failed: ', $k, "$k: the stack");

        $r = do {
            local *OCP::Cmd::Apply::AMDGPU::setup = sub { { label => 'AMD GPU DRA driver', error => $ERR{$k} } };
            capture { OCP::Cmd::Apply::AMDGPU::step($apply, undef) };
        };
        is_deeply $r->{rv}{failed}, [ 'AMD GPU DRA driver' ], "$k: the component failed";
        said_once($r->{err}, '  [!!] AMD GPU DRA driver setup failed: ', $k, "$k: a component");

        my $entry;
        $r = capture { $entry = OCP::Cmd::Apply::AMDGPU::unchecked('AMD GPU stack', $ERR{$k}) };
        said_once($r->{err}, '  [!!] AMD GPU stack not checked: ', $k, "$k: the dry run's unchecked");
        unlike $entry->{cause}, qr/$LOCATION|\n/, "$k: the entry's cause too";

        $apply->{_amd_gpu_step} = { failed => [], warned => 0 };
        $r = do {
            local *OCP::Cmd::Apply::_k8s_api = sub { StructDies->new($ERR{$k}) };
            capture { [ OCP::Cmd::Apply::AMDGPU::after_join($apply, GpuConfig->new,
                [ { name => 'w1', phase => 'Ready' } ]) ] };
        };
        is_deeply $r->{rv}, [ 'AMD GPU stack' ], "$k: after the join, counted";
        said_once($r->{err}, '  [!!] AMD GPU stack not checked after the worker join: ', $k,
            "$k: after the worker join");
    }
};

done_testing;

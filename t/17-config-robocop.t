use strict; use warnings; use Test::More;
use Path::Tiny;
use OCP;
use OCP::Config;

local @ARGV = ();
my $ocp = OCP->new;

my $tmp = Path::Tiny->tempdir;

subtest 'explicit robocop: true' => sub {
    my $f = $tmp->child('ocp1.yaml');
    $ocp->dump_file($f->stringify, {
        name     => 'test',
        robocop  => 1,
        controlPlanes => { provider => 'ssh', host => '1.2.3.4' },
    });
    my $cfg = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    ok $cfg->robocop_enabled, 'explicit true';
};

subtest 'explicit robocop: false' => sub {
    my $f = $tmp->child('ocp2.yaml');
    $ocp->dump_file($f->stringify, {
        name     => 'test',
        robocop  => 0,
        controlPlanes => { provider => 'hetzner', location => 'fsn1', serverType => 'cx32' },
    });
    my $cfg = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    ok !$cfg->robocop_enabled, 'explicit false wins over hetzner auto-enable';
};

subtest 'auto-on with hetzner provider' => sub {
    my $f = $tmp->child('ocp3.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'test',
        controlPlanes => { provider => 'hetzner', location => 'fsn1', serverType => 'cx32' },
    });
    my $cfg = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    ok $cfg->robocop_enabled, 'hetzner triggers auto-on';
};

subtest 'default off for ssh-only' => sub {
    my $f = $tmp->child('ocp4.yaml');
    $ocp->dump_file($f->stringify, {
        name          => 'test',
        controlPlanes => { provider => 'ssh', host => '1.2.3.4' },
    });
    my $cfg = OCP::Config->new(file => $f->stringify, ocp => $ocp);
    ok !$cfg->robocop_enabled, 'ssh-only stays off';
};

done_testing;
